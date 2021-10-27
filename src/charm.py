#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import datetime
import logging
import traceback
from glob import glob
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.observability_libs.v0.kubernetes_service_patch import KubernetesServicePatch
from cryptography import x509
from lightkube import Client, codecs
from lightkube.core.exceptions import ApiError
from lightkube.models.core_v1 import (
    EmptyDirVolumeSource,
    SecretVolumeSource,
    ServiceAccount,
    Volume,
    VolumeMount,
)
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.resources.core_v1 import Service, ServiceAccount
from ops.charm import CharmBase, ConfigChangedEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

import cert

logger = logging.getLogger(__name__)


class KubernetesDashboardCharm(CharmBase):
    """Charmed Operator for the Official Kubernetes Dashboard."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self._stored.set_default(dashboard_cmd="")
        self._context = {"namespace": self.model.name, "app_name": self.app.name}

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        self._service_patcher = KubernetesServicePatch(self, [("dashboard-https", 443, 8443)])

    def _on_install(self, _) -> None:
        """Handle the install event, create Kubernetes resources."""
        self.unit.status = MaintenanceStatus("creating k8s resources")

        try:
            self._create_kubernetes_resources()
        except ApiError as e:
            logger.error(traceback.format_exc())
            self.unit.status = BlockedStatus(f"Resource creation failed with code {e.status.code}")
        else:
            self.unit.status = ActiveStatus()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Handle config-changed event, start services."""
        # Default StatefulSet needs patching for extra volume mounts.
        if not self._statefulset_patched:
            self._patch_stateful_set()
            self.unit.status = MaintenanceStatus("waiting for changes to apply")
            event.defer()
            return

        # Configure and start the Metrics Scraper
        scraper = self._configure_scraper()
        # Configure and start the Kubernetes Dashboard
        dashboard = self._configure_dashboard()

        if not (scraper and dashboard):
            logger.info("pebble socket not available, deferring config-changed")
            event.defer()
            return

        self.unit.status = ActiveStatus()

    def _configure_scraper(self) -> bool:
        """Configure Pebble to start the Kubernetes Metrics Scraper."""
        # Define a simple layer
        layer = {
            "services": {"scraper": {"override": "replace", "command": "/metrics-sidecar"}},
        }
        # Add a Pebble config layer to the scraper container
        container = self.unit.get_container("scraper")
        if container.can_connect():
            container.add_layer("scraper", layer, combine=True)
            container.restart("scraper")
            return True
        else:
            return False

    def _configure_dashboard(self) -> bool:
        """Configure Pebble to start the Kubernetes Dashboard."""
        # Generate a command for the dashboard
        cmd = self._dashboard_cmd()
        # Check if anything has changed in the layer
        if cmd != self._stored.dashboard_cmd:
            # Add a Pebble config layer to the dashboard container
            container = self.unit.get_container("dashboard")
            # Create a new layer
            layer = {
                "services": {"dashboard": {"override": "replace", "command": cmd}},
            }
            if container.can_connect():
                container.add_layer("dashboard", layer, combine=True)
                self._stored.dashboard_cmd = cmd
                # Validate or generate TLS certs
                self._check_tls_certs()
                logger.debug("Starting Dashboard with command: %s", cmd)
                container.restart("dashboard")
                return True
            else:
                return False

    def _dashboard_cmd(self) -> str:
        """Build a command to start the Kubernetes Dashboard based on config."""
        # Base command and arguments
        cmd = [
            "/dashboard",
            "--bind-address=0.0.0.0",
            "--sidecar-host=http://localhost:8000",
            f"--namespace={self.namespace}",
            "--default-cert-dir=/certs",
            "--tls-cert-file=tls.crt",
            "--tls-key-file=tls.key",
        ]
        return " ".join(cmd)

    def _check_tls_certs(self) -> None:
        """Create a self-signed certificate for the Dashboard if required."""
        # TODO: Add a branch here for if a secret is specified in config
        # Make the directory we'll use for certs if it doesn't exist
        container = self.unit.get_container("dashboard")
        container.make_dir("/certs", make_parents=True)

        if "tls.crt" in [x.name for x in container.list_files("/certs")]:
            # Pull the tls.crt file from the workload container
            file = container.pull("/certs/tls.crt")
            # Create an x509 Certificate object with the contents of the file
            c = x509.load_pem_x509_certificate(file.read().encode())
            # Get the list of IP Addresses in the SAN field
            cert_san_ips = c.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.IPAddress)
            # If the cert is valid and pod IP is already in the cert, we're good
            if self.pod_ip in cert_san_ips and c.not_valid_after >= datetime.datetime.utcnow():
                return

        # If we get this far, the cert is either not present, or invalid
        # Set the FQDN of the certificate
        fqdn = f"{self.app.name}.{self.namespace}.svc.cluster.local"

        # Get the service IP for the auto-created kubernetes service
        client = Client()
        svc: Service = client.get(Service, self.app.name, namespace=self.namespace)
        svc_ip = IPv4Address(svc.spec.clusterIP)

        # Generate a valid self-signed certificate, set the Pod IP/Svc IP as SANs
        tls = cert.SelfSignedCert([fqdn], [self.pod_ip, svc_ip])
        # Write the generated certificate and key to file
        container.push("/certs/tls.crt", tls.cert)
        container.push("/certs/tls.key", tls.key)
        logger.info("New self-signed TLS certificate generated for the Kubernetes Dashboard")

    @property
    def _statefulset_patched(self) -> bool:
        """Slightly naive check to see if the StatefulSet has already been patched."""
        client = Client()
        s: StatefulSet = client.get(StatefulSet, name=self.app.name, namespace=self.namespace)
        expected = VolumeMount(mountPath="/tmp", name="tmp-volume-dashboard")
        return expected in s.spec.template.spec.containers[1].volumeMounts

    def _patch_stateful_set(self) -> None:
        """Patch the StatefulSet to include specific ServiceAccount and Secret mounts."""
        self.unit.status = MaintenanceStatus("patching StatefulSet for additional k8s permissions")
        # Get an API client
        client = Client()
        s: StatefulSet = client.get(StatefulSet, name=self.app.name, namespace=self.namespace)
        # Add the required volumes to the StatefulSet spec
        s.spec.template.spec.volumes.extend(self._dashboard_volumes)
        # Add the required volume mounts to the Dashboard container spec
        s.spec.template.spec.containers[1].volumeMounts.extend(self._dashboard_volume_mounts)
        # Add the required volume mounts to the Scraper container spec
        s.spec.template.spec.containers[2].volumeMounts.extend(self._metrics_scraper_volume_mounts)
        # Patch the StatefulSet with our modified object
        client.patch(StatefulSet, name=self.app.name, obj=s)
        logger.info("Patched StatefulSet to include additional volumes and mounts")

    @property
    def _dashboard_volumes(self) -> dict:
        """Returns the additional volumes required by the Dashboard."""
        client = Client()
        # Get the service account details so we can reference it's token
        sa = client.get(ServiceAccount, name="kubernetes-dashboard", namespace=self.namespace)
        return [
            Volume(
                name="kubernetes-dashboard-service-account",
                secret=SecretVolumeSource(secretName=sa.secrets[0].name),
            ),
            Volume(name="tmp-volume-metrics", emptyDir=EmptyDirVolumeSource(medium="Memory")),
            Volume(name="tmp-volume-dashboard", emptyDir=EmptyDirVolumeSource()),
        ]

    @property
    def _dashboard_volume_mounts(self) -> dict:
        """Returns the additional volume mounts for the dashboard containers."""
        return [
            VolumeMount(mountPath="/tmp", name="tmp-volume-dashboard"),
            VolumeMount(
                mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]

    @property
    def _metrics_scraper_volume_mounts(self) -> dict:
        """Returns the additional volume mounts for the scraper containers."""
        return [
            VolumeMount(mountPath="/tmp", name="tmp-volume-metrics"),
            VolumeMount(
                mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]

    def _create_kubernetes_resources(self):
        """Iterates over manifests in the templates directory and applies them to the cluster."""
        client = Client()
        for manifest in glob("src/templates/*.yaml.j2"):
            with open(manifest) as f:
                for resource in codecs.load_all_yaml(f, context=self._context):
                    try:
                        client.create(resource)
                    except ApiError:
                        logger.debug(f"Failed to create resource: {resource.to_dict()}")
                        raise

    @property
    def namespace(self) -> str:
        """Return the current Kubernetes namespace."""
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r") as f:
            return f.read().strip()

    @property
    def pod_ip(self) -> Optional[IPv4Address]:
        """Get the IP address of the Kubernetes pod."""
        return IPv4Address(check_output(["unit-get", "private-address"]).decode().strip())


if __name__ == "__main__":
    main(KubernetesDashboardCharm, use_juju_for_storage=True)
