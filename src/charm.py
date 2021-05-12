#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import base64
import datetime
import logging
import os
from ipaddress import IPv4Address
from pathlib import Path
from subprocess import check_output

from cryptography import x509
from kubernetes import kubernetes
from ops.charm import CharmBase, InstallEvent, StopEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

import cert
import resources

logger = logging.getLogger(__name__)


class KubernetesDashboardCharm(CharmBase):
    """Charm the service."""

    _authed = False

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.delete_resources_action, self._on_delete_resources_action)

    def _on_install(self, event: InstallEvent) -> None:
        """Handle the install event, create Kubernetes resources"""
        if not self._k8s_auth():
            event.defer()
            return
        self.unit.status = MaintenanceStatus("creating k8s resources")
        # Create the Kubernetes resources needed for the Dashboard
        r = resources.K8sDashboardResources(self)
        r.apply()

    def _on_stop(self, event: StopEvent) -> None:
        """Cleanup Kubernetes resources"""
        # Authenticate with the Kubernetes API
        if not self._k8s_auth():
            event.defer()
            return
        # Remove created Kubernetes resources
        r = resources.K8sDashboardResources(self)
        r.delete()

    def _on_config_changed(self, event) -> None:
        """Handle the pebble_ready event for the dashboard container"""
        # Defer the config-changed event if we do not have sufficient privileges
        if not self._k8s_auth():
            event.defer()
            return

        # Default StatefulSet needs patching for extra volume mounts. Ensure that
        # the StatefulSet is patched on each invocation.
        if not self._statefulset_patched:
            self._patch_dashboard_stateful_set()
            self.unit.status = MaintenanceStatus("waiting for changes to apply")

        # Add our Pebble config layer
        container = self.unit.get_container("dashboard")
        container.add_layer("dashboard", self._dashboard_layer(), combine=True)

        # Check if the dashboard service is already running and start it if not
        if not container.get_service("dashboard").is_running():
            self._check_tls_certs()
            container.start("dashboard")

        self.unit.status = ActiveStatus()

    def _dashboard_layer(self) -> dict:
        """Returns initial Pebble configuration layer for Kubernetes Dashboard"""
        # Build the command for the dashboard service
        cmd = [
            "/dashboard",
            "--bind-address=0.0.0.0",
            "--tls-cert-file=tls.crt",
            "--tls-key-file=tls.key",
            f"--namespace={self.model.name}",
        ]
        logger.debug("Dashboard command: %s", " ".join(cmd))
        return {
            "summary": "pebble config layer for kubernetes dashboard",
            "services": {"dashboard": {"override": "replace", "command": " ".join(cmd)}},
        }

    def _on_delete_resources_action(self, event):
        """Action event handler to remove all extra kubernetes resources"""
        if self._k8s_auth():
            # Remove created Kubernetes resources
            r = resources.K8sDashboardResources(self)
            r.delete()
            event.set_results({"message": "successfully deleted kubernetes resources"})

    def _check_tls_certs(self):
        """Create a self-signed certificate for the Dashboard if required"""
        # Get access to the Kubernetes CoreV1 API
        api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient())

        # Setup the required FQDN and Pod IP for any cert in use or to be generated
        pod_ip = IPv4Address(check_output(["unit-get", "private-address"]).decode().strip())
        fqdn = f"{self.app.name}.{self.model.name}.svc.cluster.local"

        # First read the current certificate from Kubernetes
        secret = api.read_namespaced_secret(
            name="kubernetes-dashboard-certs", namespace=self.model.name
        )
        # If there is already a certificate populated in the secret, validate it
        if secret.data:
            try:
                # Create an X509 Certificate from the Kubernetes secret, if one is specified
                c = x509.load_pem_x509_certificate(base64.b64decode(secret.data["tls.crt"]))

                # Get the list of IP Addresses in the SAN field
                cert_san_ips = c.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.IPAddress)

                # If the cert is valid and pod IP is already in the cert, we're good
                if pod_ip in cert_san_ips and c.not_valid_after >= datetime.datetime.utcnow():
                    return
            except KeyError:
                # KeyError raised by trying to access data['tls.crt'] if
                # it isn't populated
                pass

        # If we get this far, the cert is either not present, or invalid
        # Generate a valid self-signed certificate, set the Pod IP as a SAN
        tls = cert.SelfSignedCert([fqdn], [pod_ip])
        # Define the Kubernetes secret
        secret = {
            "namespace": self.model.name,
            "body": kubernetes.client.V1Secret(
                api_version="v1",
                metadata=kubernetes.client.V1ObjectMeta(
                    namespace=self.model.name,
                    name="kubernetes-dashboard-certs",
                    labels={"app.kubernetes.io/name": self.app.name},
                ),
                data={
                    "tls.crt": base64.b64encode(tls.cert).decode(),
                    "tls.key": base64.b64encode(tls.key).decode(),
                },
            ),
        }
        # Patch to ensure the secret has the details of the newly generated certificate
        api.patch_namespaced_secret(name=secret["body"].metadata.name, **secret)

    @property
    def _statefulset_patched(self) -> bool:
        """Slightly naive check to see if the StatefulSet has already been patched"""
        # Get an API client
        apps_api = kubernetes.client.AppsV1Api(kubernetes.client.ApiClient())
        # Get the StatefulSet for the deployed application
        stateful_set = apps_api.read_namespaced_stateful_set(
            name=self.app.name, namespace=self.model.name
        )
        # Check if it has been patched
        return stateful_set.spec.template.spec.service_account_name == "kubernetes-dashboard"

    def _patch_dashboard_stateful_set(self) -> None:
        """Patch the StatefulSet created by Juju to include specific
        ServiceAccount and Secret mounts"""
        self.unit.status = MaintenanceStatus("patching StatefulSet for additional k8s permissions")
        # Get an API client
        api = kubernetes.client.AppsV1Api(kubernetes.client.ApiClient())
        r = resources.K8sDashboardResources(self)

        # Read the StatefulSet we're deployed into
        s = api.read_namespaced_stateful_set(name=self.app.name, namespace=self.model.name)
        # Add the service account to the spec
        s.spec.template.spec.service_account_name = "kubernetes-dashboard"
        # Add the required volumes to the StatefulSet spec
        s.spec.template.spec.volumes.extend(r.dashboard_volumes)
        # Add the required volume mounts to the Dashboard container spec
        s.spec.template.spec.containers[1].volume_mounts.extend(r.dashboard_volume_mounts)

        # Patch the StatefulSet with our modified object
        api.patch_namespaced_stateful_set(name=self.app.name, namespace=self.model.name, body=s)
        logger.info("Patched StatefulSet to include additional volumes and mounts")

    def _k8s_auth(self):
        """Authenticate to kubernetes."""
        if self._authed:
            return True
        # Remove os.environ.update when lp:1892255 is FIX_RELEASED.
        os.environ.update(
            dict(
                e.split("=")
                for e in Path("/proc/1/environ").read_text().split("\x00")
                if "KUBERNETES_SERVICE" in e
            )
        )
        # Authenticate against the Kubernetes API using a mounted ServiceAccount token
        kubernetes.config.load_incluster_config()
        # Test the service account we've got for sufficient perms
        auth_api = kubernetes.client.RbacAuthorizationV1Api(kubernetes.client.ApiClient())

        try:
            auth_api.list_cluster_role()
        except:
            # If we can't read a cluster role, we don't have enough permissions
            self.unit.status = BlockedStatus("Run juju trust on this application to continue")
            return False

        self._authed = True
        return True


if __name__ == "__main__":
    main(KubernetesDashboardCharm)
