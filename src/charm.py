#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import logging
import os
from pathlib import Path

import kubernetes
import ops
from ops.charm import CharmBase, InstallEvent, PebbleReadyEvent, StopEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

logger = logging.getLogger(__name__)


class KubernetesDashboardCharm(CharmBase):
    """Charm the service."""

    _authed = False

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.stop, self._on_stop)

    def _on_install(self, event: InstallEvent) -> None:
        if not self.k8s_auth():
            event.defer()
            return
        self._create_additional_resources()

    def _on_stop(self, event: StopEvent) -> None:
        """Cleanup Kubernetes resources"""
        # Authenticate with the Kubernetes API
        self.k8s_auth()
        # Get an API client
        cl = kubernetes.client.ApiClient()
        core_api = kubernetes.client.CoreV1Api(cl)
        auth_api = kubernetes.client.RbacAuthorizationV1Api(cl)

        logger.debug("Cleaning up Kubernetes resources")
        # Remove some secrets
        core_api.delete_namespaced_secret(namespace=self.model.name, name="kubernetes-dashboard-certs")
        core_api.delete_namespaced_secret(namespace=self.model.name, name="kubernetes-dashboard-csrf")
        core_api.delete_namespaced_secret(namespace=self.model.name, name="kubernetes-dashboard-key-holder")
        # Remove the ServiceAccount
        core_api.delete_namespaced_service_account(namespace=self.model.name, name="kubernetes-dashboard")
        # Remove the Service
        core_api.delete_namespaced_service(namespace=self.model.name, name="kubernetes-dashboard")
        # Delete the ConfigMap
        core_api.delete_namespaced_config_map(namespace=self.model.name, name="kubernetes-dashboard-settings")
        # Delete the Role
        auth_api.delete_namespaced_role(namespace=self.model.name, name="kubernetes-dashboard")
        # Delete the ClusterRole
        auth_api.delete_cluster_role(name="kubernetes-dashboard")
        # Delete the RoleBinding
        auth_api.delete_namespaced_role_binding(namespace=self.model.name, name="kubernetes-dashboard")
        # Delete the ClusterRoleBinding
        auth_api.delete_cluster_role_binding(name="kubernetes-dashboard")

    def _check_patched(self) -> bool:
        """Slightly naive check to see if the StatefulSet has already been patched"""
        # Auth with the K8s api to check if the StatefulSet is already patched
        self.k8s_auth()
        # Get an API client
        cl = kubernetes.client.ApiClient()
        apps_api = kubernetes.client.AppsV1Api(cl)
        stateful_set = apps_api.read_namespaced_stateful_set(name=self.app.name, namespace=self.model.name)
        return stateful_set.spec.template.spec.service_account_name == "kubernetes-dashboard"

    def _on_config_changed(self, event) -> None:
        """ Handle the pebble_ready event for the dashboard container"""
        if not self.k8s_auth():
            event.defer()
            return

        if not self._check_patched():
            self._patch_dashboard_stateful_set()
            self.unit.status = MaintenanceStatus("waiting for changes to apply")

        container = self.unit.get_container("dashboard")
        # Add our initial config layer
        container.add_layer("dashboard", self._dashboard_layer(), combine=True)

        if not container.get_service("dashboard").is_running():
            container.start("dashboard")

        self.unit.status = ActiveStatus()

    def _dashboard_layer(self) -> dict:
        """Returns initial Pebble configuration layer for Kubernetes Dashboard"""

        cmd = [
            "/dashboard",
            "--insecure-bind-address=0.0.0.0",
            "--bind-address=0.0.0.0",
            "--auto-generate-certificates",
            f"--namespace={self.model.name}",
        ]
        return {
            "summary": "dashboard layer",
            "description": "pebble config layer for kubernetes dashboard",
            "services": {
                "dashboard": {
                    "override": "replace",
                    "summary": "kubernetes dashboard",
                    "command": " ".join(cmd),
                    # "command": "/entrypoint",
                    "startup": "enabled",
                    "environment": {},
                }
            },
        }

    def _patch_dashboard_stateful_set(self) -> None:
        """Patch the StatefulSet created by Juju to include specific
        ServiceAccount and Secret mounts"""
        self.unit.status = MaintenanceStatus("patching StatefulSet for additional k8s permissions")
        # Get an API client
        cl = kubernetes.client.ApiClient()
        apps_api = kubernetes.client.AppsV1Api(cl)
        core_api = kubernetes.client.CoreV1Api(cl)

        # Read the StatefulSet we're deployed into
        stateful_set = apps_api.read_namespaced_stateful_set(name=self.app.name, namespace=self.model.name)
        # Add the service account to the spec
        stateful_set.spec.template.spec.service_account_name = "kubernetes-dashboard"
        # Get the details of the kubernetes - dashboard service account
        service_account = core_api.read_namespaced_service_account(
            name="kubernetes-dashboard", namespace=self.model.name
        )

        # Create a Volume and VolumeMount for the dashboard service account
        service_account_volume_mount = kubernetes.client.V1VolumeMount(
            mount_path="/var/run/secrets/kubernetes.io/serviceaccount",
            name="kubernetes-dashboard-service-account",
        )
        service_account_volume = kubernetes.client.V1Volume(
            name="kubernetes-dashboard-service-account",
            secret=kubernetes.client.V1SecretVolumeSource(secret_name=service_account.secrets[0].name),
        )
        # Add them to the StatefulSet
        stateful_set.spec.template.spec.volumes.append(service_account_volume)
        stateful_set.spec.template.spec.containers[1].volume_mounts.append(service_account_volume_mount)

        # Create a Volume and VolumeMount for the dashboard certs
        certs_volume_mount = kubernetes.client.V1VolumeMount(mount_path="/certs", name="kubernetes-dashboard-certs")
        certs_volume = kubernetes.client.V1Volume(
            name="kubernetes-dashboard-certs",
            secret=kubernetes.client.V1SecretVolumeSource(secret_name="kubernetes-dashboard-certs"),
        )
        # Add them to the StatefulSet
        stateful_set.spec.template.spec.volumes.append(certs_volume)
        stateful_set.spec.template.spec.containers[1].volume_mounts.append(certs_volume_mount)

        # Patch the StatefulSet
        apps_api.patch_namespaced_stateful_set(name=self.app.name, namespace=self.model.name, body=stateful_set)
        logger.debug("Patched StatefulSet...")

    def _create_additional_resources(self) -> None:
        """Create additional Kubernetes resources"""
        self.unit.status = MaintenanceStatus("creating k8s resources")
        # Get an API client
        cl = kubernetes.client.ApiClient()
        core_api = kubernetes.client.CoreV1Api(cl)
        auth_api = kubernetes.client.RbacAuthorizationV1Api(cl)
        try:
            # Create the 'kubernetes-dashboard' service account
            logger.debug("Creating additional Kubernetes ServiceAccounts")
            core_api.create_namespaced_service_account(
                namespace=self.model.name,
                body=kubernetes.client.V1ServiceAccount(
                    api_version="v1",
                    metadata=self._template_meta("kubernetes-dashboard"),
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create the 'kubernetes-dashboard' service
            logger.debug("Creating additional Kubernetes Services")
            core_api.create_namespaced_service(
                namespace=self.model.name,
                body=kubernetes.client.V1Service(
                    api_version="v1",
                    metadata=self._template_meta("kubernetes-dashboard"),
                    spec=kubernetes.client.V1ServiceSpec(
                        ports=[kubernetes.client.V1ServicePort(port=443, target_port=8443)],
                        selector={"app.kubernetes.io/name": self.app.name},
                    ),
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create the 'kubernetes-dashboard-certs' secret
            logger.debug("Creating additional Kubernetes Secrets")
            core_api.create_namespaced_secret(
                namespace=self.model.name,
                body=kubernetes.client.V1Secret(
                    api_version="v1",
                    metadata=self._template_meta("kubernetes-dashboard-certs"),
                    type="Opaque",
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create the 'kubernetes-dashboard-csrf' secret
            core_api.create_namespaced_secret(
                namespace=self.model.name,
                body=kubernetes.client.V1Secret(
                    api_version="v1",
                    metadata=self._template_meta("kubernetes-dashboard-csrf"),
                    type="Opaque",
                    data={"csrf": ""},
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create the 'kubernetes-dashboard-key-holder' secret
            core_api.create_namespaced_secret(
                namespace=self.model.name,
                body=kubernetes.client.V1Secret(
                    api_version="v1",
                    metadata=self._template_meta("kubernetes-dashboard-key-holder"),
                    type="Opaque",
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create the 'kubernetes-dashboard-settings' configmap
            logger.debug("Creating additional Kubernetes ConfigMaps")
            core_api.create_namespaced_config_map(
                namespace=self.model.name,
                body=kubernetes.client.V1ConfigMap(
                    api_version="v1",
                    metadata=self._template_meta("kubernetes-dashboard-settings"),
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create the Kubernetes Role definition
            logger.debug("Creating additional Kubernetes Roles")
            auth_api.create_namespaced_role(
                namespace=self.model.name,
                body=kubernetes.client.V1Role(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=self._template_meta("kubernetes-dashboard"),
                    rules=[
                        # Allow Dashboard to get, update and delete Dashboard exclusive secrets.
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["secrets"],
                            resource_names=[
                                "kubernetes-dashboard-key-holder",
                                "kubernetes-dashboard-certs",
                                "kubernetes-dashboard-csrf",
                            ],
                            verbs=["get", "update", "delete"],
                        ),
                        # Allow Dashboard to get and update 'kubernetes-dashboard-settings' config map.
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["configmaps"],
                            resource_names=["kubernetes-dashboard-settings"],
                            verbs=["get", "update"],
                        ),
                        # Allow Dashboard to get metrics.
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["services"],
                            resource_names=[
                                "heapster",
                                "dashboard-metrics-scraper",
                            ],
                            verbs=["proxy"],
                        ),
                        kubernetes.client.V1PolicyRule(
                            api_groups=[""],
                            resources=["services/proxy"],
                            resource_names=[
                                "heapster",
                                "http:heapster:",
                                "https:heapster:",
                                "dashboard-metrics-scraper",
                                "http:dashboard-metrics-scraper",
                            ],
                            verbs=["get"],
                        ),
                    ],
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create ClusterRole for dashboard
            logger.debug("Creating additional Kubernetes ClusterRoles")
            auth_api.create_cluster_role(
                body=kubernetes.client.V1ClusterRole(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kubernetes-dashboard",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    rules=[
                        # Allow Metrics Scraper to get metrics from the Metrics server
                        kubernetes.client.V1PolicyRule(
                            api_groups=["metrics.k8s.io"],
                            resources=["pods", "nodes"],
                            verbs=["get", "list", "watch"],
                        ),
                    ],
                )
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 403:
                logger.warn("ClusterRole for metrics collection not created, insufficient permissions")
                pass
            elif e.status != 409:
                raise

        try:
            # Create a RoleBinding
            logger.debug("Creating additional Kubernetes RoleBindings")
            auth_api.create_namespaced_role_binding(
                namespace=self.model.name,
                body=kubernetes.client.V1RoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=self._template_meta("kubernetes-dashboard"),
                    role_ref=kubernetes.client.V1RoleRef(
                        api_group="rbac.authorization.k8s.io",
                        kind="Role",
                        name="kubernetes-dashboard",
                    ),
                    subjects=[
                        kubernetes.client.V1Subject(
                            kind="ServiceAccount",
                            name="kubernetes-dashboard",
                            namespace=self.model.name,
                        )
                    ],
                ),
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        try:
            # Create a ClusterRoleBinding
            logger.debug("Creating additional Kubernetes ClusterRoleBindings")
            auth_api.create_cluster_role_binding(
                body=kubernetes.client.V1ClusterRoleBinding(
                    api_version="rbac.authorization.k8s.io/v1",
                    metadata=kubernetes.client.V1ObjectMeta(
                        name="kubernetes-dashboard",
                        labels={"app.kubernetes.io/name": self.app.name},
                    ),
                    role_ref=kubernetes.client.V1RoleRef(
                        api_group="rbac.authorization.k8s.io",
                        kind="ClusterRole",
                        name="kubernetes-dashboard",
                    ),
                    subjects=[
                        kubernetes.client.V1Subject(
                            kind="ServiceAccount",
                            name="kubernetes-dashboard",
                            namespace=self.model.name,
                        )
                    ],
                )
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 403:
                logger.warn("ClusterRoleBinding for metrics collection not created, insufficient permissions")
                pass
            elif e.status != 409:
                raise

    def _template_meta(self, name) -> kubernetes.client.V1ObjectMeta:
        """Helper method to return common Kubernetes V1ObjectMeta"""
        return kubernetes.client.V1ObjectMeta(
            namespace=self.model.name,
            name=name,
            labels={"app.kubernetes.io/name": self.app.name},
        )

    def k8s_auth(self):
        """Authenticate to kubernetes."""
        if self._authed:
            return True
        # Remove os.environ.update when lp:1892255 is FIX_RELEASED.
        os.environ.update(
            dict(e.split("=") for e in Path("/proc/1/environ").read_text().split("\x00") if "KUBERNETES_SERVICE" in e)
        )
        # Authenticate against the Kubernetes API using a mounted ServiceAccount token
        kubernetes.config.load_incluster_config()
        # Test the service account we've got for sufficient perms
        auth_api = kubernetes.client.RbacAuthorizationV1Api(kubernetes.client.ApiClient())
        try:
            role = auth_api.read_namespaced_role(namespace=self.model.name, name=self.app.name)
        except:
            # If we can't read a namespaced role, we definitely don't have enough permissions
            self.unit.status = BlockedStatus("Run juju trust on this application to continue")
            return False

        self._authed = True
        return True


if __name__ == "__main__":
    main(KubernetesDashboardCharm)
