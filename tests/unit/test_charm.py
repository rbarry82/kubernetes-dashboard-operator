# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.


import unittest
from glob import glob
from io import BufferedReader, BytesIO
from ipaddress import IPv4Address
from pathlib import Path
from unittest.mock import MagicMock, Mock, PropertyMock, mock_open, patch

import lightkube
from cryptography import x509
from lightkube import codecs
from lightkube.core.exceptions import ApiError
from lightkube.models.apps_v1 import StatefulSet, StatefulSetSpec
from lightkube.models.core_v1 import (
    Container,
    EmptyDirVolumeSource,
    ObjectReference,
    PodSpec,
    PodTemplateSpec,
    SecretVolumeSource,
    Service,
    ServiceSpec,
    Volume,
    VolumeMount,
)
from lightkube.models.meta_v1 import LabelSelector, ObjectMeta
from lightkube.resources.core_v1 import ServiceAccount
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from ops.pebble import ChangeError
from ops.testing import Harness

from cert import SelfSignedCert
from charm import KubernetesDashboardCharm


class _FakeResponse:
    """Used to fake an httpx response during testing only."""

    def __init__(self, code):
        self.code = code

    def json(self):
        return {"apiVersion": 1, "code": self.code, "message": "broken"}


class _FakeApiError(ApiError):
    """Used to simulate an ApiError during testing."""

    def __init__(self, code=400):
        super().__init__(response=_FakeResponse(code))


@patch("lightkube.core.client.GenericSyncClient", Mock)
class TestCharm(unittest.TestCase):
    @patch("charm.KubernetesServicePatch", lambda x, y: None)
    @patch("charm.KubernetesDashboardCharm._namespace", "dashboard")
    def setUp(self) -> None:
        self.harness = Harness(KubernetesDashboardCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch("charm.KubernetesDashboardCharm._create_kubernetes_resources")
    def test_install_event(self, create):
        self.harness.charm.on.install.emit()
        create.assert_called_once()

        create.side_effect = _FakeApiError()
        with self.assertLogs("charm") as logs:
            self.harness.charm.on.install.emit()
            self.assertTrue(len(logs) > 0)

        self.assertEqual(
            self.harness.charm.unit.status, BlockedStatus("kubernetes resource creation failed")
        )

    @patch("charm.Client.create")
    @patch("charm.ApiError", _FakeApiError)
    def test_create_kubernetes_resources(self, client: MagicMock):
        self.harness.charm._context = {
            "namespace": "dashboard",
            "app_name": "jnsgruk-kubernetes-dashboard",
        }

        result = self.harness.charm._create_kubernetes_resources()
        self.assertTrue(result)

        # Construct a list of resources that should have been created
        resources = []
        for manifest in glob("src/templates/*.yaml.j2"):
            with open(manifest) as f:
                resources.extend([r for r in codecs.load_all_yaml(f, self.harness.charm._context)])

        # Ensure that all of the resources in the template directory are created
        for resource in resources:
            client.assert_any_call(resource)

        # Ensure that any encountered ApiErrors are raised from the function if encountered
        client.side_effect = _FakeApiError()
        with self.assertRaises(ApiError):
            self.harness.charm._create_kubernetes_resources()

        # Check that when the exception is raised, there is appropriate logging
        with self.assertLogs("charm", "DEBUG") as logs:
            try:
                self.harness.charm._create_kubernetes_resources()
            except ApiError:
                self.assertIn("failed to create resource:", ";".join(logs.output))

    @patch("charm.KubernetesDashboardCharm._configure_dashboard")
    @patch("charm.KubernetesDashboardCharm._statefulset_patched", new_callable=PropertyMock)
    @patch("charm.KubernetesDashboardCharm._patch_statefulset", lambda x: False)
    def test_dashboard_pebble_ready(self, patched, conf):
        self.assertEqual(self.harness.get_container_pebble_plan("dashboard")._services, {})

        # First test before the statefulset is patched
        patched.return_value = False
        self.harness.container_pebble_ready("dashboard")
        self.assertEqual(
            self.harness.charm.unit.status, MaintenanceStatus("waiting for changes to apply")
        )
        self.assertEqual(self.harness.get_container_pebble_plan("dashboard")._services, {})
        conf.assert_not_called()

        # Now after it's been patched
        patched.return_value = True
        conf.return_value = True
        self.harness.container_pebble_ready("dashboard")
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

        # Now after it's been patched, but configuring fails
        patched.return_value = True
        conf.return_value = False
        with self.assertLogs("charm", "INFO") as logs:
            self.harness.container_pebble_ready("dashboard")
            self.assertIn(
                "pebble socket not available, deferring config-changed dashboard start.",
                ";".join(logs.output),
            )

        self.assertEqual(
            self.harness.charm.unit.status, WaitingStatus("waiting for pebble socket")
        )

    def test_scraper_pebble_ready(self):
        self.assertEqual(self.harness.get_container_pebble_plan("scraper")._services, {})
        self.harness.container_pebble_ready("scraper")
        expected = {"scraper": {"override": "replace", "command": "/metrics-sidecar"}}
        self.assertEqual(self.harness.get_container_pebble_plan("scraper")._services, expected)

        with patch("ops.model.Container.start") as start:
            start.side_effect = ChangeError("borked", Mock())
            with self.assertLogs("charm", "WARNING") as logs:
                self.harness.container_pebble_ready("scraper")
                self.assertIn(
                    "unable to start scraper service, container may be restarting.",
                    ";".join(logs.output),
                )

        with patch("ops.model.Container.start") as start:
            start.side_effect = FileNotFoundError()
            with self.assertLogs("charm", "WARNING") as logs:
                self.harness.container_pebble_ready("scraper")
                self.assertIn(
                    "unable to start scraper service, container may be restarting.",
                    ";".join(logs.output),
                )

    @patch("charm.KubernetesDashboardCharm._configure_tls_certs")
    @patch("charm.KubernetesDashboardCharm._namespace", "dashboard")
    def test_configure_dashboard(self, certs):
        # setup the charm with no initial command in storedstate
        cmd = self.harness.charm._dashboard_cmd
        self.assertEqual(self.harness.charm._stored.dashboard_cmd, "")
        self.assertEqual(self.harness.get_container_pebble_plan("dashboard")._services, {})

        with self.assertLogs("charm", "DEBUG") as logs:
            result = self.harness.charm._configure_dashboard()
            msg = f"starting Kubernetes Dashboard with command: '{cmd}'."
            self.assertIn(msg, ";".join(logs.output))

        self.assertEqual(self.harness.charm._stored.dashboard_cmd, cmd)
        self.assertEqual(
            self.harness.get_container_pebble_plan("dashboard")._services,
            {"dashboard": {"override": "replace", "command": cmd}},
        )
        certs.assert_called_once()
        self.assertTrue(result)

        # Check the service doesn't restart if command hasn't changed
        certs.reset_mock()
        self.assertEqual(self.harness.charm._stored.dashboard_cmd, cmd)
        result = self.harness.charm._configure_dashboard()
        certs.assert_not_called()
        self.assertTrue(result)

        # Check we return false when the charm cannot connect to pebble
        self.harness.charm._stored.dashboard_cmd = "foobar"
        with patch("ops.model.Container.can_connect", lambda x: False):
            result = self.harness.charm._configure_dashboard()

        self.assertFalse(result)
        certs.assert_not_called()

    @patch("charm.KubernetesDashboardCharm._namespace", "dashboard")
    def test_property_dashboard_cmd(self):
        expected = (
            "/dashboard --bind-address=0.0.0.0 --sidecar-host=http://localhost:8000 "
            "--namespace=dashboard --default-cert-dir=/certs --tls-cert-file=tls.crt "
            "--tls-key-file=tls.key"
        )
        self.assertEqual(self.harness.charm._dashboard_cmd, expected)

    @patch("cert.SelfSignedCert")
    @patch("charm.KubernetesDashboardCharm._pod_ip", new_callable=PropertyMock)
    @patch("ops.model.Container.make_dir")
    @patch("ops.model.Container.list_files")
    @patch("ops.model.Container.push")
    @patch("ops.model.Container.pull")
    @patch("charm.KubernetesDashboardCharm._validate_certificate")
    @patch("charm.Client.get")
    @patch("charm.KubernetesDashboardCharm._namespace", "dashboard")
    def test_configure_tls_certs(self, get, validate, pull, push, list, mkdir, pod_ip, cert):
        pod_ip.return_value = IPv4Address("10.10.10.10")

        class FakeCertFileInfo:
            name = "tls.crt"

        class FakeCert:
            key = b"deadbeef"
            cert = b"deadbeef"

        cert.return_value = FakeCert()

        # Test the case where a tls.crt is already present in the container, and is valid
        validate.return_value = True
        list.return_value = [FakeCertFileInfo()]

        pem_lines = [
            "-----BEGIN CERTIFICATE-----",
            "MIICAzCCAWygAwIBAgIUTJSwoez33b1TdWe7efN6hx9KTYwwDQYJKoZIhvcNAQEL",
            "BQAwFTETMBEGA1UEAwwKdGVzdC5sb2NhbDAgFw0yMTEwMjgwODIxMTRaGA8yMjk1",
            "MDgxMjA4MjExNFowFTETMBEGA1UEAwwKdGVzdC5sb2NhbDCBnzANBgkqhkiG9w0B",
            "AQEFAAOBjQAwgYkCgYEAspZlj/LXllb/DzaUv2DlqBqezrtn3EXwI5gD0N4yABcB",
            "YqfYDDdvz+KIUnk2elFYZGUf47ii5RvsM6n6C9IVxM94C7Dt5Diqwd4zJQVxpO0U",
            "fZ/AA+Qk+ExL+3ZHfIOjlgPIP63en55wOzs4gwptIQlwcrCd0rGNTO2ZLPu4pW0C",
            "AwEAAaNOMEwwGwYDVR0RBBQwEoIKdGVzdC5sb2NhbIcEAQEBATAOBgNVHQ8BAf8E",
            "BAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA0GCSqGSIb3DQEB",
            "CwUAA4GBAKP//FlwEUT0jPO8VAdhKvz3Zil3XbLHvV9kajtN6G/twfhDiNden7xS",
            "DSsK9Cg+Jmh5JeHKQ9x++SfMWNbKy+ans/acmdyaiEmj2sP3mB2oHyQkGvwDj+XO",
            "rFGTuo446/dd8mhlfv55m/NZwut3ZXNVpLoKnYBYEv/qtGgDqCBn",
            "-----END CERTIFICATE-----",
        ]
        pull.return_value = BytesIO("\n".join(pem_lines).encode())

        self.harness.charm._configure_tls_certs()
        # Ensure that we try to create a directory for the certificates
        mkdir.assert_called_with("/certs", make_parents=True)
        pull.assert_called_with("/certs/tls.crt")
        validate.assert_called_with(x509.load_pem_x509_certificate("\n".join(pem_lines).encode()))
        get.assert_not_called()

        # Test the case where a tls.crt is already present in the container, and is invalid
        validate.return_value = False
        pull.return_value = BytesIO("\n".join(pem_lines).encode())
        get.return_value = Service(spec=ServiceSpec(clusterIP="1.1.1.1"))
        self.harness.charm._configure_tls_certs()
        get.assert_called_once()
        cert.assert_called_with(
            names=["jnsgruk-kubernetes-dashboard.dashboard.svc.cluster.local"],
            ips=[IPv4Address("10.10.10.10"), IPv4Address("1.1.1.1")],
        )
        push.assert_any_call("/certs/tls.crt", b"deadbeef")
        push.assert_any_call("/certs/tls.key", b"deadbeef")

    @patch("charm.Client.get")
    @patch("charm.Client.patch")
    @patch("charm.KubernetesDashboardCharm._dashboard_volumes", new_callable=PropertyMock)
    @patch("charm.KubernetesDashboardCharm._namespace", "dashboard")
    def test_patch_statefulset(self, volumes, patch, get):
        initial_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector([]),
                serviceName="dashboard",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(),
                    spec=PodSpec(
                        containers=[
                            Container(name="charm"),
                            Container(name="dashboard", volumeMounts=[]),
                            Container(name="scraper", volumeMounts=[]),
                        ],
                        volumes=[],
                    ),
                ),
            )
        )

        dashboard_volumes = [
            Volume(
                name="kubernetes-dashboard-service-account",
                secret=SecretVolumeSource(secretName="dashboard-secret"),
            ),
            Volume(name="tmp-volume-metrics", emptyDir=EmptyDirVolumeSource(medium="Memory")),
            Volume(name="tmp-volume-dashboard", emptyDir=EmptyDirVolumeSource()),
        ]

        volumes.return_value = dashboard_volumes
        get.return_value = initial_statefulset

        with self.assertLogs("charm", "INFO") as logs:
            self.harness.charm._patch_statefulset()
            self.assertIn(
                "patched StatefulSet to include additional volumes and mounts.",
                ";".join(logs.output),
            )

        expected = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector([]),
                serviceName="dashboard",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(),
                    spec=PodSpec(
                        containers=[
                            Container(name="charm"),
                            Container(
                                name="dashboard",
                                volumeMounts=[
                                    VolumeMount(mountPath="/tmp", name="tmp-volume-dashboard"),
                                    VolumeMount(
                                        mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                                        name="kubernetes-dashboard-service-account",
                                    ),
                                ],
                            ),
                            Container(
                                name="scraper",
                                volumeMounts=[
                                    VolumeMount(mountPath="/tmp", name="tmp-volume-metrics"),
                                    VolumeMount(
                                        mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                                        name="kubernetes-dashboard-service-account",
                                    ),
                                ],
                            ),
                        ],
                        volumes=[
                            Volume(
                                name="kubernetes-dashboard-service-account",
                                secret=SecretVolumeSource(secretName="dashboard-secret"),
                            ),
                            Volume(
                                name="tmp-volume-metrics",
                                emptyDir=EmptyDirVolumeSource(medium="Memory"),
                            ),
                            Volume(name="tmp-volume-dashboard", emptyDir=EmptyDirVolumeSource()),
                        ],
                    ),
                ),
            )
        )
        patch.assert_called_with(
            lightkube.resources.apps_v1.StatefulSet,
            name="jnsgruk-kubernetes-dashboard",
            obj=expected,
            namespace="dashboard",
        )

    @patch("charm.KubernetesDashboardCharm._pod_ip", IPv4Address("10.10.10.10"))
    def test_validate_certificates(self):
        certificate = SelfSignedCert(names=["dashboard.dev"], ips=[IPv4Address("10.10.10.10")])
        c = x509.load_pem_x509_certificate(certificate.cert)
        result = self.harness.charm._validate_certificate(c)
        self.assertTrue(result)

        # Test that validity fails when pod ip not in list of SANs
        certificate = SelfSignedCert(names=["dashboard.dev"], ips=[IPv4Address("8.8.8.8")])
        c = x509.load_pem_x509_certificate(certificate.cert)
        result = self.harness.charm._validate_certificate(c)
        self.assertFalse(result)

        # TODO: Fashion a test for time expired certificates

    @patch("charm.check_output", lambda x: b"10.10.10.10\n")
    def test_property_pod_ip(self):
        self.assertEqual(self.harness.charm._pod_ip, IPv4Address("10.10.10.10"))

    @patch("builtins.open", new_callable=mock_open, read_data="dashboard")
    def test_property_namespace(self, mock):
        self.assertEqual(self.harness.charm._namespace, "dashboard")
        mock.assert_called_with("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r")

    @patch("charm.Client.get")
    @patch("charm.KubernetesDashboardCharm._namespace", "dashboard")
    def test_property_stateful_set_patched(self, client):
        expected = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector([]),
                serviceName="dashboard",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(),
                    spec=PodSpec(
                        containers=[
                            Container(name="charm"),
                            Container(
                                name="dashboard",
                                volumeMounts=[
                                    VolumeMount(mountPath="/tmp", name="tmp-volume-dashboard")
                                ],
                            ),
                        ]
                    ),
                ),
            )
        )

        client.return_value = expected
        self.assertTrue(self.harness.charm._statefulset_patched)

        expected.spec.template.spec.containers[1].volumeMounts = []
        self.assertFalse(self.harness.charm._statefulset_patched)

    def test_property_metrics_scraper_volume_mounts(self):
        expected = [
            VolumeMount(mountPath="/tmp", name="tmp-volume-metrics"),
            VolumeMount(
                mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]
        self.assertEqual(self.harness.charm._metrics_scraper_volume_mounts, expected)

    def test_property_dashboard_volume_mounts(self):
        expected = [
            VolumeMount(mountPath="/tmp", name="tmp-volume-dashboard"),
            VolumeMount(
                mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]
        self.assertEqual(self.harness.charm._dashboard_volume_mounts, expected)

    @patch("charm.Client.get")
    @patch("charm.KubernetesDashboardCharm._namespace", "dashboard")
    def test_property_dashboard_volumes(self, client):
        client.return_value = ServiceAccount(
            metadata=ObjectMeta(name="kubernetes-dashboard"),
            secrets=[ObjectReference(name="dashboard-secret")],
        )

        expected = [
            Volume(
                name="kubernetes-dashboard-service-account",
                secret=SecretVolumeSource(secretName="dashboard-secret"),
            ),
            Volume(name="tmp-volume-metrics", emptyDir=EmptyDirVolumeSource(medium="Memory")),
            Volume(name="tmp-volume-dashboard", emptyDir=EmptyDirVolumeSource()),
        ]
        self.assertEqual(self.harness.charm._dashboard_volumes, expected)
