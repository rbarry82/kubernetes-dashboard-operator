# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.


import unittest
from glob import glob
from io import BytesIO
from ipaddress import IPv4Address
from types import SimpleNamespace
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
from ops.pebble import APIError, ChangeError, ConnectionError
from ops.testing import Harness

from cert import SelfSignedCert
from charm import KubernetesDashboardCharm

CHARM = "charm.KubernetesDashboardCharm"

TEST_CERTIFICATE = "\n".join(
    [
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
).encode()


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
@patch(f"{CHARM}._namespace", "dashboard")
@patch(f"{CHARM}._pod_ip", PropertyMock(return_value=IPv4Address("10.10.10.10")))
class TestCharm(unittest.TestCase):
    @patch("charm.KubernetesServicePatch", lambda x, y: None)
    @patch(f"{CHARM}._namespace", "dashboard")
    def setUp(self) -> None:
        self.harness = Harness(KubernetesDashboardCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm

    @patch(f"{CHARM}._create_kubernetes_resources")
    def test_install_event_successful(self, create):
        self.charm.on.install.emit()
        self.assertIn(
            ("status_set", "maintenance", "creating kubernetes resources", {"is_app": False}),
            self.harness._get_backend_calls(),
        )
        create.assert_called_once()

    @patch(f"{CHARM}._create_kubernetes_resources", Mock(side_effect=_FakeApiError))
    def test_install_event_fail(self):
        with self.assertLogs("charm") as logs:
            self.charm.on.install.emit()
            self.assertTrue(len(logs) > 0)

        self.assertIn(
            ("status_set", "maintenance", "creating kubernetes resources", {"is_app": False}),
            self.harness._get_backend_calls(),
        )
        self.assertEqual(
            self.charm.unit.status, BlockedStatus("kubernetes resource creation failed")
        )

    @patch(f"{CHARM}._configure_dashboard")
    @patch(f"{CHARM}._patch_statefulset")
    @patch(f"{CHARM}._statefulset_patched", PropertyMock(return_value=False))
    def test_dashboard_pebble_ready_unpatched(self, patch, conf):
        patch.return_value = True
        self.harness.container_pebble_ready("dashboard")
        self.assertEqual(self.charm.unit.status, MaintenanceStatus("waiting for changes to apply"))
        # Check we tried to patch the StatefulSet
        patch.assert_called_once()
        # Check the method returned without trying to configure the dashboard
        conf.assert_not_called()

    @patch(f"{CHARM}._configure_dashboard")
    @patch(f"{CHARM}._statefulset_patched", PropertyMock(return_value=True))
    def test_dashboard_pebble_ready_patched_fail_to_configure(self, conf):
        conf.return_value = False
        with self.assertLogs("charm", "INFO") as logs:
            self.harness.container_pebble_ready("dashboard")
            self.assertIn(
                "pebble socket not available, deferring config-changed dashboard start.",
                ";".join(logs.output),
            )
        conf.assert_called_once()
        self.assertEqual(self.charm.unit.status, WaitingStatus("waiting for pebble socket"))

    @patch(f"{CHARM}._configure_dashboard")
    @patch(f"{CHARM}._statefulset_patched", PropertyMock(return_value=True))
    def test_dashboard_pebble_ready_patched_successful_configure(self, conf):
        conf.return_value = True
        self.harness.container_pebble_ready("dashboard")
        conf.assert_called_once()
        self.assertEqual(self.charm.unit.status, ActiveStatus())

    def test_scraper_pebble_ready_success(self):
        self.assertEqual(self.harness.get_container_pebble_plan("scraper")._services, {})
        self.harness.container_pebble_ready("scraper")
        expected = {"scraper": {"override": "replace", "command": "/metrics-sidecar"}}
        self.assertEqual(self.harness.get_container_pebble_plan("scraper")._services, expected)

    def test_scraper_pebble_ready_fail(self):
        exceptions = [
            ChangeError("", Mock()),
            FileNotFoundError,
            ConnectionError,
            APIError("", 1, "", ""),
        ]

        err_msg = "unable to start scraper service, container may be restarting."
        for e in exceptions:
            with patch("ops.model.Container.start", Mock(side_effect=e)):
                with self.assertLogs("charm", "WARNING") as logs:
                    self.harness.container_pebble_ready("scraper")
                    self.assertIn(err_msg, ";".join(logs.output))

    @patch(f"{CHARM}._configure_tls_certs")
    def test_configure_dashboard_success(self, certs):
        # setup the charm with no initial command in storedstate
        cmd = self.charm._dashboard_cmd
        self.assertEqual(self.charm._stored.dashboard_cmd, "")
        self.assertEqual(self.harness.get_container_pebble_plan("dashboard")._services, {})

        with self.assertLogs("charm", "DEBUG") as logs:
            result = self.charm._configure_dashboard()
            msg = f"starting Kubernetes Dashboard with command: '{cmd}'."
            self.assertIn(msg, ";".join(logs.output))

        self.assertEqual(self.charm._stored.dashboard_cmd, cmd)
        self.assertEqual(
            self.harness.get_container_pebble_plan("dashboard")._services,
            {"dashboard": {"override": "replace", "command": cmd}},
        )
        certs.assert_called_once()
        self.assertTrue(result)

    @patch(f"{CHARM}._configure_tls_certs")
    def test_configure_dashboard_no_change(self, certs):
        self.charm._stored.dashboard_cmd = "foobar"
        with patch(f"{CHARM}._dashboard_cmd", "foobar"):
            result = self.charm._configure_dashboard()
        certs.assert_not_called()
        self.assertTrue(result)

    @patch(f"{CHARM}._configure_tls_certs")
    def test_configure_dashboard_no_pebble_connection(self, certs):
        # Check we return false when the charm cannot connect to pebble
        self.charm._stored.dashboard_cmd = "foobar"
        with patch("ops.model.Container.can_connect", lambda x: False):
            result = self.charm._configure_dashboard()
        self.assertFalse(result)
        certs.assert_not_called()

    def test_property_dashboard_cmd(self):
        expected = (
            "/dashboard --bind-address=0.0.0.0 --sidecar-host=http://localhost:8000 "
            "--namespace=dashboard --default-cert-dir=/certs --tls-cert-file=tls.crt "
            "--tls-key-file=tls.key"
        )
        self.assertEqual(self.charm._dashboard_cmd, expected)

    @patch("ops.model.Container.make_dir")
    @patch("ops.model.Container.pull")
    @patch(f"{CHARM}._validate_certificate")
    @patch("ops.model.Container.list_files", Mock(return_value=[SimpleNamespace(name="tls.crt")]))
    def test_configure_tls_certs_already_present_and_valid(self, validate, pull, mkdir):
        validate.return_value = True
        pull.return_value = BytesIO(TEST_CERTIFICATE)

        self.charm._configure_tls_certs()

        # Ensure that we try to create a directory for the certificates
        mkdir.assert_called_with("/certs", make_parents=True)
        pull.assert_called_with("/certs/tls.crt")
        validate.assert_called_with(x509.load_pem_x509_certificate(TEST_CERTIFICATE))

    @patch("cert.SelfSignedCert")
    @patch("ops.model.Container.push")
    @patch("ops.model.Container.make_dir", Mock(return_value=True))
    @patch("ops.model.Container.list_files", Mock(return_value=[SimpleNamespace(name="tls.crt")]))
    @patch("ops.model.Container.pull", Mock(return_value=BytesIO(TEST_CERTIFICATE)))
    @patch(f"{CHARM}._validate_certificate", lambda x, y: False)
    @patch("charm.Client.get", Mock(return_value=Service(spec=ServiceSpec(clusterIP="1.1.1.1"))))
    def test_configure_tls_certs_already_present_and_invalid(self, push, cert):
        cert.return_value = SimpleNamespace(key=b"deadbeef", cert=b"deadbeef")
        self.charm._configure_tls_certs()
        cert.assert_called_with(
            names=["jnsgruk-kubernetes-dashboard.dashboard.svc.cluster.local"],
            ips=[IPv4Address("10.10.10.10"), IPv4Address("1.1.1.1")],
        )
        push.assert_any_call("/certs/tls.crt", b"deadbeef")
        push.assert_any_call("/certs/tls.key", b"deadbeef")

    @patch("cert.SelfSignedCert")
    @patch("ops.model.Container.make_dir", Mock(return_value=True))
    @patch("ops.model.Container.list_files")
    @patch("ops.model.Container.push")
    @patch("ops.model.Container.pull")
    @patch("charm.Client.get")
    def test_configure_tls_certs_not_present(self, get, pull, push, list, cert):
        cert.return_value = SimpleNamespace(key=b"deadbeef", cert=b"deadbeef")
        list.return_value = []
        get.return_value = Service(spec=ServiceSpec(clusterIP="1.1.1.1"))
        self.charm._configure_tls_certs()
        pull.assert_not_called()
        get.assert_called_once()
        cert.assert_called_with(
            names=["jnsgruk-kubernetes-dashboard.dashboard.svc.cluster.local"],
            ips=[IPv4Address("10.10.10.10"), IPv4Address("1.1.1.1")],
        )
        push.assert_any_call("/certs/tls.crt", b"deadbeef")
        push.assert_any_call("/certs/tls.key", b"deadbeef")

    @patch("charm.Client.get")
    @patch("charm.Client.patch")
    @patch(f"{CHARM}._dashboard_volumes", new_callable=PropertyMock)
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

        volumes.return_value = [
            Volume(
                name="kubernetes-dashboard-service-account",
                secret=SecretVolumeSource(secretName="dashboard-secret"),
            ),
            Volume(name="tmp-volume-metrics", emptyDir=EmptyDirVolumeSource(medium="Memory")),
            Volume(name="tmp-volume-dashboard", emptyDir=EmptyDirVolumeSource()),
        ]
        get.return_value = initial_statefulset

        with self.assertLogs("charm", "INFO") as logs:
            self.charm._patch_statefulset()
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

    @patch("charm.Client.create")
    def test_create_kubernetes_resources_success(self, client: MagicMock):
        self.charm._context = {
            "namespace": "dashboard",
            "app_name": "jnsgruk-kubernetes-dashboard",
        }

        result = self.charm._create_kubernetes_resources()
        self.assertTrue(result)

        # Construct a list of resources that should have been created
        resources = []
        for manifest in glob("src/templates/*.yaml.j2"):
            with open(manifest) as f:
                resources.extend([r for r in codecs.load_all_yaml(f, self.charm._context)])

        # Ensure that all of the resources in the template directory are created
        for resource in resources:
            client.assert_any_call(resource)

    @patch("charm.Client.create")
    @patch("charm.ApiError", _FakeApiError)
    def test_create_kubernetes_resources_failure(self, client: MagicMock):
        client.side_effect = _FakeApiError()
        with self.assertRaises(ApiError):
            self.charm._create_kubernetes_resources()

        # Check that when the exception is raised, there is appropriate logging
        with self.assertLogs("charm", "DEBUG") as logs:
            try:
                self.charm._create_kubernetes_resources()
            except ApiError:
                self.assertIn("failed to create resource:", ";".join(logs.output))

    def test_validate_certificates_success(self):
        certificate = SelfSignedCert(names=["dashboard.dev"], ips=[IPv4Address("10.10.10.10")])
        result = self.charm._validate_certificate(x509.load_pem_x509_certificate(certificate.cert))
        self.assertTrue(result)

    def test_validate_certificates_failure_time_expired(self):
        expired = "\n".join(
            [
                "-----BEGIN CERTIFICATE-----",
                "MIICCjCCAXOgAwIBAgIUHF55GZlSOf5XvIdrTzN9is1QCx0wDQYJKoZIhvcNAQEL",
                "BQAwGDEWMBQGA1UEAwwNZGFzaGJvYXJkLmRldjAeFw0yMDEwMjgwODUwMDlaFw0y",
                "MTEwMTgwODUwMDlaMBgxFjAUBgNVBAMMDWRhc2hib2FyZC5kZXYwgZ8wDQYJKoZI",
                "hvcNAQEBBQADgY0AMIGJAoGBANEQnwdeU3YeX6tnaUJP14g1c2ONXIwlYEbLCSP4",
                "Eqmla7aXW+A3w+heo9xv8lx1sNWnUcevEmg2QJ9q45s9JJvDV9groSXztykdmmVd",
                "SsL4fqsMvg/BhHTYsj9JB6HyAGN0kvVFvX0MmDBJaaf2qwjO6rrN7P9ceNOCLmkC",
                "5NeZAgMBAAGjUTBPMB4GA1UdEQQXMBWCDWRhc2hib2FyZC5kZXaHBAoKCgowDgYD",
                "VR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkq",
                "hkiG9w0BAQsFAAOBgQBh+8pq4ZJ42D05HBgoUh0m3B3DxzR04hCtQ68HC7IqxNkX",
                "uJD0mSzY8p4lmmvHQ747hbqGyI47mnjrDTQgcf72H1hD9fYe650+96kBcK49/cFT",
                "3y2G8SHwBtDlU0SSnc2SSqggsgvHw7ZiOPi7fp6WBenAL+JQ8mxAFuCt0ueGNw==",
                "-----END CERTIFICATE-----",
            ]
        ).encode()
        result = self.charm._validate_certificate(x509.load_pem_x509_certificate(expired))
        self.assertFalse(result)

    def test_validate_certificates_failure_wrong_ips(self):
        certificate = SelfSignedCert(names=["dashboard.dev"], ips=[IPv4Address("8.8.8.8")])
        result = self.charm._validate_certificate(x509.load_pem_x509_certificate(certificate.cert))
        self.assertFalse(result)

    @patch("charm.Client.get")
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
        self.assertEqual(self.charm._dashboard_volumes, expected)

    def test_property_dashboard_volume_mounts(self):
        expected = [
            VolumeMount(mountPath="/tmp", name="tmp-volume-dashboard"),
            VolumeMount(
                mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]
        self.assertEqual(self.charm._dashboard_volume_mounts, expected)

    def test_property_metrics_scraper_volume_mounts(self):
        expected = [
            VolumeMount(mountPath="/tmp", name="tmp-volume-metrics"),
            VolumeMount(
                mountPath="/var/run/secrets/kubernetes.io/serviceaccount",
                name="kubernetes-dashboard-service-account",
            ),
        ]
        self.assertEqual(self.charm._metrics_scraper_volume_mounts, expected)

    @patch("charm.Client.get")
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
        self.assertTrue(self.charm._statefulset_patched)

        expected.spec.template.spec.containers[1].volumeMounts = []
        self.assertFalse(self.charm._statefulset_patched)


class TestCharmNamespaceProperty(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data="dashboard")
    @patch("charm.KubernetesServicePatch", lambda x, y: None)
    def test_property_namespace(self, mock):
        harness = Harness(KubernetesDashboardCharm)
        harness.begin()
        self.assertEqual(harness.charm._namespace, "dashboard")
        mock.assert_called_with("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r")
        harness.cleanup()


class TestCharmPodIpProperty(unittest.TestCase):
    @patch("charm.KubernetesServicePatch", lambda x, y: None)
    @patch("charm.check_output", lambda x: b"10.10.10.10\n")
    @patch(f"{CHARM}._namespace", "dashboard")
    def test_property_pod_ip(self):
        harness = Harness(KubernetesDashboardCharm)
        harness.begin()
        self.assertEqual(harness.charm._pod_ip, IPv4Address("10.10.10.10"))
        harness.cleanup()
