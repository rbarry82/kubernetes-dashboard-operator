# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from unittest.mock import Mock, patch

from charms.jnsgruk_kubernetes_dashboard.v0.cert import SelfSignedCert
from cryptography import x509
from cryptography.x509.base import Certificate

MOCK_DATE = datetime(2021, 1, 1, 15, 0, 0)
LIB = "charms.jnsgruk_kubernetes_dashboard.v0.cert.SelfSignedCert"


def _get_cert_sans(cert: Certificate):
    return cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.GeneralName)


class TestSelfSignedCertGenerator(unittest.TestCase):
    @patch(f"{LIB}._utcnow", Mock(return_value=MOCK_DATE))
    def test_create_cert_defaults(self):
        cert = SelfSignedCert(
            names=["test.local", "test.my_ns.svc.cluster.local"], ips=[IPv4Address("10.10.10.10")]
        )
        c = x509.load_pem_x509_certificate(cert.cert)

        # Check class defaults were set
        self.assertEqual(cert.validity, 365)
        self.assertTrue(c.not_valid_before == MOCK_DATE)
        self.assertTrue(c.not_valid_after == MOCK_DATE + timedelta(days=365))
        self.assertEqual(cert.key_size, 2048)
        self.assertEqual(c.public_key().key_size, 2048)

        # Check the certificate SANs
        sans = _get_cert_sans(c)
        self.assertEqual(
            sans, ["test.local", "test.my_ns.svc.cluster.local", IPv4Address("10.10.10.10")]
        )

        # Check the subject and issuer name use the first specified FQDN/name
        self.assertEqual(c.issuer.rfc4514_string(), "CN=test.local")
        self.assertEqual(c.subject.rfc4514_string(), "CN=test.local")

    def test_create_cert_defaults_no_ips(self):
        cert = SelfSignedCert(names=["test.local"])
        c = x509.load_pem_x509_certificate(cert.cert)
        # Check the certificate SANs
        sans = _get_cert_sans(c)
        self.assertEqual(sans, ["test.local"])

    @patch(f"{LIB}._utcnow", Mock(return_value=MOCK_DATE))
    def test_cert_validity_and_key_size(self):
        ssc = SelfSignedCert(
            names=["test.local"], ips=[IPv4Address("10.10.10.10")], validity=3650, key_size=4096
        )
        c = x509.load_pem_x509_certificate(ssc.cert)
        # Check that specified validity is respected
        self.assertTrue(c.not_valid_before == MOCK_DATE)
        self.assertTrue(c.not_valid_after == MOCK_DATE + timedelta(days=3650))
        # Check requested key size is respected
        self.assertEqual(c.public_key().key_size, 4096)

    def test_cert_attributes(self):
        ssc = SelfSignedCert(names=["test.local"], ips=[IPv4Address("10.10.10.10")])
        c = x509.load_pem_x509_certificate(ssc.cert)

        # Check for correct key usages
        key_usages = c.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertEqual(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            key_usages,
        )

        # Check for correct extended key usages
        ext_key_usages = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertEqual(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            ext_key_usages,
        )

        # Check the hashing algorithm
        self.assertEqual(c.signature_hash_algorithm.name, "sha256")

    def test_specify__no_names(self):
        with self.assertRaises(ValueError):
            SelfSignedCert(names=[])
