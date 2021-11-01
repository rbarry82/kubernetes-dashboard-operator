# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""TODO: Add a proper docstring here.

This is a placeholder docstring for this charm library. Docstrings are
presented on Charmhub and updated whenever you push a new version of the
library.

Complete documentation about creating and documenting libraries can be found 
in the SDK docs at https://juju.is/docs/sdk/libraries.

See `charmcraft publish-lib` and `charmcraft fetch-lib` for details of how to
share and consume charm libraries. They serve to enhance collaboration
between charmers. Use a charmer's libraries for classes that handle
integration with their charm.

Bear in mind that new revisions of the different major API versions (v0, v1,
v2 etc) are maintained independently.  You can continue to update v0 and v1
after you have pushed v3.

Markdown is supported, following the CommonMark specification.
"""

import datetime
from ipaddress import IPv4Address
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# The unique Charmhub library identifier, never change it
LIBID = "1a247bf6aa8a4e61917e89ebcab1e530"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class SelfSignedCert:
    """A class used for generating self-signed RSA TLS certificates."""

    def __init__(
        self,
        *,
        names: List[str],
        ips: List[IPv4Address] = [],
        key_size: int = 2048,
        validity: int = 365,
    ):
        """Initialise a new self-signed certificate.

        Args:
            names: A list of FQDNs that should be placed in the Subject Alternative
                Name field of the certificate. The first name in the list will be
                used as the Common Name, Subject and Issuer field.
            ips: A list of IPv4Address objects that  should be present in the list
                of Subject Alternative Names of the certificate.
            key_size: Size of the RSA Private Key to be generated. Defaults to 2048
            validity: Period in days the certificate is valid for. Default is 365.

        Raises:
            ValueError: is raised if an empty list of names is provided to the
                constructor.
        """
        # Ensure that at least one FQDN was provided
        # TODO: Do some validation on any provided names
        if not names:
            raise ValueError("Must provide at least one name for the certificate")

        # Create a list of x509.DNSName objects from the list of FQDNs provided
        self.names = [x509.DNSName(n) for n in names]
        # Create a list of x509IPAdress objects from the list of IPv4Addresses
        self.ips = [x509.IPAddress(i) for i in ips] if ips else []
        # Initialise some values
        self.key_size = key_size
        self.validity = validity
        self.cert = None
        self.key = None
        # Generate the certificate
        self._generate()

    def _generate(self) -> None:
        """Generate a self-signed certificate."""
        # Generate a new RSA private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)
        # Set the subject/issuer to the first of the given names
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, self.names[0].value)]
        )
        # Build the cert
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=self.validity))
            .add_extension(
                x509.SubjectAlternativeName(self.names + self.ips),
                critical=False,
            )
            .add_extension(
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
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        self.cert = cert.public_bytes(serialization.Encoding.PEM)
        self.key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )