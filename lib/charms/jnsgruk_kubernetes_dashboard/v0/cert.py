# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""# Self-Signed Certificate Generator

This charm library contains a class `SelfSignedCert` which can be used for generating self-signed
RSA certificates for use in TLS connections or otherwise. It does not currently provide much
configurability, apart from the FQDN the certificate should be associated with, a list of IP
addresses to be present in the Subject Alternative Name (SAN) field, validity and key length.

By default, generated certificates are valid for 365 years, and use a 2048-bit key size.

## Getting Started

In order to use this library, you will need to fetch the library from Charmhub as normal, but you
will also need to add a dependency on the `cryptography` package to your charm:

```shell
cd some-charm
charmcraft fetch-lib charms.jnsgruk_kubernetes_dashboard.v0.cert
echo <<-EOF >> requirements.txt
cryptography
EOF
```

Once complete, you can import the charm and use it like so (in the most simple form):

```python
# ...
from charms.jnsgruk_kubernetes_dashboard.v0.cert import SelfSignedCert
from ipaddress import IPv4Address

# Generate a certificate
self_signed_cert = SelfSigned(names=["test-service.dev"], ips=[IPv4Address("10.28.0.20")])

# Bytes representing the certificate in PEM format
certificate = self_signed_cert.cert

# Bytes representing the private key in PEM/PKCS8 format
key = self_signed_cert.key
```

You can also specify the validity period in days, and the required key size. The algorithm is
always RSA:

```python
# ...
from charms.jnsgruk_kubernetes_dashboard.v0.cert import SelfSignedCert
from ipaddress import IPv4Address

# Generate a certificate
self_signed_cert = SelfSigned(
    names=["some_app.my_namespace.svc.cluster.local"], 
    ips=[IPv4Address("10.41.150.12"), IPv4Address("192.168.0.20")],
    key_size = 4096,
    validity = 3650
)
```

"""

from datetime import datetime, timedelta
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
LIBPATCH = 2


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
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=self.validity))
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
