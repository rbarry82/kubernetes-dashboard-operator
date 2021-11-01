# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from ipaddress import IPv4Address

from charms.jnsgruk_kubernetes_dashboard.v0.cert import SelfSignedCert


class TestSelfSignedCertGenerator(unittest.TestCase):
    def setUp(self) -> None:
        pass

    def test_create_cert(self):
        cert = SelfSignedCert(names=["test.local"], ips=[IPv4Address("10.10.10.10")])
