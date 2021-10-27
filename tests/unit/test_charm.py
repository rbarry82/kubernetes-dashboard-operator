# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import patch

from ops.testing import Harness

from charm import KubernetesDashboardCharm


class TestCharm(unittest.TestCase):
    @patch("charm.KubernetesServicePatch", lambda x, y: None)
    def setUp(self) -> None:
        self.harness = Harness(KubernetesDashboardCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_fix_me(self):
        self.assertTrue(True)
