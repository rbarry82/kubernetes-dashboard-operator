#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import ssl
import urllib.request
from pathlib import Path

import pytest
import yaml
from lightkube import Client
from lightkube.resources.core_v1 import ConfigMap, Secret, Service, ServiceAccount
from lightkube.resources.rbac_authorization_v1 import (
    ClusterRole,
    ClusterRoleBinding,
    Role,
    RoleBinding,
)
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    # build and deploy charm from local source folder
    charm = await ops_test.build_charm(".")
    resources = {
        "dashboard-image": METADATA["resources"]["dashboard-image"]["upstream-source"],
        "scraper-image": METADATA["resources"]["scraper-image"]["upstream-source"],
    }
    await ops_test.model.deploy(
        charm, resources=resources, application_name="dashboard", trust=True
    )

    # issuing dummy update_status just to trigger an event
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(apps=["dashboard"], status="active", timeout=1000)
        assert ops_test.model.applications["dashboard"].units[0].workload_status == "active"


@pytest.mark.abort_on_fail
async def test_kubernetes_resources_created(ops_test: OpsTest):
    client = Client()
    # A slightly naive test that ensures the relevant Kubernetes resources were created.
    # If any of these fail, an exception is raised and the test will fail
    client.get(ClusterRole, name="kubernetes_dashboard")
    client.get(ClusterRoleBinding, name="kubernetes_dashboard")
    client.get(ConfigMap, name="kubernetes-dashboard-settings", namespace=ops_test.model_name)
    client.get(Role, name="kubernetes-dashboard", namespace=ops_test.model_name)
    client.get(RoleBinding, name="kubernetes-dashboard", namespace=ops_test.model_name)
    client.get(Secret, name="kubernetes-dashboard-csrf", namespace=ops_test.model_name)
    client.get(Secret, name="kubernetes-dashboard-key-holder", namespace=ops_test.model_name)
    client.get(ServiceAccount, name="kubernetes-dashboard", namespace=ops_test.model_name)
    client.get(Service, name="dashboard-metrics-scraper", namespace=ops_test.model_name)


@pytest.mark.abort_on_fail
async def test_dashboard_is_up(ops_test: OpsTest):
    status = await ops_test.model.get_status()  # noqa: F821
    address = status["applications"]["dashboard"]["units"]["dashboard/0"]["address"]

    url = f"https://{address}:8443"
    logger.info("dashboard public address: https://%s", url)

    response = urllib.request.urlopen(
        url, data=None, timeout=2.0, context=ssl._create_unverified_context()
    )
    assert response.code == 200
