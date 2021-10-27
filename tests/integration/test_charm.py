#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import ssl
import urllib.request
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
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
    await ops_test.model.set_config({"update-status-hook-interval": "10s"})

    await ops_test.model.wait_for_idle(apps=["dashboard"], status="active", timeout=1000)
    assert ops_test.model.applications["dashboard"].units[0].workload_status == "active"

    # effectively disable the update status from firing
    await ops_test.model.set_config({"update-status-hook-interval": "60m"})


@pytest.mark.abort_on_fail
async def test_dashboard_is_up(ops_test):
    status = await ops_test.model.get_status()  # noqa: F821
    address = status["applications"]["dashboard"]["units"]["dashboard/0"]["address"]

    url = f"https://{address}:8443"
    logger.info("dashboard public address: https://%s", url)

    response = urllib.request.urlopen(
        url, data=None, timeout=2.0, context=ssl._create_unverified_context()
    )
    assert response.code == 200
