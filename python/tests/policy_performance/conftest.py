# Copyright (c) Dufferin Software

import pytest

from tests.policy_sanity.conftest import (  # noqa: F401
    attached_egress,
    attached_ingress,
    bpftool_installed,
    cli_policy_client,
    client_interface,
    client_network_v4,
    client_network_v6,
    client_ip_v4,
    client_ip_v6,
    client_type,
    graphql_policy_client,
    nmap_installed,
    nmap_installed_server,
    policy_client,
    policy_engine_service,
    server_interface,
    server_ip_v4,
    server_ip_v6,
    server_network_v4,
    server_network_v6,
    websocket_installed,
)


@pytest.fixture(scope="function")
def clean_rules(policy_client):  # noqa: F811
    """Ensure rules are cleaned up before and after each test."""
    policy_client.flush_rules()
    yield
    policy_client.flush_rules()
