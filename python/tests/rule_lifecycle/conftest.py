# Copyright (c) Peter Morrow

"""
Fixtures for rule lifecycle (TTL, schedule, event stream) tests.

All lifecycle tests use GraphQL directly — the CLI client is also exercised
for the basic TTL/managed-rules path to keep CLI parity.
"""

import logging
import time
from typing import Union

import netaddr
import pytest

from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.engine.cli.client import PolicyClient, PolicyAction
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient


logger = logging.getLogger(__name__)

_POLICY_ENGINE_URL = "http://127.0.0.1:8080/graphql"
_HTTP_READY_TIMEOUT = 30
_HTTP_READY_INTERVAL = 0.5


def _wait_for_policy_engine_http(server, timeout: int = _HTTP_READY_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = server.ssh_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--max-time 2 {_POLICY_ENGINE_URL} 2>/dev/null || true",
                timeout=10,
            )
            if out.strip() and out.strip() != "000":
                logger.info("policy-engine HTTP server is ready")
                return
        except Exception:
            pass
        time.sleep(_HTTP_READY_INTERVAL)
    pytest.fail(f"policy-engine HTTP server did not become ready within {timeout}s")


AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """Start policy-engine once for all lifecycle tests, stop after."""
    server = nodes["server"]

    check_result = server.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check_result:
        pytest.skip(
            "policy-engine.service not installed (check 'packages' in the topology yaml)"
        )

    try:
        server.ssh_command(
            "sudo systemctl stop suricata 2>/dev/null || true && "
            "sudo systemctl disable suricata 2>/dev/null || true",
            timeout=15,
        )
    except Exception:
        pass

    status = restart_service(server, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine: {status.status_text}")

    _wait_for_policy_engine_http(server)
    yield status

    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


@pytest.fixture(scope="package")
def nmap_installed(nodes, install_packages):
    """Ensure nmap (nping) is installed on the client for traffic tests."""
    install_packages("client", ["nmap"])
    yield


@pytest.fixture(scope="package")
def websocket_installed(nodes, install_packages):
    """Ensure python3-websocket is installed on the server for WS event tests."""
    install_packages("server", ["python3-websocket"])
    yield


@pytest.fixture(scope="package")
def graphql_client(nodes, policy_engine_service) -> GraphQLPolicyClient:
    """GraphQL client bound to the server node."""
    return GraphQLPolicyClient(nodes["server"])


@pytest.fixture(scope="package")
def cli_client(nodes, policy_engine_service) -> PolicyClient:
    """CLI client bound to the server node."""
    return PolicyClient(nodes["server"])


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    """Server's interface on net1."""
    return node_interfaces["server"]["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    """Client's interface on net1."""
    return node_interfaces["client"]["net1"]


@pytest.fixture(scope="package")
def server_ip_v4(server_interface) -> netaddr.IPAddress:
    ip = server_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address on server interface")
    return ip


@pytest.fixture(scope="package")
def client_ip_v4(client_interface) -> netaddr.IPAddress:
    ip = client_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address on client interface")
    return ip


@pytest.fixture(scope="package")
def client_network_v4(client_interface) -> str:
    net = client_interface.get_ipv4_network()
    if net is None:
        pytest.skip("No IPv4 network on client interface")
    return str(net)


@pytest.fixture(scope="package")
def attached_ingress(graphql_client, server_interface, configure_node_interfaces):
    """Attach ingress XDP program for the duration of the package."""
    iface = server_interface.if_name
    result = graphql_client.attach_ingress(iface)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")
    yield iface
    try:
        graphql_client.detach_ingress(iface)
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


def _full_cleanup(graphql_client, iface: str):
    """Flush BPF rules, delete all managed rules, and reset default action."""
    graphql_client.flush_rules(direction="ingress")
    for mr in graphql_client.managed_rules(direction="ingress"):
        graphql_client.delete_rule(iface, rule_id=mr.rule_id, direction="ingress")
    graphql_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )


@pytest.fixture(scope="function")
def clean_ingress_rules(graphql_client, attached_ingress):
    """Flush BPF rules, managed rules registry, and default action before/after each test."""
    _full_cleanup(graphql_client, attached_ingress)
    yield
    _full_cleanup(graphql_client, attached_ingress)
