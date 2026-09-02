# Copyright (c) Peter Morrow

"""
Fixtures for MAC matching tests.

Extends the base conftest with MAC address fixtures that read the actual
hardware MAC addresses from the VMs at test time.
"""

import logging
import re
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


def _get_mac_address(node, iface_name: str) -> str:
    """Read the MAC address of iface_name on node via 'ip link show'."""
    out = node.ssh_command(f"ip link show {iface_name}", timeout=10)
    # Look for "link/ether aa:bb:cc:dd:ee:ff"
    m = re.search(r"link/ether\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})", out, re.IGNORECASE)
    if not m:
        pytest.fail(
            f"Could not parse MAC address for {iface_name} on {node.name}: {out!r}"
        )
    return m.group(1).lower()


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """Start policy-engine on the server node for the duration of this package."""
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
def cli_policy_client(nodes, policy_engine_service):
    server = nodes["server"]
    return PolicyClient(server)


@pytest.fixture(scope="package")
def graphql_policy_client(nodes, policy_engine_service):
    server = nodes["server"]
    return GraphQLPolicyClient(server)


AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    return request.param


@pytest.fixture(scope="module")
def policy_client(
    client_type, cli_policy_client, graphql_policy_client
) -> AnyPolicyClient:
    if client_type == "cli":
        return cli_policy_client
    return graphql_policy_client


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    server_ifaces = node_interfaces["server"]
    return server_ifaces["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    client_ifaces = node_interfaces["client"]
    return client_ifaces["net1"]


@pytest.fixture(scope="package")
def client_ip_v4(client_interface) -> netaddr.IPAddress:
    ip = client_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on client interface")
    return ip


@pytest.fixture(scope="package")
def server_ip_v4(server_interface) -> netaddr.IPAddress:
    ip = server_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on server interface")
    return ip


@pytest.fixture(scope="package")
def server_network_v4(server_interface):
    network = server_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on server interface")
    return str(network)


@pytest.fixture(scope="package")
def client_network_v4(client_interface):
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


@pytest.fixture(scope="package")
def server_mac(nodes, server_interface) -> str:
    """MAC address of the server's net1 interface (lowercase colon-hex)."""
    server = nodes["server"]
    return _get_mac_address(server, server_interface.if_name)


@pytest.fixture(scope="package")
def client_mac(nodes, client_interface) -> str:
    """MAC address of the client's net1 interface (lowercase colon-hex)."""
    client = nodes["client"]
    return _get_mac_address(client, client_interface.if_name)


@pytest.fixture(scope="function")
def attached_ingress(policy_client, server_interface, configure_node_interfaces):
    """Attach XDP ingress program; detach after test."""
    iface_name = server_interface.if_name
    result = policy_client.attach_ingress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")
    logger.info(f"Ingress attached to {iface_name}")
    yield iface_name
    try:
        policy_client.detach_ingress(iface_name)
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


@pytest.fixture(scope="function")
def attached_egress(policy_client, server_interface, configure_node_interfaces):
    """Attach TC egress program; detach after test."""
    iface_name = server_interface.if_name
    result = policy_client.attach_egress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach egress: {result.message}")
    logger.info(f"Egress attached to {iface_name}")
    yield iface_name
    try:
        policy_client.detach_egress(iface_name)
    except Exception as e:
        logger.warning(f"Failed to detach egress: {e}")


@pytest.fixture(scope="function")
def clean_ingress_rules(policy_client, server_interface):
    """Flush ingress rules before and after each test."""
    iface = server_interface.if_name
    policy_client.flush_rules(direction="ingress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )
    yield
    policy_client.flush_rules(direction="ingress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )


@pytest.fixture(scope="function")
def clean_egress_rules(policy_client, server_interface):
    """Flush egress rules before and after each test."""
    iface = server_interface.if_name
    policy_client.flush_rules(direction="egress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="egress", interface=iface
    )
    yield
    policy_client.flush_rules(direction="egress")
    policy_client.set_default_action(
        PolicyAction.PASS, direction="egress", interface=iface
    )


@pytest.fixture(scope="package")
def nmap_installed(nodes, install_packages):
    """Ensure nmap is installed on the client node for nping."""
    install_packages("client", ["nmap"])
    yield


@pytest.fixture(scope="package")
def nmap_installed_server(nodes, install_packages):
    """Ensure nmap is installed on the server node for nping (egress tests)."""
    install_packages("server", ["nmap"])
    yield
