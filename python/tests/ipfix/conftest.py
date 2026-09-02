# Copyright (c) Peter Morrow

"""
IPFIX flow export test suite fixtures.

Package-level fixtures for IPFIX integration tests.
IPFIX has no CLI client commands, so all tests use the GraphQL client directly.
"""

import logging
import time

import netaddr
import pytest

from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from policy_engine_client.engine.cli.client import PolicyAction


logger = logging.getLogger(__name__)

_POLICY_ENGINE_URL = "http://127.0.0.1:8080/graphql"
_HTTP_READY_TIMEOUT = 30
_HTTP_READY_INTERVAL = 0.5

# Collector port used in tests — avoid 4739 (default) so tests are explicit
_COLLECTOR_PORT = 4739

# Short timeouts for test speed: idle=5s means flows export within ~15s
# (5s idle + up to 10s background loop interval + buffer)
_TEST_IDLE_TIMEOUT_S = 5
_TEST_ACTIVE_TIMEOUT_S = 60


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


# ============================================================================
# Service fixtures
# ============================================================================


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """Start policy-engine on the server node for the duration of the package."""
    server = nodes["server"]

    check_result = server.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check_result:
        pytest.skip(
            "policy-engine.service not installed (check 'packages' in the topology yaml)"
        )

    status = restart_service(server, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine: {status.status_text}")

    logger.info(f"policy-engine running with PID {status.main_pid}")
    _wait_for_policy_engine_http(server)

    yield status

    logger.info("Stopping policy-engine service...")
    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


@pytest.fixture(scope="package")
def graphql_client(nodes, policy_engine_service) -> GraphQLPolicyClient:
    """GraphQL client connected to the server node."""
    return GraphQLPolicyClient(nodes["server"])


@pytest.fixture(scope="package")
def ipfix_available(graphql_client):
    """Skip tests if the server was not compiled with IPFIX support."""
    features = graphql_client.server_features()
    if not features.ipfix:
        pytest.skip(
            "policy-engine server does not support IPFIX "
            "(compiled without --features ipfix; install policy-engine-ipfix)"
        )
    yield


# ============================================================================
# Interface and IP fixtures
# ============================================================================


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
        pytest.skip("No IPv4 address configured on server interface")
    return ip


@pytest.fixture(scope="package")
def client_ip_v4(client_interface) -> netaddr.IPAddress:
    ip = client_interface.get_ip_address()
    if ip is None:
        pytest.skip("No IPv4 address configured on client interface")
    return ip


@pytest.fixture(scope="package")
def client_network_v4(client_interface):
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


# ============================================================================
# Attachment and cleanup fixtures
# ============================================================================


@pytest.fixture(scope="function")
def attached_ingress(graphql_client, server_interface, configure_node_interfaces):
    """Attach ingress XDP before test, detach after."""
    iface_name = server_interface.if_name

    result = graphql_client.attach_ingress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")

    logger.info(f"Ingress attached to {iface_name}")
    yield iface_name

    try:
        graphql_client.detach_ingress(iface_name)
        logger.info(f"Ingress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


@pytest.fixture(scope="function")
def clean_ingress_rules(graphql_client, server_interface):
    """Flush ingress rules and reset default action before and after each test."""
    iface = server_interface.if_name
    graphql_client.flush_rules(direction="ingress")
    graphql_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )
    yield
    graphql_client.flush_rules(direction="ingress")
    graphql_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )


@pytest.fixture(scope="function")
def flow_export_disabled(graphql_client, ipfix_available):
    """Ensure flow export is disabled before and after each test."""
    graphql_client.configure_flow_export(enabled=False)
    yield
    try:
        graphql_client.configure_flow_export(enabled=False)
    except Exception as e:
        logger.warning(f"Failed to disable flow export in teardown: {e}")


@pytest.fixture(scope="function")
def flow_export_enabled(graphql_client, flow_export_disabled):
    """
    Enable flow export with short timeouts for test speed.

    Uses idle_timeout_s=5 so flows age out quickly.
    Disables export after the test via flow_export_disabled teardown.
    """
    result = graphql_client.configure_flow_export(
        enabled=True,
        collector_host="127.0.0.1",
        collector_port=_COLLECTOR_PORT,
        idle_timeout_s=_TEST_IDLE_TIMEOUT_S,
        active_timeout_s=_TEST_ACTIVE_TIMEOUT_S,
    )
    if not result.success:
        pytest.fail(f"Failed to enable flow export: {result.message}")

    logger.info(
        f"Flow export enabled → 127.0.0.1:{_COLLECTOR_PORT} "
        f"(idle={_TEST_IDLE_TIMEOUT_S}s)"
    )
    yield


# ============================================================================
# Package tool fixtures
# ============================================================================


@pytest.fixture(scope="package")
def nmap_installed(nodes, install_packages):
    """Ensure nmap is installed on the client for nping."""
    install_packages("client", ["nmap"])
    yield
