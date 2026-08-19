# Copyright (c) Dufferin Software

"""
IPS/IDS test suite fixtures.

Package-level fixtures for Suricata-based IPS/IDS integration tests.
Tests are parameterized to run against both the CLI and GraphQL clients.
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

AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]

_POLICY_ENGINE_URL = "http://127.0.0.1:8080/graphql"
_HTTP_READY_TIMEOUT = 30  # seconds
_HTTP_READY_INTERVAL = 0.5  # seconds between retries


def _wait_for_policy_engine_http(server, timeout: int = _HTTP_READY_TIMEOUT) -> None:
    """
    Block until the policy-engine HTTP server is accepting connections on port 8080.

    systemd can report the service as "active (running)" before the HTTP socket
    is bound, so we poll until the endpoint responds.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = server.ssh_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--max-time 2 {_POLICY_ENGINE_URL} 2>/dev/null || true",
                timeout=10,
            )
            if (
                out.strip() and out.strip() != "000"
            ):  # actual HTTP response (000 = connection refused)
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
    """
    Package-level fixture that starts policy-engine on the server node.

    Starts the service once for all tests in this package and stops it after.
    Skips tests if the service unit is not installed.
    """
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

    # Wait for the HTTP server to bind to port 8080 — systemd reports "active"
    # before the socket is ready.
    _wait_for_policy_engine_http(server)

    yield status

    logger.info("Stopping policy-engine service...")
    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


@pytest.fixture(scope="package")
def suricata_available(nodes, policy_engine_service, graphql_policy_client):
    """
    Assert that the running policy-engine server was compiled with IPS/IDS support.

    Uses the serverFeatures GraphQL query — the authoritative source for whether
    the server supports Suricata IPS/IDS. Skips the test if it does not.
    """
    features = graphql_policy_client.server_features()
    if not features.suricata:
        pytest.skip(
            "policy-engine server does not support IPS/IDS "
            "(compiled without --features suricata; install policy-engine-ips)"
        )

    yield


# ============================================================================
# Client type parameterization
# ============================================================================


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    """Parameterized fixture for client type.

    Module-scoped to prevent parameterization from tearing down package-scoped
    fixtures between cli/graphql runs.
    """
    return request.param


@pytest.fixture(scope="package")
def cli_policy_client(nodes, policy_engine_service):
    """Create a CLI PolicyClient instance for the server."""
    server = nodes["server"]
    return PolicyClient(server)


@pytest.fixture(scope="package")
def graphql_policy_client(nodes, policy_engine_service):
    """Create a GraphQL PolicyClient instance for the server."""
    server = nodes["server"]
    return GraphQLPolicyClient(server)


@pytest.fixture(scope="module")
def policy_client(
    client_type, cli_policy_client, graphql_policy_client
) -> AnyPolicyClient:
    """
    Parameterized policy client fixture.

    Module-scoped to match client_type parameterization scope.
    Returns either the CLI client or GraphQL client based on client_type parameter.
    Tests using this fixture will run twice: once with CLI, once with GraphQL.
    """
    if client_type == "cli":
        return cli_policy_client
    else:
        return graphql_policy_client


# ============================================================================
# Interface and IP fixtures
# ============================================================================


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    """Get the server's interface on net1."""
    return node_interfaces["server"]["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    """Get the client's interface on net1."""
    return node_interfaces["client"]["net1"]


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
def client_network_v4(client_interface):
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


@pytest.fixture(scope="package")
def server_network_v4(server_interface):
    network = server_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on server interface")
    return str(network)


# ============================================================================
# Attachment fixtures
# ============================================================================


@pytest.fixture(scope="function")
def attached_ingress(policy_client, server_interface, configure_node_interfaces):
    """
    Fixture that attaches ingress XDP program before test and detaches after.

    Depends on configure_node_interfaces to ensure interfaces have IPs.
    """
    iface_name = server_interface.if_name

    result = policy_client.attach_ingress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")

    logger.info(f"Ingress attached to {iface_name}")
    yield iface_name

    try:
        policy_client.detach_ingress(iface_name)
        logger.info(f"Ingress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


@pytest.fixture(scope="function")
def clean_ingress_rules(policy_client, server_interface):
    """Flush ingress rules and reset default action before and after each test."""
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


# ============================================================================
# Inspect/IPS fixtures
# ============================================================================


@pytest.fixture(scope="function")
def inspect_mode_disabled(policy_client):
    """
    Ensure inspect mode is disabled before and after each test.

    Cleans up inspect state (disables mode, clears flow verdicts) so tests
    start with a clean slate.
    """
    # Disable before test
    policy_client.disable_inspect()
    policy_client.clear_flow_verdicts(direction="ingress")
    policy_client.clear_flow_verdicts(direction="egress")
    yield
    # Disable after test
    try:
        policy_client.disable_inspect()
        policy_client.clear_flow_verdicts(direction="ingress")
        policy_client.clear_flow_verdicts(direction="egress")
    except Exception as e:
        logger.warning(f"Failed to cleanup inspect mode: {e}")


@pytest.fixture(scope="function")
def ips_mode_enabled(policy_client, inspect_mode_disabled, suricata_available):
    """
    Enable IPS mode for a test, disable after.

    Depends on suricata_available to skip if Suricata not installed.
    Waits briefly for Suricata to apply config.
    """
    result = policy_client.configure_inspect("ips")
    if not result.success:
        pytest.fail(f"Failed to enable IPS mode: {result.message}")

    logger.info("IPS mode enabled")

    # Brief settle time for Suricata config to apply
    time.sleep(2)

    yield

    try:
        policy_client.disable_inspect()
        logger.info("IPS mode disabled")
    except Exception as e:
        logger.warning(f"Failed to disable IPS mode: {e}")


@pytest.fixture(scope="function")
def ids_mode_enabled(policy_client, inspect_mode_disabled, suricata_available):
    """
    Enable IDS mode for a test, disable after.

    Depends on suricata_available to skip if Suricata not installed.
    """
    result = policy_client.configure_inspect("ids")
    if not result.success:
        pytest.fail(f"Failed to enable IDS mode: {result.message}")

    logger.info("IDS mode enabled")
    time.sleep(2)

    yield

    try:
        policy_client.disable_inspect()
        logger.info("IDS mode disabled")
    except Exception as e:
        logger.warning(f"Failed to disable IDS mode: {e}")


# ============================================================================
# Package tool fixtures
# ============================================================================


@pytest.fixture(scope="package")
def nmap_installed(nodes, install_packages):
    """Ensure nmap is installed on the client for nping."""
    install_packages("client", ["nmap"])
    yield


@pytest.fixture(scope="package")
def nmap_installed_server(nodes, install_packages):
    """Ensure nmap is installed on the server for nping."""
    install_packages("server", ["nmap"])
    yield
