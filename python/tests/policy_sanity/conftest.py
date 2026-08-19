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


@pytest.fixture(scope="function")
def attached_egress(policy_client, server_interface, configure_node_interfaces):
    """
    Fixture that attaches egress program before test and detaches after.

    Depends on configure_node_interfaces to ensure interfaces have IPs
    before attaching the TC program.

    Yields the interface name.
    """
    iface_name = server_interface.if_name

    # Attach egress
    result = policy_client.attach_egress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach egress: {result.message}")

    logger.info(f"Egress attached to {iface_name}")
    yield iface_name

    # Detach egress
    try:
        policy_client.detach_egress(iface_name)
        logger.info(f"Egress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach egress: {e}")


@pytest.fixture(scope="function")
def clean_egress_rules(policy_client, server_interface):
    """Fixture to ensure egress rules and default action are cleaned up before and after each test."""
    iface = server_interface.if_name
    policy_client.flush_rules(direction="egress", interface=iface)
    policy_client.set_default_action(
        PolicyAction.PASS, direction="egress", interface=iface
    )
    yield
    policy_client.flush_rules(direction="egress", interface=iface)
    policy_client.set_default_action(
        PolicyAction.PASS, direction="egress", interface=iface
    )


@pytest.fixture(scope="function")
def attached_ingress(policy_client, server_interface, configure_node_interfaces):
    """
    Fixture that attaches ingress program before test and detaches after.

    Depends on configure_node_interfaces to ensure interfaces have IPs
    before attaching the XDP program.

    Yields the interface name.
    """
    iface_name = server_interface.if_name

    # Attach ingress
    result = policy_client.attach_ingress(iface_name)
    if not result.success:
        pytest.fail(f"Failed to attach ingress: {result.message}")

    logger.info(f"Ingress attached to {iface_name}")
    yield iface_name

    # Detach ingress
    try:
        policy_client.detach_ingress(iface_name)
        logger.info(f"Ingress detached from {iface_name}")
    except Exception as e:
        logger.warning(f"Failed to detach ingress: {e}")


@pytest.fixture(scope="function")
def clean_ingress_rules(policy_client, server_interface):
    """Fixture to ensure ingress rules and default action are cleaned up before and after each test."""
    iface = server_interface.if_name
    policy_client.flush_rules(direction="ingress", interface=iface)
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )
    yield
    policy_client.flush_rules(direction="ingress", interface=iface)
    policy_client.set_default_action(
        PolicyAction.PASS, direction="ingress", interface=iface
    )


AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """
    Package-level fixture that starts policy-engine on the server node.

    Starts the service once for all tests in this test package and stops it after.
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

    # Suricata must not be running during tests — it crash-loops when
    # unconfigured and saturates the VM.  Stop and disable it here so that
    # packages installed from an older image (before the postinst fix) are
    # also covered.
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
def nmap_installed(nodes, install_packages):
    """Ensure nmap is installed on the client for nping."""
    nodes["client"]
    install_packages("client", ["nmap"])
    yield


@pytest.fixture(scope="package")
def websocket_installed(nodes, install_packages):
    """Ensure python3-websocket is installed on the server for WS event tests."""
    nodes["server"]
    install_packages("server", ["python3-websocket"])
    yield


@pytest.fixture(scope="package")
def bpftool_installed(nodes, install_packages):
    """Ensure bpftool is installed on the server for BPF operations."""
    nodes["server"]
    install_packages("server", ["bpftool"])
    yield


@pytest.fixture(scope="module", params=["cli", "graphql"], ids=["cli", "graphql"])
def client_type(request):
    """Parameterized fixture for client type.

    Module-scoped (not package) to prevent parameterization from tearing down
    package-scoped fixtures (topology, policy-engine service) between cli/graphql runs.
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


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    """Get the server's interface on net1."""
    server_ifaces = node_interfaces["server"]
    return server_ifaces["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    """Get the client's interface on net1."""
    client_ifaces = node_interfaces["client"]
    return client_ifaces["net1"]


# IPv4 fixtures


@pytest.fixture(scope="package")
def client_network_v4(client_interface):
    network = client_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on client interface")
    return str(network)


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


# IPv6 fixtures


@pytest.fixture(scope="package")
def client_network_v6(client_interface):
    network = client_interface.get_ipv6_network()
    if network is None:
        pytest.skip("No IPv6 address configured on client interface")
    return str(network)


@pytest.fixture(scope="package")
def client_ip_v6(client_interface) -> netaddr.IPAddress:
    ip = client_interface.get_ipv6_address()
    if ip is None:
        pytest.skip("No IPv6 address configured on client interface")
    return ip


@pytest.fixture(scope="package")
def server_ip_v6(server_interface) -> netaddr.IPAddress:
    ip = server_interface.get_ipv6_address()
    if ip is None:
        pytest.skip("No IPv6 address configured on server interface")
    return ip


# Server network fixtures (for egress rules matching server-originated traffic)


@pytest.fixture(scope="package")
def server_network_v4(server_interface):
    network = server_interface.get_ipv4_network()
    if network is None:
        pytest.skip("No IPv4 address configured on server interface")
    return str(network)


@pytest.fixture(scope="package")
def server_network_v6(server_interface):
    network = server_interface.get_ipv6_network()
    if network is None:
        pytest.skip("No IPv6 address configured on server interface")
    return str(network)


@pytest.fixture(scope="package")
def nmap_installed_server(nodes, install_packages):
    """Ensure nmap is installed on the server for nping (egress traffic tests)."""
    nodes["server"]
    install_packages("server", ["nmap"])
    yield
