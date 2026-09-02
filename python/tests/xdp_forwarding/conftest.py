# Copyright (c) Peter Morrow

"""
Fixtures for XDP FIB forwarding integration tests.

Topology: client ↔ [transit: policy-engine] ↔ server
Policy-engine runs on transit (the router), attached to both interfaces.
"""

import logging
import time

import netaddr
import pytest

from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.network_helpers import add_route
from netsim.testkit.systemd_utils import restart_service, stop_service


logger = logging.getLogger(__name__)

_POLICY_ENGINE_URL = "http://127.0.0.1:8080/graphql"
_HTTP_READY_TIMEOUT = 30
_HTTP_READY_INTERVAL = 0.5


def _wait_for_policy_engine_http(node, timeout: int = _HTTP_READY_TIMEOUT) -> None:
    """Poll until the policy-engine HTTP server accepts connections on port 8080."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = node.ssh_command(
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


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """
    Start policy-engine on the transit node for the duration of the package.

    Skips tests if the service unit is not installed.
    """
    transit = nodes["transit"]

    check_result = transit.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check_result:
        pytest.skip(
            "policy-engine.service not installed on transit (check 'packages' in the topology yaml)"
        )

    # Stop suricata if present — it crash-loops when unconfigured.
    try:
        transit.ssh_command(
            "sudo systemctl stop suricata 2>/dev/null || true && "
            "sudo systemctl disable suricata 2>/dev/null || true",
            timeout=15,
        )
    except Exception:
        pass

    status = restart_service(transit, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine on transit: {status.status_text}")

    logger.info(f"policy-engine running on transit with PID {status.main_pid}")
    _wait_for_policy_engine_http(transit)

    yield status

    logger.info("Stopping policy-engine service on transit...")
    try:
        stop_service(transit, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


@pytest.fixture(scope="package")
def policy_client(nodes, policy_engine_service) -> GraphQLPolicyClient:
    """GraphQL client for the policy-engine on transit."""
    return GraphQLPolicyClient(nodes["transit"])


@pytest.fixture(autouse=True, scope="class")
def setup_routing(configure_node_interfaces, node_interfaces, topology, nodes):
    """
    Configure static routes on client/server.

    This fixture mirrors the setup in three_node_iperf so that packets actually
    reach the transit node and are processed by the XDP program.
    """
    # Client routes via transit net1 interface
    transit_net1_iface = node_interfaces["transit"]["net1"]
    transit_net1_ip = transit_net1_iface.get_ip_address()
    transit_net1_ipv6 = transit_net1_iface.get_ipv6_address()

    server_net = topology.get_network("net2")
    add_route(
        nodes["client"],
        netaddr.IPNetwork(server_net.subnet),
        netaddr.IPAddress(str(transit_net1_ip)),
        ipv6=False,
    )
    if server_net.ipv6_subnet and transit_net1_ipv6:
        client_iface = node_interfaces["client"]["net1"]
        add_route(
            nodes["client"],
            netaddr.IPNetwork(server_net.ipv6_subnet),
            netaddr.IPAddress(str(transit_net1_ipv6)),
            dev=client_iface.if_name,
            ipv6=True,
        )

    # Server routes via transit net2 interface
    transit_net2_iface = node_interfaces["transit"]["net2"]
    transit_net2_ip = transit_net2_iface.get_ip_address()
    transit_net2_ipv6 = transit_net2_iface.get_ipv6_address()

    client_net = topology.get_network("net1")
    add_route(
        nodes["server"],
        netaddr.IPNetwork(client_net.subnet),
        netaddr.IPAddress(str(transit_net2_ip)),
        ipv6=False,
    )
    if client_net.ipv6_subnet and transit_net2_ipv6:
        server_iface = node_interfaces["server"]["net2"]
        add_route(
            nodes["server"],
            netaddr.IPNetwork(client_net.ipv6_subnet),
            netaddr.IPAddress(str(transit_net2_ipv6)),
            dev=server_iface.if_name,
            ipv6=True,
        )

    logger.info("Routing configured: client → transit → server")


@pytest.fixture(scope="function")
def attached_interfaces(policy_client, node_interfaces):
    """
    Attach XDP ingress program to both transit interfaces, detach after the test.

    Yields a dict {'net1': iface_name, 'net2': iface_name}.
    """
    ifaces = {
        "net1": node_interfaces["transit"]["net1"].if_name,
        "net2": node_interfaces["transit"]["net2"].if_name,
    }

    for net, iface in ifaces.items():
        result = policy_client.attach_ingress(iface)
        if not result.success:
            pytest.fail(
                f"Failed to attach ingress to {iface} ({net}): {result.message}"
            )
        logger.info(f"XDP ingress attached to transit/{net} ({iface})")

    yield ifaces

    for net, iface in ifaces.items():
        try:
            policy_client.detach_ingress(iface)
            logger.info(f"XDP ingress detached from transit/{net} ({iface})")
        except Exception as e:
            logger.warning(f"Failed to detach ingress from {iface}: {e}")


@pytest.fixture(scope="function")
def fib_enabled(policy_client, attached_interfaces):
    """Enable FIB forwarding on both transit ingress interfaces, disable after the test."""
    for net, iface in attached_interfaces.items():
        result = policy_client.set_fib_forwarding(iface, enabled=True)
        if not result.success:
            pytest.fail(
                f"Failed to enable FIB forwarding on {iface} ({net}): {result.message}"
            )
        logger.info(f"FIB forwarding enabled on transit/{net} ({iface})")

    yield

    for net, iface in attached_interfaces.items():
        try:
            policy_client.set_fib_forwarding(iface, enabled=False)
            logger.info(f"FIB forwarding disabled on transit/{net} ({iface})")
        except Exception as e:
            logger.warning(f"Failed to disable FIB forwarding on {iface}: {e}")


@pytest.fixture(scope="function")
def cleared_stats(policy_client, node_interfaces):
    """Clear all stats on both transit interfaces before the test."""
    for net in ("net1", "net2"):
        iface = node_interfaces["transit"][net].if_name
        try:
            policy_client.clear_global_stats(iface, direction="ingress")
        except Exception:
            pass  # Stats may not exist if interface not yet attached
    yield
