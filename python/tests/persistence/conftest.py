# Copyright (c) Peter Morrow

"""
State persistence test suite fixtures.

Tests that policy-engine state (rules, attachments, default actions) survives
a full VM reboot — i.e. is restored from the JSON state file when BPF maps
are freshly initialised after boot.
"""

import logging
import time
from typing import Union

import netaddr
import pytest

from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.engine.cli.client import PolicyClient
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]

_POLICY_ENGINE_URL = "http://127.0.0.1:8080/graphql"
_HTTP_READY_TIMEOUT = 60  # longer timeout after reboot
_HTTP_READY_INTERVAL = 1.0


def _wait_for_policy_engine_http(server, timeout: int = _HTTP_READY_TIMEOUT) -> None:
    """Block until the policy-engine HTTP server is accepting connections."""
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


def reboot_node_and_wait(node, ssh_reconnect_timeout: int = 120) -> None:
    """
    Reboot a VM and wait for it to come back up with SSH available.

    Issues `sudo reboot`, then polls SSH until the node is reachable again.
    The existing SSH connection will die during reboot — a new one is
    established automatically by the next ssh_command call once the node is up.
    """
    logger.info(f"[{node.name}] Rebooting node...")

    # Issue reboot — this will drop the SSH connection mid-flight, which is expected.
    try:
        node.ssh_command("sudo reboot", timeout=10)
    except Exception:
        pass  # Connection drop on reboot is normal

    # Give the VM a moment to actually start rebooting before we poll
    time.sleep(5)

    # Invalidate the cached SSH connection so the next call establishes a new one
    import netsim.testkit.node as node_module

    with node_module.Node._ssh_lock:
        node_module.Node._ssh_connections.pop(node._connection_key, None)

    # Poll SSH until the node is back
    deadline = time.monotonic() + ssh_reconnect_timeout
    while time.monotonic() < deadline:
        try:
            result = node.ssh_command("echo ready", timeout=5)
            if "ready" in result:
                logger.info(f"[{node.name}] Node is back online after reboot")
                return
        except Exception:
            pass
        time.sleep(3)

    pytest.fail(
        f"[{node.name}] Node did not come back online within {ssh_reconnect_timeout}s after reboot"
    )


@pytest.fixture(scope="package")
def policy_engine_service(nodes, install_user_packages):
    """
    Package-level fixture that starts policy-engine on the server node.
    Ensures policy-engine.service is enabled so it starts automatically after reboot.
    """
    server = nodes["server"]

    check_result = server.ssh_command(
        "systemctl cat policy-engine.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check_result:
        pytest.skip(
            "policy-engine.service not installed (check 'packages' in the topology yaml)"
        )

    # Enable the service so it starts automatically after reboot
    server.ssh_command("sudo systemctl enable policy-engine.service", timeout=15)

    status = restart_service(server, "policy-engine")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-engine: {status.status_text}")

    _wait_for_policy_engine_http(server)
    logger.info(f"policy-engine running with PID {status.main_pid}")

    yield status

    try:
        stop_service(server, "policy-engine")
    except Exception as e:
        logger.warning(f"Failed to stop policy-engine: {e}")


@pytest.fixture(scope="package")
def graphql_policy_client(nodes, policy_engine_service):
    """GraphQL client for the server node."""
    return GraphQLPolicyClient(nodes["server"])


@pytest.fixture(scope="package")
def server_interface(node_interfaces):
    """Server interface on net1."""
    return node_interfaces["server"]["net1"]


@pytest.fixture(scope="package")
def client_interface(node_interfaces):
    """Client interface on net1."""
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
def nmap_installed(nodes, install_packages):
    """Ensure nmap is installed on the client node for nping."""
    install_packages("client", ["nmap"])
    yield
