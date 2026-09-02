# Copyright (c) Peter Morrow

"""
Fixtures for multi-node controller integration tests.

Topology: 1 controller VM + 3 node VMs, all on a shared management network.

Fixture hierarchy (all package-scoped unless noted):
  running_topology → nodes → install_user_packages
    controller_service  — starts policy-controller on controller VM
    node_services       — mints a ZTP bootstrap bundle, drops it on each managed
                          node, starts policy-engine + policy-node-agent
    enrolled_nodes      — waits for all 3 nodes to appear Active+online (ZTP
                          auto-approves) and maps VM name → controller node ID
                          by agent-reported hostname
    controller_client   — ControllerClient bound to the controller VM
"""

import ipaddress
import logging
import time
from typing import Dict, List

import pytest

from netsim.testkit.node import Node
from netsim.testkit.systemd_utils import restart_service, stop_service
from policy_engine_client.controller.graphql.client import (
    ControllerClient,
    mint_api_token,
)

logger = logging.getLogger(__name__)

_CONTROLLER_HTTP_TIMEOUT = 60  # seconds to wait for HTTP API
_ENROLLMENT_TIMEOUT = 120  # seconds to wait for nodes to enroll
_ACTIVE_TIMEOUT = 60  # seconds to wait for nodes to become Active
_POLL_INTERVAL = 2  # seconds between status polls

# Nodes that run policy-engine + policy-node-agent
_MANAGED_NODES = ["node1", "node2", "node3"]


# ── Internal helpers ──────────────────────────────────────────────────────────


def _wait_for_controller_http(
    controller: Node, timeout: int = _CONTROLLER_HTTP_TIMEOUT
) -> None:
    """Block until the controller HTTP API is responding on port 8443."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = controller.ssh_command(
                "curl -s -o /dev/null -w '%{http_code}' "
                "--max-time 2 http://127.0.0.1:8443/health 2>/dev/null || true",
                timeout=10,
            )
            if out.strip() == "200":
                logger.info("policy-controller HTTP API is ready")
                return
        except Exception:
            pass
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"policy-controller HTTP API did not become ready within {timeout}s")


def _wait_for_active_nodes_by_hostname(
    client: ControllerClient,
    expected_hostnames: List[str],
    timeout: int = _ENROLLMENT_TIMEOUT,
) -> Dict[str, str]:
    """
    Wait until each expected hostname has an Active node entry on the controller.

    Returns hostname → node_id. Used by the ZTP happy path: agents are
    auto-approved by their bootstrap token and land directly in Active, so the
    fixture identifies them by the hostname the agent reports during enrollment.
    """
    deadline = time.monotonic() + timeout
    needed = set(expected_hostnames)
    while time.monotonic() < deadline:
        try:
            active = client.list_nodes(status="active")
            by_host = {n.hostname: n.id for n in active if n.hostname in needed}
            if needed.issubset(by_host.keys()):
                logger.info(f"Found {len(by_host)} active nodes by hostname: {by_host}")
                return by_host
            missing = sorted(needed - by_host.keys())
            logger.debug(f"Still waiting for active nodes with hostnames: {missing}")
        except Exception as e:
            logger.debug(f"Error polling active nodes: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Expected active nodes for hostnames {expected_hostnames}, timed out after {timeout}s"
    )


def _wait_for_online_nodes(
    client: ControllerClient,
    node_ids: List[str],
    timeout: int = _ACTIVE_TIMEOUT,
) -> None:
    """Wait until all given node IDs appear in onlineNodes (management gRPC sessions)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            online = set(client.online_nodes())
            if all(nid in online for nid in node_ids):
                logger.info(f"All nodes online: {node_ids}")
                return
            missing = [nid for nid in node_ids if nid not in online]
            logger.debug(f"Still waiting for nodes to come online: {missing}")
        except Exception as e:
            logger.debug(f"Error polling online nodes: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Nodes {node_ids} did not come online within {timeout}s")


def _write_agent_config(node: Node) -> None:
    """
    Write /etc/policy-node-agent/config.toml on the managed node.

    Under ZTP, the bootstrap bundle carries `enrollment_url`, `controller_url`,
    and the pinned CA fingerprint. Only `local_server_url` (the agent → local
    policy-engine GraphQL endpoint) needs to live in config.toml.

    The agent identity key is auto-generated on first run if absent.
    """
    config = (
        "# Written by netsim multi-node conftest\n"
        'local_server_url = "http://127.0.0.1:8080/graphql"\n'
    )
    node.ssh_command("sudo mkdir -p /etc/policy-node-agent", timeout=10)
    node.ssh_command(
        f"printf '%s' '{config}' | sudo tee /etc/policy-node-agent/config.toml > /dev/null",
        timeout=10,
    )


def _write_bootstrap_bundle(node: Node, bundle_b64: str) -> None:
    """
    Drop the ZTP bootstrap bundle at /etc/policy-node-agent/bootstrap.bundle (mode 0600).

    The agent reads this file on startup, pins the controller CA fingerprint it
    carries, presents the embedded token during enrollment, and deletes the
    bundle from disk on first successful use. Without a bundle the agent
    refuses to start.
    """
    node.ssh_command("sudo mkdir -p /etc/policy-node-agent", timeout=10)
    node.ssh_command_with_stdin(
        "sudo tee /etc/policy-node-agent/bootstrap.bundle > /dev/null",
        bundle_b64,
        timeout=10,
    )
    # The unit has DynamicUser=yes, so the agent's runtime UID/GID is only
    # allocated once systemd starts the service. Pre-allocation we can't chown
    # to that group, so leave the bundle world-readable. Bundle is short-lived
    # (TTL'd token, deleted on first successful use) and this is a test rig.
    node.ssh_command(
        "sudo chmod 0644 /etc/policy-node-agent/bootstrap.bundle", timeout=10
    )


def _write_hosts_entry(node: Node, controller_ip: str) -> None:
    """
    Add an entry to /etc/hosts mapping 'policy-controller' to the controller IP.

    This allows the agent to connect using the DNS name that matches the
    certificate, rather than using the IP address directly.
    """
    entry = f"{controller_ip} policy-controller"
    # Remove any existing controller entries to avoid duplicates, then append.
    # Write to both /etc/hosts (immediate effect) and the cloud-init template
    # so the entry survives reboots when manage_etc_hosts=True is active.
    for target in ["/etc/hosts", "/etc/cloud/templates/hosts.debian.tmpl"]:
        node.ssh_command(
            f"sudo sed -i '/\\bpolicy-controller\\b/d' {target}", timeout=10
        )
        node.ssh_command(
            f"echo '{entry}' | sudo tee -a {target} > /dev/null",
            timeout=10,
        )


def _get_mgmt_ip(node: Node, topology) -> str:
    """
    Return the node's IPv4 address on the management network.

    Derives the management subnet from the topology (first network listed for
    the node).
    """
    topo_node = topology.get_node(node.name)
    if not topo_node or not topo_node.networks:
        pytest.fail(f"Node {node.name} has no networks defined in topology")

    mgmt_net_name = topo_node.networks[0]
    mgmt_network = topology.get_network(mgmt_net_name)
    if not mgmt_network:
        pytest.fail(f"Management network '{mgmt_net_name}' not found in topology")

    net = ipaddress.IPv4Network(mgmt_network.subnet, strict=False)
    out = node.ssh_command(
        "ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1",
        timeout=10,
    ).strip()
    for addr_str in out.splitlines():
        try:
            addr = ipaddress.IPv4Address(addr_str.strip())
            if addr in net:
                return str(addr)
        except ValueError:
            continue

    pytest.fail(
        f"Could not determine management IP for node {node.name} "
        f"on network '{mgmt_net_name}' ({mgmt_network.subnet})"
    )


# ── Package-scoped fixtures ───────────────────────────────────────────────────


@pytest.fixture(scope="package")
def controller_service(nodes, install_user_packages):
    """
    Start the policy-controller daemon on the controller VM.

    Skips the entire test package if the policy-controller package is not installed.
    """
    controller = nodes["controller"]

    check = controller.ssh_command(
        "systemctl cat policy-controller.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
    )
    if "MISSING" in check:
        pytest.skip(
            "policy-controller.service not installed (check 'packages' in the topology yaml)"
        )

    status = restart_service(controller, "policy-controller")
    if not status.is_healthy:
        pytest.fail(f"Failed to start policy-controller: {status.status_text}")

    logger.info(f"policy-controller running with PID {status.main_pid}")
    _wait_for_controller_http(controller)

    yield status

    try:
        stop_service(controller, "policy-controller")
    except Exception as e:
        logger.warning(f"Failed to stop policy-controller: {e}")


@pytest.fixture(scope="package")
def controller_api_token(nodes, controller_service) -> str:
    """
    Mint a bearer token for this test package via SSH. Also writes the
    plaintext to `/tmp/netsim-controller-token` on the controller VM so
    `_run_controller_cli` in test_controller_cli.py can pick it up via
    `--token=$(cat …)` without threading the token through every test fn.
    """
    import time

    token = mint_api_token(nodes["controller"], f"netsim-multi-node-{int(time.time())}")
    nodes["controller"].ssh_command(
        f"echo '{token}' | sudo tee /tmp/netsim-controller-token >/dev/null "
        f"&& sudo chmod 600 /tmp/netsim-controller-token",
        timeout=10,
    )
    return token


@pytest.fixture(scope="package")
def controller_client(
    nodes, controller_service, controller_api_token
) -> ControllerClient:
    """ControllerClient bound to the controller VM, with bearer token."""
    return ControllerClient(nodes["controller"], api_token=controller_api_token)


@pytest.fixture(scope="package")
def node_services(
    nodes, topology, controller_client, install_user_packages, configure_node_interfaces
):
    """
    Configure and start policy-engine + policy-node-agent on node1, node2, node3.

    Writes an agent config pointing at the controller before starting the agent.
    Skips if either service is not installed on any managed node.

    Depends on configure_node_interfaces so the management interface has a
    DHCP address before we attempt to read it.
    """
    controller_ip = _get_mgmt_ip(nodes["controller"], topology)
    logger.info(f"Controller management IP: {controller_ip}")

    # Mint a ZTP bootstrap bundle that will auto-approve all three nodes.
    # The bundle carries the controller URLs and the pinned CA fingerprint, so
    # nothing else needs to be distributed for enrollment.
    issued = controller_client.create_enrollment_token(
        enrollment_url="https://policy-controller:7776",
        controller_url="https://policy-controller:7777",
        ttl_seconds=3600,
        max_uses=len(_MANAGED_NODES),
        fleet_label="netsim-multi-node",
    )
    logger.info(
        f"Minted ZTP bundle (token_id={issued.token_id}, "
        f"uses_remaining={issued.uses_remaining})"
    )

    for node_name in _MANAGED_NODES:
        node = nodes[node_name]

        # Check that both services exist
        for svc in ("policy-engine", "policy-node-agent"):
            check = node.ssh_command(
                f"systemctl cat {svc}.service >/dev/null 2>&1 && echo EXISTS || echo MISSING"
            )
            if "MISSING" in check:
                pytest.skip(
                    f"{svc}.service not installed on {node_name} (check 'packages' in the topology yaml)"
                )

        # /etc/hosts entry resolves the "policy-controller" SAN used in the bundle URLs.
        _write_hosts_entry(node, controller_ip)
        _write_agent_config(node)
        _write_bootstrap_bundle(node, issued.bundle)

        # Start policy-engine first (agent depends on it for local GraphQL)
        pe_status = restart_service(node, "policy-engine")
        if not pe_status.is_healthy:
            pytest.fail(
                f"Failed to start policy-engine on {node_name}: {pe_status.status_text}"
            )

        # Start the node agent
        agent_status = restart_service(node, "policy-node-agent")
        if not agent_status.is_healthy:
            pytest.fail(
                f"Failed to start policy-node-agent on {node_name}: {agent_status.status_text}"
            )

        logger.info(
            f"{node_name}: policy-engine PID={pe_status.main_pid}, "
            f"policy-node-agent PID={agent_status.main_pid}"
        )

    yield

    # Stop agents then engines in reverse order
    for node_name in reversed(_MANAGED_NODES):
        node = nodes[node_name]
        for svc in ("policy-node-agent", "policy-engine"):
            try:
                stop_service(node, svc)
            except Exception as e:
                logger.warning(f"Failed to stop {svc} on {node_name}: {e}")


@pytest.fixture(scope="package")
def enrolled_nodes(nodes, controller_client, node_services) -> Dict[str, str]:
    """
    Wait for all managed nodes to auto-enrol via ZTP, then map VM name → node ID.

    With ZTP, the agent presents the bundle's token during enrollment and is
    auto-approved; nodes land directly in Active and never transit Pending. We
    map VM name (node1/node2/node3) to controller node ID by matching the
    agent-reported hostname.

    Returns a dict mapping VM name to controller node ID.
    """
    # Discover each VM's actual hostname so we can match against what the agent reports.
    vm_hostnames: Dict[str, str] = {}
    for node_name in _MANAGED_NODES:
        hostname = nodes[node_name].ssh_command("hostname", timeout=10).strip()
        vm_hostnames[node_name] = hostname
        logger.debug(f"{node_name}: hostname={hostname}")

    by_host = _wait_for_active_nodes_by_hostname(
        controller_client, list(vm_hostnames.values())
    )

    approved: Dict[str, str] = {
        vm_name: by_host[hostname] for vm_name, hostname in vm_hostnames.items()
    }

    # Apply per-VM labels so tests/operators can still identify nodes by VM name.
    for vm_name, node_id in approved.items():
        result = controller_client.label_node(node_id, vm_name)
        if not result.success:
            logger.warning(f"label_node({vm_name}) returned: {result.message}")
        logger.info(f"ZTP-enrolled {vm_name} → controller ID {node_id}")

    _wait_for_online_nodes(controller_client, list(approved.values()))

    return approved
