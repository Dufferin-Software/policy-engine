# Copyright (c) Peter Morrow

"""
Shared helpers for the multi-node controller/agent integration tests.

These functions were previously copy-pasted across the individual
``test_*.py`` modules in this package.  They are consolidated here so there is
a single implementation of each.
"""

import logging
import re
import time

import pytest

from netsim.testkit.node import Node
from policy_engine_client.controller.graphql.client import ControllerClient
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

# Polling cadence / deadline for wait_for_node_ready.
_POLL_INTERVAL = 1
_READY_TIMEOUT = 30


def data_iface(node: Node) -> str:
    """Return the name of the node's non-management (data) interface."""
    for iface in node.interfaces.values():
        if iface.network.name != "mgmt":
            return iface.if_name
    pytest.fail(f"No data interface found on {node.name}")


def get_data_ip(node: Node) -> str:
    """Return the node's IPv4 address on the data network."""
    iface = data_iface(node)
    out = node.ssh_command(
        f"ip -4 addr show {iface} | awk '/inet / {{print $2}}' | cut -d/ -f1",
        timeout=10,
    ).strip()
    for line in out.splitlines():
        addr = line.strip()
        if addr:
            return addr
    pytest.fail(f"Could not determine data IP for {node.name} on {iface}")


def read_sysfs_ifindex(node: Node, iface: str) -> int:
    """Read /sys/class/net/<iface>/ifindex on the node."""
    out = node.ssh_command(f"cat /sys/class/net/{iface}/ifindex", timeout=10).strip()
    try:
        return int(out)
    except ValueError:
        pytest.fail(
            f"[{node.name}] /sys/class/net/{iface}/ifindex returned non-int: {out!r}"
        )


def send_icmp(node: Node, target_ip: str, iface: str, count: int = 5) -> dict:
    """
    Send ICMP echo requests via ping and return packet counts.

    Returns a dict with keys: sent, received, lost, output.
    """
    out = node.ssh_command(
        f"ping -c {count} -I {iface} {target_ip} 2>&1 || true",
        timeout=30,
    )
    match = re.search(
        r"(\d+) packets transmitted, (\d+) received.*?(\d+(?:\.\d+)?)% packet loss",
        out,
    )
    if match:
        sent = int(match.group(1))
        received = int(match.group(2))
        return {
            "sent": sent,
            "received": received,
            "lost": sent - received,
            "output": out,
        }
    return {"sent": 0, "received": 0, "lost": 0, "output": out}


def wait_for_node_ready(
    client: ControllerClient,
    node_id: str,
    timeout: int = _READY_TIMEOUT,
) -> None:
    """Block until pendingGeneration is None and the node is online.

    Must be called before any gated mutation (attachProgram, detachProgram,
    createRule, setInterfaceDefaultAction) to avoid BLOCKED_PENDING_CONFIRM.

    Gated mutations from earlier tests can leave a pending generation in the
    controller registry for up to 30 s, so callers that need to issue their
    own gated mutation should call this first to avoid spurious
    BLOCKED_PENDING_CONFIRM and 'not currently connected' failures.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pg = client.pending_generation(node_id)
            online = set(client.online_nodes())
            if pg is None and node_id in online:
                return
        except Exception as e:
            logger.debug(f"wait_for_node_ready poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    # Surface the last known state in the failure message.
    pg = client.pending_generation(node_id)
    online = set(client.online_nodes())
    pytest.fail(
        f"Node {node_id} did not reach ready state within {timeout}s "
        f"(pending={pg}, online={node_id in online})"
    )


def flush_ingress_rules(node: Node) -> None:
    """Flush all ingress rules from the node's local policy-engine."""
    GraphQLPolicyClient(node).flush_rules(direction="ingress")


def delete_controller_rules(
    client: ControllerClient,
    node_id: str,
    iface: str,
    direction: str,
) -> None:
    """Delete all rules for node/iface/direction from the controller database.

    Previous tests may leave rules in the controller that are never deleted
    (only flushed locally).  When the program is detached the controller
    immediately sends a DeltaConfigPush for those stale rules, which triggers
    the agent's auto-attach logic and re-loads the BPF program.  Deleting
    rules from the controller before detaching prevents that push.
    """
    wait_for_node_ready(client, node_id)
    for rule in client.list_rules_for_node(node_id, iface, direction):
        result = client.delete_rule(rule["id"])
        if not result.success:
            logger.warning(f"deleteRule {rule['id']} failed: {result.message}")
