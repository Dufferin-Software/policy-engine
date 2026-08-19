# Copyright (c) Dufferin Software

"""
Integration test for the config confirm / rollback handshake.

Scenario
--------
The controller ↔ agent protocol requires the agent to confirm every
mutation via ``ConfigConfirm``; the controller commits to its DB only after
the confirm arrives and then sends back ``ConfigCommitAck``. If the agent
never gets the ack — for example because the mutation itself black-holed
the controller path — an agent-side watchdog fires, runs the inverse delta
captured before apply, and sends ``ConfigConfirm{REVERTED}``.

This test exercises that end-to-end:

1. Attach the TC egress program on node1's management interface (the one
   the agent uses to reach the controller).
2. Create a rule via the *gated* ``createRule`` mutation that drops all
   TCP traffic to the controller's management gRPC port (7777) in the
   egress direction. Once applied this prevents the node from sending
   any confirm or ack back to the controller.
3. Expect the mutation to fail from the controller's perspective (the
   APPLIED confirm never arrived, so the controller's watchdog reaps the
   generation as ``Abandoned``).
4. Expect the agent's watchdog to fire, delete the blackhole rule, and
   restore connectivity.
5. Verify:
   - The rule is NOT in the controller's DB (never committed).
   - The rule is NOT on the node's local policy-engine (reverted).
   - ``pendingGeneration(nodeId)`` returns null again.
   - The node remains online and reachable.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_config_rollback.py -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml
"""

import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Dict

import pytest

from policy_engine_client.controller.graphql.client import ControllerClient
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

# The agent's watchdog deadline is 5 s by default (controller-stamped);
# allow headroom for apply + revert + network round trip on top.
_ROLLBACK_DEADLINE_SECS = 30
_POLL_INTERVAL = 1

# Controller management gRPC port. Must match the port the agent actually
# connects to (see multi_node/conftest.py:_write_agent_config).
_CONTROLLER_MGMT_PORT = 7777


def _find_mgmt_interface(node, topology) -> str:
    """Return the name of the node's management interface (the one on the
    network that reaches the controller)."""
    for iface in node.interfaces.values():
        if iface.network.name == "mgmt":
            return iface.if_name
    pytest.fail(f"No mgmt interface found on {node.name}")


def _controller_mgmt_ip(controller, topology) -> str:
    """Return the controller's IPv4 address on the mgmt network."""
    topo_node = topology.get_node(controller.name)
    mgmt_net = topology.get_network(topo_node.networks[0])
    net = ipaddress.IPv4Network(mgmt_net.subnet, strict=False)
    out = controller.ssh_command(
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
    pytest.fail(f"Could not determine controller mgmt IP on {mgmt_net.subnet}")


def _rule_present_on_node(node, rule_id: str, direction: str = "egress") -> bool:
    """Return True if a rule with the given controller ID is on the node's local policy-engine."""
    client = GraphQLPolicyClient(node)
    try:
        rules = client.list_rules(direction=direction)
    except Exception as e:
        logger.debug(f"[{node.name}] list_rules failed: {e}")
        return False
    return any(str(r.rule_id) == rule_id for r in rules)


def _wait_until_no_pending(
    client: ControllerClient, node_id: str, timeout: int
) -> None:
    """Poll ``pendingGeneration(nodeId)`` until null (generation resolved)."""
    logger.info(
        f"Waiting up to {timeout}s for pendingGeneration to clear for node {node_id}..."
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pg = client.pending_generation(node_id)
        if pg is None:
            logger.info(
                f"pendingGeneration cleared for node {node_id} after {timeout - (deadline - time.monotonic()):.1f}s"
            )
            return
        logger.debug(f"pendingGeneration still present: {pg}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"pendingGeneration for {node_id} did not clear within {timeout}s; "
        f"last value: {client.pending_generation(node_id)}"
    )


def _wait_until_reconnected(
    client: ControllerClient, node_id: str, since: datetime, timeout: int
) -> None:
    """Poll ``node.lastSeen`` until the agent has reconnected after ``since``.

    The controller updates ``lastSeen`` on every AgentHello, so a timestamp
    newer than ``since`` proves the agent established a fresh management
    stream after the blackhole scenario.  This is more reliable than watching
    ``onlineNodes`` go offline: the controller may atomically swap the old
    session for the new one without ever removing the node from the set.
    """
    logger.info(
        f"Waiting up to {timeout}s for node {node_id} to reconnect "
        f"(lastSeen > {since.isoformat()})..."
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            last_seen_str = client.node_last_seen(node_id)
            if last_seen_str:
                last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                if last_seen > since:
                    elapsed = timeout - (deadline - time.monotonic())
                    logger.info(
                        f"Node {node_id} reconnected after {elapsed:.1f}s "
                        f"(lastSeen={last_seen_str})"
                    )
                    return
        except Exception as e:
            logger.debug(f"node_last_seen poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Node {node_id} did not reconnect within {timeout}s — "
        "lastSeen was not updated after the blackhole scenario"
    )


def _wait_until_online(client: ControllerClient, node_id: str, timeout: int) -> None:
    """Poll ``onlineNodes`` until the node reappears."""
    logger.info(
        f"Waiting up to {timeout}s for node {node_id} to return to onlineNodes..."
    )
    deadline = time.monotonic() + timeout
    last_seen: set = set()
    while time.monotonic() < deadline:
        try:
            last_seen = set(client.online_nodes())
            if node_id in last_seen:
                logger.info(
                    f"Node {node_id} is back online after {timeout - (deadline - time.monotonic()):.1f}s"
                )
                return
        except Exception as e:
            logger.debug(f"online_nodes poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"Node {node_id} did not return to onlineNodes within {timeout}s "
        f"(online set: {last_seen})"
    )


class TestConfigRollback:
    """Agent-side rollback when the confirm/ack handshake cannot complete."""

    def test_blackhole_rule_is_rolled_back(
        self,
        nodes,
        topology,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        node_name = "node1"
        node = nodes[node_name]
        node_id = enrolled_nodes[node_name]
        mgmt_iface = _find_mgmt_interface(node, topology)
        controller_ip = _controller_mgmt_ip(nodes["controller"], topology)
        controller_cidr = f"{controller_ip}/32"

        logger.info(
            f"Test target: {node_name} mgmt={mgmt_iface} "
            f"controller={controller_ip}:{_CONTROLLER_MGMT_PORT}"
        )

        # Sanity: the node should be online before we break things.
        assert node_id in set(controller_client.online_nodes()), (
            f"{node_name} is not online before the test starts"
        )

        # 1. Attach TC egress on the mgmt interface. This is a gated op and
        #    should succeed normally — nothing is blocked yet.
        result = controller_client.attach_program(
            node_id=node_id,
            interface_name=mgmt_iface,
            direction="egress",
        )
        assert result.success, f"attach_program(egress) failed: {result.message}"
        logger.info(f"[{node_name}] Attached TC egress on {mgmt_iface}")

        # Snapshot egress rules on the node before the blackhole attempt so
        # we can prove nothing leaks through.
        pe_client = GraphQLPolicyClient(node)
        rules_before = pe_client.list_rules(direction="egress")
        logger.info(f"[{node_name}] Egress rules before blackhole: {len(rules_before)}")

        # 2. Create a rule that drops traffic to the controller's mgmt port.
        #    Once applied the agent cannot send the APPLIED confirm; the
        #    controller watchdog will reap the generation as Abandoned and
        #    the mutation raises. The agent watchdog then reverts.
        #
        #    Record the time just before the blackhole goes in.  We use it
        #    later to detect a genuine reconnect via lastSeen.
        blackhole_time = datetime.now(tz=timezone.utc)
        blackhole_raised = False
        blackhole_error: str = ""
        try:
            controller_client.create_rule(
                node_id=node_id,
                interface_name=mgmt_iface,
                direction="egress",
                dst_cidr=controller_cidr,
                dst_port=_CONTROLLER_MGMT_PORT,
                protocol="tcp",
                actions_json='[{"action":"drop","priority":0}]',
            )
        except RuntimeError as e:
            blackhole_raised = True
            blackhole_error = str(e)
            logger.info(f"Blackhole createRule raised (expected): {blackhole_error}")

        assert blackhole_raised, (
            "createRule unexpectedly succeeded; the blackhole rule should have "
            "prevented the APPLIED confirm from reaching the controller"
        )
        # Expect either abandonment, a rollback notification, or the block
        # error (if the test raced a retry). All three imply the handshake
        # did not commit.
        expected_tokens = (
            "abandoned",
            "reverted",
            "BLOCKED_PENDING_CONFIRM",
            "deadline",
        )
        assert any(
            tok in blackhole_error.lower()
            for tok in (t.lower() for t in expected_tokens)
        ), f"Unexpected error from createRule: {blackhole_error!r}"

        # 3. Wait for the pending generation to clear on the controller side.
        _wait_until_no_pending(
            controller_client, node_id, timeout=_ROLLBACK_DEADLINE_SECS
        )

        # 4. Wait for the agent to reconnect with a fresh management stream.
        #    We detect this via lastSeen: the controller stamps it on every
        #    AgentHello, so lastSeen > blackhole_time means the agent re-
        #    established its connection after the blackhole scenario ended.
        #
        #    We do NOT use _wait_until_offline because the controller's session
        #    manager atomically replaces the old session when the new AgentHello
        #    arrives, so the node may never appear offline in onlineNodes.
        _wait_until_reconnected(
            controller_client,
            node_id,
            since=blackhole_time,
            timeout=_ROLLBACK_DEADLINE_SECS,
        )

        # 5. Controller DB must NOT contain the blackhole rule — it was
        #    never committed (APPLIED never arrived).
        controller_rules = controller_client.list_rules_for_node(
            node_id, interface_name=mgmt_iface, direction="egress"
        )
        blackhole_rules = [
            r
            for r in controller_rules
            if r.get("dstCidr") == controller_cidr
            and r.get("dstPort") == _CONTROLLER_MGMT_PORT
            and r.get("protocol") == "tcp"
        ]
        assert not blackhole_rules, (
            f"Controller DB still contains blackhole rule(s): {blackhole_rules}. "
            "The rule should never have been committed because the agent "
            "could not send APPLIED back."
        )

        # 6. The node's local policy-engine must have reverted the rule.
        #    We accept a short settle window in case the revert is still
        #    flushing when we query.
        deadline = time.monotonic() + _ROLLBACK_DEADLINE_SECS
        local_rules = []
        while time.monotonic() < deadline:
            local_rules = pe_client.list_rules(direction="egress")
            matching = [
                r
                for r in local_rules
                if r.dst_prefix == controller_cidr
                and r.dport == _CONTROLLER_MGMT_PORT
                and str(r.protocol).lower().endswith("tcp")
            ]
            if not matching:
                break
            logger.debug(
                f"[{node_name}] blackhole rule still present locally: {matching}"
            )
            time.sleep(_POLL_INTERVAL)
        else:
            pytest.fail(
                f"[{node_name}] blackhole rule was not reverted locally; "
                f"current egress rules: {local_rules}"
            )

        logger.info(
            f"[{node_name}] Rollback verified: rule absent on controller, "
            "absent on node, pending cleared, node online."
        )

        # Harmless benign rule: drop UDP to 10.255.255.254:65535 — not used
        # by anything in the topology, so it will not interfere with the
        # management path. Confirms the confirm/ack handshake still works.
        rule = controller_client.create_rule(
            node_id=node_id,
            interface_name=mgmt_iface,
            direction="egress",
            dst_cidr="10.255.255.254/32",
            dst_port=65535,
            protocol="udp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        assert rule.get("id"), f"createRule did not return an id: {rule}"
        logger.info(f"Benign rule created and committed: {rule['id']}")

        # Clean up: ensure no dangling pending state.
        pg = controller_client.pending_generation(node_id)
        assert pg is None, f"pendingGeneration should be null, got {pg}"
