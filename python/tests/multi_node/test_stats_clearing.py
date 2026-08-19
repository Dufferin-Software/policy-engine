# Copyright (c) Dufferin Software

"""
Integration tests for stats clearing via the controller API.

These exercise the full UI → controller → agent → engine pathway added for
clearing policy-engine statistics. The controller's clear* mutations are
fire-and-forget: they push a ClearStats message to the agent, which calls the
local engine. There is no controller-side confirm, so each test drives the
clear through the controller and then verifies the effect by reading the
node's local policy-engine directly (the authoritative BPF counters), polling
until the counters reach zero.

A drop-ICMP ingress rule is used as the workload: matching traffic increments
both the rule's packet counter and the interface-level ``policyDrops`` counter,
so a single setup verifies both interface- and rule-scoped clears.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_stats_clearing.py -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml
"""

import logging
import time
from typing import Callable, Dict

from policy_engine_client.controller.graphql.client import ControllerClient
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from tests.multi_node.helpers import (
    data_iface,
    delete_controller_rules,
    flush_ingress_rules,
    get_data_ip,
    send_icmp,
    wait_for_node_ready,
)

logger = logging.getLogger(__name__)

_SETTLE_SECS = 3
# The clear is fire-and-forget; allow time for controller→agent→engine delivery.
_CLEAR_TIMEOUT = 20
_POLL_INTERVAL = 1


def _wait_until_zero(read_fn: Callable[[], int]) -> int:
    """Poll ``read_fn`` until it returns 0 or the deadline passes.

    Returns the last observed value (0 on success, non-zero on timeout) so the
    caller can assert with a useful message.
    """
    deadline = time.monotonic() + _CLEAR_TIMEOUT
    last = read_fn()
    while last != 0 and time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL)
        last = read_fn()
    return last


def _rule_packets(pe: GraphQLPolicyClient, engine_rule_id: int) -> int:
    """Read a rule's ingress packet counter from the local engine (0 if absent)."""
    resp = pe.get_rule_stats(rule_id=engine_rule_id, direction="ingress")
    for rws in resp.rules:
        if rws.rule.rule_id == engine_rule_id and rws.stats is not None:
            return rws.stats.packets
    return 0


def _iface_drops(pe: GraphQLPolicyClient, iface: str) -> int:
    """Read an interface's ingress policyDrops counter from the local engine."""
    return pe.get_stats(iface, direction="ingress").global_stats.policy_drops


class TestStatsClearing:
    """Controller-driven stats clearing, verified against the node's engine."""

    def _setup_dropped_traffic(
        self,
        controller_client: ControllerClient,
        node1,
        node2,
        node1_id: str,
    ) -> dict:
        """Attach ingress, install a drop-ICMP rule, and send matching traffic.

        Returns a context dict with the controller/engine rule IDs and the
        interface/IP details, with both the rule and interface counters > 0.
        """
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)
        pe = GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)
        controller_client.attach_program(
            node_id=node1_id, interface_name=iface1, direction="ingress"
        )
        time.sleep(_SETTLE_SECS)
        flush_ingress_rules(node1)

        rule = controller_client.create_rule(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        controller_rule_id = rule.get("id")
        assert controller_rule_id, f"createRule returned no id: {rule}"
        time.sleep(_SETTLE_SECS)

        # Start from a known-zero baseline, then generate matching (dropped) traffic.
        pe.clear_all_stats()
        send_icmp(node2, node1_ip, iface2, count=5)
        time.sleep(_SETTLE_SECS)

        local_rules = pe.list_rules(direction="ingress", interface=iface1)
        assert local_rules, "No ingress rules on node1 after push"
        engine_rule_id = local_rules[0].rule_id

        # The controller-assigned ID is the same value the engine keys stats on
        # (a u64 the controller stores as a string), so the per-rule clear can
        # target it directly.
        assert str(engine_rule_id) == str(controller_rule_id), (
            f"controller rule id {controller_rule_id!r} != engine rule id "
            f"{engine_rule_id!r}"
        )

        assert _rule_packets(pe, engine_rule_id) > 0, "rule packets did not increment"
        assert _iface_drops(pe, iface1) > 0, "interface policyDrops did not increment"

        return {
            "pe": pe,
            "iface1": iface1,
            "controller_rule_id": controller_rule_id,
            "engine_rule_id": engine_rule_id,
        }

    def _teardown(
        self, controller_client: ControllerClient, node1, node1_id: str, iface1: str
    ):
        flush_ingress_rules(node1)
        delete_controller_rules(controller_client, node1_id, iface1, "ingress")
        wait_for_node_ready(controller_client, node1_id)
        controller_client.detach_program(
            node_id=node1_id, interface_name=iface1, direction="ingress"
        )

    def test_clear_interface_stats(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """clearInterfaceStats zeroes the interface counters on the engine."""
        node1, node2 = nodes["node1"], nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        ctx = self._setup_dropped_traffic(controller_client, node1, node2, node1_id)
        pe, iface1 = ctx["pe"], ctx["iface1"]
        try:
            result = controller_client.clear_interface_stats(node1_id, iface1)
            assert result.success, f"clearInterfaceStats failed: {result.message}"

            drops = _wait_until_zero(lambda: _iface_drops(pe, iface1))
            assert drops == 0, f"interface policyDrops not cleared, got {drops}"
            logger.info(f"[node1] interface stats cleared on {iface1}")
        finally:
            self._teardown(controller_client, node1, node1_id, iface1)

    def test_clear_all_interface_stats(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """clearAllInterfaceStats zeroes interface counters across attachments."""
        node1, node2 = nodes["node1"], nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        ctx = self._setup_dropped_traffic(controller_client, node1, node2, node1_id)
        pe, iface1 = ctx["pe"], ctx["iface1"]
        try:
            result = controller_client.clear_all_interface_stats(node1_id)
            assert result.success, f"clearAllInterfaceStats failed: {result.message}"

            drops = _wait_until_zero(lambda: _iface_drops(pe, iface1))
            assert drops == 0, f"interface policyDrops not cleared, got {drops}"
        finally:
            self._teardown(controller_client, node1, node1_id, iface1)

    def test_clear_rule_stats(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """clearRuleStats zeroes a single rule's counters on the engine."""
        node1, node2 = nodes["node1"], nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        ctx = self._setup_dropped_traffic(controller_client, node1, node2, node1_id)
        pe, iface1 = ctx["pe"], ctx["iface1"]
        try:
            result = controller_client.clear_rule_stats(
                node1_id, ctx["controller_rule_id"]
            )
            assert result.success, f"clearRuleStats failed: {result.message}"

            packets = _wait_until_zero(lambda: _rule_packets(pe, ctx["engine_rule_id"]))
            assert packets == 0, f"rule packets not cleared, got {packets}"
            logger.info(f"[node1] rule {ctx['controller_rule_id']} stats cleared")
        finally:
            self._teardown(controller_client, node1, node1_id, iface1)

    def test_clear_all_policy_stats(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """clearAllPolicyStats zeroes rule counters across all rules."""
        node1, node2 = nodes["node1"], nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        ctx = self._setup_dropped_traffic(controller_client, node1, node2, node1_id)
        pe, iface1 = ctx["pe"], ctx["iface1"]
        try:
            result = controller_client.clear_all_policy_stats(node1_id)
            assert result.success, f"clearAllPolicyStats failed: {result.message}"

            packets = _wait_until_zero(lambda: _rule_packets(pe, ctx["engine_rule_id"]))
            assert packets == 0, f"rule packets not cleared, got {packets}"
        finally:
            self._teardown(controller_client, node1, node1_id, iface1)

    def test_clear_all_stats(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """clearAllStats zeroes both interface and rule counters in one shot."""
        node1, node2 = nodes["node1"], nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        ctx = self._setup_dropped_traffic(controller_client, node1, node2, node1_id)
        pe, iface1 = ctx["pe"], ctx["iface1"]
        try:
            result = controller_client.clear_all_stats(node1_id)
            assert result.success, f"clearAllStats failed: {result.message}"

            packets = _wait_until_zero(lambda: _rule_packets(pe, ctx["engine_rule_id"]))
            drops = _wait_until_zero(lambda: _iface_drops(pe, iface1))
            assert packets == 0, f"rule packets not cleared, got {packets}"
            assert drops == 0, f"interface policyDrops not cleared, got {drops}"
        finally:
            self._teardown(controller_client, node1, node1_id, iface1)

    def test_clear_stats_unknown_node_fails(
        self,
        controller_client: ControllerClient,
    ):
        """Clearing stats for a node not in the tenant must fail, not silently pass."""
        bogus = "deadbeef" * 8  # 64-hex node id that does not exist
        try:
            result = controller_client.clear_interface_stats(bogus, "eth0")
            assert not result.success, "Expected failure for unknown node"
        except RuntimeError:
            pass  # GraphQL "Node not found" error from _execute is also acceptable
