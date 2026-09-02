# Copyright (c) Peter Morrow

"""
Multi-node attach/detach and traffic enforcement tests.

Scenarios covered:

1. Attach/detach ingress BPF programs via the controller; verify the
   attachment state is reflected in ``nodeInterfaces`` and locally on
   each node.

2. Traffic enforcement: ICMP from node2 → node1 is dropped when a
   drop-ICMP ingress rule is installed and the program is attached;
   traffic passes with no rule.

3. Rules survive a BPF program detach — they remain in the local
   policy-engine and become re-enforced once the program is re-attached
   and config is pushed.

4. Per-node rule statistics increment after traffic that hits the rule
   is sent, verifiable via the local GraphQL API on each node.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_attach_detach_traffic.py -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml
"""

import logging
import time
from typing import Dict

import pytest

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


# ── TestAttachDetachController ──────────────────────────────────────────────────


class TestAttachDetachController:
    """Verify controller-driven attach/detach is reflected in nodeInterfaces."""

    def test_attach_ingress_reflected_in_nodeinterfaces(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        After attachProgram(ingress) the controller's nodeInterfaces query must
        report xdpAttached=True for the node's data interface.
        """
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)

        wait_for_node_ready(controller_client, node1_id)

        result = controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        assert result.success, f"attachProgram(ingress) failed: {result.message}"
        logger.info(f"[node1] Attached ingress on {iface}")

        time.sleep(_SETTLE_SECS)

        ifaces = controller_client.node_interfaces(node1_id)
        match = next((i for i in ifaces if i.name == iface), None)
        assert match is not None, (
            f"Interface {iface} not found in nodeInterfaces, interfaces={ifaces}"
        )
        assert match.xdp_attached, (
            f"Expected xdpAttached=True on {iface} after attach, got {match.xdp_attached}"
        )
        logger.info(f"[node1] nodeInterfaces confirms xdpAttached=True on {iface}")

    def test_detach_ingress_reflected_in_nodeinterfaces(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        After detachProgram(ingress) the controller's nodeInterfaces query must
        report xdpAttached=False for the data interface.
        """
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)

        wait_for_node_ready(controller_client, node1_id)

        # Ensure ingress is attached before testing detach
        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        time.sleep(_SETTLE_SECS)

        wait_for_node_ready(controller_client, node1_id)
        result = controller_client.detach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        assert result.success, f"detachProgram(ingress) failed: {result.message}"
        logger.info(f"[node1] Detached ingress from {iface}")

        time.sleep(_SETTLE_SECS)

        ifaces = controller_client.node_interfaces(node1_id)
        match = next((i for i in ifaces if i.name == iface), None)
        assert match is not None, f"Interface {iface} not found in nodeInterfaces"
        assert not match.xdp_attached, (
            f"Expected xdpAttached=False after detach, got {match.xdp_attached}"
        )
        logger.info(f"[node1] nodeInterfaces confirms xdpAttached=False on {iface}")

    def test_attach_detach_all_managed_nodes(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Attach ingress on every enrolled node; verify each reports
        xdpAttached=True; then detach all and verify xdpAttached=False.
        """
        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            iface = data_iface(node)

            wait_for_node_ready(controller_client, node_id)
            res = controller_client.attach_program(
                node_id=node_id,
                interface_name=iface,
                direction="ingress",
            )
            assert res.success, f"[{vm_name}] attachProgram failed: {res.message}"

        time.sleep(_SETTLE_SECS)

        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            iface = data_iface(node)
            ifaces = controller_client.node_interfaces(node_id)
            match = next((i for i in ifaces if i.name == iface), None)
            assert match is not None, f"[{vm_name}] {iface} not in nodeInterfaces"
            assert match.xdp_attached, (
                f"[{vm_name}] Expected xdpAttached=True, got False"
            )

        # Detach all
        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            iface = data_iface(node)
            wait_for_node_ready(controller_client, node_id)
            controller_client.detach_program(
                node_id=node_id,
                interface_name=iface,
                direction="ingress",
            )

        time.sleep(_SETTLE_SECS)

        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            iface = data_iface(node)
            ifaces = controller_client.node_interfaces(node_id)
            match = next((i for i in ifaces if i.name == iface), None)
            assert match is not None, (
                f"[{vm_name}] {iface} not in nodeInterfaces after detach"
            )
            assert not match.xdp_attached, (
                f"[{vm_name}] Expected xdpAttached=False after detach, got True"
            )
            logger.info(f"[{vm_name}] xdpAttached=False confirmed after detach")

    def test_local_engine_reflects_attach_state(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        The local policy-engine's status must report programAttached=True/False
        in sync with the controller attach/detach operations.
        """
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)
        pe = GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)

        # Attach via controller
        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        time.sleep(_SETTLE_SECS)

        attached_ifaces = pe.list_interfaces()
        attached_names = {i.interface for i in attached_ifaces}
        assert iface in attached_names, (
            f"Local policy-engine does not show {iface} as attached; "
            f"got: {attached_names}"
        )
        logger.info(f"[node1] Local engine confirms {iface} attached")

        # Detach via controller
        wait_for_node_ready(controller_client, node1_id)
        controller_client.detach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        time.sleep(_SETTLE_SECS)

        detached_ifaces = pe.list_interfaces()
        detached_names = {i.interface for i in detached_ifaces}
        assert iface not in detached_names, (
            f"Local engine still shows {iface} as attached after detach; "
            f"attached set: {detached_names}"
        )
        logger.info(f"[node1] Local engine confirms {iface} detached")


# ── TestTrafficEnforcement ─────────────────────────────────────────────────────


class TestTrafficEnforcement:
    """
    Send real ICMP traffic between data-network nodes and verify BPF
    drop rules take effect.

    node2 sends ICMP echo requests to node1 on the data network.  A
    drop-ICMP ingress rule is installed on node1's data interface.
    """

    def test_traffic_passes_without_rule(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        With the ingress program attached but no drop rules, ICMP from
        node2 to node1 must be received.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        wait_for_node_ready(controller_client, node1_id)

        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
        )
        time.sleep(_SETTLE_SECS)
        flush_ingress_rules(node1)

        try:
            result = send_icmp(node2, node1_ip, iface2, count=5)
            logger.info(f"[no-rule] ICMP result: {result}")
            assert result["received"] > 0, (
                f"Expected ICMP to reach node1 with no drop rule; got {result}"
            )
        finally:
            wait_for_node_ready(controller_client, node1_id)
            controller_client.detach_program(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
            )

    def test_traffic_dropped_by_ingress_rule(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        After installing a drop-ICMP ingress rule on node1 via the
        controller, pings from node2 must be dropped.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        wait_for_node_ready(controller_client, node1_id)

        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
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
        assert rule.get("id"), f"createRule returned no id: {rule}"
        logger.info(f"[node1] Installed drop-ICMP rule id={rule['id']}")
        time.sleep(_SETTLE_SECS)

        try:
            result = send_icmp(node2, node1_ip, iface2, count=5)
            logger.info(f"[drop-rule] ICMP result: {result}")
            assert result["lost"] > 0, (
                f"Expected ICMP packets to be dropped; "
                f"{result['received']}/{result['sent']} received"
            )
        finally:
            flush_ingress_rules(node1)
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            wait_for_node_ready(controller_client, node1_id)
            controller_client.detach_program(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
            )

    def test_rule_stats_increment_after_traffic(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        After sending ICMP that matches a drop rule, the rule's packet
        counter on node1's local policy-engine must be > 0.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)
        pe = GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)

        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
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
        assert rule.get("id"), f"createRule returned no id: {rule}"
        time.sleep(_SETTLE_SECS)

        # Clear stats then send 5 matching packets
        pe.clear_all_stats()
        send_icmp(node2, node1_ip, iface2, count=5)
        time.sleep(_SETTLE_SECS)

        try:
            local_rules = pe.list_rules(direction="ingress", interface=iface1)
            assert local_rules, "No ingress rules on node1 after push"
            rule_id = local_rules[0].rule_id

            stats_resp = pe.get_rule_stats(rule_id=rule_id, direction="ingress")
            matching = [rws for rws in stats_resp.rules if rws.rule.rule_id == rule_id]
            assert matching, f"No stats entry for rule {rule_id}"

            stats = matching[0].stats
            assert stats is not None, f"stats is None for rule {rule_id}"
            assert stats.packets > 0, (
                f"Expected rule {rule_id} packet counter > 0 after 5 ICMP packets, "
                f"got {stats.packets}"
            )
            logger.info(
                f"[node1] Rule {rule_id} hit: packets={stats.packets}, bytes={stats.bytes}"
            )
        finally:
            flush_ingress_rules(node1)
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            wait_for_node_ready(controller_client, node1_id)
            controller_client.detach_program(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
            )

    def test_global_stats_reflect_drops(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        After sending ICMP that hits a drop rule, the interface-level
        ``policyDrops`` stat on node1 must increase.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)
        pe = GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)

        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
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
        assert rule.get("id"), "createRule returned no id"
        time.sleep(_SETTLE_SECS)

        pe.clear_global_stats(iface1, direction="ingress")
        send_icmp(node2, node1_ip, iface2, count=5)
        time.sleep(_SETTLE_SECS)

        try:
            stats = pe.get_stats(iface1, direction="ingress")
            drops = stats.global_stats.policy_drops
            assert drops > 0, (
                f"Expected policyDrops > 0 after drop rule + traffic, got {drops}"
            )
            logger.info(f"[node1] policyDrops after traffic: {drops}")
        finally:
            flush_ingress_rules(node1)
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            wait_for_node_ready(controller_client, node1_id)
            controller_client.detach_program(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
            )


# ── TestDetachWithRulesInstalled ───────────────────────────────────────────────


class TestDetachWithRulesInstalled:
    """
    Rules installed via the controller persist in the local policy-engine
    after the BPF program is detached and are re-enforced on re-attach.
    """

    def test_rules_persist_in_engine_after_detach(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Detaching the BPF program must not remove rules from the local
        policy-engine's state.  The same rules must be listed before and
        after detach.
        """
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)
        pe = GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)

        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        time.sleep(_SETTLE_SECS)
        flush_ingress_rules(node1)

        rule = controller_client.create_rule(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        assert rule.get("id"), "createRule returned no id"
        time.sleep(_SETTLE_SECS)

        rules_before = pe.list_rules(direction="ingress")
        assert len(rules_before) >= 1, "Rule must be present before detach"
        rule_ids_before = {r.rule_id for r in rules_before}

        # Detach BPF program
        wait_for_node_ready(controller_client, node1_id)
        detach = controller_client.detach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        assert detach.success, f"detachProgram failed: {detach.message}"
        time.sleep(_SETTLE_SECS)

        rules_after = pe.list_rules(direction="ingress")
        rule_ids_after = {r.rule_id for r in rules_after}

        assert rule_ids_before.issubset(rule_ids_after), (
            f"Rules disappeared after detach; before={rule_ids_before}, "
            f"after={rule_ids_after}"
        )
        logger.info(
            f"[node1] Rules persist after detach: "
            f"before={len(rules_before)}, after={len(rules_after)}"
        )

        # Clean up
        flush_ingress_rules(node1)
        delete_controller_rules(controller_client, node1_id, iface, "ingress")

    def test_traffic_passes_after_detach_with_rules(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        When the BPF program is detached, traffic passes even if a drop rule
        is still installed in the engine — the program is no longer in the
        kernel so no enforcement occurs.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        wait_for_node_ready(controller_client, node1_id)

        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
        )
        wait_for_node_ready(controller_client, node1_id)
        flush_ingress_rules(node1)

        result = controller_client.set_interface_default_action(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
            action="pass",
        )
        assert result.success, f"setInterfaceDefaultAction failed: {result.message}"
        logger.info(f"[node1] Set ingress default to pass on {iface1}")

        ping_result = send_icmp(node2, node1_ip, iface2, count=3)
        logger.info(f"[attached+rule] ICMP: {ping_result}")
        assert ping_result["received"] == 3, (
            "Expected traffic to pass before rule install"
        )

        rule = controller_client.create_rule(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        assert rule.get("id"), "createRule returned no id"
        time.sleep(_SETTLE_SECS)

        # Confirm the rule is currently enforced
        drop_result = send_icmp(node2, node1_ip, iface2, count=3)
        logger.info(f"[attached+rule] ICMP: {drop_result}")
        assert drop_result["lost"] > 0, "Expected drops with BPF attached + rule"

        # Delete all controller rules before detaching.  Without this the
        # controller sends a DeltaConfigPush carrying those rules immediately
        # after the detach is committed, which triggers the agent's auto-attach
        # logic and re-loads the BPF program — defeating the point of the test.
        delete_controller_rules(controller_client, node1_id, iface1, "ingress")

        # Detach program
        wait_for_node_ready(controller_client, node1_id)
        controller_client.detach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
        )
        wait_for_node_ready(controller_client, node1_id)

        try:
            # Traffic should now pass (program removed from kernel path)
            pass_result = send_icmp(node2, node1_ip, iface2, count=5)
            logger.info(f"[detached+rule] ICMP: {pass_result}")
            assert pass_result["received"] > 0, (
                f"Expected traffic to pass after BPF detach (rule still in engine "
                f"but no enforcement); got {pass_result}"
            )
        finally:
            flush_ingress_rules(node1)
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")

    def test_rules_enforced_after_reattach(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Re-attaching the BPF program and pushing config restores rule
        enforcement: traffic that passed while detached is dropped again.

        Flow:
          1. attach + install drop-ICMP → pings dropped.
          2. detach → pings pass.
          3. re-attach + push_config → pings dropped again.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)
        GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)

        # 1. Attach + drop-ICMP rule
        controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
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
        assert rule.get("id"), "createRule returned no id"
        time.sleep(_SETTLE_SECS)

        try:
            drop_result = send_icmp(node2, node1_ip, iface2, count=3)
            assert drop_result["lost"] > 0, (
                f"Expected drops while attached with rule; got {drop_result}"
            )
            logger.info(f"[step1/attached] ICMP dropped: {drop_result}")

            # 2. Detach — rule remains in engine
            wait_for_node_ready(controller_client, node1_id)
            controller_client.detach_program(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
            )
            time.sleep(_SETTLE_SECS)

            pass_result = send_icmp(node2, node1_ip, iface2, count=3)
            assert pass_result["received"] > 0, (
                f"Expected traffic to pass after detach; got {pass_result}"
            )
            logger.info(f"[step2/detached] ICMP passes: {pass_result}")

            # 3. Re-attach + push_config to restore enforcement
            wait_for_node_ready(controller_client, node1_id)
            reattach = controller_client.attach_program(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
            )
            assert reattach.success, f"Re-attach failed: {reattach.message}"

            push = controller_client.push_config(node1_id)
            assert push.success, f"push_config after re-attach failed: {push.message}"
            wait_for_node_ready(controller_client, node1_id)
            time.sleep(_SETTLE_SECS)

            redrop_result = send_icmp(node2, node1_ip, iface2, count=5)
            logger.info(f"[step3/reattached] ICMP: {redrop_result}")
            assert redrop_result["lost"] > 0, (
                f"Expected traffic to be dropped after re-attach + push_config; "
                f"got {redrop_result}"
            )
        finally:
            flush_ingress_rules(node1)
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            wait_for_node_ready(controller_client, node1_id)
            controller_client.detach_program(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
            )


# ── TestMultiNodeRuleStats ─────────────────────────────────────────────────────


class TestMultiNodeRuleStats:
    """
    Install rules on multiple nodes simultaneously and verify per-node
    rule statistics after sending matching traffic to each.
    """

    def test_per_node_stats_after_multinode_rule(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Push the same drop-ICMP rule to node1 and node2 via
        createRulesMultiNode, send ICMP traffic targeting each, then
        verify each node's local rule stats show hit packets > 0.
        """
        test_nodes = {
            name: enrolled_nodes[name]
            for name in ("node1", "node2")
            if name in enrolled_nodes
        }
        if len(test_nodes) < 2:
            pytest.skip("Need at least node1 and node2 enrolled")

        node1 = nodes["node1"]
        node2 = nodes["node2"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)

        # Attach ingress and flush rules on both nodes. Defensively clear any
        # stale controller-side rules a prior (possibly failed) run may have
        # left behind, else createRulesMultiNode rejects them as duplicates.
        for vm_name, node_id in test_nodes.items():
            node = nodes[vm_name]
            iface = data_iface(node)
            wait_for_node_ready(controller_client, node_id)
            controller_client.attach_program(
                node_id=node_id,
                interface_name=iface,
                direction="ingress",
            )
            flush_ingress_rules(node)
            delete_controller_rules(controller_client, node_id, iface, "ingress")

        time.sleep(_SETTLE_SECS)

        # Both nodes share the same data interface name — use node1's
        shared_iface = iface1

        # Install drop-ICMP on node1 and node2 simultaneously
        node_ids = list(test_nodes.values())
        rules = controller_client.create_rules_multi_node(
            node_ids=node_ids,
            interface_name=shared_iface,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        assert len(rules) == len(node_ids), (
            f"Expected {len(node_ids)} rules from createRulesMultiNode, "
            f"got {len(rules)}"
        )
        logger.info(f"Installed drop-ICMP rule on {list(test_nodes.keys())}")
        time.sleep(_SETTLE_SECS)

        # Clear stats on both nodes before traffic
        for vm_name in test_nodes:
            GraphQLPolicyClient(nodes[vm_name]).clear_all_stats()

        node1_ip = get_data_ip(node1)
        node2_ip = get_data_ip(node2)

        try:
            # node2 → node1: pings hit node1's ingress drop rule
            send_icmp(node2, node1_ip, iface2, count=5)
            # node1 → node2: pings hit node2's ingress drop rule
            send_icmp(node1, node2_ip, iface1, count=5)
            time.sleep(_SETTLE_SECS)

            for vm_name in test_nodes:
                node = nodes[vm_name]
                pe = GraphQLPolicyClient(node)
                iface = data_iface(node)

                local_rules = pe.list_rules(direction="ingress", interface=iface)
                assert local_rules, (
                    f"[{vm_name}] No ingress rules after multi-node push"
                )

                rule_id = local_rules[0].rule_id
                stats_resp = pe.get_rule_stats(rule_id=rule_id, direction="ingress")
                matching = [
                    rws for rws in stats_resp.rules if rws.rule.rule_id == rule_id
                ]
                assert matching, f"[{vm_name}] No stats entry for rule {rule_id}"

                rule_stats = matching[0].stats
                assert rule_stats is not None and rule_stats.packets > 0, (
                    f"[{vm_name}] Expected rule {rule_id} packets > 0, "
                    f"got {rule_stats.packets if rule_stats else None}"
                )
                logger.info(
                    f"[{vm_name}] Rule {rule_id}: "
                    f"packets={rule_stats.packets}, bytes={rule_stats.bytes}"
                )
        finally:
            for vm_name, node_id in test_nodes.items():
                node = nodes[vm_name]
                iface = data_iface(node)
                flush_ingress_rules(node)
                delete_controller_rules(controller_client, node_id, iface, "ingress")
                wait_for_node_ready(controller_client, node_id)
                controller_client.detach_program(
                    node_id=node_id,
                    interface_name=iface,
                    direction="ingress",
                )

    def test_rule_stats_independent_per_node(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Send traffic only to node1 (not node2). node1's rule stats must
        increment; node2's stats must remain at zero — confirming stats
        are tracked independently per node.
        """
        test_nodes = {
            name: enrolled_nodes[name]
            for name in ("node1", "node2")
            if name in enrolled_nodes
        }
        if len(test_nodes) < 2:
            pytest.skip("Need at least node1 and node2 enrolled")

        node1 = nodes["node1"]
        node2 = nodes["node2"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        # Attach and flush on both nodes. Defensively clear any stale
        # controller-side rules a prior (possibly failed) run may have left
        # behind, else createRulesMultiNode rejects them as duplicates.
        for vm_name, node_id in test_nodes.items():
            node = nodes[vm_name]
            iface = data_iface(node)
            wait_for_node_ready(controller_client, node_id)
            controller_client.attach_program(
                node_id=node_id,
                interface_name=iface,
                direction="ingress",
            )
            flush_ingress_rules(node)
            delete_controller_rules(controller_client, node_id, iface, "ingress")

        time.sleep(_SETTLE_SECS)

        # Install drop-ICMP on both
        node_ids = list(test_nodes.values())
        controller_client.create_rules_multi_node(
            node_ids=node_ids,
            interface_name=iface1,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        time.sleep(_SETTLE_SECS)

        # Clear stats on both nodes
        GraphQLPolicyClient(node1).clear_all_stats()
        GraphQLPolicyClient(node2).clear_all_stats()

        try:
            # Send traffic only to node1 (from node2)
            send_icmp(node2, node1_ip, iface2, count=5)
            time.sleep(_SETTLE_SECS)

            # node1 must show hits
            pe1 = GraphQLPolicyClient(node1)
            local1 = pe1.list_rules(direction="ingress", interface=iface1)
            assert local1, "[node1] No rules found"
            rule_id1 = local1[0].rule_id
            sr1 = pe1.get_rule_stats(rule_id=rule_id1, direction="ingress")
            m1 = next((r for r in sr1.rules if r.rule.rule_id == rule_id1), None)
            assert m1 and m1.stats and m1.stats.packets > 0, (
                f"[node1] Expected rule packets > 0 after receiving traffic, "
                f"got {m1.stats.packets if m1 and m1.stats else None}"
            )
            logger.info(f"[node1] Rule hit packets={m1.stats.packets} (expected > 0)")

            # node2 must show zero hits (no traffic was directed to it)
            pe2 = GraphQLPolicyClient(node2)
            local2 = pe2.list_rules(direction="ingress", interface=iface2)
            assert local2, "[node2] No rules found"
            rule_id2 = local2[0].rule_id
            sr2 = pe2.get_rule_stats(rule_id=rule_id2, direction="ingress")
            m2 = next((r for r in sr2.rules if r.rule.rule_id == rule_id2), None)
            node2_pkts = m2.stats.packets if m2 and m2.stats else 0
            assert node2_pkts == 0, (
                f"[node2] Expected 0 rule hits (no traffic sent to node2), "
                f"got {node2_pkts}"
            )
            logger.info(f"[node2] Rule hit packets={node2_pkts} (expected 0)")
        finally:
            for vm_name, node_id in test_nodes.items():
                node = nodes[vm_name]
                iface = data_iface(node)
                flush_ingress_rules(node)
                delete_controller_rules(controller_client, node_id, iface, "ingress")
                wait_for_node_ready(controller_client, node_id)
                controller_client.detach_program(
                    node_id=node_id,
                    interface_name=iface,
                    direction="ingress",
                )
