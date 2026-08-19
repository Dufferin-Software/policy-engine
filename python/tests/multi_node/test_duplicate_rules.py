# Copyright (c) Dufferin Software

"""
Controller-level duplicate match-criteria rejection.

The controller must reject a rule whose match criteria (everything except the
id, actions, and lifecycle) duplicate an existing rule on the same
(node, interface, direction). For createRulesMultiNode, a conflict on ANY
selected node fails the whole mutation and creates nothing.

These mirror the engine-level checks in tests/policy_sanity/test_duplicate_rules.py
but exercise the controller GraphQL API (createRule / createRulesMultiNode), which
is the path the controller UI and CLI use.
"""

import logging
from typing import Dict

import pytest

from policy_engine_client.controller.graphql.client import ControllerClient
from tests.multi_node.helpers import (
    data_iface,
    delete_controller_rules,
    wait_for_node_ready,
)

logger = logging.getLogger(__name__)

# Substring of the controller's rejection message.
_DUP_MSG = "identical match criteria"


def _attach_ingress(controller_client: ControllerClient, node, node_id: str) -> str:
    """Attach ingress on the node's data interface and return its name."""
    iface = data_iface(node)
    wait_for_node_ready(controller_client, node_id)
    result = controller_client.attach_program(
        node_id=node_id,
        interface_name=iface,
        direction="ingress",
        mode="auto",
    )
    if not result.success:
        pytest.fail(f"Failed to attach ingress on {node.name}: {result.message}")
    return iface


class TestControllerDuplicateRules:
    def test_create_duplicate_rule_rejected(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """A second createRule with identical match criteria must be rejected,
        leaving exactly one rule in the controller store."""
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = _attach_ingress(controller_client, node1, node1_id)

        # Start from a clean slate for this (node, interface, direction).
        delete_controller_rules(controller_client, node1_id, iface, "ingress")

        wait_for_node_ready(controller_client, node1_id)
        created = controller_client.create_rule(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
            src_cidr="10.77.0.0/16",
            dst_port=8080,
            protocol="tcp",
        )
        assert created["id"], f"First create should return a rule id: {created}"

        # Same match criteria — the controller raises on the GraphQL error.
        wait_for_node_ready(controller_client, node1_id)
        with pytest.raises(RuntimeError) as exc:
            controller_client.create_rule(
                node_id=node1_id,
                interface_name=iface,
                direction="ingress",
                src_cidr="10.77.0.0/16",
                dst_port=8080,
                protocol="tcp",
                actions_json='[{"action":"pass","priority":0}]',
            )
        assert _DUP_MSG in str(exc.value), (
            f"Expected '{_DUP_MSG}' in error, got: {exc.value}"
        )

        # Only the first rule should exist in the controller store.
        rules = controller_client.list_rules_for_node(node1_id, iface, "ingress")
        assert len(rules) == 1, (
            f"Expected exactly 1 controller rule, got {len(rules)}: {rules}"
        )

        # Cleanup.
        delete_controller_rules(controller_client, node1_id, iface, "ingress")

    def test_create_rules_multi_node_duplicate_fails_wholesale(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """If the rule already exists on one selected node, createRulesMultiNode
        must fail entirely and create nothing on the other nodes."""
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        node2_id = enrolled_nodes["node2"]

        iface = _attach_ingress(controller_client, node1, node1_id)
        _attach_ingress(controller_client, node2, node2_id)

        # Clean slate on both nodes.
        delete_controller_rules(controller_client, node1_id, iface, "ingress")
        delete_controller_rules(controller_client, node2_id, iface, "ingress")

        # Pre-create the rule on node2 only.
        wait_for_node_ready(controller_client, node2_id)
        controller_client.create_rule(
            node_id=node2_id,
            interface_name=iface,
            direction="ingress",
            src_cidr="10.88.0.0/16",
            dst_port=9090,
            protocol="tcp",
        )

        # Multi-node create over [node1, node2]: node2 conflicts, so the whole
        # batch must fail and node1 must get nothing.
        wait_for_node_ready(controller_client, node1_id)
        wait_for_node_ready(controller_client, node2_id)
        with pytest.raises(RuntimeError) as exc:
            controller_client.create_rules_multi_node(
                node_ids=[node1_id, node2_id],
                interface_name=iface,
                direction="ingress",
                src_cidr="10.88.0.0/16",
                dst_port=9090,
                protocol="tcp",
            )
        assert _DUP_MSG in str(exc.value), (
            f"Expected '{_DUP_MSG}' in error, got: {exc.value}"
        )

        # node1 must have no rule (nothing created); node2 keeps its single rule.
        node1_rules = controller_client.list_rules_for_node(node1_id, iface, "ingress")
        node2_rules = controller_client.list_rules_for_node(node2_id, iface, "ingress")
        assert node1_rules == [], (
            f"node1 should have no rules after wholesale failure, got: {node1_rules}"
        )
        assert len(node2_rules) == 1, (
            f"node2 should still have its single rule, got {len(node2_rules)}"
        )

        # Cleanup.
        delete_controller_rules(controller_client, node1_id, iface, "ingress")
        delete_controller_rules(controller_client, node2_id, iface, "ingress")
