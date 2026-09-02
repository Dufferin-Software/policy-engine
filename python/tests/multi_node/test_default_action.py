# Copyright (c) Peter Morrow

"""
Integration tests for per-interface default action via the controller API.

The controller's ``setInterfaceDefaultAction`` mutation persists a default
action for a specific interface+direction and propagates it to the agent via
the full-restore push (confirmed by ConfigConfirm handshake).  These tests:

1. Verify the value is stored in the controller DB (nodeInterfaces query).
2. Verify that push_config succeeds end-to-end (agent applied and confirmed).
3. Verify setting back to pass is also reflected.
4. Verify invalid inputs are rejected.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_default_action.py -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml
"""

import logging
from typing import Dict

from policy_engine_client.controller.graphql.client import ControllerClient
from tests.multi_node.helpers import data_iface, wait_for_node_ready

logger = logging.getLogger(__name__)


class TestPerInterfaceDefaultAction:
    """Controller-managed per-interface default action end-to-end."""

    def test_set_ingress_default_drop_stored_in_controller(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        ``setInterfaceDefaultAction`` must persist the value and expose it
        via ``nodeInterfaces(nodeId)``.
        """
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)

        wait_for_node_ready(controller_client, node1_id)

        result = controller_client.set_interface_default_action(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
            action="drop",
        )
        assert result.success, f"setInterfaceDefaultAction failed: {result.message}"
        logger.info(f"[node1] Set ingress default to drop on {iface}")

        # The value must be visible in nodeInterfaces
        ifaces = controller_client.node_interfaces(node1_id)
        match = next((i for i in ifaces if i.name == iface), None)
        assert match is not None, f"Interface {iface} not found in nodeInterfaces"
        assert match.ingress_default_action == "drop", (
            f"Expected ingressDefaultAction='drop', got {match.ingress_default_action!r}"
        )

    def test_set_ingress_default_drop_propagated_to_node(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        After ``setInterfaceDefaultAction``, push_config must complete the
        agent confirm handshake successfully — meaning the agent received
        and applied the new default.

        Precondition: test_set_ingress_default_drop_stored_in_controller ran first.
        """
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)

        # Attach ingress so the default action is active on the BPF program
        result = controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        # Attachment may already be present from a prior test in the suite
        logger.info(f"[node1] attach_program(ingress): success={result.success}")

        # Push config includes the ingress default=drop; the mutation blocks until
        # the agent sends ConfigConfirm(APPLIED), so success here proves the
        # node applied the change.
        push_result = controller_client.push_config(node1_id)
        assert push_result.success, f"push_config failed: {push_result.message}"
        logger.info(
            f"[node1] push_config confirmed ingress default=drop applied on {iface}"
        )

        # push_config is fire-and-forget on the controller side; the agent
        # may briefly drop and re-establish its gRPC session while applying
        # a full-restore push.  Wait until it is back online before handing
        # off to the next test.
        wait_for_node_ready(controller_client, node1_id)

    def test_reset_ingress_default_to_pass(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Setting the default action back to ``pass`` must be stored in the
        controller and propagated to the node via push_config.
        """
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)

        wait_for_node_ready(controller_client, node1_id)

        result = controller_client.set_interface_default_action(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
            action="pass",
        )
        assert result.success, (
            f"setInterfaceDefaultAction(pass) failed: {result.message}"
        )

        push_result = controller_client.push_config(node1_id)
        assert push_result.success, f"push_config failed: {push_result.message}"
        logger.info(
            f"[node1] push_config confirmed ingress default=pass applied on {iface}"
        )

        # Controller DB must also reflect the new value
        ifaces = controller_client.node_interfaces(node1_id)
        match = next((i for i in ifaces if i.name == iface), None)
        assert match is not None, f"Interface {iface} not found in nodeInterfaces"
        assert match.ingress_default_action == "pass", (
            f"Expected ingressDefaultAction='pass', got {match.ingress_default_action!r}"
        )

    def test_egress_default_drop_stored_in_controller(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """Egress default action is stored and queryable independently of ingress."""
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface = data_iface(node1)

        wait_for_node_ready(controller_client, node1_id)

        result = controller_client.set_interface_default_action(
            node_id=node1_id,
            interface_name=iface,
            direction="egress",
            action="drop",
        )
        assert result.success, (
            f"setInterfaceDefaultAction(egress/drop) failed: {result.message}"
        )

        ifaces = controller_client.node_interfaces(node1_id)
        match = next((i for i in ifaces if i.name == iface), None)
        assert match is not None
        assert match.egress_default_action == "drop", (
            f"Expected egressDefaultAction='drop', got {match.egress_default_action!r}"
        )

        # Reset
        controller_client.set_interface_default_action(
            node_id=node1_id,
            interface_name=iface,
            direction="egress",
            action="pass",
        )

    def test_invalid_action_rejected(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """``setInterfaceDefaultAction`` with an unknown action must fail gracefully."""
        node1_id = enrolled_nodes["node1"]
        try:
            result = controller_client.set_interface_default_action(
                node_id=node1_id,
                interface_name="eth0",
                direction="ingress",
                action="banana",
            )
            assert not result.success, "Expected failure for invalid action 'banana'"
        except RuntimeError:
            pass  # GraphQL error raised by _execute — also acceptable

    def test_invalid_direction_rejected(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """``setInterfaceDefaultAction`` with an invalid direction must fail gracefully."""
        node1_id = enrolled_nodes["node1"]
        try:
            result = controller_client.set_interface_default_action(
                node_id=node1_id,
                interface_name="eth0",
                direction="sideways",
                action="drop",
            )
            assert not result.success, (
                "Expected failure for invalid direction 'sideways'"
            )
        except RuntimeError:
            pass
