# Copyright (c) Dufferin Software

"""
policy-controller-client CLI smoke tests.

These tests verify that the policy-controller-client binary is functional by
exercising it via SSH on the controller node. They complement the existing
GraphQL-based multi-node tests by ensuring the CLI path works correctly.

Covered:
  - nodes list (plain and JSON output)
  - nodes pending (lists pending enrollment requests)
  - nodes connected
  - interfaces list-all
  - rules list for a node
  - audit log listing
"""

import json
import logging


from netsim.testkit.node import Node

logger = logging.getLogger(__name__)

_CONTROLLER_URL = "http://127.0.0.1:8443"


def _run_controller_cli(controller: Node, *args: str, timeout: int = 15) -> str:
    """
    Run the policy-controller-client binary on the controller node and return
    its stdout. The --json flag is always passed for reliable parsing.

    Reads the bearer token from `/tmp/netsim-controller-token` (written by
    the `controller_api_token` fixture in conftest.py); enrolled_nodes
    depends on controller_client → controller_api_token, so the file exists
    by the time any test in this module runs.
    """
    cmd_parts = [
        "POLICY_CONTROLLER_TOKEN=$(sudo cat /tmp/netsim-controller-token)",
        "policy-controller-client",
        f"--url={_CONTROLLER_URL}",
        "--json",
    ] + list(args)
    cmd = " ".join(cmd_parts)
    logger.debug(f"[controller] {cmd}")
    return controller.ssh_command(cmd, timeout=timeout)


def _run_controller_cli_json(controller: Node, *args: str, timeout: int = 15):
    """Run CLI command and parse JSON output."""
    output = _run_controller_cli(controller, *args, timeout=timeout)
    return json.loads(output)


class TestControllerCliNodes:
    """Verify node management commands through the CLI."""

    def test_nodes_list_returns_json_array(self, nodes, enrolled_nodes):
        """nodes list --json should return a JSON array."""
        controller = nodes["controller"]
        data = _run_controller_cli_json(controller, "nodes", "list")
        assert isinstance(data, list), f"Expected JSON array, got {type(data)}"

    def test_nodes_list_contains_enrolled_nodes(self, nodes, enrolled_nodes):
        """All enrolled nodes should appear in the nodes list."""
        controller = nodes["controller"]
        node_list = _run_controller_cli_json(controller, "nodes", "list")
        node_ids = {n.get("id") or n.get("nodeId") for n in node_list}
        for node_name, node_id in enrolled_nodes.items():
            assert node_id in node_ids, (
                f"Enrolled node {node_name!r} (controller id={node_id!r}) missing from CLI nodes list"
            )

    def test_nodes_list_active_filter(self, nodes, enrolled_nodes):
        """nodes list --status=active returns only active nodes."""
        controller = nodes["controller"]
        data = _run_controller_cli_json(controller, "nodes", "list", "--status=active")
        assert isinstance(data, list)
        for entry in data:
            status = entry.get("status", "").upper()
            assert status == "ACTIVE", (
                f"Expected only ACTIVE nodes, found status={status!r}"
            )

    def test_nodes_get_returns_node_details(self, nodes, enrolled_nodes):
        """nodes get <id> should return details for a specific node."""
        controller = nodes["controller"]
        any_node_id = next(iter(enrolled_nodes.values()))
        data = _run_controller_cli_json(controller, "nodes", "get", any_node_id)
        assert isinstance(data, dict), "Expected dict for single-node response"
        returned_id = data.get("id") or data.get("nodeId")
        assert returned_id == any_node_id, (
            f"Expected node {any_node_id!r}, got {returned_id!r}"
        )

    def test_nodes_pending_returns_list(self, nodes, enrolled_nodes):
        """nodes pending should return a list (possibly empty after enrollment)."""
        controller = nodes["controller"]
        data = _run_controller_cli_json(controller, "nodes", "pending")
        assert isinstance(data, list), "Expected JSON array for pending nodes"

    def test_nodes_online_returns_list(self, nodes, enrolled_nodes):
        """nodes online should return a list of currently-online node IDs."""
        controller = nodes["controller"]
        data = _run_controller_cli_json(controller, "nodes", "online")
        assert isinstance(data, list), "Expected JSON array for online nodes"


class TestControllerCliInterfaces:
    """Verify interface listing commands through the CLI."""

    def test_interfaces_list_all_returns_entries(self, nodes, enrolled_nodes):
        """interfaces list-all should return interface records for enrolled nodes."""
        controller = nodes["controller"]
        data = _run_controller_cli_json(controller, "interfaces", "list-all")
        assert isinstance(data, list), "Expected JSON array for list-all"

    def test_interfaces_list_node_returns_entries(self, nodes, enrolled_nodes):
        """interfaces list <node-id> should return interfaces for that node."""
        controller = nodes["controller"]
        any_node_id = next(iter(enrolled_nodes.values()))
        data = _run_controller_cli_json(
            controller, "interfaces", "list", "--node-id", any_node_id
        )
        assert isinstance(data, list), "Expected JSON array for node interfaces"


class TestControllerCliRules:
    """Verify rule listing commands through the CLI."""

    def test_rules_list_node_returns_list(self, nodes, enrolled_nodes):
        """rules list <node-id> should return a list (possibly empty)."""
        controller = nodes["controller"]
        any_node_id = next(iter(enrolled_nodes.values()))
        data = _run_controller_cli_json(
            controller, "rules", "list", "--node-id", any_node_id
        )
        assert isinstance(data, list), "Expected JSON array for rules list"

    def test_rules_list_node_filtered_by_direction(self, nodes, enrolled_nodes):
        """rules list <node-id> --direction=ingress should only return ingress rules."""
        controller = nodes["controller"]
        any_node_id = next(iter(enrolled_nodes.values()))
        data = _run_controller_cli_json(
            controller, "rules", "list", "--node-id", any_node_id, "--direction=ingress"
        )
        assert isinstance(data, list)
        for rule in data:
            direction = (rule.get("direction") or "").upper()
            assert direction in ("INGRESS", ""), (
                f"Expected only ingress rules, found direction={direction!r}"
            )


class TestControllerCliAuditLog:
    """Verify audit log commands through the CLI."""

    def test_audit_log_returns_list(self, nodes, enrolled_nodes):
        """audit-log list should return a JSON array."""
        controller = nodes["controller"]
        data = _run_controller_cli_json(controller, "audit", "list")
        assert isinstance(data, list), "Expected JSON array for audit log"
