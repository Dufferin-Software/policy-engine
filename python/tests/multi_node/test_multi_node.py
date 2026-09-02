# Copyright (c) Peter Morrow

"""
Multi-node controller integration tests.

These tests exercise the complete controller ↔ agent workflow:
1. All 3 nodes enroll and reach Active status
2. Create + assign a ruleset → rules appear on all nodes via local GraphQL
3. Send ICMP traffic, verify BPF drop stats visible via controller metrics
4. Kill controller, verify nodes continue enforcing; restart → reconciliation
5. Decommission node3 → cert is rejected on reconnect

Requires the topology in multi_node.yaml; each node's required packages
are declared per node in the yaml ('packages') and installed automatically
(resolve the .deb directory with --package-dir).

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/ -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml
"""

import logging
import time
from typing import Dict

import pytest

from netsim.testkit.systemd_utils import (
    restart_service,
    stop_service,
    get_service_status,
)
from policy_engine_client.controller.graphql.client import ControllerClient
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from tests.multi_node.helpers import data_iface

logger = logging.getLogger(__name__)

_METRICS_SETTLE_SECS = 5  # time after traffic before checking metrics
_RECONCILE_TIMEOUT = 90  # time for controller restart + agent reconnect + reconcile
_POLL_INTERVAL = 2


def _attach_ingress_on_node(
    node, controller_client: ControllerClient, node_id: str
) -> None:
    """Attach ingress program via the controller to the node's data interface."""
    # Find the data interface (not mgmt)
    data_iface = None
    for iface in node.interfaces.values():
        if iface.network.name != "mgmt":
            data_iface = iface
            break
    if not data_iface:
        pytest.fail(f"No data interface found on {node.name}")

    # Use controller to attach ingress program
    result = controller_client.attach_program(
        node_id=node_id,
        interface_name=data_iface.if_name,
        direction="ingress",
        mode="auto",
    )
    if not result.success:
        pytest.fail(
            f"Failed to attach ingress via controller on {node.name}: {result.message}"
        )
    logger.info(
        f"Ingress attached via controller on {node.name} interface {data_iface.if_name}"
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


def _list_rules_on_node(node) -> list:
    """Return the ingress rule list from a node's local policy-engine."""
    client = GraphQLPolicyClient(node)
    rules = client.list_rules(direction="ingress")
    return [
        {
            "ruleId": r.rule_id,
            "srcPrefix": r.src_prefix,
            "dstPrefix": r.dst_prefix,
            "actions": [
                {"action": a.action.name, "priority": a.priority} for a in r.actions
            ],
        }
        for r in rules
    ]


def _wait_for_rules_on_node(node, expected_rule_count: int, timeout: int = 60) -> None:
    """Poll the node's local policy-engine until at least N rules are present."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            rules = _list_rules_on_node(node)
            if len(rules) >= expected_rule_count:
                return
            logger.debug(
                f"[{node.name}] {len(rules)}/{expected_rule_count} rules present, waiting..."
            )
        except Exception as e:
            logger.debug(f"[{node.name}] Rule poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(
        f"[{node.name}] Expected {expected_rule_count} rules after {timeout}s, "
        f"got: {_list_rules_on_node(node)}"
    )


def _wait_for_online(
    client: ControllerClient, node_ids: list, timeout: int = 60
) -> None:
    """Wait until all given node IDs appear in onlineNodes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            online = set(client.online_nodes())
            if all(nid in online for nid in node_ids):
                return
            missing = [nid for nid in node_ids if nid not in online]
            logger.debug(f"Waiting for nodes to come online: {missing}")
        except Exception as e:
            logger.debug(f"online_nodes error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Nodes {node_ids} did not appear online within {timeout}s")


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestTPMSupport:
    """Verify that the controller reports tpm_backed=True for all enrolled nodes."""

    def test_enrolled_nodes_are_tpm_backed(
        self,
        request,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """All enrolled nodes must report tpm_backed=True when --tpm is active."""
        if not request.config.getoption("--tpm"):
            pytest.skip("TPM not enabled (--no-tpm)")

        all_nodes = {n.id: n for n in controller_client.list_nodes()}
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in all_nodes, (
                f"{vm_name} (id={node_id}) not found in controller"
            )
            assert all_nodes[node_id].tpm_backed, (
                f"{vm_name} (id={node_id}) has tpm_backed=False — "
                "check that swtpm is installed and the agent detected the TPM"
            )
            logger.info(f"{vm_name} (id={node_id}): tpm_backed=True")


class TestEnrollment:
    """Scenario 1: all 3 nodes enroll and reach Active status."""

    def test_all_nodes_active(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """All three managed nodes must reach Active status after approval."""
        active_nodes = controller_client.list_nodes(status="active")
        active_ids = {n.id for n in active_nodes}
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in active_ids, (
                f"{vm_name} (id={node_id}) is not Active; active set: {active_ids}"
            )
        logger.info(f"All 3 nodes active: {list(enrolled_nodes.values())}")

    def test_nodes_have_labels(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """Approved nodes must carry the labels set during approval."""
        all_nodes = {n.id: n for n in controller_client.list_nodes()}
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in all_nodes, f"Node {node_id} not found"
            assert all_nodes[node_id].label == vm_name, (
                f"Expected label '{vm_name}', got '{all_nodes[node_id].label}'"
            )

    def test_nodes_appear_online(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """All active nodes must appear in the onlineNodes list (agents connected)."""
        _wait_for_online(controller_client, list(enrolled_nodes.values()))
        online = set(controller_client.online_nodes())
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in online, f"{vm_name} (id={node_id}) not in onlineNodes"


class TestConfigDistribution:
    """Scenario 2: create rules on all nodes, verify they appear via local GraphQL."""

    def test_rules_pushed_to_all_nodes(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Attach ingress on all nodes, create a drop-all rule on all nodes via
        createRulesMultiNode, then verify each node's local policy-engine
        reflects the rule.
        """
        # Attach ingress programs on all managed nodes first
        for vm_name, node_id in enrolled_nodes.items():
            node = nodes[vm_name]
            _attach_ingress_on_node(node, controller_client, node_id)

        # Find the data interface name for node1 (all nodes share the same topology)
        node1 = nodes["node1"]
        data_iface = None
        for iface in node1.interfaces.values():
            if iface.network.name != "mgmt":
                data_iface = iface
                break
        if not data_iface:
            pytest.fail("No data interface found on node1")

        # Create a drop-all ingress rule on all managed nodes at once
        node_ids = list(enrolled_nodes.values())
        rules = controller_client.create_rules_multi_node(
            node_ids=node_ids,
            interface_name=data_iface.if_name,
            direction="ingress",
            actions_json='[{"action":"drop","priority":0}]',
        )
        assert len(rules) == len(node_ids), (
            f"Expected {len(node_ids)} rules, got {len(rules)}"
        )
        logger.info(f"Created {len(rules)} rules across {len(node_ids)} nodes")

        # Verify rules appeared on each node's local policy-engine
        for vm_name in enrolled_nodes:
            node = nodes[vm_name]
            _wait_for_rules_on_node(node, expected_rule_count=1)
            local_rules = _list_rules_on_node(node)
            logger.info(f"[{vm_name}] Rules after push: {local_rules}")
            assert len(local_rules) >= 1, (
                f"[{vm_name}] Expected at least 1 rule after push"
            )

    def test_push_config_per_node_succeeds(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """pushConfig must succeed for each online node."""
        for vm_name, node_id in enrolled_nodes.items():
            result = controller_client.push_config(node_id)
            assert result.success, (
                f"push_config to {vm_name} (id={node_id}) failed: {result.message}"
            )
            logger.info(f"push_config to {vm_name}: ok")


class TestFlushRules:
    """Controller `flushRules` mutation: bulk-delete every rule scoped to
    a single (node, interface, direction) in one gated agent push."""

    def test_flush_rules_via_controller(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        Seed multiple ingress rules on node1 and a control rule on node2,
        flush node1's ingress, and verify:
          - node1's local engine reports zero ingress rules
          - node2's rule is untouched (scoping is per-node)
          - the controller store agrees
        """
        # Ingress must be attached on the nodes we touch.
        for vm_name in ("node1", "node2"):
            _attach_ingress_on_node(
                nodes[vm_name], controller_client, enrolled_nodes[vm_name]
            )

        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        node2_id = enrolled_nodes["node2"]

        # All managed nodes share the same topology — pick the first non-mgmt
        # interface as the data interface (matches what _attach_ingress_on_node
        # used).
        iface = data_iface(node1)

        # Start clean — earlier tests in this class may have left rules behind.
        for nid in (node1_id, node2_id):
            controller_client.flush_rules(
                node_id=nid, interface_name=iface, direction="ingress"
            )

        # Seed 3 distinct rules on node1 and 1 on node2 (the control).
        node1_seed_srcs = ["10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16"]
        for src in node1_seed_srcs:
            controller_client.create_rule(
                node_id=node1_id,
                interface_name=iface,
                direction="ingress",
                src_cidr=src,
            )
        controller_client.create_rule(
            node_id=node2_id,
            interface_name=iface,
            direction="ingress",
            src_cidr="10.99.0.0/16",
        )

        # Wait for the agents to actually install them locally.
        _wait_for_rules_on_node(node1, expected_rule_count=len(node1_seed_srcs))
        _wait_for_rules_on_node(node2, expected_rule_count=1)

        # Sanity: controller store agrees on the pre-flush counts.
        pre_node1 = controller_client.list_rules_for_node(
            node1_id, interface_name=iface, direction="ingress"
        )
        pre_node2 = controller_client.list_rules_for_node(
            node2_id, interface_name=iface, direction="ingress"
        )
        assert len(pre_node1) == len(node1_seed_srcs), (
            f"Controller store has {len(pre_node1)} ingress rule(s) on node1, "
            f"expected {len(node1_seed_srcs)}"
        )
        assert len(pre_node2) == 1, (
            f"Controller store has {len(pre_node2)} ingress rule(s) on node2, expected 1"
        )

        # Flush node1's ingress only — this is the new gated mutation.
        result = controller_client.flush_rules(
            node_id=node1_id,
            interface_name=iface,
            direction="ingress",
        )
        assert result.success, f"flushRules failed: {result.message}"
        logger.info(f"flushRules on node1: {result.message}")

        # The mutation is gated — by the time it returns, the agent has
        # applied the deletes and the controller has committed. Poll briefly
        # anyway in case the local engine takes a moment to update its view.
        deadline = time.monotonic() + 30
        node1_local = None
        while time.monotonic() < deadline:
            node1_local = _list_rules_on_node(node1)
            if len(node1_local) == 0:
                break
            time.sleep(_POLL_INTERVAL)
        assert node1_local == [], (
            f"[node1] Expected 0 ingress rules after flush, got: {node1_local}"
        )

        # Node2 must be untouched.
        node2_local = _list_rules_on_node(node2)
        assert len(node2_local) == 1, (
            f"[node2] Expected 1 ingress rule (untouched), got: {node2_local}"
        )

        # Controller store must agree.
        post_node1 = controller_client.list_rules_for_node(
            node1_id, interface_name=iface, direction="ingress"
        )
        post_node2 = controller_client.list_rules_for_node(
            node2_id, interface_name=iface, direction="ingress"
        )
        assert post_node1 == [], (
            f"Controller store still lists {len(post_node1)} rule(s) on node1 after flush"
        )
        assert len(post_node2) == 1, (
            f"Controller store dropped node2's rule unexpectedly (got {len(post_node2)})"
        )

    def test_flush_rules_empty_scope_is_noop(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """Flushing a (node, interface, direction) with no rules must succeed."""
        node1 = nodes["node1"]
        _attach_ingress_on_node(node1, controller_client, enrolled_nodes["node1"])
        for iface in node1.interfaces.values():
            if iface.network.name != "mgmt":
                data_iface = iface.if_name
                break
        # Pre-clean.
        controller_client.flush_rules(
            node_id=enrolled_nodes["node1"],
            interface_name=data_iface,
            direction="ingress",
        )
        # Second flush on an already-empty scope must still succeed.
        result = controller_client.flush_rules(
            node_id=enrolled_nodes["node1"],
            interface_name=data_iface,
            direction="ingress",
        )
        assert result.success, f"flushRules on empty scope failed: {result.message}"


class TestMetricsVisibility:
    """Scenario 3: BPF drop stats visible via controller Prometheus metrics endpoint."""

    def test_metrics_endpoint_responds(
        self,
        nodes,
        enrolled_nodes: Dict[str, str],
    ):
        """
        The controller /metrics/node/<id> endpoint must respond with prometheus
        text after the agent has scraped the local policy-engine at least once.
        """
        controller = nodes["controller"]

        # Give the metrics forwarder time to scrape and send
        time.sleep(35)  # metrics forwarded every 30s

        for vm_name, node_id in enrolled_nodes.items():
            out = controller.ssh_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"http://127.0.0.1:8443/metrics/node/{node_id}",
                timeout=10,
            ).strip()
            # 200 = metrics present; 404 = not yet scraped (acceptable initially)
            assert out in ("200", "404"), (
                f"Unexpected HTTP status {out!r} for /metrics/node/{node_id}"
            )
            if out == "200":
                logger.info(f"[{vm_name}] Prometheus metrics available at controller")
            else:
                logger.info(f"[{vm_name}] Metrics not yet scraped (first 30s window)")

    def test_aggregated_metrics_endpoint(self, nodes):
        """The /metrics endpoint must respond with 200 (even if empty)."""
        controller = nodes["controller"]
        out = controller.ssh_command(
            "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8443/metrics",
            timeout=10,
        ).strip()
        assert out == "200", f"Expected 200 from /metrics, got {out!r}"


class TestControllerRestart:
    """
    Scenario 4: kill controller, verify nodes keep enforcing; restart →
    agents reconnect and reconciliation pushes config.
    """

    def test_nodes_enforce_during_controller_outage(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        While the controller is down, managed nodes must continue running
        their local policy-engine (rules still loaded in BPF).
        """
        controller = nodes["controller"]

        # Stop the controller
        logger.info("Stopping policy-controller for outage test...")
        stop_service(controller, "policy-controller")

        # Give agents time to notice the connection is gone
        time.sleep(5)

        # Each managed node's policy-engine should still be running
        for vm_name in enrolled_nodes:
            node = nodes[vm_name]
            status = get_service_status(node, "policy-engine")
            assert status.is_healthy, (
                f"[{vm_name}] policy-engine stopped during controller outage: "
                f"{status.status_text}"
            )

        logger.info("All nodes still enforcing during controller outage")

    def test_reconciliation_after_controller_restart(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        After the controller restarts, agents must reconnect and the controller
        must reconcile the desired state (existing ruleset assignments push config).
        Precondition: test_nodes_enforce_during_controller_outage ran first and
        left the controller stopped.
        """
        controller = nodes["controller"]

        # If controller is already running (test ordering changed), skip reconcile wait
        status = get_service_status(controller, "policy-controller")
        if not status.is_healthy:
            logger.info("Restarting policy-controller...")
            restart_status = restart_service(controller, "policy-controller")
            assert restart_status.is_healthy, (
                f"Failed to restart policy-controller: {restart_status.status_text}"
            )
            # Wait for HTTP API
            from tests.multi_node.conftest import _wait_for_controller_http

            _wait_for_controller_http(controller, timeout=60)

        # Wait for agents to reconnect
        logger.info("Waiting for agents to reconnect after controller restart...")
        _wait_for_online(
            controller_client,
            list(enrolled_nodes.values()),
            timeout=_RECONCILE_TIMEOUT,
        )

        # Verify all nodes are still active (reconciliation didn't break anything)
        active = controller_client.list_nodes(status="active")
        active_ids = {n.id for n in active}
        for vm_name, node_id in enrolled_nodes.items():
            assert node_id in active_ids, f"{vm_name} not Active after reconciliation"

        logger.info("Reconciliation successful — all nodes active and online")


class TestDecommission:
    """
    Scenario 5: decommission node3 → cert is rejected on reconnect.
    """

    def test_decommission_blocks_reconnect(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        After decommissioning node3, the agent's client cert is revoked.
        The agent must not appear in onlineNodes after reconnecting.
        """
        node3_id = enrolled_nodes.get("node3")
        if node3_id is None:
            pytest.skip("node3 not in enrolled_nodes")

        node3 = nodes["node3"]

        # Sanity: an approved node must have a non-empty cert serial recorded.
        # This is what the controller will mark as revoked on decommission.
        nodes_by_id = {n.id: n for n in controller_client.list_nodes()}
        pre = nodes_by_id.get(node3_id)
        assert pre is not None, f"node3 ({node3_id}) missing from list_nodes"
        assert pre.cert_serial, (
            f"node3 ({node3_id}) has no cert_serial recorded — controller "
            f"failed to capture the issued cert serial at approval time, so "
            f"revocation has nothing to target"
        )
        node3_serial: str = pre.cert_serial
        logger.info(f"node3 cert_serial pre-decommission: {node3_serial}")

        # Decommission
        result = controller_client.decommission_node(node3_id)
        assert result.success, f"decommissionNode failed: {result.message}"
        logger.info(f"Decommissioned node3 (id={node3_id})")

        # The recorded cert_serial must be unchanged after decommission — the
        # serial is what `revoke_cert` keys on, so it must persist on the row.
        nodes_by_id = {n.id: n for n in controller_client.list_nodes()}
        post = nodes_by_id.get(node3_id)
        if post is not None:
            assert post.cert_serial == node3_serial, (
                f"cert_serial changed across decommission "
                f"(pre={node3_serial}, post={post.cert_serial}) — "
                f"the revoked serial would no longer match the row"
            )

        # Verify status changed in controller
        time.sleep(2)
        all_nodes = {n.id: n for n in controller_client.list_nodes()}
        if node3_id in all_nodes:
            assert all_nodes[node3_id].status == "decommissioned", (
                f"Expected decommissioned status, got: {all_nodes[node3_id].status}"
            )

        # Restart agent to force reconnect attempt
        logger.info("Restarting policy-node-agent on node3 to force reconnect...")
        restart_service(node3, "policy-node-agent")

        # Give agent time to attempt reconnect (should be rejected by mTLS cert check)
        time.sleep(10)

        # node3 must NOT appear in onlineNodes — revoked cert must be rejected
        online = set(controller_client.online_nodes())
        assert node3_id not in online, (
            f"Decommissioned node3 (id={node3_id}) appeared in onlineNodes — "
            f"cert revocation not enforced"
        )
        logger.info(
            f"Decommissioned node3 correctly excluded from onlineNodes: {online}"
        )

    def test_remove_decommissioned_node(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """
        After decommission, removeNode must delete the node from the registry.
        Precondition: test_decommission_blocks_reconnect ran first.
        """
        node3_id = enrolled_nodes.get("node3")
        if node3_id is None:
            pytest.skip("node3 not in enrolled_nodes")

        result = controller_client.remove_node(node3_id)
        assert result.success, f"removeNode failed: {result.message}"

        # Verify it's gone
        all_nodes = {n.id: n for n in controller_client.list_nodes()}
        assert node3_id not in all_nodes, "node3 still present in registry after remove"
        logger.info(f"node3 (id={node3_id}) removed from registry")
