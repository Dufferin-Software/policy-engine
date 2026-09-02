# Copyright (c) Peter Morrow

"""
Scale tests: enrollment and policy distribution across N Docker-based nodes.

Each node is a policy-engine + policy-node-agent container pair.  The engine
has two interfaces:
  eth0 — scale_net (management bridge, used for controller connectivity)
  eth1 — scale_data (data bridge, used for BPF program attachment)

Run with:
  pytest tests/scale_test/ -v \\
      --package-dir /path/to/debs \\
      --engine-image policy-engine:0.1.0 \\
      --agent-image policy-node-agent:0.1.0 \\
      --scale-nodes 25
"""

import logging
import time
from typing import Dict, List

import pytest

from policy_engine_client.controller.graphql.client import ControllerClient
from tests.scale_test.conftest import (
    SCALE_FLEET_LABEL,
    ContainerPair,
    EnrollmentResult,
)

logger = logging.getLogger(__name__)

_POLICY_PROPAGATION_TIMEOUT = 60
_POLL_INTERVAL = 2


def _wait_for_rules_on_engine(engine_client, expected_count: int, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            rules = engine_client.list_rules(direction="ingress")
            if len(rules) >= expected_count:
                return True
        except Exception as e:
            logger.debug(f"Polling rules: {e}")
        time.sleep(_POLL_INTERVAL)
    return False


def _wait_for_zero_rules_on_engine(engine_client, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            rules = engine_client.list_rules(direction="ingress")
            if not rules:
                return True
        except Exception as e:
            logger.debug(f"Polling rules: {e}")
        time.sleep(_POLL_INTERVAL)
    return False


class TestEnrollmentScale:
    """Verify that all N nodes enroll successfully and the controller tracks them."""

    def test_all_nodes_enrolled(
        self, enrolled_scale_nodes: EnrollmentResult, scale_node_count: int
    ) -> None:
        assert len(enrolled_scale_nodes.node_map) == scale_node_count, (
            f"Expected {scale_node_count} enrolled nodes, "
            f"got {len(enrolled_scale_nodes.node_map)}"
        )

    def test_all_nodes_active(
        self,
        enrolled_scale_nodes: EnrollmentResult,
        controller_client: ControllerClient,
    ) -> None:
        active_ids = {n.id for n in controller_client.list_nodes(status="active")}
        not_active = [
            label
            for label, nid in enrolled_scale_nodes.node_map.items()
            if nid not in active_ids
        ]
        assert not not_active, f"Nodes not in Active state: {not_active}"

    def test_all_nodes_online(
        self,
        enrolled_scale_nodes: EnrollmentResult,
        controller_client: ControllerClient,
    ) -> None:
        online_ids = set(controller_client.online_nodes())
        not_online = [
            label
            for label, nid in enrolled_scale_nodes.node_map.items()
            if nid not in online_ids
        ]
        assert not not_online, (
            f"Nodes not online (no management gRPC session): {not_online}"
        )

    def test_enrollment_timing(
        self, enrolled_scale_nodes: EnrollmentResult, scale_node_count: int
    ) -> None:
        logger.info(
            f"Scale={scale_node_count}: "
            f"active in {enrolled_scale_nodes.seconds_to_active:.1f}s, "
            f"online in {enrolled_scale_nodes.seconds_to_online:.1f}s"
        )
        max_seconds = 60 + scale_node_count * 3
        assert enrolled_scale_nodes.seconds_to_online <= max_seconds, (
            f"Enrollment took {enrolled_scale_nodes.seconds_to_online:.1f}s, "
            f"expected ≤ {max_seconds}s for {scale_node_count} nodes"
        )

    def test_node_labels_present(
        self,
        enrolled_scale_nodes: EnrollmentResult,
        controller_client: ControllerClient,
    ) -> None:
        # Every node ZTP-enrolls through a single token carrying the fleet
        # label, which the controller stamps onto each node's `label` on
        # auto-approval. The scale-node-N keys in node_map are synthetic names
        # derived from hostnames for test messaging — they're never sent to the
        # controller, so the controller label is the shared fleet label.
        active_nodes = controller_client.list_nodes(status="active")
        label_map = {n.id: n.label for n in active_nodes}
        for synthetic_name, nid in enrolled_scale_nodes.node_map.items():
            assert label_map.get(nid) == SCALE_FLEET_LABEL, (
                f"Controller label for {synthetic_name} ({nid}) is "
                f"'{label_map.get(nid)}', expected fleet label '{SCALE_FLEET_LABEL}'"
            )


class TestScalePolicyDistribution:
    """Verify that rules pushed via the controller reach all enrolled engines."""

    @pytest.fixture(scope="class")
    def attached_programs(
        self,
        enrolled_scale_nodes: EnrollmentResult,
        scale_containers: List[ContainerPair],
        controller_client: ControllerClient,
    ) -> Dict[str, str]:
        """
        Attach an ingress BPF program to each node's data interface (eth1) via
        the controller.  Returns a mapping of controller node ID → interface name.
        """
        pair_by_label = {
            f"scale-node-{i}": pair for i, pair in enumerate(scale_containers)
        }
        iface_map: Dict[str, str] = {}
        for label, node_id in enrolled_scale_nodes.node_map.items():
            iface = pair_by_label[label].data_iface
            result = controller_client.attach_program(
                node_id=node_id,
                interface_name=iface,
                direction="ingress",
                mode="auto",
            )
            if not result.success:
                pytest.fail(
                    f"attach_program failed for {label} on {iface}: {result.message}"
                )
            iface_map[node_id] = iface
            logger.debug(f"Attached ingress on {label} ({iface})")

        logger.info(f"Ingress attached on {len(iface_map)} nodes")
        return iface_map

    def test_policy_push_all_nodes(
        self,
        attached_programs: Dict[str, str],
        enrolled_scale_nodes: EnrollmentResult,
        controller_client: ControllerClient,
        engine_client_for,
        scale_containers: List[ContainerPair],
        scale_node_count: int,
    ) -> None:
        """
        Create one ingress rule on every node via the controller, then verify
        that each engine reports it in its local rule list.
        """
        node_ids = list(enrolled_scale_nodes.node_map.values())
        # All nodes share the same data interface name (eth1) — use the first
        iface = next(iter(attached_programs.values()))

        created = controller_client.create_rules_multi_node(
            node_ids=node_ids,
            interface_name=iface,
            direction="ingress",
            src_cidr="0.0.0.0/0",
        )
        assert created, "create_rules_multi_node returned no rules"
        logger.info(f"Created {len(created)} rules across {scale_node_count} nodes")

        failures: List[int] = []
        for pair in scale_containers:
            client = engine_client_for(pair.index)
            if not _wait_for_rules_on_engine(
                client, expected_count=1, timeout=_POLICY_PROPAGATION_TIMEOUT
            ):
                failures.append(pair.index)

        assert not failures, (
            f"Rules did not propagate to engine containers: indices {failures}"
        )
        logger.info(f"Rules propagated to all {scale_node_count} engines")

        rule_ids = [r["id"] for r in created if isinstance(r, dict) and "id" in r]
        for rule_id in rule_ids:
            try:
                controller_client.delete_rule(rule_id)
            except Exception as e:
                logger.warning(f"Failed to delete rule {rule_id}: {e}")

    def test_policy_removed_from_all_nodes(
        self,
        attached_programs: Dict[str, str],
        enrolled_scale_nodes: EnrollmentResult,
        controller_client: ControllerClient,
        engine_client_for,
        scale_containers: List[ContainerPair],
        scale_node_count: int,
    ) -> None:
        """
        Create a rule, delete it, and verify all engines clear it — exercising
        the full delete propagation path.
        """
        node_ids = list(enrolled_scale_nodes.node_map.values())
        iface = next(iter(attached_programs.values()))

        created = controller_client.create_rules_multi_node(
            node_ids=node_ids,
            interface_name=iface,
            direction="ingress",
            src_cidr="10.0.0.0/8",
        )
        assert created, "create_rules_multi_node returned no rules"

        rule_ids = [r["id"] for r in created if isinstance(r, dict) and "id" in r]
        for rule_id in rule_ids:
            controller_client.delete_rule(rule_id)
        logger.info(f"Deleted {len(rule_ids)} rules from controller")

        failures: List[int] = []
        for pair in scale_containers:
            client = engine_client_for(pair.index)
            if not _wait_for_zero_rules_on_engine(
                client, timeout=_POLICY_PROPAGATION_TIMEOUT
            ):
                failures.append(pair.index)

        assert not failures, (
            f"Rules still present on engines after deletion: indices {failures}"
        )
        logger.info(f"Rules cleared from all {scale_node_count} engines")
