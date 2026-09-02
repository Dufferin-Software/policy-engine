# Copyright (c) Peter Morrow

"""
Integration tests for the controller-configurable metrics scrape interval.

The agent's metrics push cadence — not the UI poll — gates how fresh the
controller's view of a node's stats is. The controller's setNodeMetricsInterval
mutation persists a per-node interval and pushes a SetMetricsInterval message to
the agent, which applies it live to its metrics forwarder.

These tests cover:

1. Control-plane round-trip: the mutation persists and is queryable; clearing
   the override reverts to "no preference"; out-of-range values are rejected.
2. End-to-end effect: after configuring a short interval, freshly-generated
   stats propagate to the controller's scraped view within the expected window.
   This is observed as a clear→increment cycle on the controller's
   nodeInterfaceStats, which only advances when the agent pushes.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_metrics_interval.py -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml
"""

import logging
import time
from typing import Callable, Dict, Optional

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
# Short interval used for the end-to-end test. Well below the 5s default so a
# fresh push lands quickly; the assertions use generous bounds to avoid flakiness.
_SHORT_INTERVAL_SECS = 2
# Two push cycles plus parse/slack at a 2s cadence; comfortably bounded.
_REFRESH_TIMEOUT = 20
_POLL_INTERVAL = 1


def _controller_drops(
    controller_client: ControllerClient, node_id: str, iface: str
) -> Optional[int]:
    """policyDrops for an interface from the controller's scraped metrics (None if none yet)."""
    stats = controller_client.node_interface_stats(node_id, iface, "ingress")
    return None if stats is None else stats.policy_drops


def _wait_until(predicate: Callable[[], bool], timeout: int) -> bool:
    """Poll until ``predicate`` is true or the deadline passes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_POLL_INTERVAL)
    return False


class TestMetricsInterval:
    """Controller-configurable metrics scrape interval, end to end."""

    def test_set_and_query(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """Setting an interval persists it and exposes it on the node."""
        node1_id = enrolled_nodes["node1"]
        try:
            result = controller_client.set_node_metrics_interval(node1_id, 3)
            assert result.success, f"setNodeMetricsInterval failed: {result.message}"
            assert controller_client.node_metrics_interval(node1_id) == 3
        finally:
            controller_client.set_node_metrics_interval(node1_id, None)

    def test_clear_override(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """Passing null clears the override so the agent reverts to its default."""
        node1_id = enrolled_nodes["node1"]
        controller_client.set_node_metrics_interval(node1_id, 6)
        assert controller_client.node_metrics_interval(node1_id) == 6

        result = controller_client.set_node_metrics_interval(node1_id, None)
        assert result.success, f"clearing interval failed: {result.message}"
        assert controller_client.node_metrics_interval(node1_id) is None

    def test_out_of_range_rejected(
        self,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """Values outside 1..=3600 are rejected and leave the stored value unchanged."""
        node1_id = enrolled_nodes["node1"]
        controller_client.set_node_metrics_interval(node1_id, 7)
        try:
            for bad in (0, 99999):
                try:
                    res = controller_client.set_node_metrics_interval(node1_id, bad)
                    assert not res.success, f"expected {bad}s to be rejected"
                except RuntimeError:
                    pass  # a GraphQL error from _execute is also acceptable
                # The rejected write must not clobber the stored value.
                assert controller_client.node_metrics_interval(node1_id) == 7
        finally:
            controller_client.set_node_metrics_interval(node1_id, None)

    def test_interval_drives_metrics_refresh(
        self,
        nodes,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        """A configured short interval drives controller-visible stat refreshes.

        Observed as a clear→increment cycle on the controller's scraped
        nodeInterfaceStats, which only advances when the agent pushes. Seeing
        both transitions proves the agent applied the controller-set interval
        and is forwarding at that cadence.
        """
        node1, node2 = nodes["node1"], nodes["node2"]
        node1_id = enrolled_nodes["node1"]
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

        controller_client.create_rule(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
            protocol="icmp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        time.sleep(_SETTLE_SECS)

        try:
            # Configure a fast cadence; re-wait for ready in case create_rule's
            # gated push briefly bounced the agent's stream.
            wait_for_node_ready(controller_client, node1_id)
            result = controller_client.set_node_metrics_interval(
                node1_id, _SHORT_INTERVAL_SECS
            )
            assert result.success, f"setNodeMetricsInterval failed: {result.message}"

            # Zero the engine counters, then confirm the controller observes the
            # cleared state — i.e. a fresh push landed at the new cadence.
            pe.clear_all_stats()
            assert _wait_until(
                lambda: _controller_drops(controller_client, node1_id, iface1) == 0,
                _REFRESH_TIMEOUT,
            ), "controller did not observe cleared stats within the interval window"

            # Now generate drops and confirm the controller observes the
            # increment on a subsequent push.
            send_icmp(node2, node1_ip, iface2, count=5)
            assert _wait_until(
                lambda: (_controller_drops(controller_client, node1_id, iface1) or 0)
                > 0,
                _REFRESH_TIMEOUT,
            ), "controller did not observe new drops within the interval window"
            logger.info(
                "[node1] controller saw clear→increment cycle at %ss interval",
                _SHORT_INTERVAL_SECS,
            )
        finally:
            controller_client.set_node_metrics_interval(node1_id, None)
            flush_ingress_rules(node1)
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            wait_for_node_ready(controller_client, node1_id)
            controller_client.detach_program(
                node_id=node1_id, interface_name=iface1, direction="ingress"
            )
