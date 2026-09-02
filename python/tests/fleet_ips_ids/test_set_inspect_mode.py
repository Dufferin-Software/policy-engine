# Copyright (c) Peter Morrow

"""
Fleet IPS/IDS: controller-driven inspect mode + per-interface enable.

Verifies that setInspectMode / setInspectInterface push through the gated
controller→agent path, land in the local engine, and are reflected back in
the controller's node view (agent-authoritative snapshot writeback).

Run with:
  netsim start tests/fleet_ips_ids/fleet_ips_ids.yaml
  python3 -m pytest tests/fleet_ips_ids/test_set_inspect_mode.py -v --package-dir ..
  netsim destroy tests/fleet_ips_ids/fleet_ips_ids.yaml
"""

import logging
import time

from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from tests.fleet_ips_ids.helpers import data_iface

logger = logging.getLogger(__name__)

_SETTLE_SECS = 20
_POLL = 1


def _wait_controller_inspect_mode(client, node_id, expected, timeout=_SETTLE_SECS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = client.node_inspect_state(node_id)
        if state["node"]["inspectMode"] == expected:
            return
        time.sleep(_POLL)
    raise AssertionError(
        f"controller inspectMode for {node_id} != {expected} within {timeout}s"
    )


def test_set_mode_and_interface_end_to_end(nodes, controller_client, enrolled_nodes):
    node_id = enrolled_nodes["node1"]
    engine = GraphQLPolicyClient(nodes["node1"])
    iface = data_iface(nodes["node1"])

    # The data interface must have XDP attached for TC auto-attach to work.
    controller_client.attach_program(node_id, iface, "ingress")

    # Enable node-global IPS mode.
    r = controller_client.set_inspect_mode(node_id, "ips")
    assert r.success, r.message
    _wait_controller_inspect_mode(controller_client, node_id, "ips")

    # Local engine reflects IPS + Suricata running.
    status = engine.get_inspect_status()
    assert status.mode.upper() == "IPS"

    # Enable inspection on the data interface.
    r = controller_client.set_inspect_interface(node_id, iface, True)
    assert r.success, r.message

    # Snapshot writeback marks the interface inspect-enabled on the controller.
    deadline = time.monotonic() + _SETTLE_SECS
    enabled = False
    while time.monotonic() < deadline:
        ifaces = controller_client.node_inspect_state(node_id)["nodeInterfaces"]
        if any(i["name"] == iface and i["inspectEnabled"] for i in ifaces):
            enabled = True
            break
        time.sleep(_POLL)
    assert enabled, f"interface {iface} not reported inspect-enabled on controller"

    # Disable again; controller mode returns to disabled.
    r = controller_client.set_inspect_mode(node_id, "disabled")
    assert r.success, r.message
    _wait_controller_inspect_mode(controller_client, node_id, "disabled")
