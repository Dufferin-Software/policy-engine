# Copyright (c) Dufferin Software

"""
Fleet IPS/IDS: node capability advertisement and gating.

A node built with the suricata feature (policy-engine-ips) advertises the
"suricata" capability and "suricata_alerts" source in its AgentHello; a plain
policy-engine node advertises neither. The controller must:

  * expose inspectMode + capabilities on the node,
  * reject setInspectMode / ruleset assignment for non-capable nodes
    synchronously (an old/plain agent silently drops the message, so a push
    would otherwise strand the pending generation until its deadline).

Run with:
  netsim start tests/fleet_ips_ids/fleet_ips_ids.yaml
  python3 -m pytest tests/fleet_ips_ids/test_capabilities.py -v --package-dir ..
  netsim destroy tests/fleet_ips_ids/fleet_ips_ids.yaml
"""

import json
import logging

logger = logging.getLogger(__name__)


def _features(state: dict) -> list:
    caps = state.get("node", {}).get("capabilities", "{}")
    try:
        return json.loads(caps).get("features", [])
    except (json.JSONDecodeError, TypeError):
        return []


def test_capable_node_advertises_suricata(controller_client, enrolled_nodes):
    state = controller_client.node_inspect_state(enrolled_nodes["node1"])
    assert "suricata" in _features(state), (
        "policy-engine-ips node should advertise the suricata capability"
    )
    assert state["node"]["inspectMode"] == "disabled"


def test_plain_node_does_not_advertise_suricata(controller_client, enrolled_nodes):
    state = controller_client.node_inspect_state(enrolled_nodes["plain"])
    assert "suricata" not in _features(state), (
        "plain policy-engine node must not advertise the suricata capability"
    )


def test_set_inspect_mode_rejected_on_plain_node(controller_client, enrolled_nodes):
    result = controller_client.set_inspect_mode(enrolled_nodes["plain"], "ips")
    assert not result.success
    assert "does not support" in (result.message or "").lower()
    # Nothing was committed.
    state = controller_client.node_inspect_state(enrolled_nodes["plain"])
    assert state["node"]["inspectMode"] == "disabled"


def test_assign_ruleset_rejected_on_plain_node(controller_client, enrolled_nodes):
    rs = controller_client.create_suricata_ruleset(
        "gating-check",
        'alert tcp any any -> any any (msg:"gate"; sid:9100001; rev:1;)',
    )
    try:
        result = controller_client.assign_suricata_ruleset(
            enrolled_nodes["plain"], rs["id"]
        )
        assert not result.success
        assert "does not support" in (result.message or "").lower()
    finally:
        controller_client.delete_suricata_ruleset(rs["id"])
