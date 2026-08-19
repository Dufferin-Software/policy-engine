# Copyright (c) Dufferin Software

"""
Regression test: a controller-driven fleet rule must not echo back as a
"local change".

Background
----------
The fleet rule creator in the controller UI installs a rule on each selected
target by looping the gated ``createRule`` mutation once per node. Each gated
push installs the rule into the node's local policy-engine and only *afterwards*
refreshes the agent's change-detector baseline. The change detector runs as a
separate task that polls the local engine every few seconds.

The bug this guards against: a poll landing in the window *after* the rule was
installed but *before* the baseline was refreshed classified the controller's
own rule as an out-of-band *local* edit and emitted a ``LocalChangeReport``.
The controller then "adopted" that snapshot via ``apply_local_change``,
relabelling the rule's provenance and — racing the pending commit's bare
``INSERT`` — potentially landing a duplicate row. The operator-visible
symptoms were spurious ``local_change_detected`` audit entries and, on an
unlucky node, two rules where one was created.

The fix serialises the change-detector poll against the controller-apply
critical section (apply + baseline refresh) so the poll can never observe a
half-applied push, and makes the controller's ``create_rule`` an idempotent
upsert as a backstop.

Scenario
--------
1. Pick node1 and node2, attach XDP ingress on each node's data interface.
2. Record how many ``local_change_detected`` audit entries each node already
   has (prior tests in the package may have produced some).
3. Create the *same* rule (dst 1.1.1.1/32, protocol icmp, LOG action — the
   shape from the original bug report) on each node via the per-node gated
   ``createRule``, exactly as the fleet rule creator does.
4. Wait for each rule to land in its node's local engine, then wait several
   change-detector poll cycles so a racing/echoing detector has ample
   opportunity to misfire.
5. Assert the controller-only workflow produced **no new**
   ``local_change_detected`` audit entries for either node, that each node's
   controller DB holds **exactly one** matching rule, and that each node's
   local engine holds **exactly one** rule with the created id.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_fleet_rule_no_local_change_echo.py -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml

``policy-engine-client.deb`` is needed on the agent nodes (declared in
the topology yaml) so this test can read
the local engine's rule table via ``policy-client``.
"""

import json
import logging
import time
from typing import Dict, List

import pytest

from policy_engine_client.controller.graphql.client import ControllerClient
from policy_engine_client.engine.cli.client import PolicyClient
from netsim.testkit.node import Node

from .helpers import wait_for_node_ready

logger = logging.getLogger(__name__)

# The agent's change detector polls the local engine every 5s. Wait a few
# cycles (plus controller RTT slack) so a detector that was going to echo the
# controller's own push back as a local change has had every chance to fire.
_DETECTOR_SETTLE_SECS = 20
_LAND_TIMEOUT_SECS = 30
_POLL_INTERVAL = 1

# Distinctive match so we never count rules left behind by other tests in the
# package. Mirrors the shape from the original bug report.
_DST_CIDR = "1.1.1.1/32"
_PROTOCOL = "icmp"
_ACTIONS_JSON = '[{"action":"log","priority":0,"param":0}]'

_CONTROLLER_URL = "http://127.0.0.1:8443"

# The two targets a fleet rule fans out to in this scenario.
_TARGET_VMS = ["node1", "node2"]


def _find_data_interface(node: Node, topology) -> str:
    """Return the ``data`` network interface name on ``node`` (NOT mgmt)."""
    for iface in node.interfaces.values():
        if iface.network.name == "data":
            return iface.if_name
    pytest.fail(f"No 'data' interface found on {node.name}")


def _run_controller_cli(controller: Node, *args: str, timeout: int = 15) -> str:
    cmd = " ".join(
        [
            "POLICY_CONTROLLER_TOKEN=$(sudo cat /tmp/netsim-controller-token)",
            "policy-controller-client",
            f"--url={_CONTROLLER_URL}",
            "--json",
            *args,
        ]
    )
    return controller.ssh_command(cmd, timeout=timeout)


def _local_change_count(controller: Node, node_id: str) -> int:
    """Number of ``local_change_detected`` audit entries recorded for a node."""
    out = _run_controller_cli(controller, "audit", "list")
    entries: List[dict] = json.loads(out)
    return sum(
        1
        for e in entries
        if e.get("action") == "local_change_detected"
        and (e.get("nodeId") == node_id or e.get("node_id") == node_id)
    )


def _matching_controller_rules(
    client: ControllerClient, node_id: str, iface: str
) -> list:
    """Controller-stored ingress rules on ``iface`` matching our test rule shape."""
    return [
        r
        for r in client.list_rules_for_node(
            node_id, interface_name=iface, direction="ingress"
        )
        if r.get("dstCidr") == _DST_CIDR
        and (r.get("protocol") or "").lower() == _PROTOCOL
    ]


def _wait_until(predicate, timeout: int, what: str):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Timed out after {timeout}s waiting for: {what} (last={last!r})")


class TestFleetRuleNoLocalChangeEcho:
    """A controller-driven multi-node rule create must not self-trigger
    local-change detection or duplicate rows."""

    def test_fleet_rule_does_not_echo_as_local_change(
        self,
        nodes,
        topology,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        controller = nodes["controller"]

        # Resolve targets: (vm_name, node, node_id, iface, PolicyClient).
        targets = []
        for vm in _TARGET_VMS:
            node = nodes[vm]
            node_id = enrolled_nodes[vm]
            iface = _find_data_interface(node, topology)
            targets.append((vm, node, node_id, iface, PolicyClient(node)))

        online = set(controller_client.online_nodes())
        for vm, _node, node_id, _iface, _pe in targets:
            assert node_id in online, f"{vm} ({node_id}) not online before test"

        created_ids: Dict[str, str] = {}
        try:
            # Attach ingress + snapshot the pre-create local-change audit count.
            baseline_counts: Dict[str, int] = {}
            for vm, _node, node_id, iface, _pe in targets:
                wait_for_node_ready(controller_client, node_id)
                attach = controller_client.attach_program(
                    node_id=node_id, interface_name=iface, direction="ingress"
                )
                assert attach.success, f"[{vm}] attach_program failed: {attach.message}"
                baseline_counts[node_id] = _local_change_count(controller, node_id)
                logger.info(
                    f"[{vm}] attached ingress on {iface}; "
                    f"baseline local_change count={baseline_counts[node_id]}"
                )

            # Fan the same rule out across both targets, one gated createRule per
            # node — exactly what the fleet rule creator does.
            for vm, _node, node_id, iface, _pe in targets:
                wait_for_node_ready(controller_client, node_id)
                rule = controller_client.create_rule(
                    node_id=node_id,
                    interface_name=iface,
                    direction="ingress",
                    dst_cidr=_DST_CIDR,
                    protocol=_PROTOCOL,
                    actions_json=_ACTIONS_JSON,
                )
                rid = str(rule.get("id"))
                assert rid, f"[{vm}] createRule returned no id: {rule}"
                created_ids[vm] = rid
                logger.info(f"[{vm}] created fleet rule id={rid} on {iface}")

            # Each rule must land in its node's local engine before we judge the
            # detector — otherwise we'd measure an idle window.
            for vm, _node, node_id, iface, pe in targets:
                rid_int = int(created_ids[vm])
                _wait_until(
                    lambda pe=pe, rid=rid_int: any(
                        r.rule_id == rid for r in pe.list_rules(direction="ingress")
                    ),
                    timeout=_LAND_TIMEOUT_SECS,
                    what=f"rule {rid_int} to load in {vm}'s local engine",
                )

            # Give the change detector several poll cycles to (mis)fire.
            logger.info(
                f"Waiting {_DETECTOR_SETTLE_SECS}s for change-detector poll cycles…"
            )
            time.sleep(_DETECTOR_SETTLE_SECS)

            # ── Assertions ────────────────────────────────────────────────────
            for vm, _node, node_id, iface, pe in targets:
                rid = created_ids[vm]

                # (1) The controller-only workflow must not have tripped local
                #     change detection. This is the core regression: the agent's
                #     poll used to echo the controller's own push back.
                after = _local_change_count(controller, node_id)
                assert after == baseline_counts[node_id], (
                    f"[{vm}] controller-driven createRule produced "
                    f"{after - baseline_counts[node_id]} spurious "
                    f"local_change_detected audit entr(ies) "
                    f"(before={baseline_counts[node_id]}, after={after})"
                )

                # (2) Exactly one matching rule in the controller DB — no
                #     duplicate row from a racing apply_local_change adoption.
                ctrl_matches = _matching_controller_rules(
                    controller_client, node_id, iface
                )
                assert len(ctrl_matches) == 1, (
                    f"[{vm}] expected exactly one controller rule for "
                    f"{_DST_CIDR}/{_PROTOCOL}, found {len(ctrl_matches)}: "
                    f"{[m.get('id') for m in ctrl_matches]}"
                )
                assert str(ctrl_matches[0].get("id")) == rid, (
                    f"[{vm}] controller rule id changed under us: "
                    f"created {rid}, found {ctrl_matches[0].get('id')}"
                )

                # (3) Exactly one rule with the created id in the local engine.
                local_matches = [
                    r
                    for r in pe.list_rules(direction="ingress")
                    if r.rule_id == int(rid)
                ]
                assert len(local_matches) == 1, (
                    f"[{vm}] expected exactly one local engine rule with id {rid}, "
                    f"found {len(local_matches)}"
                )

                logger.info(
                    f"[{vm}] OK — 1 controller rule, 1 local rule, "
                    f"no spurious local_change_detected"
                )

        finally:
            # Best-effort cleanup so re-runs start clean.
            for vm, _node, node_id, iface, _pe in targets:
                cleanup_rid = created_ids.get(vm)
                if cleanup_rid:
                    try:
                        controller_client.delete_rule(cleanup_rid)
                    except Exception as e:
                        logger.debug(
                            f"[{vm}] cleanup delete_rule({cleanup_rid}) ignored: {e}"
                        )
                try:
                    controller_client.detach_program(
                        node_id=node_id, interface_name=iface, direction="ingress"
                    )
                except Exception as e:
                    logger.debug(f"[{vm}] cleanup detach_program ignored: {e}")
