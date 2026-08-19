# Copyright (c) Dufferin Software

"""
Integration test for the LocalChange write-back path.

Scenario
--------
When an operator modifies a node's policy out-of-band — typically by running
``policy-client`` on the host — the agent's change detector emits a
``LocalChangeReport`` on its management stream. The controller is expected to
treat that snapshot as authoritative for the node and persist the diff into
its own DB so subsequent ``rules list`` queries and reconciliation deltas
agree with what the agent actually has loaded.

This test exercises the write-back wiring end-to-end:

1. Pick ``node1`` and find its non-management ("data") interface so we never
   risk breaking the agent's path back to the controller.
2. Attach the XDP ingress program on that interface and push a baseline rule
   via the controller's GraphQL ``createRule`` mutation. Both the controller
   DB and the agent's policy engine now have the rule.
3. From the agent host, run ``policy-client rule add --id <X>`` with an
   explicit rule ID so we know exactly what to look for. The agent's change
   detector picks it up and forwards a ``LocalChangeReport``.
4. Poll the controller until ``list_rules_for_node`` includes the new rule.
5. From the agent host, run ``policy-client rule delete --id <baseline>``
   to remove the original rule out-of-band.
6. Poll the controller until the baseline rule is gone.
7. Query the controller's audit log via the ``policy-controller-client``
   CLI and verify at least one ``local_change_detected`` entry carries the
   ``added=1`` (from step 3) and ``deleted=1`` (from step 5) markers
   emitted by ``apply_local_change``.

Run with:
  netsim start tests/multi_node/multi_node.yaml
  python3 -m pytest tests/multi_node/test_local_change_writeback.py -v \\
      --package-dir ..
  netsim destroy tests/multi_node/multi_node.yaml

The ``policy-engine-client.deb`` package is required on agent nodes
(declared in the topology yaml) — this
test drives the agent's local engine via the ``policy-client`` CLI to
trigger a LocalChangeReport, and ``policy-engine`` only *Suggests* the
client package so apt won't pull it in automatically.
"""

import json
import logging
import time
from typing import Dict, List, Optional

import pytest

from policy_engine_client.controller.graphql.client import ControllerClient
from policy_engine_client.engine.cli.client import AddRuleOptions, PolicyClient
from netsim.testkit.node import Node

logger = logging.getLogger(__name__)

# Generous: the change detector's poll interval + the controller's RTT.
# 30s matches the rollback test's deadline and gives plenty of slack.
_SETTLE_TIMEOUT_SECS = 30
_POLL_INTERVAL = 1

# Explicit IDs so we don't have to guess what the engine auto-assigned. They
# only need to be unique within the node's local engine for the duration of
# the test; we clean both up in the finally block.
_BASELINE_RULE_ID = 990_001
_LOCAL_ADD_RULE_ID = 990_002

# Controller CLI plumbing — identical to test_controller_cli.py.
_CONTROLLER_URL = "http://127.0.0.1:8443"


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


def _audit_entries(controller: Node) -> List[dict]:
    out = _run_controller_cli(controller, "audit", "list")
    return json.loads(out)


def _wait_until(predicate, timeout: int, what: str):
    """Poll until ``predicate()`` returns truthy or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Timed out after {timeout}s waiting for: {what} (last={last!r})")


def _controller_rule_ids(
    client: ControllerClient, node_id: str, interface_name: str, direction: str
) -> set:
    rules = client.list_rules_for_node(
        node_id, interface_name=interface_name, direction=direction
    )
    return {str(r.get("id")) for r in rules}


def _find_audit_detail(
    entries: List[dict], node_id: str, marker: str
) -> Optional[dict]:
    """Return the newest local_change_detected entry for ``node_id`` whose
    detail string contains ``marker`` (e.g. ``"added=1"``)."""
    for entry in entries:
        if entry.get("action") != "local_change_detected":
            continue
        if entry.get("nodeId") != node_id and entry.get("node_id") != node_id:
            continue
        detail = entry.get("detail") or ""
        if marker in detail:
            return entry
    return None


class TestLocalChangeWriteBack:
    """The controller writes back out-of-band agent changes to its DB."""

    def test_local_change_round_trips_through_controller(
        self,
        nodes,
        topology,
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ):
        node_name = "node1"
        node = nodes[node_name]
        node_id = enrolled_nodes[node_name]
        controller = nodes["controller"]
        iface = _find_data_interface(node, topology)

        logger.info(f"Test target: {node_name} (id={node_id}) iface={iface} (ingress)")

        # 1. Sanity: node is online.
        assert node_id in set(controller_client.online_nodes()), (
            f"{node_name} not online before test"
        )

        # 2. Attach XDP ingress so rules on this iface actually load.
        attach = controller_client.attach_program(
            node_id=node_id, interface_name=iface, direction="ingress"
        )
        assert attach.success, f"attach_program failed: {attach.message}"

        # 3. Push baseline rule via the controller. After this both the DB and
        #    the agent's engine should have the rule.
        baseline = controller_client.create_rule(
            node_id=node_id,
            interface_name=iface,
            direction="ingress",
            src_cidr="10.99.0.0/24",
            dst_port=12001,
            protocol="tcp",
            actions_json='[{"action":"drop","priority":0}]',
        )
        baseline_id = str(baseline.get("id"))
        assert baseline_id, f"createRule returned no id: {baseline}"
        logger.info(f"Baseline rule id={baseline_id} pushed via controller")

        pe_cli = PolicyClient(node)
        try:
            # Confirm baseline landed locally before we start poking it.
            _wait_until(
                lambda: any(
                    str(r.rule_id) == baseline_id
                    for r in pe_cli.list_rules(direction="ingress")
                ),
                timeout=_SETTLE_TIMEOUT_SECS,
                what=f"baseline rule {baseline_id} to appear on {node_name}",
            )

            # 4. Out-of-band add via policy-client. Pin --id so we know what
            #    to look for upstream. This is the change the controller
            #    must learn about via LocalChangeReport.
            local_id = _LOCAL_ADD_RULE_ID
            add_result = pe_cli.add_rule(
                AddRuleOptions(
                    interface=iface,
                    src="10.99.1.0/24",
                    dport=12002,
                    protocol="tcp",
                    actions=[("drop", 0)],
                    rule_id=local_id,
                ),
                direction="ingress",
            )
            assert add_result.success, (
                f"local add via policy-client failed: {add_result.message}"
            )
            logger.info(
                f"[{node_name}] Added rule id={local_id} out-of-band via policy-client"
            )

            # 5. Wait for controller to learn the new rule via LocalChange.
            _wait_until(
                lambda: str(local_id)
                in _controller_rule_ids(controller_client, node_id, iface, "ingress"),
                timeout=_SETTLE_TIMEOUT_SECS,
                what=(
                    f"controller to learn locally-added rule {local_id} "
                    f"on {node_name}/{iface}"
                ),
            )
            logger.info(f"Controller DB now contains locally-added rule {local_id}")

            # The baseline rule must still be there — LocalChange is a sync,
            # not a wipe; the apply preserves unchanged rows.
            current = _controller_rule_ids(controller_client, node_id, iface, "ingress")
            assert baseline_id in current, (
                f"Baseline rule {baseline_id} disappeared from controller "
                f"after LocalChange add (current ids: {current})"
            )

            # 6. Out-of-band delete via policy-client of the baseline rule.
            del_result = pe_cli.delete_rule(
                interface=iface, rule_id=int(baseline_id), direction="ingress"
            )
            assert del_result.success, (
                f"local delete via policy-client failed: {del_result.message}"
            )
            logger.info(
                f"[{node_name}] Deleted baseline rule id={baseline_id} via "
                "policy-client"
            )

            # 7. Wait for controller to learn the deletion.
            _wait_until(
                lambda: baseline_id
                not in _controller_rule_ids(
                    controller_client, node_id, iface, "ingress"
                ),
                timeout=_SETTLE_TIMEOUT_SECS,
                what=(
                    f"controller to drop locally-deleted rule {baseline_id} "
                    f"on {node_name}/{iface}"
                ),
            )
            logger.info(f"Controller DB has dropped baseline rule {baseline_id}")

            # 8. Audit log carries the diff summary apply_local_change emits.
            entries = _audit_entries(controller)
            add_entry = _find_audit_detail(entries, node_id, "added=1")
            del_entry = _find_audit_detail(entries, node_id, "deleted=1")
            assert add_entry is not None, (
                "No local_change_detected audit entry with added=1 found for "
                f"{node_id}. Recent entries: "
                f"{[e for e in entries if e.get('action') == 'local_change_detected'][:5]}"
            )
            assert del_entry is not None, (
                "No local_change_detected audit entry with deleted=1 found for "
                f"{node_id}. Recent entries: "
                f"{[e for e in entries if e.get('action') == 'local_change_detected'][:5]}"
            )
            # apply_local_change always reports source=... in the detail.
            assert "source=" in (add_entry.get("detail") or "")
            assert "source=" in (del_entry.get("detail") or "")

        finally:
            # Best-effort cleanup so re-runs start from a clean slate.
            for rid in (baseline_id, str(_LOCAL_ADD_RULE_ID)):
                try:
                    pe_cli.delete_rule(
                        interface=iface, rule_id=int(rid), direction="ingress"
                    )
                except Exception as e:
                    logger.debug(f"cleanup delete_rule({rid}) ignored: {e}")
            try:
                controller_client.detach_program(
                    node_id=node_id, interface_name=iface, direction="ingress"
                )
            except Exception as e:
                logger.debug(f"cleanup detach_program ignored: {e}")
