# Copyright (c) Dufferin Software

"""
Chaos tests for multi-node policy engine deployment.

These tests exercise resilience under disruptive conditions — service
restarts, concurrent restarts across nodes, full VM reboots, and rapid
rule lifecycle churn — verifying that enforcement is correct at every
stage.

Scenarios
---------
1. policy-node-agent restart with rules installed — controller re-pushes
   rules when the agent reconnects; drop enforcement resumes.
2. policy-engine restart with rules installed — engine and agent restarted
   in order; controller reconciliation restores full enforcement state.
3. Concurrent service restarts on multiple nodes — node1 and node2 agents
   restart simultaneously; both reconnect and rules remain enforced.
4. Full node reboot — VM rebooted, services manually restarted, controller
   reconciliation re-pushes config and enforcement resumes.
5. Rapid rule churn — rules installed and deleted repeatedly in quick
   succession; final clean state (no rules) is confirmed by traffic passing.
6. Add/remove rules interleaved with traffic — alternating rule install,
   traffic check (dropped), rule removal, traffic check (passes).

"""

import logging
import threading
import time
from typing import Dict, List

import pytest

from policy_engine_client.controller.graphql.client import ControllerClient
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.node import Node
from netsim.testkit.systemd_utils import (
    get_service_status,
    restart_service,
    start_service,
)
from tests.multi_node.helpers import (
    data_iface,
    delete_controller_rules,
    get_data_ip,
    send_icmp,
)
from tests.multi_node.helpers import wait_for_node_ready as wait_for_node_ready_shared

logger = logging.getLogger(__name__)

_SETTLE_SECS = 3
_POLL_INTERVAL = 1
_READY_TIMEOUT = 60
_RECONNECT_TIMEOUT = 90
_REBOOT_TIMEOUT = 150
_CHURN_CYCLES = 5


# ── Shared helpers ─────────────────────────────────────────────────────────────


def wait_for_node_ready(
    client: ControllerClient, node_id: str, timeout: int = _READY_TIMEOUT
) -> None:
    """Readiness gate with the chaos suite's longer default window.

    Thin wrapper over the shared helper that defaults ``timeout`` to
    ``_READY_TIMEOUT``; chaos nodes recovering from induced failures need
    longer than the 30 s default used elsewhere.
    """
    wait_for_node_ready_shared(client, node_id, timeout=timeout)


def _wait_for_nodes_online(
    client: ControllerClient,
    node_ids: List[str],
    timeout: int = _RECONNECT_TIMEOUT,
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
            logger.debug(f"online_nodes poll error: {e}")
        time.sleep(_POLL_INTERVAL)
    pytest.fail(f"Nodes {node_ids} did not come online within {timeout}s")


def _wait_for_ssh(node: Node, timeout: int = _REBOOT_TIMEOUT) -> None:
    """Poll until SSH is reachable on the node after a reboot."""
    time.sleep(5)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with Node._ssh_lock:
            key = node._connection_key
            if key in Node._ssh_connections:
                try:
                    Node._ssh_connections[key].close()
                except Exception:
                    pass
                del Node._ssh_connections[key]
        try:
            node.ssh_command("true", timeout=5)
            logger.info(f"[{node.name}] SSH available after reboot")
            return
        except Exception as e:
            logger.debug(f"[{node.name}] SSH not yet available: {e}")
            time.sleep(3)
    pytest.fail(
        f"[{node.name}] SSH did not become available within {timeout}s after reboot"
    )


def _attach_and_install_drop_icmp(
    client: ControllerClient,
    node_id: str,
    iface: str,
) -> dict:
    """Attach ingress program and create a drop-ICMP rule; return the rule dict."""
    wait_for_node_ready(client, node_id)
    res = client.attach_program(
        node_id=node_id,
        interface_name=iface,
        direction="ingress",
    )
    assert res.success, f"attach_program failed: {res.message}"
    time.sleep(_SETTLE_SECS)

    rule = client.create_rule(
        node_id=node_id,
        interface_name=iface,
        direction="ingress",
        protocol="icmp",
        actions_json='[{"action":"drop","priority":0}]',
    )
    assert rule.get("id"), f"createRule returned no id: {rule}"
    time.sleep(_SETTLE_SECS)
    return rule


def _cleanup_node(
    client: ControllerClient,
    node: Node,
    node_id: str,
    iface: str,
) -> None:
    """Best-effort cleanup: flush local rules, delete controller rules, detach."""
    try:
        GraphQLPolicyClient(node).flush_rules(direction="ingress")
    except Exception as e:
        logger.warning(f"[{node.name}] flush_rules: {e}")
    try:
        delete_controller_rules(client, node_id, iface, "ingress")
        wait_for_node_ready(client, node_id, timeout=30)
        client.detach_program(
            node_id=node_id, interface_name=iface, direction="ingress"
        )
    except Exception as e:
        logger.warning(f"[{node.name}] cleanup: {e}")


# ── TestAgentRestartWithRulesInstalled ────────────────────────────────────────


class TestAgentRestartWithRulesInstalled:
    """
    Rule enforcement survives a policy-node-agent restart.

    The controller holds the desired state and pushes it back when the
    agent reconnects, so a drop-ICMP rule must still be enforced.
    """

    def test_traffic_still_dropped_after_agent_restart(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        GraphQLPolicyClient(node1).flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            pre = send_icmp(node2, node1_ip, iface2, count=5)
            assert pre["lost"] > 0, (
                f"Expected ICMP drops before agent restart; got {pre}"
            )
            logger.info(
                f"[node1] Pre-restart: {pre['lost']}/{pre['sent']} packets dropped"
            )

            logger.info("[node1] Restarting policy-node-agent...")
            restart_service(node1, "policy-node-agent")

            _wait_for_nodes_online(controller_client, [node1_id])
            wait_for_node_ready(controller_client, node1_id)
            time.sleep(_SETTLE_SECS)

            post = send_icmp(node2, node1_ip, iface2, count=5)
            assert post["lost"] > 0, (
                f"Expected ICMP drops after agent restart; got {post}. "
                "Controller should have re-pushed the drop rule on reconnect."
            )
            logger.info(
                f"[node1] Post-restart: {post['lost']}/{post['sent']} packets dropped"
            )
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)

    def test_rules_present_on_local_engine_after_agent_restart(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """Local policy-engine rule list must be non-empty after agent reconnect."""
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        pe = GraphQLPolicyClient(node1)

        pe.flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            assert len(pe.list_rules(direction="ingress")) >= 1, (
                "Rule must be present before agent restart"
            )

            restart_service(node1, "policy-node-agent")
            _wait_for_nodes_online(controller_client, [node1_id])
            wait_for_node_ready(controller_client, node1_id)
            time.sleep(_SETTLE_SECS)

            rules_after = pe.list_rules(direction="ingress")
            assert len(rules_after) >= 1, (
                "Rule must still be present on local engine after agent restart "
                "and controller reconciliation"
            )
            logger.info(
                f"[node1] {len(rules_after)} rule(s) on local engine after restart"
            )
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)

    def test_agent_restart_multiple_times(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """Multiple consecutive agent restarts must not corrupt rule state."""
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        GraphQLPolicyClient(node1).flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            for i in range(3):
                logger.info(f"[node1] Agent restart cycle {i + 1}/3")
                restart_service(node1, "policy-node-agent")
                _wait_for_nodes_online(controller_client, [node1_id])
                wait_for_node_ready(controller_client, node1_id)
                time.sleep(_SETTLE_SECS)

                result = send_icmp(node2, node1_ip, iface2, count=5)
                assert result["lost"] > 0, (
                    f"[node1] Expected drops after agent restart cycle {i + 1}; "
                    f"got {result}"
                )
                logger.info(
                    f"[node1] Cycle {i + 1}: {result['lost']}/{result['sent']} dropped"
                )
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)


# ── TestEngineRestartWithRulesInstalled ───────────────────────────────────────


class TestEngineRestartWithRulesInstalled:
    """
    Rule enforcement recovers after a policy-engine restart.

    The engine restart clears in-kernel BPF state.  After the engine and
    agent restart in order, the controller re-pushes config and enforcement
    resumes.
    """

    def test_traffic_dropped_after_engine_restart(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        GraphQLPolicyClient(node1).flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            pre = send_icmp(node2, node1_ip, iface2, count=5)
            assert pre["lost"] > 0, f"Expected drops before engine restart; got {pre}"
            logger.info(f"[node1] Pre-restart: {pre['lost']}/{pre['sent']} dropped")

            # Restart engine first, then agent (engine must be up before agent
            # can connect to the local GraphQL)
            logger.info("[node1] Restarting policy-engine...")
            restart_service(node1, "policy-engine")
            time.sleep(_SETTLE_SECS)

            logger.info("[node1] Restarting policy-node-agent...")
            restart_service(node1, "policy-node-agent")

            _wait_for_nodes_online(controller_client, [node1_id])
            wait_for_node_ready(controller_client, node1_id)
            time.sleep(_SETTLE_SECS)

            post = send_icmp(node2, node1_ip, iface2, count=5)
            assert post["lost"] > 0, (
                f"Expected drops after engine+agent restart; got {post}. "
                "Controller should have re-pushed config on reconnect."
            )
            logger.info(f"[node1] Post-restart: {post['lost']}/{post['sent']} dropped")
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)

    def test_engine_stops_drops_traffic_resumes_after_restart(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        With preserve-state configured, BPF programs remain attached while the
        engine is stopped and traffic continues to be dropped.  After the engine
        and agent restart, drops resume with controller-reconciled rules.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        engine_client = GraphQLPolicyClient(node1)
        engine_client.flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            # The engine default is clear-state, which detaches BPF programs on a
            # clean shutdown.  This test verifies the preserve-state path (programs
            # stay attached while the daemon is down), so enable it explicitly.
            res = engine_client.configure_stop_behavior("preserve-state")
            assert res.success, f"Failed to set preserve-state: {res.message}"

            # Confirm drops while everything is running
            active = send_icmp(node2, node1_ip, iface2, count=5)
            assert active["lost"] > 0, (
                f"Expected drops before engine stop; got {active}"
            )

            # Stop agent then engine (agent must stop first)
            logger.info("[node1] Stopping policy-node-agent and policy-engine...")
            node1.ssh_command("sudo systemctl stop policy-node-agent", timeout=15)
            node1.ssh_command("sudo systemctl stop policy-engine", timeout=15)
            time.sleep(_SETTLE_SECS)

            # BPF programs remain attached (preserve-state default) — traffic
            # must still be dropped while the daemon is not running.
            still_dropped = send_icmp(node2, node1_ip, iface2, count=5)
            logger.info(
                f"[node1] With engine stopped: "
                f"{still_dropped['lost']}/{still_dropped['sent']} dropped"
            )
            assert still_dropped["lost"] > 0, (
                "Expected traffic to remain dropped while policy-engine is stopped "
                "(BPF programs preserved in kernel path)"
            )

            # Restart engine first, then agent
            logger.info("[node1] Restarting policy-engine...")
            start_service(node1, "policy-engine")
            time.sleep(_SETTLE_SECS)
            logger.info("[node1] Restarting policy-node-agent...")
            start_service(node1, "policy-node-agent")

            _wait_for_nodes_online(controller_client, [node1_id])
            wait_for_node_ready(controller_client, node1_id)
            time.sleep(_SETTLE_SECS)

            # Drops must resume
            resumed = send_icmp(node2, node1_ip, iface2, count=5)
            assert resumed["lost"] > 0, (
                f"Expected drops to resume after engine+agent restart; got {resumed}"
            )
            logger.info(
                f"[node1] After restart: {resumed['lost']}/{resumed['sent']} dropped"
            )
        finally:
            # Restore the default so later tests on this node aren't affected.
            try:
                GraphQLPolicyClient(node1).configure_stop_behavior("clear-state")
            except Exception as e:
                logger.warning(f"[node1] reset stop behavior: {e}")
            _cleanup_node(controller_client, node1, node1_id, iface1)

    def test_policy_engine_healthy_after_restart(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """policy-engine systemd unit must be healthy after restart."""
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)

        GraphQLPolicyClient(node1).flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            restart_service(node1, "policy-engine")
            time.sleep(_SETTLE_SECS)
            restart_service(node1, "policy-node-agent")

            _wait_for_nodes_online(controller_client, [node1_id])

            status = get_service_status(node1, "policy-engine")
            assert status.is_healthy, (
                f"[node1] policy-engine not healthy after restart: {status.status_text}"
            )
            logger.info(
                f"[node1] policy-engine healthy after restart (PID={status.main_pid})"
            )
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)


# ── TestConcurrentNodeServiceRestarts ─────────────────────────────────────────


class TestConcurrentNodeServiceRestarts:
    """
    Simultaneous service restarts across multiple nodes.

    Both node1 and node2 agents restart at the same time; all must
    reconnect and rules must remain enforced on both.
    """

    def test_concurrent_agent_restart_enforces_rules(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        test_vms = [n for n in ("node1", "node2") if n in enrolled_nodes]
        if len(test_vms) < 2:
            pytest.skip("Need at least node1 and node2 enrolled")

        node2 = nodes["node2"]
        iface2 = data_iface(node2)

        # Install drop-ICMP on node1 and node2; verify initial drops
        for vm in test_vms:
            node = nodes[vm]
            node_id = enrolled_nodes[vm]
            GraphQLPolicyClient(node).flush_rules(direction="ingress")
            _attach_and_install_drop_icmp(controller_client, node_id, data_iface(node))

        try:
            for vm in test_vms:
                node = nodes[vm]
                node_ip = get_data_ip(node)
                pre = send_icmp(node2, node_ip, iface2, count=5)
                logger.info(f"[{vm}] Pre-restart: {pre['lost']}/{pre['sent']} dropped")
                # node2 is the sender so we only check its own ingress via node1
                if vm != "node2":
                    assert pre["lost"] > 0, (
                        f"[{vm}] Expected drops before restart; got {pre}"
                    )

            # Restart agents on all test nodes concurrently
            errors: List[str] = []

            def _restart(vm: str) -> None:
                try:
                    logger.info(f"[{vm}] Restarting policy-node-agent (concurrent)")
                    restart_service(nodes[vm], "policy-node-agent")
                except Exception as e:
                    errors.append(f"[{vm}] restart failed: {e}")

            threads = [
                threading.Thread(target=_restart, args=(vm,), daemon=True)
                for vm in test_vms
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)

            assert not errors, f"Service restart errors: {errors}"

            # All nodes must reconnect
            node_ids = [enrolled_nodes[vm] for vm in test_vms]
            _wait_for_nodes_online(controller_client, node_ids)
            for nid in node_ids:
                wait_for_node_ready(controller_client, nid)
            time.sleep(_SETTLE_SECS)

            # Verify enforcement on each node
            for vm in test_vms:
                node = nodes[vm]
                node_ip = get_data_ip(node)
                result = send_icmp(node2, node_ip, iface2, count=5)
                logger.info(
                    f"[{vm}] Post-restart: {result['lost']}/{result['sent']} dropped"
                )
                if vm != "node2":
                    assert result["lost"] > 0, (
                        f"[{vm}] Expected drops after concurrent restart; got {result}"
                    )
        finally:
            for vm in test_vms:
                node = nodes[vm]
                node_id = enrolled_nodes[vm]
                _cleanup_node(controller_client, node, node_id, data_iface(node))

    def test_concurrent_engine_and_agent_restart(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """All managed nodes restart both services concurrently and recover."""
        test_vms = [n for n in ("node1", "node2") if n in enrolled_nodes]
        if len(test_vms) < 2:
            pytest.skip("Need at least node1 and node2 enrolled")

        for vm in test_vms:
            node = nodes[vm]
            node_id = enrolled_nodes[vm]
            GraphQLPolicyClient(node).flush_rules(direction="ingress")
            _attach_and_install_drop_icmp(controller_client, node_id, data_iface(node))

        try:
            errors: List[str] = []

            def _restart_both(vm: str) -> None:
                try:
                    node = nodes[vm]
                    logger.info(f"[{vm}] Restarting policy-engine + agent (concurrent)")
                    restart_service(node, "policy-engine")
                    time.sleep(1)
                    restart_service(node, "policy-node-agent")
                except Exception as e:
                    errors.append(f"[{vm}] {e}")

            threads = [
                threading.Thread(target=_restart_both, args=(vm,), daemon=True)
                for vm in test_vms
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=90)

            assert not errors, f"Restart errors: {errors}"

            node_ids = [enrolled_nodes[vm] for vm in test_vms]
            _wait_for_nodes_online(controller_client, node_ids)
            for nid in node_ids:
                wait_for_node_ready(controller_client, nid)
            time.sleep(_SETTLE_SECS)

            # All nodes must have their rules restored
            for vm in test_vms:
                node = nodes[vm]
                pe = GraphQLPolicyClient(node)
                rules = pe.list_rules(direction="ingress")
                assert len(rules) >= 1, (
                    f"[{vm}] Expected at least 1 rule after concurrent engine+agent "
                    f"restart and reconciliation; got {len(rules)}"
                )
                logger.info(
                    f"[{vm}] {len(rules)} rule(s) present after concurrent restart"
                )
        finally:
            for vm in test_vms:
                node = nodes[vm]
                node_id = enrolled_nodes[vm]
                _cleanup_node(controller_client, node, node_id, data_iface(node))


# ── TestNodeReboot ────────────────────────────────────────────────────────────


class TestNodeReboot:
    """
    Full VM reboot resilience.

    After a managed node reboots, services are restarted manually (they are
    not enabled for auto-start by the test fixtures).  The controller must
    reconcile state and push rules back; enforcement must resume.
    """

    def test_rules_enforced_after_node_reboot(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        GraphQLPolicyClient(node1).flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            # Confirm drops before reboot
            pre = send_icmp(node2, node1_ip, iface2, count=5)
            assert pre["lost"] > 0, f"Expected drops before reboot; got {pre}"
            logger.info(f"[node1] Pre-reboot: {pre['lost']}/{pre['sent']} dropped")

            # Reboot the node (SSH connection will drop immediately)
            logger.info("[node1] Initiating reboot...")
            try:
                node1.ssh_command("sudo reboot", timeout=10)
            except Exception:
                pass  # expected — connection closes when the VM reboots

            # Wait for SSH to become available again
            _wait_for_ssh(node1, timeout=_REBOOT_TIMEOUT)

            # Wait for the agent to reconnect and the controller to push config
            _wait_for_nodes_online(
                controller_client, [node1_id], timeout=_RECONNECT_TIMEOUT * 2
            )
            wait_for_node_ready(controller_client, node1_id)
            time.sleep(_SETTLE_SECS)

            # Enforcement must be restored via controller reconciliation
            post = send_icmp(node2, node1_ip, iface2, count=5)
            assert post["lost"] > 0, (
                f"Expected drops after reboot + service restart; got {post}. "
                "Controller reconciliation should have re-pushed the drop rule."
            )
            logger.info(f"[node1] Post-reboot: {post['lost']}/{post['sent']} dropped")
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)

    def test_node_still_active_after_reboot(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """Rebooting a node must not change its controller status from Active."""
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)

        GraphQLPolicyClient(node1).flush_rules(direction="ingress")
        _attach_and_install_drop_icmp(controller_client, node1_id, iface1)

        try:
            logger.info("[node1] Initiating reboot...")
            try:
                node1.ssh_command("sudo reboot", timeout=10)
            except Exception:
                pass

            _wait_for_ssh(node1, timeout=_REBOOT_TIMEOUT)

            start_service(node1, "policy-engine")
            time.sleep(_SETTLE_SECS)
            start_service(node1, "policy-node-agent")

            _wait_for_nodes_online(controller_client, [node1_id])

            active_ids = {n.id for n in controller_client.list_nodes(status="active")}
            assert node1_id in active_ids, (
                f"node1 ({node1_id}) is not Active after reboot; "
                f"active set: {active_ids}"
            )
            logger.info("[node1] Confirmed Active in controller after reboot")
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)

    def test_controller_pushes_rules_after_reboot_reconnect(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """Local policy-engine must list the drop rule after post-reboot reconnect."""
        node1 = nodes["node1"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        pe = GraphQLPolicyClient(node1)

        pe.flush_rules(direction="ingress")
        rule = _attach_and_install_drop_icmp(controller_client, node1_id, iface1)
        rule["id"]

        try:
            logger.info("[node1] Initiating reboot...")
            try:
                node1.ssh_command("sudo reboot", timeout=10)
            except Exception:
                pass

            _wait_for_ssh(node1, timeout=_REBOOT_TIMEOUT)
            start_service(node1, "policy-engine")
            time.sleep(_SETTLE_SECS)
            start_service(node1, "policy-node-agent")

            _wait_for_nodes_online(controller_client, [node1_id])
            wait_for_node_ready(controller_client, node1_id)
            time.sleep(_SETTLE_SECS)

            # The controller must have pushed the rule back
            local_rules = pe.list_rules(direction="ingress")
            assert len(local_rules) >= 1, (
                "Expected at least one rule on local engine after post-reboot "
                "controller reconciliation"
            )
            logger.info(
                f"[node1] {len(local_rules)} rule(s) on local engine after reboot"
            )
        finally:
            _cleanup_node(controller_client, node1, node1_id, iface1)


# ── TestRapidRuleChurn ─────────────────────────────────────────────────────────


class TestRapidRuleChurn:
    """
    Rapid rule install/delete cycles under live traffic.

    Rules are installed and deleted in quick succession while ICMP traffic
    is sent; each phase checks that enforcement matches the installed state.
    After all cycles the final clean state (no rules) must be confirmed by
    traffic passing.
    """

    def test_churn_install_delete_cycles(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)

        wait_for_node_ready(controller_client, node1_id)
        res = controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
        )
        assert res.success, f"attach_program failed: {res.message}"
        GraphQLPolicyClient(node1).flush_rules(direction="ingress")
        time.sleep(_SETTLE_SECS)

        try:
            for cycle in range(_CHURN_CYCLES):
                logger.info(f"[node1] Rule churn cycle {cycle + 1}/{_CHURN_CYCLES}")

                # Install drop-ICMP rule
                wait_for_node_ready(controller_client, node1_id)
                rule = controller_client.create_rule(
                    node_id=node1_id,
                    interface_name=iface1,
                    direction="ingress",
                    protocol="icmp",
                    actions_json='[{"action":"drop","priority":0}]',
                )
                assert rule.get("id"), f"Cycle {cycle + 1}: createRule returned no id"
                time.sleep(_SETTLE_SECS)

                # Traffic must be dropped
                drop_result = send_icmp(node2, node1_ip, iface2, count=5)
                assert drop_result["lost"] > 0, (
                    f"Cycle {cycle + 1}: expected drops with rule installed; "
                    f"got {drop_result}"
                )
                logger.info(
                    f"[node1] Cycle {cycle + 1}: "
                    f"{drop_result['lost']}/{drop_result['sent']} dropped (rule present)"
                )

                # Delete the rule
                wait_for_node_ready(controller_client, node1_id)
                del_result = controller_client.delete_rule(rule["id"])
                assert del_result.success, (
                    f"Cycle {cycle + 1}: deleteRule failed: {del_result.message}"
                )
                GraphQLPolicyClient(node1).flush_rules(direction="ingress")
                time.sleep(_SETTLE_SECS)

                # Traffic must pass again
                pass_result = send_icmp(node2, node1_ip, iface2, count=5)
                assert pass_result["received"] > 0, (
                    f"Cycle {cycle + 1}: expected traffic to pass after rule delete; "
                    f"got {pass_result}"
                )
                logger.info(
                    f"[node1] Cycle {cycle + 1}: "
                    f"{pass_result['received']}/{pass_result['sent']} received (no rule)"
                )
        finally:
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            try:
                GraphQLPolicyClient(node1).flush_rules(direction="ingress")
            except Exception as e:
                logger.warning(f"[node1] flush_rules during cleanup: {e}")
            wait_for_node_ready(controller_client, node1_id, timeout=30)
            controller_client.detach_program(
                node_id=node1_id, interface_name=iface1, direction="ingress"
            )

    def test_churn_multiple_rules_partial_delete(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Install two rules, delete the first, verify the second still enforces.

        Ensures rule deletion is granular — removing one rule must not remove
        or corrupt sibling rules.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)
        pe = GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)
        res = controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
        )
        assert res.success, f"attach_program failed: {res.message}"
        pe.flush_rules(direction="ingress")
        time.sleep(_SETTLE_SECS)

        try:
            # Rule A: drop ICMP
            wait_for_node_ready(controller_client, node1_id)
            rule_a = controller_client.create_rule(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
                protocol="icmp",
                actions_json='[{"action":"drop","priority":0}]',
            )
            assert rule_a.get("id"), "createRule(A) returned no id"

            # Rule B: drop TCP to an unused port — does not affect ICMP traffic
            wait_for_node_ready(controller_client, node1_id)
            rule_b = controller_client.create_rule(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
                protocol="tcp",
                dst_port=19999,
                actions_json='[{"action":"drop","priority":0}]',
            )
            assert rule_b.get("id"), "createRule(B) returned no id"
            time.sleep(_SETTLE_SECS)

            # Both rules present — ICMP must be dropped
            with_both = send_icmp(node2, node1_ip, iface2, count=5)
            assert with_both["lost"] > 0, (
                f"Expected ICMP drops with both rules; got {with_both}"
            )
            logger.info(
                f"[node1] Both rules: {with_both['lost']}/{with_both['sent']} dropped"
            )

            # Delete rule A (ICMP drop)
            wait_for_node_ready(controller_client, node1_id)
            del_a = controller_client.delete_rule(rule_a["id"])
            assert del_a.success, f"deleteRule(A) failed: {del_a.message}"
            time.sleep(_SETTLE_SECS)

            # Rule B (TCP) remains — ICMP must now pass
            after_delete_a = send_icmp(node2, node1_ip, iface2, count=5)
            assert after_delete_a["received"] > 0, (
                f"Expected ICMP to pass after deleting ICMP rule; "
                f"got {after_delete_a}. Rule B (TCP) must not affect ICMP."
            )
            logger.info(
                f"[node1] After deleting rule A: "
                f"{after_delete_a['received']}/{after_delete_a['sent']} ICMP received"
            )

            # Verify rule B is still listed on the local engine
            remaining = pe.list_rules(direction="ingress")
            assert len(remaining) >= 1, (
                "Rule B must still be present on local engine after deleting rule A"
            )
            logger.info(
                f"[node1] {len(remaining)} rule(s) remaining after partial delete"
            )
        finally:
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            try:
                pe.flush_rules(direction="ingress")
            except Exception as e:
                logger.warning(f"[node1] flush_rules during cleanup: {e}")
            wait_for_node_ready(controller_client, node1_id, timeout=30)
            controller_client.detach_program(
                node_id=node1_id, interface_name=iface1, direction="ingress"
            )

    def test_rapid_successive_rule_installs(
        self,
        nodes: Dict[str, Node],
        controller_client: ControllerClient,
        enrolled_nodes: Dict[str, str],
    ) -> None:
        """
        Install multiple rules in rapid succession without waiting for
        settlement, then verify all are present on the node and enforced.
        """
        node1 = nodes["node1"]
        node2 = nodes["node2"]
        node1_id = enrolled_nodes["node1"]
        iface1 = data_iface(node1)
        iface2 = data_iface(node2)
        node1_ip = get_data_ip(node1)
        pe = GraphQLPolicyClient(node1)

        wait_for_node_ready(controller_client, node1_id)
        res = controller_client.attach_program(
            node_id=node1_id,
            interface_name=iface1,
            direction="ingress",
        )
        assert res.success, f"attach_program failed: {res.message}"
        pe.flush_rules(direction="ingress")
        time.sleep(_SETTLE_SECS)

        created_ids: List[str] = []
        try:
            # Install _CHURN_CYCLES rules back-to-back with minimal delay
            for i in range(_CHURN_CYCLES):
                wait_for_node_ready(controller_client, node1_id)
                rule = controller_client.create_rule(
                    node_id=node1_id,
                    interface_name=iface1,
                    direction="ingress",
                    protocol="tcp",
                    dst_port=10000 + i,
                    actions_json='[{"action":"drop","priority":0}]',
                )
                assert rule.get("id"), f"createRule {i} returned no id"
                created_ids.append(rule["id"])
                logger.info(f"[node1] Installed rule {i + 1}/{_CHURN_CYCLES}")

            time.sleep(_SETTLE_SECS)

            # Add the ICMP drop rule last (only this one hits our ICMP probe)
            wait_for_node_ready(controller_client, node1_id)
            icmp_rule = controller_client.create_rule(
                node_id=node1_id,
                interface_name=iface1,
                direction="ingress",
                protocol="icmp",
                actions_json='[{"action":"drop","priority":0}]',
            )
            assert icmp_rule.get("id"), "ICMP createRule returned no id"
            created_ids.append(icmp_rule["id"])
            time.sleep(_SETTLE_SECS)

            # All rules (+1 ICMP) must be on the local engine
            local_rules = pe.list_rules(direction="ingress")
            assert len(local_rules) >= _CHURN_CYCLES + 1, (
                f"Expected {_CHURN_CYCLES + 1} rules on engine after rapid install; "
                f"got {len(local_rules)}"
            )
            logger.info(f"[node1] {len(local_rules)} rules present after rapid install")

            # ICMP must be dropped
            result = send_icmp(node2, node1_ip, iface2, count=5)
            assert result["lost"] > 0, (
                f"Expected ICMP drops after rapid rule install; got {result}"
            )
            logger.info(
                f"[node1] {result['lost']}/{result['sent']} ICMP dropped "
                "after rapid rule install"
            )
        finally:
            delete_controller_rules(controller_client, node1_id, iface1, "ingress")
            try:
                pe.flush_rules(direction="ingress")
            except Exception as e:
                logger.warning(f"[node1] flush_rules during cleanup: {e}")
            wait_for_node_ready(controller_client, node1_id, timeout=30)
            controller_client.detach_program(
                node_id=node1_id, interface_name=iface1, direction="ingress"
            )
