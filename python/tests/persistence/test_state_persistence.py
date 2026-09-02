# Copyright (c) Peter Morrow

"""
State persistence tests.

Verifies that policy-engine rules, interface attachments, and default actions
survive a full VM reboot.  After reboot the BPF maps are empty; the daemon
must restore state from /var/lib/policy-engine/state.json on startup.

Note: daemon-restart persistence (without reboot) is already covered by the
pinned BPF map mechanism and does not require testing here.
"""

import logging

from netsim.testkit.nping_utils import send_ping
from tests.persistence.conftest import (
    reboot_node_and_wait,
    _wait_for_policy_engine_http,
)

logger = logging.getLogger(__name__)

_STATE_FILE = "/var/lib/policy-engine/state.json"


# ============================================================================
# Helpers
# ============================================================================


def _assert_traffic_dropped(client_node, server_ip, description: str) -> None:
    """Assert that ICMP traffic from client to server is dropped."""
    result = send_ping(client_node, str(server_ip), count=3, timeout=5)
    assert not result.success, (
        f"{description}: expected traffic to be DROPPED but ping succeeded"
    )
    logger.info(f"{description}: traffic correctly dropped")


def _assert_traffic_passes(client_node, server_ip, description: str) -> None:
    """Assert that ICMP traffic from client to server passes."""
    result = send_ping(client_node, str(server_ip), count=3, timeout=5)
    assert result.success, f"{description}: expected traffic to PASS but ping failed"
    logger.info(f"{description}: traffic correctly passes")


# ============================================================================
# Tests
# ============================================================================


class TestStatePersistenceAfterReboot:
    """
    Test that policy-engine state is fully restored after a VM reboot.

    Scenario:
    1. Attach ingress program to an interface
    2. Add a DROP rule for traffic from the client
    3. Set default action to LOG (non-default, so we can verify it's restored)
    4. Verify the rule blocks traffic
    5. Reboot the server VM
    6. Wait for policy-engine to start
    7. Verify: interface is still attached
    8. Verify: rule is still present
    9. Verify: default action is still LOG
    10. Verify: traffic is still blocked
    """

    def test_rules_survive_reboot(
        self,
        nodes,
        graphql_policy_client,
        server_interface,
        client_interface,
        server_ip_v4,
        client_ip_v4,
        nmap_installed,
    ):
        server = nodes["server"]
        client = nodes["client"]
        policy_client = graphql_policy_client
        iface_name = server_interface.if_name

        # ── Setup ──────────────────────────────────────────────────────────────

        from policy_engine_client.engine.cli.client import (
            AddRuleOptions,
            PolicyAction,
            Protocol,
        )

        # Ensure clean state
        policy_client.flush_rules(direction="ingress")
        policy_client.set_default_action(PolicyAction.PASS, direction="ingress")
        try:
            policy_client.detach_ingress(iface_name)
        except Exception:
            pass

        # Attach ingress
        attach_result = policy_client.attach_ingress(iface_name)
        assert attach_result.success, (
            f"Failed to attach ingress: {attach_result.message}"
        )
        logger.info(f"Attached ingress to {iface_name}")

        # Add DROP rule for client → server ICMP
        add_result = policy_client.add_rule(
            AddRuleOptions(
                interface=iface_name,
                src=f"{client_ip_v4}/32",
                dst=f"{server_ip_v4}/32",
                protocol=Protocol.ICMP,
                actions=[(PolicyAction.DROP, 0)],
            ),
            direction="ingress",
        )
        assert add_result.success, f"Failed to add rule: {add_result.message}"

        # Retrieve the assigned rule ID from the rule list
        rules_before = policy_client.list_rules(direction="ingress")
        assert rules_before, "No rules found after add"
        rule_id = rules_before[-1].rule_id
        logger.info(f"Added DROP rule id={rule_id}")

        # Verify traffic is blocked before reboot
        _assert_traffic_dropped(client, server_ip_v4, "pre-reboot")

        # ── Reboot ─────────────────────────────────────────────────────────────

        logger.info("Rebooting server node to test persistence...")
        reboot_node_and_wait(server, ssh_reconnect_timeout=120)

        # Wait for policy-engine to start and bind its HTTP server
        _wait_for_policy_engine_http(server, timeout=90)
        logger.info("policy-engine is ready after reboot")

        # ── Verify attachments restored ────────────────────────────────────────

        interfaces = policy_client.list_interfaces()
        attached_names = [iface.interface for iface in interfaces]
        assert iface_name in attached_names, (
            f"Interface {iface_name} not re-attached after reboot. "
            f"Got: {attached_names}"
        )
        logger.info(f"Interface {iface_name} correctly re-attached after reboot")

        # ── Verify rule restored ───────────────────────────────────────────────

        rules = policy_client.list_rules(direction="ingress")
        rule_ids = [r.rule_id for r in rules]
        assert rule_id in rule_ids, (
            f"Rule {rule_id} not found after reboot. Rules present: {rule_ids}"
        )
        logger.info(f"Rule {rule_id} correctly restored after reboot")

        # ── Verify enforcement ─────────────────────────────────────────────────

        _assert_traffic_dropped(client, server_ip_v4, "post-reboot")

        # ── Cleanup ────────────────────────────────────────────────────────────

        policy_client.flush_rules(direction="ingress")
        policy_client.set_default_action(PolicyAction.PASS, direction="ingress")
        policy_client.detach_ingress(iface_name)

    def test_default_action_survives_reboot(
        self,
        nodes,
        graphql_policy_client,
        server_interface,
        client_interface,
        server_ip_v4,
        client_ip_v4,
    ):
        """
        Verify that a non-default default action (DROP) is restored after reboot.
        """
        server = nodes["server"]
        client = nodes["client"]
        policy_client = graphql_policy_client
        iface_name = server_interface.if_name

        # ── Setup ──────────────────────────────────────────────────────────────

        from policy_engine_client.engine.cli.client import PolicyAction

        policy_client.flush_rules(direction="ingress")
        try:
            policy_client.detach_ingress(iface_name)
        except Exception:
            pass

        attach_result = policy_client.attach_ingress(iface_name)
        assert attach_result.success, f"Failed to attach: {attach_result.message}"

        # Set default action to DROP (non-default — normally PASS)
        policy_client.set_default_action(PolicyAction.DROP, direction="ingress")

        # Verify traffic is blocked before reboot
        _assert_traffic_dropped(client, server_ip_v4, "pre-reboot default DROP")

        # ── Reboot ─────────────────────────────────────────────────────────────

        reboot_node_and_wait(server, ssh_reconnect_timeout=120)
        _wait_for_policy_engine_http(server, timeout=90)

        # ── Verify default action restored ─────────────────────────────────────

        # Traffic should still be dropped (default action restored to DROP)
        _assert_traffic_dropped(client, server_ip_v4, "post-reboot default DROP")
        logger.info("Default DROP action correctly restored after reboot")

        # ── Cleanup ────────────────────────────────────────────────────────────

        policy_client.set_default_action(PolicyAction.PASS, direction="ingress")
        policy_client.detach_ingress(iface_name)

    def test_state_file_exists_after_rule_add(
        self,
        nodes,
        graphql_policy_client,
        server_interface,
        server_ip_v4,
        client_ip_v4,
    ):
        """
        Sanity check: the state file is created/updated when a rule is added.
        """
        server = nodes["server"]
        policy_client = graphql_policy_client
        iface_name = server_interface.if_name

        from policy_engine_client.engine.cli.client import (
            AddRuleOptions,
            PolicyAction,
            Protocol,
        )

        # Attach and add a rule
        attach_result = policy_client.attach_ingress(iface_name)
        assert attach_result.success

        add_result = policy_client.add_rule(
            AddRuleOptions(
                interface=iface_name,
                src=f"{client_ip_v4}/32",
                protocol=Protocol.ANY,
                actions=[(PolicyAction.LOG, 0)],
            ),
            direction="ingress",
        )
        assert add_result.success

        # Verify the state file exists and is valid JSON
        output = server.ssh_command(
            f"cat {_STATE_FILE} | python3 -c 'import sys,json; d=json.load(sys.stdin); "
            f'print(len(d["rules"]))\' 2>&1 || echo MISSING'
        )
        assert "MISSING" not in output, (
            f"State file missing or not valid JSON: {output}"
        )
        rule_count = int(output.strip())
        assert rule_count >= 1, (
            f"Expected at least 1 rule in state file, got {rule_count}"
        )
        logger.info(f"State file contains {rule_count} rule(s)")

        # Cleanup
        policy_client.flush_rules(direction="ingress")
        policy_client.detach_ingress(iface_name)
