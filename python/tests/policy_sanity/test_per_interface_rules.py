# Copyright (c) Peter Morrow

"""
Per-interface rule scoping tests.

Rules are now scoped to a specific (interface, direction) via ifindex embedded in the
BPF LPM src key. These tests verify:
  - list_rules() returns the correct interface field per rule
  - Traffic matching enforces rules on the correct interface
  - Default actions are per-interface (set + query + traffic)
  - Per-interface stats increment correctly
  - Deleting a rule requires the correct interface
"""

import logging
import time

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions, PolicyAction
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.nping_utils import send_ping, send_tcp_syn, send_udp_packets

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_default_action_via_gql(policy_client, interface: str, direction: str) -> str:
    """
    Query the default action for an interface+direction.
    Skips (marks the caller as skipped) when the client is CLI-only.
    Returns "PASS" or "DROP".
    """
    if not isinstance(policy_client, GraphQLPolicyClient):
        pytest.skip("defaultAction query is GraphQL-only")
    return policy_client.get_default_action(interface, direction)


# ---------------------------------------------------------------------------
# CRUD: interface field in rule listings
# ---------------------------------------------------------------------------


class TestPerInterfaceRuleListing:
    """Verify that listed rules carry the interface field from the BPF LPM key."""

    def test_ingress_rule_interface_field_populated(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """list_rules should return the interface name for each ingress rule."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add rule: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        assert len(rules) == 1, "Should have exactly 1 ingress rule"
        assert rules[0].interface == attached_ingress, (
            f"Expected interface={attached_ingress!r}, got {rules[0].interface!r}"
        )

    def test_egress_rule_interface_field_populated(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """list_rules should return the interface name for each egress rule."""
        options = AddRuleOptions(
            interface=attached_egress,
            src="10.0.0.0/8",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress rule: {result.message}"

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1, "Should have exactly 1 egress rule"
        assert rules[0].interface == attached_egress, (
            f"Expected interface={attached_egress!r}, got {rules[0].interface!r}"
        )

    def test_multiple_ingress_rules_all_have_interface(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """All rules in list_rules should carry the correct interface field."""
        for i in range(3):
            result = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=f"10.{i}.0.0/16",
                    protocol="any",
                    actions=[("drop", 0)],
                ),
                direction="ingress",
            )
            assert result.success, f"Add rule {i} failed: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        assert len(rules) == 3

        for rule in rules:
            assert rule.interface == attached_ingress, (
                f"Rule interface mismatch: expected {attached_ingress!r}, got {rule.interface!r}"
            )

    def test_ipv6_ingress_rule_interface_field(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """IPv6 rules should also carry the interface field."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="2001:db8::/32",
            dst="::/0",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add IPv6 rule: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        assert len(rules) == 1
        assert rules[0].interface == attached_ingress, (
            f"IPv6 rule interface mismatch: expected {attached_ingress!r}, got {rules[0].interface!r}"
        )

    def test_delete_rule_scoped_to_interface(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """delete_rule with the correct interface removes the rule."""
        rule_id = 41001
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="10.0.0.0/8",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=rule_id,
            ),
            direction="ingress",
        )
        assert result.success, f"Add failed: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        assert any(r.rule_id == rule_id for r in rules), "Rule should be present"

        result = policy_client.delete_rule(
            attached_ingress, rule_id=rule_id, direction="ingress"
        )
        assert result.success, f"Delete failed: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        assert not any(r.rule_id == rule_id for r in rules), "Rule should be gone"

    def test_egress_rule_crud_with_interface(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Full add/list/delete cycle for an egress rule, verifying interface field."""
        rule_id = 41002
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src="10.0.0.0/8",
                protocol="tcp",
                dport=8080,
                actions=[("drop", 0)],
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert result.success, f"Add failed: {result.message}"

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1
        assert rules[0].rule_id == rule_id
        assert rules[0].interface == attached_egress

        result = policy_client.delete_rule(
            attached_egress, rule_id=rule_id, direction="egress"
        )
        assert result.success, f"Delete failed: {result.message}"

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 0


# ---------------------------------------------------------------------------
# Default action: per-interface query and traffic verification
# ---------------------------------------------------------------------------


class TestPerInterfaceDefaultAction:
    """
    Default action is now per-interface — each (interface, direction) pair has
    its own default that applies only to unmatched traffic on that interface.
    """

    def test_ingress_default_action_query_starts_as_pass(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """GraphQL defaultAction query should return PASS when no explicit default is set."""
        action = _get_default_action_via_gql(policy_client, attached_ingress, "ingress")
        assert action.upper() == "PASS", f"Expected default PASS, got {action!r}"

    def test_ingress_set_default_action_reflected_in_query(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """Setting default DROP should be reflected by the defaultAction query."""
        result = policy_client.set_default_action(
            PolicyAction.DROP, direction="ingress", interface=attached_ingress
        )
        assert result.success, f"set_default_action failed: {result.message}"

        try:
            action = _get_default_action_via_gql(
                policy_client, attached_ingress, "ingress"
            )
            assert action.upper() == "DROP", f"Expected DROP after set, got {action!r}"
        finally:
            policy_client.set_default_action(
                PolicyAction.PASS, direction="ingress", interface=attached_ingress
            )

    def test_egress_set_default_action_reflected_in_query(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Setting egress default DROP is reflected by the defaultAction query."""
        result = policy_client.set_default_action(
            PolicyAction.DROP, direction="egress", interface=attached_egress
        )
        assert result.success, f"set_default_action failed: {result.message}"

        try:
            action = _get_default_action_via_gql(
                policy_client, attached_egress, "egress"
            )
            assert action.upper() == "DROP", (
                f"Expected egress default DROP, got {action!r}"
            )
        finally:
            policy_client.set_default_action(
                PolicyAction.PASS, direction="egress", interface=attached_egress
            )

    def test_ingress_default_drop_blocks_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """With default DROP and no rules, all ingress traffic should be blocked."""
        client = nodes["client"]

        result = policy_client.set_default_action(
            PolicyAction.DROP, direction="ingress", interface=attached_ingress
        )
        assert result.success, f"set_default_action failed: {result.message}"

        try:
            initial_stats = policy_client.get_stats(
                attached_ingress, direction="ingress"
            )
            initial_drops = initial_stats.global_stats.policy_drops

            packets_to_send = 5
            result = send_ping(
                client,
                server_ip_v4,
                count=packets_to_send,
                interface=client_interface.if_name,
            )
            assert result.packets_lost > 0, "Packets should be dropped by default DROP"

            final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
            drops_delta = final_stats.global_stats.policy_drops - initial_drops
            logger.info(
                f"Default DROP ingress: sent={packets_to_send}, drops={drops_delta}"
            )
            assert drops_delta >= packets_to_send, (
                f"Expected at least {packets_to_send} drops, got {drops_delta}"
            )
        finally:
            policy_client.set_default_action(
                PolicyAction.PASS, direction="ingress", interface=attached_ingress
            )

    def test_ingress_default_pass_allows_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """With explicit default PASS (reset), traffic should flow freely."""
        client = nodes["client"]

        # Ensure default is PASS
        result = policy_client.set_default_action(
            PolicyAction.PASS, direction="ingress", interface=attached_ingress
        )
        assert result.success, f"set_default_action failed: {result.message}"

        result = send_ping(
            client,
            server_ip_v4,
            count=5,
            interface=client_interface.if_name,
        )
        assert result.packets_received > 0, "Traffic should pass with default PASS"

    def test_egress_default_drop_blocks_traffic(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        client_ip_v4,
        nmap_installed_server,
    ):
        """With egress default DROP, outbound traffic from server is blocked."""
        server = nodes["server"]

        result = policy_client.set_default_action(
            PolicyAction.DROP, direction="egress", interface=attached_egress
        )
        assert result.success, f"set_default_action failed: {result.message}"

        try:
            initial_stats = policy_client.get_stats(attached_egress, direction="egress")
            initial_drops = initial_stats.global_stats.policy_drops

            packets_to_send = 5
            result = send_ping(
                server,
                client_ip_v4,
                count=packets_to_send,
                interface=server_interface.if_name,
            )
            assert result.packets_lost > 0, (
                "Egress traffic should be dropped by default DROP"
            )

            final_stats = policy_client.get_stats(attached_egress, direction="egress")
            drops_delta = final_stats.global_stats.policy_drops - initial_drops
            logger.info(
                f"Egress default DROP: sent={packets_to_send}, drops={drops_delta}"
            )
            assert drops_delta >= packets_to_send, (
                f"Expected at least {packets_to_send} drops, got {drops_delta}"
            )
        finally:
            policy_client.set_default_action(
                PolicyAction.PASS, direction="egress", interface=attached_egress
            )


# ---------------------------------------------------------------------------
# Traffic: ingress rules enforce on the correct interface
# ---------------------------------------------------------------------------


class TestPerInterfaceIngressTraffic:
    """Verify ingress traffic matching and per-interface stats."""

    def test_icmp_drop_rule_on_interface_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Drop rule scoped to the attached interface blocks matching traffic."""
        client = nodes["client"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
            ),
            direction="ingress",
        )
        assert result.success, f"Add rule failed: {result.message}"

        # Verify rule lists the interface
        rules = policy_client.list_rules(direction="ingress")
        assert len(rules) == 1
        assert rules[0].interface == attached_ingress

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )
        assert result.packets_lost > 0, "ICMP should be dropped by interface rule"

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface ingress ICMP drop: sent={packets_to_send}, drops={drops_delta}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected {packets_to_send} drops, got {drops_delta}"
        )

    def test_tcp_drop_rule_on_interface_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """TCP port drop rule scoped to the interface drops matching packets."""
        client = nodes["client"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                protocol="tcp",
                dport=9999,
                actions=[("drop", 0)],
            ),
            direction="ingress",
        )
        assert result.success, f"Add rule failed: {result.message}"

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            client,
            server_ip_v4,
            dest_port=9999,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface TCP drop port 9999: sent={packets_to_send}, drops={drops_delta}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected {packets_to_send} drops, got {drops_delta}"
        )

    def test_udp_drop_rule_on_interface_v4(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """UDP drop rule scoped to the interface drops matching packets."""
        client = nodes["client"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                protocol="udp",
                dport=7777,
                actions=[("drop", 0)],
            ),
            direction="ingress",
        )
        assert result.success, f"Add rule failed: {result.message}"

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_udp_packets(
            client,
            server_ip_v4,
            dest_port=7777,
            count=packets_to_send,
            interface=client_interface.if_name,
        )

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface UDP drop port 7777: sent={packets_to_send}, drops={drops_delta}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected {packets_to_send} drops, got {drops_delta}"
        )

    def test_ingress_rule_stats_per_interface(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4,
        nmap_installed,
    ):
        """Rule stats should count packets matching the per-interface rule."""
        client = nodes["client"]
        rule_id = 41100

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                protocol="icmp",
                actions=[("log", 0), ("pass", 1)],
                rule_id=rule_id,
            ),
            direction="ingress",
        )
        assert result.success, f"Add rule failed: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")

        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v4,
            count=packets_to_send,
            interface=client_interface.if_name,
        )
        assert result.success, (
            f"Ping should pass with log+pass rule: {result.error_message}"
        )

        time.sleep(0.5)

        rule_stats = policy_client.get_rule_stats(rule_id=rule_id, direction="ingress")
        assert len(rule_stats.rules) > 0, "Should have rule stats"
        stats = rule_stats.rules[0].stats
        assert stats is not None, "Stats should not be None"

        logger.info(
            f"Per-interface rule stats: packets={stats.packets}, expected={packets_to_send}"
        )
        assert stats.packets == packets_to_send, (
            f"Expected {packets_to_send} packets in rule stats, got {stats.packets}"
        )

    def test_icmp_drop_rule_v6(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v6,
        server_ip_v6,
        nmap_installed,
    ):
        """IPv6 drop rule on interface blocks ICMPv6 traffic."""
        client = nodes["client"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v6,
                dst="::/0",
                protocol="icmpv6",
                actions=[("drop", 0)],
            ),
            direction="ingress",
        )
        assert result.success, f"Add IPv6 rule failed: {result.message}"

        # Verify interface field
        rules = policy_client.list_rules(direction="ingress")
        assert len(rules) == 1
        assert rules[0].interface == attached_ingress

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        result = send_ping(
            client,
            server_ip_v6,
            count=packets_to_send,
            interface=client_interface.if_name,
        )
        assert result.packets_lost > 0, "ICMPv6 should be dropped"

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface ICMPv6 drop: drops={drops_delta}, expected>={packets_to_send}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} drops, got {drops_delta}"
        )


# ---------------------------------------------------------------------------
# Traffic: egress rules enforce on the correct interface
# ---------------------------------------------------------------------------


class TestPerInterfaceEgressTraffic:
    """Verify egress traffic matching and per-interface stats."""

    def test_egress_icmp_drop_rule_on_interface_v4(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """Egress drop rule scoped to the interface drops outbound ICMP."""
        server = nodes["server"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
            ),
            direction="egress",
        )
        assert result.success, f"Add egress rule failed: {result.message}"

        # Verify interface field
        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1
        assert rules[0].interface == attached_egress, (
            f"Egress rule interface mismatch: {rules[0].interface!r}"
        )

        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        result = send_ping(
            server,
            client_ip_v4,
            count=packets_to_send,
            interface=server_interface.if_name,
        )
        assert result.packets_lost > 0, (
            "Egress ICMP should be dropped by interface rule"
        )

        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface egress ICMP drop: sent={packets_to_send}, drops={drops_delta}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected {packets_to_send} egress drops, got {drops_delta}"
        )

    def test_egress_tcp_drop_rule_on_interface_v4(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """Egress TCP drop rule on interface drops outbound TCP packets."""
        server = nodes["server"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=8888,
                actions=[("drop", 0)],
            ),
            direction="egress",
        )
        assert result.success, f"Add egress TCP rule failed: {result.message}"

        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=8888,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface egress TCP 8888 drop: sent={packets_to_send}, drops={drops_delta}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected {packets_to_send} egress drops for TCP 8888, got {drops_delta}"
        )

    def test_egress_udp_drop_rule_on_interface_v4(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """Egress UDP drop rule on interface drops outbound UDP packets."""
        server = nodes["server"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=6666,
                actions=[("drop", 0)],
            ),
            direction="egress",
        )
        assert result.success, f"Add egress UDP rule failed: {result.message}"

        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_udp_packets(
            server,
            client_ip_v4,
            dest_port=6666,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface egress UDP 6666 drop: sent={packets_to_send}, drops={drops_delta}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected {packets_to_send} egress drops for UDP 6666, got {drops_delta}"
        )

    def test_egress_rule_stats_per_interface(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v4,
        client_ip_v4,
        nmap_installed_server,
    ):
        """Egress rule stats should count packets matched on the interface."""
        server = nodes["server"]
        rule_id = 41200

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="icmp",
                actions=[("log", 0), ("pass", 1)],
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert result.success, f"Add egress rule failed: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        packets_to_send = 5
        result = send_ping(
            server,
            client_ip_v4,
            count=packets_to_send,
            interface=server_interface.if_name,
        )
        assert result.success, f"Ping should pass with log+pass: {result.error_message}"

        time.sleep(0.5)

        rule_stats = policy_client.get_rule_stats(rule_id=rule_id, direction="egress")
        assert len(rule_stats.rules) > 0, "Should have egress rule stats"
        stats = rule_stats.rules[0].stats
        assert stats is not None

        logger.info(
            f"Per-interface egress rule stats: packets={stats.packets}, expected={packets_to_send}"
        )
        assert stats.packets == packets_to_send, (
            f"Expected {packets_to_send} packets, got {stats.packets}"
        )

    def test_egress_icmp_drop_rule_v6(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        server_network_v6,
        server_ip_v6,
        client_ip_v6,
        nmap_installed_server,
    ):
        """Egress IPv6 drop rule on interface blocks outbound ICMPv6."""
        server = nodes["server"]

        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v6,
                dst="::/0",
                protocol="icmpv6",
                actions=[("drop", 0)],
            ),
            direction="egress",
        )
        assert result.success, f"Add egress IPv6 rule failed: {result.message}"

        # Verify interface field
        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1
        assert rules[0].interface == attached_egress

        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        result = send_ping(
            server,
            client_ip_v6,
            count=packets_to_send,
            interface=server_interface.if_name,
        )
        assert result.packets_lost > 0, "Egress ICMPv6 should be dropped"

        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(
            f"Per-interface egress ICMPv6 drop: drops={drops_delta}, expected>={packets_to_send}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} egress drops, got {drops_delta}"
        )


# ---------------------------------------------------------------------------
# Combined: both ingress and egress rules on the same interface
# ---------------------------------------------------------------------------


class TestPerInterfaceBothDirections:
    """Ingress and egress rules on the same interface are independent."""

    def test_ingress_and_egress_rules_independent(
        self,
        policy_client,
        server_interface,
        configure_node_interfaces,
    ):
        """Rules on the same interface in different directions don't interfere."""
        iface = server_interface.if_name

        policy_client.attach_ingress(iface)
        policy_client.attach_egress(iface)

        try:
            ingress_id = 41300
            egress_id = 41301

            r = policy_client.add_rule(
                AddRuleOptions(
                    interface=iface,
                    src="10.0.0.0/8",
                    protocol="tcp",
                    dport=80,
                    actions=[("drop", 0)],
                    rule_id=ingress_id,
                ),
                direction="ingress",
            )
            assert r.success, f"Add ingress rule failed: {r.message}"

            r = policy_client.add_rule(
                AddRuleOptions(
                    interface=iface,
                    src="192.168.0.0/16",
                    protocol="udp",
                    dport=53,
                    actions=[("drop", 0)],
                    rule_id=egress_id,
                ),
                direction="egress",
            )
            assert r.success, f"Add egress rule failed: {r.message}"

            ingress_rules = policy_client.list_rules(direction="ingress")
            egress_rules = policy_client.list_rules(direction="egress")

            ingress_ids = {r.rule_id for r in ingress_rules}
            egress_ids = {r.rule_id for r in egress_rules}

            assert ingress_id in ingress_ids, "Ingress rule missing from ingress list"
            assert egress_id in egress_ids, "Egress rule missing from egress list"
            assert ingress_id not in egress_ids, "Ingress rule leaked into egress list"
            assert egress_id not in ingress_ids, "Egress rule leaked into ingress list"

            # Both rules should have the correct interface
            for r in ingress_rules:
                if r.rule_id == ingress_id:
                    assert r.interface == iface, (
                        f"Ingress rule interface mismatch: {r.interface!r}"
                    )
            for r in egress_rules:
                if r.rule_id == egress_id:
                    assert r.interface == iface, (
                        f"Egress rule interface mismatch: {r.interface!r}"
                    )

        finally:
            policy_client.flush_rules(direction="ingress")
            policy_client.flush_rules(direction="egress")
            policy_client.detach_all()
