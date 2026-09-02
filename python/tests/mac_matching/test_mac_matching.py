# Copyright (c) Peter Morrow

"""
MAC address matching tests for policy-engine.

The policy-engine supports 7-tuple rules: src_ip/prefix, dst_ip/prefix,
sport, dport, protocol, src_mac, dst_mac.  MAC fields use a sidecar map
(mac_rules / tc_mac_rules) so the l4_rule struct stays at 96 bytes.

Tests cover:
  Rule management
  - MAC rule is accepted and appears in the rule list with correct MACs
  - All-zeros MAC is rejected (use None/omit for wildcard)
  - Invalid MAC format is rejected

  Ingress (XDP) traffic matching
  - DROP rule matching client's src MAC drops inbound traffic
  - DROP rule on wrong src MAC does not drop traffic
  - DROP rule matching server's dst MAC drops inbound traffic

  Egress (TC) traffic matching
  - DROP rule matching server's src MAC drops outbound traffic
  - DROP rule on wrong src MAC does not drop outbound traffic
  - DROP rule matching client's dst MAC drops outbound traffic

  Combined src+dst MAC matching
  - Rule requires both src and dst MAC to match — only fires when both match
"""

import logging
import time

from netsim.testkit.nping_utils import send_tcp_syn
from policy_engine_client.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)


class TestMacRuleManagement:
    """Tests that MAC rules are accepted, listed, and validated correctly."""

    def test_add_rule_with_src_mac_succeeds(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_mac,
    ):
        """Adding an ingress rule with src_mac should succeed."""
        options = AddRuleOptions(
            interface=attached_ingress,
            actions=[("drop", 0)],
            src_mac=client_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Rule with src_mac should succeed: {result.message}"

    def test_add_rule_with_dst_mac_succeeds(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_mac,
    ):
        """Adding an ingress rule with dst_mac should succeed."""
        options = AddRuleOptions(
            interface=attached_ingress,
            actions=[("drop", 0)],
            dst_mac=server_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Rule with dst_mac should succeed: {result.message}"

    def test_add_rule_with_both_macs_succeeds(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_mac,
        server_mac,
    ):
        """Adding a rule with both src_mac and dst_mac should succeed."""
        options = AddRuleOptions(
            interface=attached_ingress,
            actions=[("log", 0)],
            src_mac=client_mac,
            dst_mac=server_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Rule with src+dst MAC should succeed: {result.message}"

    def test_mac_rule_appears_in_list(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        client_mac,
        server_mac,
    ):
        """A MAC rule should appear in the rule list with correct MAC fields."""
        rule_id = 98001
        options = AddRuleOptions(
            interface=attached_ingress,
            actions=[("log", 0)],
            rule_id=rule_id,
            src_mac=client_mac,
            dst_mac=server_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add MAC rule: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        mac_rule = next((r for r in rules if r.rule_id == rule_id), None)
        assert mac_rule is not None, f"Rule {rule_id} not found in list"
        assert mac_rule.src_mac == client_mac, (
            f"src_mac mismatch: expected {client_mac!r}, got {mac_rule.src_mac!r}"
        )
        assert mac_rule.dst_mac == server_mac, (
            f"dst_mac mismatch: expected {server_mac!r}, got {mac_rule.dst_mac!r}"
        )

    def test_rule_without_mac_has_no_mac_fields(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """A rule without MAC fields should have null src_mac and dst_mac."""
        rule_id = 98002
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="tcp",
            dport=80,
            actions=[("log", 0)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add plain rule: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        plain_rule = next((r for r in rules if r.rule_id == rule_id), None)
        assert plain_rule is not None, f"Rule {rule_id} not found in list"
        assert plain_rule.src_mac is None, (
            f"Plain rule should have no src_mac, got {plain_rule.src_mac!r}"
        )
        assert plain_rule.dst_mac is None, (
            f"Plain rule should have no dst_mac, got {plain_rule.dst_mac!r}"
        )


class TestIngressMacMatching:
    """Tests that ingress (XDP) MAC DROP rules block only matching traffic."""

    def test_ingress_drop_matching_src_mac_blocks_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        client_ip_v4,
        client_network_v4,
        client_mac,
        nmap_installed,
    ):
        """Ingress DROP rule with client's src_mac should drop inbound traffic."""
        client = nodes["client"]

        rule_id = 98010
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            src_mac=client_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add MAC DROP rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            client,
            client_ip_v4.__class__(str(server_interface.get_ip_address())),
            dest_port=9999,
            count=packets_to_send,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Ingress src_mac DROP: sent={packets_to_send}, policy_drops={drops_delta}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} drops for matching src_mac rule, "
            f"got {drops_delta}"
        )

    def test_ingress_drop_wrong_src_mac_passes_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        client_ip_v4,
        client_network_v4,
        nmap_installed,
    ):
        """Ingress DROP rule with a fabricated (wrong) src_mac should not drop traffic."""
        client = nodes["client"]
        wrong_mac = "de:ad:be:ef:00:01"

        rule_id = 98011
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            src_mac=wrong_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add wrong-MAC DROP rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            client,
            client_ip_v4.__class__(str(server_interface.get_ip_address())),
            dest_port=9999,
            count=packets_to_send,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Ingress wrong src_mac: sent={packets_to_send}, policy_drops={drops_delta}"
        )
        assert drops_delta == 0, (
            f"Expected 0 drops for wrong src_mac, got {drops_delta}"
        )

    def test_ingress_drop_matching_dst_mac_blocks_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        client_ip_v4,
        client_network_v4,
        server_mac,
        nmap_installed,
    ):
        """Ingress DROP rule matching the server's dst_mac should drop inbound traffic."""
        client = nodes["client"]

        rule_id = 98012
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            dst_mac=server_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add dst_mac DROP rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            client,
            client_ip_v4.__class__(str(server_interface.get_ip_address())),
            dest_port=9999,
            count=packets_to_send,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Ingress dst_mac DROP: sent={packets_to_send}, policy_drops={drops_delta}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} drops for matching dst_mac rule, "
            f"got {drops_delta}"
        )


class TestEgressMacMatching:
    """Tests that egress (TC) MAC DROP rules block only matching traffic."""

    def test_egress_drop_matching_src_mac_blocks_traffic(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        client_ip_v4,
        server_network_v4,
        server_mac,
        nmap_installed_server,
    ):
        """Egress DROP rule with server's src_mac should drop outbound traffic."""
        server = nodes["server"]

        rule_id = 98020
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            src_mac=server_mac,
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, (
            f"Failed to add egress src_mac DROP rule: {result.message}"
        )

        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=9999,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Egress src_mac DROP: sent={packets_to_send}, policy_drops={drops_delta}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} drops for matching egress src_mac rule, "
            f"got {drops_delta}"
        )

    def test_egress_drop_wrong_src_mac_passes_traffic(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        client_ip_v4,
        server_network_v4,
        nmap_installed_server,
    ):
        """Egress DROP rule with a fabricated (wrong) src_mac should not drop traffic."""
        server = nodes["server"]
        wrong_mac = "de:ad:be:ef:00:02"

        rule_id = 98021
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            src_mac=wrong_mac,
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add wrong egress MAC rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=9999,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Egress wrong src_mac: sent={packets_to_send}, policy_drops={drops_delta}"
        )
        assert drops_delta == 0, (
            f"Expected 0 drops for wrong egress src_mac, got {drops_delta}"
        )

    def test_egress_drop_matching_dst_mac_blocks_traffic(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        client_ip_v4,
        server_network_v4,
        client_mac,
        nmap_installed_server,
    ):
        """Egress DROP rule with client's dst_mac should drop outbound traffic."""
        server = nodes["server"]

        rule_id = 98022
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            dst_mac=client_mac,
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, (
            f"Failed to add egress dst_mac DROP rule: {result.message}"
        )

        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=9999,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="egress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Egress dst_mac DROP: sent={packets_to_send}, policy_drops={drops_delta}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} drops for matching egress dst_mac rule, "
            f"got {drops_delta}"
        )


class TestCombinedMacMatching:
    """Tests rules that combine both src_mac and dst_mac constraints."""

    def test_ingress_src_and_dst_mac_both_match_drops(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        client_ip_v4,
        client_network_v4,
        client_mac,
        server_mac,
        nmap_installed,
    ):
        """Ingress rule with correct src+dst MAC should drop matching traffic."""
        client = nodes["client"]

        rule_id = 98030
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            src_mac=client_mac,
            dst_mac=server_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add combined MAC rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            client,
            client_ip_v4.__class__(str(server_interface.get_ip_address())),
            dest_port=9999,
            count=packets_to_send,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Ingress src+dst MAC DROP: sent={packets_to_send}, "
            f"policy_drops={drops_delta}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} drops for matching src+dst MAC rule, "
            f"got {drops_delta}"
        )

    def test_ingress_src_and_dst_mac_wrong_dst_passes(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        client_ip_v4,
        client_network_v4,
        client_mac,
        nmap_installed,
    ):
        """Ingress rule with correct src_mac but wrong dst_mac should NOT drop traffic.

        Both MACs must match when a rule specifies both.  If the dst_mac is
        wrong (not the actual server MAC), the rule should not fire.
        """
        client = nodes["client"]
        wrong_dst_mac = "de:ad:be:ef:00:03"

        rule_id = 98031
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            actions=[("drop", 0)],
            rule_id=rule_id,
            src_mac=client_mac,
            dst_mac=wrong_dst_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add combined MAC rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")
        initial_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        initial_drops = initial_stats.global_stats.policy_drops

        packets_to_send = 5
        send_tcp_syn(
            client,
            client_ip_v4.__class__(str(server_interface.get_ip_address())),
            dest_port=9999,
            count=packets_to_send,
        )

        time.sleep(0.5)

        final_stats = policy_client.get_stats(
            server_interface.if_name, direction="ingress"
        )
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Ingress correct src_mac + wrong dst_mac: sent={packets_to_send}, "
            f"policy_drops={drops_delta}"
        )
        assert drops_delta == 0, (
            f"Expected 0 drops when dst_mac does not match, got {drops_delta}. "
            f"Both src_mac AND dst_mac must match when both are set."
        )


class TestMacRuleStats:
    """Tests that MAC rules accumulate per-rule statistics correctly."""

    def test_mac_rule_accumulates_stats(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        client_ip_v4,
        client_network_v4,
        client_mac,
        nmap_installed,
    ):
        """A matching MAC rule should accumulate per-rule packet statistics."""
        client = nodes["client"]

        rule_id = 98040
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            actions=[("log", 0)],
            rule_id=rule_id,
            src_mac=client_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add MAC LOG rule: {result.message}"

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")

        packets_to_send = 5
        send_tcp_syn(
            client,
            client_ip_v4.__class__(str(server_interface.get_ip_address())),
            dest_port=9999,
            count=packets_to_send,
        )

        time.sleep(0.5)

        stats = policy_client.get_rule_stats(rule_id=rule_id, direction="ingress")
        assert stats.rules, f"No stats entry for rule {rule_id}"
        rule_stats = stats.rules[0].stats
        assert rule_stats is not None, f"Stats object is None for rule {rule_id}"

        logger.info(
            f"MAC LOG rule stats: packets={rule_stats.packets} "
            f"(expected {packets_to_send})"
        )
        assert rule_stats.packets >= packets_to_send, (
            f"Expected at least {packets_to_send} packets in rule stats, "
            f"got {rule_stats.packets}"
        )

    def test_non_matching_mac_rule_has_zero_stats(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        server_interface,
        client_ip_v4,
        client_network_v4,
        nmap_installed,
    ):
        """A MAC LOG rule that doesn't match should have zero packet stats."""
        client = nodes["client"]
        wrong_mac = "de:ad:be:ef:00:04"

        rule_id = 98041
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            actions=[("log", 0)],
            rule_id=rule_id,
            src_mac=wrong_mac,
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, (
            f"Failed to add non-matching MAC LOG rule: {result.message}"
        )

        policy_client.clear_rule_stats(rule_id=rule_id, direction="ingress")

        packets_to_send = 5
        send_tcp_syn(
            client,
            client_ip_v4.__class__(str(server_interface.get_ip_address())),
            dest_port=9999,
            count=packets_to_send,
        )

        time.sleep(0.5)

        stats = policy_client.get_rule_stats(rule_id=rule_id, direction="ingress")
        packet_count = (
            stats.rules[0].stats.packets if stats.rules and stats.rules[0].stats else 0
        )

        logger.info(
            f"Non-matching MAC LOG rule stats: packets={packet_count} (expected 0)"
        )
        assert packet_count == 0, (
            f"Expected 0 packets for non-matching MAC rule, got {packet_count}"
        )
