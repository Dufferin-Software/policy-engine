# Copyright (c) Peter Morrow

"""
Egress traffic tests for policy-engine TC program.

Tests that egress policies actually block outbound traffic from the server.
Egress rules are installed on the server, matching traffic TO the client.
Traffic is sent FROM the server node, and we verify it's dropped by the TC program.

Key difference from ingress tests:
- Ingress: rules match client→server traffic, traffic sent from client
- Egress: rules match server→client traffic, traffic sent from server
- Egress stats use tx_packets/tx_bytes and policy_drops
"""

import logging
import time


from netsim.testkit.nping_utils import send_ping, send_tcp_syn, send_udp_packets
from policy_engine_client.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)


class TestEgressTrafficMatching:
    """Tests that egress policies actually drop/pass outbound traffic."""

    def test_egress_icmp_pass_v4(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        client_ip_v4,
        nmap_installed_server,
    ):
        """Test that ICMP traffic passes by default on egress (IPv4)."""
        server = nodes["server"]

        # Send ICMP ping from server to client
        result = send_ping(
            server,
            client_ip_v4,
            count=5,
            interface=server_interface.if_name,
        )

        assert result.success, f"ICMP ping failed: {result.error_message}"
        assert result.packets_received > 0, "Should receive some packets"
        logger.info(
            f"Egress ICMP ping: sent={result.packets_sent}, received={result.packets_received}"
        )

    def test_egress_icmp_drop_v4(
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
        """Test that ICMP traffic is dropped when matching an egress drop rule (IPv4)."""
        server = nodes["server"]

        # Add egress drop rule for ICMP from server's network
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="icmp",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress drop rule: {result.message}"

        # Get egress stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send ICMP from server to client - should be dropped by egress TC
        packets_to_send = 5
        result = send_ping(
            server,
            client_ip_v4,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        # With a drop rule, we expect packet loss
        assert result.packets_lost > 0, "Packets should be dropped by egress policy"
        logger.info(f"Egress ICMP with drop rule: lost={result.packets_lost}")

        # Verify egress stats show the drops
        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        final_drops = final_stats.global_stats.policy_drops
        drops_delta = final_drops - initial_drops

        logger.info(
            f"Egress policy drops: initial={initial_drops}, final={final_drops}, "
            f"delta={drops_delta}, expected={packets_to_send}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} egress policy drops, got {drops_delta}"
        )

    def test_egress_icmp_drop_v6(
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
        """Test that ICMPv6 traffic is dropped when matching an egress drop rule."""
        server = nodes["server"]

        # Add egress drop rule for ICMPv6 from server's network
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v6,
            dst="::/0",
            protocol="icmpv6",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress IPv6 drop rule: {result.message}"

        # Get egress stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send ICMPv6 from server to client - should be dropped
        packets_to_send = 5
        result = send_ping(
            server,
            client_ip_v6,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        # With a drop rule, we expect packet loss
        assert result.packets_lost > 0, "Packets should be dropped by egress policy"
        logger.info(f"Egress ICMPv6 with drop rule: lost={result.packets_lost}")

        # Verify egress stats show the drops
        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        final_drops = final_stats.global_stats.policy_drops
        drops_delta = final_drops - initial_drops

        logger.info(
            f"Egress policy drops: initial={initial_drops}, final={final_drops}, "
            f"delta={drops_delta}, expected>={packets_to_send}"
        )
        assert drops_delta >= packets_to_send, (
            f"Expected at least {packets_to_send} egress policy drops, got {drops_delta}"
        )

    def test_egress_tcp_port_drop_v4(
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
        """Test TCP traffic matching with specific ports on egress (IPv4)."""
        server = nodes["server"]

        # Add egress drop rule for TCP port 8080 from server
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="tcp",
            dport=8080,
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress TCP drop rule: {result.message}"

        # Get egress stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send TCP SYN to port 8080 from server - should be dropped
        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=8080,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        # Verify egress stats show drops for port 8080
        stats_after_8080 = policy_client.get_stats(attached_egress, direction="egress")
        drops_8080 = stats_after_8080.global_stats.policy_drops - initial_drops

        logger.info(
            f"Egress TCP 8080 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_8080}, expected={packets_to_send}"
        )
        assert drops_8080 == packets_to_send, (
            f"Expected exactly {packets_to_send} egress policy drops for TCP 8080, got {drops_8080}"
        )

        # Verify traffic to a different port is NOT dropped
        initial_drops_9090 = stats_after_8080.global_stats.policy_drops

        send_tcp_syn(
            server,
            client_ip_v4,
            dest_port=9090,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        stats_after_9090 = policy_client.get_stats(attached_egress, direction="egress")
        drops_9090 = stats_after_9090.global_stats.policy_drops - initial_drops_9090

        logger.info(f"Egress TCP 9090 (no rule): policy_drops={drops_9090}, expected=0")
        assert drops_9090 == 0, (
            f"Expected 0 egress policy drops for TCP 9090, got {drops_9090}"
        )

    def test_egress_tcp_port_drop_v6(
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
        """Test TCP traffic matching with specific ports on egress (IPv6)."""
        server = nodes["server"]

        # Add egress drop rule for TCP port 8080 from server IPv6 network
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v6,
            dst="::/0",
            protocol="tcp",
            dport=8080,
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress TCP6 drop rule: {result.message}"

        # Get egress stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send TCP SYN to port 8080 from server - should be dropped
        packets_to_send = 5
        send_tcp_syn(
            server,
            client_ip_v6,
            dest_port=8080,
            count=packets_to_send,
            source_ip=str(server_ip_v6),
            interface=server_interface.if_name,
        )

        # Verify egress stats show drops
        stats_after = policy_client.get_stats(attached_egress, direction="egress")
        drops_delta = stats_after.global_stats.policy_drops - initial_drops

        logger.info(
            f"Egress TCP6 8080 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_delta}, expected={packets_to_send}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} egress policy drops for TCP6 8080, got {drops_delta}"
        )

    def test_egress_udp_drop_v4(
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
        """Test UDP traffic matching on egress (IPv4)."""
        server = nodes["server"]

        # Add egress drop rule for UDP port 5353
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="udp",
            dport=5353,
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress UDP drop rule: {result.message}"

        # Get egress stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send UDP to port 5353 from server - should be dropped
        packets_to_send = 5
        send_udp_packets(
            server,
            client_ip_v4,
            dest_port=5353,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        # Verify egress stats show drops
        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Egress UDP 5353 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_delta}, expected={packets_to_send}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} egress policy drops for UDP 5353, got {drops_delta}"
        )

    def test_egress_udp_drop_v6(
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
        """Test UDP traffic matching on egress (IPv6)."""
        server = nodes["server"]

        # Add egress drop rule for UDP port 5353
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v6,
            dst="::/0",
            protocol="udp",
            dport=5353,
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress UDP6 drop rule: {result.message}"

        # Get egress stats BEFORE sending traffic
        initial_stats = policy_client.get_stats(attached_egress, direction="egress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send UDP to port 5353 from server - should be dropped
        packets_to_send = 5
        send_udp_packets(
            server,
            client_ip_v6,
            dest_port=5353,
            count=packets_to_send,
            source_ip=str(server_ip_v6),
            interface=server_interface.if_name,
        )

        # Brief wait for stats to settle
        time.sleep(0.5)

        # Verify egress stats show drops
        final_stats = policy_client.get_stats(attached_egress, direction="egress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"Egress UDP6 5353 (drop rule): sent={packets_to_send}, "
            f"policy_drops={drops_delta}, expected={packets_to_send}"
        )
        assert drops_delta == packets_to_send, (
            f"Expected exactly {packets_to_send} egress policy drops for UDP6 5353, got {drops_delta}"
        )

    def test_egress_default_action_drop_traffic(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        server_interface,
        client_ip_v4,
        nmap_installed_server,
    ):
        """Test that default action DROP blocks all egress traffic."""
        from policy_engine_client.engine.cli.client import PolicyAction

        server = nodes["server"]

        # Set egress default action to DROP
        result = policy_client.set_default_action(
            PolicyAction.DROP, direction="egress", interface=attached_egress
        )
        assert result.success, f"Failed to set egress default action: {result.message}"

        try:
            # Get egress stats BEFORE sending traffic
            initial_stats = policy_client.get_stats(attached_egress, direction="egress")
            initial_drops = initial_stats.global_stats.policy_drops

            # Send ICMP from server to client - should ALL be dropped
            packets_to_send = 5
            result = send_ping(
                server,
                client_ip_v4,
                count=packets_to_send,
                interface=server_interface.if_name,
            )

            # All packets should be dropped
            assert result.packets_lost > 0, (
                "All packets should be dropped with default DROP"
            )
            logger.info(
                f"Egress default DROP: sent={result.packets_sent}, lost={result.packets_lost}"
            )

            # Verify egress stats
            final_stats = policy_client.get_stats(attached_egress, direction="egress")
            drops_delta = final_stats.global_stats.policy_drops - initial_drops

            logger.info(f"Egress default action drops: delta={drops_delta}")
            assert drops_delta >= packets_to_send, (
                f"Expected at least {packets_to_send} drops with default DROP, got {drops_delta}"
            )
        finally:
            # Reset default action to PASS
            policy_client.set_default_action(
                PolicyAction.PASS, direction="egress", interface=attached_egress
            )

    def test_egress_rule_stats_increment(
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
        """Test that egress rule stats increment correctly for matched traffic."""
        server = nodes["server"]

        # Add egress log+pass rule for ICMP
        rule_id = 99999
        options = AddRuleOptions(
            interface=attached_egress,
            src=server_network_v4,
            protocol="icmp",
            actions=[("log", 0), ("pass", 1)],
            rule_id=rule_id,
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress log+pass rule: {result.message}"

        # Clear rule stats first
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        # Send ICMP from server to client - should be logged and passed
        packets_to_send = 5
        result = send_ping(
            server,
            client_ip_v4,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        # Packets should pass (log+pass)
        assert result.success, (
            f"ICMP should pass with log+pass rule: {result.error_message}"
        )

        # Brief wait for stats to settle
        time.sleep(0.5)

        # Verify rule stats show the correct packet count
        rule_stats = policy_client.get_rule_stats(rule_id=rule_id, direction="egress")
        assert len(rule_stats.rules) > 0, "Should have rule stats"

        stats = rule_stats.rules[0].stats
        assert stats is not None, "Rule stats should not be None"

        logger.info(
            f"Egress rule stats: packets={stats.packets}, expected={packets_to_send}"
        )
        assert stats.packets == packets_to_send, (
            f"Expected {packets_to_send} packets in rule stats, got {stats.packets}"
        )
