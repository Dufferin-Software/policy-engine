"""
Tests that detaching a program from an interface clears interface and rule stats.

When a program is detached, all accumulated statistics for that interface
and direction (both global interface stats and per-rule stats) must be reset
to zero so that a subsequent re-attachment starts with a clean slate.

Coverage:
- Ingress detach clears interface stats
- Ingress detach clears rule stats
- Egress detach clears interface stats
- Egress detach clears rule stats
"""

import logging


from policy_engine_client.engine.cli.client import AddRuleOptions
from netsim.testkit.nping_utils import send_ping

logger = logging.getLogger(__name__)


class TestDetachClearsIngressStats:
    """Verify that detaching an ingress program resets interface and rule stats."""

    def test_detach_ingress_clears_interface_stats(
        self,
        nodes,
        policy_client,
        server_interface,
        client_interface,
        client_network_v4,
        server_ip_v4,
        configure_node_interfaces,
        nmap_installed,
    ) -> None:
        """Interface stats (policy_drops) are zeroed after ingress detach + re-attach."""
        iface_name = server_interface.if_name
        client = nodes["client"]

        # Attach ingress
        result = policy_client.attach_ingress(iface_name)
        assert result.success, f"Failed to attach ingress: {result.message}"

        try:
            # Add a drop rule so traffic generates policy_drops
            rule_opts = AddRuleOptions(
                interface=iface_name,
                src=client_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
            )
            result = policy_client.add_rule(rule_opts)
            assert result.success, f"Failed to add rule: {result.message}"

            # Send traffic to accumulate policy_drops
            packets_to_send = 5
            send_ping(
                client,
                server_ip_v4,
                count=packets_to_send,
                interface=client_interface.if_name,
            )

            # Verify stats are non-zero before detach
            stats_before = policy_client.get_stats(iface_name, direction="ingress")
            assert stats_before.global_stats.policy_drops > 0, (
                "policy_drops should be > 0 before detach"
            )
            logger.info(
                f"Ingress policy_drops before detach: {stats_before.global_stats.policy_drops}"
            )
        finally:
            policy_client.flush_rules()
            policy_client.detach_ingress(iface_name)

        # Re-attach and verify stats were cleared by the detach
        result = policy_client.attach_ingress(iface_name)
        assert result.success, f"Failed to re-attach ingress: {result.message}"
        try:
            stats_after = policy_client.get_stats(iface_name, direction="ingress")
            logger.info(
                f"Ingress policy_drops after detach+re-attach: {stats_after.global_stats.policy_drops}"
            )
            assert stats_after.global_stats.policy_drops == 0, (
                "Interface stats should be cleared after ingress detach"
            )
        finally:
            policy_client.detach_ingress(iface_name)

    def test_detach_ingress_clears_rule_stats(
        self,
        nodes,
        policy_client,
        server_interface,
        client_interface,
        client_network_v4,
        server_ip_v4,
        configure_node_interfaces,
        nmap_installed,
    ) -> None:
        """Per-rule packet counts are zeroed after ingress detach + re-attach."""
        iface_name = server_interface.if_name
        client = nodes["client"]
        rule_id = 880001

        # Attach ingress
        result = policy_client.attach_ingress(iface_name)
        assert result.success, f"Failed to attach ingress: {result.message}"

        try:
            # Add a drop rule with a known ID
            rule_opts = AddRuleOptions(
                interface=iface_name,
                src=client_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
                rule_id=rule_id,
            )
            result = policy_client.add_rule(rule_opts)
            assert result.success, f"Failed to add rule: {result.message}"

            # Send traffic so the rule accumulates hits
            packets_to_send = 5
            send_ping(
                client,
                server_ip_v4,
                count=packets_to_send,
                interface=client_interface.if_name,
            )

            # Verify rule stats are non-zero before detach
            rule_stats_before = policy_client.get_rule_stats(rule_id=rule_id)
            packets_before = 0
            for rws in rule_stats_before.rules:
                if rws.rule.rule_id == rule_id and rws.stats:
                    packets_before = rws.stats.packets
                    break
            assert packets_before > 0, "Rule should have counted packets before detach"
            logger.info(
                f"Ingress rule {rule_id} packets before detach: {packets_before}"
            )
        finally:
            policy_client.flush_rules()
            policy_client.detach_ingress(iface_name)

        # Re-attach, re-add the same rule, verify stats start at zero
        result = policy_client.attach_ingress(iface_name)
        assert result.success, f"Failed to re-attach ingress: {result.message}"
        try:
            rule_opts = AddRuleOptions(
                interface=iface_name,
                src=client_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
                rule_id=rule_id,
            )
            result = policy_client.add_rule(rule_opts)
            assert result.success, f"Failed to re-add rule: {result.message}"

            rule_stats_after = policy_client.get_rule_stats(rule_id=rule_id)
            packets_after = 0
            for rws in rule_stats_after.rules:
                if rws.rule.rule_id == rule_id and rws.stats:
                    packets_after = rws.stats.packets
                    break
            logger.info(
                f"Ingress rule {rule_id} packets after detach+re-attach: {packets_after}"
            )
            assert packets_after == 0, (
                "Rule stats should be cleared after ingress detach"
            )
        finally:
            policy_client.flush_rules()
            policy_client.detach_ingress(iface_name)


class TestDetachClearsEgressStats:
    """Verify that detaching an egress program resets interface and rule stats."""

    def test_detach_egress_clears_interface_stats(
        self,
        nodes,
        policy_client,
        server_interface,
        server_network_v4,
        client_ip_v4,
        configure_node_interfaces,
        nmap_installed_server,
    ) -> None:
        """Interface stats (policy_drops) are zeroed after egress detach + re-attach."""
        iface_name = server_interface.if_name
        server = nodes["server"]

        # Attach egress
        result = policy_client.attach_egress(iface_name)
        assert result.success, f"Failed to attach egress: {result.message}"

        try:
            # Add an egress drop rule so outbound traffic generates policy_drops
            rule_opts = AddRuleOptions(
                interface=iface_name,
                src=server_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
            )
            result = policy_client.add_rule(rule_opts, direction="egress")
            assert result.success, f"Failed to add egress rule: {result.message}"

            # Send traffic from server to client to accumulate egress policy_drops
            packets_to_send = 5
            send_ping(
                server,
                client_ip_v4,
                count=packets_to_send,
                interface=iface_name,
            )

            # Verify stats are non-zero before detach
            stats_before = policy_client.get_stats(iface_name, direction="egress")
            assert stats_before.global_stats.policy_drops > 0, (
                "Egress policy_drops should be > 0 before detach"
            )
            logger.info(
                f"Egress policy_drops before detach: {stats_before.global_stats.policy_drops}"
            )
        finally:
            policy_client.flush_rules(direction="egress")
            policy_client.detach_egress(iface_name)

        # Re-attach and verify stats were cleared by the detach
        result = policy_client.attach_egress(iface_name)
        assert result.success, f"Failed to re-attach egress: {result.message}"
        try:
            stats_after = policy_client.get_stats(iface_name, direction="egress")
            logger.info(
                f"Egress policy_drops after detach+re-attach: {stats_after.global_stats.policy_drops}"
            )
            assert stats_after.global_stats.policy_drops == 0, (
                "Interface stats should be cleared after egress detach"
            )
        finally:
            policy_client.detach_egress(iface_name)

    def test_detach_egress_clears_rule_stats(
        self,
        nodes,
        policy_client,
        server_interface,
        server_network_v4,
        client_ip_v4,
        configure_node_interfaces,
        nmap_installed_server,
    ) -> None:
        """Per-rule packet counts are zeroed after egress detach + re-attach."""
        iface_name = server_interface.if_name
        server = nodes["server"]
        rule_id = 880002

        # Attach egress
        result = policy_client.attach_egress(iface_name)
        assert result.success, f"Failed to attach egress: {result.message}"

        try:
            # Add an egress drop rule with a known ID
            rule_opts = AddRuleOptions(
                interface=iface_name,
                src=server_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
                rule_id=rule_id,
            )
            result = policy_client.add_rule(rule_opts, direction="egress")
            assert result.success, f"Failed to add egress rule: {result.message}"

            # Send traffic to accumulate rule hits
            packets_to_send = 5
            send_ping(
                server,
                client_ip_v4,
                count=packets_to_send,
                interface=iface_name,
            )

            # Verify rule stats are non-zero before detach
            rule_stats_before = policy_client.get_rule_stats(
                rule_id=rule_id, direction="egress"
            )
            packets_before = 0
            for rws in rule_stats_before.rules:
                if rws.rule.rule_id == rule_id and rws.stats:
                    packets_before = rws.stats.packets
                    break
            assert packets_before > 0, (
                "Egress rule should have counted packets before detach"
            )
            logger.info(
                f"Egress rule {rule_id} packets before detach: {packets_before}"
            )
        finally:
            policy_client.flush_rules(direction="egress")
            policy_client.detach_egress(iface_name)

        # Re-attach, re-add the same rule, verify stats start at zero
        result = policy_client.attach_egress(iface_name)
        assert result.success, f"Failed to re-attach egress: {result.message}"
        try:
            rule_opts = AddRuleOptions(
                interface=iface_name,
                src=server_network_v4,
                protocol="icmp",
                actions=[("drop", 0)],
                rule_id=rule_id,
            )
            result = policy_client.add_rule(rule_opts, direction="egress")
            assert result.success, f"Failed to re-add egress rule: {result.message}"

            rule_stats_after = policy_client.get_rule_stats(
                rule_id=rule_id, direction="egress"
            )
            packets_after = 0
            for rws in rule_stats_after.rules:
                if rws.rule.rule_id == rule_id and rws.stats:
                    packets_after = rws.stats.packets
                    break
            logger.info(
                f"Egress rule {rule_id} packets after detach+re-attach: {packets_after}"
            )
            assert packets_after == 0, (
                "Rule stats should be cleared after egress detach"
            )
        finally:
            policy_client.flush_rules(direction="egress")
            policy_client.detach_egress(iface_name)
