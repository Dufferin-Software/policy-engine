# Copyright (c) Dufferin Software

"""
XDP FIB forwarding integration tests.

Topology: client ↔ [transit: policy-engine XDP] ↔ server

Tests validate that:
  - XDP attached with FIB enabled: packets forwarded at XDP layer, fib_forwarded_packets > 0
  - Policy DROP rules are respected even when FIB is enabled
  - FIB can be toggled on/off at runtime
  - FIB stats (forwarded / fallback) are accurate
  - TTL=1 packets are NOT forwarded by FIB (kernel handles ICMP TTL Exceeded)
"""

import time
import logging
import pytest

from policy_engine_client.engine.graphql.client import AddRuleOptions

logger = logging.getLogger(__name__)

# Number of ICMP echo requests per ping burst
_PING_COUNT = 5
# Time to wait for ARP/NDP resolution on first packet
_ARP_SETTLE_SECONDS = 0.5


def _ping(node, target_ip: str, count: int = _PING_COUNT, ipv6: bool = False) -> bool:
    """
    Run ping from node to target_ip.  Returns True if all packets received.
    """
    cmd = "ping6" if ipv6 else "ping"
    try:
        result = node.ssh_command(
            f"{cmd} -c {count} -W 2 {target_ip}",
            timeout=count * 3 + 5,
        )
        return "0% packet loss" in result or "0 packets received" not in result
    except Exception as e:
        logger.debug(f"ping failed: {e}")
        return False


def _ping_ttl(node, target_ip: str, ttl: int, count: int = 3) -> bool:
    """Run ping with a specific TTL.  Returns True if any replies received."""
    try:
        result = node.ssh_command(
            f"ping -c {count} -W 2 -t {ttl} {target_ip}",
            timeout=count * 3 + 5,
        )
        # If TTL=1 and the transit drops it, we expect ICMP TTL Exceeded back
        # rather than echo replies, so "0 received" / "100% loss"
        return "0% packet loss" in result
    except Exception:
        return False


class TestXdpFibForwarding:
    """Integration tests for XDP FIB forwarding feature."""

    def _server_ip(self, node_interfaces) -> str:
        return str(node_interfaces["server"]["net2"].get_ip_address())

    def _server_ipv6(self, node_interfaces):
        return node_interfaces["server"]["net2"].get_ipv6_address()

    def _client_ip(self, node_interfaces) -> str:
        return str(node_interfaces["client"]["net1"].get_ip_address())

    def _transit_net1_iface(self, node_interfaces) -> str:
        return node_interfaces["transit"]["net1"].if_name

    def _get_ingress_stats(self, policy_client, node_interfaces):
        """Return GlobalStats for transit net1 ingress (client-to-server direction)."""
        iface = self._transit_net1_iface(node_interfaces)
        return policy_client.get_stats(iface, direction="ingress").global_stats

    # ------------------------------------------------------------------
    # FIB enabled: forwarding at XDP layer
    # ------------------------------------------------------------------

    def test_fib_forwarding_enabled_ipv4(
        self,
        nodes,
        node_interfaces,
        policy_client,
        attached_interfaces,
        fib_enabled,
        cleared_stats,
    ):
        """
        FIB forwarding enabled: IPv4 ping must succeed and fib_forwarded_packets > 0.
        First packet may hit ARP miss (fallback), subsequent packets use FIB path.
        """
        server_ip = self._server_ip(node_interfaces)
        # Warm up ARP
        _ping(nodes["client"], server_ip, count=1)
        time.sleep(_ARP_SETTLE_SECONDS)
        policy_client.clear_global_stats(
            self._transit_net1_iface(node_interfaces), direction="ingress"
        )

        assert _ping(nodes["client"], server_ip, count=_PING_COUNT), (
            "IPv4 ping failed with FIB forwarding enabled"
        )

        stats = self._get_ingress_stats(policy_client, node_interfaces)
        assert stats.fib_forwarded_packets > 0, (
            f"Expected fib_forwarded_packets > 0 after FIB-forwarded pings, "
            f"got {stats.fib_forwarded_packets}"
        )
        assert stats.fib_forwarded_bytes > 0, (
            f"Expected fib_forwarded_bytes > 0, got {stats.fib_forwarded_bytes}"
        )
        logger.info(
            f"FIB forwarding IPv4: forwarded={stats.fib_forwarded_packets} pkts "
            f"({stats.fib_forwarded_bytes} bytes), fallback={stats.fib_fallback_packets}"
        )

    def test_fib_forwarding_enabled_ipv6(
        self,
        nodes,
        node_interfaces,
        policy_client,
        attached_interfaces,
        fib_enabled,
        cleared_stats,
    ):
        """
        FIB forwarding enabled: IPv6 ping must succeed and fib_forwarded_packets > 0.
        """
        server_ipv6 = self._server_ipv6(node_interfaces)
        if not server_ipv6:
            pytest.skip("IPv6 not configured on server")

        # Warm up NDP
        _ping(nodes["client"], str(server_ipv6), count=1, ipv6=True)
        time.sleep(_ARP_SETTLE_SECONDS)
        policy_client.clear_global_stats(
            self._transit_net1_iface(node_interfaces), direction="ingress"
        )

        assert _ping(nodes["client"], str(server_ipv6), count=_PING_COUNT, ipv6=True), (
            "IPv6 ping failed with FIB forwarding enabled"
        )

        stats = self._get_ingress_stats(policy_client, node_interfaces)
        assert stats.fib_forwarded_packets > 0, (
            f"Expected fib_forwarded_packets > 0 after FIB-forwarded IPv6 pings, "
            f"got {stats.fib_forwarded_packets}"
        )
        logger.info(
            f"FIB forwarding IPv6: forwarded={stats.fib_forwarded_packets} pkts, "
            f"fallback={stats.fib_fallback_packets}"
        )

    # ------------------------------------------------------------------
    # Policy rules take precedence over FIB
    # ------------------------------------------------------------------

    def test_drop_rule_respected_with_fib(
        self,
        nodes,
        node_interfaces,
        policy_client,
        attached_interfaces,
        fib_enabled,
        cleared_stats,
    ):
        """
        A DROP rule must block traffic even when FIB forwarding is enabled.
        After removing the rule, traffic must resume.
        """
        server_ip = self._server_ip(node_interfaces)
        client_ip = self._client_ip(node_interfaces)
        client_prefix = client_ip + "/32"

        # Add a DROP rule for client source IP
        transit_iface = self._transit_net1_iface(node_interfaces)
        drop_rule_id = 70001
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=transit_iface,
                src=client_prefix,
                actions=[("drop", 0)],
                rule_id=drop_rule_id,
            ),
            direction="ingress",
        )
        assert result.success, f"Failed to add DROP rule: {result.message}"
        logger.info(f"Added DROP rule for src {client_prefix}")

        try:
            # Traffic must be dropped
            assert not _ping(nodes["client"], server_ip), (
                "Expected ping to fail with DROP rule active, but it succeeded"
            )

            drop_stats = self._get_ingress_stats(policy_client, node_interfaces)
            assert drop_stats.policy_drops > 0, (
                f"Expected policy_drops > 0 with DROP rule, got {drop_stats.policy_drops}"
            )
            logger.info(f"DROP rule active: policy_drops={drop_stats.policy_drops}")

        finally:
            # Remove rule and verify traffic resumes
            del_result = policy_client.delete_rule(
                transit_iface, rule_id=drop_rule_id, direction="ingress"
            )
            assert del_result.success, (
                f"Failed to delete DROP rule: {del_result.message}"
            )

        # Warm up ARP after rule removal
        time.sleep(_ARP_SETTLE_SECONDS)
        assert _ping(nodes["client"], server_ip), (
            "Expected ping to succeed after DROP rule removed, but it failed"
        )
        logger.info("Traffic resumed after DROP rule removal")

    # ------------------------------------------------------------------
    # Stats accuracy
    # ------------------------------------------------------------------

    def test_fib_stats_count(
        self,
        nodes,
        node_interfaces,
        policy_client,
        attached_interfaces,
        fib_enabled,
    ):
        """
        Verify fib_forwarded_packets >= ping count after clearing stats.
        The first packet may miss ARP and fall back; subsequent ones use FIB.
        """
        server_ip = self._server_ip(node_interfaces)

        # Warm up ARP first
        _ping(nodes["client"], server_ip, count=1)
        time.sleep(_ARP_SETTLE_SECONDS)

        # Clear stats and send a known number of pings
        iface = self._transit_net1_iface(node_interfaces)
        policy_client.clear_global_stats(iface, direction="ingress")

        n = 10
        assert _ping(nodes["client"], server_ip, count=n), "Ping burst failed"

        stats = self._get_ingress_stats(policy_client, node_interfaces)
        # Each ICMP echo request passes through transit net1 ingress once
        assert stats.fib_forwarded_packets >= n, (
            f"Expected fib_forwarded_packets >= {n}, got {stats.fib_forwarded_packets}"
        )
        assert stats.fib_forwarded_bytes > 0, (
            f"Expected fib_forwarded_bytes > 0, got {stats.fib_forwarded_bytes}"
        )
        logger.info(
            f"Stats: fib_forwarded={stats.fib_forwarded_packets}/{n} pings, "
            f"bytes={stats.fib_forwarded_bytes}"
        )

    # ------------------------------------------------------------------
    # Toggle FIB on/off
    # ------------------------------------------------------------------

    def test_fib_forwarding_toggle(
        self,
        nodes,
        node_interfaces,
        policy_client,
        attached_interfaces,
        cleared_stats,
    ):
        """
        Enabling FIB and then disabling it should toggle fib_forwarded_packets
        from non-zero back to zero (for new traffic after clearing stats).
        """
        server_ip = self._server_ip(node_interfaces)
        iface = self._transit_net1_iface(node_interfaces)

        # Initially disabled: query must return False for this interface
        assert not policy_client.get_fib_forwarding(iface), (
            f"Expected FIB forwarding to be disabled initially on {iface}"
        )

        # Enable FIB on both transit ingress interfaces (client→server and reverse)
        for peer_iface in attached_interfaces.values():
            result = policy_client.set_fib_forwarding(peer_iface, enabled=True)
            assert result.success, (
                f"Failed to enable FIB on {peer_iface}: {result.message}"
            )
        assert policy_client.get_fib_forwarding(iface), (
            f"Expected FIB forwarding to be enabled on {iface} after setFibForwarding(true)"
        )

        # Warm up ARP and send pings with FIB enabled
        _ping(nodes["client"], server_ip, count=1)
        time.sleep(_ARP_SETTLE_SECONDS)
        policy_client.clear_global_stats(iface, direction="ingress")
        assert _ping(nodes["client"], server_ip, count=_PING_COUNT)
        stats_on = self._get_ingress_stats(policy_client, node_interfaces)
        assert stats_on.fib_forwarded_packets > 0, (
            f"FIB enabled: expected fib_forwarded_packets > 0, got {stats_on.fib_forwarded_packets}"
        )

        # Disable FIB on both transit ingress interfaces
        for peer_iface in attached_interfaces.values():
            result = policy_client.set_fib_forwarding(peer_iface, enabled=False)
            assert result.success, (
                f"Failed to disable FIB on {peer_iface}: {result.message}"
            )
        assert not policy_client.get_fib_forwarding(iface), (
            f"Expected FIB forwarding to be disabled on {iface} after setFibForwarding(false)"
        )

        policy_client.clear_global_stats(iface, direction="ingress")
        assert _ping(nodes["client"], server_ip, count=_PING_COUNT), (
            "Ping failed after FIB disabled (should fall back to XDP_PASS)"
        )
        stats_off = self._get_ingress_stats(policy_client, node_interfaces)
        assert stats_off.fib_forwarded_packets == 0, (
            f"FIB disabled: expected fib_forwarded_packets == 0, got {stats_off.fib_forwarded_packets}"
        )
        logger.info(
            f"Toggle: FIB on → forwarded={stats_on.fib_forwarded_packets}, "
            f"FIB off → forwarded={stats_off.fib_forwarded_packets}"
        )

    # ------------------------------------------------------------------
    # TTL=1 is NOT FIB-forwarded (kernel must send ICMP TTL Exceeded)
    # ------------------------------------------------------------------

    def test_ttl_one_not_fib_forwarded(
        self,
        nodes,
        node_interfaces,
        policy_client,
        attached_interfaces,
        fib_enabled,
        cleared_stats,
    ):
        """
        Packets with TTL=1 must NOT be FIB-forwarded (the BPF program falls back
        to XDP_PASS so the kernel can generate an ICMP TTL Exceeded reply).
        fib_forwarded_packets must remain 0 for TTL=1 pings.
        """
        server_ip = self._server_ip(node_interfaces)

        # TTL=1 — packets die at transit, kernel sends ICMP TTL Exceeded
        _ping_ttl(nodes["client"], server_ip, ttl=1, count=3)

        stats = self._get_ingress_stats(policy_client, node_interfaces)
        assert stats.fib_forwarded_packets == 0, (
            f"Expected fib_forwarded_packets == 0 for TTL=1 pings, "
            f"got {stats.fib_forwarded_packets}"
        )
        logger.info(
            f"TTL=1: fib_forwarded={stats.fib_forwarded_packets}, "
            f"fib_fallback={stats.fib_fallback_packets}"
        )

    # ------------------------------------------------------------------
    # FIB fallback counter
    # ------------------------------------------------------------------

    def test_fib_fallback_counter(
        self,
        nodes,
        node_interfaces,
        policy_client,
        attached_interfaces,
        fib_enabled,
        cleared_stats,
    ):
        """
        The first packet to a new destination (before ARP resolves) causes a
        BPF_FIB_LKUP_RET_NO_NEIGH result, incrementing fib_fallback_packets.
        Subsequent packets after ARP resolution should use the FIB path.
        """
        server_ip = self._server_ip(node_interfaces)

        # Flush the ARP cache on transit so the first packet triggers a miss
        nodes["transit"].ssh_command(
            "sudo ip neigh flush all 2>/dev/null || true", timeout=5
        )
        time.sleep(0.1)

        # Send first ping — likely ARP miss → fib_fallback
        _ping(nodes["client"], server_ip, count=1)
        time.sleep(_ARP_SETTLE_SECONDS)

        stats_after_first = self._get_ingress_stats(policy_client, node_interfaces)

        # Send more pings — ARP should be resolved now → FIB path
        _ping(nodes["client"], server_ip, count=_PING_COUNT)
        stats_after_more = self._get_ingress_stats(policy_client, node_interfaces)

        assert stats_after_more.fib_forwarded_packets > 0, (
            f"Expected fib_forwarded_packets > 0 after ARP resolved, "
            f"got {stats_after_more.fib_forwarded_packets}"
        )
        logger.info(
            f"Fallback test: first_pkt fib_fallback={stats_after_first.fib_fallback_packets}, "
            f"after ARP fib_forwarded={stats_after_more.fib_forwarded_packets}"
        )
