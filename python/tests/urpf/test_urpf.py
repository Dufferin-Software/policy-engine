# Copyright (c) Dufferin Software

"""
uRPF (unicast Reverse Path Forwarding) integration tests.

Topology: client ↔ [transit: policy-engine XDP] ↔ server

The transit node routes between net1 (client side) and net2 (server side) with
XDP attached on both ingress interfaces. uRPF on transit/net1 checks each
packet's *source* address against the FIB:

  - strict — pass only if the route back to the source exits via net1 (the
    ingress interface). A source that lives on net2 routes back via net2, so a
    packet claiming such a source but arriving on net1 is spoofed → dropped.
  - loose  — pass if any route to the source exists; only fully unroutable
    sources are dropped.

Tests validate:
  - Legitimate client traffic passes under strict uRPF (no drops).
  - A cross-interface spoofed source is dropped in strict but allowed in loose.
  - A fully unroutable spoofed source is dropped even in loose.
  - With uRPF off, spoofed traffic is not dropped by the check.
  - The uRPF mode query/toggle round-trips.
  - Enabling uRPF on an interface without XDP attached is rejected (ingress-only).
"""

import logging
import time

import netaddr

from netsim.testkit.nping_utils import NpingOptions, NpingProtocol, run_nping

logger = logging.getLogger(__name__)

_PING_COUNT = 5
_SPOOF_COUNT = 10
_SETTLE_SECONDS = 0.5


def _ping(node, target_ip: str, count: int = _PING_COUNT, ipv6: bool = False) -> bool:
    """Run ping from node to target_ip. Returns True if all packets received."""
    cmd = "ping6" if ipv6 else "ping"
    try:
        result = node.ssh_command(
            f"{cmd} -c {count} -W 2 {target_ip}",
            timeout=count * 3 + 5,
        )
        return "0% packet loss" in result
    except Exception as e:
        logger.debug(f"ping failed: {e}")
        return False


def _send_spoofed(
    client, iface: str, source_ip: str, dest_ip: str, count: int = _SPOOF_COUNT
) -> None:
    """
    Send ICMP echo requests from `client` with a spoofed source IP toward
    `dest_ip` out `iface`. Replies never return (the source is spoofed); the
    point is purely to deliver the packets to transit/net1 ingress so the uRPF
    check runs.
    """
    opts = NpingOptions(
        target=dest_ip,
        protocol=NpingProtocol.ICMP,
        source_ip=source_ip,
        interface=iface,
        count=count,
        delay="50ms",
    )
    run_nping(client, opts, timeout=count * 2 + 15)


class TestUrpf:
    """Integration tests for the uRPF data-plane feature."""

    # ── helpers ──────────────────────────────────────────────────────────────

    def _server_ip(self, node_interfaces) -> str:
        return str(node_interfaces["server"]["net2"].get_ip_address())

    def _transit_net1_iface(self, node_interfaces) -> str:
        return node_interfaces["transit"]["net1"].if_name

    def _transit_net1_ip(self, node_interfaces) -> str:
        return str(node_interfaces["transit"]["net1"].get_ip_address())

    def _client_net1_iface(self, node_interfaces) -> str:
        return node_interfaces["client"]["net1"].if_name

    def _net2_spoof_source(self, topology) -> str:
        """An address in the server subnet (routes back via net2, not net1)."""
        return str(netaddr.IPNetwork(topology.get_network("net2").subnet)[99])

    def _ingress_stats(self, policy_client, node_interfaces):
        """GlobalStats for transit net1 ingress (the client→server direction)."""
        iface = self._transit_net1_iface(node_interfaces)
        return policy_client.get_stats(iface, direction="ingress").global_stats

    # ── query / toggle ───────────────────────────────────────────────────────

    def test_urpf_default_off(
        self, node_interfaces, policy_client, attached_interfaces
    ):
        """A freshly-attached interface reports uRPF off and is absent from the list."""
        iface = self._transit_net1_iface(node_interfaces)
        assert policy_client.get_urpf(iface).upper() == "OFF", (
            f"Expected uRPF OFF by default on {iface}"
        )
        listed = dict(policy_client.list_urpf())
        assert iface not in listed, (
            f"Expected {iface} absent from uRPF list when off, got {listed}"
        )

    def test_urpf_toggle_query(
        self, node_interfaces, policy_client, attached_interfaces
    ):
        """Setting strict then off round-trips through the query API."""
        iface = self._transit_net1_iface(node_interfaces)

        r = policy_client.set_urpf(iface, "strict")
        assert r.success, f"Failed to set uRPF strict: {r.message}"
        assert policy_client.get_urpf(iface).upper() == "STRICT", (
            f"Expected uRPF STRICT on {iface} after setUrpf(strict)"
        )
        assert (iface, "STRICT") in [
            (i, m.upper()) for i, m in policy_client.list_urpf()
        ], "Expected interface to appear as STRICT in uRPF list"

        r = policy_client.set_urpf(iface, "off")
        assert r.success, f"Failed to set uRPF off: {r.message}"
        assert policy_client.get_urpf(iface).upper() == "OFF", (
            f"Expected uRPF OFF on {iface} after setUrpf(off)"
        )

    def test_urpf_rejected_without_xdp(self, policy_client):
        """
        uRPF is ingress-only (XDP). Enabling it on an interface that has no XDP
        program attached must be rejected — this is the same guard that prevents
        configuring uRPF on an egress (TC-only) interface.
        """
        r = policy_client.set_urpf("urpf-absent0", "strict")
        assert not r.success, (
            "Expected uRPF to be rejected on an interface without XDP attached"
        )
        assert "XDP" in r.message or "egress" in r.message, (
            f"Expected an XDP/egress-related rejection message, got: {r.message}"
        )

    # ── strict mode ──────────────────────────────────────────────────────────

    def test_legit_traffic_passes_strict(
        self, nodes, node_interfaces, policy_client, urpf_strict, cleared_stats
    ):
        """Legitimate client→server traffic passes strict uRPF (source routes via net1)."""
        server_ip = self._server_ip(node_interfaces)
        # Ping succeeding (0% loss) already proves the echo requests passed uRPF
        # on net1 ingress and the replies passed uRPF on net2 ingress.
        assert _ping(nodes["client"], server_ip), (
            "Legitimate IPv4 ping failed under strict uRPF"
        )
        stats = self._ingress_stats(policy_client, node_interfaces)
        # The echo requests must have traversed the uRPF → policy → pass path.
        assert stats.policy_pass >= _PING_COUNT, (
            f"Expected >= {_PING_COUNT} packets to pass, got policy_pass={stats.policy_pass}"
        )
        # IPv6 control traffic (link-local / multicast: NDP, DAD, MLD, RS/RA) is
        # exempt from uRPF, so legitimate traffic should produce no drops at all.
        # The "< ping count" bound is a safety margin against any rare stray
        # non-routable source: what it proves is that none of the legitimate
        # IPv4 echo requests were dropped.
        assert stats.urpf_drop_packets < _PING_COUNT, (
            f"Legitimate echoes appear to have been dropped by strict uRPF: "
            f"urpf_drop_packets={stats.urpf_drop_packets} (>= ping count {_PING_COUNT})"
        )
        logger.info(
            f"strict uRPF, legit traffic: policy_pass={stats.policy_pass} "
            f"urpf_drop_packets={stats.urpf_drop_packets}"
        )

    def test_spoofed_cross_iface_dropped_strict(
        self,
        nodes,
        node_interfaces,
        topology,
        policy_client,
        urpf_strict,
        cleared_stats,
        nmap_installed,
    ):
        """
        A packet whose source belongs to the net2 subnet but arrives on net1 is
        spoofed under strict uRPF (reverse path is net2 ≠ net1) → dropped.
        """
        server_ip = self._server_ip(node_interfaces)
        spoof_src = self._net2_spoof_source(topology)
        client_iface = self._client_net1_iface(node_interfaces)

        _send_spoofed(nodes["client"], client_iface, spoof_src, server_ip)
        time.sleep(_SETTLE_SECONDS)

        stats = self._ingress_stats(policy_client, node_interfaces)
        assert stats.urpf_drop_packets > 0, (
            f"Expected strict uRPF to drop cross-interface spoof from {spoof_src}, "
            f"got urpf_drop_packets={stats.urpf_drop_packets}"
        )
        assert stats.urpf_drop_bytes > 0, (
            f"Expected urpf_drop_bytes > 0, got {stats.urpf_drop_bytes}"
        )
        logger.info(
            f"strict uRPF, spoof {spoof_src}: "
            f"urpf_drop_packets={stats.urpf_drop_packets} bytes={stats.urpf_drop_bytes}"
        )

    # ── loose mode ───────────────────────────────────────────────────────────

    def test_spoofed_cross_iface_allowed_loose(
        self,
        nodes,
        node_interfaces,
        topology,
        policy_client,
        urpf_loose,
        cleared_stats,
        nmap_installed,
    ):
        """
        The same net2-sourced spoof that strict drops is *allowed* by loose,
        because a route to that source exists (via net2). uRPF must not drop it.
        """
        server_ip = self._server_ip(node_interfaces)
        spoof_src = self._net2_spoof_source(topology)
        client_iface = self._client_net1_iface(node_interfaces)

        # Legitimate traffic still flows under loose.
        assert _ping(nodes["client"], server_ip), (
            "Legitimate IPv4 ping failed under loose uRPF"
        )

        _send_spoofed(nodes["client"], client_iface, spoof_src, server_ip)
        time.sleep(_SETTLE_SECONDS)

        stats = self._ingress_stats(policy_client, node_interfaces)
        # Loose uRPF only drops sources with no route at all, so the routable
        # net2 spoof must be allowed: drops stay well below the number of
        # spoofed packets sent. (IPv6 control traffic is exempt, so in practice
        # this is ~0; "<" rather than "==" tolerates any rare stray source.)
        assert stats.urpf_drop_packets < _SPOOF_COUNT, (
            f"Expected loose uRPF to allow routable source {spoof_src} "
            f"(< {_SPOOF_COUNT} drops), got urpf_drop_packets={stats.urpf_drop_packets}"
        )
        logger.info(
            f"loose uRPF, routable spoof {spoof_src}: "
            f"urpf_drop_packets={stats.urpf_drop_packets} (allowed)"
        )

    def test_unroutable_source_dropped_loose(
        self,
        nodes,
        node_interfaces,
        policy_client,
        urpf_loose,
        cleared_stats,
        nmap_installed,
    ):
        """
        A fully unroutable source is dropped even in loose mode. An explicit
        `unreachable` route on transit makes the FIB lookup fail deterministically,
        regardless of any default route present in the environment.
        """
        server_ip = self._server_ip(node_interfaces)
        client_iface = self._client_net1_iface(node_interfaces)
        bogus_net = "192.0.2.0/24"  # TEST-NET-1 (RFC 5737)
        spoof_src = "192.0.2.5"

        nodes["transit"].ssh_command(
            f"sudo ip route replace unreachable {bogus_net}", timeout=5
        )
        try:
            _send_spoofed(nodes["client"], client_iface, spoof_src, server_ip)
            time.sleep(_SETTLE_SECONDS)

            stats = self._ingress_stats(policy_client, node_interfaces)
            assert stats.urpf_drop_packets > 0, (
                f"Expected loose uRPF to drop unroutable source {spoof_src}, "
                f"got urpf_drop_packets={stats.urpf_drop_packets}"
            )
            logger.info(
                f"loose uRPF, unroutable spoof {spoof_src}: "
                f"urpf_drop_packets={stats.urpf_drop_packets}"
            )
        finally:
            nodes["transit"].ssh_command(
                f"sudo ip route del unreachable {bogus_net} 2>/dev/null || true",
                timeout=5,
            )

    # ── non-forwarding host (regression) ─────────────────────────────────────

    def test_loose_passes_host_traffic_without_forwarding(
        self, nodes, node_interfaces, policy_client, urpf_loose, cleared_stats
    ):
        """
        Regression for the lockout: uRPF must never black-hole a node with IP
        forwarding DISABLED (an ordinary host/edge box, not a router). The
        reverse-path check uses bpf_fib_lookup, whose forwarding check returns
        FWD_DISABLED on a non-forwarding interface — which the check treats as
        fail-open (pass) rather than a drop. An earlier version classified that
        result (and a malformed ifindex=0 lookup) as "no route" and dropped
        *all* inbound traffic, locking the box out.

        The client pings transit's own net1 address (local delivery to transit),
        which still traverses transit's net1 XDP ingress and so is uRPF-checked.
        """
        transit = nodes["transit"]
        transit_ip = self._transit_net1_ip(node_interfaces)

        prev = transit.ssh_command(
            "cat /proc/sys/net/ipv4/ip_forward", timeout=5
        ).strip()
        transit.ssh_command("sudo sysctl -w net.ipv4.ip_forward=0", timeout=5)
        try:
            assert _ping(nodes["client"], transit_ip), (
                "Host-bound ping was dropped by uRPF on a non-forwarding node — "
                "FWD_DISABLED from the reverse-path lookup must fail open, not drop"
            )
            stats = self._ingress_stats(policy_client, node_interfaces)
            assert stats.urpf_drop_packets < _PING_COUNT, (
                f"Legitimate host-bound traffic dropped by uRPF on a "
                f"non-forwarding node: urpf_drop_packets={stats.urpf_drop_packets}"
            )
            logger.info(
                f"loose uRPF, forwarding=0, host-bound ping: "
                f"urpf_drop_packets={stats.urpf_drop_packets} (passed)"
            )
        finally:
            transit.ssh_command(
                f"sudo sysctl -w net.ipv4.ip_forward={prev or '1'}", timeout=5
            )

    # ── disabled ─────────────────────────────────────────────────────────────

    def test_spoof_passes_when_disabled(
        self,
        nodes,
        node_interfaces,
        topology,
        policy_client,
        attached_interfaces,
        cleared_stats,
        nmap_installed,
    ):
        """
        With uRPF off (default), the cross-interface spoof is not dropped by the
        uRPF check — the drop counter stays at zero.
        """
        server_ip = self._server_ip(node_interfaces)
        spoof_src = self._net2_spoof_source(topology)
        client_iface = self._client_net1_iface(node_interfaces)

        _send_spoofed(nodes["client"], client_iface, spoof_src, server_ip)
        time.sleep(_SETTLE_SECONDS)

        stats = self._ingress_stats(policy_client, node_interfaces)
        assert stats.urpf_drop_packets == 0, (
            f"Expected no uRPF drops when disabled, got {stats.urpf_drop_packets}"
        )
        logger.info(
            f"uRPF off, spoof {spoof_src}: urpf_drop_packets={stats.urpf_drop_packets}"
        )
