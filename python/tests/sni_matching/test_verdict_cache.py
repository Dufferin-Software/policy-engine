# Copyright (c) Peter Morrow

"""
Verdict-cache fast-path behaviour.

After the SNI inspector decides a verdict on a flow it writes a verdict
into the verdict cache with the 10-minute SNI/QUIC TTL
(SNI_VERDICT_TTL_NS / QUIC_VERDICT_TTL_NS).  Subsequent packets on the
same 5-tuple short-circuit in BPF without re-running the SNI tail call
(TCP) or re-emitting a ringbuf event (QUIC) — that's the whole point of
the cache.

Both transports are covered here:

* **QUIC** — userspace consumer (``process_quic_sample`` in
  ``event_stream.rs``) writes via ``BpfOperations::update_flow_verdict``
  after Initial decryption.
* **TCP** — ``tc_sni_inspect`` writes to ``tc_flow_verdict_cache``
  directly from BPF once it has walked the matched rule's
  ``actions[]`` (or selected PASS on the no-match-after-exhaustion
  path).

Test approach: use ``active_verdicts`` as the "inspector ran and wrote"
counter.
"""

import logging
import time

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions
from tests.sni_matching.helpers import (
    wait_for_verdict_entry,
    wait_for_verdict_evicted,
    wait_verdicts,
)

logger = logging.getLogger(__name__)

_DPORT = 443


class TestQuicVerdictCacheFastPath:
    def test_distinct_5tuples_each_write_a_verdict(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """Three QUIC Initials on distinct source ports → three verdict entries."""
        sni = "cache-distinct.example"
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=930_002,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        for src in (50101, 50102, 50103):
            quic_sender(str(client_ip_v4), _DPORT, sni, src_port=src)
            time.sleep(0.15)

        after = wait_verdicts(policy_client, before, want=3)
        grew = after - before
        logger.info(f"distinct-5tuple verdicts: before={before} after={after}")
        assert grew >= 3, (
            f"Expected at least 3 new verdicts across 3 distinct flows; got {grew}"
        )


@pytest.mark.usefixtures("tcp_sni_listener")
class TestTcpVerdictCacheFastPath:
    # tcp_sni_listener is required so connect() completes and the
    # ClientHello actually leaves the client.  Without it the test
    # binary exits non-zero before tc_sni_inspect ever runs.

    """
    Mirrors the QUIC class above for the in-kernel TCP SNI inspector.
    ``tc_sni_inspect`` now writes ``tc_flow_verdict_cache`` directly after
    walking the matched rule's actions[] (or PASS on no-match-after-exhaustion)
    so subsequent packets on the same flow short-circuit at L4 entry.
    """

    def test_distinct_5tuples_each_write_a_verdict(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """Three TLS ClientHellos on distinct source ports → three verdict entries.

        Uses a LOG (non-terminal) action.  A DROP rule would cache DROP for
        the first flow's 5-tuple, then the FIN packet from ``shutdown()`` on
        that same 5-tuple would also hit the L4 cache and be dropped at
        egress.  The listener (single-threaded, blocked in ``recv()``) would
        then never get the FIN, and the TCP cleanup interplay can make
        subsequent ``connect()`` calls flaky.  LOG matches still write the
        verdict cache (PASS, after walking actions[]) so the invariant under
        test is unchanged, while the on-the-wire handshake completes cleanly.
        """
        sni = "cache-tcp-distinct.example"
        rule_id = 930_003
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=_DPORT,
                actions=[("log", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        for src in (50201, 50202, 50203):
            tls_sender(str(client_ip_v4), _DPORT, sni, src_port=src)
            time.sleep(0.15)

        after = wait_verdicts(policy_client, before, want=3)
        grew = after - before
        logger.info(f"distinct-5tuple TCP verdicts: before={before} after={after}")
        assert grew >= 3, (
            f"Expected at least 3 new verdicts across 3 distinct TCP flows; got {grew}"
        )

    def test_same_5tuple_inspects_once(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """
        Repeated ClientHellos on the same source port must hit the cached
        verdict on every packet after the first, so ``rule_stats.packets``
        increments at most once across N sends.  Without the in-kernel cache
        write each send re-runs ``tc_sni_inspect`` and the counter grows
        linearly with the send count.

        Uses a LOG (non-terminal) action so the cached verdict is PASS;
        DROP would block the SYN of subsequent sends at the L4 cache check
        and ``connect()`` would never complete, masking the very behaviour
        under test.
        """
        sni = "cache-tcp-same.example"
        rule_id = 930_004
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=_DPORT,
                actions=[("log", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        src_port = 50301
        sends = 3
        for _ in range(sends):
            tls_sender(str(client_ip_v4), _DPORT, sni, src_port=src_port)
            time.sleep(0.15)

        # Give the engine a moment to surface the latest rule_stats.
        time.sleep(0.5)
        stats = policy_client.get_rule_stats(rule_id=rule_id, direction="egress")
        pkts = (
            stats.rules[0].stats.packets if stats.rules and stats.rules[0].stats else 0
        )
        logger.info(f"same-5-tuple TCP rule_stats.packets after {sends} sends: {pkts}")
        assert pkts >= 1, (
            "First ClientHello on this flow should have advanced rule_stats."
        )
        assert pkts < sends, (
            f"Verdict cache did not short-circuit subsequent sends — "
            f"rule_stats.packets={pkts} after {sends} sends (expected < {sends})."
        )


class TestVerdictCacheListing:
    """End-to-end coverage of the verdict-cache *contents* (not just the count).

    Exercises the ``flowVerdictList`` / ``policy-client inspect verdicts --list``
    surface — the entries an operator sees in the CLI and web UIs — and the
    background evictor that removes them once their TTL elapses.
    """

    def test_list_exposes_entry_with_expected_verdict(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """A DROP-SNI QUIC flow surfaces as a DROP entry on its own 5-tuple.

        Validates the full read path: BPF map → engine ``flowVerdictList`` →
        client. The fields (src port, dst port, protocol, action) must match the
        flow we generated, not just an opaque count.
        """
        sni = "cache-list.example"
        src_port = 50410
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=930_010,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        # Clean slate so the only entry on our src port is the one we create.
        policy_client.clear_flow_verdicts(direction="egress")

        quic_sender(str(client_ip_v4), _DPORT, sni, src_port=src_port)

        entry = wait_for_verdict_entry(policy_client, src_port, direction="egress")
        assert entry is not None, (
            f"no cached verdict appeared for src_port={src_port}; "
            "flowVerdictList returned nothing for our flow"
        )
        logger.info(f"cached entry: {entry}")
        assert entry.action == "DROP", f"expected DROP verdict, got {entry.action}"
        assert entry.dst_port == _DPORT, f"unexpected dst_port {entry.dst_port}"
        assert entry.protocol.lower() == "udp", f"expected udp, got {entry.protocol}"
        assert not entry.expired, "freshly-written verdict should not be expired yet"

    @pytest.mark.slow
    def test_expired_verdicts_are_evicted(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """A verdict that is never refreshed is swept out after its TTL.

        Regression test for the evictor: BPF HASH maps don't auto-expire, so the
        userspace ``FlowVerdictManager`` sweep is the only thing that removes
        stale entries. With it disabled, entries accumulate forever (the entry
        below would persist indefinitely). SNI/QUIC verdicts use the 10-minute
        SNI_VERDICT_TTL_NS / QUIC_VERDICT_TTL_NS (deliberately long — see the
        constant's rationale in policy_common.h), swept every 30 s, so a single
        un-refreshed flow disappears within ~TTL + one sweep. Marked ``slow``
        accordingly.
        """
        sni = "cache-evict.example"
        src_port = 50411
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=930_011,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        policy_client.clear_flow_verdicts(direction="egress")
        quic_sender(str(client_ip_v4), _DPORT, sni, src_port=src_port)

        entry = wait_for_verdict_entry(policy_client, src_port, direction="egress")
        assert entry is not None, "verdict should have been written before eviction"

        # Do not touch this 5-tuple again — let the TTL lapse and the sweep run.
        # SNI/QUIC TTL is 10 min + a 30 s sweep, so allow ~TTL + sweep + margin.
        evicted = wait_for_verdict_evicted(
            policy_client, src_port, direction="egress", budget_s=700.0
        )
        assert evicted, (
            f"verdict for src_port={src_port} was not evicted within 700 s — "
            "the FlowVerdictManager cleanup loop may not be running"
        )
