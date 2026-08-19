# Copyright (c) Dufferin Software

"""
End-to-end SNI matching: real handshake on the wire → BPF/userspace
inspector → rule_stats and (for QUIC) flow_verdict_cache.

Each test parametrises over transport:

* ``tcp``     — scapy-crafted TLS 1.3 ClientHello over a real TCP
                connection.  Exercises ``tc_sni_inspect`` (in-kernel
                ClientHello parser) on egress.  Oracle: ``rule_stats``
                **and** verdict cache (``tc_sni_inspect`` writes
                ``tc_flow_verdict_cache`` from BPF after walking the
                matched rule's actions[]).
* ``quic-v1`` — aioquic v1 Initial.  Exercises the BPF
                ``tc_quic_initial_inspect`` tail call → userspace decrypt.
                Oracle: verdict cache.
* ``quic-v2`` — aioquic v2 Initial.  Same userspace path with the v2
                key-derivation salt; pins the version-pre-check in BPF
                and the v2 HKDF branch in userspace.

A separate ``TestMatchIngressQuic`` class re-runs the QUIC v1 match
scenario on the XDP ingress path so we don't lose coverage of
``xdp_quic_initial_inspect`` after consolidation.
"""

import logging
import time

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient

logger = logging.getLogger(__name__)

_DPORT = 443
_VERDICT_POLL_BUDGET_S = 5.0
_VERDICT_POLL_INTERVAL_S = 0.25


# ============================================================================
# Helpers
# ============================================================================


def _send_handshake(
    transport: str,
    *,
    tls_sender,
    quic_sender,
    target_ip,
    sni: str,
    src_port: int = 0,
) -> None:
    if transport == "tcp":
        tls_sender(str(target_ip), _DPORT, sni, src_port=src_port)
    elif transport == "quic-v1":
        quic_sender(str(target_ip), _DPORT, sni, version="v1", src_port=src_port)
    elif transport == "quic-v2":
        quic_sender(str(target_ip), _DPORT, sni, version="v2", src_port=src_port)
    else:
        raise AssertionError(f"unknown transport {transport!r}")


def _wait_for_verdict_growth(policy_client, direction: str, baseline: int) -> int:
    deadline = time.monotonic() + _VERDICT_POLL_BUDGET_S
    last = baseline
    while time.monotonic() < deadline:
        last = policy_client.get_flow_verdicts(direction=direction).active_verdicts
        if last > baseline:
            return last
        time.sleep(_VERDICT_POLL_INTERVAL_S)
    return last


def _wait_for_rule_packets(
    policy_client, rule_id: int, direction: str = "egress"
) -> int:
    """Poll rule_stats.packets for the given rule until it advances or budget expires."""
    deadline = time.monotonic() + _VERDICT_POLL_BUDGET_S
    last = 0
    while time.monotonic() < deadline:
        stats = policy_client.get_rule_stats(rule_id=rule_id, direction=direction)
        if stats.rules and stats.rules[0].stats:
            last = stats.rules[0].stats.packets
            if last > 0:
                return last
        time.sleep(_VERDICT_POLL_INTERVAL_S)
    return last


def _list_verdicts_raw(graphql_client: GraphQLPolicyClient, direction: str):
    query = """
    query VerdictList($direction: GqlDirection!) {
        flowVerdictList(direction: $direction) {
            srcIp dstIp srcPort dstPort protocol action expired
        }
    }
    """
    data = graphql_client._execute_graphql(query, {"direction": direction.upper()})
    if "__error__" in data:
        pytest.fail(f"flowVerdictList query failed: {data['__error__']}")
    return data.get("flowVerdictList", [])


def _live_actions(graphql_client, direction: str):
    return [
        v.get("action", "").upper()
        for v in _list_verdicts_raw(graphql_client, direction)
        if not v.get("expired")
    ]


def _proto_for(transport: str) -> str:
    return "tcp" if transport == "tcp" else "udp"


def _assert_match_observed(
    transport: str,
    policy_client,
    rule_id: int,
    direction: str = "egress",
    *,
    verdict_baseline: int | None = None,
) -> None:
    """
    Per-transport oracle: both TCP and QUIC matches now produce a
    verdict-cache entry (TCP via ``tc_sni_inspect`` in BPF, QUIC via the
    userspace consumer).  We assert the universal invariants:
    ``rule_stats.packets`` advances **and** the active verdict count grows.
    ``verdict_baseline`` is the active-verdict count captured before the
    handshake; if omitted, only the rule_stats invariant is checked (use
    that form for tests that intentionally don't measure the cache, e.g.
    when multiple flows confound the per-direction counter).
    """
    pkts = _wait_for_rule_packets(policy_client, rule_id, direction)
    assert pkts >= 1, (
        f"[{transport}] rule_stats.packets did not advance — SNI inspector "
        f"either didn't run or didn't match.  Got {pkts}."
    )
    if verdict_baseline is not None:
        after = _wait_for_verdict_growth(policy_client, direction, verdict_baseline)
        assert after > verdict_baseline, (
            f"[{transport}] verdict cache did not grow after match "
            f"({verdict_baseline} → {after}) — fast-path write is missing."
        )


# ============================================================================
# Egress — host filters its own outbound TLS / QUIC handshakes
# ============================================================================


@pytest.mark.usefixtures("tcp_sni_listener")
class TestMatchEgress:
    """One real handshake on each transport → rule_stats advances."""

    @pytest.mark.parametrize("transport", ["tcp", "quic-v1", "quic-v2"])
    def test_matching_sni_bumps_rule_stats(
        self,
        transport,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        sni = f"block.{transport}.example"
        rule_id = 910_001
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol=_proto_for(transport),
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert result.success, f"add_rule failed: {result.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        verdict_baseline = policy_client.get_flow_verdicts(
            direction="egress"
        ).active_verdicts

        _send_handshake(
            transport,
            tls_sender=tls_sender,
            quic_sender=quic_sender,
            target_ip=client_ip_v4,
            sni=sni,
        )

        _assert_match_observed(
            transport,
            policy_client,
            rule_id,
            verdict_baseline=verdict_baseline,
        )

    @pytest.mark.parametrize("transport", ["quic-v1", "quic-v2"])
    def test_quic_matching_sni_produces_drop_verdict(
        self,
        transport,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """QUIC-specific: userspace consumer writes a DROP verdict on match."""
        sni = f"verdict.{transport}.example"
        rule_id = 910_002
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert result.success, f"add_rule failed: {result.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts

        _send_handshake(
            transport,
            tls_sender=tls_sender,
            quic_sender=quic_sender,
            target_ip=client_ip_v4,
            sni=sni,
        )

        after = _wait_for_verdict_growth(policy_client, "egress", before)
        assert after > before, (
            f"[{transport}] verdict cache did not grow ({before} → {after})"
        )

    @pytest.mark.parametrize("transport", ["quic-v1", "quic-v2"])
    def test_quic_non_matching_sni_writes_pass_verdict(
        self,
        transport,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """
        QUIC: even when SNI misses, the userspace consumer writes a PASS
        verdict so subsequent packets on the flow fast-path through BPF.
        Without this every Initial would re-tail-call userspace.
        """
        rule_id = 910_003
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni="never-matches.example",
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts

        _send_handshake(
            transport,
            tls_sender=tls_sender,
            quic_sender=quic_sender,
            target_ip=client_ip_v4,
            sni="totally-other.example",
        )

        after = _wait_for_verdict_growth(policy_client, "egress", before)
        assert after > before, (
            f"[{transport}] expected always-write-PASS behaviour; "
            f"verdict cache did not grow ({before} → {after})"
        )

    @pytest.mark.parametrize("transport", ["tcp", "quic-v1", "quic-v2"])
    def test_wildcard_sni_matches(
        self,
        transport,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """`*.example.com` must match `host.example.com` on every transport."""
        rule_id = 910_004
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol=_proto_for(transport),
                dport=_DPORT,
                actions=[("drop", 0)],
                sni="*.wild.example",
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        verdict_baseline = policy_client.get_flow_verdicts(
            direction="egress"
        ).active_verdicts

        _send_handshake(
            transport,
            tls_sender=tls_sender,
            quic_sender=quic_sender,
            target_ip=client_ip_v4,
            sni="host.wild.example",
        )

        _assert_match_observed(
            transport,
            policy_client,
            rule_id,
            verdict_baseline=verdict_baseline,
        )


# ============================================================================
# Verdict-action assertion — DROP vs PASS — QUIC only (TCP doesn't write
# the verdict cache; see module docstring)
# ============================================================================


@pytest.mark.usefixtures("tcp_sni_listener")
class TestQuicVerdictAction:
    @pytest.fixture
    def graphql_only(self, client_type):
        if client_type != "graphql":
            pytest.skip("verdict-action check requires flowVerdictList (GraphQL only)")

    @pytest.mark.parametrize("transport", ["quic-v1", "quic-v2"])
    def test_match_writes_drop_action(
        self,
        graphql_only,
        transport,
        policy_client,
        graphql_policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        sni = f"drop-action.{transport}.example"
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=910_010,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        _send_handshake(
            transport,
            tls_sender=tls_sender,
            quic_sender=quic_sender,
            target_ip=client_ip_v4,
            sni=sni,
        )
        _wait_for_verdict_growth(policy_client, "egress", before)

        actions = _live_actions(graphql_policy_client, "egress")
        assert "DROP" in actions, (
            f"[{transport}] expected DROP verdict, got actions={actions}"
        )

    @pytest.mark.parametrize("transport", ["quic-v1", "quic-v2"])
    def test_miss_writes_pass_action(
        self,
        graphql_only,
        transport,
        policy_client,
        graphql_policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni="never.example",
                rule_id=910_011,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        before = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        _send_handshake(
            transport,
            tls_sender=tls_sender,
            quic_sender=quic_sender,
            target_ip=client_ip_v4,
            sni="other.example",
        )
        _wait_for_verdict_growth(policy_client, "egress", before)

        actions = _live_actions(graphql_policy_client, "egress")
        assert any(a == "PASS" for a in actions), (
            f"[{transport}] expected PASS verdict for non-matching SNI, "
            f"got actions={actions}"
        )
        assert "DROP" not in actions, (
            f"[{transport}] unexpected DROP verdict for non-matching SNI: "
            f"actions={actions}"
        )


# ============================================================================
# Ingress XDP — narrow coverage: TC and XDP share most of the QUIC
# userspace path; this test exists to catch divergence in the BPF
# pre-check / tail-call slot, not to re-test the userspace logic.
# ============================================================================


class TestMatchIngressQuic:
    def test_quic_v1_ingress_writes_verdict(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        quic_sender_ingress,
        server_ip_v4,
    ):
        sni = "ingress.quictest.example"
        rule_id = 910_020
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="ingress",
        )
        assert result.success, f"add_rule failed: {result.message}"

        before = policy_client.get_flow_verdicts(direction="ingress").active_verdicts
        quic_sender_ingress(str(server_ip_v4), _DPORT, sni, version="v1")
        after = _wait_for_verdict_growth(policy_client, "ingress", before)

        assert after > before, (
            "QUIC v1 ingress did not produce a verdict — the XDP pre-check / "
            "tail-call slot may be wrong."
        )
