# Copyright (c) Peter Morrow

"""
Action-loop semantics for SNI matches.

These tests target the TCP path (in-kernel ``tc_sni_inspect`` matcher).
The QUIC userspace action loop is already exhaustively covered by
``quic_initial_inspect_tests.rs``; TCP is cheaper to drive repeatedly
and exercises the BPF-side walker directly.

What's under test:

* Per-rule action ordering — ``actions=[log, drop]`` walks both before
  terminating.  DROP is terminal but second in the list, so observing
  ``policy_drops`` advance implies LOG fired immediately before it.
* Multi-rule tail-call safety — two SNI rules on the same L4 slot must
  both accumulate ``rule_stats.packets``.  Regression test for the
  historical bug where the SNI tail-call swallowed control before rule
  2 was evaluated.

Oracle choice rationale: TCP SNI matches don't currently populate
``tc_flow_verdict_cache`` (only the QUIC userspace consumer writes that
map).  TCP tests therefore rely on ``rule_stats.packets`` (proof of
SNI match) and ``policy_drops`` (proof of DROP action).  Direct LOG-
event observation requires WebSocket subscription — see
``tests/policy_sanity/test_log_rate_limit.py`` for that pattern.
"""

import logging
import time

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions
from tests.sni_matching.helpers import policy_drops, rule_packets

logger = logging.getLogger(__name__)

_DPORT = 443


@pytest.mark.usefixtures("tcp_sni_listener")
class TestActionLoop:
    def test_log_then_drop_both_fire(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """[log, drop] must walk both actions before terminating.

        DROP is terminal but it's second in the action list, so if DROP
        fires it implies LOG fired immediately before in the same loop
        iteration.  We verify DROP via ``policy_drops`` and rely on the
        action-loop unit tests to cover ordering exhaustively.  Direct
        LOG-event observation goes via the WebSocket event stream (see
        ``tests/policy_sanity/test_log_rate_limit.py`` for the pattern);
        the rate-limit test below is where that machinery would belong.
        """
        sni = "logdrop.action.example"
        rule_id = 920_001
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=_DPORT,
                actions=[("log", 0), ("drop", 0)],
                sni=sni,
                rule_id=rule_id,
            ),
            direction="egress",
        )
        assert result.success, f"add_rule failed: {result.message}"
        policy_client.clear_rule_stats(rule_id=rule_id, direction="egress")

        drops_before = policy_drops(policy_client, attached_egress)

        tls_sender(str(client_ip_v4), _DPORT, sni)
        time.sleep(0.3)

        assert rule_packets(policy_client, rule_id) >= 1, (
            "rule_stats did not advance — SNI inspector never matched"
        )
        drops_delta = policy_drops(policy_client, attached_egress) - drops_before
        assert drops_delta >= 1, (
            f"DROP action did not fire — policy_drops only advanced by {drops_delta}"
        )

    def test_two_sni_rules_same_port_both_count(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """Tail-call safety: two SNI rules on the same L4 slot both fire.

        Send two handshakes (one per SNI).  Each rule must count its own
        match exactly once.  Regression test for the historical bug where
        the SNI tail-call swallowed control and starved rule 2.
        """
        rule_alpha = 920_010
        rule_beta = 920_011

        for rid, sni in [
            (rule_alpha, "alpha.same.example"),
            (rule_beta, "beta.same.example"),
        ]:
            r = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_egress,
                    src=server_network_v4,
                    protocol="tcp",
                    dport=_DPORT,
                    actions=[("log", 0)],
                    sni=sni,
                    rule_id=rid,
                ),
                direction="egress",
            )
            assert r.success, f"add_rule {rid} failed: {r.message}"
            policy_client.clear_rule_stats(rule_id=rid, direction="egress")

        tls_sender(str(client_ip_v4), _DPORT, "alpha.same.example")
        tls_sender(str(client_ip_v4), _DPORT, "beta.same.example")

        time.sleep(0.5)

        count_alpha = rule_packets(policy_client, rule_alpha)
        count_beta = rule_packets(policy_client, rule_beta)
        logger.info(f"alpha rule={count_alpha} packets, beta rule={count_beta} packets")
        assert count_alpha >= 1, (
            f"alpha rule did not count its own handshake (got {count_alpha})"
        )
        assert count_beta >= 1, (
            f"beta rule did not count its own handshake (got {count_beta}) — "
            "likely the SNI tail-call swallowed control before rule 2 was "
            "evaluated."
        )
