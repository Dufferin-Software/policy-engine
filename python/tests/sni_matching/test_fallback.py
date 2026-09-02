# Copyright (c) Peter Morrow

"""
HTTP/3 ↔ TCP fallback story (real-world deployment footgun).

Browsers race QUIC and TCP on every navigation; blocking one transport
typically does not block the site because the browser silently falls
back to the other within a few hundred ms.  ``docs/sni-matching.md``
calls this out as a limitation — the configuration guidance is to
install rules on *both* transports for the same SNI.

We can't run a browser inside netsim, but we can verify the underlying
invariant the guidance relies on:

* A rule on TCP only does not block UDP traffic to the same SNI.
* A rule on UDP only does not block TCP traffic to the same SNI.
* A rule on both transports blocks both.

Oracle:
* TCP DROP rule firing  → ``global_stats.policy_drops`` advances.
* TCP DROP rule NOT firing → ``policy_drops`` flat.
* UDP DROP rule firing  → verdict cache contains a DROP entry for udp.
* UDP DROP rule NOT firing → verdict cache contains no DROP for udp.

The two oracles differ because the TCP path matches in BPF (drops at
``TC_ACT_SHOT``) but doesn't populate the verdict cache yet, while the
QUIC userspace consumer writes the verdict cache directly.
"""

import logging

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from tests.sni_matching.helpers import policy_drops, wait_verdicts

logger = logging.getLogger(__name__)

_DPORT = 443


def _udp_actions(graphql_client: GraphQLPolicyClient):
    query = """
    query VerdictList { flowVerdictList(direction: EGRESS) {
        protocol action expired
    } }
    """
    data = graphql_client._execute_graphql(query, {})
    if "__error__" in data:
        pytest.fail(f"flowVerdictList query failed: {data['__error__']}")
    return [
        v.get("action", "").upper()
        for v in data.get("flowVerdictList", [])
        if not v.get("expired") and v.get("protocol", "").lower() == "udp"
    ]


@pytest.mark.usefixtures("tcp_sni_listener")
class TestTransportFallback:
    """Rules on one transport must not affect the other."""

    @pytest.fixture
    def graphql_only(self, client_type):
        if client_type != "graphql":
            pytest.skip("verdict-action assertion requires GraphQL")

    def _drive_both(self, tls_sender, quic_sender, client_ip_v4, sni: str) -> None:
        tls_sender(str(client_ip_v4), _DPORT, sni)
        quic_sender(str(client_ip_v4), _DPORT, sni, version="v1")

    def test_tcp_only_rule_does_not_affect_quic(
        self,
        graphql_only,
        policy_client,
        graphql_policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        sni = "fallback-tcp-only.example"
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="tcp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=950_001,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        drops_before = policy_drops(policy_client, attached_egress)
        verdicts_before = policy_client.get_flow_verdicts(
            direction="egress"
        ).active_verdicts

        self._drive_both(tls_sender, quic_sender, client_ip_v4, sni)
        wait_verdicts(policy_client, verdicts_before, want=1)

        drops_delta = policy_drops(policy_client, attached_egress) - drops_before
        udp_actions = _udp_actions(graphql_policy_client)
        logger.info(f"tcp-only rule: drops_delta={drops_delta} udp={udp_actions}")

        assert drops_delta >= 1, (
            f"TCP rule should drop the TLS CH; policy_drops only advanced "
            f"by {drops_delta}"
        )
        # No UDP rule for this SNI → QUIC userspace finds nothing to match
        # and writes a PASS verdict.  Either way, no DROP on UDP.
        assert "DROP" not in udp_actions, (
            f"TCP-only rule must not affect QUIC traffic; udp_actions={udp_actions}"
        )

    def test_udp_only_rule_does_not_affect_tcp(
        self,
        graphql_only,
        policy_client,
        graphql_policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        sni = "fallback-udp-only.example"
        r = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src=server_network_v4,
                protocol="udp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
                rule_id=950_002,
            ),
            direction="egress",
        )
        assert r.success, f"add_rule failed: {r.message}"

        drops_before = policy_drops(policy_client, attached_egress)
        verdicts_before = policy_client.get_flow_verdicts(
            direction="egress"
        ).active_verdicts

        self._drive_both(tls_sender, quic_sender, client_ip_v4, sni)
        wait_verdicts(policy_client, verdicts_before, want=1)

        drops_delta = policy_drops(policy_client, attached_egress) - drops_before
        udp_actions = _udp_actions(graphql_policy_client)
        logger.info(f"udp-only rule: drops_delta={drops_delta} udp={udp_actions}")

        assert "DROP" in udp_actions, (
            f"UDP rule should DROP its own traffic; udp_actions={udp_actions}"
        )
        # The TCP handshake produces a brief data segment that the L4
        # dispatcher will pass (no matching rule) — policy_drops should
        # not grow on the TCP side.  Allow ±1 slack for any stray packets.
        assert drops_delta <= 1, (
            f"UDP-only rule must not affect TCP traffic; "
            f"policy_drops grew by {drops_delta}"
        )

    def test_both_rules_block_both_transports(
        self,
        graphql_only,
        policy_client,
        graphql_policy_client,
        attached_egress,
        clean_egress_rules,
        tls_sender,
        quic_sender,
        client_ip_v4,
        server_network_v4,
    ):
        """The configuration the docs prescribe: rule on both transports."""
        sni = "fallback-both.example"
        for proto, rid in [("tcp", 950_010), ("udp", 950_011)]:
            r = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_egress,
                    src=server_network_v4,
                    protocol=proto,
                    dport=_DPORT,
                    actions=[("drop", 0)],
                    sni=sni,
                    rule_id=rid,
                ),
                direction="egress",
            )
            assert r.success, f"add_rule {proto} failed: {r.message}"

        drops_before = policy_drops(policy_client, attached_egress)
        verdicts_before = policy_client.get_flow_verdicts(
            direction="egress"
        ).active_verdicts

        self._drive_both(tls_sender, quic_sender, client_ip_v4, sni)
        wait_verdicts(policy_client, verdicts_before, want=1)

        drops_delta = policy_drops(policy_client, attached_egress) - drops_before
        udp_actions = _udp_actions(graphql_policy_client)
        logger.info(f"both rules: drops_delta={drops_delta} udp={udp_actions}")

        assert drops_delta >= 1, (
            f"TCP traffic should be dropped; policy_drops only advanced "
            f"by {drops_delta}"
        )
        assert "DROP" in udp_actions, (
            f"UDP traffic should be dropped; udp_actions={udp_actions}"
        )
