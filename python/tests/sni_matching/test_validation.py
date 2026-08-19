# Copyright (c) Dufferin Software

"""
SNI rule validation — no traffic.

Confirms the policy-engine API accepts SNI on TCP and UDP and rejects it
on protocols that have no SNI semantics (ICMP, `any`).  The traffic tests
in `test_match.py` cover real-handshake behaviour.
"""

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions


_DPORT = 443


class TestSniRuleValidation:
    @pytest.mark.parametrize("protocol", ["tcp", "udp"])
    @pytest.mark.parametrize("sni", ["example.com", "*.example.com"])
    def test_sni_accepted_on_tls_protocols(
        self, policy_client, attached_egress, clean_egress_rules, protocol, sni
    ):
        """SNI is accepted on every protocol the policy-engine actually inspects."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                protocol=protocol,
                dport=_DPORT,
                actions=[("drop", 0)],
                sni=sni,
            ),
            direction="egress",
        )
        assert result.success, (
            f"{protocol} rule with sni={sni!r} should succeed: {result.message}"
        )

    @pytest.mark.parametrize(
        "protocol,kwargs",
        [
            ("icmp", {}),
            ("any", {"dport": _DPORT}),
        ],
    )
    def test_sni_rejected_on_non_tls_protocols(
        self, policy_client, attached_egress, clean_egress_rules, protocol, kwargs
    ):
        """SNI must be rejected where there's no handshake to parse."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                protocol=protocol,
                actions=[("drop", 0)],
                sni="example.com",
                **kwargs,
            ),
            direction="egress",
        )
        assert not result.success, (
            f"{protocol} rule with SNI should be rejected, got success"
        )
        msg = result.message.lower()
        assert "tcp" in msg or "udp" in msg or "sni" in msg, (
            f"Error should mention TCP/UDP/SNI requirement: {result.message}"
        )

    def test_sni_rule_listed_after_creation(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Rule list round-trip preserves the SNI pattern verbatim."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                protocol="tcp",
                dport=_DPORT,
                actions=[("drop", 0)],
                sni="listed.example.com",
            ),
            direction="egress",
        )
        assert result.success, f"add_rule failed: {result.message}"

        rules = policy_client.list_rules(direction="egress")
        match = next(
            (r for r in rules if getattr(r, "sni", None) == "listed.example.com"),
            None,
        )
        assert match is not None, (
            f"Installed SNI rule not found in list: "
            f"{[getattr(r, 'sni', None) for r in rules]}"
        )
