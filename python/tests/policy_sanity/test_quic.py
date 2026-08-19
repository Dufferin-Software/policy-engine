# Copyright (c) Dufferin Software

"""
QUIC rule management tests for policy-engine.

Tests:
- QUIC rule creation succeeds with UDP or 'any' protocol
- QUIC rule creation is rejected with TCP/ICMP protocols
- Listed rules include quic_version field
- Plain UDP rules without QUIC filter have no quic_version
"""

import logging

from policy_engine_client.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)


class TestQuicRuleValidation:
    """Tests that QUIC rules are accepted/rejected based on protocol."""

    def test_add_quic_rule_udp_succeeds(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Adding a QUIC rule with UDP protocol should succeed."""
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="udp",
            dport=443,
            actions=[("drop", 0)],
            quic_version="v1",
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"UDP rule with QUIC v1 should succeed: {result.message}"

    def test_add_quic_rule_any_protocol_succeeds(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Adding a QUIC rule with 'any' protocol should succeed."""
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="any",
            dport=443,
            actions=[("drop", 0)],
            quic_version="any",
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, (
            f"any-protocol rule with QUIC 'any' should succeed: {result.message}"
        )

    def test_add_quic_rule_tcp_fails(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Adding a QUIC rule with TCP protocol should be rejected."""
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="tcp",
            dport=443,
            actions=[("drop", 0)],
            quic_version="v1",
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert not result.success, "TCP rule with QUIC version should be rejected"

    def test_add_quic_rule_v2_egress_succeeds(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Adding a QUIC v2 rule on egress should succeed."""
        options = AddRuleOptions(
            interface=attached_egress,
            protocol="udp",
            dport=443,
            actions=[("drop", 0)],
            quic_version="v2",
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Egress QUIC v2 rule should succeed: {result.message}"

    def test_add_quic_v2_udp_ingress_succeeds(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Adding a QUIC v2 rule on ingress with UDP should succeed."""
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="udp",
            dport=443,
            actions=[("log", 0), ("pass", 1)],
            quic_version="v2",
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, (
            f"Ingress QUIC v2 UDP rule should succeed: {result.message}"
        )


class TestQuicRuleOutput:
    """Tests that QUIC rules are returned correctly in list output."""

    def test_list_rules_includes_quic_version(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Listed rules should include the quic_version field."""
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="udp",
            dport=443,
            actions=[("log", 0)],
            quic_version="v1",
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add QUIC rule: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        quic_rules = [r for r in rules if r.quic_version is not None]
        assert len(quic_rules) == 1, f"Expected 1 QUIC rule, got {len(quic_rules)}"
        assert quic_rules[0].quic_version == "v1", (
            f"Expected quic_version='v1', got '{quic_rules[0].quic_version}'"
        )

    def test_list_rules_no_quic_version_for_plain_rule(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Plain UDP rules without QUIC filter should have no quic_version."""
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="udp",
            dport=53,
            actions=[("pass", 0)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add plain UDP rule: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        assert all(r.quic_version is None for r in rules), (
            "Plain UDP rule should have no quic_version"
        )

    def test_quic_any_version_round_trips(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """A QUIC 'any' rule should be stored and returned as 'any'."""
        options = AddRuleOptions(
            interface=attached_ingress,
            protocol="udp",
            dport=443,
            actions=[("pass", 0)],
            quic_version="any",
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add QUIC 'any' rule: {result.message}"

        rules = policy_client.list_rules(direction="ingress")
        quic_rules = [r for r in rules if r.quic_version is not None]
        assert len(quic_rules) == 1
        assert quic_rules[0].quic_version == "any"

    def test_multiple_quic_rules_different_versions(
        self,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
    ):
        """Multiple QUIC rules with different versions should all be stored correctly."""
        for version in ("v1", "v2"):
            options = AddRuleOptions(
                interface=attached_ingress,
                protocol="udp",
                dport=443,
                actions=[("log", 0)],
                quic_version=version,
            )
            result = policy_client.add_rule(options, direction="ingress")
            assert result.success, (
                f"Failed to add QUIC {version} rule: {result.message}"
            )

        rules = policy_client.list_rules(direction="ingress")
        versions = {r.quic_version for r in rules if r.quic_version is not None}
        assert versions == {"v1", "v2"}, f"Expected {{v1, v2}}, got {versions}"
