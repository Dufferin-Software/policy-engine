import logging

from policy_engine_client.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)

# Substring of the engine's rejection message:
# "A rule with identical match criteria already exists (rule N) on this
#  interface/direction"
_DUP_MSG = "identical match criteria"


class TestDuplicateRules:
    """The engine must reject a second rule whose match criteria (everything
    except the id, actions, and lifecycle) duplicate an already-installed rule
    on the same interface/direction."""

    def test_add_duplicate_ingress_rule_rejected(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """Adding the same ingress rule twice must fail on the second add."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            dst="0.0.0.0/0",
            dport=80,
            protocol="tcp",
            actions=[("drop", 0)],
        )

        first = policy_client.add_rule(options, direction="ingress")
        assert first.success, f"First add should succeed: {first.message}"

        # Same match criteria (a different action is irrelevant to the match) —
        # must be rejected by the API.
        dup_options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            dst="0.0.0.0/0",
            dport=80,
            protocol="tcp",
            actions=[("pass", 0)],
        )
        second = policy_client.add_rule(dup_options, direction="ingress")
        assert not second.success, (
            f"Duplicate rule should be rejected, got success: {second.message}"
        )
        assert _DUP_MSG in second.message, (
            f"Expected '{_DUP_MSG}' in error, got: {second.message}"
        )

        # Only the first rule should be installed.
        rules = policy_client.list_rules(direction="ingress")
        assert len(rules) == 1, f"Expected exactly 1 rule, got {len(rules)}"

    def test_add_duplicate_egress_rule_rejected(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """The same rejection applies to egress rules."""
        options = AddRuleOptions(
            interface=attached_egress,
            src="192.168.0.0/16",
            protocol="any",
            actions=[("drop", 0)],
        )
        first = policy_client.add_rule(options, direction="egress")
        assert first.success, f"First egress add should succeed: {first.message}"

        second = policy_client.add_rule(options, direction="egress")
        assert not second.success, (
            f"Duplicate egress rule should be rejected: {second.message}"
        )
        assert _DUP_MSG in second.message, (
            f"Expected '{_DUP_MSG}' in error, got: {second.message}"
        )

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1, f"Expected exactly 1 egress rule, got {len(rules)}"

    def test_add_rule_differing_criteria_allowed(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """A rule that differs in any match field (here: dport) is NOT a
        duplicate and must be accepted."""
        base = dict(
            interface=attached_ingress,
            src="10.0.0.0/8",
            dst="0.0.0.0/0",
            protocol="tcp",
            actions=[("drop", 0)],
        )

        r1 = policy_client.add_rule(
            AddRuleOptions(dport=80, **base), direction="ingress"
        )
        assert r1.success, f"First add should succeed: {r1.message}"

        # Different destination port → distinct match criteria → allowed.
        r2 = policy_client.add_rule(
            AddRuleOptions(dport=443, **base), direction="ingress"
        )
        assert r2.success, f"Differing rule should be accepted: {r2.message}"

        rules = policy_client.list_rules(direction="ingress")
        assert len(rules) == 2, f"Expected 2 rules, got {len(rules)}"
