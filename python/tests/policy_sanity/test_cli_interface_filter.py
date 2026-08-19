# Copyright (c) Dufferin Software

"""
Tests for the --interface filter on rule list, flush, and managed-rules commands.

These commands were extended to accept an optional --interface argument so that
operators can scope their queries and mutations to a single interface without
affecting rules on other interfaces. The tests verify:

  - rule list --interface returns only rules for the requested interface
  - rule flush --interface removes only rules on that interface
  - rule managed-rules --interface filters TTL/scheduled rules by interface
"""

import logging


from policy_engine_client.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)


class TestListInterfaceFilter:
    """rule list --interface returns the correct subset of rules."""

    def test_list_ingress_filters_by_interface(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """Listing with --interface returns only rules for that interface."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="10.1.0.0/16",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=60001,
            ),
            direction="ingress",
        )
        assert result.success, f"Add failed: {result.message}"

        filtered = policy_client.list_rules(
            direction="ingress", interface=attached_ingress
        )
        assert len(filtered) == 1, (
            f"Expected 1 rule for {attached_ingress}, got {len(filtered)}"
        )
        assert filtered[0].interface == attached_ingress

    def test_list_ingress_unknown_interface_returns_empty(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """Listing with a non-existent interface name returns an empty list."""
        policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="10.2.0.0/16",
                protocol="any",
                actions=[("drop", 0)],
            ),
            direction="ingress",
        )

        result = policy_client.list_rules(
            direction="ingress", interface="does-not-exist"
        )
        assert result == [], "Should return empty list for unknown interface"

    def test_list_egress_filters_by_interface(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Listing with --interface returns only egress rules for that interface."""
        policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src="192.168.1.0/24",
                protocol="tcp",
                dport=443,
                actions=[("pass", 0)],
                rule_id=60002,
            ),
            direction="egress",
        )

        filtered = policy_client.list_rules(
            direction="egress", interface=attached_egress
        )
        assert any(r.rule_id == 60002 for r in filtered), (
            "Rule 60002 should appear in filtered list"
        )
        for rule in filtered:
            assert rule.interface == attached_egress, (
                f"Unexpected interface {rule.interface!r} in filtered list"
            )

    def test_list_without_interface_returns_all(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """Calling list_rules without --interface returns all rules (unfiltered)."""
        for i in range(3):
            policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=f"10.{i + 10}.0.0/16",
                    protocol="any",
                    actions=[("pass", 0)],
                ),
                direction="ingress",
            )

        all_rules = policy_client.list_rules(direction="ingress")
        assert len(all_rules) == 3


class TestFlushInterfaceFilter:
    """rule flush --interface removes only rules on the specified interface."""

    def test_flush_ingress_scoped_to_interface(
        self,
        policy_client,
        server_interface,
        configure_node_interfaces,
    ):
        """Flushing with --interface only removes that interface's rules."""
        iface = server_interface.if_name

        policy_client.attach_ingress(iface)
        policy_client.attach_egress(iface)

        try:
            # Add rules on the primary interface (ingress)
            for i in range(3):
                policy_client.add_rule(
                    AddRuleOptions(
                        interface=iface,
                        src=f"10.{i}.0.0/16",
                        protocol="any",
                        actions=[("drop", 0)],
                    ),
                    direction="ingress",
                )

            rules_before = policy_client.list_rules(direction="ingress")
            assert len(rules_before) == 3, "Should have 3 ingress rules before flush"

            # Flush only the primary interface's rules
            result = policy_client.flush_rules(direction="ingress", interface=iface)
            assert result.success, f"Interface-scoped flush failed: {result.message}"

            rules_after = policy_client.list_rules(direction="ingress")
            assert len(rules_after) == 0, (
                f"All rules for {iface} should be gone, got {len(rules_after)}"
            )

        finally:
            policy_client.flush_rules(direction="ingress")
            policy_client.flush_rules(direction="egress")
            policy_client.detach_all()

    def test_flush_interface_leaves_other_direction_intact(
        self,
        policy_client,
        server_interface,
        configure_node_interfaces,
    ):
        """Flushing ingress rules for an interface does not affect egress rules."""
        iface = server_interface.if_name

        policy_client.attach_ingress(iface)
        policy_client.attach_egress(iface)

        try:
            policy_client.add_rule(
                AddRuleOptions(
                    interface=iface,
                    src="10.0.0.0/8",
                    protocol="any",
                    actions=[("drop", 0)],
                    rule_id=61001,
                ),
                direction="ingress",
            )
            policy_client.add_rule(
                AddRuleOptions(
                    interface=iface,
                    src="192.168.0.0/16",
                    protocol="any",
                    actions=[("drop", 0)],
                    rule_id=61002,
                ),
                direction="egress",
            )

            # Flush ingress for the interface only
            result = policy_client.flush_rules(direction="ingress", interface=iface)
            assert result.success, f"Flush failed: {result.message}"

            ingress_after = policy_client.list_rules(direction="ingress")
            egress_after = policy_client.list_rules(direction="egress")

            assert len(ingress_after) == 0, "Ingress rules should be gone"
            assert any(r.rule_id == 61002 for r in egress_after), (
                "Egress rule should be untouched after ingress flush"
            )

        finally:
            policy_client.flush_rules(direction="ingress")
            policy_client.flush_rules(direction="egress")
            policy_client.detach_all()

    def test_flush_unknown_interface_is_noop(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """Flushing rules for a non-existent interface does not remove any rules."""
        policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="10.0.0.0/8",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=61100,
            ),
            direction="ingress",
        )

        result = policy_client.flush_rules(
            direction="ingress", interface="does-not-exist"
        )
        assert result.success, (
            f"Flush with unknown interface should succeed: {result.message}"
        )

        remaining = policy_client.list_rules(direction="ingress")
        assert any(r.rule_id == 61100 for r in remaining), (
            "Rule should survive flush targeting a different interface"
        )


class TestManagedRulesInterfaceFilter:
    """rule managed-rules --interface filters TTL/scheduled rules by interface."""

    def test_managed_rules_ingress_filtered_by_interface(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """managed_rules with --interface returns only TTL rules on that interface."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="10.0.0.0/8",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=62001,
                expires_after_secs=3600,
            ),
            direction="ingress",
        )
        assert result.success, f"Add TTL rule failed: {result.message}"

        filtered = policy_client.managed_rules(
            direction="ingress", interface=attached_ingress
        )
        assert any(r.rule_id == 62001 for r in filtered), (
            "TTL rule should appear in filtered managed-rules list"
        )
        for rule in filtered:
            assert rule.interface == attached_ingress, (
                f"Unexpected interface {rule.interface!r} in filtered managed-rules"
            )

    def test_managed_rules_unknown_interface_returns_empty(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """managed_rules with a non-existent interface returns an empty list."""
        policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src="10.0.0.0/8",
                protocol="any",
                actions=[("drop", 0)],
                expires_after_secs=3600,
            ),
            direction="ingress",
        )

        result = policy_client.managed_rules(
            direction="ingress", interface="does-not-exist"
        )
        assert result == [], "Should return empty list for unknown interface"

    def test_managed_rules_without_interface_returns_all(
        self, policy_client, attached_ingress, clean_ingress_rules
    ):
        """managed_rules without --interface returns all managed rules."""
        for i in range(2):
            policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=f"10.{i}.0.0/16",
                    protocol="any",
                    actions=[("drop", 0)],
                    expires_after_secs=3600,
                ),
                direction="ingress",
            )

        all_managed = policy_client.managed_rules(direction="ingress")
        assert len(all_managed) >= 2, (
            f"Expected at least 2 managed rules, got {len(all_managed)}"
        )

    def test_managed_rules_egress_filtered(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Egress TTL rules are filtered correctly by interface."""
        result = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_egress,
                src="192.168.0.0/16",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=62002,
                expires_after_secs=3600,
            ),
            direction="egress",
        )
        assert result.success, f"Add egress TTL rule failed: {result.message}"

        filtered = policy_client.managed_rules(
            direction="egress", interface=attached_egress
        )
        assert any(r.rule_id == 62002 for r in filtered), (
            "Egress TTL rule should appear in interface-filtered managed-rules"
        )
