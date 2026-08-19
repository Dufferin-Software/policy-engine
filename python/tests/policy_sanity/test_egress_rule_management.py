import logging

from policy_engine_client.engine.cli.client import (
    AddRuleOptions,
    IngressMode,
    PolicyAction,
)

logger = logging.getLogger(__name__)


class TestEgressRuleManagement:
    """Tests for egress rule addition, deletion, and listing."""

    def test_add_egress_rule_basic_ipv4(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Test adding a basic IPv4 egress rule."""
        options = AddRuleOptions(
            interface=attached_egress,
            src="10.0.0.0/8",
            dst="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add egress rule: {result.message}"

        # Verify rule was added to egress
        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1, "Should have 1 egress rule"
        assert rules[0].src_prefix == "10.0.0.0/8"
        assert rules[0].actions[0].action == PolicyAction.DROP

    def test_add_egress_rule_basic_ipv6(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Test adding a basic IPv6 egress rule."""
        options = AddRuleOptions(
            interface=attached_egress,
            src="2001:db8::/32",
            dst="::/0",
            protocol="any",
            actions=[("drop", 0)],
        )
        result = policy_client.add_rule(options, direction="egress")
        assert result.success, f"Failed to add IPv6 egress rule: {result.message}"

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1, "Should have 1 egress rule"
        assert "2001:db8::" in rules[0].src_prefix.lower()

    def test_delete_egress_rule_by_id(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Test deleting an egress rule by ID."""
        options = AddRuleOptions(
            interface=attached_egress,
            src="10.0.0.0/8",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=88888,
        )
        policy_client.add_rule(options, direction="egress")

        # Verify it exists
        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 1
        assert rules[0].rule_id == 88888

        # Delete by ID
        result = policy_client.delete_rule(
            attached_egress, rule_id=88888, direction="egress"
        )
        assert result.success, f"Failed to delete egress rule: {result.message}"

        # Verify deletion
        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 0, "Egress rule should be deleted"

    def test_flush_egress_rules(
        self, policy_client, attached_egress, clean_egress_rules
    ):
        """Test flushing all egress rules."""
        for i in range(3):
            policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_egress,
                    src=f"10.{i}.0.0/16",
                    protocol="any",
                    actions=[("pass", 0)],
                ),
                direction="egress",
            )

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 3

        result = policy_client.flush_rules(direction="egress")
        assert result.success, f"Failed to flush egress rules: {result.message}"

        rules = policy_client.list_rules(direction="egress")
        assert len(rules) == 0, "All egress rules should be flushed"

    def test_egress_rules_independent_of_ingress(
        self,
        policy_client,
        server_interface,
        configure_node_interfaces,
    ):
        """Test that egress and ingress rules are independent."""
        iface_name = server_interface.if_name

        policy_client.attach_ingress(iface_name, IngressMode.AUTO)
        policy_client.attach_egress(iface_name)

        try:
            # Add ingress rule
            policy_client.add_rule(
                AddRuleOptions(
                    interface=iface_name,
                    src="10.0.0.0/8",
                    protocol="any",
                    actions=[("drop", 0)],
                    rule_id=55001,
                ),
                direction="ingress",
            )

            # Add egress rule
            policy_client.add_rule(
                AddRuleOptions(
                    interface=iface_name,
                    src="192.168.0.0/16",
                    protocol="any",
                    actions=[("pass", 0)],
                    rule_id=55002,
                ),
                direction="egress",
            )

            # Verify rules are in their respective directions
            ingress_rules = policy_client.list_rules(direction="ingress")
            egress_rules = policy_client.list_rules(direction="egress")

            ingress_ids = {r.rule_id for r in ingress_rules}
            egress_ids = {r.rule_id for r in egress_rules}

            assert 55001 in ingress_ids, "Ingress rule should be in ingress list"
            assert 55002 in egress_ids, "Egress rule should be in egress list"
            assert 55001 not in egress_ids, "Ingress rule should NOT be in egress list"
            assert 55002 not in ingress_ids, "Egress rule should NOT be in ingress list"
        finally:
            policy_client.flush_rules(direction="ingress")
            policy_client.flush_rules(direction="egress")
            policy_client.detach_all()
