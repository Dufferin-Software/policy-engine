import logging

from policy_engine_client.engine.cli.client import PolicyAction

logger = logging.getLogger(__name__)


class TestEgressDefaultAction:
    """Tests for egress default action configuration."""

    def test_set_egress_default_action_drop(
        self,
        nodes,
        policy_client,
        attached_egress,
        clean_egress_rules,
        client_interface,
        server_ip_v4,
        nmap_installed,
    ):
        """Test setting egress default action to drop."""
        result = policy_client.set_default_action(
            PolicyAction.DROP, direction="egress", interface=attached_egress
        )
        try:
            assert result.success, (
                f"Failed to set egress default action: {result.message}"
            )
        finally:
            policy_client.set_default_action(
                PolicyAction.PASS, direction="egress", interface=attached_egress
            )

    def test_set_egress_default_action_pass(
        self,
        policy_client,
        attached_egress,
        clean_egress_rules,
    ):
        """Test setting egress default action to pass."""
        result = policy_client.set_default_action(
            PolicyAction.PASS, direction="egress", interface=attached_egress
        )
        assert result.success, f"Failed to set egress default action: {result.message}"
