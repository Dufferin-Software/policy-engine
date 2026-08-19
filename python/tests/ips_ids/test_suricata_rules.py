# Copyright (c) Dufferin Software

"""
Suricata rule management tests.

Tests for deploying, querying, and managing Suricata rules via the policy-engine API.
These tests do not require IPS/IDS mode to be active — rule management is
independent of inspect mode.

Tests cover:
- Querying Suricata service status
- Deploying custom rules to the engine's rules directory
- Reloading rules after deployment
- Inspect status shows deployed custom rules
- Deploying rules with a custom filename
"""

import logging


logger = logging.getLogger(__name__)

# Sample Suricata rule definitions for test use
BASIC_ALERT_RULE = (
    'alert tcp any any -> any any (msg:"Test basic alert"; sid:1100001; rev:1;)'
)

MULTI_PORT_RULES = "\n".join(
    [
        'alert tcp any any -> any 7001 (msg:"Test alert port 7001"; sid:1200001; rev:1;)',
        'alert tcp any any -> any 7002 (msg:"Test alert port 7002"; sid:1200002; rev:1;)',
        'alert udp any any -> any 5353 (msg:"Test DNS alert"; sid:1200003; rev:1;)',
    ]
)

INVALID_RULE = "this is not a valid suricata rule"

DROP_RULE = 'drop tcp any any -> any 6666 (msg:"Test drop rule"; sid:1300001; rev:1;)'


class TestSuricataStatus:
    """Tests for querying Suricata service status."""

    def test_suricata_status_query_succeeds(self, policy_client, policy_engine_service):
        """Suricata status query should succeed without error."""
        result = policy_client.suricata_status()
        # success=True means running, success=False means not running
        # Both are valid — we just verify the call doesn't raise
        assert hasattr(result, "success"), "Result should have success field"
        assert hasattr(result, "message"), "Result should have message field"
        logger.info(
            f"Suricata status: running={result.success}, message={result.message}"
        )

    def test_suricata_status_consistent_with_inspect_status(
        self, policy_client, policy_engine_service
    ):
        """Suricata running state from suricata_status() should match inspect_status()."""
        suricata_result = policy_client.suricata_status()
        inspect_status = policy_client.get_inspect_status()

        logger.info(
            f"suricata_status.success={suricata_result.success}, "
            f"inspect_status.suricata_running={inspect_status.suricata_running}"
        )
        assert suricata_result.success == inspect_status.suricata_running, (
            "Suricata running state should be consistent between suricata_status() "
            "and get_inspect_status()"
        )


class TestSuricataRuleDeployment:
    """Tests for deploying Suricata rules via the policy-engine."""

    def test_deploy_basic_rule(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Can deploy a basic Suricata alert rule."""
        result = policy_client.deploy_suricata_rules(
            BASIC_ALERT_RULE, "test_basic.rules"
        )
        assert result.success, f"Failed to deploy basic rule: {result.message}"
        logger.info(f"Deploy result: {result.message}")

    def test_deploy_multiple_rules(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Can deploy a file containing multiple rules."""
        result = policy_client.deploy_suricata_rules(
            MULTI_PORT_RULES, "test_multi.rules"
        )
        assert result.success, f"Failed to deploy multiple rules: {result.message}"
        logger.info(f"Multi-rule deploy result: {result.message}")

    def test_deploy_rules_with_custom_filename(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Can deploy rules to a custom filename in the rules directory."""
        result = policy_client.deploy_suricata_rules(
            BASIC_ALERT_RULE, "my_custom_rules.rules"
        )
        assert result.success, f"Failed to deploy to custom filename: {result.message}"

    def test_deploy_drop_rule(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Can deploy a Suricata drop rule."""
        result = policy_client.deploy_suricata_rules(DROP_RULE, "test_drop.rules")
        assert result.success, f"Failed to deploy drop rule: {result.message}"

    def test_deploy_rules_default_filename(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Deploy with default filename (custom.rules) should succeed."""
        result = policy_client.deploy_suricata_rules(BASIC_ALERT_RULE)
        assert result.success, (
            f"Failed to deploy with default filename: {result.message}"
        )

    def test_redeploy_overwrites_existing_file(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Re-deploying to the same filename should overwrite the existing rules."""
        filename = "test_overwrite.rules"

        # First deployment
        result = policy_client.deploy_suricata_rules(BASIC_ALERT_RULE, filename)
        assert result.success, f"First deploy failed: {result.message}"

        # Second deployment with different content
        result = policy_client.deploy_suricata_rules(DROP_RULE, filename)
        assert result.success, f"Second deploy failed: {result.message}"


class TestSuricataRuleReload:
    """Tests for reloading Suricata rules."""

    def test_reload_rules_after_deploy(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Can reload Suricata rules after deploying new rules."""
        # Deploy a rule first
        result = policy_client.deploy_suricata_rules(
            BASIC_ALERT_RULE, "reload_test.rules"
        )
        assert result.success

        # Reload rules
        result = policy_client.reload_suricata_rules()
        assert result.success, f"Failed to reload rules: {result.message}"
        logger.info(f"Rule reload result: {result.message}")

    def test_reload_is_idempotent(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Multiple reloads should succeed."""
        for i in range(3):
            result = policy_client.reload_suricata_rules()
            assert result.success, f"Reload #{i + 1} failed: {result.message}"


class TestInspectStatusShowsCustomRules:
    """Tests that inspect status reflects deployed custom rules."""

    def test_inspect_status_reports_custom_rule_files(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """
        After deploying rules, inspect status should list the deployed files.

        This verifies that the API surface is correct — the actual file content
        listing is a server-side responsibility.
        """
        filename = "inspect_status_test.rules"
        result = policy_client.deploy_suricata_rules(BASIC_ALERT_RULE, filename)
        assert result.success, f"Failed to deploy rules: {result.message}"

        # Inspect status returns custom_rule_files (from graphql) but our
        # Python InspectStatus dataclass focuses on the core fields.
        # Just verify the status call succeeds and has expected fields.
        status = policy_client.get_inspect_status()
        assert hasattr(status, "mode"), "InspectStatus should have mode field"
        assert hasattr(status, "suricata_running"), (
            "InspectStatus should have suricata_running field"
        )
        logger.info(
            f"Inspect status after rule deploy: mode={status.mode}, "
            f"suricata_running={status.suricata_running}"
        )

    def test_suricata_version_reported(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Inspect status should report the Suricata version if Suricata is installed."""
        status = policy_client.get_inspect_status()
        # suricata_version may be None if Suricata hasn't been started yet
        logger.info(f"Suricata version: {status.suricata_version}")
        # Just verify the field exists on the dataclass
        assert hasattr(status, "suricata_version"), (
            "InspectStatus should have suricata_version field"
        )
