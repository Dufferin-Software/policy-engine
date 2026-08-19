# Copyright (c) Dufferin Software

"""
Inspect/IPS mode configuration tests.

Tests the lifecycle of inspect mode (IPS/IDS):
- Default state is DISABLED
- Can enable IPS mode
- Can enable IDS mode
- Can disable and re-enable
- Server status reflects inspect mode
- Inspect status reports Suricata state and veth pair
"""

import logging


from netsim.testkit.base import BaseTopologyTests

logger = logging.getLogger(__name__)


class TestTopologyBase(BaseTopologyTests):
    """Inherit base topology sanity checks."""


class TestInspectModeDefault:
    """Tests for the default inspect mode state."""

    def test_inspect_status_default_disabled(
        self, policy_client, policy_engine_service
    ):
        """Inspect mode should be DISABLED on a freshly started policy-engine."""
        status = policy_client.get_inspect_status()
        assert status.mode == "DISABLED", (
            f"Expected DISABLED inspect mode, got {status.mode}"
        )
        logger.info(f"Default inspect mode: {status.mode}")

    def test_inspect_status_no_mirror_interface(
        self, policy_client, policy_engine_service
    ):
        """No mirror interface should exist when inspect mode is DISABLED."""
        status = policy_client.get_inspect_status()
        assert status.mirror_interface is None or status.mirror_interface == "", (
            f"Expected no mirror interface when disabled, got {status.mirror_interface}"
        )

    def test_server_features_suricata(
        self, policy_client, policy_engine_service, suricata_available
    ):
        """Server features should report suricata=True on an IPS/IDS server."""
        features = policy_client.server_features()
        assert features.suricata, (
            "serverFeatures.suricata should be True on an IPS/IDS server"
        )
        logger.info(f"Server features: suricata={features.suricata}")

    def test_flow_verdicts_empty_when_disabled(
        self, policy_client, policy_engine_service
    ):
        """Flow verdict count should be 0 when inspect is disabled."""
        stats = policy_client.get_flow_verdicts(direction="ingress")
        assert stats.active_verdicts == 0, (
            f"Expected 0 flow verdicts when disabled, got {stats.active_verdicts}"
        )


class TestInspectModeConfiguration:
    """Tests for enabling and disabling inspect modes."""

    def test_enable_ips_mode(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Can enable IPS mode successfully."""
        result = policy_client.configure_inspect("ips")
        assert result.success, f"Failed to enable IPS mode: {result.message}"
        logger.info(f"IPS enable result: {result.message}")

        status = policy_client.get_inspect_status()
        assert status.mode == "IPS", f"Expected IPS mode, got {status.mode}"

    def test_enable_ids_mode(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Can enable IDS mode successfully."""
        result = policy_client.configure_inspect("ids")
        assert result.success, f"Failed to enable IDS mode: {result.message}"
        logger.info(f"IDS enable result: {result.message}")

        status = policy_client.get_inspect_status()
        assert status.mode == "IDS", f"Expected IDS mode, got {status.mode}"

    def test_disable_inspect_from_ips(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Can disable inspect mode after enabling IPS."""
        # Enable IPS
        result = policy_client.configure_inspect("ips")
        assert result.success, f"Failed to enable IPS: {result.message}"

        # Disable
        result = policy_client.disable_inspect()
        assert result.success, f"Failed to disable inspect: {result.message}"

        status = policy_client.get_inspect_status()
        assert status.mode == "DISABLED", f"Expected DISABLED, got {status.mode}"

    def test_disable_inspect_from_ids(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Can disable inspect mode after enabling IDS."""
        result = policy_client.configure_inspect("ids")
        assert result.success, f"Failed to enable IDS: {result.message}"

        result = policy_client.disable_inspect()
        assert result.success, f"Failed to disable inspect: {result.message}"

        status = policy_client.get_inspect_status()
        assert status.mode == "DISABLED", f"Expected DISABLED, got {status.mode}"

    def test_switch_from_ips_to_ids(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Can switch from IPS to IDS mode without disabling first."""
        result = policy_client.configure_inspect("ips")
        assert result.success, f"Failed to enable IPS: {result.message}"

        status = policy_client.get_inspect_status()
        assert status.mode == "IPS"

        result = policy_client.configure_inspect("ids")
        assert result.success, f"Failed to switch to IDS: {result.message}"

        status = policy_client.get_inspect_status()
        assert status.mode == "IDS", f"Expected IDS after switch, got {status.mode}"

    def test_ips_mode_creates_veth_pair(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Enabling IPS mode should create the pe-inspect0/pe-inspect1 veth pair."""
        result = policy_client.configure_inspect("ips")
        assert result.success, f"Failed to enable IPS: {result.message}"

        status = policy_client.get_inspect_status()
        assert status.mirror_interface is not None, (
            "Mirror interface (pe-inspect0) should exist in IPS mode"
        )
        assert "inspect" in status.mirror_interface.lower(), (
            f"Mirror interface should be pe-inspect0, got {status.mirror_interface}"
        )
        logger.info(
            f"IPS veth pair: mirror={status.mirror_interface}, peer={status.peer_interface}"
        )

    def test_ips_mode_reports_suricata_state(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Inspect status should report whether Suricata is running."""
        result = policy_client.configure_inspect("ips")
        assert result.success, f"Failed to enable IPS: {result.message}"

        status = policy_client.get_inspect_status()
        # suricata_running is a boolean — just verify the field is present
        assert isinstance(status.suricata_running, bool), (
            f"suricata_running should be a bool, got {type(status.suricata_running)}"
        )
        logger.info(f"Suricata running in IPS mode: {status.suricata_running}")

    def test_server_status_reflects_ips_mode(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Server status inspect_mode field should reflect active IPS mode."""
        result = policy_client.configure_inspect("ips")
        assert result.success, f"Failed to enable IPS: {result.message}"

        server_status = policy_client.status()
        assert server_status.inspect_mode == "IPS", (
            f"Server status should show IPS, got {server_status.inspect_mode}"
        )

    def test_server_status_reflects_ids_mode(
        self, policy_client, inspect_mode_disabled, suricata_available
    ):
        """Server status inspect_mode field should reflect active IDS mode."""
        result = policy_client.configure_inspect("ids")
        assert result.success, f"Failed to enable IDS: {result.message}"

        server_status = policy_client.status()
        assert server_status.inspect_mode == "IDS", (
            f"Server status should show IDS, got {server_status.inspect_mode}"
        )

    def test_disable_removes_veth_pair(
        self, policy_client, inspect_mode_disabled, suricata_available, nodes
    ):
        """Disabling inspect mode should tear down the pe-inspect veth pair."""
        result = policy_client.configure_inspect("ips")
        assert result.success

        # Verify veth pair exists
        status = policy_client.get_inspect_status()
        assert status.mirror_interface is not None

        # Disable
        result = policy_client.disable_inspect()
        assert result.success

        # Verify veth pair is gone from the OS perspective
        server = nodes["server"]
        check = server.ssh_command(
            "ip link show pe-inspect0 2>/dev/null && echo EXISTS || echo MISSING"
        )
        assert "MISSING" in check, (
            "pe-inspect0 veth interface should be removed after disabling inspect"
        )
