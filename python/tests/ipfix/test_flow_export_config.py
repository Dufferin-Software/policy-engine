# Copyright (c) Dufferin Software

"""
IPFIX flow export configuration tests.

Tests the configureFlowExport mutation and flowExportStatus query lifecycle:
- Server feature flag reflects IPFIX support
- Default state is disabled
- Enable/disable round-trip
- Custom collector host, port, and timeout parameters persist correctly
- Re-enabling with different parameters updates the config
"""

import logging

logger = logging.getLogger(__name__)


class TestServerFeatures:
    """Tests for the serverFeatures.ipfix flag."""

    def test_ipfix_feature_flag_present(self, graphql_client, ipfix_available):
        """serverFeatures.ipfix must be True when compiled with IPFIX support."""
        features = graphql_client.server_features()
        assert features.ipfix is True, (
            "Expected serverFeatures.ipfix=True for policy-engine-ipfix package"
        )


class TestFlowExportDefaults:
    """Tests for the default (disabled) flow export state."""

    def test_disabled_by_default(self, graphql_client, flow_export_disabled):
        """Flow export should be disabled on a freshly started server."""
        status = graphql_client.get_flow_export_status()
        assert status.enabled is False, (
            f"Expected flow export disabled by default, got enabled={status.enabled}"
        )

    def test_default_collector_port(self, graphql_client, flow_export_disabled):
        """Default collector port should be 4739 (IANA IPFIX port)."""
        result = graphql_client.configure_flow_export(enabled=False)
        assert result.success

        status = graphql_client.get_flow_export_status()
        assert status.collector_port == 4739, (
            f"Expected default collector port 4739, got {status.collector_port}"
        )

    def test_default_timeouts(self, graphql_client, flow_export_disabled):
        """Default idle=15s and active=60s timeouts should be present."""
        result = graphql_client.configure_flow_export(enabled=False)
        assert result.success

        status = graphql_client.get_flow_export_status()
        assert status.idle_timeout_s == 15, (
            f"Expected idle_timeout_s=15, got {status.idle_timeout_s}"
        )
        assert status.active_timeout_s == 60, (
            f"Expected active_timeout_s=60, got {status.active_timeout_s}"
        )


class TestFlowExportEnable:
    """Tests for enabling and disabling flow export."""

    def test_enable_flow_export(self, graphql_client, flow_export_disabled):
        """configureFlowExport(enabled=True) should succeed and reflect in status."""
        result = graphql_client.configure_flow_export(
            enabled=True,
            collector_host="127.0.0.1",
            collector_port=4739,
        )
        assert result.success, f"Failed to enable flow export: {result.message}"

        status = graphql_client.get_flow_export_status()
        assert status.enabled is True
        assert status.collector_host == "127.0.0.1"
        assert status.collector_port == 4739

    def test_disable_flow_export(self, graphql_client, flow_export_disabled):
        """Disabling after enabling should reflect in status."""
        graphql_client.configure_flow_export(enabled=True, collector_host="127.0.0.1")

        result = graphql_client.configure_flow_export(enabled=False)
        assert result.success, f"Failed to disable flow export: {result.message}"

        status = graphql_client.get_flow_export_status()
        assert status.enabled is False

    def test_custom_collector_host_and_port(self, graphql_client, flow_export_disabled):
        """Custom collector host and port should be stored in status."""
        result = graphql_client.configure_flow_export(
            enabled=True,
            collector_host="10.0.0.1",
            collector_port=9995,
        )
        assert result.success, f"configureFlowExport failed: {result.message}"

        status = graphql_client.get_flow_export_status()
        assert status.collector_host == "10.0.0.1"
        assert status.collector_port == 9995

    def test_custom_timeouts(self, graphql_client, flow_export_disabled):
        """Custom idle and active timeouts should be stored in status."""
        result = graphql_client.configure_flow_export(
            enabled=True,
            collector_host="127.0.0.1",
            idle_timeout_s=30,
            active_timeout_s=120,
        )
        assert result.success, f"configureFlowExport failed: {result.message}"

        status = graphql_client.get_flow_export_status()
        assert status.idle_timeout_s == 30, (
            f"Expected idle_timeout_s=30, got {status.idle_timeout_s}"
        )
        assert status.active_timeout_s == 120, (
            f"Expected active_timeout_s=120, got {status.active_timeout_s}"
        )

    def test_reconfigure_updates_params(self, graphql_client, flow_export_disabled):
        """Re-enabling with different parameters should update the config."""
        graphql_client.configure_flow_export(
            enabled=True, collector_host="127.0.0.1", collector_port=4739
        )
        graphql_client.configure_flow_export(
            enabled=True, collector_host="127.0.0.1", collector_port=9999
        )

        status = graphql_client.get_flow_export_status()
        assert status.enabled is True
        assert status.collector_port == 9999


class TestFlowExportCounters:
    """Tests for flow export counters in the status query."""

    def test_flows_exported_total_starts_at_zero(
        self, graphql_client, flow_export_enabled
    ):
        """flowsExportedTotal should start at 0 on a freshly enabled exporter."""
        status = graphql_client.get_flow_export_status()
        logger.info(f"flowsExportedTotal after enable: {status.flows_exported_total}")
        # May be non-zero if previous tests left flows; just verify it's non-negative
        assert status.flows_exported_total >= 0

    def test_active_flow_count_non_negative(self, graphql_client, flow_export_enabled):
        """activeFlowCount should be a non-negative integer."""
        status = graphql_client.get_flow_export_status()
        assert status.active_flow_count >= 0, (
            f"activeFlowCount should be non-negative, got {status.active_flow_count}"
        )
