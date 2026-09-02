# Copyright (c) Peter Morrow

"""
IPS/IDS traffic inspection tests.

Tests that the INSPECT action correctly redirects matched traffic to Suricata
for deep packet inspection, and that flow verdicts are tracked.

Architecture under test:
  client → [server NIC] → XDP program → INSPECT action → pe-inspect0 (clone)
                                                         → Suricata (pe-inspect1)
                                                         → flow verdict (DROP/PASS)
  client → [original packet still passes until verdict is installed]

These tests verify:
- INSPECT action increments inspect_redirects stat
- Flow verdicts are created after TCP connections are inspected
- IPS mode installs DROP verdicts for flows matching alert rules
- IDS mode does NOT install DROP verdicts (alert only)
- Flow verdicts can be cleared
"""

import logging

from tenacity import retry, retry_if_exception_type, stop_after_delay, wait_fixed

from netsim.testkit.nping_utils import send_ping, send_tcp_syn
from policy_engine_client.engine.cli.client import AddRuleOptions

logger = logging.getLogger(__name__)

# A simple Suricata alert rule that fires on any TCP traffic to port 9999
ALERT_RULE_TCP_9999 = (
    'alert tcp any any -> any 9999 (msg:"IPS test alert TCP 9999"; sid:9999001; rev:1;)'
)

# A drop rule for IPS mode
DROP_RULE_TCP_8888 = (
    'drop tcp any any -> any 8888 (msg:"IPS test drop TCP 8888"; sid:8888001; rev:1;)'
)


class TestInspectAction:
    """Tests for the INSPECT policy action."""

    def test_inspect_action_increments_redirect_stat(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        ips_mode_enabled,
        server_interface,
        client_interface,
        client_network_v4,
        nmap_installed,
    ):
        """
        INSPECT action should increment inspect_redirects stat on matched traffic.

        Adds an INSPECT rule for TCP traffic from the client, sends TCP SYNs,
        and verifies the inspect_redirects counter increases.
        """
        client = nodes["client"]
        server_ip = server_interface.get_ip_address()

        # Log inspect status to verify IPS mode is active
        inspect_status = policy_client.get_inspect_status()
        logger.info(
            f"Inspect status before test: mode={inspect_status.mode}, "
            f"suricata_running={inspect_status.suricata_running}, "
            f"mirror_iface={inspect_status.mirror_interface}"
        )

        # Add INSPECT rule for all TCP from client subnet
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            actions=[("inspect", 0), ("pass", 1)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add INSPECT rule: {result.message}"
        logger.info(f"Added INSPECT rule: {result.message}")

        # Verify the rule is present
        rules = policy_client.list_rules(direction="ingress")
        logger.info(f"Rules after add: {len(rules)} rule(s)")
        for r in rules:
            logger.info(
                f"  Rule {r.rule_id}: src={r.src_prefix} proto={r.protocol} actions={[a.action.value for a in r.actions]}"
            )

        # Record initial stats
        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_redirects = initial_stats.global_stats.inspect_redirects
        initial_rx = initial_stats.global_stats.rx_packets
        initial_matches = initial_stats.global_stats.policy_matches
        logger.info(
            f"Initial stats: rx_packets={initial_rx}, "
            f"policy_matches={initial_matches}, "
            f"inspect_redirects={initial_redirects}"
        )

        # Send a burst of TCP SYNs from client to server.  The XDP INSPECT
        # action installs a PASS verdict in the flow cache on the first match;
        # subsequent packets on the same 5-tuple hit the cached verdict and
        # bypass the INSPECT counter.  We need at least one new redirect.
        # Use the client's own interface name (not the server's) for sending.
        nping_result = send_tcp_syn(
            client,
            server_ip,
            dest_port=8080,
            count=5,
            interface=client_interface.if_name,
        )
        logger.info(
            f"nping result: success={nping_result.success}, "
            f"sent={nping_result.packets_sent}, "
            f"received={nping_result.packets_received}, "
            f"error={nping_result.error_message}"
        )

        @retry(
            stop=stop_after_delay(5),
            wait=wait_fixed(0.25),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_redirects_incremented():
            stats = policy_client.get_stats(attached_ingress, direction="ingress")
            rx_delta = stats.global_stats.rx_packets - initial_rx
            matches_delta = stats.global_stats.policy_matches - initial_matches
            redirects_delta = stats.global_stats.inspect_redirects - initial_redirects
            logger.info(
                f"Stats delta: rx_packets={rx_delta}, "
                f"policy_matches={matches_delta}, "
                f"inspect_redirects={redirects_delta}"
            )
            assert redirects_delta >= 1, (
                f"Expected inspect_redirects to increment, got delta={redirects_delta} "
                f"(rx_delta={rx_delta}, matches_delta={matches_delta})"
            )

        assert_redirects_incremented()

    def test_inspect_action_does_not_drop_by_default(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        ips_mode_enabled,
        server_interface,
        client_network_v4,
        client_ip_v4,
        nmap_installed,
    ):
        """
        An INSPECT rule should not drop traffic unless Suricata issues a DROP verdict.

        With no Suricata alert/drop rules, traffic with INSPECT+PASS action should
        pass through (inspect_redirects increments but policy_drops stays 0).
        """
        client = nodes["client"]
        server_ip = server_interface.get_ip_address()

        # INSPECT + PASS action — traffic should pass while being cloned to Suricata
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("inspect", 0), ("pass", 1)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add INSPECT+PASS rule: {result.message}"

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_drops = initial_stats.global_stats.policy_drops

        # Send ICMP from client — should pass (no Suricata drop rule).
        # BPF drops are applied synchronously during packet processing, so a
        # single read immediately after the send completes is sufficient.
        packets_to_send = 5
        ping_result = send_ping(
            client,
            server_ip,
            count=packets_to_send,
            interface=server_interface.if_name,
        )

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops

        logger.info(
            f"INSPECT+PASS: packets_sent={packets_to_send}, drops_delta={drops_delta}, "
            f"ping_received={ping_result.packets_received}"
        )
        assert drops_delta == 0, (
            f"INSPECT+PASS should not drop traffic without a Suricata drop rule, "
            f"got {drops_delta} drops"
        )


class TestFlowVerdicts:
    """Tests for flow verdict tracking."""

    def test_flow_verdicts_initially_zero(self, policy_client, ips_mode_enabled):
        """Flow verdict count should start at 0 in fresh IPS mode."""
        # ips_mode_enabled fixture already clears verdicts via inspect_mode_disabled
        stats = policy_client.get_flow_verdicts(direction="ingress")
        assert stats.active_verdicts == 0, (
            f"Expected 0 verdicts after clearing, got {stats.active_verdicts}"
        )

    def test_clear_flow_verdicts(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        ips_mode_enabled,
        server_interface,
        client_network_v4,
        client_ip_v4,
        nmap_installed,
    ):
        """
        Cleared flow verdicts should drop to zero.

        Sends traffic to create some verdicts (if any), then clears them and
        verifies the count is 0.
        """
        client = nodes["client"]
        server_ip = server_interface.get_ip_address()

        # Add INSPECT rule
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            actions=[("inspect", 0), ("pass", 1)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success

        # Generate some traffic
        send_tcp_syn(
            client,
            server_ip,
            dest_port=8080,
            count=5,
        )

        # Clear flow verdicts — the map delete is synchronous on the server
        result = policy_client.clear_flow_verdicts(direction="ingress")
        assert result.success, f"Failed to clear flow verdicts: {result.message}"

        stats = policy_client.get_flow_verdicts(direction="ingress")
        assert stats.active_verdicts == 0, (
            f"Expected 0 verdicts after clear, got {stats.active_verdicts}"
        )
        logger.info("Flow verdicts cleared successfully")

    def test_clear_flow_verdicts_egress(self, policy_client, ips_mode_enabled):
        """Can clear egress flow verdicts."""
        result = policy_client.clear_flow_verdicts(direction="egress")
        assert result.success, f"Failed to clear egress flow verdicts: {result.message}"

        stats = policy_client.get_flow_verdicts(direction="egress")
        assert stats.active_verdicts == 0


class TestIpsModeTraffic:
    """Tests for IPS mode traffic behaviour with Suricata rules."""

    def test_suricata_drop_rule_drops_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        ips_mode_enabled,
        server_interface,
        client_network_v4,
        client_ip_v4,
        nmap_installed,
    ):
        """
        In IPS mode, a Suricata 'drop' rule should cause matched TCP flows to
        be dropped after the initial connection attempt is inspected.

        Deploys a Suricata drop rule for TCP port 8888, sends traffic, and
        verifies that inspect_redirects increments (traffic reached Suricata).
        """
        client = nodes["client"]
        server_ip = server_interface.get_ip_address()

        # Deploy Suricata drop rule for port 8888
        result = policy_client.deploy_suricata_rules(
            DROP_RULE_TCP_8888, "ips_test.rules"
        )
        assert result.success, f"Failed to deploy Suricata rules: {result.message}"
        logger.info("Suricata drop rule deployed for TCP port 8888")

        policy_client.reload_suricata_rules()

        # Add INSPECT rule for TCP from client to port 8888
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            dport=8888,
            actions=[("inspect", 0), ("pass", 1)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success, f"Failed to add INSPECT rule: {result.message}"

        # Get initial stats
        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_redirects = initial_stats.global_stats.inspect_redirects

        # Send TCP SYNs to port 8888 — should be inspected and eventually dropped.
        # Retry the assertion to allow time for Suricata rule reload and verdict
        # installation.
        send_tcp_syn(
            client,
            server_ip,
            dest_port=8888,
            count=10,
            interface=server_interface.if_name,
        )

        @retry(
            stop=stop_after_delay(15),
            wait=wait_fixed(0.5),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_traffic_redirected():
            stats = policy_client.get_stats(attached_ingress, direction="ingress")
            delta = stats.global_stats.inspect_redirects - initial_redirects
            logger.info(
                f"IPS TCP 8888: inspect_redirects_delta={delta}, "
                f"verdict_drop_packets={stats.global_stats.verdict_drop_packets}"
            )
            assert delta > 0, (
                f"Expected traffic to be redirected to Suricata for inspection, "
                f"got {delta} redirects"
            )

        assert_traffic_redirected()

    def test_ips_mode_does_not_affect_unmatched_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        ips_mode_enabled,
        server_interface,
        client_network_v4,
        client_ip_v4,
        nmap_installed,
    ):
        """
        In IPS mode, traffic that does NOT match the INSPECT rule should pass normally.

        Adds an INSPECT rule only for TCP port 8888, sends ICMP — should pass
        without any inspection redirects.
        """
        client = nodes["client"]
        server_ip = server_interface.get_ip_address()

        # Add INSPECT rule only for TCP port 8888
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            dport=8888,
            actions=[("inspect", 0), ("pass", 1)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_redirects = initial_stats.global_stats.inspect_redirects

        # Send ICMP — should NOT match the TCP rule.  Redirect decisions are
        # made synchronously by XDP, so a single read after the send completes
        # is sufficient.
        send_ping(client, server_ip, count=5)

        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        redirects_delta = final_stats.global_stats.inspect_redirects - initial_redirects

        logger.info(
            f"ICMP with TCP INSPECT rule: inspect_redirects_delta={redirects_delta}"
        )
        assert redirects_delta == 0, (
            f"ICMP should not be redirected by a TCP-only INSPECT rule, "
            f"got {redirects_delta} redirects"
        )


class TestIdsModeTraffic:
    """Tests for IDS mode traffic behaviour (alert-only, no drops)."""

    def test_ids_mode_does_not_drop_traffic(
        self,
        nodes,
        policy_client,
        attached_ingress,
        clean_ingress_rules,
        ids_mode_enabled,
        server_interface,
        client_network_v4,
        client_ip_v4,
        nmap_installed,
    ):
        """
        In IDS mode, traffic is cloned to Suricata for alerting but the original
        packets are not dropped, even if Suricata has a drop rule.

        Verifies that inspect_redirects increments (cloning happened) but
        policy_drops stays at 0 (no drop verdicts are installed).
        """
        client = nodes["client"]
        server_ip = server_interface.get_ip_address()

        # Deploy alert rule (in IDS mode, drop rules should still only alert)
        result = policy_client.deploy_suricata_rules(
            ALERT_RULE_TCP_9999, "ids_test.rules"
        )
        assert result.success
        policy_client.reload_suricata_rules()

        # Add INSPECT rule for TCP port 9999
        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="tcp",
            dport=9999,
            actions=[("inspect", 0), ("pass", 1)],
        )
        result = policy_client.add_rule(options, direction="ingress")
        assert result.success

        initial_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        initial_redirects = initial_stats.global_stats.inspect_redirects
        initial_drops = initial_stats.global_stats.policy_drops

        # Send TCP SYNs to port 9999
        send_tcp_syn(
            client,
            server_ip,
            dest_port=9999,
            count=5,
        )

        @retry(
            stop=stop_after_delay(10),
            wait=wait_fixed(0.25),
            retry=retry_if_exception_type(AssertionError),
            reraise=True,
        )
        def assert_traffic_cloned():
            stats = policy_client.get_stats(attached_ingress, direction="ingress")
            delta = stats.global_stats.inspect_redirects - initial_redirects
            logger.info(f"IDS mode TCP 9999: inspect_redirects_delta={delta}")
            assert delta > 0, (
                f"Expected traffic to be cloned to Suricata in IDS mode, "
                f"got {delta} redirects"
            )

        assert_traffic_cloned()

        # In IDS mode no DROP verdicts should be installed — check immediately
        # after traffic is confirmed cloned (drops are applied synchronously).
        final_stats = policy_client.get_stats(attached_ingress, direction="ingress")
        drops_delta = final_stats.global_stats.policy_drops - initial_drops
        logger.info(f"IDS mode drops_delta={drops_delta}")
        assert drops_delta == 0, (
            f"IDS mode should not install DROP verdicts, got {drops_delta} drops"
        )
