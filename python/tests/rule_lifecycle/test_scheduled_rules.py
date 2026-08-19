# Copyright (c) Dufferin Software

"""
Scheduled rule tests.

Verifies that rules with a weekly recurring schedule are:
  - Active in BPF when the current time falls within a window
  - Stored in managedRules but NOT in the live BPF map when outside a window
  - Deletable (including while inactive) and the deletion is reflected everywhere
  - Rejected when given an invalid timezone or out-of-range window fields

Window activation / deactivation by the scheduler (which ticks every 30 s) is
tested in the "slow" suite and requires carefully chosen window boundaries.
"""

import logging
import time

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions, WeeklyWindow
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.nping_utils import send_ping


logger = logging.getLogger(__name__)

_SCHEDULER_WAIT = 45  # seconds to wait for a scheduler tick


# ---------------------------------------------------------------------------
# Helper windows
# ---------------------------------------------------------------------------


def _all_week() -> list:
    """A single window that covers the entire week (Sun 00:00 → Sat 23:59)."""
    return [WeeklyWindow(0, 0, 0, 6, 23, 59)]


def _inactive_narrow_window() -> list:
    """
    A 1-minute window at an obscure time (Sun 03:47–03:48) that is almost
    certainly not the current time.  Tests that need this to be truly inactive
    should check the server time and skip if necessary (see fixture below).
    """
    return [WeeklyWindow(0, 3, 47, 0, 3, 48)]


# ---------------------------------------------------------------------------
# Management / registry tests (no traffic needed)
# ---------------------------------------------------------------------------


class TestScheduledRuleRegistry:
    """Scheduled rule management: registry state and validation."""

    def test_all_week_rule_is_active(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """A rule whose window covers the entire week must start active."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8001,
            schedule_windows=_all_week(),
            schedule_tz="UTC",
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        # Must be in managedRules as active
        managed = graphql_client.managed_rules(direction="ingress")
        mr = next((r for r in managed if r.rule_id == 8001), None)
        assert mr is not None, "Rule 8001 should be in managedRules"
        assert mr.rule_state == "active", f"Expected active, got {mr.rule_state}"
        assert mr.schedule_windows is not None
        assert mr.expires_at_ms is None

        # Must also be in the live BPF map
        rules = graphql_client.list_rules(direction="ingress")
        assert any(r.rule_id == 8001 for r in rules), (
            "Active scheduled rule should be in list_rules"
        )

    def test_inactive_window_rule_not_in_bpf(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        not_inactive_window_time,
    ):
        """A rule outside its active window must NOT be in the live BPF map."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8002,
            schedule_windows=_inactive_narrow_window(),
            schedule_tz="UTC",
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        rules = graphql_client.list_rules(direction="ingress")
        assert not any(r.rule_id == 8002 for r in rules), (
            "Inactive scheduled rule must NOT be in BPF map"
        )

    def test_inactive_window_rule_in_managed_rules(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        not_inactive_window_time,
    ):
        """A rule outside its window must appear in managedRules with state=inactive."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8003,
            schedule_windows=_inactive_narrow_window(),
            schedule_tz="UTC",
        )
        graphql_client.add_rule(opts, direction="ingress")

        managed = graphql_client.managed_rules(direction="ingress")
        mr = next((r for r in managed if r.rule_id == 8003), None)
        assert mr is not None, "Inactive rule should still be in managedRules"
        assert mr.rule_state == "inactive", f"Expected inactive, got {mr.rule_state}"

    def test_delete_active_scheduled_rule(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """Deleting an active scheduled rule removes it from both BPF and managedRules."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8004,
            schedule_windows=_all_week(),
        )
        graphql_client.add_rule(opts, direction="ingress")

        result = graphql_client.delete_rule(
            attached_ingress, rule_id=8004, direction="ingress"
        )
        assert result.success, result.message

        rules = graphql_client.list_rules(direction="ingress")
        assert not any(r.rule_id == 8004 for r in rules)

        managed = graphql_client.managed_rules(direction="ingress")
        assert not any(r.rule_id == 8004 for r in managed)

    def test_delete_inactive_scheduled_rule(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        not_inactive_window_time,
    ):
        """Deleting an inactive (out-of-window) scheduled rule succeeds."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8005,
            schedule_windows=_inactive_narrow_window(),
        )
        graphql_client.add_rule(opts, direction="ingress")

        result = graphql_client.delete_rule(
            attached_ingress, rule_id=8005, direction="ingress"
        )
        assert result.success, result.message

        managed = graphql_client.managed_rules(direction="ingress")
        assert not any(r.rule_id == 8005 for r in managed)

    def test_schedule_stores_timezone(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """The schedule timezone must be round-tripped through managedRules."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8006,
            schedule_windows=_all_week(),
            schedule_tz="America/Toronto",
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        managed = graphql_client.managed_rules(direction="ingress")
        mr = next((r for r in managed if r.rule_id == 8006), None)
        assert mr is not None
        assert mr.schedule_timezone == "America/Toronto"

    def test_schedule_stores_window_fields(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """Window day/hour/minute values must be preserved exactly."""
        window = WeeklyWindow(1, 8, 30, 5, 18, 0)  # Mon 08:30 → Fri 18:00
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8007,
            schedule_windows=[window],
            schedule_tz="UTC",
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        managed = graphql_client.managed_rules(direction="ingress")
        mr = next((r for r in managed if r.rule_id == 8007), None)
        assert mr is not None and mr.schedule_windows

        w = mr.schedule_windows[0]
        assert w.start_day == 1 and w.start_hour == 8 and w.start_minute == 30
        assert w.end_day == 5 and w.end_hour == 18 and w.end_minute == 0


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestScheduledRuleValidation:
    """Server-side validation for scheduled rule inputs."""

    def test_invalid_timezone_rejected(
        self, graphql_client: GraphQLPolicyClient, attached_ingress
    ):
        """An unrecognised timezone string must be rejected."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            schedule_windows=_all_week(),
            schedule_tz="NotATimezone/BadZone",
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert not result.success, "Invalid timezone should be rejected"

    def test_day_out_of_range_rejected(
        self, graphql_client: GraphQLPolicyClient, attached_ingress
    ):
        """A day_of_week value outside 0–6 must be rejected."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            schedule_windows=[WeeklyWindow(7, 0, 0, 7, 23, 59)],  # day=7 is invalid
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert not result.success, "dayOfWeek=7 should be rejected"

    def test_hour_out_of_range_rejected(
        self, graphql_client: GraphQLPolicyClient, attached_ingress
    ):
        """An hour value ≥ 24 must be rejected."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            schedule_windows=[WeeklyWindow(0, 24, 0, 6, 23, 59)],
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert not result.success, "hour=24 should be rejected"

    def test_minute_out_of_range_rejected(
        self, graphql_client: GraphQLPolicyClient, attached_ingress
    ):
        """A minute value ≥ 60 must be rejected."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            schedule_windows=[WeeklyWindow(0, 0, 60, 6, 23, 59)],
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert not result.success, "minute=60 should be rejected"

    def test_empty_windows_list_rejected(
        self, graphql_client: GraphQLPolicyClient, attached_ingress
    ):
        """A schedule with zero windows must be rejected."""
        # Build the request directly since AddRuleOptions won't normally
        # produce an empty windows list via add_rule().
        mutation = """
        mutation AddRule($input: AddRuleInput!) {
            addRule(input: $input) { success message }
        }
        """
        variables = {
            "input": {
                "direction": "INGRESS",
                "src": "0.0.0.0/0",
                "sport": 0,
                "dport": 0,
                "protocol": "any",
                "actions": [{"action": "DROP", "priority": 0, "param": 0}],
                "schedule": {"timezone": "UTC", "windows": []},
            }
        }
        data = graphql_client._execute_graphql(mutation, variables)
        if "__error__" in data:
            # GraphQL-level error — acceptable
            return
        result = data.get("addRule", {})
        assert not result.get("success", True), "Empty windows list should be rejected"


# ---------------------------------------------------------------------------
# Scheduled rule traffic tests
# ---------------------------------------------------------------------------


class TestScheduledRuleTraffic:
    """Active scheduled rules enforce policy; inactive ones do not."""

    def test_active_scheduled_rule_blocks_traffic(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nmap_installed,
        nodes,
        server_ip_v4,
        client_ip_v4,
    ):
        """An active (all-week) scheduled DROP rule blocks ingress ICMP."""
        client = nodes["client"]

        # Baseline — traffic passes
        baseline = send_ping(client, str(server_ip_v4), count=3)
        assert baseline.packets_received > 0, "Baseline ICMP should pass"

        opts = AddRuleOptions(
            interface=attached_ingress,
            src=f"{client_ip_v4}/32",
            dst=f"{server_ip_v4}/32",
            protocol="icmp",
            actions=[("drop", 0)],
            rule_id=8010,
            schedule_windows=_all_week(),
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        blocked = send_ping(client, str(server_ip_v4), count=3, timeout=5)
        assert blocked.packets_received == 0, (
            "ICMP should be blocked by active scheduled DROP rule"
        )

    def test_inactive_scheduled_rule_allows_traffic(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nmap_installed,
        not_inactive_window_time,
        nodes,
        server_ip_v4,
        client_ip_v4,
    ):
        """An inactive (out-of-window) scheduled DROP rule must not block traffic."""
        client = nodes["client"]

        opts = AddRuleOptions(
            interface=attached_ingress,
            src=f"{client_ip_v4}/32",
            dst=f"{server_ip_v4}/32",
            protocol="icmp",
            actions=[("drop", 0)],
            rule_id=8011,
            schedule_windows=_inactive_narrow_window(),
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        # Rule is inactive — traffic should still pass
        ping = send_ping(client, str(server_ip_v4), count=3)
        assert ping.packets_received > 0, (
            "ICMP should pass when scheduled rule is outside its window"
        )


# ---------------------------------------------------------------------------
# Slow: window activation / deactivation via scheduler tick
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestScheduledRuleSchedulerTransitions:
    """Window transitions processed by the background scheduler."""

    def _get_server_week_minutes(self, server) -> int:
        """Return current UTC week-minutes (0=Sun 00:00 … 10079=Sat 23:59)."""
        raw = server.ssh_command("date -u '+%w %H %M'")
        dow, hour, minute = map(int, raw.strip().split())
        return dow * 1440 + hour * 60 + minute

    def test_rule_deactivates_when_window_ends(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
    ):
        """
        Add an active rule whose window ends 10 s from now.
        After the scheduler tick the rule must move to inactive state.

        Strategy: compute a window [now-1 min, now+10 s), add rule (active),
        sleep until window ends + scheduler tick, assert state=inactive.
        """
        server = nodes["server"]
        wm = self._get_server_week_minutes(server)
        # start = 1 minute ago (mod week), end = wm itself (already past by
        # the time we check after _SCHEDULER_WAIT seconds)
        start_wm = (wm - 1) % 10080
        end_wm = wm  # window ends at current minute; we'll be past it soon

        start_dow, start_rem = divmod(start_wm, 1440)
        start_h, start_m = divmod(start_rem, 60)
        end_dow, end_rem = divmod(end_wm, 1440)
        end_h, end_m = divmod(end_rem, 60)

        window = WeeklyWindow(start_dow, start_h, start_m, end_dow, end_h, end_m)
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=8020,
            schedule_windows=[window],
            schedule_tz="UTC",
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        # Verify initially active
        managed = graphql_client.managed_rules(direction="ingress")
        mr = next((r for r in managed if r.rule_id == 8020), None)
        if mr is None or mr.rule_state != "active":
            pytest.skip(
                "Window boundary arithmetic did not produce an active rule — skipping"
            )

        logger.info(
            f"Waiting {_SCHEDULER_WAIT}s for window to close + scheduler tick..."
        )
        time.sleep(_SCHEDULER_WAIT + 70)  # window is 1 min wide; wait a full min + tick

        managed_after = graphql_client.managed_rules(direction="ingress")
        mr_after = next((r for r in managed_after if r.rule_id == 8020), None)
        assert mr_after is not None, (
            "Rule should still be in managedRules (just inactive)"
        )
        assert mr_after.rule_state == "inactive", (
            f"Expected inactive after window ended, got {mr_after.rule_state}"
        )

        # And not in BPF
        rules = graphql_client.list_rules(direction="ingress")
        assert not any(r.rule_id == 8020 for r in rules), (
            "Deactivated rule must not be in BPF map"
        )


# ---------------------------------------------------------------------------
# Package-level fixture: skip "inactive window" tests if we're in that window
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def not_inactive_window_time(nodes):
    """
    Skip the test if the server's current UTC time happens to fall inside the
    narrow inactive test window (Sun 03:47–03:48).
    """
    server = nodes["server"]
    raw = server.ssh_command("date -u '+%w %H %M'")
    dow, hour, minute = map(int, raw.strip().split())
    if dow == 0 and hour == 3 and minute in (47, 48):
        pytest.skip("Current time is inside the 'inactive' test window — skipping")
