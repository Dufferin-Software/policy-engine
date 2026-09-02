# Copyright (c) Peter Morrow

"""
TTL rule tests.

Verifies that rules with `expiresAfterSecs` are:
  - Immediately active in BPF maps and the managedRules registry
  - Automatically removed from both once the TTL elapses and the scheduler ticks
  - Able to block traffic while active and allow it after expiry

The scheduler tick interval is 30 s, so "expiry" tests wait up to ~60 s
for the effect to propagate. These tests are marked @pytest.mark.slow so they
can be excluded during fast pre-merge runs with: -m "not slow".
"""

import logging
import time
from typing import List

import pytest

from policy_engine_client.engine.cli.client import (
    AddRuleOptions,
    LpmRule,
    ManagedRule,
    OperationResult,
    WeeklyWindow,
)
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.nping_utils import NpingResult, send_ping

logger: logging.Logger = logging.getLogger(__name__)

# How long to wait for a scheduler tick to process an expired TTL rule.
# Scheduler runs every 30 s; add 15 s margin.
_SCHEDULER_WAIT = 45


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _drop_rule(
    src: str = "0.0.0.0/0",
    dst: str = "0.0.0.0/0",
    rule_id: int = 9001,
    interface: str = "",
    **kw,
) -> AddRuleOptions:
    return AddRuleOptions(
        interface=interface,
        src=src,
        dst=dst,
        protocol="any",
        actions=[("drop", 0)],
        rule_id=rule_id,
        **kw,
    )


# ---------------------------------------------------------------------------
# Management / registry tests (no traffic needed)
# ---------------------------------------------------------------------------


class TestTTLRuleRegistry:
    """TTL rule management: registry state, validation, CLI parity."""

    def test_ttl_rule_appears_in_managed_rules(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ) -> None:
        """A rule added with expiresAfterSecs must appear in managedRules."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9001, expires_after_secs=3600
        )
        result: OperationResult = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        managed: List[ManagedRule] = graphql_client.managed_rules(direction="ingress")
        ids: list[int] = [r.rule_id for r in managed]
        assert 9001 in ids, f"Rule 9001 not in managedRules: {ids}"

        mr: ManagedRule = next(r for r in managed if r.rule_id == 9001)
        assert mr.rule_state == "active"
        assert mr.expires_at_ms is not None
        assert mr.schedule_windows is None

    def test_ttl_rule_active_in_bpf(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ) -> None:
        """A TTL rule must be in the live BPF map (visible via list_rules)."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9002, expires_after_secs=3600
        )
        graphql_client.add_rule(opts, direction="ingress")

        rules: List[LpmRule] = graphql_client.list_rules(direction="ingress")
        ids: list[int] = [r.rule_id for r in rules]
        assert 9002 in ids, f"Rule 9002 not in list_rules: {ids}"

    def test_permanent_rule_not_in_managed_rules(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ) -> None:
        """A plain (permanent) rule must NOT appear in managedRules."""
        opts: AddRuleOptions = _drop_rule(interface=attached_ingress, rule_id=9003)
        graphql_client.add_rule(opts, direction="ingress")

        managed: List[ManagedRule] = graphql_client.managed_rules(direction="ingress")
        ids: list[int] = [r.rule_id for r in managed]
        assert 9003 not in ids, "Permanent rule should not be in managedRules"

    def test_ttl_rule_validation_zero_ttl(
        self, graphql_client: GraphQLPolicyClient, attached_ingress
    ) -> None:
        """expiresAfterSecs=0 must be rejected by the server."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9004, expires_after_secs=0
        )
        result: OperationResult = graphql_client.add_rule(opts, direction="ingress")
        assert not result.success, "Zero TTL should fail"
        assert "positive" in result.message.lower() or "0" in result.message

    def test_ttl_rule_validation_both_ttl_and_schedule(
        self, graphql_client: GraphQLPolicyClient, attached_ingress
    ) -> None:
        """Setting both expiresAfterSecs and schedule windows must be rejected."""
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            expires_after_secs=60,
            schedule_windows=[WeeklyWindow(0, 0, 0, 6, 23, 59)],
        )
        result: OperationResult = graphql_client.add_rule(opts, direction="ingress")
        assert not result.success, "Both TTL and schedule should be mutually exclusive"
        assert (
            "exclusive" in result.message.lower()
            or "mutually" in result.message.lower()
        )

    def test_delete_ttl_rule_removes_from_managed_rules(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ) -> None:
        """Manually deleting a TTL rule must remove it from managedRules."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9005, expires_after_secs=3600
        )
        graphql_client.add_rule(opts, direction="ingress")

        managed_before: List[ManagedRule] = graphql_client.managed_rules(
            direction="ingress"
        )
        assert any(r.rule_id == 9005 for r in managed_before)

        graphql_client.delete_rule(attached_ingress, rule_id=9005, direction="ingress")

        managed_after: List[ManagedRule] = graphql_client.managed_rules(
            direction="ingress"
        )
        assert not any(r.rule_id == 9005 for r in managed_after), (
            "Deleted TTL rule should be removed from managedRules"
        )

    def test_expires_at_ms_is_in_the_future(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ) -> None:
        """The expiresAtMs timestamp must be in the future relative to now."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9006, expires_after_secs=3600
        )
        graphql_client.add_rule(opts, direction="ingress")

        managed: List[ManagedRule] = graphql_client.managed_rules(direction="ingress")
        mr: ManagedRule | None = next((r for r in managed if r.rule_id == 9006), None)
        assert mr is not None
        now_ms = int(time.time() * 1000)
        assert mr.expires_at_ms is not None and mr.expires_at_ms > now_ms, (
            f"expiresAtMs {mr.expires_at_ms} is not in the future (now={now_ms})"
        )

    def test_cli_ttl_rule_appears_in_managed_rules(
        self, cli_client, attached_ingress, clean_ingress_rules
    ) -> None:
        """CLI: --expires-after-secs must be reflected in 'rule managed-rules'."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9007, expires_after_secs=3600
        )
        result = cli_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        managed = cli_client.managed_rules(direction="ingress")
        ids = [r.rule_id for r in managed]
        assert 9007 in ids, f"Rule 9007 not in CLI managed-rules: {ids}"

        mr = next(r for r in managed if r.rule_id == 9007)
        assert mr.rule_state == "active"
        assert mr.expires_at_ms is not None


# ---------------------------------------------------------------------------
# Expiry behaviour tests (slow — wait for scheduler tick)
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestTTLRuleExpiry:
    """TTL rules expire after their TTL elapses and the scheduler ticks."""

    def test_ttl_rule_removed_from_bpf_after_expiry(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ) -> None:
        """After expiry the rule must disappear from the live BPF map."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9010, expires_after_secs=5
        )
        graphql_client.add_rule(opts, direction="ingress")

        # Confirm it is active immediately
        rules_before: List[LpmRule] = graphql_client.list_rules(direction="ingress")
        assert any(r.rule_id == 9010 for r in rules_before), (
            "Rule should be active in BPF immediately after add"
        )

        logger.info(f"Waiting {_SCHEDULER_WAIT}s for TTL expiry + scheduler tick...")
        time.sleep(_SCHEDULER_WAIT)

        rules_after: List[LpmRule] = graphql_client.list_rules(direction="ingress")
        assert not any(r.rule_id == 9010 for r in rules_after), (
            "Rule 9010 should have been removed from BPF after TTL expiry"
        )

    def test_ttl_rule_removed_from_managed_rules_after_expiry(
        self, graphql_client: GraphQLPolicyClient, attached_ingress, clean_ingress_rules
    ) -> None:
        """After expiry the rule must disappear from managedRules too."""
        opts: AddRuleOptions = _drop_rule(
            interface=attached_ingress, rule_id=9011, expires_after_secs=5
        )
        graphql_client.add_rule(opts, direction="ingress")

        logger.info(f"Waiting {_SCHEDULER_WAIT}s for TTL expiry + scheduler tick...")
        time.sleep(_SCHEDULER_WAIT)

        managed: List[ManagedRule] = graphql_client.managed_rules(direction="ingress")
        assert not any(r.rule_id == 9011 for r in managed), (
            "Expired TTL rule should be removed from managedRules"
        )

    def test_ttl_rule_drop_then_allow_after_expiry(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nmap_installed,
        nodes,
        server_ip_v4,
        client_ip_v4,
    ) -> None:
        """
        Traffic is blocked while a DROP TTL rule is active, and flows freely
        once the rule has expired and been removed by the scheduler.
        """
        client = nodes["client"]

        # Baseline: traffic should pass before adding any DROP rule
        pre_result: NpingResult = send_ping(client, str(server_ip_v4), count=3)
        assert pre_result.packets_received > 0, (
            "Baseline: ICMP should pass before DROP rule"
        )

        # Add a short-TTL DROP rule
        opts = AddRuleOptions(
            interface=attached_ingress,
            src=f"{client_ip_v4}/32",
            dst=f"{server_ip_v4}/32",
            protocol="icmp",
            actions=[("drop", 0)],
            rule_id=9012,
            expires_after_secs=5,
        )
        result: OperationResult = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        # Traffic should be blocked
        drop_result: NpingResult = send_ping(
            client, str(server_ip_v4), count=3, timeout=5
        )
        assert drop_result.packets_received == 0, (
            "ICMP should be blocked by active TTL DROP rule"
        )

        # Wait for expiry
        logger.info(f"Waiting {_SCHEDULER_WAIT}s for TTL expiry...")
        time.sleep(_SCHEDULER_WAIT)

        # Traffic should flow again
        post_result: NpingResult = send_ping(client, str(server_ip_v4), count=3)
        assert post_result.packets_received > 0, (
            "ICMP should pass after TTL DROP rule has expired"
        )
