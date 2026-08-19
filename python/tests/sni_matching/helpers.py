# Copyright (c) Dufferin Software

"""
Shared helpers for the SNI-matching tests.

These stat-polling helpers were previously copy-pasted across the individual
``test_*.py`` modules in this package; consolidated here so there is a single
implementation of each.
"""

import time

# Polling budget / cadence for wait_verdicts.
_POLL_BUDGET_S = 5.0
_POLL_INTERVAL_S = 0.25


def rule_packets(policy_client, rule_id: int) -> int:
    stats = policy_client.get_rule_stats(rule_id=rule_id, direction="egress")
    if not stats.rules or not stats.rules[0].stats:
        return 0
    return stats.rules[0].stats.packets


def policy_drops(policy_client, interface: str) -> int:
    return policy_client.get_stats(
        interface, direction="egress"
    ).global_stats.policy_drops


def wait_verdicts(policy_client, baseline: int, want: int) -> int:
    deadline = time.monotonic() + _POLL_BUDGET_S
    last = baseline
    while time.monotonic() < deadline:
        last = policy_client.get_flow_verdicts(direction="egress").active_verdicts
        if last >= baseline + want:
            return last
        time.sleep(_POLL_INTERVAL_S)
    return last


def find_verdict_by_src_port(policy_client, src_port: int, direction: str = "egress"):
    """Return the cached verdict entry for ``src_port``, or None if absent."""
    for entry in policy_client.list_flow_verdicts(direction=direction):
        if entry.src_port == src_port:
            return entry
    return None


def wait_for_verdict_entry(
    policy_client,
    src_port: int,
    direction: str = "egress",
    budget_s: float = _POLL_BUDGET_S,
):
    """Poll the cache until an entry for ``src_port`` appears; return it or None."""
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        entry = find_verdict_by_src_port(policy_client, src_port, direction)
        if entry is not None:
            return entry
        time.sleep(_POLL_INTERVAL_S)
    return None


def wait_for_verdict_evicted(
    policy_client,
    src_port: int,
    direction: str = "egress",
    budget_s: float = 700.0,
) -> bool:
    """Poll until the entry for ``src_port`` is gone (evicted). Returns True if so.

    SNI/QUIC verdicts carry the 10-minute SNI_VERDICT_TTL_NS / QUIC_VERDICT_TTL_NS
    (deliberately long: the verdict is keyed by the 5-tuple but decided by the SNI
    hostname, so a reused 5-tuple must time out rather than mis-apply). The evictor
    sweeps every 30 s, so an un-refreshed flow disappears within ~TTL + one sweep
    (~630 s). The default budget allows for that plus margin.
    """
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        if find_verdict_by_src_port(policy_client, src_port, direction) is None:
            return True
        time.sleep(2.0)
    return False
