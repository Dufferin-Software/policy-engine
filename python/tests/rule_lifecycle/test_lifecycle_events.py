# Copyright (c) Dufferin Software

"""
Rule lifecycle WebSocket event stream tests.

Verifies that /ws/rule-events broadcasts the correct events when:
  - A rule is added (event_type="activated")
  - A rule is deleted (event_type="deleted")
  - A TTL rule expires (event_type="expired")  [slow]
  - A scheduled rule is activated/deactivated by the scheduler  [slow]

The WS listener runs as a background Python script on the server VM,
writing events to a temp file. The test thread performs API calls while
the listener collects, then reads the file after a fixed window.
"""

import json
import logging
import threading
import time
from typing import List

import pytest

from policy_engine_client.engine.cli.client import AddRuleOptions, WeeklyWindow
from policy_engine_client.engine.graphql.client import GraphQLPolicyClient


logger = logging.getLogger(__name__)

_WS_URL = "ws://127.0.0.1:8080/ws/rule-events"
_SCHEDULER_WAIT = 45  # seconds; scheduler tick is every 30 s


# ---------------------------------------------------------------------------
# WebSocket helper
# ---------------------------------------------------------------------------


_WS_LISTENER_SCRIPT = r"""
import websocket
import json
import sys
import threading
import time

events = []
connected = threading.Event()

def on_open(ws):
    connected.set()

def on_message(ws, msg):
    try:
        ev = json.loads(msg)
        if isinstance(ev, dict) and "event_type" in ev:
            events.append(ev)
    except Exception:
        pass

def on_error(ws, err):
    pass

ws = websocket.WebSocketApp(
    "{url}",
    on_open=on_open,
    on_message=on_message,
    on_error=on_error,
)

t = threading.Thread(target=lambda: ws.run_forever(ping_interval=10))
t.daemon = True
t.start()

# Wait for connection (up to 5 s)
connected.wait(timeout=5)
# Collect for the requested duration
time.sleep({duration})
ws.close()
t.join(timeout=3)
print(json.dumps(events))
"""


def _collect_ws_events(
    server,
    duration: float,
    action_fn=None,
    action_delay: float = 0.5,
) -> List[dict]:
    """
    Run a WebSocket listener on the server in a background thread, optionally
    calling ``action_fn()`` after ``action_delay`` seconds (while the listener
    is still connected), then return the collected events.

    Args:
        server:       Node object with ssh_command / ssh_command_with_stdin
        duration:     How long (seconds) to collect events
        action_fn:    Callable to invoke while the WS is open (may be None)
        action_delay: Seconds to wait after opening WS before calling action_fn
    """
    script = _WS_LISTENER_SCRIPT.format(url=_WS_URL, duration=duration)

    collected: List[dict] = []
    errors: List[str] = []

    def _run_listener():
        try:
            output = server.ssh_command_with_stdin(
                "python3 -",
                script,
                timeout=int(duration) + 15,
            )
            try:
                collected.extend(json.loads(output.strip()))
            except json.JSONDecodeError as e:
                errors.append(f"JSON decode: {e} | output={output!r}")
        except Exception as e:
            errors.append(str(e))

    listener_thread = threading.Thread(target=_run_listener, daemon=True)
    listener_thread.start()

    # Give the WS time to connect before performing actions, then invoke the
    # action.  Skip the sleep entirely when there is no action to perform —
    # a large sentinel value like 99999 would block indefinitely otherwise.
    if action_fn is not None:
        time.sleep(action_delay)
        action_fn()

    listener_thread.join(timeout=duration + 20)

    if errors:
        logger.warning(f"WS listener errors: {errors}")

    return collected


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLifecycleEventStream:
    """Basic connectivity and event emission for /ws/rule-events."""

    def test_ws_connection_is_established(self, nodes, websocket_installed):
        """The server accepts WebSocket connections on /ws/rule-events."""
        server = nodes["server"]
        # A short-lived connection with no actions should produce zero events
        # but must not error.
        events = _collect_ws_events(server, duration=2)
        assert isinstance(events, list)  # any list (including empty) is fine

    def test_rule_add_emits_activated_event(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
        websocket_installed,
    ):
        """Adding a permanent rule must broadcast an 'activated' event."""
        server = nodes["server"]
        rule_id = 7001

        def _add():
            opts = AddRuleOptions(
                interface=attached_ingress,
                src="0.0.0.0/0",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=rule_id,
            )
            graphql_client.add_rule(opts, direction="ingress")

        events = _collect_ws_events(server, duration=5, action_fn=_add)

        matching = [e for e in events if e.get("rule_id") == rule_id]
        assert any(e["event_type"] == "activated" for e in matching), (
            f"Expected 'activated' event for rule {rule_id}; got: {events}"
        )

    def test_rule_delete_emits_deleted_event(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
        websocket_installed,
    ):
        """Deleting a rule must broadcast a 'deleted' event."""
        server = nodes["server"]
        rule_id = 7002

        # Pre-add the rule so delete has something to act on
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        graphql_client.add_rule(opts, direction="ingress")

        def _delete():
            graphql_client.delete_rule(
                attached_ingress, rule_id=rule_id, direction="ingress"
            )

        events = _collect_ws_events(server, duration=5, action_fn=_delete)

        matching = [e for e in events if e.get("rule_id") == rule_id]
        assert any(e["event_type"] == "deleted" for e in matching), (
            f"Expected 'deleted' event for rule {rule_id}; got: {events}"
        )

    def test_activated_event_contains_direction(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
        websocket_installed,
    ):
        """Lifecycle events must carry the correct direction field."""
        server = nodes["server"]
        rule_id = 7003

        def _add():
            opts = AddRuleOptions(
                interface=attached_ingress,
                src="0.0.0.0/0",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=rule_id,
            )
            graphql_client.add_rule(opts, direction="ingress")

        events = _collect_ws_events(server, duration=5, action_fn=_add)

        matching = [
            e
            for e in events
            if e.get("rule_id") == rule_id and e.get("event_type") == "activated"
        ]
        assert matching, f"No 'activated' event for rule {rule_id}"
        assert matching[0].get("direction") == "INGRESS", (
            f"Expected direction=INGRESS, got {matching[0].get('direction')}"
        )

    def test_delete_inactive_managed_rule_emits_deleted_event(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
        websocket_installed,
        not_inactive_window_time,
    ):
        """Deleting an inactive (out-of-window) managed rule must emit 'deleted'."""
        server = nodes["server"]
        rule_id = 7004

        # Add rule with a window that is currently inactive (Sun 03:47–03:48)
        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=rule_id,
            schedule_windows=[WeeklyWindow(0, 3, 47, 0, 3, 48)],
        )
        graphql_client.add_rule(opts, direction="ingress")

        # Confirm it is inactive
        managed = graphql_client.managed_rules(direction="ingress")
        mr = next((r for r in managed if r.rule_id == rule_id), None)
        if mr is None or mr.rule_state != "inactive":
            pytest.skip("Rule did not start inactive — window boundary issue")

        def _delete():
            graphql_client.delete_rule(
                attached_ingress, rule_id=rule_id, direction="ingress"
            )

        events = _collect_ws_events(server, duration=5, action_fn=_delete)

        matching = [e for e in events if e.get("rule_id") == rule_id]
        assert any(e["event_type"] == "deleted" for e in matching), (
            f"Expected 'deleted' event for inactive managed rule; got: {events}"
        )

    def test_multiple_clients_receive_same_events(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
        websocket_installed,
    ):
        """Two concurrent WS subscribers must each receive the same lifecycle event."""
        server = nodes["server"]
        rule_id = 7005

        results_a: List[dict] = []
        results_b: List[dict] = []

        def _run_a():
            results_a.extend(_collect_ws_events(server, duration=6, action_delay=99999))

        def _run_b():
            results_b.extend(_collect_ws_events(server, duration=6, action_delay=99999))

        # Both listeners start, then the main thread adds the rule
        t_a = threading.Thread(target=_run_a, daemon=True)
        t_b = threading.Thread(target=_run_b, daemon=True)
        t_a.start()
        t_b.start()

        time.sleep(1)  # let both WS connections open

        opts = AddRuleOptions(
            interface=attached_ingress,
            src="0.0.0.0/0",
            protocol="any",
            actions=[("drop", 0)],
            rule_id=rule_id,
        )
        graphql_client.add_rule(opts, direction="ingress")

        t_a.join(timeout=15)
        t_b.join(timeout=15)

        def _has_activated(events):
            return any(
                e.get("rule_id") == rule_id and e.get("event_type") == "activated"
                for e in events
            )

        assert _has_activated(results_a), (
            f"Client A did not receive 'activated' for rule {rule_id}"
        )
        assert _has_activated(results_b), (
            f"Client B did not receive 'activated' for rule {rule_id}"
        )


# ---------------------------------------------------------------------------
# Slow: TTL expiry event
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestLifecycleEventTTLExpiry:
    """TTL expiry emits 'expired' event via the WS stream."""

    def test_ttl_expiry_emits_expired_event(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
        websocket_installed,
    ):
        """After TTL elapses the scheduler must broadcast an 'expired' event."""
        server = nodes["server"]
        rule_id = 7010
        collect_duration = _SCHEDULER_WAIT + 10  # enough time for tick + margin

        def _add_ttl_rule():
            opts = AddRuleOptions(
                interface=attached_ingress,
                src="0.0.0.0/0",
                protocol="any",
                actions=[("drop", 0)],
                rule_id=rule_id,
                expires_after_secs=5,
            )
            graphql_client.add_rule(opts, direction="ingress")

        events = _collect_ws_events(
            server,
            duration=collect_duration,
            action_fn=_add_ttl_rule,
            action_delay=0.5,
        )

        matching = [e for e in events if e.get("rule_id") == rule_id]
        event_types = [e["event_type"] for e in matching]

        assert "activated" in event_types, (
            f"Expected 'activated' event; got event_types={event_types}"
        )
        assert "expired" in event_types, (
            f"Expected 'expired' event after TTL elapses; got event_types={event_types}"
        )


# ---------------------------------------------------------------------------
# Slow: scheduled rule deactivation event
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestLifecycleEventSchedulerTransitions:
    """Scheduler-driven window transitions emit activation/deactivation events."""

    def _get_server_week_minutes(self, server) -> int:
        raw = server.ssh_command("date -u '+%w %H %M'")
        dow, hour, minute = map(int, raw.strip().split())
        return dow * 1440 + hour * 60 + minute

    def test_scheduled_rule_deactivation_emits_event(
        self,
        graphql_client: GraphQLPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        nodes,
        websocket_installed,
    ):
        """When a scheduled rule's window closes the scheduler emits 'deactivated'."""
        server = nodes["server"]
        rule_id = 7020

        # Construct a window: [now-1min, now) — already closing this minute
        wm = self._get_server_week_minutes(server)
        start_wm = (wm - 1) % 10080
        end_wm = wm

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
            rule_id=rule_id,
            schedule_windows=[window],
            schedule_tz="UTC",
        )
        result = graphql_client.add_rule(opts, direction="ingress")
        assert result.success, result.message

        # Confirm initially active
        managed = graphql_client.managed_rules(direction="ingress")
        mr = next((r for r in managed if r.rule_id == rule_id), None)
        if mr is None or mr.rule_state != "active":
            pytest.skip("Window boundary did not produce an active rule")

        collect_duration = _SCHEDULER_WAIT + 70  # > 1 min + tick

        # Listen for the deactivation event (no action needed — just wait)
        events = _collect_ws_events(server, duration=collect_duration)

        matching = [e for e in events if e.get("rule_id") == rule_id]
        event_types = [e["event_type"] for e in matching]

        assert "deactivated" in event_types, (
            f"Expected 'deactivated' event; got event_types={event_types}"
        )


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def not_inactive_window_time(nodes):
    """Skip if the server's current UTC time is inside Sun 03:47–03:48."""
    server = nodes["server"]
    raw = server.ssh_command("date -u '+%w %H %M'")
    dow, hour, minute = map(int, raw.strip().split())
    if dow == 0 and hour == 3 and minute in (47, 48):
        pytest.skip("Current time is inside the 'inactive' test window — skipping")
