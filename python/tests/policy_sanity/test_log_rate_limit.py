# Copyright (c) Dufferin Software

"""
Tests for the LOG action rate-limit parameter.

The LOG action accepts an optional rate-limit parameter (in milliseconds) that
suppresses repeated events for the same flow within the rate-limit window.
Rule statistics (packet/byte counters) are always updated regardless of rate
limiting — only event emission to the ring buffer is suppressed.

Tests verify:
- Rules with a rate-limit param are accepted and stored correctly (round-trip).
- Traffic is never dropped by a LOG rule, even when rate limiting is active.
- Rapid packets within the rate-limit window produce only one log event.
- Packets with no rate limit (param=0) produce one event per packet.

Tests run against both the CLI client and the GraphQL client.
"""

import logging
import shlex
import threading
import time
from typing import Union

import netaddr

from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.nping_utils import send_ping
from policy_engine_client.engine.cli.client import (
    AddRuleOptions,
    PolicyAction,
    PolicyClient,
)

logger = logging.getLogger(__name__)

AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]

# Rate limit used in behavioral tests (ms).  Large enough that all packets in
# a single nping burst land within the window, but small enough that the test
# doesn't have to wait long between bursts.
RATE_LIMIT_MS = 3000

# How long the WS listener listens for events (must be < RATE_LIMIT_MS/1000
# so that the second burst is NOT captured in the same window).
LISTEN_SECS = 2.0


# ---------------------------------------------------------------------------
# WebSocket event helper
# ---------------------------------------------------------------------------

# WebSocket client script run on the server node via SSH.
# Uses the websocket-client library (python3-websocket) for reliable
# WebSocket communication.  Connects to the policy-engine event stream,
# then goes through three phases:
#
#   1. **Ready** — WS connected; creates READY_FILE so the test can start
#      sending probe traffic.
#   2. **Warmup** — Waits for the first event of ANY kind (proves the BPF
#      ring buffer has been opened by the event reader thread).  Creates
#      PRIMED_FILE so the test knows the pipeline is operational.
#   3. **Measurement** — Waits for TRIGGER_FILE, then counts LOG events
#      matching ``rule_id`` for ``duration`` seconds.
#
# This three-phase protocol eliminates the race between WebSocket
# connectivity and BPF ring buffer readiness.
_WS_LISTENER_SCRIPT = """\
import json, time, sys, os
import websocket

RULE_ID = {rule_id}
READY_FILE = '{ready_file}'
PRIMED_FILE = '{primed_file}'
TRIGGER_FILE = '{trigger_file}'
WARMUP_TIMEOUT = 30.0

ws = websocket.create_connection(
    'ws://127.0.0.1:8080/ws/events',
    timeout=2.0,
)

# Phase 1: Signal that the WebSocket connection is established.
with open(READY_FILE, 'w') as f:
    f.write(str(os.getpid()))

# Phase 2: Warmup — wait for the first event of ANY kind.  This confirms
# that the event reader thread has successfully opened the BPF ring buffer
# maps (which may be retried on a 5 s interval after server start).
warmup_deadline = time.time() + WARMUP_TIMEOUT
warmup_ok = False
while time.time() < warmup_deadline:
    remaining = warmup_deadline - time.time()
    if remaining <= 0:
        break
    ws.settimeout(min(1.0, max(0.1, remaining)))
    try:
        data = ws.recv()
        if data:
            warmup_ok = True
            break
    except websocket.WebSocketTimeoutException:
        continue
    except websocket.WebSocketConnectionClosedException:
        result = {{"count": 0, "total_msgs": 0, "errors": ["connection_closed_during_warmup"]}}
        print(json.dumps(result))
        sys.exit(0)
    except Exception as e:
        result = {{"count": 0, "total_msgs": 0, "errors": [str(e)]}}
        print(json.dumps(result))
        sys.exit(0)

if not warmup_ok:
    result = {{"count": 0, "total_msgs": 0, "errors": ["warmup_timeout"]}}
    print(json.dumps(result))
    sys.exit(0)

# Signal that the event pipeline is confirmed working.
with open(PRIMED_FILE, 'w') as f:
    f.write('1')

# Phase 3: Wait for the trigger file, draining any buffered events.
trigger_deadline = time.time() + 30.0
while not os.path.exists(TRIGGER_FILE) and time.time() < trigger_deadline:
    ws.settimeout(0.1)
    try:
        ws.recv()
    except:
        pass
    time.sleep(0.05)

# Phase 4: Measurement — count matching LOG events for the requested duration.
DEADLINE = time.time() + {duration}

count = 0
total_msgs = 0
errors = []
while time.time() < DEADLINE:
    remaining = DEADLINE - time.time()
    if remaining <= 0:
        break
    ws.settimeout(min(0.5, remaining))
    try:
        data = ws.recv()
        if data:
            total_msgs += 1
            try:
                msg = json.loads(data)
                if msg.get('rule_id') == RULE_ID and msg.get('action') == 'LOG':
                    count += 1
            except (ValueError, TypeError):
                pass
    except websocket.WebSocketTimeoutException:
        continue
    except websocket.WebSocketConnectionClosedException:
        errors.append('connection_closed')
        break
    except Exception as e:
        errors.append(str(e))
        break

ws.close()
for f in [READY_FILE, PRIMED_FILE, TRIGGER_FILE]:
    try:
        os.unlink(f)
    except OSError:
        pass
# Output JSON with diagnostics — the test parses this.
result = {{"count": count, "total_msgs": total_msgs, "errors": errors}}
print(json.dumps(result))
sys.stdout.flush()
"""


def start_ws_listener(server_node, rule_id: int, duration_secs: float):
    """
    Start the WS event listener on the server in a background thread.

    Returns ``(result_holder, thread, ready_file, primed_file, trigger_file)``
    where:

    - ``result_holder`` is a single-element list; ``result_holder[0]`` will
      contain the event count once the thread completes.
    - ``thread`` is the :class:`threading.Thread` running the listener.
    - ``ready_file`` — created once the WebSocket connection is established.
    - ``primed_file`` — created once the first BPF event is received
      (confirms the ring buffer is open).
    - ``trigger_file`` — the test creates this file to start the measurement
      window.

    The caller should:

    1. Poll for ``ready_file`` (WS connected).
    2. Send probe traffic until ``primed_file`` appears (ring buffer open).
    3. Optionally sleep (e.g. for rate-limit expiry).
    4. Create ``trigger_file`` to start measurement.
    5. Send real test traffic.
    """
    ready_file = f"/tmp/ws_ready_{rule_id}"
    primed_file = f"/tmp/ws_primed_{rule_id}"
    trigger_file = f"/tmp/ws_trigger_{rule_id}"
    result: list[int] = [0]

    # Remove stale files from a previous run.
    for f in [ready_file, primed_file, trigger_file]:
        try:
            server_node.ssh_command(f"rm -f {shlex.quote(f)}", timeout=5)
        except Exception:
            pass

    def _run():
        import json as _json

        script = _WS_LISTENER_SCRIPT.format(
            rule_id=rule_id,
            duration=duration_secs,
            ready_file=ready_file,
            primed_file=primed_file,
            trigger_file=trigger_file,
        )
        try:
            # Timeout must cover warmup (up to 30s) + trigger wait + measurement.
            ssh_timeout = 30 + 30 + int(duration_secs) + 15
            output = server_node.ssh_command_with_stdin(
                "python3 -",
                script,
                timeout=ssh_timeout,
            )
            try:
                data = _json.loads(output.strip())
                result[0] = data["count"]
                if data.get("total_msgs"):
                    logger.info(
                        f"WS listener: {data['count']} matching events "
                        f"out of {data['total_msgs']} total messages"
                    )
                if data.get("errors"):
                    logger.warning(f"WS listener errors: {data['errors']}")
            except (ValueError, KeyError, _json.JSONDecodeError):
                logger.warning(f"WS listener output: {output!r}")
                # Fall back to plain integer parse
                try:
                    result[0] = int(output.strip())
                except ValueError:
                    pass
        except Exception as e:
            logger.error(f"WS listener failed: {e}")
            stderr = getattr(e, "stderr", None)
            if stderr:
                logger.error(f"WS listener stderr: {stderr}")
            result[0] = -1

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return result, thread, ready_file, primed_file, trigger_file


def _poll_for_file(server_node, filepath: str, timeout: float):
    """Poll (via SSH) until a file appears on the server node."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            out = server_node.ssh_command(
                f"test -f {shlex.quote(filepath)} && echo YES || echo NO",
                timeout=5,
            )
            if out.strip() == "YES":
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise TimeoutError(f"File {filepath} did not appear within {timeout}s")


def wait_for_ws_ready(server_node, ready_file: str, timeout: float = 10.0):
    """Poll until the listener's ready-signal file appears (WS connected)."""
    _poll_for_file(server_node, ready_file, timeout)


def wait_for_event_pipeline(
    server_node,
    client_node,
    server_ip,
    client_interface,
    primed_file: str,
    timeout: float = 30.0,
):
    """Send probe pings until the WS listener confirms events are flowing.

    The WS listener script creates ``primed_file`` once it receives its first
    BPF event.  This function sends one ICMP echo every 0.5 s until that file
    appears, confirming the BPF ring buffer is open and the event reader is
    polling.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Send a single probe ping.
        try:
            send_ping(
                client_node,
                server_ip,
                count=1,
                interface=client_interface.if_name,
            )
        except Exception:
            pass
        # Check if the listener has seen an event.
        try:
            out = server_node.ssh_command(
                f"test -f {shlex.quote(primed_file)} && echo YES || echo NO",
                timeout=5,
            )
            if out.strip() == "YES":
                logger.info("Event pipeline confirmed ready (primed file appeared)")
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError(
        f"Event pipeline did not become ready within {timeout}s "
        f"(waiting for {primed_file})"
    )


# ---------------------------------------------------------------------------
# Config round-trip tests (no traffic needed)
# ---------------------------------------------------------------------------


class TestLogRateLimitConfig:
    """
    Verify that LOG rules with a rate-limit param are accepted by the server
    and that the param value survives the round-trip through the BPF map and
    back out via the GraphQL rules query.
    """

    def test_log_rule_with_rate_limit_accepted(
        self, policy_client: AnyPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """A LOG rule with a non-zero rate-limit param must be accepted."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="icmp",
            actions=[("log", 0, RATE_LIMIT_MS)],
            rule_id=88001,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

    def test_log_rule_with_rate_limit_param_stored(
        self, policy_client: AnyPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """The rate-limit param must round-trip correctly through the BPF map."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="icmp",
            actions=[("log", 0, RATE_LIMIT_MS)],
            rule_id=88002,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        rules = policy_client.list_rules()
        rule = next((r for r in rules if r.rule_id == 88002), None)
        assert rule is not None, "Rule 88002 not found after add"

        log_action = next(
            (a for a in rule.actions if a.action == PolicyAction.LOG), None
        )
        assert log_action is not None, "LOG action not found on rule"
        assert log_action.param == RATE_LIMIT_MS, (
            f"Expected param={RATE_LIMIT_MS}ms, got {log_action.param}"
        )

    def test_log_rule_no_rate_limit_param_zero(
        self, policy_client: AnyPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """A LOG rule without a rate-limit param must store param=0."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="icmp",
            actions=[("log", 0)],  # 2-tuple: no param
            rule_id=88003,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        rules = policy_client.list_rules()
        rule = next((r for r in rules if r.rule_id == 88003), None)
        assert rule is not None, "Rule 88003 not found after add"

        log_action = next(
            (a for a in rule.actions if a.action == PolicyAction.LOG), None
        )
        assert log_action is not None, "LOG action not found on rule"
        assert log_action.param == 0, (
            f"Expected param=0 (no rate limit), got {log_action.param}"
        )

    def test_log_rate_limit_multi_action_rule(
        self, policy_client: AnyPolicyClient, attached_ingress, clean_ingress_rules
    ):
        """A LOG+PASS multi-action rule with a rate-limit param is accepted and stored."""
        options = AddRuleOptions(
            interface=attached_ingress,
            src="10.0.0.0/8",
            protocol="tcp",
            dport=443,
            actions=[("log", 0, 5000), ("pass", 1)],
            rule_id=88004,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        rules = policy_client.list_rules()
        rule = next((r for r in rules if r.rule_id == 88004), None)
        assert rule is not None, "Rule 88004 not found after add"

        log_action = next(
            (a for a in rule.actions if a.action == PolicyAction.LOG), None
        )
        assert log_action is not None, "LOG action not found on rule"
        assert log_action.param == 5000, (
            f"Expected LOG param=5000ms, got {log_action.param}"
        )

        pass_action = next(
            (a for a in rule.actions if a.action == PolicyAction.PASS), None
        )
        assert pass_action is not None, "PASS action not found on rule"
        assert pass_action.param == 0, f"Expected PASS param=0, got {pass_action.param}"


# ---------------------------------------------------------------------------
# Traffic behaviour tests (require a live attachment + traffic)
# ---------------------------------------------------------------------------


class TestLogRateLimitBehavior:
    """
    Verify rate-limit behaviour under actual packet traffic.

    These tests attach the XDP program, add LOG rules, send traffic, and check:
    - Traffic still passes (LOG never drops).
    - Rule packet counters always reflect the real traffic volume.
    - The WebSocket event stream emits fewer events when rate limiting is active.
    """

    def test_rate_limited_log_does_not_drop_traffic(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
    ):
        """A rate-limited LOG rule must never drop packets."""
        client = nodes["client"]

        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("log", 0, RATE_LIMIT_MS), ("pass", 1)],
            rule_id=88010,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        count = 10
        ping_result = send_ping(
            client, server_ip_v4, count=count, interface=client_interface.if_name
        )
        logger.info(
            f"Ping: sent={ping_result.packets_sent}, received={ping_result.packets_received}"
        )
        assert ping_result.packets_received == count, (
            f"Rate-limited LOG rule dropped traffic: "
            f"sent={ping_result.packets_sent}, received={ping_result.packets_received}"
        )

    def test_rate_limited_log_counts_all_packets_in_stats(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
    ):
        """
        Rule statistics must count every matched packet even when events are
        suppressed by rate limiting.
        """
        client = nodes["client"]

        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("log", 0, RATE_LIMIT_MS)],
            rule_id=88011,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        policy_client.clear_rule_stats(88011)

        count = 8
        send_ping(client, server_ip_v4, count=count, interface=client_interface.if_name)

        stats_resp = policy_client.get_rule_stats()
        rule_stats = next(
            (rws.stats for rws in stats_resp.rules if rws.rule.rule_id == 88011), None
        )
        assert rule_stats is not None, "No stats entry for rule 88011"
        logger.info(f"Rule stats: packets={rule_stats.packets}, expected={count}")
        assert rule_stats.packets == count, (
            f"Expected {count} packets in stats (rate limiting must not affect counters), "
            f"got {rule_stats.packets}"
        )

    def test_rate_limit_suppresses_events_within_window(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
        websocket_installed,
    ):
        """
        Sending multiple packets within the rate-limit window must produce only
        one log event, not one per packet.
        """
        server = nodes["server"]
        client = nodes["client"]

        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("log", 0, RATE_LIMIT_MS)],
            rule_id=88012,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        # Start the WS listener and confirm the event pipeline is operational
        # before sending test traffic.  The warmup probe pings may start the
        # rate-limit timer, so we sleep for the window to expire afterwards.
        event_count, listener, ready_file, primed_file, trigger_file = (
            start_ws_listener(server, 88012, LISTEN_SECS)
        )
        wait_for_ws_ready(server, ready_file)
        wait_for_event_pipeline(
            server,
            client,
            server_ip_v4,
            client_interface,
            primed_file,
        )

        # Let the rate-limit window from warmup probes expire.
        time.sleep(RATE_LIMIT_MS / 1000 + 0.5)

        # Signal the listener to start the measurement window.
        server.ssh_command(f"touch {shlex.quote(trigger_file)}", timeout=5)
        # Give the listener time to detect the trigger file and enter Phase 4
        # before sending test traffic.  The Phase 3 drain loop polls every ~0.15 s,
        # so 0.3 s guarantees Python is in the measurement window before pings arrive.
        time.sleep(0.3)

        # Send 5 packets within ~500 ms — well inside the 3 s rate-limit window
        send_ping(client, server_ip_v4, count=5, interface=client_interface.if_name)

        listener.join(timeout=LISTEN_SECS + 10)

        logger.info(
            f"Events in {LISTEN_SECS}s window with {RATE_LIMIT_MS}ms rate limit: "
            f"{event_count[0]} (expected 1)"
        )
        assert event_count[0] != -1, "WS listener script failed (check logs for stderr)"
        assert event_count[0] == 1, (
            f"Expected exactly 1 event with {RATE_LIMIT_MS}ms rate limit, "
            f"got {event_count[0]}"
        )

    def test_no_rate_limit_emits_event_per_packet(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
        websocket_installed,
    ):
        """
        Without rate limiting (param=0) every matched packet must produce its
        own log event.
        """
        server = nodes["server"]
        client = nodes["client"]

        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("log", 0)],  # no rate limit
            rule_id=88013,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        packet_count = 5
        event_count, listener, ready_file, primed_file, trigger_file = (
            start_ws_listener(server, 88013, LISTEN_SECS)
        )
        wait_for_ws_ready(server, ready_file)
        wait_for_event_pipeline(
            server,
            client,
            server_ip_v4,
            client_interface,
            primed_file,
        )

        # No rate limit — trigger measurement immediately.
        server.ssh_command(f"touch {shlex.quote(trigger_file)}", timeout=5)
        # Allow Python to detect the trigger and enter Phase 4 before pings arrive.
        time.sleep(0.3)

        send_ping(
            client, server_ip_v4, count=packet_count, interface=client_interface.if_name
        )

        listener.join(timeout=LISTEN_SECS + 10)

        logger.info(
            f"Events in {LISTEN_SECS}s window with no rate limit: "
            f"{event_count[0]} (expected {packet_count})"
        )
        assert event_count[0] != -1, "WS listener script failed (check logs for stderr)"
        assert event_count[0] == packet_count, (
            f"Expected {packet_count} events (one per packet, no rate limit), "
            f"got {event_count[0]}"
        )

    def test_rate_limit_resets_after_window_expires(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
        websocket_installed,
    ):
        """
        After the rate-limit window expires, the next packet must produce a new
        event.  Two bursts separated by more than RATE_LIMIT_MS should yield
        exactly two events total.
        """
        server = nodes["server"]
        client = nodes["client"]

        options = AddRuleOptions(
            interface=attached_ingress,
            src=client_network_v4,
            protocol="icmp",
            actions=[("log", 0, RATE_LIMIT_MS)],
            rule_id=88014,
        )
        result = policy_client.add_rule(options)
        assert result.success, f"add_rule failed: {result.message}"

        total_listen = LISTEN_SECS * 2 + (RATE_LIMIT_MS / 1000) + 1
        event_count, listener, ready_file, primed_file, trigger_file = (
            start_ws_listener(server, 88014, total_listen)
        )
        wait_for_ws_ready(server, ready_file)
        wait_for_event_pipeline(
            server,
            client,
            server_ip_v4,
            client_interface,
            primed_file,
        )

        # Let the rate-limit window from warmup probes expire.
        time.sleep(RATE_LIMIT_MS / 1000 + 0.5)

        # Signal the listener to start the measurement window.
        server.ssh_command(f"touch {shlex.quote(trigger_file)}", timeout=5)
        # Allow Python to detect the trigger and enter Phase 4 before pings arrive.
        time.sleep(0.3)

        # Burst 1 — produces 1 event, starts the rate-limit clock
        send_ping(client, server_ip_v4, count=3, interface=client_interface.if_name)
        logger.info(
            f"Burst 1 sent; sleeping {RATE_LIMIT_MS}ms for rate limit to expire"
        )

        # Wait for the rate-limit window to expire (with a small margin)
        time.sleep(RATE_LIMIT_MS / 1000)

        # Burst 2 — rate limit has expired, so this produces 1 more event
        send_ping(client, server_ip_v4, count=3, interface=client_interface.if_name)

        listener.join(timeout=total_listen + 10)

        logger.info(
            f"Total events across two bursts separated by >{RATE_LIMIT_MS}ms: "
            f"{event_count[0]} (expected 2)"
        )
        assert event_count[0] != -1, "WS listener script failed (check logs for stderr)"
        assert event_count[0] == 2, (
            f"Expected 2 events (one per burst after rate-limit reset), "
            f"got {event_count[0]}"
        )
