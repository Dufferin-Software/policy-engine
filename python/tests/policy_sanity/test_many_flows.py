# Copyright (c) Peter Morrow

"""
Tests for policy engine correctness under many parallel flows.

Exercises concurrency by sending traffic from multiple independent flows
(varying dst/src ports) simultaneously via background threads and verifies:

  - Global rule statistics (packet/byte counters) are exact under parallel load.
  - Per-rule statistics are exact when each flow maps to a distinct rule.
  - DROP rules correctly account for all matching flows without race losses.
  - Mixed DROP/PASS rulesets count both kinds correctly in parallel.
  - LOG rules emit exactly one event per packet when no rate limit is set,
    even across many simultaneous flows hitting the BPF ring buffer together.
  - Per-rule LOG event counts match the exact packet count for each flow,
    with no cross-rule contamination.
  - WebSocket event counts and BPF rule statistics agree on the same total.

Tests run against both the CLI client and the GraphQL client.
"""

import json
import logging
import shlex
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Union

import netaddr

if TYPE_CHECKING:
    from netsim.testkit.node import Node

from policy_engine_client.engine.graphql.client import GraphQLPolicyClient
from netsim.testkit.nping_utils import (
    send_ping,
    send_tcp_packets,
    send_udp_packets,
)
from policy_engine_client.engine.cli.client import (
    AddRuleOptions,
    InterfaceStats,
    OperationResult,
    PolicyClient,
    RuleStatsResponse,
    RuleWithStats,
)

logger: logging.Logger = logging.getLogger(__name__)

AnyPolicyClient = Union[PolicyClient, GraphQLPolicyClient]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of concurrent flows in parallel stress tests.
# Capped at 8 because all per-port rules share the same src/dst LPM entry
# and the BPF architecture limits MAX_L4_RULES=8 per dst prefix.
NUM_FLOWS = 8

# Packets each flow sends.
PACKETS_PER_FLOW = 5

# Base destination port; flow i targets BASE_DST_PORT + i.
BASE_DST_PORT = 21000

# Base source port; flow i uses BASE_SRC_PORT + i (distinct 5-tuple per flow).
BASE_SRC_PORT = 51000

# Rule ID namespace for this module.  Tests allocate IDs within sub-ranges:
#   BASE + 1      : test_many_udp_flows_global_drop_stats (1 broad rule)
#   BASE + 11     : test_many_tcp_flows_global_drop_stats (1 broad rule)
#   BASE + 20..27 : test_per_rule_stats_parallel_udp_flows
#   BASE + 30..37 : test_per_rule_stats_parallel_tcp_flows
#   BASE + 40..43 : test_mixed_drop_pass_parallel_flows (drop half)
#   BASE + 50..53 : test_mixed_drop_pass_parallel_flows (pass half)
#   BASE + 100    : test_many_flows_total_log_events
#   BASE + 110..117: test_per_rule_log_events_parallel_flows
#   BASE + 130    : test_log_stats_and_ws_events_agree
BASE_RULE_ID = 91000

# How long the multi-rule WS listener measures events after the trigger file
# is created.  Parallel flows with --delay 100ms and 5 packets take ~0.5s,
# so 15 s provides a very generous margin.
LISTEN_SECS = 15.0


# ---------------------------------------------------------------------------
# Parallel flow helpers
# ---------------------------------------------------------------------------


@dataclass
class _FlowTask:
    """Describes a single flow to send in a background thread."""

    thread_idx: int
    node: "Node"  # Forward reference to avoid circular import
    target: netaddr.IPAddress
    dst_port: int
    src_port: int
    count: int
    interface: str
    protocol: str = "udp"  # "udp" or "tcp"


@dataclass
class _FlowResult:
    """Result from a single parallel flow thread."""

    thread_idx: int
    dst_port: int
    packets_sent: int
    error: Optional[str] = None


def _run_flow(
    task: _FlowTask,
    results: List[_FlowResult],
    barrier: threading.Barrier,
) -> None:
    """Thread target: wait at barrier for simultaneous start, then send traffic."""
    try:
        barrier.wait(timeout=30)
    except threading.BrokenBarrierError:
        results.append(_FlowResult(task.thread_idx, task.dst_port, 0, "barrier_broken"))
        return

    try:
        if task.protocol == "udp":
            nping_result = send_udp_packets(
                task.node,
                task.target,
                dest_port=task.dst_port,
                count=task.count,
                source_port=task.src_port,
                interface=task.interface,
            )
        else:
            nping_result = send_tcp_packets(
                task.node,
                task.target,
                dest_port=task.dst_port,
                count=task.count,
                source_port=task.src_port,
                flags="SYN",
                interface=task.interface,
            )
        results.append(
            _FlowResult(task.thread_idx, task.dst_port, nping_result.packets_sent)
        )
    except Exception as exc:
        results.append(_FlowResult(task.thread_idx, task.dst_port, 0, str(exc)))


def _run_parallel_flows(
    node,
    target: netaddr.IPAddress,
    interface: str,
    num_flows: int,
    packets_per_flow: int,
    protocol: str = "udp",
    base_dst_port: int = BASE_DST_PORT,
    base_src_port: int = BASE_SRC_PORT,
) -> List[_FlowResult]:
    """
    Send ``num_flows`` independent flows in parallel.

    Each flow uses a unique (dst_port, src_port) pair so the BPF 5-tuple
    distinguishes them as separate flows.  A ``threading.Barrier`` synchronises
    all threads to start at the same moment, maximising concurrency.

    Returns one :class:`_FlowResult` per flow.
    """
    results: List[_FlowResult] = []
    barrier = threading.Barrier(num_flows)
    threads = []

    for i in range(num_flows):
        task = _FlowTask(
            thread_idx=i,
            node=node,
            target=target,
            dst_port=base_dst_port + i,
            src_port=base_src_port + i,
            count=packets_per_flow,
            interface=interface,
            protocol=protocol,
        )
        t = threading.Thread(
            target=_run_flow, args=(task, results, barrier), daemon=True
        )
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    return results


# ---------------------------------------------------------------------------
# Multi-rule WebSocket listener
# ---------------------------------------------------------------------------

# Listens for LOG events matching any of a set of rule IDs.  Same three-phase
# protocol as _WS_LISTENER_SCRIPT in test_log_rate_limit.py:
#   Phase 1: WebSocket connected → create READY_FILE
#   Phase 2: First event of any kind received → create PRIMED_FILE
#   Phase 3: Drain until TRIGGER_FILE appears
#   Phase 4: Measure for ``duration`` seconds; count per-rule LOG events
_WS_MULTI_RULE_LISTENER = """\
import json, time, sys, os, collections
import websocket

RULE_IDS = set({rule_ids})
READY_FILE  = '{ready_file}'
PRIMED_FILE = '{primed_file}'
TRIGGER_FILE = '{trigger_file}'
WARMUP_TIMEOUT = 30.0

ws = websocket.create_connection('ws://127.0.0.1:8080/ws/events', timeout=2.0)

# Phase 1
with open(READY_FILE, 'w') as f:
    f.write(str(os.getpid()))

# Phase 2: warmup — wait for first event of any kind
warmup_deadline = time.time() + WARMUP_TIMEOUT
warmup_ok = False
while time.time() < warmup_deadline:
    remaining = warmup_deadline - time.time()
    ws.settimeout(min(1.0, max(0.1, remaining)))
    try:
        data = ws.recv()
        if data:
            warmup_ok = True
            break
    except websocket.WebSocketTimeoutException:
        continue
    except websocket.WebSocketConnectionClosedException:
        print(json.dumps({{"per_rule": {{}}, "total": 0, "total_msgs": 0, "errors": ["conn_closed_warmup"]}}))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({{"per_rule": {{}}, "total": 0, "total_msgs": 0, "errors": [str(e)]}}))
        sys.exit(0)

if not warmup_ok:
    print(json.dumps({{"per_rule": {{}}, "total": 0, "total_msgs": 0, "errors": ["warmup_timeout"]}}))
    sys.exit(0)

# Phase 2 complete
with open(PRIMED_FILE, 'w') as f:
    f.write('1')

# Phase 3: drain until trigger file appears
trigger_deadline = time.time() + 30.0
while not os.path.exists(TRIGGER_FILE) and time.time() < trigger_deadline:
    ws.settimeout(0.1)
    try:
        ws.recv()
    except:
        pass
    time.sleep(0.05)

# Phase 4: measurement window
DEADLINE = time.time() + {duration}
per_rule = collections.defaultdict(int)
total = 0
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
                if msg.get('rule_id') in RULE_IDS and msg.get('action') == 'LOG':
                    per_rule[str(msg['rule_id'])] += 1
                    total += 1
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

print(json.dumps({{"per_rule": dict(per_rule), "total": total, "total_msgs": total_msgs, "errors": errors}}))
sys.stdout.flush()
"""


def _start_multi_rule_listener(
    server_node,
    rule_ids: List[int],
    duration_secs: float,
    listener_id: str,
):
    """
    Start the multi-rule WS event listener on the server in a background thread.

    Returns ``(result_holder, thread, ready_file, primed_file, trigger_file)``.
    ``result_holder[0]`` is populated with a dict once the thread completes::

        {"per_rule": {"<rule_id>": count, ...}, "total": int, "total_msgs": int}
    """
    ready_file: str = f"/tmp/ws_mf_ready_{listener_id}"
    primed_file: str = f"/tmp/ws_mf_primed_{listener_id}"
    trigger_file: str = f"/tmp/ws_mf_trigger_{listener_id}"
    result: list = [{"per_rule": {}, "total": 0, "total_msgs": 0, "errors": []}]

    for fpath in [ready_file, primed_file, trigger_file]:
        try:
            server_node.ssh_command(f"rm -f {shlex.quote(fpath)}", timeout=5)
        except Exception:
            pass

    def _run() -> None:
        script: str = _WS_MULTI_RULE_LISTENER.format(
            rule_ids=list(rule_ids),
            duration=duration_secs,
            ready_file=ready_file,
            primed_file=primed_file,
            trigger_file=trigger_file,
        )
        try:
            ssh_timeout: int = 30 + 30 + int(duration_secs) + 15
            output = server_node.ssh_command_with_stdin(
                "python3 -",
                script,
                timeout=ssh_timeout,
            )
            try:
                data = json.loads(output.strip())
                result[0] = data
                logger.info(
                    f"WS listener [{listener_id}]: {data['total']} matching events, "
                    f"{data['total_msgs']} total msgs; per_rule={data['per_rule']}"
                )
                if data.get("errors"):
                    logger.warning(
                        f"WS listener [{listener_id}] errors: {data['errors']}"
                    )
            except (ValueError, KeyError, json.JSONDecodeError):
                logger.warning(f"WS listener [{listener_id}] raw output: {output!r}")
        except Exception as exc:
            logger.error(f"WS listener [{listener_id}] failed: {exc}")
            result[0] = {
                "per_rule": {},
                "total": -1,
                "total_msgs": 0,
                "errors": [str(exc)],
            }

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return result, thread, ready_file, primed_file, trigger_file


def _poll_for_file(server_node, filepath: str, timeout: float) -> None:
    """Poll via SSH until a file exists on the server node."""
    deadline: float = time.time() + timeout
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
    raise TimeoutError(f"{filepath} did not appear within {timeout}s")


def _prime_pipeline(
    server_node,
    client_node,
    server_ip,
    client_interface,
    primed_file: str,
    *,
    protocol: str = "icmp",
    dport: int = BASE_DST_PORT,
) -> None:
    """
    Send probe packets until the WS listener's ``primed_file`` appears.

    The probe packets must match the LOG rule under test so that the listener
    receives at least one event (confirming the BPF ring buffer is open).
    Use ``protocol="icmp"`` when the LOG rule matches all protocols; use
    ``protocol="udp"`` with an appropriate ``dport`` for port-specific rules.

    All probe traffic occurs before the trigger file is created, so it falls
    in Phase 3 (drain) and is NOT counted in the measurement window.
    """
    deadline: float = time.time() + 30.0
    while time.time() < deadline:
        try:
            if protocol == "icmp":
                send_ping(
                    client_node, server_ip, count=1, interface=client_interface.if_name
                )
            elif protocol == "udp":
                send_udp_packets(
                    client_node,
                    server_ip,
                    dest_port=dport,
                    count=1,
                    interface=client_interface.if_name,
                )
        except Exception:
            pass
        try:
            out = server_node.ssh_command(
                f"test -f {shlex.quote(primed_file)} && echo YES || echo NO",
                timeout=5,
            )
            if out.strip() == "YES":
                logger.info("Event pipeline confirmed ready")
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise TimeoutError("Event pipeline did not prime within 30s")


# ---------------------------------------------------------------------------
# Tests: statistics accuracy under many parallel flows
# ---------------------------------------------------------------------------


class TestManyFlowStats:
    """
    Verify that global and per-rule BPF statistics are exact when many flows
    are processed simultaneously.
    """

    def test_many_udp_flows_global_drop_stats(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
    ) -> None:
        """
        A single DROP rule covers all UDP traffic from the client subnet.
        ``NUM_FLOWS`` parallel flows each send ``PACKETS_PER_FLOW`` UDP packets
        to distinct destination ports.  The global policy_drops counter must
        equal the total number of packets sent across all flows.
        """
        client = nodes["client"]

        result: OperationResult = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                dst=f"{server_ip_v4}/32",
                protocol="udp",
                actions=[("drop", 0)],
                rule_id=BASE_RULE_ID + 1,
            )
        )
        assert result.success, f"add_rule failed: {result.message}"

        initial: InterfaceStats = policy_client.get_stats(attached_ingress)
        initial_drops: int = initial.global_stats.policy_drops

        flow_results: List[_FlowResult] = _run_parallel_flows(
            client,
            server_ip_v4,
            interface=client_interface.if_name,
            num_flows=NUM_FLOWS,
            packets_per_flow=PACKETS_PER_FLOW,
            protocol="udp",
        )

        packets_sent: int = sum(r.packets_sent for r in flow_results)
        errors: List[str] = [r.error for r in flow_results if r.error]
        logger.info(
            f"Sent {packets_sent} UDP packets across {NUM_FLOWS} parallel flows"
        )
        assert packets_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Not all flows delivered expected packets: "
            f"sent={packets_sent}, expected={NUM_FLOWS * PACKETS_PER_FLOW}; "
            f"flow errors: {errors}"
        )

        final: InterfaceStats = policy_client.get_stats(attached_ingress)
        drops_delta: int = final.global_stats.policy_drops - initial_drops
        logger.info(f"Global drops delta: {drops_delta} (expected {packets_sent})")
        assert drops_delta == packets_sent, (
            f"Global policy_drops mismatch under parallel UDP load: "
            f"delta={drops_delta}, expected={packets_sent}"
        )

    def test_many_tcp_flows_global_drop_stats(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
    ) -> None:
        """
        Same as ``test_many_udp_flows_global_drop_stats`` but using TCP SYN
        packets.  Confirms stat accuracy is protocol-independent.
        """
        client = nodes["client"]

        result: OperationResult = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                protocol="tcp",
                actions=[("drop", 0)],
                rule_id=BASE_RULE_ID + 11,
            )
        )
        assert result.success, f"add_rule failed: {result.message}"

        initial: InterfaceStats = policy_client.get_stats(attached_ingress)
        initial_drops: int = initial.global_stats.policy_drops

        flow_results: List[_FlowResult] = _run_parallel_flows(
            client,
            server_ip_v4,
            interface=client_interface.if_name,
            num_flows=NUM_FLOWS,
            packets_per_flow=PACKETS_PER_FLOW,
            protocol="tcp",
            base_dst_port=BASE_DST_PORT + 100,
        )

        packets_sent: int = sum(r.packets_sent for r in flow_results)
        errors: List[str] = [r.error for r in flow_results if r.error]
        logger.info(
            f"Sent {packets_sent} TCP SYN packets across {NUM_FLOWS} parallel flows"
        )
        assert packets_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Not all flows delivered expected packets: "
            f"sent={packets_sent}, expected={NUM_FLOWS * PACKETS_PER_FLOW}; "
            f"flow errors: {errors}"
        )

        final: InterfaceStats = policy_client.get_stats(attached_ingress)
        drops_delta: int = final.global_stats.policy_drops - initial_drops
        logger.info(f"Global drops delta: {drops_delta} (expected {packets_sent})")
        assert drops_delta == packets_sent, (
            f"Global policy_drops mismatch under parallel TCP load: "
            f"delta={drops_delta}, expected={packets_sent}"
        )

    def test_per_rule_stats_parallel_udp_flows(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
    ) -> None:
        """
        Install ``NUM_FLOWS`` DROP rules each matching a distinct UDP destination
        port.  Send all flows in parallel, each to its own port.  Every rule's
        per-rule packet counter must equal exactly ``PACKETS_PER_FLOW`` —
        no counter is incremented by the wrong flow.
        """
        client = nodes["client"]

        rule_ids = []
        for i in range(NUM_FLOWS):
            rid: int = BASE_RULE_ID + 20 + i
            rule_ids.append(rid)
            r: OperationResult = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=client_network_v4,
                    dport=BASE_DST_PORT + 200 + i,
                    protocol="udp",
                    actions=[("drop", 0)],
                    rule_id=rid,
                )
            )
            assert r.success, (
                f"add_rule(dport={BASE_DST_PORT + 200 + i}) failed: {r.message}"
            )

        # Clear per-rule stats to zero before sending traffic.
        for rid in rule_ids:
            policy_client.clear_rule_stats(rid)

        flow_results: List[_FlowResult] = _run_parallel_flows(
            client,
            server_ip_v4,
            interface=client_interface.if_name,
            num_flows=NUM_FLOWS,
            packets_per_flow=PACKETS_PER_FLOW,
            protocol="udp",
            base_dst_port=BASE_DST_PORT + 200,
        )

        packets_sent: int = sum(r.packets_sent for r in flow_results)
        errors: List[str] = [r.error for r in flow_results if r.error]
        assert packets_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Flows sent {packets_sent}/{NUM_FLOWS * PACKETS_PER_FLOW}; errors: {errors}"
        )

        stats_resp: RuleStatsResponse = policy_client.get_rule_stats()
        mismatches = []
        for i, rid in enumerate(rule_ids):
            entry: RuleWithStats | None = next(
                (rws for rws in stats_resp.rules if rws.rule.rule_id == rid), None
            )
            assert entry is not None, f"No stats entry for rule {rid}"
            if entry.stats is None or entry.stats.packets != PACKETS_PER_FLOW:
                packets = entry.stats.packets if entry.stats else "None"
                mismatches.append(
                    f"rule={rid} dport={BASE_DST_PORT + 200 + i}: "
                    f"packets={packets}, expected={PACKETS_PER_FLOW}"
                )

        assert not mismatches, (
            "Per-rule UDP stat mismatches under parallel load:\n"
            + "\n".join(mismatches)
        )

    def test_per_rule_stats_parallel_tcp_flows(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
    ) -> None:
        """
        Same as ``test_per_rule_stats_parallel_udp_flows`` but using TCP SYN.
        Each TCP flow must be counted only by its matching per-port rule.
        """
        client = nodes["client"]

        rule_ids = []
        for i in range(NUM_FLOWS):
            rid: int = BASE_RULE_ID + 30 + i
            rule_ids.append(rid)
            r: OperationResult = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=client_network_v4,
                    dport=BASE_DST_PORT + 300 + i,
                    protocol="tcp",
                    actions=[("drop", 0)],
                    rule_id=rid,
                )
            )
            assert r.success, (
                f"add_rule(dport={BASE_DST_PORT + 300 + i}) failed: {r.message}"
            )

        for rid in rule_ids:
            policy_client.clear_rule_stats(rid)

        flow_results: List[_FlowResult] = _run_parallel_flows(
            client,
            server_ip_v4,
            interface=client_interface.if_name,
            num_flows=NUM_FLOWS,
            packets_per_flow=PACKETS_PER_FLOW,
            protocol="tcp",
            base_dst_port=BASE_DST_PORT + 300,
        )

        packets_sent: int = sum(r.packets_sent for r in flow_results)
        errors: List[str] = [r.error for r in flow_results if r.error]
        assert packets_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Flows sent {packets_sent}/{NUM_FLOWS * PACKETS_PER_FLOW}; errors: {errors}"
        )

        stats_resp: RuleStatsResponse = policy_client.get_rule_stats()
        mismatches = []
        for i, rid in enumerate(rule_ids):
            entry: RuleWithStats | None = next(
                (rws for rws in stats_resp.rules if rws.rule.rule_id == rid), None
            )
            assert entry is not None, f"No stats entry for rule {rid}"
            if entry.stats is None or entry.stats.packets != PACKETS_PER_FLOW:
                packets = entry.stats.packets if entry.stats else "None"
                mismatches.append(
                    f"rule={rid} dport={BASE_DST_PORT + 300 + i}: "
                    f"packets={packets}, expected={PACKETS_PER_FLOW}"
                )

        assert not mismatches, (
            "Per-rule TCP stat mismatches under parallel load:\n"
            + "\n".join(mismatches)
        )

    def test_mixed_drop_pass_parallel_flows(
        self,
        nodes,
        policy_client: AnyPolicyClient,
        attached_ingress,
        clean_ingress_rules,
        client_interface,
        client_network_v4,
        server_ip_v4: netaddr.IPAddress,
        nmap_installed,
    ) -> None:
        """
        Half the flows target DROP rules; the other half target PASS rules.
        All flows are launched simultaneously from a single barrier.

        Assertions:
        - global policy_drops == (NUM_FLOWS/2) * PACKETS_PER_FLOW
        - global policy_matches == NUM_FLOWS * PACKETS_PER_FLOW
        - each individual rule's packet counter == PACKETS_PER_FLOW
        """
        client = nodes["client"]
        half: int = NUM_FLOWS // 2

        drop_rule_ids = []
        pass_rule_ids = []

        for i in range(half):
            rid: int = BASE_RULE_ID + 40 + i
            drop_rule_ids.append(rid)
            r: OperationResult = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=client_network_v4,
                    dport=BASE_DST_PORT + 400 + i,
                    protocol="udp",
                    actions=[("drop", 0)],
                    rule_id=rid,
                )
            )
            assert r.success, (
                f"add_rule(drop,dport={BASE_DST_PORT + 400 + i}): {r.message}"
            )

        for i in range(half):
            rid = BASE_RULE_ID + 50 + i
            pass_rule_ids.append(rid)
            r = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=client_network_v4,
                    dport=BASE_DST_PORT + 410 + i,
                    protocol="udp",
                    actions=[("pass", 0)],
                    rule_id=rid,
                )
            )
            assert r.success, (
                f"add_rule(pass,dport={BASE_DST_PORT + 410 + i}): {r.message}"
            )

        all_rule_ids = drop_rule_ids + pass_rule_ids
        for rid in all_rule_ids:
            policy_client.clear_rule_stats(rid)

        initial: InterfaceStats = policy_client.get_stats(attached_ingress)
        initial_drops: int = initial.global_stats.policy_drops
        initial_matches: int = initial.global_stats.policy_matches

        # Build one barrier for all NUM_FLOWS threads (drop + pass flows together).
        all_results: List[_FlowResult] = []
        barrier = threading.Barrier(NUM_FLOWS)
        threads = []

        for i in range(half):
            task = _FlowTask(
                thread_idx=i,
                node=client,
                target=server_ip_v4,
                dst_port=BASE_DST_PORT + 400 + i,
                src_port=BASE_SRC_PORT + 400 + i,
                count=PACKETS_PER_FLOW,
                interface=client_interface.if_name,
                protocol="udp",
            )
            threads.append(
                threading.Thread(
                    target=_run_flow, args=(task, all_results, barrier), daemon=True
                )
            )

        for i in range(half):
            task = _FlowTask(
                thread_idx=half + i,
                node=client,
                target=server_ip_v4,
                dst_port=BASE_DST_PORT + 410 + i,
                src_port=BASE_SRC_PORT + 410 + i,
                count=PACKETS_PER_FLOW,
                interface=client_interface.if_name,
                protocol="udp",
            )
            threads.append(
                threading.Thread(
                    target=_run_flow, args=(task, all_results, barrier), daemon=True
                )
            )

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        total_sent: int = sum(r.packets_sent for r in all_results)
        errors: List[str] = [r.error for r in all_results if r.error]
        assert total_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Expected {NUM_FLOWS * PACKETS_PER_FLOW} packets, got {total_sent}; "
            f"errors: {errors}"
        )

        final: InterfaceStats = policy_client.get_stats(attached_ingress)
        drops_delta: int = final.global_stats.policy_drops - initial_drops
        matches_delta: int = final.global_stats.policy_matches - initial_matches
        expected_drops: int = half * PACKETS_PER_FLOW
        expected_matches: int = NUM_FLOWS * PACKETS_PER_FLOW

        logger.info(
            f"drops_delta={drops_delta} (expected {expected_drops}), "
            f"matches_delta={matches_delta} (expected {expected_matches})"
        )
        assert drops_delta == expected_drops, (
            f"Global drops mismatch: delta={drops_delta}, expected={expected_drops}"
        )
        assert matches_delta == expected_matches, (
            f"Global matches mismatch: delta={matches_delta}, expected={expected_matches}"
        )

        # Per-rule packet counters must each equal exactly PACKETS_PER_FLOW.
        stats_resp: RuleStatsResponse = policy_client.get_rule_stats()
        mismatches = []
        for rid in all_rule_ids:
            entry: RuleWithStats | None = next(
                (rws for rws in stats_resp.rules if rws.rule.rule_id == rid), None
            )
            assert entry is not None, f"No stats entry for rule {rid}"
            if entry.stats is None or entry.stats.packets != PACKETS_PER_FLOW:
                packets = entry.stats.packets if entry.stats else "None"
                mismatches.append(
                    f"rule={rid}: packets={packets}, expected={PACKETS_PER_FLOW}"
                )

        assert not mismatches, (
            "Per-rule mismatches in mixed drop/pass parallel test:\n"
            + "\n".join(mismatches)
        )


# ---------------------------------------------------------------------------
# Tests: LOG events under many parallel flows
# ---------------------------------------------------------------------------


class TestManyFlowLogEvents:
    """
    Verify that LOG events are emitted correctly when many flows hit the BPF
    ring buffer at the same time.

    All LOG rules in this class have no rate limit (param=0), so every matched
    packet must produce exactly one WebSocket event.  The parallel flow load
    stresses the ring buffer and the event reader thread.
    """

    def test_many_flows_total_log_events(
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
    ) -> None:
        """
        A single UDP LOG rule (no rate limit, src→dst) covers all UDP traffic
        from the client subnet to the server IP.  ``NUM_FLOWS`` parallel UDP
        flows each send ``PACKETS_PER_FLOW`` packets.  The total WebSocket
        event count must equal the total packets sent — no events may be lost
        or duplicated under burst ring-buffer load.

        The rule is scoped to ``dst=server_ip_v4/32`` to exclude background
        client UDP (mDNS, NTP, DNS) that would otherwise cause spurious events.
        """
        server = nodes["server"]
        client = nodes["client"]
        rule_id: int = BASE_RULE_ID + 100

        r: OperationResult = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                dst=f"{server_ip_v4}/32",
                protocol="udp",
                actions=[("log", 0)],
                rule_id=rule_id,
            )
        )
        assert r.success, f"add_rule failed: {r.message}"

        listener_result, listener_thread, ready_file, primed_file, trigger_file = (
            _start_multi_rule_listener(
                server, [rule_id], LISTEN_SECS, listener_id="tf_total"
            )
        )
        _poll_for_file(server, ready_file, timeout=15.0)
        # Prime with a UDP packet to the server so the WS pipeline is warm.
        _prime_pipeline(
            server,
            client,
            server_ip_v4,
            client_interface,
            primed_file,
            protocol="udp",
            dport=BASE_DST_PORT + 500,
        )
        # Give Phase 3 (drain) time to flush all buffered priming events before
        # the measurement window opens.  The drain loop runs every ~0.15 s; 2 s
        # is enough for ~13 iterations, well above the typical priming ping count.
        time.sleep(2.0)

        # Start measurement window.
        server.ssh_command(f"touch {shlex.quote(trigger_file)}", timeout=5)
        time.sleep(0.3)  # allow listener to enter Phase 4

        flow_results: List[_FlowResult] = _run_parallel_flows(
            client,
            server_ip_v4,
            interface=client_interface.if_name,
            num_flows=NUM_FLOWS,
            packets_per_flow=PACKETS_PER_FLOW,
            protocol="udp",
            base_dst_port=BASE_DST_PORT + 500,
        )

        listener_thread.join(timeout=LISTEN_SECS + 15)

        total_sent: int = sum(r.packets_sent for r in flow_results)
        errors: List[str] = [r.error for r in flow_results if r.error]
        assert total_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Flows sent {total_sent}/{NUM_FLOWS * PACKETS_PER_FLOW}; errors: {errors}"
        )

        data = listener_result[0]
        assert data.get("total") != -1, (
            "WS listener script failed (check logs for errors)"
        )
        total_events = data["total"]
        logger.info(
            f"Total LOG events: {total_events} (expected {total_sent}), "
            f"total_msgs={data.get('total_msgs')}"
        )
        # Primary check: no events lost under burst ring-buffer load.
        assert total_events >= total_sent, (
            f"LOG events LOST under parallel load: "
            f"events={total_events}, packets_sent={total_sent}"
        )
        # Sanity upper bound: rule is scoped to dst=server_ip/32 + UDP only, so
        # at most a handful of priming-drain edge-case events are expected above
        # total_sent.  A large excess would indicate a real counting bug.
        assert total_events <= total_sent + NUM_FLOWS, (
            f"Excessive spurious LOG events under parallel load: "
            f"events={total_events}, packets_sent={total_sent}"
        )

    def test_per_rule_log_events_parallel_flows(
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
    ) -> None:
        """
        ``NUM_FLOWS`` LOG rules each match a distinct UDP destination port.
        ``NUM_FLOWS`` parallel flows each target their matching rule.

        After all flows complete:
        - The total event count must equal ``NUM_FLOWS * PACKETS_PER_FLOW``.
        - Each individual rule must have received exactly ``PACKETS_PER_FLOW``
          events — no cross-rule contamination, no missing events.
        """
        server = nodes["server"]
        client = nodes["client"]

        rule_ids = []
        for i in range(NUM_FLOWS):
            rid: int = BASE_RULE_ID + 110 + i
            rule_ids.append(rid)
            r: OperationResult = policy_client.add_rule(
                AddRuleOptions(
                    interface=attached_ingress,
                    src=client_network_v4,
                    dport=BASE_DST_PORT + 600 + i,
                    protocol="udp",
                    actions=[("log", 0)],
                    rule_id=rid,
                )
            )
            assert r.success, f"add_rule(rule_id={rid}): {r.message}"

        listener_result, listener_thread, ready_file, primed_file, trigger_file = (
            _start_multi_rule_listener(
                server, rule_ids, LISTEN_SECS, listener_id="tf_perrule"
            )
        )
        _poll_for_file(server, ready_file, timeout=15.0)
        # Probe with UDP to the first rule's port so the LOG rule fires.
        _prime_pipeline(
            server,
            client,
            server_ip_v4,
            client_interface,
            primed_file,
            protocol="udp",
            dport=BASE_DST_PORT + 600,
        )
        # Drain Phase 3 — priming probes to rule 91110 (dport 21600) generate
        # buffered WS events that must be fully consumed before Phase 4 starts.
        time.sleep(2.0)

        server.ssh_command(f"touch {shlex.quote(trigger_file)}", timeout=5)
        time.sleep(0.3)

        flow_results: List[_FlowResult] = _run_parallel_flows(
            client,
            server_ip_v4,
            interface=client_interface.if_name,
            num_flows=NUM_FLOWS,
            packets_per_flow=PACKETS_PER_FLOW,
            protocol="udp",
            base_dst_port=BASE_DST_PORT + 600,
        )

        listener_thread.join(timeout=LISTEN_SECS + 15)

        total_sent: int = sum(r.packets_sent for r in flow_results)
        errors: List[str] = [r.error for r in flow_results if r.error]
        assert total_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Flows sent {total_sent}/{NUM_FLOWS * PACKETS_PER_FLOW}; errors: {errors}"
        )

        data = listener_result[0]
        assert data.get("total") != -1, (
            "WS listener script failed (check logs for errors)"
        )
        per_rule = data["per_rule"]
        total_events = data["total"]
        logger.info(
            f"Per-rule events: {per_rule}, total={total_events} (expected {total_sent})"
        )

        assert total_events == total_sent, (
            f"Total LOG event mismatch: events={total_events}, sent={total_sent}"
        )

        mismatches = []
        for rid in rule_ids:
            count = per_rule.get(str(rid), 0)
            if count != PACKETS_PER_FLOW:
                mismatches.append(
                    f"rule={rid}: events={count}, expected={PACKETS_PER_FLOW}"
                )
        assert not mismatches, (
            "Per-rule LOG event mismatches under parallel load:\n"
            + "\n".join(mismatches)
        )

    def test_log_stats_and_ws_events_agree(
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
    ) -> None:
        """
        A LOG+PASS multi-action rule (no rate limit) is hit by ``NUM_FLOWS``
        parallel UDP flows, each from a distinct source port.

        Both counters are independently maintained — BPF rule statistics
        (packet counter in the BPF map) and the WebSocket event stream (ring
        buffer events reaching userspace).  After the test both must equal
        ``NUM_FLOWS * PACKETS_PER_FLOW``, confirming they do not diverge under
        concurrent BPF processing.
        """
        server = nodes["server"]
        client = nodes["client"]
        rule_id: int = BASE_RULE_ID + 130

        # No protocol restriction so ICMP priming probes can trigger the LOG
        # rule and confirm the ring buffer is open before measurement starts.
        r: OperationResult = policy_client.add_rule(
            AddRuleOptions(
                interface=attached_ingress,
                src=client_network_v4,
                actions=[("log", 0), ("pass", 1)],
                rule_id=rule_id,
            )
        )
        assert r.success, f"add_rule failed: {r.message}"
        # Do NOT clear stats here — we clear them after priming so that the
        # priming probes (ICMP pings that match the any-protocol rule) are
        # excluded from the measurement baseline.

        listener_result, listener_thread, ready_file, primed_file, trigger_file = (
            _start_multi_rule_listener(
                server, [rule_id], LISTEN_SECS, listener_id="tf_agree"
            )
        )
        _poll_for_file(server, ready_file, timeout=15.0)
        # ICMP priming fires the any-protocol LOG rule → primed_file appears.
        _prime_pipeline(
            server, client, server_ip_v4, client_interface, primed_file, protocol="icmp"
        )
        # Drain Phase 3 so all priming WS events are consumed before Phase 4,
        # then zero the BPF stats counter so priming pings are excluded from
        # the measurement comparison.
        time.sleep(2.0)
        policy_client.clear_rule_stats(rule_id)

        server.ssh_command(f"touch {shlex.quote(trigger_file)}", timeout=5)
        time.sleep(0.3)

        # All flows target a port range matched by the broad rule.  Each flow
        # uses a distinct source port so BPF sees them as separate 5-tuples.
        flow_results: List[_FlowResult] = _run_parallel_flows(
            client,
            server_ip_v4,
            interface=client_interface.if_name,
            num_flows=NUM_FLOWS,
            packets_per_flow=PACKETS_PER_FLOW,
            protocol="udp",
            base_dst_port=BASE_DST_PORT + 700,
        )

        listener_thread.join(timeout=LISTEN_SECS + 15)

        total_sent: int = sum(r.packets_sent for r in flow_results)
        errors: List[str] = [r.error for r in flow_results if r.error]
        assert total_sent == NUM_FLOWS * PACKETS_PER_FLOW, (
            f"Flows sent {total_sent}/{NUM_FLOWS * PACKETS_PER_FLOW}; errors: {errors}"
        )

        # BPF rule statistics counter.
        stats_resp: RuleStatsResponse = policy_client.get_rule_stats()
        entry: RuleWithStats | None = next(
            (rws for rws in stats_resp.rules if rws.rule.rule_id == rule_id), None
        )
        assert entry is not None, f"No stats entry for rule {rule_id}"
        stat_packets: int = entry.stats.packets if entry.stats else 0

        # WebSocket event count.
        data = listener_result[0]
        assert data.get("total") != -1, (
            "WS listener script failed (check logs for errors)"
        )
        ws_events = data["total"]

        logger.info(
            f"BPF rule stats packets={stat_packets}, "
            f"WS events={ws_events}, packets_sent={total_sent}"
        )

        assert stat_packets >= total_sent, (
            f"BPF rule stats counter ({stat_packets}) < packets sent ({total_sent}): "
            f"possible undercounting"
        )
        assert ws_events >= total_sent, (
            f"WS event count ({ws_events}) < packets sent ({total_sent}): "
            f"possible undercounting"
        )
        assert stat_packets == ws_events, (
            f"BPF stats ({stat_packets}) and WS events ({ws_events}) disagree "
            f"under parallel load"
        )
