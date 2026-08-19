# Copyright (c) Dufferin Software

"""
Policy Engine client wrapper for test infrastructure.

Provides typed Python objects that mirror the policy-client JSON output.
All interactions with the policy-engine are done via the policy-client CLI.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from ...node import Node

logger = logging.getLogger(__name__)


# ============================================================================
# Enums matching the Rust GraphQL types
# ============================================================================


class PolicyAction(str, Enum):
    """Policy action enum matching GqlPolicyAction."""

    PASS = "Pass"
    DROP = "Drop"
    LOG = "Log"
    NAT = "Nat"
    TAIL_CALL = "TailCall"
    INSPECT = "Inspect"

    @classmethod
    def from_string(cls, value: str) -> "PolicyAction":
        """Convert string to PolicyAction enum (case-insensitive)."""
        value_lower = value.lower()
        mapping = {
            "pass": cls.PASS,
            "drop": cls.DROP,
            "log": cls.LOG,
            "nat": cls.NAT,
            "tailcall": cls.TAIL_CALL,
            "tail_call": cls.TAIL_CALL,
            "inspect": cls.INSPECT,
        }
        if value_lower in mapping:
            return mapping[value_lower]
        raise ValueError(f"Unknown PolicyAction: {value}")


class Protocol(str, Enum):
    """Protocol enum matching GqlProtocol."""

    ANY = "Any"
    TCP = "Tcp"
    UDP = "Udp"
    ICMP = "Icmp"

    @classmethod
    def from_string(cls, value: str) -> "Protocol":
        """Convert string to Protocol enum (case-insensitive)."""
        value_lower = value.lower()
        mapping = {
            "any": cls.ANY,
            "tcp": cls.TCP,
            "udp": cls.UDP,
            "icmp": cls.ICMP,
        }
        if value_lower in mapping:
            return mapping[value_lower]
        raise ValueError(f"Unknown Protocol: {value}")


class IngressMode(str, Enum):
    """Ingress attach mode."""

    AUTO = "auto"
    NATIVE = "native"
    GENERIC = "generic"
    OFFLOAD = "offload"


# Backward compatibility alias
XdpMode = IngressMode


class InspectMode(str, Enum):
    """Inspect/IPS mode enum matching GqlInspectMode."""

    DISABLED = "DISABLED"
    IPS = "IPS"
    IDS = "IDS"

    @classmethod
    def from_string(cls, value: str) -> "InspectMode":
        """Convert string to InspectMode enum (case-insensitive)."""
        mapping = {
            "disabled": cls.DISABLED,
            "off": cls.DISABLED,
            "ips": cls.IPS,
            "ids": cls.IDS,
        }
        if value.lower() in mapping:
            return mapping[value.lower()]
        raise ValueError(f"Unknown InspectMode: {value}")


# ============================================================================
# Data classes matching the Rust JSON output structures
# ============================================================================


@dataclass
class OperationResult:
    """Result of a policy-client operation."""

    success: bool
    message: str

    @classmethod
    def from_json(cls, data: dict) -> "OperationResult":
        return cls(
            success=data.get("success", False),
            message=data.get("message", ""),
        )


@dataclass
class BatchRuleResult:
    """Result for a single rule in a batch operation."""

    index: int
    rule_id: Optional[int]
    success: bool
    error: Optional[str]

    @classmethod
    def from_json(cls, data: dict) -> "BatchRuleResult":
        return cls(
            index=data.get("index", 0),
            rule_id=data.get("ruleId"),
            success=data.get("success", False),
            error=data.get("error"),
        )


@dataclass
class BatchAddRulesResult:
    """Result for batch add rules operation."""

    total: int
    succeeded: int
    failed: int
    success: bool
    message: str
    results: List["BatchRuleResult"]

    @classmethod
    def from_json(cls, data: dict) -> "BatchAddRulesResult":
        results = [BatchRuleResult.from_json(r) for r in data.get("results", [])]
        return cls(
            total=data.get("total", 0),
            succeeded=data.get("succeeded", 0),
            failed=data.get("failed", 0),
            success=data.get("success", False),
            message=data.get("message", ""),
            results=results,
        )


@dataclass
class BatchDeleteRulesResult:
    """Result for batch delete rules operation."""

    total: int
    succeeded: int
    failed: int
    success: bool
    message: str
    results: List[BatchRuleResult]

    @classmethod
    def from_json(cls, data: dict) -> "BatchDeleteRulesResult":
        results = [BatchRuleResult.from_json(r) for r in data.get("results", [])]
        return cls(
            total=data.get("total", 0),
            succeeded=data.get("succeeded", 0),
            failed=data.get("failed", 0),
            success=data.get("success", False),
            message=data.get("message", ""),
            results=results,
        )


@dataclass
class ServerStatus:
    """Server status output."""

    running: bool
    version: str
    uptime_secs: int
    program_attached: bool
    inspect_mode: Optional[str] = None

    @classmethod
    def from_json(cls, data: dict) -> "ServerStatus":
        return cls(
            running=data.get("running", False),
            version=data.get("version", ""),
            uptime_secs=data.get("uptimeSecs", 0),
            program_attached=data.get("programAttached", False),
            inspect_mode=data.get("inspectMode"),
        )


@dataclass
class ServerFeatures:
    """Server compile-time feature flags."""

    suricata: bool
    ipfix: bool = False

    @classmethod
    def from_json(cls, data: dict) -> "ServerFeatures":
        return cls(
            suricata=data.get("suricata", False),
            ipfix=data.get("ipfix", False),
        )


@dataclass
class FlowExportStatus:
    """IPFIX flow export status and configuration."""

    enabled: bool
    collector_host: str
    collector_port: int
    idle_timeout_s: int
    active_timeout_s: int
    flows_exported_total: int
    active_flow_count: int

    @classmethod
    def from_json(cls, data: dict) -> "FlowExportStatus":
        return cls(
            enabled=data.get("enabled", False),
            collector_host=data.get("collectorHost", ""),
            collector_port=data.get("collectorPort", 0),
            idle_timeout_s=data.get("idleTimeoutS", 0),
            active_timeout_s=data.get("activeTimeoutS", 0),
            flows_exported_total=data.get("flowsExportedTotal", 0),
            active_flow_count=data.get("activeFlowCount", 0),
        )


@dataclass
class InterfaceAttachment:
    """Interface attachment info."""

    interface: str
    ifindex: int
    mode: str
    direction: str

    @classmethod
    def from_json(cls, data: dict) -> "InterfaceAttachment":
        return cls(
            interface=data.get("interface", ""),
            ifindex=data.get("ifindex", 0),
            mode=data.get("mode", ""),
            direction=data.get("direction", "ingress"),
        )


@dataclass
class RuleAction:
    """Rule action with priority and optional parameter."""

    action: PolicyAction
    priority: int
    param: int = (
        0  # Action-specific param: for LOG, rate-limit interval in ms (0=no limit)
    )

    @classmethod
    def from_json(cls, data: dict) -> "RuleAction":
        action_str = data.get("action", "Pass")
        return cls(
            action=PolicyAction.from_string(action_str),
            priority=data.get("priority", 0),
            param=data.get("param", 0),
        )


@dataclass
class LpmRule:
    """LPM rule output (IPv4 or IPv6)."""

    rule_id: int
    src_prefix: str
    dst_prefix: str
    sport: int
    dport: int
    protocol: Protocol
    actions: List[RuleAction]
    sni: Optional[str] = None
    quic_version: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    interface: str = ""

    @classmethod
    def from_json(cls, data: dict) -> "LpmRule":
        protocol_str = data.get("protocol", "Any")
        actions_data = data.get("actions", [])
        return cls(
            rule_id=int(data.get("ruleId", 0)),
            src_prefix=data.get("srcPrefix", "0.0.0.0/0"),
            dst_prefix=data.get("dstPrefix", "0.0.0.0/0"),
            sport=data.get("sport", 0),
            dport=data.get("dport", 0),
            protocol=Protocol.from_string(protocol_str),
            actions=[RuleAction.from_json(a) for a in actions_data],
            sni=data.get("sni"),
            quic_version=data.get("quicVersion"),
            src_mac=data.get("srcMac"),
            dst_mac=data.get("dstMac"),
            interface=data.get("interface", ""),
        )

    @property
    def is_ipv6(self) -> bool:
        """Check if this is an IPv6 rule based on prefix format."""
        return ":" in self.src_prefix


@dataclass
class RuleStats:
    """Statistics for a rule."""

    packets: int
    bytes: int
    last_seen_ns: int

    @classmethod
    def from_json(cls, data: dict) -> "RuleStats":
        return cls(
            packets=data.get("packets", 0),
            bytes=data.get("bytes", 0),
            last_seen_ns=data.get("lastSeenNs", 0),
        )


@dataclass
class RuleWithStats:
    """Rule with its statistics."""

    rule: LpmRule
    stats: Optional[RuleStats]

    @classmethod
    def from_json(cls, data: dict) -> "RuleWithStats":
        rule_data = data.get("rule", {})
        stats_data = data.get("stats")
        return cls(
            rule=LpmRule.from_json(rule_data),
            stats=RuleStats.from_json(stats_data) if stats_data else None,
        )


@dataclass
class GlobalStats:
    """Global statistics output."""

    rx_packets: int
    rx_bytes: int
    tx_packets: int
    tx_bytes: int
    policy_matches: int
    policy_drops: int
    policy_pass: int
    policy_redirects: int
    parse_errors: int
    tail_calls: int
    bum_packets: int
    non_ip_unicast: int
    inspect_redirects: int = 0
    fragments: int = 0
    verdict_pass_packets: int = 0
    verdict_pass_bytes: int = 0
    verdict_drop_packets: int = 0
    verdict_drop_bytes: int = 0
    fib_forwarded_packets: int = 0
    fib_forwarded_bytes: int = 0
    fib_fallback_packets: int = 0
    urpf_drop_packets: int = 0
    urpf_drop_bytes: int = 0

    @classmethod
    def from_json(cls, data: dict) -> "GlobalStats":
        return cls(
            rx_packets=data.get("rxPackets", 0),
            rx_bytes=data.get("rxBytes", 0),
            tx_packets=data.get("txPackets", 0),
            tx_bytes=data.get("txBytes", 0),
            policy_matches=data.get("policyMatches", 0),
            policy_drops=data.get("policyDrops", 0),
            policy_pass=data.get("policyPass", 0),
            policy_redirects=data.get("policyRedirects", 0),
            parse_errors=data.get("parseErrors", 0),
            tail_calls=data.get("tailCalls", 0),
            bum_packets=data.get("bumPackets", 0),
            non_ip_unicast=data.get("nonIpUnicast", 0),
            inspect_redirects=data.get("inspectRedirects", 0),
            fragments=data.get("fragments", 0),
            verdict_pass_packets=data.get("verdictPassPackets", 0),
            verdict_pass_bytes=data.get("verdictPassBytes", 0),
            verdict_drop_packets=data.get("verdictDropPackets", 0),
            verdict_drop_bytes=data.get("verdictDropBytes", 0),
            fib_forwarded_packets=data.get("fibForwardedPackets", 0),
            fib_forwarded_bytes=data.get("fibForwardedBytes", 0),
            fib_fallback_packets=data.get("fibFallbackPackets", 0),
            urpf_drop_packets=data.get("urpfDropPackets", 0),
            urpf_drop_bytes=data.get("urpfDropBytes", 0),
        )


@dataclass
class EthertypeStats:
    """Ethertype statistics."""

    ethertype: int
    ethertype_hex: str
    name: str
    packets: int

    @classmethod
    def from_json(cls, data: dict) -> "EthertypeStats":
        return cls(
            ethertype=data.get("ethertype", 0),
            ethertype_hex=data.get("ethertypeHex", ""),
            name=data.get("name", ""),
            packets=data.get("packets", 0),
        )


@dataclass
class InterfaceStats:
    """Combined stats response for an interface."""

    interface: str
    program_attached: bool
    global_stats: GlobalStats
    ethertype_stats: List[EthertypeStats]

    @classmethod
    def from_json(cls, data: dict) -> "InterfaceStats":
        return cls(
            interface=data.get("interface", ""),
            program_attached=data.get("programAttached", False),
            global_stats=GlobalStats.from_json(data.get("globalStats", {})),
            ethertype_stats=[
                EthertypeStats.from_json(e) for e in data.get("ethertypeStats", [])
            ],
        )


@dataclass
class RuleStatsResponse:
    """Response for rule stats query."""

    program_attached: bool
    rules: List[RuleWithStats]

    @classmethod
    def from_json(cls, data: dict) -> "RuleStatsResponse":
        # Handle both single-rule response (with --id) and all-rules response
        if "rules" in data:
            # All rules response: {"programAttached": true, "rules": [...]}
            rules = [RuleWithStats.from_json(r) for r in data.get("rules", [])]
        elif "ruleId" in data and "stats" in data:
            # Single rule response: {"programAttached": true, "ruleId": X, "stats": {...}}
            # Convert to RuleWithStats format
            rule_data = {
                "rule": {"ruleId": data["ruleId"]},
                "stats": data["stats"],
            }
            rules = [RuleWithStats.from_json(rule_data)]
        else:
            rules = []
        return cls(
            program_attached=data.get("programAttached", False),
            rules=rules,
        )


# ============================================================================
# Policy Client class
# ============================================================================


@dataclass
class InspectStatus:
    """Inspect/IPS status output."""

    mode: str
    suricata_running: bool
    mirror_interface: Optional[str]
    mirror_ifindex: Optional[int]
    peer_interface: Optional[str]
    flow_verdict_count: int
    suricata_version: Optional[str] = None
    ruleset_version: Optional[str] = None

    @classmethod
    def from_json(cls, data: dict) -> "InspectStatus":
        return cls(
            mode=data.get("mode", "DISABLED"),
            suricata_running=data.get("suricataRunning", False),
            mirror_interface=data.get("mirrorInterface"),
            mirror_ifindex=data.get("mirrorIfindex"),
            peer_interface=data.get("peerInterface"),
            flow_verdict_count=data.get("flowVerdictCount", 0),
            suricata_version=data.get("suricataVersion"),
            ruleset_version=data.get("rulesetVersion"),
        )


@dataclass
class FlowVerdictStats:
    """Flow verdict statistics."""

    active_verdicts: int

    @classmethod
    def from_json(cls, data: dict) -> "FlowVerdictStats":
        return cls(
            active_verdicts=data.get("activeVerdicts", 0),
        )


@dataclass
class FlowVerdictEntry:
    """A single cached flow verdict entry from ``flowVerdictList``."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    action: str
    expires_ns: str
    expired: bool
    packets: int
    bytes: int

    @classmethod
    def from_json(cls, data: dict) -> "FlowVerdictEntry":
        return cls(
            src_ip=data.get("srcIp", ""),
            dst_ip=data.get("dstIp", ""),
            src_port=data.get("srcPort", 0),
            dst_port=data.get("dstPort", 0),
            protocol=data.get("protocol", ""),
            action=data.get("action", ""),
            expires_ns=data.get("expiresNs", "0"),
            expired=data.get("expired", False),
            packets=data.get("packets", 0),
            bytes=data.get("bytes", 0),
        )


@dataclass
class WeeklyWindow:
    """A half-open weekly time window [start, end).

    day_of_week: 0=Sunday … 6=Saturday
    """

    start_day: int
    start_hour: int
    start_minute: int
    end_day: int
    end_hour: int
    end_minute: int

    def to_cli_spec(self) -> str:
        """Format as CLI --schedule-window argument: 'D:HH:MM-D:HH:MM'."""
        return (
            f"{self.start_day}:{self.start_hour:02d}:{self.start_minute:02d}"
            f"-{self.end_day}:{self.end_hour:02d}:{self.end_minute:02d}"
        )

    def to_graphql(self) -> dict:
        """Format as GraphQL WeeklyWindowInput."""
        return {
            "start": {
                "dayOfWeek": self.start_day,
                "hour": self.start_hour,
                "minute": self.start_minute,
            },
            "end": {
                "dayOfWeek": self.end_day,
                "hour": self.end_hour,
                "minute": self.end_minute,
            },
        }


@dataclass
class ManagedRule:
    """A rule with a TTL or recurring schedule."""

    rule_id: int
    direction: str
    interface: str
    rule_state: str  # "active" | "inactive"
    expires_at_ms: Optional[int]  # epoch-ms, None for scheduled/permanent
    schedule_windows: Optional[List[WeeklyWindow]]
    schedule_timezone: Optional[str]

    @classmethod
    def from_json(cls, data: dict) -> "ManagedRule":
        windows = None
        tz = None
        sched = data.get("schedule")
        if sched:
            tz = sched.get("timezone")
            raw_windows = sched.get("windows", [])
            windows = []
            for w in raw_windows:
                s = w.get("start", {})
                e = w.get("end", {})
                windows.append(
                    WeeklyWindow(
                        start_day=s.get("dayOfWeek", 0),
                        start_hour=s.get("hour", 0),
                        start_minute=s.get("minute", 0),
                        end_day=e.get("dayOfWeek", 0),
                        end_hour=e.get("hour", 0),
                        end_minute=e.get("minute", 0),
                    )
                )
        raw_expires = data.get("expiresAtMs")
        return cls(
            rule_id=int(data.get("ruleId", 0)),
            direction=data.get("direction", "INGRESS"),
            interface=data.get("interface", ""),
            rule_state=data.get("ruleState", "active"),
            expires_at_ms=int(raw_expires) if raw_expires is not None else None,
            schedule_windows=windows,
            schedule_timezone=tz,
        )


@dataclass
class AddRuleOptions:
    """Options for adding a rule."""

    # Rules are scoped per-interface per-direction. Callers must set `interface`
    # to the name of an attached interface (e.g., "eth0") before invoking the
    # client; the server resolves this to an ifindex.
    interface: str = ""
    src: Optional[str] = None
    dst: Optional[str] = None
    sport: int = 0
    dport: int = 0
    protocol: str = "any"
    actions: List[tuple] = field(
        default_factory=list
    )  # [(action, priority)] or [(action, priority, param_ms)]
    rule_id: Optional[int] = None
    sni: Optional[str] = None
    quic_version: Optional[str] = None
    src_mac: Optional[str] = None  # "aa:bb:cc:dd:ee:ff" or None for any
    dst_mac: Optional[str] = None  # "aa:bb:cc:dd:ee:ff" or None for any
    # Lifecycle fields (mutually exclusive)
    expires_after_secs: Optional[int] = None
    schedule_tz: Optional[str] = None
    schedule_windows: List[WeeklyWindow] = field(default_factory=list)


class PolicyClient:
    """
    Wrapper for the policy-client CLI.

    Executes policy-client commands on a remote node via SSH and parses JSON output.
    """

    def __init__(
        self,
        node: Node,
        server_url: str = "http://127.0.0.1:8080/graphql",
        tls_ca_cert: Optional[str] = None,
        tls_insecure: bool = False,
    ):
        """
        Initialize the policy client wrapper.

        Args:
            node: Node where policy-engine is running
            server_url: URL of the policy-engine GraphQL server
            tls_ca_cert: Path (on the remote node) to a PEM CA cert to trust
            tls_insecure: Skip TLS certificate verification (dev only)
        """
        self.node = node
        self.server_url = server_url
        self.tls_ca_cert = tls_ca_cert
        self.tls_insecure = tls_insecure

    def _run_command(self, args: List[str], timeout: int = 30) -> str:
        """
        Run a policy-client command and return JSON output.

        Args:
            args: Command arguments (after 'policy-client')
            timeout: Command timeout in seconds

        Returns:
            Raw JSON output string

        Raises:
            subprocess.CalledProcessError: If command fails without JSON output
        """
        cmd_parts = ["policy-client", "--json", f"--server={self.server_url}"]
        if self.tls_ca_cert:
            cmd_parts += [f"--tls-ca-cert={self.tls_ca_cert}"]
        if self.tls_insecure:
            cmd_parts += ["--tls-insecure"]
        cmd_parts += args
        cmd = " ".join(cmd_parts)
        logger.debug(f"[{self.node.name}] Running: {cmd}")

        try:
            output = self.node.ssh_command(cmd, timeout=timeout)
            return output
        except subprocess.CalledProcessError as e:
            # Check if we got JSON output despite the error (e.g., validation errors)
            # The policy-client returns exit code 2 for clap errors but still outputs JSON
            # CalledProcessError has 'output' (alias for stdout) when capture_output=True
            stdout = e.output or e.stdout or ""
            if stdout and stdout.strip():
                try:
                    # Verify it's valid JSON before returning
                    json.loads(stdout.strip())
                    logger.debug(
                        f"[{self.node.name}] Command failed with exit {e.returncode} but returned JSON"
                    )
                    return stdout.strip()
                except json.JSONDecodeError:
                    pass
            # Re-raise if we didn't get valid JSON output
            raise

    def _run_command_json(self, args: List[str], timeout: int = 30) -> dict:
        """Run command and parse JSON output."""
        output = self._run_command(args, timeout)
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output: {output}")
            raise ValueError(f"Invalid JSON from policy-client: {e}") from e

    # ========================================================================
    # Status commands
    # ========================================================================

    def status(self) -> ServerStatus:
        """Get server status."""
        data = self._run_command_json(["status"])
        return ServerStatus.from_json(data)

    def server_features(self) -> ServerFeatures:
        """Get server compile-time feature flags."""
        data = self._run_command_json(["show", "features"])
        return ServerFeatures.from_json(data)

    # ========================================================================
    # Attach/Detach commands
    # ========================================================================

    def attach_ingress(
        self, interface: str, mode: IngressMode = IngressMode.AUTO
    ) -> OperationResult:
        """
        Attach ingress program to an interface.

        Args:
            interface: Interface name
            mode: Ingress attach mode

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(
            ["attach", "ingress", "--interface", interface, "--mode", mode.value]
        )
        return OperationResult.from_json(data)

    def detach_ingress(self, interface: str) -> OperationResult:
        """
        Detach ingress program from an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["detach", "ingress", "--interface", interface])
        return OperationResult.from_json(data)

    def attach_egress(self, interface: str) -> OperationResult:
        """
        Attach egress program to an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["attach", "egress", "--interface", interface])
        return OperationResult.from_json(data)

    def detach_egress(self, interface: str) -> OperationResult:
        """
        Detach egress program from an interface.

        Args:
            interface: Interface name

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["detach", "egress", "--interface", interface])
        return OperationResult.from_json(data)

    def detach_all(self) -> OperationResult:
        """
        Detach all programs (both ingress and egress).

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["detach", "all"])
        return OperationResult.from_json(data)

    # ========================================================================
    # Rule commands
    # ========================================================================

    def add_rule(
        self, options: AddRuleOptions, direction: str = "ingress", timeout: int = 10
    ) -> OperationResult:
        """
        Add a policy rule.

        Args:
            options: Rule configuration options
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        args = [
            "rule",
            "add",
            "--interface",
            options.interface,
            "--direction",
            direction,
        ]

        if options.src:
            args.extend(["--src", options.src])
        if options.dst:
            args.extend(["--dst", options.dst])
        if options.sport:
            args.extend(["--sport", str(options.sport)])
        if options.dport:
            args.extend(["--dport", str(options.dport)])
        if options.protocol:
            args.extend(["--proto", options.protocol])
        if options.rule_id is not None:
            args.extend(["--id", str(options.rule_id)])

        if options.sni:
            args.extend(["--sni", options.sni])

        if options.quic_version:
            args.extend(["--quic-version", options.quic_version])

        if options.src_mac:
            args.extend(["--src-mac", options.src_mac])

        if options.dst_mac:
            args.extend(["--dst-mac", options.dst_mac])

        if options.expires_after_secs is not None:
            args.extend(["--expires-after-secs", str(options.expires_after_secs)])

        if options.schedule_windows:
            if options.schedule_tz:
                args.extend(["--schedule-tz", options.schedule_tz])
            for window in options.schedule_windows:
                args.extend(["--schedule-window", window.to_cli_spec()])

        # Add actions (support 2-tuple (action, priority) or 3-tuple (action, priority, param_ms))
        for entry in options.actions:
            action, priority = entry[0], entry[1]
            param_ms = entry[2] if len(entry) >= 3 else 0
            action_str = (
                action.value if isinstance(action, PolicyAction) else str(action)
            )
            if param_ms:
                args.extend(["--action", f"{action_str}:{priority}:{param_ms}"])
            else:
                args.extend(["--action", f"{action_str}:{priority}"])

        data = self._run_command_json(args, timeout=timeout)
        return OperationResult.from_json(data)

    def delete_rule(
        self,
        interface: str,
        rule_id: int,
        direction: str = "ingress",
    ) -> OperationResult:
        """
        Delete a policy rule by ID.

        Args:
            interface: Interface the rule is scoped to (required)
            rule_id: Rule ID to delete (required)
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        args = [
            "rule",
            "delete",
            "--interface",
            interface,
            "--direction",
            direction,
            "--id",
            str(rule_id),
        ]

        data = self._run_command_json(args)
        return OperationResult.from_json(data)

    def list_rules(
        self, direction: str = "ingress", interface: Optional[str] = None
    ) -> List[LpmRule]:
        """
        List all policy rules.

        Args:
            direction: Traffic direction ("ingress" or "egress")
            interface: Optional interface name to filter results

        Returns:
            List of LpmRule objects
        """
        args = ["rule", "list", "--direction", direction]
        if interface is not None:
            args.extend(["--interface", interface])
        data = self._run_command_json(args)
        if isinstance(data, list):
            return [LpmRule.from_json(r) for r in data]
        return []

    def flush_rules(
        self, direction: str = "ingress", interface: Optional[str] = None
    ) -> OperationResult:
        """
        Flush policy rules scoped to a single (interface, direction).

        Args:
            direction: Traffic direction ("ingress" or "egress")
            interface: Interface name to flush. If omitted, the helper
                enumerates every interface attached in this direction and
                flushes each — convenient for tests that just want a clean
                slate on a single-interface node.

        Returns:
            OperationResult indicating success/failure
        """
        if interface is None:
            ifaces = [
                a.interface
                for a in self.list_interfaces()
                if a.direction.lower() == direction.lower()
            ]
            total = 0
            for iface in ifaces:
                r = self.flush_rules(direction=direction, interface=iface)
                if not r.success:
                    return r
                total += 1
            return OperationResult(
                success=True,
                message=f"Flushed {direction} rules on {total} interface(s)",
            )

        args = [
            "rule",
            "flush",
            "--direction",
            direction,
            "--interface",
            interface,
        ]
        data = self._run_command_json(args)
        return OperationResult.from_json(data)

    def managed_rules(
        self, direction: str = "ingress", interface: Optional[str] = None
    ) -> List[ManagedRule]:
        """
        List rules with a TTL or schedule (managed rules).

        Args:
            direction: Traffic direction ("ingress" or "egress")
            interface: Optional interface name to filter results

        Returns:
            List of ManagedRule objects
        """
        args = ["rule", "managed-rules", "--direction", direction]
        if interface is not None:
            args.extend(["--interface", interface])
        data = self._run_command_json(args)
        if isinstance(data, list):
            return [ManagedRule.from_json(r) for r in data]
        return []

    # ========================================================================
    # Show commands
    # ========================================================================

    def list_interfaces(self) -> List[InterfaceAttachment]:
        """
        List attached interfaces.

        Returns:
            List of InterfaceAttachment objects
        """
        data = self._run_command_json(["show", "interfaces"])
        if isinstance(data, list):
            return [InterfaceAttachment.from_json(i) for i in data]
        return []

    def get_stats(self, interface: str, direction: str = "ingress") -> InterfaceStats:
        """
        Get statistics for an interface.

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            InterfaceStats object
        """
        data = self._run_command_json(
            ["show", "stats", "--interface", interface, "--direction", direction]
        )
        return InterfaceStats.from_json(data)

    def get_rule_stats(
        self, rule_id: Optional[int] = None, direction: str = "ingress"
    ) -> RuleStatsResponse:
        """
        Get rule statistics.

        Args:
            rule_id: Optional rule ID (all rules if not specified)
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            RuleStatsResponse object
        """
        args = ["show", "rule-stats", "--direction", direction]
        if rule_id is not None:
            args.extend(["--id", str(rule_id)])
        data = self._run_command_json(args)
        return RuleStatsResponse.from_json(data)

    # ========================================================================
    # Config commands
    # ========================================================================

    def set_default_action(
        self, action: PolicyAction, direction: str = "ingress", interface: str = ""
    ) -> OperationResult:
        """
        Set the default action for unmatched packets.

        Args:
            action: Default action
            direction: Traffic direction ("ingress" or "egress")
            interface: Interface name (required by server)

        Returns:
            OperationResult indicating success/failure
        """
        action_str = action.value.lower()
        args = [
            "config",
            "default-action",
            "--interface",
            interface,
            "--action",
            action_str,
            "--direction",
            direction,
        ]
        data = self._run_command_json(args)
        return OperationResult.from_json(data)

    def register_tail_call(
        self, slot: int, program: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Register a tail call program.

        Args:
            slot: Slot number (0-63)
            program: Program name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(
            [
                "config",
                "tail-call",
                "--slot",
                str(slot),
                "--program",
                program,
                "--direction",
                direction,
            ]
        )
        return OperationResult.from_json(data)

    # ========================================================================
    # Clear stats commands
    # ========================================================================

    def clear_global_stats(
        self, interface: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear global statistics for an interface.

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(
            [
                "clear-stats",
                "global",
                "--interface",
                interface,
                "--direction",
                direction,
            ]
        )
        return OperationResult.from_json(data)

    def clear_interface_stats(
        self, interface: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear all statistics for an interface (global + ethertype).

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(
            [
                "clear-stats",
                "interface",
                "--interface",
                interface,
                "--direction",
                direction,
            ]
        )
        return OperationResult.from_json(data)

    def clear_rule_stats(
        self, rule_id: Optional[int] = None, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear rule statistics.

        Args:
            rule_id: Optional rule ID (clears all rules if not specified)
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        args = ["clear-stats", "rule", "--direction", direction]
        if rule_id is not None:
            args.extend(["--id", str(rule_id)])
        data = self._run_command_json(args)
        return OperationResult.from_json(data)

    def clear_ethertype_stats(
        self, interface: str, direction: str = "ingress"
    ) -> OperationResult:
        """
        Clear ethertype statistics for an interface.

        Args:
            interface: Interface name
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(
            [
                "clear-stats",
                "ethertype",
                "--interface",
                interface,
                "--direction",
                direction,
            ]
        )
        return OperationResult.from_json(data)

    def clear_all_stats(self) -> OperationResult:
        """
        Clear all statistics.

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["clear-stats", "all"])
        return OperationResult.from_json(data)

    # ========================================================================
    # Inspect/IPS commands
    # ========================================================================

    def get_inspect_status(self) -> InspectStatus:
        """
        Get inspect/IPS mode status.

        Returns:
            InspectStatus with mode, suricata state, and verdict counts
        """
        data = self._run_command_json(["inspect", "status"])
        return InspectStatus.from_json(data)

    def configure_inspect(self, mode: str) -> OperationResult:
        """
        Enable inspect mode (IPS or IDS).

        Args:
            mode: Inspect mode string ("ips" or "ids")

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["inspect", "enable", "--mode", mode.lower()])
        return OperationResult.from_json(data)

    def disable_inspect(self) -> OperationResult:
        """
        Disable inspect mode.

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["inspect", "disable"])
        return OperationResult.from_json(data)

    def get_flow_verdicts(self, direction: str = "ingress") -> FlowVerdictStats:
        """
        Get flow verdict statistics for a direction.

        Args:
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            FlowVerdictStats with active verdict count
        """
        data = self._run_command_json(["inspect", "verdicts", "--direction", direction])
        return FlowVerdictStats.from_json(data)

    def list_flow_verdicts(
        self, direction: str = "ingress", limit: Optional[int] = None
    ) -> List[FlowVerdictEntry]:
        """
        List individual cached flow verdict entries for a direction.

        Entries come back soonest-expiring first, capped at ``limit``
        (default 1000 server-side when ``None``).

        Args:
            direction: Traffic direction ("ingress" or "egress")
            limit: Max entries to return (None = CLI default of 1000)

        Returns:
            List of FlowVerdictEntry
        """
        args = ["inspect", "verdicts", "--direction", direction, "--list"]
        if limit is not None:
            args += ["--limit", str(limit)]
        data = self._run_command_json(args)
        return [FlowVerdictEntry.from_json(e) for e in data]

    def clear_flow_verdicts(self, direction: str = "ingress") -> OperationResult:
        """
        Clear all flow verdicts for a direction.

        Args:
            direction: Traffic direction ("ingress" or "egress")

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(
            ["inspect", "clear-verdicts", "--direction", direction]
        )
        return OperationResult.from_json(data)

    # ========================================================================
    # Suricata commands
    # ========================================================================

    def suricata_status(self) -> OperationResult:
        """
        Get Suricata service status.

        Returns:
            OperationResult where success=True means Suricata is running
        """
        data = self._run_command_json(["suricata", "status"])
        return OperationResult.from_json(data)

    def deploy_suricata_rules(
        self, rules_text: str, filename: str = "custom.rules"
    ) -> OperationResult:
        """
        Deploy Suricata rules to the server.

        Writes rules_text to a temporary file on the remote node, then
        deploys it via the CLI.

        Args:
            rules_text: Suricata rules content
            filename: Target filename in the Suricata rules directory

        Returns:
            OperationResult indicating success/failure
        """
        import time

        tmp_path = f"/tmp/pe_rules_{int(time.time())}.rules"
        # Write rules to temp file on the remote node
        self.node.ssh_command_with_stdin(f"cat > {tmp_path}", rules_text, timeout=10)
        try:
            data = self._run_command_json(
                ["suricata", "deploy-rules", "--file", tmp_path, "--name", filename]
            )
            return OperationResult.from_json(data)
        finally:
            self.node.ssh_command(f"rm -f {tmp_path}", timeout=5)

    def reload_suricata_rules(self) -> OperationResult:
        """
        Reload Suricata rules.

        Returns:
            OperationResult indicating success/failure
        """
        data = self._run_command_json(["suricata", "reload"])
        return OperationResult.from_json(data)


# ============================================================================
# Convenience functions
# ============================================================================


def create_policy_client(node: Node) -> PolicyClient:
    """
    Create a PolicyClient for a node.

    Args:
        node: Node where policy-engine is running

    Returns:
        PolicyClient instance
    """
    return PolicyClient(node)
