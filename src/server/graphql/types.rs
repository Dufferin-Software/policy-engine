// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! GraphQL types with async_graphql derives for the server

use async_graphql::{Enum, InputObject, SimpleObject, ID};
use serde::{Deserialize, Serialize};

/// Policy action enum for GraphQL
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum GqlPolicyAction {
    Pass,
    Drop,
    Log,
    /// Internal action: triggers a tail call for further processing
    TailCall,
    /// Inspect action: mirrors packet to Suricata for IPS analysis
    #[cfg(feature = "suricata")]
    Inspect,
}

impl From<crate::types::PolicyAction> for GqlPolicyAction {
    fn from(action: crate::types::PolicyAction) -> Self {
        match action {
            crate::types::PolicyAction::Pass => GqlPolicyAction::Pass,
            crate::types::PolicyAction::Drop => GqlPolicyAction::Drop,
            crate::types::PolicyAction::Log => GqlPolicyAction::Log,
            crate::types::PolicyAction::TailCall => GqlPolicyAction::TailCall,
            #[cfg(feature = "suricata")]
            crate::types::PolicyAction::Inspect => GqlPolicyAction::Inspect,
        }
    }
}

impl From<GqlPolicyAction> for crate::types::PolicyAction {
    fn from(action: GqlPolicyAction) -> Self {
        match action {
            GqlPolicyAction::Pass => crate::types::PolicyAction::Pass,
            GqlPolicyAction::Drop => crate::types::PolicyAction::Drop,
            GqlPolicyAction::Log => crate::types::PolicyAction::Log,
            GqlPolicyAction::TailCall => crate::types::PolicyAction::TailCall,
            #[cfg(feature = "suricata")]
            GqlPolicyAction::Inspect => crate::types::PolicyAction::Inspect,
        }
    }
}

/// Ingress attach mode for GraphQL
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum GqlIngressMode {
    Unspec,
    Native,
    Generic,
    Offload,
}

impl From<crate::types::XdpMode> for GqlIngressMode {
    fn from(mode: crate::types::XdpMode) -> Self {
        match mode {
            crate::types::XdpMode::Unspec => GqlIngressMode::Unspec,
            crate::types::XdpMode::Native => GqlIngressMode::Native,
            crate::types::XdpMode::Generic => GqlIngressMode::Generic,
            crate::types::XdpMode::Offload => GqlIngressMode::Offload,
        }
    }
}

impl From<GqlIngressMode> for crate::types::XdpMode {
    fn from(mode: GqlIngressMode) -> Self {
        match mode {
            GqlIngressMode::Unspec => crate::types::XdpMode::Unspec,
            GqlIngressMode::Native => crate::types::XdpMode::Native,
            GqlIngressMode::Generic => crate::types::XdpMode::Generic,
            GqlIngressMode::Offload => crate::types::XdpMode::Offload,
        }
    }
}

impl std::str::FromStr for GqlIngressMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "native" | "drv" => Ok(GqlIngressMode::Native),
            "generic" | "skb" => Ok(GqlIngressMode::Generic),
            "offload" | "hw" => Ok(GqlIngressMode::Offload),
            "unspec" => Ok(GqlIngressMode::Unspec),
            _ => Err(anyhow::anyhow!("Invalid ingress mode: {}", s)),
        }
    }
}

/// Traffic direction for GraphQL
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GqlDirection {
    Ingress,
    Egress,
}

impl From<crate::types::Direction> for GqlDirection {
    fn from(d: crate::types::Direction) -> Self {
        match d {
            crate::types::Direction::Ingress => GqlDirection::Ingress,
            crate::types::Direction::Egress => GqlDirection::Egress,
        }
    }
}

impl From<GqlDirection> for crate::types::Direction {
    fn from(d: GqlDirection) -> Self {
        match d {
            GqlDirection::Ingress => crate::types::Direction::Ingress,
            GqlDirection::Egress => crate::types::Direction::Egress,
        }
    }
}

/// Protocol type for GraphQL
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum GqlProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

impl GqlProtocol {
    pub fn to_proto_number(&self) -> u8 {
        match self {
            GqlProtocol::Any => 0,
            GqlProtocol::Tcp => libc::IPPROTO_TCP as u8,
            GqlProtocol::Udp => libc::IPPROTO_UDP as u8,
            GqlProtocol::Icmp => libc::IPPROTO_ICMP as u8,
        }
    }

    /// Get protocol number for IPv6 rules (auto-converts ICMP to ICMPv6)
    pub fn to_proto_number_v6(&self) -> u8 {
        match self {
            GqlProtocol::Any => 0,
            GqlProtocol::Tcp => libc::IPPROTO_TCP as u8,
            GqlProtocol::Udp => libc::IPPROTO_UDP as u8,
            GqlProtocol::Icmp => libc::IPPROTO_ICMPV6 as u8,
        }
    }

    pub fn from_proto_number(proto: u8) -> Self {
        match proto {
            p if p == libc::IPPROTO_TCP as u8 => GqlProtocol::Tcp,
            p if p == libc::IPPROTO_UDP as u8 => GqlProtocol::Udp,
            p if p == libc::IPPROTO_ICMP as u8 => GqlProtocol::Icmp,
            _ => GqlProtocol::Any,
        }
    }
}

impl std::str::FromStr for GqlProtocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" | "all" | "*" | "" => Ok(GqlProtocol::Any),
            "tcp" => Ok(GqlProtocol::Tcp),
            "udp" => Ok(GqlProtocol::Udp),
            // Accept both icmp and icmpv6 - the service layer auto-converts to icmpv6 for IPv6 rules
            "icmp" | "icmpv6" => Ok(GqlProtocol::Icmp),
            _ => Err(anyhow::anyhow!("Invalid protocol: {}", s)),
        }
    }
}

/// Action with priority input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct ActionInput {
    pub action: GqlPolicyAction,
    pub priority: u8,
    /// Action-specific parameter. For LOG: rate-limit interval in milliseconds (0 = no limit).
    #[graphql(default = 0)]
    pub param: i64,
}

/// Interface attachment info
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceAttachment {
    pub interface: String,
    pub ifindex: i32,
    pub mode: String,
    pub direction: String,
}

/// Global statistics output type
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlobalStatsOutput {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub policy_matches: u64,
    pub policy_drops: u64,
    pub policy_pass: u64,
    pub policy_redirects: u64,
    pub parse_errors: u64,
    pub tail_calls: u64,
    pub bum_packets: u64,
    pub non_ip_unicast: u64,
    pub inspect_redirects: i64,
    pub fragments: u64,
    /// Flow verdict cache: packets/bytes that hit a PASS verdict
    pub verdict_pass_packets: u64,
    pub verdict_pass_bytes: u64,
    /// Flow verdict cache: packets/bytes that hit a DROP verdict
    pub verdict_drop_packets: u64,
    pub verdict_drop_bytes: u64,
    /// XDP FIB forwarding: packets successfully forwarded via bpf_redirect
    pub fib_forwarded_packets: u64,
    pub fib_forwarded_bytes: u64,
    /// XDP FIB forwarding: packets where FIB lookup was attempted but fell back to XDP_PASS
    pub fib_fallback_packets: u64,
}

impl From<crate::types::GlobalStats> for GlobalStatsOutput {
    fn from(stats: crate::types::GlobalStats) -> Self {
        Self {
            rx_packets: stats.rx_packets,
            rx_bytes: stats.rx_bytes,
            tx_packets: stats.tx_packets,
            tx_bytes: stats.tx_bytes,
            policy_matches: stats.policy_matches,
            policy_drops: stats.policy_drops,
            policy_pass: stats.policy_pass,
            policy_redirects: stats.policy_redirects,
            parse_errors: stats.parse_errors,
            tail_calls: stats.tail_calls,
            bum_packets: stats.bum_packets,
            non_ip_unicast: stats.non_ip_unicast,
            inspect_redirects: stats.inspect_redirects as i64,
            fragments: stats.fragments,
            verdict_pass_packets: stats.verdict_pass_packets,
            verdict_pass_bytes: stats.verdict_pass_bytes,
            verdict_drop_packets: stats.verdict_drop_packets,
            verdict_drop_bytes: stats.verdict_drop_bytes,
            fib_forwarded_packets: stats.fib_forwarded_packets,
            fib_forwarded_bytes: stats.fib_forwarded_bytes,
            fib_fallback_packets: stats.fib_fallback_packets,
        }
    }
}

/// Ethertype statistics output type.
/// `ethertype` is the numeric value; callers should format it as hex for display.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthertypeStatsOutput {
    pub ethertype: u16,
    pub name: String,
    pub packets: u64,
}

impl From<crate::types::EthertypeStats> for EthertypeStatsOutput {
    fn from(stats: crate::types::EthertypeStats) -> Self {
        Self {
            ethertype: stats.ethertype,
            name: stats.name().to_string(),
            packets: stats.packets,
        }
    }
}

/// Non-IP sender statistics output type.
/// One entry per (source MAC, ethertype) pair observed on ingress.
/// `ethertype` is the numeric value; callers should format it as hex for display.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NonIpSenderOutput {
    /// Source MAC address in colon-separated hex (e.g. "aa:bb:cc:dd:ee:ff")
    pub mac: String,
    /// Ethertype numeric value
    pub ethertype: u16,
    /// Human-readable ethertype name ("ARP", "LLDP", "Unknown", …)
    pub name: String,
    /// Packet count for this (MAC, ethertype) pair
    pub packets: u64,
}

impl From<crate::types::NonIpSenderEntry> for NonIpSenderOutput {
    fn from(e: crate::types::NonIpSenderEntry) -> Self {
        use crate::types::ethertypes;
        Self {
            mac: e.mac_str(),
            ethertype: e.ethertype,
            name: ethertypes::name(e.ethertype).to_string(),
            packets: e.packets,
        }
    }
}

/// Rule statistics output type
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleStatsOutput {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

/// Rule action output type
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct RuleActionOutput {
    pub action: GqlPolicyAction,
    pub priority: u8,
    /// Action-specific parameter. For LOG: rate-limit interval in milliseconds (0 = no limit).
    pub param: i64,
}

/// LPM rule output type (for IPv4 and IPv6)
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LpmRuleOutput {
    pub rule_id: ID,
    /// Network interface the rule is scoped to (empty string if unresolved).
    pub interface: String,
    pub src_prefix: String,
    pub dst_prefix: String,
    pub sport: u16,
    pub dport: u16,
    pub protocol: GqlProtocol,
    pub actions: Vec<RuleActionOutput>,
    /// TLS SNI pattern if set
    pub sni: Option<String>,
    /// QUIC version filter if set ("any", "v1", "v2")
    pub quic_version: Option<String>,
    /// Source MAC filter if set (colon-hex format, e.g. "aa:bb:cc:dd:ee:ff")
    pub src_mac: Option<String>,
    /// Destination MAC filter if set (colon-hex format, e.g. "aa:bb:cc:dd:ee:ff")
    pub dst_mac: Option<String>,
}

/// QUIC version packet/byte statistics
#[derive(SimpleObject, Clone, Debug)]
pub struct QuicStatsOutput {
    pub version: String,
    pub packets: u64,
    pub bytes: u64,
}

// ── Schedule input / output types ────────────────────────────────────────────

/// A point-in-time within a repeating week.
/// `dayOfWeek`: 0 = Sunday … 6 = Saturday.
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeeklyTimePointInput {
    pub day_of_week: i32,
    pub hour: i32,
    pub minute: i32,
}

/// A half-open weekly time window `[start, end)`.
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct WeeklyWindowInput {
    pub start: WeeklyTimePointInput,
    pub end: WeeklyTimePointInput,
}

/// A weekly schedule for a rule.
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleScheduleInput {
    pub windows: Vec<WeeklyWindowInput>,
    /// IANA timezone name (e.g. "America/Toronto"). Defaults to "UTC".
    #[graphql(default_with = "String::from(\"UTC\")")]
    pub timezone: String,
}

/// Output type: point-in-time within a week.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeeklyTimePointOutput {
    pub day_of_week: i32,
    pub hour: i32,
    pub minute: i32,
}

/// Output type: weekly window.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct WeeklyWindowOutput {
    pub start: WeeklyTimePointOutput,
    pub end: WeeklyTimePointOutput,
}

/// Output type: schedule metadata for a managed rule.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct RuleScheduleOutput {
    pub windows: Vec<WeeklyWindowOutput>,
    pub timezone: String,
}

/// Output type for a rule that has TTL or schedule metadata.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedRuleOutput {
    pub rule_id: ID,
    pub direction: GqlDirection,
    /// Interface name the rule is scoped to (e.g. "eth0"). Empty string when the
    /// interface can no longer be resolved from its ifindex (e.g. after detach).
    pub interface: String,
    pub src_prefix: String,
    pub dst_prefix: String,
    pub sport: i32,
    pub dport: i32,
    pub protocol: GqlProtocol,
    pub actions: Vec<RuleActionOutput>,
    pub sni: Option<String>,
    pub quic_version: Option<String>,
    /// Unix timestamp in milliseconds when the TTL expires. `null` for scheduled/permanent rules.
    pub expires_at_ms: Option<String>,
    /// Weekly schedule. `null` for TTL/permanent rules.
    pub schedule: Option<RuleScheduleOutput>,
    /// `"active"` or `"inactive"`.
    pub rule_state: String,
}

/// Input for adding a rule
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRuleInput {
    /// Network interface name the rule applies to (e.g., "eth0", "enp1s0").
    /// Rules are scoped per-interface per-direction.
    pub interface: String,
    /// Traffic direction: INGRESS or EGRESS
    pub direction: GqlDirection,
    /// Source IP/CIDR (e.g., "192.168.1.0/24" or "10.0.0.1/32")
    pub src: Option<String>,
    /// Destination IP/CIDR
    pub dst: Option<String>,
    /// Source port (0 for any)
    #[graphql(default = 0)]
    pub sport: u16,
    /// Destination port (0 for any)
    #[graphql(default = 0)]
    pub dport: u16,
    /// Protocol: "tcp", "udp", "icmp", "any"
    #[graphql(default_with = "String::from(\"any\")")]
    pub protocol: String,
    /// Ordered list of actions to apply. Actions are processed by priority (lowest first).
    /// DROP immediately stops further action processing.
    pub actions: Vec<ActionInput>,
    /// Optional rule ID (auto-generated if not specified)
    /// Accepts either String or Int via GraphQL `ID` scalar
    pub id: Option<ID>,
    /// TLS SNI pattern to match (e.g., "example.com" or "*.example.com")
    pub sni: Option<String>,
    /// QUIC version filter: "any", "v1", "v2", or omit for no filter
    pub quic_version: Option<String>,
    /// Source MAC address filter in colon-hex format (e.g., "aa:bb:cc:dd:ee:ff").
    /// Omit or null for no filtering. All-zeros is rejected — use null instead.
    pub src_mac: Option<String>,
    /// Destination MAC address filter in colon-hex format (e.g., "aa:bb:cc:dd:ee:ff").
    /// Omit or null for no filtering. All-zeros is rejected — use null instead.
    pub dst_mac: Option<String>,
    /// Auto-remove rule after this many seconds. Mutually exclusive with `schedule`.
    pub expires_after_secs: Option<i32>,
    /// Weekly recurring windows during which the rule should be active.
    /// Mutually exclusive with `expiresAfterSecs`.
    pub schedule: Option<RuleScheduleInput>,
}

/// Input for deleting a rule
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DeleteRuleInput {
    /// Network interface name the rule is scoped to.
    pub interface: String,
    /// Traffic direction: INGRESS or EGRESS
    pub direction: GqlDirection,
    /// Rule ID to delete (ID scalar accepts string or int)
    pub id: Option<ID>,
    /// Source IP/CIDR
    pub src: Option<String>,
    /// Destination IP/CIDR
    pub dst: Option<String>,
    /// Source port
    pub sport: Option<u16>,
    /// Destination port
    pub dport: Option<u16>,
    /// Protocol
    pub protocol: Option<String>,
}

/// Generic operation result
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct OperationResult {
    pub success: bool,
    pub message: String,
}

/// Attach ingress input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct AttachIngressInput {
    pub interface: String,
    /// Ingress mode: auto (default), offload, native, or generic
    /// Auto tries offload → native → generic until one succeeds
    #[graphql(default_with = "String::from(\"auto\")")]
    pub mode: String,
}

/// Detach ingress input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DetachIngressInput {
    pub interface: String,
}

/// Attach egress input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct AttachTcInput {
    pub interface: String,
}

/// Detach egress input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DetachTcInput {
    pub interface: String,
}

/// Config input for default action
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DefaultActionInput {
    /// Network interface name to set the default action on.
    pub interface: String,
    pub action: GqlPolicyAction,
    /// Traffic direction: INGRESS or EGRESS
    pub direction: GqlDirection,
}

/// Config input for tail call registration
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct TailCallInput {
    pub slot: u32,
    pub program: String,
    /// Traffic direction: INGRESS or EGRESS
    pub direction: GqlDirection,
}

/// Input for enabling or disabling XDP FIB forwarding on a single interface.
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct SetFibForwardingInput {
    pub interface: String,
    pub enabled: bool,
}

/// FIB forwarding enable state for a single interface.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FibForwardingEntry {
    pub interface: String,
    pub enabled: bool,
}

/// CPU affinity configuration currently in effect.
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpuAffinityStatus {
    /// True when all CPU pinning is disabled (e.g. in a container).
    pub disabled: bool,
    /// CPUs used by Tokio worker threads and actix-web request handlers.
    pub control_cpus: Vec<i32>,
    /// CPU used by the BPF ring-buffer polling thread.
    pub event_cpus: Vec<i32>,
    /// CPUs that NIC IRQs and RPS are steered to after interface attach.
    pub dataplane_cpus: Vec<i32>,
    /// Number of actix-web worker threads.
    pub actix_workers: i32,
}

/// Server status output
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub running: bool,
    pub version: String,
    pub uptime_secs: u64,
    /// Whether any program is attached to any interface
    pub program_attached: bool,
    /// Current inspect mode (e.g., "IPS" or "DISABLED"), if applicable
    pub inspect_mode: Option<String>,
    /// Whether Suricata is currently running
    pub suricata_running: Option<bool>,
    /// Current CPU affinity configuration.
    pub cpu_affinity: CpuAffinityStatus,
}

/// Result for a single rule in a batch operation
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchRuleResult {
    /// Index of the rule in the input array
    pub index: u32,
    /// Rule ID (if successfully added)
    pub rule_id: Option<ID>,
    /// Whether this rule was added successfully
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Result for batch add rules mutation
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchAddRulesResult {
    /// Total number of rules in the request
    pub total: u32,
    /// Number of rules successfully added
    pub succeeded: u32,
    /// Number of rules that failed
    pub failed: u32,
    /// Overall success (all rules added)
    pub success: bool,
    /// Summary message
    pub message: String,
    /// Individual results for each rule
    pub results: Vec<BatchRuleResult>,
}

/// Result for batch delete rules mutation
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteRulesResult {
    /// Total number of rules in the request
    pub total: u32,
    /// Number of rules successfully deleted
    pub succeeded: u32,
    /// Number of deletes that failed
    pub failed: u32,
    /// Overall success (all deletes succeeded)
    pub success: bool,
    /// Summary message
    pub message: String,
    /// Individual results for each delete request
    pub results: Vec<BatchRuleResult>,
}

/// Inspect mode for GraphQL
#[cfg(feature = "suricata")]
#[derive(Enum, Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GqlInspectMode {
    Disabled,
    #[graphql(name = "IPS")]
    Ips,
    #[graphql(name = "IDS")]
    /// IDS: clone traffic to Suricata for alerting; no DROP verdicts installed
    Ids,
}

/// Input for configuring inspect mode
#[cfg(feature = "suricata")]
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct ConfigureInspectInput {
    pub mode: GqlInspectMode,
}

/// Input for deploying Suricata rules
#[cfg(feature = "suricata")]
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DeploySuricataRulesInput {
    pub rules: String,
    #[graphql(default_with = "\"custom.rules\".to_string()")]
    pub filename: String,
}

/// Individual flow verdict entry
#[derive(SimpleObject, Clone, Debug)]
pub struct FlowVerdictOutput {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: i32,
    pub dst_port: i32,
    pub protocol: String,
    pub action: String,
    /// Expiry time as nanoseconds since Unix epoch (as string to avoid i64 precision issues)
    pub expires_ns: String,
    /// Whether this verdict has already expired
    pub expired: bool,
    /// Total packets matched by this cached verdict
    pub packets: i64,
    /// Total bytes matched by this cached verdict
    pub bytes: i64,
}

/// A custom Suricata rules file deployed to the policy-engine rules directory
#[cfg(feature = "suricata")]
#[derive(SimpleObject, Clone, Debug)]
pub struct CustomRuleFileOutput {
    pub filename: String,
    pub rule_count: i32,
    /// Individual rule lines (non-empty, non-comment lines)
    pub rules: Vec<String>,
}

/// Inspect status output
#[cfg(feature = "suricata")]
#[derive(SimpleObject, Clone, Debug)]
pub struct InspectStatusOutput {
    pub mode: GqlInspectMode,
    pub suricata_running: bool,
    /// Local veth endpoint (pe-inspect0) — XDP redirects packets here
    pub mirror_interface: Option<String>,
    pub mirror_ifindex: Option<i32>,
    /// Peer veth endpoint (pe-inspect1) — Suricata listens on this via AF-XDP
    pub peer_interface: Option<String>,
    pub flow_verdict_count: i64,
    /// Suricata binary version string
    pub suricata_version: Option<String>,
    /// Ruleset version/timestamp from suricata-update
    pub ruleset_version: Option<String>,
    /// Custom rule files deployed to the policy-engine rules directory
    pub custom_rule_files: Vec<CustomRuleFileOutput>,
}

/// Suricata alert output
#[cfg(feature = "suricata")]
#[derive(SimpleObject, Clone, Debug)]
pub struct SuricataAlertOutput {
    pub timestamp: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_port: i32,
    pub dest_port: i32,
    pub protocol: String,
    pub signature_id: i64,
    pub signature: String,
    pub category: String,
    pub severity: i32,
    pub action: String,
}

/// Flow verdict statistics
#[derive(SimpleObject, Clone, Debug)]
pub struct FlowVerdictStatsOutput {
    pub active_verdicts: i64,
}

/// Input for deleting custom Suricata rules by SID
#[cfg(feature = "suricata")]
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DeleteCustomRulesInput {
    pub filename: String,
    pub sids: Vec<i32>,
}

/// Server compile-time feature flags
#[derive(SimpleObject, Clone, Debug)]
pub struct ServerFeaturesOutput {
    /// Whether the server was compiled with Suricata IPS/IDS support
    pub suricata: bool,
    /// Whether the server was compiled with IPFIX flow export support
    pub ipfix: bool,
}

/// Processing-time percentile statistics
#[derive(SimpleObject, Clone, Debug)]
pub struct TimingStatsOutput {
    pub p50_ns: i64,
    pub p95_ns: i64,
    pub p99_ns: i64,
    pub p999_ns: i64,
    pub total_samples: i64,
    pub buckets: Vec<i64>,
}

/// Per-protocol traffic statistics
#[derive(SimpleObject, Clone, Debug)]
pub struct ProtoStatsOutput {
    pub protocol: i32,
    pub name: String,
    pub packets: i64,
    pub bytes: i64,
}

/// Combined performance statistics output
#[derive(SimpleObject, Clone, Debug)]
pub struct PerformanceStatsOutput {
    pub timing: TimingStatsOutput,
    /// L4 (IP) protocol breakdown — keyed by IP protocol number
    pub proto_stats: Vec<ProtoStatsOutput>,
    /// L3 protocol breakdown — keyed by ethertype (0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP, 0=Other)
    pub l3_stats: Vec<ProtoStatsOutput>,
    pub rx_bytes_per_sec: i64,
    pub tx_bytes_per_sec: i64,
}

/// Input for configuring IPFIX flow export
#[cfg(feature = "ipfix")]
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct ConfigureFlowExportInput {
    /// Enable or disable IPFIX flow export
    pub enabled: bool,
    /// Collector hostname or IP address (default: "127.0.0.1")
    #[graphql(default)]
    pub collector_host: Option<String>,
    /// Collector UDP port (default: 4739)
    #[graphql(default)]
    pub collector_port: Option<i32>,
    /// Idle timeout in seconds: export a flow after this many seconds of inactivity (default: 15)
    #[graphql(default)]
    pub idle_timeout_s: Option<i32>,
    /// Active timeout in seconds: export a long-running flow after this many seconds (default: 60)
    #[graphql(default)]
    pub active_timeout_s: Option<i32>,
}

/// IPFIX flow export status
#[cfg(feature = "ipfix")]
#[derive(SimpleObject, Clone, Debug)]
#[graphql(name = "FlowExportStatus")]
pub struct FlowExportStatusOutput {
    pub enabled: bool,
    pub collector_host: String,
    pub collector_port: i32,
    pub idle_timeout_s: i32,
    pub active_timeout_s: i32,
    /// Total number of flows exported since the server started
    pub flows_exported_total: i64,
    /// Current number of entries in the XDP + TC flow cache maps
    pub active_flow_count: i64,
}

/// Output type for the current stop-behavior setting.
#[derive(SimpleObject, Clone, Debug)]
#[graphql(name = "StopBehavior")]
pub struct StopBehaviorOutput {
    /// "clear-state" or "preserve-state"
    pub behavior: String,
}

/// Input for configuring the stop-behavior setting.
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct ConfigureStopBehaviorInput {
    /// "clear-state" — detach programs and remove maps on shutdown.
    /// "preserve-state" — leave programs and maps in the kernel (legacy behaviour).
    pub stop_behavior: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // -------------------------------------------------------------------------
    // GqlPolicyAction ↔ PolicyAction conversions
    // -------------------------------------------------------------------------

    #[test]
    fn policy_action_from_pass() {
        let a: GqlPolicyAction = crate::types::PolicyAction::Pass.into();
        assert_eq!(a, GqlPolicyAction::Pass);
    }

    #[test]
    fn policy_action_from_drop() {
        let a: GqlPolicyAction = crate::types::PolicyAction::Drop.into();
        assert_eq!(a, GqlPolicyAction::Drop);
    }

    #[test]
    fn policy_action_from_log() {
        let a: GqlPolicyAction = crate::types::PolicyAction::Log.into();
        assert_eq!(a, GqlPolicyAction::Log);
    }

    #[test]
    fn policy_action_from_tail_call() {
        let a: GqlPolicyAction = crate::types::PolicyAction::TailCall.into();
        assert_eq!(a, GqlPolicyAction::TailCall);
    }

    #[cfg(feature = "suricata")]
    #[test]
    fn policy_action_from_inspect() {
        let a: GqlPolicyAction = crate::types::PolicyAction::Inspect.into();
        assert_eq!(a, GqlPolicyAction::Inspect);
    }

    #[test]
    fn policy_action_roundtrip() {
        for gql in [
            GqlPolicyAction::Pass,
            GqlPolicyAction::Drop,
            GqlPolicyAction::Log,
            GqlPolicyAction::TailCall,
            #[cfg(feature = "suricata")]
            GqlPolicyAction::Inspect,
        ] {
            let native: crate::types::PolicyAction = gql.into();
            let back: GqlPolicyAction = native.into();
            assert_eq!(back, gql);
        }
    }

    // -------------------------------------------------------------------------
    // GqlIngressMode ↔ XdpMode conversions
    // -------------------------------------------------------------------------

    #[test]
    fn ingress_mode_roundtrip() {
        for gql in [
            GqlIngressMode::Unspec,
            GqlIngressMode::Native,
            GqlIngressMode::Generic,
            GqlIngressMode::Offload,
        ] {
            let native: crate::types::XdpMode = gql.into();
            let back: GqlIngressMode = native.into();
            assert_eq!(back, gql);
        }
    }

    #[test]
    fn ingress_mode_from_str_native() {
        assert_eq!(
            GqlIngressMode::from_str("native").unwrap(),
            GqlIngressMode::Native
        );
        assert_eq!(
            GqlIngressMode::from_str("drv").unwrap(),
            GqlIngressMode::Native
        );
        assert_eq!(
            GqlIngressMode::from_str("NATIVE").unwrap(),
            GqlIngressMode::Native
        );
    }

    #[test]
    fn ingress_mode_from_str_generic() {
        assert_eq!(
            GqlIngressMode::from_str("generic").unwrap(),
            GqlIngressMode::Generic
        );
        assert_eq!(
            GqlIngressMode::from_str("skb").unwrap(),
            GqlIngressMode::Generic
        );
    }

    #[test]
    fn ingress_mode_from_str_offload() {
        assert_eq!(
            GqlIngressMode::from_str("offload").unwrap(),
            GqlIngressMode::Offload
        );
        assert_eq!(
            GqlIngressMode::from_str("hw").unwrap(),
            GqlIngressMode::Offload
        );
    }

    #[test]
    fn ingress_mode_from_str_unspec() {
        assert_eq!(
            GqlIngressMode::from_str("unspec").unwrap(),
            GqlIngressMode::Unspec
        );
    }

    #[test]
    fn ingress_mode_from_str_invalid() {
        assert!(GqlIngressMode::from_str("bogus").is_err());
        assert!(GqlIngressMode::from_str("").is_err());
    }

    // -------------------------------------------------------------------------
    // GqlDirection ↔ Direction conversions
    // -------------------------------------------------------------------------

    #[test]
    fn direction_roundtrip_ingress() {
        let gql = GqlDirection::Ingress;
        let native: crate::types::Direction = gql.into();
        let back: GqlDirection = native.into();
        assert_eq!(back, GqlDirection::Ingress);
    }

    #[test]
    fn direction_roundtrip_egress() {
        let gql = GqlDirection::Egress;
        let native: crate::types::Direction = gql.into();
        let back: GqlDirection = native.into();
        assert_eq!(back, GqlDirection::Egress);
    }

    // -------------------------------------------------------------------------
    // GqlProtocol conversions
    // -------------------------------------------------------------------------

    #[test]
    fn protocol_to_proto_number_any() {
        assert_eq!(GqlProtocol::Any.to_proto_number(), 0);
    }

    #[test]
    fn protocol_to_proto_number_tcp() {
        assert_eq!(GqlProtocol::Tcp.to_proto_number(), libc::IPPROTO_TCP as u8);
    }

    #[test]
    fn protocol_to_proto_number_udp() {
        assert_eq!(GqlProtocol::Udp.to_proto_number(), libc::IPPROTO_UDP as u8);
    }

    #[test]
    fn protocol_to_proto_number_icmp() {
        assert_eq!(
            GqlProtocol::Icmp.to_proto_number(),
            libc::IPPROTO_ICMP as u8
        );
    }

    #[test]
    fn protocol_to_proto_number_v6_icmp_becomes_icmpv6() {
        // ICMP→ICMPv6 is the key difference in v6 path
        assert_eq!(
            GqlProtocol::Icmp.to_proto_number_v6(),
            libc::IPPROTO_ICMPV6 as u8
        );
    }

    #[test]
    fn protocol_to_proto_number_v6_tcp_unchanged() {
        assert_eq!(
            GqlProtocol::Tcp.to_proto_number_v6(),
            GqlProtocol::Tcp.to_proto_number()
        );
    }

    #[test]
    fn protocol_from_proto_number_tcp() {
        assert_eq!(
            GqlProtocol::from_proto_number(libc::IPPROTO_TCP as u8),
            GqlProtocol::Tcp
        );
    }

    #[test]
    fn protocol_from_proto_number_udp() {
        assert_eq!(
            GqlProtocol::from_proto_number(libc::IPPROTO_UDP as u8),
            GqlProtocol::Udp
        );
    }

    #[test]
    fn protocol_from_proto_number_icmp() {
        assert_eq!(
            GqlProtocol::from_proto_number(libc::IPPROTO_ICMP as u8),
            GqlProtocol::Icmp
        );
    }

    #[test]
    fn protocol_from_proto_number_unknown_is_any() {
        assert_eq!(GqlProtocol::from_proto_number(255), GqlProtocol::Any);
        assert_eq!(GqlProtocol::from_proto_number(0), GqlProtocol::Any);
    }

    #[test]
    fn protocol_from_str_tcp() {
        assert_eq!(GqlProtocol::from_str("tcp").unwrap(), GqlProtocol::Tcp);
        assert_eq!(GqlProtocol::from_str("TCP").unwrap(), GqlProtocol::Tcp);
    }

    #[test]
    fn protocol_from_str_udp() {
        assert_eq!(GqlProtocol::from_str("udp").unwrap(), GqlProtocol::Udp);
    }

    #[test]
    fn protocol_from_str_icmp_variants() {
        assert_eq!(GqlProtocol::from_str("icmp").unwrap(), GqlProtocol::Icmp);
        assert_eq!(GqlProtocol::from_str("icmpv6").unwrap(), GqlProtocol::Icmp);
    }

    #[test]
    fn protocol_from_str_any_variants() {
        for s in &["any", "all", "*", ""] {
            assert_eq!(
                GqlProtocol::from_str(s).unwrap(),
                GqlProtocol::Any,
                "expected Any for {:?}",
                s
            );
        }
    }

    #[test]
    fn protocol_from_str_invalid() {
        assert!(GqlProtocol::from_str("sctp").is_err());
        assert!(GqlProtocol::from_str("bogus").is_err());
    }

    #[test]
    fn protocol_roundtrip_via_number() {
        for p in [GqlProtocol::Tcp, GqlProtocol::Udp, GqlProtocol::Icmp] {
            let num = p.to_proto_number();
            let back = GqlProtocol::from_proto_number(num);
            assert_eq!(back, p);
        }
    }

    // -------------------------------------------------------------------------
    // GlobalStats → GlobalStatsOutput conversion
    // -------------------------------------------------------------------------

    #[test]
    fn global_stats_from_conversion() {
        let stats = crate::types::GlobalStats {
            rx_packets: 100,
            rx_bytes: 200,
            tx_packets: 50,
            tx_bytes: 75,
            policy_matches: 10,
            policy_drops: 3,
            policy_pass: 7,
            policy_redirects: 1,
            parse_errors: 0,
            tail_calls: 2,
            bum_packets: 4,
            non_ip_unicast: 5,
            inspect_redirects: 6,
            fragments: 8,
            verdict_pass_packets: 9,
            verdict_pass_bytes: 18,
            verdict_drop_packets: 2,
            verdict_drop_bytes: 4,
            fib_forwarded_packets: 11,
            fib_forwarded_bytes: 22,
            fib_fallback_packets: 3,
        };
        let out = GlobalStatsOutput::from(stats);
        assert_eq!(out.rx_packets, 100);
        assert_eq!(out.rx_bytes, 200);
        assert_eq!(out.policy_drops, 3);
        #[cfg(feature = "suricata")]
        assert_eq!(out.inspect_redirects, 6);
        assert_eq!(out.verdict_drop_packets, 2);
        assert_eq!(out.fib_forwarded_packets, 11);
        assert_eq!(out.fib_forwarded_bytes, 22);
        assert_eq!(out.fib_fallback_packets, 3);
    }

    // -------------------------------------------------------------------------
    // EthertypeStats → EthertypeStatsOutput conversion
    // -------------------------------------------------------------------------

    #[test]
    fn ethertype_stats_from_conversion() {
        let stats = crate::types::EthertypeStats {
            ethertype: 0x0800,
            packets: 42,
        };
        let out = EthertypeStatsOutput::from(stats);
        assert_eq!(out.ethertype, 0x0800);
        assert_eq!(out.packets, 42);
        assert_eq!(out.name, "IPv4");
    }
}
