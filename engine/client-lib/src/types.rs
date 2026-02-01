// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Shared GraphQL types used by both client and server
//!
//! These types represent the GraphQL API contract and can be used
//! for serialization/deserialization on both sides.

use serde::{Deserialize, Serialize};

/// Traffic direction for GraphQL
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GqlDirection {
    Ingress,
    Egress,
}

impl std::str::FromStr for GqlDirection {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ingress" | "in" => Ok(GqlDirection::Ingress),
            "egress" | "out" => Ok(GqlDirection::Egress),
            _ => Err(anyhow::anyhow!(
                "Invalid direction: {}. Use: ingress, egress",
                s
            )),
        }
    }
}

impl std::fmt::Display for GqlDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GqlDirection::Ingress => write!(f, "INGRESS"),
            GqlDirection::Egress => write!(f, "EGRESS"),
        }
    }
}

/// Policy action enum for GraphQL
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GqlPolicyAction {
    Pass,
    Drop,
    Log,
    /// Internal action: triggers a tail call for further processing
    TailCall,
    /// Mirror to Suricata for deep packet inspection (IPS/IDS builds only)
    Inspect,
}

/// Inspect mode for GraphQL (IPS/IDS builds only)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GqlInspectMode {
    Disabled,
    Ips,
    Ids,
}

impl std::str::FromStr for GqlInspectMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" | "off" => Ok(GqlInspectMode::Disabled),
            "ips" => Ok(GqlInspectMode::Ips),
            "ids" => Ok(GqlInspectMode::Ids),
            _ => Err(anyhow::anyhow!(
                "Invalid inspect mode: {}. Use: ips, ids, disabled",
                s
            )),
        }
    }
}

impl std::fmt::Display for GqlInspectMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GqlInspectMode::Disabled => write!(f, "DISABLED"),
            GqlInspectMode::Ips => write!(f, "IPS"),
            GqlInspectMode::Ids => write!(f, "IDS"),
        }
    }
}

/// Ingress attach mode for GraphQL
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GqlIngressMode {
    Unspec,
    Native,
    Generic,
    Offload,
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

/// Protocol type for GraphQL
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
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

/// Action with priority (for client input)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionInput {
    pub action: GqlPolicyAction,
    pub priority: u8,
    /// Action-specific parameter. For LOG: rate-limit interval in milliseconds (0 = no limit).
    #[serde(default)]
    pub param: i64,
}

/// Interface attachment info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceAttachment {
    pub interface: String,
    pub ifindex: i32,
    pub mode: String,
    pub direction: String,
}

/// Global statistics output type
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[serde(default)]
    pub inspect_redirects: u64,
    #[serde(default)]
    pub fragments: u64,
    #[serde(default)]
    pub verdict_pass_packets: u64,
    #[serde(default)]
    pub verdict_pass_bytes: u64,
    #[serde(default)]
    pub verdict_drop_packets: u64,
    #[serde(default)]
    pub verdict_drop_bytes: u64,
}

/// Ethertype statistics output type.
/// `ethertype` is the numeric value; format as `0x{:04X}` for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthertypeStatsOutput {
    pub ethertype: u16,
    pub name: String,
    pub packets: u64,
}

/// Non-IP sender statistics output type.
/// One entry per (source MAC, ethertype) pair observed on ingress.
/// `ethertype` is the numeric value; format as `0x{:04X}` for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NonIpSenderOutput {
    pub mac: String,
    pub ethertype: u16,
    pub name: String,
    pub packets: u64,
}

/// Rule statistics output type
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleStatsOutput {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

/// Rule action output type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleActionOutput {
    pub action: GqlPolicyAction,
    pub priority: u8,
    /// Action-specific parameter. For LOG: rate-limit interval in milliseconds (0 = no limit).
    #[serde(default)]
    pub param: i64,
}

/// LPM rule output type (for IPv4 and IPv6)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LpmRuleOutput {
    pub rule_id: u64,
    /// Network interface the rule is scoped to (empty string if unresolved).
    #[serde(default)]
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
    /// Source MAC filter if set (e.g., "aa:bb:cc:dd:ee:ff")
    pub src_mac: Option<String>,
    /// Destination MAC filter if set (e.g., "aa:bb:cc:dd:ee:ff")
    pub dst_mac: Option<String>,
}

/// A point-in-time within a repeating week. `day_of_week`: 0=Sunday…6=Saturday.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeeklyTimePointInput {
    pub day_of_week: i32,
    pub hour: i32,
    pub minute: i32,
}

/// A half-open weekly time window `[start, end)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeeklyWindowInput {
    pub start: WeeklyTimePointInput,
    pub end: WeeklyTimePointInput,
}

/// A weekly schedule for a rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleScheduleInput {
    pub windows: Vec<WeeklyWindowInput>,
    pub timezone: String,
}

/// Input for adding a rule
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRuleInput {
    /// Network interface name the rule applies to.
    pub interface: String,
    pub direction: GqlDirection,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sport: u16,
    pub dport: u16,
    pub protocol: String,
    pub actions: Vec<ActionInput>,
    pub id: Option<u64>,
    /// TLS SNI pattern to match (e.g., "example.com" or "*.example.com")
    pub sni: Option<String>,
    /// QUIC version filter ("any", "v1", "v2")
    pub quic_version: Option<String>,
    /// Source MAC filter (e.g., "aa:bb:cc:dd:ee:ff"). None means any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<String>,
    /// Destination MAC filter (e.g., "aa:bb:cc:dd:ee:ff"). None means any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_mac: Option<String>,
    /// Auto-remove rule after this many seconds. Mutually exclusive with `schedule`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_after_secs: Option<i32>,
    /// Weekly recurring windows. Mutually exclusive with `expires_after_secs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<RuleScheduleInput>,
}

/// Input for deleting a rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteRuleInput {
    /// Network interface name the rule is scoped to.
    pub interface: String,
    pub direction: GqlDirection,
    pub id: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub protocol: Option<String>,
}

/// Generic operation result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationResult {
    pub success: bool,
    pub message: String,
}

/// Server status output.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub running: bool,
    pub version: String,
    pub uptime_secs: u64,
    /// Whether any program is attached to any interface
    pub program_attached: bool,
    /// Current inspect mode ("IPS" or "IDS"), or None if disabled/unavailable
    #[serde(default)]
    pub inspect_mode: Option<String>,
}

/// Inspect/IPS status (only available on IPS/IDS servers)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectStatusOutput {
    pub mode: GqlInspectMode,
    pub suricata_running: bool,
    pub mirror_interface: Option<String>,
    pub mirror_ifindex: Option<i32>,
    /// Peer veth endpoint (pe-inspect1) — Suricata listens on this
    pub peer_interface: Option<String>,
    pub flow_verdict_count: i64,
    pub suricata_version: Option<String>,
    pub ruleset_version: Option<String>,
}

/// Suricata alert output (only available on IPS/IDS servers)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataAlertOutput {
    pub timestamp: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub signature_id: u64,
    pub signature: String,
    pub category: String,
    pub severity: u32,
    pub action: String,
}

/// Flow verdict statistics output (only available on IPS/IDS servers)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowVerdictStatsOutput {
    pub active_verdicts: i64,
}

/// Server compile-time feature flags.
/// Always available — use this to discover what the server supports before
/// calling IPS/IDS-specific queries or mutations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerFeaturesOutput {
    /// Whether the server was compiled with Suricata IPS/IDS support
    pub suricata: bool,
}
