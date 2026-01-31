//! Shared GraphQL types used by both client and server
//!
//! These types represent the GraphQL API contract and can be used
//! for serialization/deserialization on both sides.

use serde::{Deserialize, Serialize};

/// Policy action enum for GraphQL
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GqlPolicyAction {
    Pass,
    Drop,
    Log,
    TailCall,
}

/// XDP attach mode for GraphQL
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GqlXdpMode {
    Unspec,
    Native,
    Generic,
    Offload,
}

impl std::str::FromStr for GqlXdpMode {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "native" | "drv" => Ok(GqlXdpMode::Native),
            "generic" | "skb" => Ok(GqlXdpMode::Generic),
            "offload" | "hw" => Ok(GqlXdpMode::Offload),
            "unspec" => Ok(GqlXdpMode::Unspec),
            _ => Err(anyhow::anyhow!("Invalid XDP mode: {}", s)),
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
            "icmp" => Ok(GqlProtocol::Icmp),
            _ => Err(anyhow::anyhow!("Invalid protocol: {}", s)),
        }
    }
}

/// Action with priority (for client input)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionInput {
    pub action: GqlPolicyAction,
    pub priority: u8,
}

/// XDP interface attachment info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceAttachment {
    pub interface: String,
    pub ifindex: i32,
    pub mode: String,
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
}

/// Ethertype statistics output type
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthertypeStatsOutput {
    pub ethertype: u16,
    pub ethertype_hex: String,
    pub name: String,
    pub packets: u64,
}

/// Rule statistics output type
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleStatsOutput {
    pub rule_id: u64,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

/// Rule action output type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleActionOutput {
    pub action: GqlPolicyAction,
    pub priority: u8,
}

/// LPM rule output type (for IPv4 and IPv6)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LpmRuleOutput {
    pub rule_id: u64,
    pub src_prefix: String,
    pub dst_prefix: String,
    pub sport: u16,
    pub dport: u16,
    pub protocol: GqlProtocol,
    pub priority: u32,
    pub actions: Vec<RuleActionOutput>,
    pub is_ipv6: bool,
}

/// Input for adding a rule
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRuleInput {
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sport: u16,
    pub dport: u16,
    pub protocol: String,
    pub actions: Vec<ActionInput>,
    pub id: Option<u64>,
    pub priority: u32,
    pub tail_call_slot: Option<u32>,
}

/// Input for deleting a rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteRuleInput {
    pub id: Option<u64>,
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

/// Server status output
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub running: bool,
    pub version: String,
    pub uptime_secs: u64,
}
