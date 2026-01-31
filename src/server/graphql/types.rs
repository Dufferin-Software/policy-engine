//! GraphQL types with async_graphql derives for the server

use async_graphql::{Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};

/// Policy action enum for GraphQL
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum GqlPolicyAction {
    Pass,
    Drop,
    Log,
    TailCall,
}

impl From<crate::types::PolicyAction> for GqlPolicyAction {
    fn from(action: crate::types::PolicyAction) -> Self {
        match action {
            crate::types::PolicyAction::Pass => GqlPolicyAction::Pass,
            crate::types::PolicyAction::Drop => GqlPolicyAction::Drop,
            crate::types::PolicyAction::Log => GqlPolicyAction::Log,
            crate::types::PolicyAction::TailCall => GqlPolicyAction::TailCall,
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
        }
    }
}

/// XDP attach mode for GraphQL
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum GqlXdpMode {
    Unspec,
    Native,
    Generic,
    Offload,
}

impl From<crate::types::XdpMode> for GqlXdpMode {
    fn from(mode: crate::types::XdpMode) -> Self {
        match mode {
            crate::types::XdpMode::Unspec => GqlXdpMode::Unspec,
            crate::types::XdpMode::Native => GqlXdpMode::Native,
            crate::types::XdpMode::Generic => GqlXdpMode::Generic,
            crate::types::XdpMode::Offload => GqlXdpMode::Offload,
        }
    }
}

impl From<GqlXdpMode> for crate::types::XdpMode {
    fn from(mode: GqlXdpMode) -> Self {
        match mode {
            GqlXdpMode::Unspec => crate::types::XdpMode::Unspec,
            GqlXdpMode::Native => crate::types::XdpMode::Native,
            GqlXdpMode::Generic => crate::types::XdpMode::Generic,
            GqlXdpMode::Offload => crate::types::XdpMode::Offload,
        }
    }
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

/// Action with priority input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct ActionInput {
    pub action: GqlPolicyAction,
    pub priority: u8,
}

/// XDP interface attachment info
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceAttachment {
    pub interface: String,
    pub ifindex: i32,
    pub mode: String,
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
        }
    }
}

/// Ethertype statistics output type
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthertypeStatsOutput {
    pub ethertype: u16,
    pub ethertype_hex: String,
    pub name: String,
    pub packets: u64,
}

impl From<crate::types::EthertypeStats> for EthertypeStatsOutput {
    fn from(stats: crate::types::EthertypeStats) -> Self {
        Self {
            ethertype: stats.ethertype,
            ethertype_hex: stats.hex(),
            name: stats.name().to_string(),
            packets: stats.packets,
        }
    }
}

/// Rule statistics output type
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleStatsOutput {
    pub rule_id: u64,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

/// Rule action output type
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
pub struct RuleActionOutput {
    pub action: GqlPolicyAction,
    pub priority: u8,
}

/// LPM rule output type (for IPv4 and IPv6)
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
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
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRuleInput {
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
    /// Actions with priorities
    pub actions: Vec<ActionInput>,
    /// Optional rule ID (auto-generated if not specified)
    pub id: Option<u64>,
    /// Rule priority (lower = higher priority)
    #[graphql(default = 1000)]
    pub priority: u32,
    /// Tail call slot (for tail-call action)
    pub tail_call_slot: Option<u32>,
}

/// Input for deleting a rule
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DeleteRuleInput {
    /// Rule ID to delete
    pub id: Option<u64>,
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

/// Attach XDP input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct AttachXdpInput {
    pub interface: String,
    /// XDP mode: auto (default), offload, native, or generic
    /// Auto tries offload → native → generic until one succeeds
    #[graphql(default_with = "String::from(\"auto\")")]
    pub mode: String,
}

/// Detach XDP input
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DetachXdpInput {
    pub interface: String,
}

/// Config input for default action
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct DefaultActionInput {
    pub action: GqlPolicyAction,
}

/// Config input for tail call registration
#[derive(InputObject, Clone, Debug, Serialize, Deserialize)]
pub struct TailCallInput {
    pub slot: u32,
    pub program: String,
}

/// Server status output
#[derive(SimpleObject, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub running: bool,
    pub version: String,
    pub uptime_secs: u64,
}
