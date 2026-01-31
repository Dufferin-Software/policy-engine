//! Common types shared between BPF programs and userspace
//! These must match the definitions in policy_common.h

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};


/// Maximum number of tail call programs
pub const MAX_DISPATCHER_PROGS: u32 = 1;

/// Maximum interfaces we track
pub const MAX_INTERFACES: u32 = 256;

/// Maximum actions per rule
pub const MAX_ACTIONS_PER_RULE: u32 = 8;

/// Maximum ethertype counters per interface
pub const MAX_ETHERTYPE_COUNTERS: u32 = 16;

/// Policy flags
pub mod flags {
    pub const POLICY_FLAG_ENABLED: u32 = 1 << 0;
    pub const POLICY_FLAG_LOG: u32 = 1 << 1;
    pub const POLICY_FLAG_BIDIRECTIONAL: u32 = 1 << 2;
    pub const POLICY_FLAG_CONNTRACK: u32 = 1 << 3;
}

/// Well-known ethertypes
pub mod ethertypes {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const VLAN_8021Q: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    pub const LLDP: u16 = 0x88CC;
    pub const MPLS: u16 = 0x8847;
    pub const MPLS_MC: u16 = 0x8848;
    pub const VLAN_8021AD: u16 = 0x88A8;
    pub const SLOW: u16 = 0x8809; // LACP, etc
    
    /// Convert ethertype to human-readable name
    pub fn name(ethertype: u16) -> &'static str {
        match ethertype {
            IPV4 => "IPv4",
            ARP => "ARP",
            VLAN_8021Q => "802.1Q VLAN",
            IPV6 => "IPv6",
            LLDP => "LLDP",
            MPLS => "MPLS",
            MPLS_MC => "MPLS Multicast",
            VLAN_8021AD => "802.1ad QinQ",
            SLOW => "Slow Protocols (LACP)",
            0x88E5 => "MACsec",
            0x8808 => "Flow Control",
            0x22F3 => "TRILL",
            0x6003 => "DECnet",
            0x0842 => "Wake-on-LAN",
            _ => "Unknown",
        }
    }
}

/// Address families
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// LPM key for IPv4 addresses (must match BPF struct layout)
/// Used with BPF_MAP_TYPE_LPM_TRIE
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct LpmKeyV4 {
    pub prefixlen: u32,  // Prefix length in bits (0-32 for IPv4)
    pub addr: u32,       // IPv4 address in network byte order
}

impl LpmKeyV4 {
    /// Create a new LPM key from an IPv4 address and prefix length
    /// The address is stored in network byte order (big-endian) as expected by BPF LPM trie
    pub fn new(addr: Ipv4Addr, prefixlen: u8) -> Self {
        Self {
            prefixlen: prefixlen as u32,
            // Store as network byte order (big-endian) - just copy the octets as a u32
            addr: u32::from_ne_bytes(addr.octets()),
        }
    }
    
    /// Create an LPM key for a /0 (match any) prefix
    pub fn any() -> Self {
        Self {
            prefixlen: 0,
            addr: 0,
        }
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

impl fmt::Debug for LpmKeyV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixlen = self.prefixlen;
        // addr is stored in network byte order, convert back to Ipv4Addr
        let addr = Ipv4Addr::from(self.addr.to_ne_bytes());
        write!(f, "{}/{}", addr, prefixlen)
    }
}

unsafe impl plain::Plain for LpmKeyV4 {}

/// LPM key for IPv6 addresses (must match BPF struct layout)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct LpmKeyV6 {
    pub prefixlen: u32,  // Prefix length in bits (0-128 for IPv6)
    pub addr: [u32; 4],  // IPv6 address (128 bits) in network byte order
}

impl LpmKeyV6 {
    /// Create a new LPM key from an IPv6 address and prefix length
    pub fn new(addr: Ipv6Addr, prefixlen: u8) -> Self {
        let octets = addr.octets();
        let mut key = Self {
            prefixlen: prefixlen as u32,
            addr: [0; 4],
        };
        // Convert to u32 array in network byte order
        for i in 0..4 {
            let offset = i * 4;
            key.addr[i] = u32::from_be_bytes([
                octets[offset],
                octets[offset + 1],
                octets[offset + 2],
                octets[offset + 3],
            ]);
        }
        key
    }
    
    /// Create an LPM key for a /0 (match any) prefix
    pub fn any() -> Self {
        Self {
            prefixlen: 0,
            addr: [0; 4],
        }
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

impl fmt::Debug for LpmKeyV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixlen = self.prefixlen;
        let mut octets = [0u8; 16];
        for i in 0..4 {
            let bytes = u32::to_be_bytes(self.addr[i]);
            octets[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        let addr = Ipv6Addr::from(octets);
        write!(f, "{}/{}", addr, prefixlen)
    }
}

unsafe impl plain::Plain for LpmKeyV6 {}

/// Policy actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PolicyAction {
    Pass = 0,
    Drop = 1,
    Log = 2,
    TailCall = 3,
}

impl From<u32> for PolicyAction {
    fn from(v: u32) -> Self {
        match v {
            0 => PolicyAction::Pass,
            1 => PolicyAction::Drop,
            2 => PolicyAction::Log,
            3 => PolicyAction::TailCall,
            _ => PolicyAction::Pass,
        }
    }
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyAction::Pass => write!(f, "PASS"),
            PolicyAction::Drop => write!(f, "DROP"),
            PolicyAction::Log => write!(f, "LOG"),
            PolicyAction::TailCall => write!(f, "TAIL_CALL"),
        }
    }
}

impl std::str::FromStr for PolicyAction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pass" | "accept" | "allow" => Ok(PolicyAction::Pass),
            "drop" | "deny" | "reject" => Ok(PolicyAction::Drop),
            "log" => Ok(PolicyAction::Log),
            "tail-call" | "tailcall" | "tail_call" => Ok(PolicyAction::TailCall),
            _ => Err(anyhow::anyhow!("Invalid action: {}", s)),
        }
    }
}


/// XDP attach modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum XdpMode {
    Unspec = 0,
    Native = 1,
    Generic = 2,
    Offload = 3,
}

impl fmt::Display for XdpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdpMode::Unspec => write!(f, "unspec"),
            XdpMode::Native => write!(f, "native"),
            XdpMode::Generic => write!(f, "generic"),
            XdpMode::Offload => write!(f, "offload"),
        }
    }
}

impl std::str::FromStr for XdpMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "native" | "drv" | "driver" => Ok(XdpMode::Native),
            "generic" | "skb" => Ok(XdpMode::Generic),
            "offload" | "hw" | "hardware" => Ok(XdpMode::Offload),
            "" | "unspec" | "auto" => Ok(XdpMode::Unspec),
            _ => Err(anyhow::anyhow!("Invalid XDP mode: {}. Use: native, generic, offload", s)),
        }
    }
}

impl From<u32> for XdpMode {
    fn from(v: u32) -> Self {
        match v {
            1 => XdpMode::Native,
            2 => XdpMode::Generic,
            3 => XdpMode::Offload,
            _ => XdpMode::Unspec,
        }
    }
}

/// 5-tuple flow key (must match BPF struct layout)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct FlowKey {
    pub saddr: [u8; 16], // Can hold IPv4 (first 4 bytes) or IPv6
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub af: u8,
    pub _pad: u16,
}

// Implement Debug manually to avoid issues with packed struct
impl fmt::Debug for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Copy values from packed struct
        let sport = self.sport;
        let dport = self.dport;
        f.debug_struct("FlowKey")
            .field("src", &self.format_addr_src())
            .field("dst", &self.format_addr_dst())
            .field("sport", &sport)
            .field("dport", &dport)
            .field("protocol", &self.protocol_name())
            .finish()
    }
}

impl FlowKey {
    /// Create a new IPv4 flow key
    pub fn new_v4(
        saddr: Ipv4Addr,
        daddr: Ipv4Addr,
        sport: u16,
        dport: u16,
        protocol: u8,
    ) -> Self {
        let mut key = Self::default();
        key.saddr[..4].copy_from_slice(&saddr.octets());
        key.daddr[..4].copy_from_slice(&daddr.octets());
        key.sport = sport;
        key.dport = dport;
        key.protocol = protocol;
        key.af = AF_INET;
        key
    }

    /// Create a new IPv6 flow key
    pub fn new_v6(
        saddr: Ipv6Addr,
        daddr: Ipv6Addr,
        sport: u16,
        dport: u16,
        protocol: u8,
    ) -> Self {
        let mut key = Self::default();
        key.saddr.copy_from_slice(&saddr.octets());
        key.daddr.copy_from_slice(&daddr.octets());
        key.sport = sport;
        key.dport = dport;
        key.protocol = protocol;
        key.af = AF_INET6;
        key
    }

    fn format_addr_src(&self) -> String {
        if self.af == AF_INET {
            let octets: [u8; 4] = self.saddr[..4].try_into().unwrap();
            Ipv4Addr::from(octets).to_string()
        } else {
            let octets: [u8; 16] = self.saddr;
            Ipv6Addr::from(octets).to_string()
        }
    }

    fn format_addr_dst(&self) -> String {
        if self.af == AF_INET {
            let octets: [u8; 4] = self.daddr[..4].try_into().unwrap();
            Ipv4Addr::from(octets).to_string()
        } else {
            let octets: [u8; 16] = self.daddr;
            Ipv6Addr::from(octets).to_string()
        }
    }

    fn protocol_name(&self) -> &'static str {
        match self.protocol {
            p if p == libc::IPPROTO_TCP as u8 => "TCP",
            p if p == libc::IPPROTO_UDP as u8 => "UDP",
            p if p == libc::IPPROTO_ICMP as u8 => "ICMP",
            0 => "ANY",
            _ => "OTHER",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

unsafe impl plain::Plain for FlowKey {}

/// Rule action entry (embedded in PolicyValue)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct RuleAction {
    pub action: u32,
    pub priority: u8,
    pub _pad1: u8,
    pub _pad2: u16,
}

/// LPM policy entry stored in LPM trie maps (must match BPF struct layout)
/// Contains additional match criteria beyond the IP prefix and the policy value
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LpmPolicyEntry {
    // Additional match criteria (0 = any/wildcard)
    pub sport: u16,           // Source port (0 = any)
    pub dport: u16,           // Destination port (0 = any)
    pub protocol: u8,         // Protocol number (0 = any)
    pub src_prefixlen: u8,    // Original source prefix length for reference
    pub dst_prefixlen: u8,    // Original dest prefix length for reference
    pub _pad1: u8,
    
    // Destination address (IPv4 in first 4 bytes, or full IPv6)
    pub daddr: [u8; 16],
    pub af: u8,               // Address family
    pub _pad2: [u8; 3],
    
    // Policy value fields
    pub flags: u32,
    pub tail_call_idx: u32,
    pub rule_id: u64,
    pub priority: u32,
    pub num_actions: u8,
    pub _pad3: u8,
    pub _pad4: u16,
    pub actions: [RuleAction; MAX_ACTIONS_PER_RULE as usize],
}

impl Default for LpmPolicyEntry {
    fn default() -> Self {
        Self {
            sport: 0,
            dport: 0,
            protocol: 0,
            src_prefixlen: 0,
            dst_prefixlen: 0,
            _pad1: 0,
            daddr: [0; 16],
            af: AF_INET,
            _pad2: [0; 3],
            flags: 0,
            tail_call_idx: 0,
            rule_id: 0,
            priority: 0,
            num_actions: 0,
            _pad3: 0,
            _pad4: 0,
            actions: [RuleAction::default(); MAX_ACTIONS_PER_RULE as usize],
        }
    }
}

impl LpmPolicyEntry {
    /// Create a new LPM policy entry for IPv4
    pub fn new_v4(
        src_prefixlen: u8,
        daddr: Ipv4Addr,
        dst_prefixlen: u8,
        sport: u16,
        dport: u16,
        protocol: u8,
        rule_id: u64,
    ) -> Self {
        let mut entry = Self::default();
        entry.sport = sport;
        entry.dport = dport;
        entry.protocol = protocol;
        entry.src_prefixlen = src_prefixlen;
        entry.dst_prefixlen = dst_prefixlen;
        entry.daddr[..4].copy_from_slice(&daddr.octets());
        entry.af = AF_INET;
        entry.flags = flags::POLICY_FLAG_ENABLED;
        entry.rule_id = rule_id;
        entry.priority = 1000;
        entry
    }
    
    /// Create a new LPM policy entry for IPv6
    pub fn new_v6(
        src_prefixlen: u8,
        daddr: Ipv6Addr,
        dst_prefixlen: u8,
        sport: u16,
        dport: u16,
        protocol: u8,
        rule_id: u64,
    ) -> Self {
        let mut entry = Self::default();
        entry.sport = sport;
        entry.dport = dport;
        entry.protocol = protocol;
        entry.src_prefixlen = src_prefixlen;
        entry.dst_prefixlen = dst_prefixlen;
        entry.daddr.copy_from_slice(&daddr.octets());
        entry.af = AF_INET6;
        entry.flags = flags::POLICY_FLAG_ENABLED;
        entry.rule_id = rule_id;
        entry.priority = 1000;
        entry
    }
    
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
    
    pub fn with_tail_call(mut self, idx: u32) -> Self {
        self.tail_call_idx = idx;
        self
    }
    
    pub fn set_actions(&mut self, actions: &[(PolicyAction, u8)]) {
        let count = actions.len().min(MAX_ACTIONS_PER_RULE as usize);
        for (i, (action, priority)) in actions.iter().enumerate().take(count) {
            self.actions[i] = RuleAction {
                action: *action as u32,
                priority: *priority,
                _pad1: 0,
                _pad2: 0,
            };
        }
        self.num_actions = count as u8;
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

impl fmt::Debug for LpmPolicyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sport = self.sport;
        let dport = self.dport;
        let rule_id = self.rule_id;
        let priority = self.priority;
        let dst_str = if self.af == AF_INET {
            let octets: [u8; 4] = self.daddr[..4].try_into().unwrap();
            format!("{}/{}", Ipv4Addr::from(octets), self.dst_prefixlen)
        } else {
            format!("{}/{}", Ipv6Addr::from(self.daddr), self.dst_prefixlen)
        };
        f.debug_struct("LpmPolicyEntry")
            .field("src_prefix", &self.src_prefixlen)
            .field("dst", &dst_str)
            .field("sport", &sport)
            .field("dport", &dport)
            .field("protocol", &self.protocol)
            .field("rule_id", &rule_id)
            .field("priority", &priority)
            .finish()
    }
}

unsafe impl plain::Plain for LpmPolicyEntry {}

/// Policy rule value with embedded action list (must match BPF struct layout)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PolicyValue {
    pub flags: u32,
    pub tail_call_idx: u32,
    pub rule_id: u64,
    pub priority: u32,
    pub num_actions: u8,
    pub _pad1: u8,
    pub _pad2: u16,
    pub actions: [RuleAction; MAX_ACTIONS_PER_RULE as usize],
}

impl Default for PolicyValue {
    fn default() -> Self {
        Self {
            flags: 0,
            tail_call_idx: 0,
            rule_id: 0,
            priority: 0,
            num_actions: 0,
            _pad1: 0,
            _pad2: 0,
            actions: [RuleAction::default(); MAX_ACTIONS_PER_RULE as usize],
        }
    }
}

impl fmt::Debug for PolicyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Copy values from packed struct
        let flags = self.flags;
        let tail_call_idx = self.tail_call_idx;
        let rule_id = self.rule_id;
        let priority = self.priority;
        let num_actions = self.num_actions;
        f.debug_struct("PolicyValue")
            .field("flags", &flags)
            .field("tail_call_idx", &tail_call_idx)
            .field("rule_id", &rule_id)
            .field("priority", &priority)
            .field("num_actions", &num_actions)
            .finish()
    }
}

impl PolicyValue {
    pub fn new(rule_id: u64) -> Self {
        Self {
            flags: flags::POLICY_FLAG_ENABLED,
            tail_call_idx: 0,
            rule_id,
            priority: 1000,
            num_actions: 0,
            _pad1: 0,
            _pad2: 0,
            actions: [RuleAction::default(); MAX_ACTIONS_PER_RULE as usize],
        }
    }

    pub fn with_tail_call(mut self, idx: u32) -> Self {
        self.tail_call_idx = idx;
        self
    }

    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    pub fn set_actions(&mut self, actions: &[(PolicyAction, u8)]) {
        let count = actions.len().min(MAX_ACTIONS_PER_RULE as usize);
        for (i, (action, priority)) in actions.iter().enumerate().take(count) {
            self.actions[i] = RuleAction {
                action: *action as u32,
                priority: *priority,
                _pad1: 0,
                _pad2: 0,
            };
        }
        self.num_actions = count as u8;
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const _ as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

unsafe impl plain::Plain for PolicyValue {}

/// Per-rule statistics (must match BPF struct layout)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct RuleStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

impl fmt::Debug for RuleStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Copy values from packed struct
        let packets = self.packets;
        let bytes = self.bytes;
        let last_seen_ns = self.last_seen_ns;
        f.debug_struct("RuleStats")
            .field("packets", &packets)
            .field("bytes", &bytes)
            .field("last_seen_ns", &last_seen_ns)
            .finish()
    }
}

unsafe impl plain::Plain for RuleStats {}

/// Global statistics (must match BPF struct layout)
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct GlobalStats {
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

unsafe impl plain::Plain for GlobalStats {}

/// Ethertype statistics entry
#[derive(Clone, Debug, Default)]
pub struct EthertypeStats {
    pub ethertype: u16,
    pub packets: u64,
}

impl EthertypeStats {
    /// Get human-readable name for this ethertype
    pub fn name(&self) -> &'static str {
        ethertypes::name(self.ethertype)
    }
    
    /// Format ethertype as hex string (e.g., "0x0806")
    pub fn hex(&self) -> String {
        format!("0x{:04X}", self.ethertype)
    }
}

