// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Common types shared between BPF programs and userspace
//! These must match the definitions in policy_common.h

use std::fmt::{self, Display};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::FromStr;

use libc::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};

/// Maximum number of tail call programs in the dispatcher
pub const MAX_DISPATCHER_PROGS: u32 = 4;

/// Tail call feature definitions
/// Maps user-friendly feature names to dispatcher slot numbers
pub mod tail_call_features {
    use anyhow::{anyhow, Result};

    /// Convert a feature name to its dispatcher slot number
    pub fn feature_to_slot(feature: &str) -> Result<u32> {
        Err(anyhow!(
            "Unknown tail call feature: '{}'. No tail call features currently registered",
            feature
        ))
    }

    /// Get the program name for a feature (used when registering tail calls)
    pub fn feature_to_program(feature: &str) -> Result<&'static str> {
        Err(anyhow!(
            "Unknown tail call feature: '{}'. No tail call features currently registered",
            feature
        ))
    }

    /// List all supported feature names
    pub fn supported_features() -> &'static [&'static str] {
        &[]
    }
}

/// Maximum interfaces we track.  Sizes the per-interface BPF stats/config
/// maps; must be a power of two (the datapath masks with `ifindex %
/// MAX_INTERFACES`).  Keep in sync with MAX_INTERFACES in policy_common.h.
pub const MAX_INTERFACES: u32 = 16;

/// Local endpoint of the inspect veth pair (TC clone-redirect target).
pub const INSPECT_VETH_LOCAL: &str = "pe-inspect0";
/// Peer endpoint of the inspect veth pair (Suricata listens here).
pub const INSPECT_VETH_PEER: &str = "pe-inspect1";

/// True for interfaces that belong to the engine itself (the inspect veth
/// pair). These are hidden from interface discovery and rejected by policy
/// attach operations — the controller must never see or manage them.
pub fn is_internal_interface(name: &str) -> bool {
    name == INSPECT_VETH_LOCAL || name == INSPECT_VETH_PEER
}

/// Maximum actions per rule
pub const MAX_ACTIONS_PER_RULE: u32 = 4;

/// Maximum number of distinct source prefix groups in two-level LPM
pub const MAX_SRC_GROUPS: u32 = 4096;

/// Maximum destination LPM entries per source group inner trie
pub const MAX_DST_ENTRIES_PER_GROUP: u32 = 512;

/// Maximum L4 rules stored at each destination LPM leaf
pub const MAX_L4_RULES: usize = 8;

/// Maximum ancestor walk depth per LPM level
pub const MAX_LPM_ANCESTORS: usize = 8;

/// Dispatcher slot for the built-in TLS SNI inspection tail call program (XDP ingress)
pub const XDP_DISPATCHER_SNI_SLOT: u32 = 0;
/// Dispatcher slot for the XDP FIB forwarding program (XDP ingress only)
pub const XDP_DISPATCHER_FIB_SLOT: u32 = 1;
/// Dispatcher slot for the XDP flow cache update program (XDP ingress)
pub const XDP_DISPATCHER_FLOW_CACHE_SLOT: u32 = 2;
/// Dispatcher slot for the XDP QUIC Initial packet detector (XDP ingress)
pub const XDP_DISPATCHER_QUIC_SLOT: u32 = 3;

/// Dispatcher slot for the built-in TLS SNI inspection tail call program (TC egress)
pub const TC_DISPATCHER_SNI_SLOT: u32 = 0;
/// Dispatcher slot for the TC flow cache update program (TC egress)
pub const TC_DISPATCHER_FLOW_CACHE_SLOT: u32 = 1;
/// Dispatcher slot for the TC QUIC Initial packet detector (TC egress)
pub const TC_DISPATCHER_QUIC_SLOT: u32 = 2;

/// Max captured QUIC payload bytes per quic_inspect_event (matches QUIC_INSPECT_PAYLOAD_MAX)
pub const QUIC_INSPECT_PAYLOAD_MAX: usize = 1280;
/// Max DCID length per QUIC_INSPECT_MAX_DCID_LEN in policy_common.h
pub const QUIC_INSPECT_MAX_DCID_LEN: usize = 20;

/// Maximum ethertype counters per interface
pub const MAX_ETHERTYPE_COUNTERS: u32 = 16;

/// Policy flags
pub mod flags {
    /// Rule uses INSPECT action — mirror to Suricata for deep inspection
    pub const POLICY_FLAG_INSPECT: u32 = 1 << 1;
}

/// Flow key flags (must match FLOW_FLAG_* in policy_common.h)
pub mod flow_flags {
    pub const FLOW_FLAG_FRAGMENT: u16 = 1 << 0;
    pub const FLOW_FLAG_QUIC: u16 = 1 << 1;
    pub const FLOW_FLAG_QUIC_V1: u16 = 1 << 2;
    pub const FLOW_FLAG_QUIC_V2: u16 = 1 << 3;
}

/// QUIC version filter constants (stored in L4Rule.quic_version; must match policy_common.h)
pub const QUIC_VERSION_ANY: u32 = 0xFFFF_FFFF;
pub const QUIC_VERSION_V1: u32 = 0x0000_0001;
pub const QUIC_VERSION_V2: u32 = 0x6b33_43cf;

/// Flow verdict cache capacity (must match MAX_FLOW_VERDICTS in policy_common.h).
/// Used by both the Suricata IPS path and the QUIC SNI inspector.
pub const MAX_FLOW_VERDICTS: u32 = 131072;

/// Inspect mode constants
#[cfg(feature = "suricata")]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectMode {
    Disabled = 0,
    Ips = 1,
    /// IDS: clone traffic to Suricata for alerting, but never install DROP verdicts
    Ids = 2,
}

#[cfg(feature = "suricata")]
impl From<u32> for InspectMode {
    fn from(v: u32) -> Self {
        match v {
            1 => InspectMode::Ips,
            2 => InspectMode::Ids,
            _ => InspectMode::Disabled,
        }
    }
}

#[cfg(feature = "suricata")]
impl fmt::Display for InspectMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectMode::Disabled => write!(f, "DISABLED"),
            InspectMode::Ips => write!(f, "IPS"),
            InspectMode::Ids => write!(f, "IDS"),
        }
    }
}

/// Inspect configuration (must match BPF struct layout)
#[cfg(feature = "suricata")]
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct InspectConfig {
    pub mode: u32,
    pub mirror_ifindex: u32,
    pub _pad: [u32; 2],
}

#[cfg(feature = "suricata")]
impl InspectConfig {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

#[cfg(feature = "suricata")]
impl fmt::Debug for InspectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = self.mode;
        let mirror_ifindex = self.mirror_ifindex;
        f.debug_struct("InspectConfig")
            .field("mode", &InspectMode::from(mode))
            .field("mirror_ifindex", &mirror_ifindex)
            .finish()
    }
}

#[cfg(feature = "suricata")]
unsafe impl plain::Plain for InspectConfig {}

/// FIB forwarding mode constants (must match BPF policy_common.h)
pub const FIB_FORWARD_DISABLED: u32 = 0;
pub const FIB_FORWARD_ENABLED: u32 = 1;

/// uRPF (unicast Reverse Path Forwarding) mode constants (must match BPF
/// policy_common.h). uRPF is ingress-only (XDP); it is never applied on egress.
pub const URPF_DISABLED: u32 = 0;
pub const URPF_LOOSE: u32 = 1;
pub const URPF_STRICT: u32 = 2;

/// Per-interface Suricata inspection enable constants (must match BPF
/// policy_common.h). Gates INSPECT flow marking; requires an active
/// node-global inspect mode to have any effect.
pub const INSPECT_IF_DISABLED: u32 = 0;
pub const INSPECT_IF_ENABLED: u32 = 1;

/// FIB forwarding configuration (must match BPF struct fib_config layout).
/// The same per-interface entry also carries the uRPF mode and the Suricata
/// per-interface inspection flag so a single BPF map entry covers all three
/// XDP per-interface features.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct FibConfig {
    pub mode: u32,
    pub urpf_mode: u32,
    pub inspect_enabled: u32,
    pub _pad: u32,
}

impl FibConfig {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

unsafe impl plain::Plain for FibConfig {}

/// Flow cache mode constants (must match BPF policy_common.h)
#[cfg(feature = "ipfix")]
pub const FLOW_CACHE_DISABLED: u32 = 0;
#[cfg(feature = "ipfix")]
pub const FLOW_CACHE_ENABLED: u32 = 1;

/// Flow cache configuration (must match BPF struct flow_cache_config layout)
#[cfg(feature = "ipfix")]
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct FlowCacheConfig {
    pub enabled: u32,
    pub _pad: [u32; 3],
}

#[cfg(feature = "ipfix")]
impl FlowCacheConfig {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

#[cfg(feature = "ipfix")]
unsafe impl plain::Plain for FlowCacheConfig {}

/// Flow key for the flow cache (must match BPF struct flow_key layout).
#[cfg(feature = "ipfix")]
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub af: u8,
    pub flags: u16,
}

#[cfg(feature = "ipfix")]
const _: () = assert!(std::mem::size_of::<FlowKey>() == 40);

#[cfg(feature = "ipfix")]
impl FlowKey {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

#[cfg(feature = "ipfix")]
unsafe impl plain::Plain for FlowKey {}

/// Per-flow accounting entry in the flow cache (must match BPF struct flow_cache_entry).
#[cfg(feature = "ipfix")]
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FlowCacheEntry {
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub rule_id: u64,
    pub action: u32,
    pub _pad: u32,
}

#[cfg(feature = "ipfix")]
const _: () = assert!(std::mem::size_of::<FlowCacheEntry>() == 48);

#[cfg(feature = "ipfix")]
impl FlowCacheEntry {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

#[cfg(feature = "ipfix")]
unsafe impl plain::Plain for FlowCacheEntry {}

/// Flow export configuration (persisted in state file; not a BPF struct).
#[cfg(feature = "ipfix")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FlowExportConfig {
    pub enabled: bool,
    pub collector_host: String,
    pub collector_port: u16,
    pub idle_timeout_s: u32,
    pub active_timeout_s: u32,
}

#[cfg(feature = "ipfix")]
impl Default for FlowExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            collector_host: "127.0.0.1".to_string(),
            collector_port: 4739,
            idle_timeout_s: 15,
            active_timeout_s: 60,
        }
    }
}

/// Flow verdict key (must match BPF struct layout)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct FlowVerdictKey {
    pub saddr: [u8; 16], // IPv4 in first 4 bytes, or full IPv6
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub af: u8,
    pub _pad: u16,
    /// Interface index scoping this verdict (must match the BPF
    /// `flow_verdict_key.ifindex`). Policy is per-interface, so the cache key
    /// is too: XDP keys by `ctx->ingress_ifindex`, TC by `ctx->ifindex`.
    pub ifindex: u32,
}

impl FlowVerdictKey {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for FlowVerdictKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sport = self.sport;
        let dport = self.dport;
        let proto = self.protocol;
        let af = self.af;
        let ifindex = self.ifindex;
        f.debug_struct("FlowVerdictKey")
            .field("sport", &sport)
            .field("dport", &dport)
            .field("protocol", &proto)
            .field("af", &af)
            .field("ifindex", &ifindex)
            .finish()
    }
}

unsafe impl plain::Plain for FlowVerdictKey {}

/// Flow verdict value (must match BPF struct layout)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FlowVerdict {
    pub action: u32,
    pub _pad: u32,
    pub timestamp_ns: u64,
    pub expires_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    /// bpf_ktime_get_ns() at the most recent cache hit (CLOCK_MONOTONIC).
    pub last_seen_ns: u64,
    /// Rule that produced this verdict (0 = none / default / SNI / IPS). The
    /// dataplane does not touch rule_stats on cache hits; userspace folds this
    /// entry's packet/byte/last_seen deltas into `rule_stats[rule_id]` when it
    /// walks the cache (see server/verdict_harvest.rs).
    pub rule_id: u64,
}

impl FlowVerdict {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for FlowVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowVerdict")
            .field("action", &PolicyAction::from(self.action))
            .field("timestamp_ns", &self.timestamp_ns)
            .field("expires_ns", &self.expires_ns)
            .field("packets", &self.packets)
            .field("bytes", &self.bytes)
            .field("last_seen_ns", &self.last_seen_ns)
            .field("rule_id", &self.rule_id)
            .finish()
    }
}

unsafe impl plain::Plain for FlowVerdict {}

/// Well-known ethertypes
pub mod ethertypes {
    // Common protocols
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const WAKE_ON_LAN: u16 = 0x0842;
    pub const RARP: u16 = 0x8035;
    pub const APPLETALK: u16 = 0x809B;
    pub const AARP: u16 = 0x80F3;
    pub const VLAN_8021Q: u16 = 0x8100;
    pub const IPX: u16 = 0x8137;
    pub const NOVELL: u16 = 0x8138;
    pub const IPV6: u16 = 0x86DD;
    pub const FLOW_CONTROL: u16 = 0x8808;
    pub const SLOW: u16 = 0x8809; // LACP, etc
    pub const MPLS: u16 = 0x8847;
    pub const MPLS_MC: u16 = 0x8848;
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    pub const PPPOE_SESSION: u16 = 0x8864;
    pub const JUMBO_FRAMES: u16 = 0x8870;
    pub const EAPOL: u16 = 0x888E;
    pub const PROFINET: u16 = 0x8892;
    pub const HYPERSCSI: u16 = 0x889A;
    pub const VLAN_8021AD: u16 = 0x88A8;
    pub const POWERLINK: u16 = 0x88AB;
    pub const GOOSE: u16 = 0x88B8;
    pub const GSE: u16 = 0x88B9;
    pub const SV: u16 = 0x88BA;
    pub const LLDP: u16 = 0x88CC;
    pub const SERCOS: u16 = 0x88CD;
    pub const MRP: u16 = 0x88E3;
    pub const MACSEC: u16 = 0x88E5;
    pub const PBB: u16 = 0x88E7;
    pub const PTP: u16 = 0x88F7;
    pub const NC_SI: u16 = 0x88F8;
    pub const PRP: u16 = 0x88FB;
    pub const CFM: u16 = 0x8902;
    pub const FCOE: u16 = 0x8906;
    pub const FCOE_INIT: u16 = 0x8914;
    pub const ROCE: u16 = 0x8915;
    pub const TTE: u16 = 0x891D;
    pub const HSR: u16 = 0x892F;
    pub const ECTP: u16 = 0x9000;
    pub const TRILL: u16 = 0x22F3;
    pub const DECNET: u16 = 0x6003;

    /// Convert ethertype to human-readable name
    pub fn name(ethertype: u16) -> &'static str {
        match ethertype {
            IPV4 => "IPv4",
            ARP => "ARP",
            WAKE_ON_LAN => "Wake-on-LAN",
            RARP => "RARP",
            APPLETALK => "AppleTalk",
            AARP => "AppleTalk ARP",
            VLAN_8021Q => "802.1Q VLAN",
            IPX => "IPX",
            NOVELL => "Novell",
            IPV6 => "IPv6",
            FLOW_CONTROL => "Flow Control",
            SLOW => "Slow Protocols (LACP)",
            MPLS => "MPLS",
            MPLS_MC => "MPLS Multicast",
            PPPOE_DISCOVERY => "PPPoE Discovery",
            PPPOE_SESSION => "PPPoE Session",
            JUMBO_FRAMES => "Jumbo Frames",
            EAPOL => "EAP over LAN (802.1X)",
            PROFINET => "PROFINET",
            HYPERSCSI => "HyperSCSI",
            VLAN_8021AD => "802.1ad QinQ",
            POWERLINK => "Ethernet Powerlink",
            GOOSE => "IEC 61850 GOOSE",
            GSE => "IEC 61850 GSE",
            SV => "IEC 61850 SV",
            LLDP => "LLDP",
            SERCOS => "SERCOS III",
            MRP => "MRP (Media Redundancy)",
            MACSEC => "MACsec (802.1AE)",
            PBB => "Provider Backbone Bridges",
            PTP => "PTP (IEEE 1588)",
            NC_SI => "NC-SI",
            PRP => "PRP (Parallel Redundancy)",
            CFM => "CFM (802.1ag)",
            FCOE => "FCoE",
            FCOE_INIT => "FCoE Init",
            ROCE => "RoCE",
            TTE => "TTEthernet",
            HSR => "HSR",
            ECTP => "Ethernet Config Testing",
            TRILL => "TRILL",
            DECNET => "DECnet",
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
    pub prefixlen: u32, // Prefix length in bits (0-32 for IPv4)
    pub addr: [u8; 4],  // IPv4 address octets (network byte order)
}

impl LpmKeyV4 {
    /// Create a new LPM key from an IPv4 address and prefix length
    /// The address is stored in network byte order (big-endian) as expected by BPF LPM trie
    pub fn new(addr: Ipv4Addr, prefixlen: u8) -> Self {
        Self {
            prefixlen: prefixlen as u32,
            // Store as network byte order (big-endian) - just copy the octets as a u32
            addr: addr.octets(),
        }
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
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for LpmKeyV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixlen = self.prefixlen;
        // addr is stored as octets in network byte order
        let addr = Ipv4Addr::from(self.addr);
        write!(f, "{}/{}", addr, prefixlen)
    }
}

unsafe impl plain::Plain for LpmKeyV4 {}

/// LPM key for IPv6 addresses (must match BPF struct layout)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct LpmKeyV6 {
    pub prefixlen: u32, // Prefix length in bits (0-128 for IPv6)
    pub addr: [u8; 16], // IPv6 address octets (network byte order)
}

impl LpmKeyV6 {
    /// Create a new LPM key from an IPv6 address and prefix length
    pub fn new(addr: Ipv6Addr, prefixlen: u8) -> Self {
        let octets = addr.octets();
        let mut key = Self {
            prefixlen: prefixlen as u32,
            addr: [0; 16],
        };
        key.addr.copy_from_slice(&octets);
        key
    }

    /// Create an LPM key for a /0 (match any) prefix
    pub fn any() -> Self {
        Self {
            prefixlen: 0,
            addr: [0; 16],
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for LpmKeyV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixlen = self.prefixlen;
        let addr = Ipv6Addr::from(self.addr);
        write!(f, "{}/{}", addr, prefixlen)
    }
}

unsafe impl plain::Plain for LpmKeyV6 {}

/// Source LPM trie key for IPv4 (must match BPF `struct src_lpm_key_v4`).
///
/// Rules are scoped per-interface: the trie descends ifindex bits first (exact
/// match, 32 bits) then longest-prefix-matches on the address. `prefixlen` is
/// encoded as `32 + addr_prefixlen`, so valid values are 32..=64.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct SrcLpmKeyV4 {
    pub prefixlen: u32, // 32 + addr_prefixlen (32..=64)
    pub ifindex: u32,   // host-order interface index (exact match)
    pub addr: [u8; 4],  // IPv4 address octets (network byte order)
}

impl SrcLpmKeyV4 {
    /// Create a new source LPM key from ifindex, address, and address prefix length.
    pub fn new(ifindex: u32, addr: Ipv4Addr, addr_prefixlen: u8) -> Self {
        Self {
            prefixlen: 32 + addr_prefixlen as u32,
            ifindex,
            addr: addr.octets(),
        }
    }

    /// Interface-scoped "any address" key (/0 on the address, exact ifindex).
    pub fn any_on(ifindex: u32) -> Self {
        Self {
            prefixlen: 32,
            ifindex,
            addr: [0; 4],
        }
    }

    /// The address portion of the prefixlen (subtracting the 32 ifindex bits).
    pub fn addr_prefixlen(&self) -> u8 {
        let pl = self.prefixlen;
        (pl.saturating_sub(32)) as u8
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for SrcLpmKeyV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ifindex = self.ifindex;
        let addr = Ipv4Addr::from(self.addr);
        let plen = self.addr_prefixlen();
        write!(f, "if{}:{}/{}", ifindex, addr, plen)
    }
}

unsafe impl plain::Plain for SrcLpmKeyV4 {}

/// Source LPM trie key for IPv6 (must match BPF `struct src_lpm_key_v6`).
/// `prefixlen` is encoded as `32 + addr_prefixlen`, valid values 32..=160.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct SrcLpmKeyV6 {
    pub prefixlen: u32, // 32 + addr_prefixlen (32..=160)
    pub ifindex: u32,
    pub addr: [u8; 16],
}

impl SrcLpmKeyV6 {
    pub fn new(ifindex: u32, addr: Ipv6Addr, addr_prefixlen: u8) -> Self {
        let mut key = Self {
            prefixlen: 32 + addr_prefixlen as u32,
            ifindex,
            addr: [0; 16],
        };
        key.addr.copy_from_slice(&addr.octets());
        key
    }

    pub fn any_on(ifindex: u32) -> Self {
        Self {
            prefixlen: 32,
            ifindex,
            addr: [0; 16],
        }
    }

    pub fn addr_prefixlen(&self) -> u8 {
        let pl = self.prefixlen;
        (pl.saturating_sub(32)) as u8
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for SrcLpmKeyV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ifindex = self.ifindex;
        let addr = Ipv6Addr::from(self.addr);
        let plen = self.addr_prefixlen();
        write!(f, "if{}:{}/{}", ifindex, addr, plen)
    }
}

unsafe impl plain::Plain for SrcLpmKeyV6 {}

/// Policy actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum PolicyAction {
    Pass = 0,
    Drop = 1,
    Log = 2,
    /// Internal action: triggers a tail call for further processing
    TailCall = 3,
    /// Mirror to Suricata for deep packet inspection (requires suricata feature)
    #[cfg(feature = "suricata")]
    Inspect = 4,
}

impl From<u32> for PolicyAction {
    fn from(v: u32) -> Self {
        match v {
            0 => PolicyAction::Pass,
            1 => PolicyAction::Drop,
            2 => PolicyAction::Log,
            3 => PolicyAction::TailCall,
            #[cfg(feature = "suricata")]
            4 => PolicyAction::Inspect,
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
            PolicyAction::TailCall => write!(f, "TAILCALL"),
            #[cfg(feature = "suricata")]
            PolicyAction::Inspect => write!(f, "INSPECT"),
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
            #[cfg(feature = "suricata")]
            "inspect" => Ok(PolicyAction::Inspect),
            _ => Err(anyhow::anyhow!("Invalid action: {}", s)),
        }
    }
}

/// Action-specific parameters, typed per action kind.
///
/// Stored as a raw `u64` in the BPF `rule_action.param` field.
/// This enum is the Rust-level representation used by the service layer;
/// it is converted to/from the raw field via [`ActionParams::to_raw`] and
/// [`ActionParams::from_action_and_raw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ActionParams {
    /// No parameters (used for DROP, PASS, INSPECT, TAIL_CALL).
    None,
    /// Parameters for the LOG action.
    Log {
        /// Minimum interval between log events for this rule, in nanoseconds.
        /// 0 means no rate limiting (every matching packet is logged).
        rate_limit_ns: u64,
    },
}

impl ActionParams {
    /// Encode to the raw `u64` stored in `rule_action.param`.
    pub fn to_raw(self) -> u64 {
        match self {
            ActionParams::None => 0,
            ActionParams::Log { rate_limit_ns } => rate_limit_ns,
        }
    }

    /// Reconstruct from an action type and the raw `param` field.
    pub fn from_action_and_raw(action: PolicyAction, raw: u64) -> Self {
        match action {
            PolicyAction::Log => ActionParams::Log { rate_limit_ns: raw },
            _ => ActionParams::None,
        }
    }
}

/// Traffic direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Direction {
    Ingress,
    Egress,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Ingress => write!(f, "ingress"),
            Direction::Egress => write!(f, "egress"),
        }
    }
}

impl std::str::FromStr for Direction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ingress" | "in" => Ok(Direction::Ingress),
            "egress" | "out" => Ok(Direction::Egress),
            _ => Err(anyhow::anyhow!(
                "Invalid direction: {}. Use: ingress, egress",
                s
            )),
        }
    }
}

/// XDP attach modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
            _ => Err(anyhow::anyhow!(
                "Invalid XDP mode: {}. Use: native, generic, offload",
                s
            )),
        }
    }
}

/// Controls what happens to BPF programs and pinned maps when the daemon stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopBehavior {
    /// Detach all XDP/TC programs and remove pinned maps on shutdown.
    /// Rules are preserved in state.json for restore on next start.
    #[default]
    ClearState,
    /// Leave programs attached and maps pinned.
    /// Traffic continues to be enforced while the daemon is not running.
    PreserveState,
}

impl fmt::Display for StopBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopBehavior::ClearState => write!(f, "clear-state"),
            StopBehavior::PreserveState => write!(f, "preserve-state"),
        }
    }
}

impl std::str::FromStr for StopBehavior {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "clear-state" | "clear" => Ok(StopBehavior::ClearState),
            "preserve-state" | "preserve" => Ok(StopBehavior::PreserveState),
            _ => Err(anyhow::anyhow!(
                "Invalid stop behavior: '{}'. Use: clear-state or preserve-state",
                s
            )),
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

/// Rule action entry
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct RuleAction {
    pub action: u32,
    pub priority: u8,
    pub _pad1: u8,
    pub _pad2: u16,
    /// Action parameter (e.g., rate-limit interval in nanoseconds for LOG; 0 = no limit)
    pub param: u64,
}

/// L4 Protocol
#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Protocol(u8);

impl Protocol {
    pub fn new(protocol: u8) -> Self {
        Protocol(protocol)
    }
}

impl Deref for Protocol {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto_name = match self.0 as i32 {
            0 => "ANY".to_string(),
            IPPROTO_ICMP => "ICMP".to_string(),
            IPPROTO_TCP => "TCP".to_string(),
            IPPROTO_UDP => "UDP".to_string(),
            IPPROTO_ICMPV6 => "ICMPv6".to_string(),
            n => format!("{}", n),
        };
        write!(f, "{}", proto_name)
    }
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        Protocol(v)
    }
}

impl TryFrom<&str> for Protocol {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "any" => Ok(Protocol(0)),
            "icmp" => Ok(Protocol(IPPROTO_ICMP as u8)),
            "tcp" => Ok(Protocol(IPPROTO_TCP as u8)),
            "udp" => Ok(Protocol(IPPROTO_UDP as u8)),
            "icmpv6" => Ok(Protocol(IPPROTO_ICMPV6 as u8)),
            s if s.parse::<u8>().is_ok() => Ok(Protocol(s.parse()?)),
            _ => Err(anyhow::anyhow!("Unknown protocol: {s}")),
        }
    }
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let proto = match s.to_lowercase().as_str() {
            "any" => 0,
            "icmp" => IPPROTO_ICMP as u8,
            "tcp" => IPPROTO_TCP as u8,
            "udp" => IPPROTO_UDP as u8,
            "icmpv6" => IPPROTO_ICMPV6 as u8,
            _ => {
                // Try parsing as number
                s.parse::<u8>().map_err(|_| {
                    anyhow::anyhow!(
                        "Invalid protocol: {}. Use: any, icmp, tcp, udp, icmpv6 or numeric value",
                        s
                    )
                })?
            }
        };
        Ok(Protocol(proto))
    }
}

/// Maximum SNI pattern length
pub const MAX_SNI_LEN: usize = 128;

/// SNI match type constants
pub const SNI_MATCH_NONE: u8 = 0;
pub const SNI_MATCH_EXACT: u8 = 1;
pub const SNI_MATCH_SUFFIX: u8 = 2;

/// SNI rule entry stored in the sni_rules BPF hash map (keyed by rule_id).
/// Must match BPF struct sni_rule_entry layout from policy_common.h.
/// Looked up exclusively by the xdp_sni_inspect tail call program.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SniRuleEntry {
    pub sni_match_type: u8, // SNI_MATCH_EXACT or SNI_MATCH_SUFFIX
    pub sni_len: u8,        // Byte length of sni_pattern
    pub _pad: [u8; 2],
    pub sni_pattern: [u8; MAX_SNI_LEN], // Lowercase domain pattern, null-terminated
}

impl Default for SniRuleEntry {
    fn default() -> Self {
        Self {
            sni_match_type: 0,
            sni_len: 0,
            _pad: [0; 2],
            sni_pattern: [0; MAX_SNI_LEN],
        }
    }
}

impl SniRuleEntry {
    /// Create a new SNI rule entry from a match type and pattern string.
    pub fn new(match_type: u8, pattern: &str) -> Self {
        let mut entry = Self {
            sni_match_type: match_type,
            ..Self::default()
        };
        let bytes = pattern.as_bytes();
        let len = bytes.len().min(MAX_SNI_LEN - 1);
        entry.sni_pattern[..len].copy_from_slice(&bytes[..len]);
        entry.sni_len = len as u8;
        entry
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

unsafe impl plain::Plain for SniRuleEntry {}

/// MAC rule entry stored in the `mac_rules` / `tc_mac_rules` sidecar BPF map.
/// Keyed by `rule_id` (u64); looked up when `l4_rule.mac_match_flags != 0`.
/// Must match BPF `struct mac_rule_entry` in policy_common.h (12 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MacRuleEntry {
    /// Source MAC to match (all-zeros = any). Used when MAC_MATCH_SRC is set.
    pub src_mac: [u8; 6],
    /// Destination MAC to match (all-zeros = any). Used when MAC_MATCH_DST is set.
    pub dst_mac: [u8; 6],
}

const _: () = assert!(std::mem::size_of::<MacRuleEntry>() == 12);

impl MacRuleEntry {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

unsafe impl plain::Plain for MacRuleEntry {}

/// Source LPM trie value — result of first-level lookup (must match BPF struct src_lpm_value)
///
/// Maps a source prefix to a group ID used to index into the `src_groups_v4/v6`
/// HASH_OF_MAPS, where each group holds an inner destination LPM trie.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct SrcLpmValue {
    /// Stored prefix length of this entry (used for ancestor walk)
    pub src_prefixlen: u32,
    /// Key into src_groups_v4/v6 HASH_OF_MAPS
    pub src_group_id: u32,
}

impl SrcLpmValue {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for SrcLpmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefixlen = self.src_prefixlen;
        let group_id = self.src_group_id;
        f.debug_struct("SrcLpmValue")
            .field("src_prefixlen", &prefixlen)
            .field("src_group_id", &group_id)
            .finish()
    }
}

unsafe impl plain::Plain for SrcLpmValue {}

/// MAC match flag bits for `L4Rule.mac_match_flags` (must match policy_common.h)
pub const MAC_MATCH_SRC: u8 = 1 << 0;
pub const MAC_MATCH_DST: u8 = 1 << 1;

/// Terminal L4 rule — result of two-level LPM lookup (must match BPF struct l4_rule)
///
/// Contains match criteria (protocol, ports) and ordered policy actions.
/// Lives inside a `DstLpmValue.rules[]` array.
///
/// When `mac_match_flags != 0`, a separate sidecar map (`mac_rules` / `tc_mac_rules`)
/// is consulted during BPF execution using `rule_id` as the key.
///
/// Layout (96 bytes, packed — must match BPF struct l4_rule in policy_common.h):
///   offset  0: sport, dport, protocol, sni_match_type, num_actions, mac_match_flags
///   offset  8: rule_id
///   offset 16: flags, tail_call_idx, quic_version, _pad2
///   offset 32: actions[MAX_ACTIONS_PER_RULE]
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct L4Rule {
    pub sport: u16,
    pub dport: u16,
    pub protocol: u8,
    pub sni_match_type: u8,
    pub num_actions: u8,
    /// MAC match flags: MAC_MATCH_SRC | MAC_MATCH_DST; 0 = no L2 filter
    pub mac_match_flags: u8,
    pub rule_id: u64,
    pub flags: u32,
    pub tail_call_idx: u32,
    pub quic_version: u32,
    pub _pad2: u32,
    pub actions: [RuleAction; MAX_ACTIONS_PER_RULE as usize],
}

const _: () = assert!(std::mem::size_of::<L4Rule>() == 96);

impl Default for L4Rule {
    fn default() -> Self {
        Self {
            sport: 0,
            dport: 0,
            protocol: 0,
            sni_match_type: SNI_MATCH_NONE,
            num_actions: 0,
            mac_match_flags: 0,
            rule_id: 0,
            flags: 0,
            tail_call_idx: 0,
            quic_version: 0,
            _pad2: 0,
            actions: [RuleAction::default(); MAX_ACTIONS_PER_RULE as usize],
        }
    }
}

impl L4Rule {
    /// Set MAC filter flags on this rule.
    /// The actual MAC bytes live in the sidecar `mac_rules` / `tc_mac_rules` BPF map.
    /// `Some(_)` sets the corresponding flag; `None` leaves it unset (no filtering).
    pub fn set_mac_filter(&mut self, src_mac: Option<[u8; 6]>, dst_mac: Option<[u8; 6]>) {
        if src_mac.is_some() {
            self.mac_match_flags |= MAC_MATCH_SRC;
        }
        if dst_mac.is_some() {
            self.mac_match_flags |= MAC_MATCH_DST;
        }
    }

    pub fn set_actions(&mut self, actions: &[(PolicyAction, u8, ActionParams)]) {
        let count = actions.len().min(MAX_ACTIONS_PER_RULE as usize);
        for (i, (action, priority, params)) in actions.iter().enumerate().take(count) {
            self.actions[i] = RuleAction {
                action: *action as u32,
                priority: *priority,
                _pad1: 0,
                _pad2: 0,
                param: params.to_raw(),
            };
        }
        self.num_actions = count as u8;
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fmt::Debug for L4Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sport = self.sport;
        let dport = self.dport;
        let rule_id = self.rule_id;
        let mac_match_flags = self.mac_match_flags;
        f.debug_struct("L4Rule")
            .field("rule_id", &rule_id)
            .field("protocol", &self.protocol)
            .field("sport", &sport)
            .field("dport", &dport)
            .field("num_actions", &self.num_actions)
            .field("mac_match_flags", &mac_match_flags)
            .finish()
    }
}

unsafe impl plain::Plain for L4Rule {}

/// Destination LPM trie value — second-level lookup result (must match BPF struct dst_lpm_value)
// Size: 4 (dst_prefixlen) + 1 (count) + 3 (_pad) + MAX_L4_RULES * sizeof(L4Rule)
//     = 8 + 8 * 96 = 776 bytes
///
/// Each inner trie entry holds up to `MAX_L4_RULES` sorted L4 rules.
/// `dst_prefixlen` is stored for the ancestor walk.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DstLpmValue {
    /// Stored prefix length of this entry (used for ancestor walk)
    pub dst_prefixlen: u32,
    /// Number of valid rules in `rules[]` (0..MAX_L4_RULES)
    pub count: u8,
    pub _pad: [u8; 3],
    pub rules: [L4Rule; MAX_L4_RULES],
}

impl Default for DstLpmValue {
    fn default() -> Self {
        Self {
            dst_prefixlen: 0,
            count: 0,
            _pad: [0; 3],
            rules: [L4Rule::default(); MAX_L4_RULES],
        }
    }
}

impl DstLpmValue {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

const _: () = assert!(std::mem::size_of::<DstLpmValue>() == 776);

impl fmt::Debug for DstLpmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dst_prefixlen = self.dst_prefixlen;
        let count = self.count;
        f.debug_struct("DstLpmValue")
            .field("dst_prefixlen", &dst_prefixlen)
            .field("count", &count)
            .finish()
    }
}

unsafe impl plain::Plain for DstLpmValue {}

/// Per-rule statistics (must match BPF struct layout)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RuleStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
    /// Timestamp of the last LOG event emitted for this rule (nanoseconds,
    /// CLOCK_MONOTONIC). Used by the BPF LOG rate-limiter; 0 = never logged.
    pub last_log_ns: u64,
}

impl fmt::Debug for RuleStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleStats")
            .field("packets", &self.packets)
            .field("bytes", &self.bytes)
            .field("last_seen_ns", &self.last_seen_ns)
            .finish()
    }
}

impl RuleStats {
    /// Convert to byte slice for BPF map operations
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const RuleStats as *const u8,
                std::mem::size_of::<RuleStats>(),
            )
        }
    }
}

unsafe impl plain::Plain for RuleStats {}

/// Per-protocol packet/byte stats (used by get_proto_stats)
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ProtoStats {
    pub packets: u64,
    pub bytes: u64,
}

unsafe impl plain::Plain for ProtoStats {}

pub const HIST_BUCKETS: usize = 64;

/// L3 protocol buckets in `GlobalStats::l3` (0=IPv4, 1=IPv6, 2=ARP, 3=MPLS, 4=Other).
/// Keep in sync with L3_PROTO_BUCKETS in policy_common.h.
pub const L3_BUCKETS: usize = 5;

/// QUIC version slots in `GlobalStats::quic` (0=unused, 1=v1, 2=v2, 3=other).
/// Keep in sync with QUIC_STATS_SLOTS in policy_common.h.
pub const QUIC_SLOTS: usize = 4;

/// Per-IP-protocol slots in `GlobalStats::proto`.  One dedicated slot per
/// tracked protocol plus a catch-all (slot 0); the BPF side buckets with
/// ip_proto_to_slot().  Keep in sync with IP_PROTO_SLOTS and the
/// IP_PROTO_SLOT_* defines in policy_common.h.
pub const IP_PROTO_SLOTS: usize = 8;

/// IP protocol number represented by each `GlobalStats::proto` slot
/// (slot 0 = catch-all "other", reported as protocol 0).  Must mirror the
/// IP_PROTO_SLOT_* → PROTO_* mapping in policy_common.h.
pub const IP_PROTO_SLOT_PROTOS: [u8; IP_PROTO_SLOTS] = [
    0,   // IP_PROTO_SLOT_OTHER
    1,   // IP_PROTO_SLOT_ICMP
    6,   // IP_PROTO_SLOT_TCP
    17,  // IP_PROTO_SLOT_UDP
    47,  // IP_PROTO_SLOT_GRE
    50,  // IP_PROTO_SLOT_ESP
    58,  // IP_PROTO_SLOT_ICMPV6
    132, // IP_PROTO_SLOT_SCTP
];

/// Global statistics (must match BPF struct layout)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
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
    pub inspect_redirects: u64,
    pub fragments: u64,
    pub verdict_pass_packets: u64,
    pub verdict_pass_bytes: u64,
    pub verdict_drop_packets: u64,
    pub verdict_drop_bytes: u64,
    pub fib_forwarded_packets: u64,
    pub fib_forwarded_bytes: u64,
    pub fib_fallback_packets: u64,
    pub urpf_drop_packets: u64,
    pub urpf_drop_bytes: u64,
    /// Per-L3-protocol counters (0=IPv4, 1=IPv6, 2=ARP, 3=MPLS, 4=Other)
    pub l3: [ProtoStats; L3_BUCKETS],
    /// Per-QUIC-version counters (0=unused, 1=v1, 2=v2, 3=other; XDP only)
    pub quic: [ProtoStats; QUIC_SLOTS],
    /// log2(ns) processing-time histogram
    pub proc_hist: [u64; HIST_BUCKETS],
    /// Per-IP-protocol counters, indexed by slot (see IP_PROTO_SLOT_PROTOS)
    pub proto: [ProtoStats; IP_PROTO_SLOTS],
}

impl Default for GlobalStats {
    fn default() -> Self {
        // All-zero is valid for this plain-old-data struct; derive(Default)
        // is unavailable because std only implements Default for arrays of
        // up to 32 elements and proc_hist has HIST_BUCKETS (64).
        unsafe { std::mem::zeroed() }
    }
}

impl GlobalStats {
    /// Convert to byte slice for BPF map operations
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const GlobalStats as *const u8,
                std::mem::size_of::<GlobalStats>(),
            )
        }
    }

    /// Add `other`'s counters into `self`.  Used to sum the per-CPU copies of
    /// one interface slot and to aggregate across interface slots for the
    /// engine-wide l3/quic/proc_hist views.
    pub fn accumulate(&mut self, other: &GlobalStats) {
        self.rx_packets += other.rx_packets;
        self.rx_bytes += other.rx_bytes;
        self.tx_packets += other.tx_packets;
        self.tx_bytes += other.tx_bytes;
        self.policy_matches += other.policy_matches;
        self.policy_drops += other.policy_drops;
        self.policy_pass += other.policy_pass;
        self.policy_redirects += other.policy_redirects;
        self.parse_errors += other.parse_errors;
        self.tail_calls += other.tail_calls;
        self.bum_packets += other.bum_packets;
        self.non_ip_unicast += other.non_ip_unicast;
        self.inspect_redirects += other.inspect_redirects;
        self.fragments += other.fragments;
        self.verdict_pass_packets += other.verdict_pass_packets;
        self.verdict_pass_bytes += other.verdict_pass_bytes;
        self.verdict_drop_packets += other.verdict_drop_packets;
        self.verdict_drop_bytes += other.verdict_drop_bytes;
        self.fib_forwarded_packets += other.fib_forwarded_packets;
        self.fib_forwarded_bytes += other.fib_forwarded_bytes;
        self.fib_fallback_packets += other.fib_fallback_packets;
        self.urpf_drop_packets += other.urpf_drop_packets;
        self.urpf_drop_bytes += other.urpf_drop_bytes;
        for (d, s) in self.l3.iter_mut().zip(other.l3.iter()) {
            d.packets += s.packets;
            d.bytes += s.bytes;
        }
        for (d, s) in self.quic.iter_mut().zip(other.quic.iter()) {
            d.packets += s.packets;
            d.bytes += s.bytes;
        }
        for (d, s) in self.proc_hist.iter_mut().zip(other.proc_hist.iter()) {
            *d += *s;
        }
        for (d, s) in self.proto.iter_mut().zip(other.proto.iter()) {
            d.packets += s.packets;
            d.bytes += s.bytes;
        }
    }
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

/// Statistics for a single non-IP sender, keyed by (source MAC, ethertype).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonIpSenderEntry {
    /// Source MAC address (6 bytes).
    pub mac: [u8; 6],
    /// Ethertype (host byte order).
    pub ethertype: u16,
    /// Packet count seen from this sender for this ethertype.
    pub packets: u64,
}

impl NonIpSenderEntry {
    /// Format the MAC address as a colon-separated hex string.
    pub fn mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    mod lpm_key_v4 {
        use super::*;

        #[test]
        fn test_new_creates_correct_key() {
            let addr: Ipv4Addr = "192.168.1.100".parse().unwrap();
            let key = LpmKeyV4::new(addr, 24);

            // Copy from packed struct to avoid alignment issues
            let prefixlen = key.prefixlen;
            assert_eq!(prefixlen, 24);
        }

        #[test]
        fn test_roundtrip_preserves_address() {
            let original: Ipv4Addr = "10.20.30.40".parse().unwrap();
            let key = LpmKeyV4::new(original, 32);

            // Copy from packed struct to avoid alignment issues
            let addr = key.addr;
            // Extract address back using the same method as Debug impl
            let recovered = Ipv4Addr::from(addr);

            assert_eq!(original, recovered, "IPv4 address should survive roundtrip");
        }

        #[test]
        fn test_debug_format() {
            let addr: Ipv4Addr = "172.16.0.0".parse().unwrap();
            let key = LpmKeyV4::new(addr, 12);

            let debug_str = format!("{:?}", key);
            assert!(
                debug_str.contains("172.16.0.0"),
                "Debug should contain correct IP: {}",
                debug_str
            );
            assert!(
                debug_str.contains("/12"),
                "Debug should contain prefix length: {}",
                debug_str
            );
        }

        #[test]
        fn test_any_prefix() {
            let key = LpmKeyV4::any();
            // Copy from packed struct to avoid alignment issues
            let prefixlen = key.prefixlen;
            let addr = key.addr;
            assert_eq!(prefixlen, 0);
            assert_eq!(addr, [0, 0, 0, 0]);
        }

        #[test]
        fn test_various_addresses() {
            let test_cases = [
                ("0.0.0.0", 0),
                ("127.0.0.1", 8),
                ("192.168.1.1", 24),
                ("255.255.255.255", 32),
                ("10.0.0.1", 8),
            ];

            for (addr_str, prefix) in test_cases {
                let addr: Ipv4Addr = addr_str.parse().unwrap();
                let key = LpmKeyV4::new(addr, prefix);
                let recovered = Ipv4Addr::from(key.addr);

                assert_eq!(
                    addr, recovered,
                    "Address {} should survive roundtrip",
                    addr_str
                );
            }
        }
    }

    mod lpm_key_v6 {
        use super::*;

        #[test]
        fn test_new_creates_correct_key() {
            let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
            let key = LpmKeyV6::new(addr, 64);

            // Copy from packed struct to avoid alignment issues
            let prefixlen = key.prefixlen;
            assert_eq!(prefixlen, 64);
        }

        #[test]
        fn test_roundtrip_preserves_address() {
            let original: Ipv6Addr = "2001:db8:1234:5678:9abc:def0:1234:5678".parse().unwrap();
            let key = LpmKeyV6::new(original, 128);

            // Copy from packed struct to avoid alignment issues
            let addr = key.addr;
            // Extract address back using the same method as Debug impl (addr is octets)
            let recovered = Ipv6Addr::from(addr);

            assert_eq!(original, recovered, "IPv6 address should survive roundtrip");
        }

        #[test]
        fn test_debug_format() {
            let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
            let key = LpmKeyV6::new(addr, 32);

            let debug_str = format!("{:?}", key);
            // IPv6 addresses can be formatted in different ways, check for key parts
            assert!(
                debug_str.contains("2001:db8::1") || debug_str.contains("2001:db8:0:0:0:0:0:1"),
                "Debug should contain correct IP: {}",
                debug_str
            );
            assert!(
                debug_str.contains("/32"),
                "Debug should contain prefix length: {}",
                debug_str
            );
        }

        #[test]
        fn test_any_prefix() {
            let key = LpmKeyV6::any();
            // Copy from packed struct to avoid alignment issues
            let prefixlen = key.prefixlen;
            let addr = key.addr;
            assert_eq!(prefixlen, 0);
            assert_eq!(addr, [0u8; 16]);
        }

        #[test]
        fn test_various_addresses() {
            let test_cases = [
                ("::", 0),
                ("::1", 128),
                ("2001:db8::", 32),
                ("fe80::1", 10),
                ("fd00:1:2:3:4:5:6:7", 64),
                ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128),
            ];

            for (addr_str, prefix) in test_cases {
                let addr: Ipv6Addr = addr_str.parse().unwrap();
                let key = LpmKeyV6::new(addr, prefix);

                // Recover using same logic as Debug impl
                let recovered = Ipv6Addr::from(key.addr);

                assert_eq!(
                    addr, recovered,
                    "Address {} should survive roundtrip",
                    addr_str
                );
            }
        }

        #[test]
        fn test_byte_order_consistency() {
            // This test specifically catches the to_be_bytes vs to_ne_bytes bug
            // The address 2001:db8:: has specific byte values we can check
            let addr: Ipv6Addr = "2001:0db8:0000:0000:0000:0000:0000:0000".parse().unwrap();
            let expected_octets = addr.octets();

            let key = LpmKeyV6::new(addr, 32);

            // The key stores raw octets directly
            assert_eq!(
                expected_octets, key.addr,
                "Stored octets should match original"
            );
        }

        #[test]
        fn test_ipv6_address_not_garbled() {
            // Regression test: addresses like 2001:db8:: were being displayed as b80d:120::
            // due to incorrect byte order conversion
            let addr: Ipv6Addr = "2001:db8::".parse().unwrap();
            let key = LpmKeyV6::new(addr, 32);

            let debug_str = format!("{:?}", key);

            // The debug output should NOT contain the garbled address
            assert!(
                !debug_str.contains("b80d"),
                "IPv6 address should not be garbled: {}",
                debug_str
            );
            assert!(
                debug_str.contains("2001:db8"),
                "IPv6 address should be correct: {}",
                debug_str
            );
        }
    }

    #[cfg(feature = "suricata")]
    mod inspect_mode {
        use super::*;

        #[test]
        fn from_u32_disabled() {
            assert_eq!(InspectMode::from(0u32), InspectMode::Disabled);
            assert_eq!(InspectMode::from(99u32), InspectMode::Disabled); // unknown → Disabled
        }

        #[test]
        fn from_u32_ips() {
            assert_eq!(InspectMode::from(1u32), InspectMode::Ips);
        }

        #[test]
        fn from_u32_ids() {
            assert_eq!(InspectMode::from(2u32), InspectMode::Ids);
        }

        #[test]
        fn display_disabled() {
            assert_eq!(format!("{}", InspectMode::Disabled), "DISABLED");
        }

        #[test]
        fn display_ips() {
            assert_eq!(format!("{}", InspectMode::Ips), "IPS");
        }

        #[test]
        fn display_ids() {
            assert_eq!(format!("{}", InspectMode::Ids), "IDS");
        }
    }

    mod policy_action {
        use super::*;

        #[test]
        fn from_u32_all_variants() {
            assert_eq!(PolicyAction::from(0), PolicyAction::Pass);
            assert_eq!(PolicyAction::from(1), PolicyAction::Drop);
            assert_eq!(PolicyAction::from(2), PolicyAction::Log);
            assert_eq!(PolicyAction::from(3), PolicyAction::TailCall);
            #[cfg(feature = "suricata")]
            assert_eq!(PolicyAction::from(4), PolicyAction::Inspect);
            assert_eq!(PolicyAction::from(99), PolicyAction::Pass); // unknown → Pass
        }

        #[test]
        fn display_all_variants() {
            assert_eq!(format!("{}", PolicyAction::Pass), "PASS");
            assert_eq!(format!("{}", PolicyAction::Drop), "DROP");
            assert_eq!(format!("{}", PolicyAction::Log), "LOG");
            assert_eq!(format!("{}", PolicyAction::TailCall), "TAILCALL");
            #[cfg(feature = "suricata")]
            assert_eq!(format!("{}", PolicyAction::Inspect), "INSPECT");
        }

        #[test]
        fn from_str_pass_aliases() {
            assert_eq!("pass".parse::<PolicyAction>().unwrap(), PolicyAction::Pass);
            assert_eq!(
                "accept".parse::<PolicyAction>().unwrap(),
                PolicyAction::Pass
            );
            assert_eq!("allow".parse::<PolicyAction>().unwrap(), PolicyAction::Pass);
        }

        #[test]
        fn from_str_drop_aliases() {
            assert_eq!("drop".parse::<PolicyAction>().unwrap(), PolicyAction::Drop);
            assert_eq!("deny".parse::<PolicyAction>().unwrap(), PolicyAction::Drop);
            assert_eq!(
                "reject".parse::<PolicyAction>().unwrap(),
                PolicyAction::Drop
            );
        }

        #[test]
        fn from_str_log() {
            assert_eq!("log".parse::<PolicyAction>().unwrap(), PolicyAction::Log);
        }

        #[cfg(feature = "suricata")]
        #[test]
        fn from_str_inspect() {
            assert_eq!(
                "inspect".parse::<PolicyAction>().unwrap(),
                PolicyAction::Inspect
            );
        }

        #[test]
        fn from_str_invalid() {
            assert!("invalid_action".parse::<PolicyAction>().is_err());
            assert!("".parse::<PolicyAction>().is_err());
        }
    }

    mod xdp_mode {
        use super::*;

        #[test]
        fn display_all() {
            assert_eq!(format!("{}", XdpMode::Unspec), "unspec");
            assert_eq!(format!("{}", XdpMode::Native), "native");
            assert_eq!(format!("{}", XdpMode::Generic), "generic");
            assert_eq!(format!("{}", XdpMode::Offload), "offload");
        }

        #[test]
        fn from_u32_all() {
            assert_eq!(XdpMode::from(0u32), XdpMode::Unspec);
            assert_eq!(XdpMode::from(1u32), XdpMode::Native);
            assert_eq!(XdpMode::from(2u32), XdpMode::Generic);
            assert_eq!(XdpMode::from(3u32), XdpMode::Offload);
            assert_eq!(XdpMode::from(99u32), XdpMode::Unspec);
        }

        #[test]
        fn from_str_native_aliases() {
            assert_eq!("native".parse::<XdpMode>().unwrap(), XdpMode::Native);
            assert_eq!("drv".parse::<XdpMode>().unwrap(), XdpMode::Native);
            assert_eq!("driver".parse::<XdpMode>().unwrap(), XdpMode::Native);
        }

        #[test]
        fn from_str_generic_aliases() {
            assert_eq!("generic".parse::<XdpMode>().unwrap(), XdpMode::Generic);
            assert_eq!("skb".parse::<XdpMode>().unwrap(), XdpMode::Generic);
        }

        #[test]
        fn from_str_offload_aliases() {
            assert_eq!("offload".parse::<XdpMode>().unwrap(), XdpMode::Offload);
            assert_eq!("hw".parse::<XdpMode>().unwrap(), XdpMode::Offload);
            assert_eq!("hardware".parse::<XdpMode>().unwrap(), XdpMode::Offload);
        }

        #[test]
        fn from_str_unspec_aliases() {
            assert_eq!("".parse::<XdpMode>().unwrap(), XdpMode::Unspec);
            assert_eq!("unspec".parse::<XdpMode>().unwrap(), XdpMode::Unspec);
            assert_eq!("auto".parse::<XdpMode>().unwrap(), XdpMode::Unspec);
        }

        #[test]
        fn from_str_invalid() {
            assert!("invalid".parse::<XdpMode>().is_err());
        }
    }

    mod protocol {
        use super::*;

        #[test]
        fn display_named_protocols() {
            assert_eq!(format!("{}", Protocol::new(0)), "ANY");
            assert_eq!(format!("{}", Protocol::new(libc::IPPROTO_TCP as u8)), "TCP");
            assert_eq!(format!("{}", Protocol::new(libc::IPPROTO_UDP as u8)), "UDP");
            assert_eq!(
                format!("{}", Protocol::new(libc::IPPROTO_ICMP as u8)),
                "ICMP"
            );
            assert_eq!(
                format!("{}", Protocol::new(libc::IPPROTO_ICMPV6 as u8)),
                "ICMPv6"
            );
        }

        #[test]
        fn display_numeric_fallback() {
            let result = format!("{}", Protocol::new(47)); // GRE
            assert_eq!(result, "47");
        }

        #[test]
        fn from_str_named() {
            assert_eq!(*"any".parse::<Protocol>().unwrap(), 0);
            assert_eq!(*"tcp".parse::<Protocol>().unwrap(), libc::IPPROTO_TCP as u8);
            assert_eq!(*"udp".parse::<Protocol>().unwrap(), libc::IPPROTO_UDP as u8);
            assert_eq!(
                *"icmp".parse::<Protocol>().unwrap(),
                libc::IPPROTO_ICMP as u8
            );
            assert_eq!(
                *"icmpv6".parse::<Protocol>().unwrap(),
                libc::IPPROTO_ICMPV6 as u8
            );
        }

        #[test]
        fn from_str_numeric() {
            assert_eq!(*"47".parse::<Protocol>().unwrap(), 47u8);
        }

        #[test]
        fn from_str_invalid() {
            assert!("bogus".parse::<Protocol>().is_err());
        }

        #[test]
        fn try_from_str_all_named() {
            assert_eq!(*Protocol::try_from("any").unwrap(), 0);
            assert_eq!(*Protocol::try_from("tcp").unwrap(), libc::IPPROTO_TCP as u8);
            assert_eq!(*Protocol::try_from("udp").unwrap(), libc::IPPROTO_UDP as u8);
            assert_eq!(
                *Protocol::try_from("icmp").unwrap(),
                libc::IPPROTO_ICMP as u8
            );
            assert_eq!(
                *Protocol::try_from("icmpv6").unwrap(),
                libc::IPPROTO_ICMPV6 as u8
            );
        }

        #[test]
        fn try_from_str_invalid() {
            assert!(Protocol::try_from("bogus").is_err());
        }

        #[test]
        fn from_u8() {
            let p = Protocol::from(17u8);
            assert_eq!(*p, 17);
        }

        #[test]
        fn deref() {
            let p = Protocol::new(6);
            let raw: u8 = *p;
            assert_eq!(raw, 6);
        }
    }

    mod action_params {
        use super::*;

        #[test]
        fn none_to_raw_is_zero() {
            assert_eq!(ActionParams::None.to_raw(), 0);
        }

        #[test]
        fn log_to_raw_preserves_ns() {
            let params = ActionParams::Log {
                rate_limit_ns: 5_000_000_000,
            };
            assert_eq!(params.to_raw(), 5_000_000_000);
        }

        #[test]
        fn log_to_raw_zero() {
            let params = ActionParams::Log { rate_limit_ns: 0 };
            assert_eq!(params.to_raw(), 0);
        }

        #[test]
        fn from_action_and_raw_log() {
            let params = ActionParams::from_action_and_raw(PolicyAction::Log, 1_000_000);
            assert_eq!(
                params,
                ActionParams::Log {
                    rate_limit_ns: 1_000_000
                }
            );
        }

        #[test]
        fn from_action_and_raw_drop_is_none() {
            let params = ActionParams::from_action_and_raw(PolicyAction::Drop, 9999);
            assert_eq!(params, ActionParams::None);
        }

        #[test]
        fn from_action_and_raw_pass_is_none() {
            let params = ActionParams::from_action_and_raw(PolicyAction::Pass, 9999);
            assert_eq!(params, ActionParams::None);
        }

        #[cfg(feature = "suricata")]
        #[test]
        fn from_action_and_raw_inspect_is_none() {
            let params = ActionParams::from_action_and_raw(PolicyAction::Inspect, 42);
            assert_eq!(params, ActionParams::None);
        }
    }

    mod sni_rule_entry {
        use super::*;

        #[test]
        fn default_is_zeroed() {
            let e = SniRuleEntry::default();
            assert_eq!(e.sni_match_type, 0);
            assert_eq!(e.sni_len, 0);
            assert_eq!(e.sni_pattern, [0u8; MAX_SNI_LEN]);
        }

        #[test]
        fn new_exact_match() {
            let e = SniRuleEntry::new(SNI_MATCH_EXACT, "example.com");
            assert_eq!(e.sni_match_type, SNI_MATCH_EXACT);
            assert_eq!(e.sni_len as usize, "example.com".len());
            let pat = &e.sni_pattern[.."example.com".len()];
            assert_eq!(pat, b"example.com");
        }

        #[test]
        fn new_suffix_match() {
            let e = SniRuleEntry::new(SNI_MATCH_SUFFIX, ".example.com");
            assert_eq!(e.sni_match_type, SNI_MATCH_SUFFIX);
        }

        #[test]
        fn new_truncates_at_max_len() {
            let long_pattern = "a".repeat(MAX_SNI_LEN + 10);
            let e = SniRuleEntry::new(SNI_MATCH_EXACT, &long_pattern);
            assert_eq!(e.sni_len as usize, MAX_SNI_LEN - 1);
        }

        #[test]
        fn as_bytes_correct_size() {
            let e = SniRuleEntry::default();
            assert_eq!(e.as_bytes().len(), std::mem::size_of::<SniRuleEntry>());
        }
    }

    mod l4_rule {
        use super::*;

        #[test]
        fn default_fields() {
            let r = L4Rule::default();
            // Copy packed fields to locals before comparing
            let rule_id = r.rule_id;
            let num_actions = r.num_actions;
            let sni_match_type = r.sni_match_type;
            assert_eq!(rule_id, 0);
            assert_eq!(num_actions, 0);
            assert_eq!(sni_match_type, SNI_MATCH_NONE);
        }

        #[test]
        fn set_actions_single() {
            let mut r = L4Rule::default();
            r.set_actions(&[(PolicyAction::Drop, 0, ActionParams::None)]);
            let num_actions = r.num_actions;
            assert_eq!(num_actions, 1);
            // Copy packed action fields to locals
            let action = r.actions[0].action;
            let priority = r.actions[0].priority;
            let param = r.actions[0].param;
            assert_eq!(action, PolicyAction::Drop as u32);
            assert_eq!(priority, 0);
            assert_eq!(param, 0);
        }

        #[test]
        fn set_actions_with_log_param() {
            let mut r = L4Rule::default();
            r.set_actions(&[(
                PolicyAction::Log,
                5,
                ActionParams::Log {
                    rate_limit_ns: 1_000_000,
                },
            )]);
            let num_actions = r.num_actions;
            assert_eq!(num_actions, 1);
            let action = r.actions[0].action;
            let priority = r.actions[0].priority;
            let param = r.actions[0].param;
            assert_eq!(action, PolicyAction::Log as u32);
            assert_eq!(priority, 5);
            assert_eq!(param, 1_000_000);
        }

        #[test]
        fn set_actions_truncates_at_max() {
            let many = vec![
                (PolicyAction::Pass, 0, ActionParams::None);
                MAX_ACTIONS_PER_RULE as usize + 5
            ];
            let mut r = L4Rule::default();
            r.set_actions(&many);
            assert_eq!(r.num_actions, MAX_ACTIONS_PER_RULE as u8);
        }

        #[test]
        fn set_actions_multiple() {
            let mut r = L4Rule::default();
            r.set_actions(&[
                (PolicyAction::Log, 0, ActionParams::Log { rate_limit_ns: 0 }),
                (PolicyAction::Drop, 1, ActionParams::None),
            ]);
            assert_eq!(r.num_actions, 2);
        }

        #[test]
        fn debug_format() {
            let r = L4Rule {
                rule_id: 99,
                ..Default::default()
            };
            let s = format!("{:?}", r);
            assert!(s.contains("99"));
        }

        #[test]
        fn as_bytes_correct_size() {
            let r = L4Rule::default();
            assert_eq!(r.as_bytes().len(), std::mem::size_of::<L4Rule>());
        }
    }

    mod ethertype_stats {
        use super::*;

        #[test]
        fn name_ipv4() {
            let s = EthertypeStats {
                ethertype: ethertypes::IPV4,
                packets: 0,
            };
            assert_eq!(s.name(), "IPv4");
        }

        #[test]
        fn name_arp() {
            let s = EthertypeStats {
                ethertype: ethertypes::ARP,
                packets: 0,
            };
            assert_eq!(s.name(), "ARP");
        }

        #[test]
        fn name_unknown() {
            let s = EthertypeStats {
                ethertype: 0xFFFF,
                packets: 0,
            };
            assert_eq!(s.name(), "Unknown");
        }

        #[test]
        fn hex_format() {
            let s = EthertypeStats {
                ethertype: 0x0806,
                packets: 0,
            };
            assert_eq!(s.hex(), "0x0806");
        }

        #[test]
        fn hex_format_ipv6() {
            let s = EthertypeStats {
                ethertype: ethertypes::IPV6,
                packets: 0,
            };
            assert_eq!(s.hex(), "0x86DD");
        }
    }

    mod ethertypes_module {
        use super::ethertypes;

        #[test]
        fn known_ethertypes() {
            assert_eq!(ethertypes::name(ethertypes::IPV4), "IPv4");
            assert_eq!(ethertypes::name(ethertypes::IPV6), "IPv6");
            assert_eq!(ethertypes::name(ethertypes::ARP), "ARP");
            assert_eq!(ethertypes::name(ethertypes::LLDP), "LLDP");
            assert_eq!(ethertypes::name(ethertypes::MPLS), "MPLS");
            assert_eq!(ethertypes::name(ethertypes::VLAN_8021Q), "802.1Q VLAN");
        }

        #[test]
        fn unknown_ethertype() {
            assert_eq!(ethertypes::name(0xFFFF), "Unknown");
            assert_eq!(ethertypes::name(0x0000), "Unknown");
        }
    }

    mod tail_call_features_module {
        use super::tail_call_features;

        #[test]
        fn feature_to_slot_always_errors() {
            assert!(tail_call_features::feature_to_slot("sni").is_err());
            assert!(tail_call_features::feature_to_slot("").is_err());
            assert!(tail_call_features::feature_to_slot("unknown").is_err());
        }

        #[test]
        fn feature_to_program_always_errors() {
            assert!(tail_call_features::feature_to_program("sni").is_err());
            assert!(tail_call_features::feature_to_program("").is_err());
        }

        #[test]
        fn supported_features_is_empty() {
            assert_eq!(tail_call_features::supported_features(), &[] as &[&str]);
        }
    }

    #[cfg(feature = "suricata")]
    mod flow_verdict_types {
        use super::*;

        #[test]
        fn flow_verdict_key_debug() {
            let k = FlowVerdictKey {
                sport: 1234,
                dport: 80,
                protocol: 6,
                af: AF_INET,
                ..Default::default()
            };
            let s = format!("{:?}", k);
            assert!(s.contains("1234"));
            assert!(s.contains("80"));
        }

        #[test]
        fn flow_verdict_key_as_bytes() {
            let k = FlowVerdictKey::default();
            assert_eq!(k.as_bytes().len(), std::mem::size_of::<FlowVerdictKey>());
        }

        #[test]
        fn flow_verdict_debug() {
            let v = FlowVerdict {
                action: PolicyAction::Drop as u32,
                _pad: 0,
                timestamp_ns: 12345,
                expires_ns: 99999,
                packets: 5,
                bytes: 500,
                last_seen_ns: 0,
                rule_id: 0,
            };
            let s = format!("{:?}", v);
            assert!(s.contains("12345"));
            assert!(s.contains("99999"));
        }

        #[test]
        fn flow_verdict_as_bytes() {
            let v = FlowVerdict::default();
            assert_eq!(v.as_bytes().len(), std::mem::size_of::<FlowVerdict>());
        }
    }

    #[cfg(feature = "suricata")]
    mod inspect_config_type {
        use super::*;

        #[test]
        fn as_bytes_correct_size() {
            let c = InspectConfig::default();
            assert_eq!(c.as_bytes().len(), std::mem::size_of::<InspectConfig>());
        }

        #[test]
        fn debug_format() {
            let c = InspectConfig {
                mode: 1, // IPS
                mirror_ifindex: 5,
                _pad: [0; 2],
            };
            let s = format!("{:?}", c);
            // InspectMode derives Debug so it formats as "Ips" (not "IPS")
            assert!(s.contains("Ips"), "expected Ips in debug: {}", s);
            assert!(s.contains("5"), "expected mirror_ifindex 5: {}", s);
        }
    }

    mod src_lpm_value_type {
        use super::*;

        #[test]
        fn debug_format() {
            let v = SrcLpmValue {
                src_prefixlen: 24,
                src_group_id: 7,
            };
            let s = format!("{:?}", v);
            assert!(s.contains("24"));
            assert!(s.contains("7"));
        }

        #[test]
        fn as_bytes_correct_size() {
            let v = SrcLpmValue::default();
            assert_eq!(v.as_bytes().len(), std::mem::size_of::<SrcLpmValue>());
        }
    }

    mod global_stats_type {
        use super::*;

        #[test]
        fn as_bytes_correct_size() {
            let g = GlobalStats::default();
            assert_eq!(g.as_bytes().len(), std::mem::size_of::<GlobalStats>());
        }

        /// Guards the layout contract with the packed BPF struct: 23 scalar
        /// u64 counters + l3[5] + quic[4] + proto[IP_PROTO_SLOTS] (16 bytes
        /// each) + proc_hist[64].  If this fails, struct global_stats in
        /// policy_common.h and GlobalStats have drifted apart.
        #[test]
        fn matches_bpf_struct_size() {
            assert_eq!(
                std::mem::size_of::<GlobalStats>(),
                23 * 8 + L3_BUCKETS * 16 + QUIC_SLOTS * 16 + HIST_BUCKETS * 8 + IP_PROTO_SLOTS * 16
            );
        }

        /// Guards the slot→protocol table against the IP_PROTO_SLOT_* defines
        /// in policy_common.h: slot 0 is the catch-all and every tracked
        /// protocol has exactly one slot.
        #[test]
        fn ip_proto_slot_table_consistent() {
            assert_eq!(IP_PROTO_SLOT_PROTOS.len(), IP_PROTO_SLOTS);
            assert_eq!(IP_PROTO_SLOT_PROTOS[0], 0, "slot 0 must be the catch-all");
            let mut protos = IP_PROTO_SLOT_PROTOS;
            protos.sort_unstable();
            assert!(
                protos.windows(2).all(|w| w[0] < w[1]),
                "duplicate protocol number in IP_PROTO_SLOT_PROTOS"
            );
        }

        #[test]
        fn accumulate_sums_scalars_and_arrays() {
            let mut a = GlobalStats {
                rx_packets: 1,
                urpf_drop_bytes: 2,
                ..Default::default()
            };
            a.l3[0].packets = 10;
            a.quic[1].bytes = 20;
            a.proc_hist[63] = 30;

            let mut b = GlobalStats {
                rx_packets: 100,
                urpf_drop_bytes: 200,
                ..Default::default()
            };
            b.l3[0].packets = 1000;
            b.l3[4].bytes = 4;
            b.quic[1].bytes = 2000;
            b.proc_hist[63] = 3000;

            a.accumulate(&b);
            assert_eq!(a.rx_packets, 101);
            assert_eq!(a.urpf_drop_bytes, 202);
            assert_eq!(a.l3[0].packets, 1010);
            assert_eq!(a.l3[4].bytes, 4);
            assert_eq!(a.quic[1].bytes, 2020);
            assert_eq!(a.proc_hist[63], 3030);
        }
    }

    mod rule_stats_type {
        use super::*;

        #[test]
        fn as_bytes_correct_size() {
            let s = RuleStats::default();
            assert_eq!(s.as_bytes().len(), std::mem::size_of::<RuleStats>());
        }

        #[test]
        fn debug_format() {
            let s = RuleStats {
                packets: 100,
                bytes: 5000,
                last_seen_ns: 999,
                last_log_ns: 0,
            };
            let dbg = format!("{:?}", s);
            assert!(dbg.contains("100"));
            assert!(dbg.contains("5000"));
        }
    }

    mod dst_lpm_value_type {
        use super::*;

        #[test]
        fn default_count_zero() {
            let d = DstLpmValue::default();
            assert_eq!(d.count, 0);
        }

        #[test]
        fn as_bytes_correct_size() {
            let d = DstLpmValue::default();
            assert_eq!(d.as_bytes().len(), std::mem::size_of::<DstLpmValue>());
        }

        #[test]
        fn debug_format() {
            let d = DstLpmValue {
                dst_prefixlen: 32,
                count: 3,
                ..Default::default()
            };
            let s = format!("{:?}", d);
            assert!(s.contains("32"));
            assert!(s.contains("3"));
        }
    }

    mod direction {
        use super::*;

        #[test]
        fn test_direction_display() {
            assert_eq!(format!("{}", Direction::Ingress), "ingress");
            assert_eq!(format!("{}", Direction::Egress), "egress");
        }

        #[test]
        fn test_direction_from_str() {
            assert_eq!("ingress".parse::<Direction>().unwrap(), Direction::Ingress);
            assert_eq!("egress".parse::<Direction>().unwrap(), Direction::Egress);
            assert_eq!("in".parse::<Direction>().unwrap(), Direction::Ingress);
            assert_eq!("out".parse::<Direction>().unwrap(), Direction::Egress);
        }

        #[test]
        fn test_direction_from_str_case_insensitive() {
            assert_eq!("INGRESS".parse::<Direction>().unwrap(), Direction::Ingress);
            assert_eq!("EGRESS".parse::<Direction>().unwrap(), Direction::Egress);
            assert_eq!("Ingress".parse::<Direction>().unwrap(), Direction::Ingress);
            assert_eq!("OUT".parse::<Direction>().unwrap(), Direction::Egress);
        }

        #[test]
        fn test_direction_from_str_invalid() {
            assert!("invalid".parse::<Direction>().is_err());
            assert!("".parse::<Direction>().is_err());
            assert!("both".parse::<Direction>().is_err());
        }

        #[test]
        fn test_direction_serialize() {
            let ingress = Direction::Ingress;
            let egress = Direction::Egress;

            let json_ingress = serde_json::to_string(&ingress).unwrap();
            let json_egress = serde_json::to_string(&egress).unwrap();

            assert_eq!(json_ingress, "\"Ingress\"");
            assert_eq!(json_egress, "\"Egress\"");
        }

        #[test]
        fn test_direction_deserialize() {
            let ingress: Direction = serde_json::from_str("\"Ingress\"").unwrap();
            let egress: Direction = serde_json::from_str("\"Egress\"").unwrap();

            assert_eq!(ingress, Direction::Ingress);
            assert_eq!(egress, Direction::Egress);
        }

        #[test]
        fn test_direction_equality() {
            assert_eq!(Direction::Ingress, Direction::Ingress);
            assert_eq!(Direction::Egress, Direction::Egress);
            assert_ne!(Direction::Ingress, Direction::Egress);
        }

        #[test]
        fn test_direction_copy() {
            let dir = Direction::Ingress;
            let dir2 = dir; // Copy
            assert_eq!(dir, dir2);
        }
    }
}
