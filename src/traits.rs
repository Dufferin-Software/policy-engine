// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Trait definitions for BPF operations
//!
//! This module defines traits that abstract system interactions for testability.
//! The `BpfOperations` trait allows mocking of all BPF map and program operations.

use anyhow::Result;

#[cfg(test)]
use mockall::automock;

use crate::shared_types::InterfaceAttachment;
use crate::types::*;

/// Trait for BPF operations - allows mocking for unit tests
#[cfg_attr(test, automock)]
pub trait BpfOperations: Send + Sync {
    /// Load BPF programs (called lazily when needed)
    fn load_programs(&mut self) -> Result<()>;

    /// Attach ingress program to an interface
    fn attach_ingress(&mut self, ifname: &str, mode: XdpMode) -> Result<()>;

    /// Detach ingress program from an interface
    fn detach_ingress(&mut self, ifname: &str) -> Result<()>;

    /// Attach TC programs (ingress clone + egress firewall) to an interface
    fn attach_tc(&mut self, ifname: &str) -> Result<()>;

    /// Detach TC programs from an interface
    fn detach_tc(&mut self, ifname: &str) -> Result<()>;

    /// Get all attached interfaces
    fn get_attached_interfaces(&self) -> Vec<InterfaceAttachment>;

    /// Add an IPv4 policy rule to the two-level LPM (src prefix → dst prefix → L4 rule).
    /// Creates an inner dst trie group for the src prefix if it doesn't exist.
    /// `src_key` carries the ifindex the rule is scoped to.
    fn add_policy_rule_v4(
        &mut self,
        src_key: &SrcLpmKeyV4,
        dst_key: &LpmKeyV4,
        rule: &L4Rule,
        direction: Direction,
    ) -> Result<()>;

    /// Add an IPv6 policy rule to the two-level LPM.
    fn add_policy_rule_v6(
        &mut self,
        src_key: &SrcLpmKeyV6,
        dst_key: &LpmKeyV6,
        rule: &L4Rule,
        direction: Direction,
    ) -> Result<()>;

    /// Delete an IPv4 policy rule by rule ID.
    /// Removes the rule from the dst trie entry; deletes the entry (and group) if empty.
    fn delete_policy_rule_v4(
        &mut self,
        src_key: &SrcLpmKeyV4,
        dst_key: &LpmKeyV4,
        rule_id: u64,
        direction: Direction,
    ) -> Result<()>;

    /// Delete an IPv6 policy rule by rule ID.
    fn delete_policy_rule_v6(
        &mut self,
        src_key: &SrcLpmKeyV6,
        dst_key: &LpmKeyV6,
        rule_id: u64,
        direction: Direction,
    ) -> Result<()>;

    /// List all IPv4 policy rules as (src_key, dst_key, l4_rule) triples.
    /// Each src_key includes the ifindex of the interface the rule is scoped to.
    fn list_policy_rules_v4(
        &self,
        direction: Direction,
    ) -> Result<Vec<(SrcLpmKeyV4, LpmKeyV4, L4Rule)>>;

    /// List all IPv6 policy rules as (src_key, dst_key, l4_rule) triples.
    fn list_policy_rules_v6(
        &self,
        direction: Direction,
    ) -> Result<Vec<(SrcLpmKeyV6, LpmKeyV6, L4Rule)>>;

    /// Get statistics for a rule by ID
    fn get_rule_stats(&self, rule_id: u64, direction: Direction) -> Result<Option<RuleStats>>;

    /// Get global statistics for an interface
    fn get_global_stats(&self, ifindex: u32, direction: Direction) -> Result<GlobalStats>;

    /// Get ethertype statistics for an interface
    fn get_ethertype_stats(
        &self,
        ifindex: u32,
        direction: Direction,
    ) -> Result<Vec<EthertypeStats>>;

    /// Get non-IP sender statistics for an interface (ingress only; egress returns empty).
    /// Returns one entry per (src_mac, ethertype) pair, sorted by packet count desc.
    fn get_nonip_senders(&self, ifindex: u32) -> Result<Vec<NonIpSenderEntry>>;

    /// Clear global statistics for an interface
    fn clear_global_stats(&mut self, ifindex: u32, direction: Direction) -> Result<()>;

    /// Clear statistics for a specific rule
    fn clear_rule_stats(&mut self, rule_id: u64, direction: Direction) -> Result<()>;

    /// Clear statistics for all rules
    fn clear_all_rule_stats(&mut self, direction: Direction) -> Result<()>;

    /// Clear ethertype statistics for an interface
    fn clear_ethertype_stats(&mut self, ifindex: u32, direction: Direction) -> Result<()>;

    /// Clear all statistics for an interface (global + ethertype)
    fn clear_interface_stats(&mut self, ifindex: u32, direction: Direction) -> Result<()>;

    /// Clear all statistics
    fn clear_all_stats(&mut self) -> Result<()>;

    /// Set the per-interface default action for unmatched packets
    fn set_default_action(
        &mut self,
        action: PolicyAction,
        direction: Direction,
        ifindex: u32,
    ) -> Result<()>;

    /// Get the per-interface default action (returns None if not explicitly set)
    fn get_default_action(
        &self,
        direction: Direction,
        ifindex: u32,
    ) -> Result<Option<PolicyAction>>;

    /// Register a tail call program at a dispatcher slot
    fn register_tail_call(
        &mut self,
        slot: u32,
        prog_name: &str,
        direction: Direction,
    ) -> Result<()>;

    /// Detach all BPF programs and remove all pinned maps and metadata.
    /// Called at shutdown when stop_behavior is ClearState.
    fn clear_bpf_state(&mut self);

    /// Set FIB forwarding configuration for the given ingress interface (XDP ingress only)
    fn set_fib_config(&mut self, interface: &str, config: &FibConfig) -> Result<()>;

    /// Get current FIB forwarding configuration for the given ingress interface.
    /// Returns FIB_FORWARD_DISABLED if no entry is present for the interface.
    fn get_fib_config(&self, interface: &str) -> Result<FibConfig>;

    /// List all (interface_name, FibConfig) entries currently in the map.
    fn list_fib_configs(&self) -> Result<Vec<(String, FibConfig)>>;

    /// Enable or disable per-flow accounting for IPFIX export (both XDP and TC)
    #[cfg(feature = "ipfix")]
    fn set_flow_cache_config(&mut self, config: &FlowCacheConfig) -> Result<()>;

    /// Get current flow cache configuration
    #[cfg(feature = "ipfix")]
    fn get_flow_cache_config(&self) -> Result<FlowCacheConfig>;

    /// List all entries from the flow cache (Ingress=XDP, Egress=TC)
    #[cfg(feature = "ipfix")]
    fn list_flow_cache_entries(
        &self,
        direction: Direction,
    ) -> Result<Vec<(FlowKey, FlowCacheEntry)>>;

    /// Delete a single entry from the flow cache
    #[cfg(feature = "ipfix")]
    fn delete_flow_cache_entry(&mut self, key: &FlowKey, direction: Direction) -> Result<()>;

    /// Set inspect configuration (mode, mirror interface, fail-open)
    #[cfg(feature = "suricata")]
    fn set_inspect_config(&mut self, config: &InspectConfig, direction: Direction) -> Result<()>;

    /// Get current inspect configuration
    #[cfg(feature = "suricata")]
    fn get_inspect_config(&self, direction: Direction) -> Result<InspectConfig>;

    /// Update a flow verdict.  Writers include the Suricata EVE consumer and
    /// the QUIC SNI inspector.
    fn update_flow_verdict(
        &mut self,
        key: &FlowVerdictKey,
        value: &FlowVerdict,
        direction: Direction,
    ) -> Result<()>;

    /// Bump per-rule stats (packets += 1, bytes += `pkt_len`, last_seen_ns =
    /// now) from userspace.  Mirrors `tc_update_rule_stats` /
    /// `update_rule_stats` in BPF, used by inspection paths that don't run
    /// in-kernel — currently the userspace QUIC SNI inspector.  Wraps a
    /// read-modify-write on `rule_stats` / `tc_rule_stats` (plain HASH map,
    /// not per-CPU).
    fn bump_rule_stats(&mut self, rule_id: u64, direction: Direction, pkt_len: u64) -> Result<()>;

    /// Delete a flow verdict entry
    fn delete_flow_verdict(&mut self, key: &FlowVerdictKey, direction: Direction) -> Result<()>;

    /// Iterate flow verdicts (for cleanup of expired entries)
    fn list_flow_verdicts(
        &self,
        direction: Direction,
    ) -> Result<Vec<(FlowVerdictKey, FlowVerdict)>>;

    /// Get count of active flow verdicts
    fn get_flow_verdict_count(&self, direction: Direction) -> Result<u64>;

    /// Get processing-time histogram buckets (64 entries, summed across CPUs)
    fn get_processing_time_hist(&self, direction: Direction) -> Result<Vec<u64>>;

    /// Get per-protocol packet/byte stats (256 entries, summed across CPUs)
    fn get_proto_stats(&self, direction: Direction) -> Result<Vec<ProtoStats>>;

    /// Get L3 protocol stats (4 buckets: 0=IPv4, 1=IPv6, 2=ARP, 3=Other)
    fn get_l3_stats(&self, direction: Direction) -> Result<Vec<ProtoStats>>;

    /// Get per-QUIC-version stats as (version_name, packets, bytes) triples.
    /// Ingress only; egress returns empty vec (TC has no QUIC stats map).
    fn get_quic_stats(&self, direction: Direction) -> Result<Vec<(String, u64, u64)>>;

    /// Add or update an SNI rule entry in the direction-appropriate sni_rules map.
    /// Ingress rules use the XDP sni_rules map; egress rules use tc_sni_rules.
    /// Called when a rule with sni_match_type != SNI_MATCH_NONE is added.
    fn add_sni_rule(
        &mut self,
        rule_id: u64,
        entry: &SniRuleEntry,
        direction: Direction,
    ) -> Result<()>;

    /// Delete an SNI rule entry from the direction-appropriate sni_rules map.
    fn delete_sni_rule(&mut self, rule_id: u64, direction: Direction) -> Result<()>;

    /// Flush all entries from the direction-appropriate sni_rules map.
    fn flush_sni_rules(&mut self, direction: Direction) -> Result<()>;

    /// Look up a single SNI rule entry by rule_id for the given direction.
    fn lookup_sni_rule(&self, rule_id: u64, direction: Direction) -> Result<Option<SniRuleEntry>>;

    /// Add or update a MAC rule entry in the direction-appropriate mac_rules map.
    /// Ingress rules use the XDP mac_rules map; egress rules use tc_mac_rules.
    /// Called when a rule with mac_match_flags != 0 is added.
    fn add_mac_rule(
        &mut self,
        rule_id: u64,
        entry: &MacRuleEntry,
        direction: Direction,
    ) -> Result<()>;

    /// Delete a MAC rule entry from the direction-appropriate mac_rules map.
    fn delete_mac_rule(&mut self, rule_id: u64, direction: Direction) -> Result<()>;

    /// Flush all entries from the direction-appropriate mac_rules map.
    fn flush_mac_rules(&mut self, direction: Direction) -> Result<()>;

    /// Look up a single MAC rule entry by rule_id for the given direction.
    fn lookup_mac_rule(&self, rule_id: u64, direction: Direction) -> Result<Option<MacRuleEntry>>;
}

/// Trait for network interface operations - allows mocking for unit tests
#[cfg_attr(test, automock)]
pub trait NetworkOperations: Send + Sync {
    /// Get interface index from name
    fn get_ifindex(&self, ifname: &str) -> Result<i32>;

    /// List all network interface names
    fn list_interfaces(&self) -> Result<Vec<String>>;
}

/// Default implementation of NetworkOperations using libc
pub struct SystemNetworkOps;

impl NetworkOperations for SystemNetworkOps {
    fn get_ifindex(&self, ifname: &str) -> Result<i32> {
        use std::ffi::CString;
        let name = CString::new(ifname)?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            anyhow::bail!("Interface {} not found", ifname);
        }
        Ok(ifindex as i32)
    }

    fn list_interfaces(&self) -> Result<Vec<String>> {
        use std::fs;
        let mut interfaces = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if crate::types::is_internal_interface(&name) {
                        continue;
                    }
                    interfaces.push(name);
                }
            }
        }
        Ok(interfaces)
    }
}
