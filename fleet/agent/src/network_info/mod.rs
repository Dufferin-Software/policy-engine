// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Network interface discovery abstraction.
//!
//! The [`NetworkInfo`] trait provides a mockable interface for querying the
//! host's network interfaces.  The real implementation ([`SystemNetworkInfo`])
//! reads from the kernel via `getifaddrs` and `/sys/class/net`.

pub mod system;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use mockall::automock;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    IPv4,
    IPv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkState {
    Up,
    Down,
    Unknown,
}

impl std::fmt::Display for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkState::Up => write!(f, "up"),
            LinkState::Down => write!(f, "down"),
            LinkState::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressFamily::IPv4 => write!(f, "ipv4"),
            AddressFamily::IPv6 => write!(f, "ipv6"),
        }
    }
}

/// A single address assigned to an interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// Human-readable address string, e.g. "192.168.1.1" or "fe80::1".
    pub address: String,
    /// CIDR prefix length, e.g. 24 for a /24.
    pub prefix_len: u32,
    /// Address family.
    pub family: AddressFamily,
}

/// Description of a single network interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// Interface name (e.g. "eth0").
    pub name: String,
    /// All addresses assigned to this interface.
    pub addresses: Vec<AddressInfo>,
    /// MAC address in colon-hex notation (e.g. "aa:bb:cc:dd:ee:ff"), if available.
    pub mac_address: Option<String>,
    /// Operational link state.
    pub link_state: LinkState,
    /// Linux interface index (from `if_nametoindex(3)`). 0 if unknown.
    pub ifindex: u32,
}

/// True for interfaces internal to the policy engine that must be hidden
/// from discovery (and therefore from the controller): the pe-inspect0/
/// pe-inspect1 veth pair the engine creates in IPS/IDS mode to mirror
/// traffic to Suricata. Mirrors `is_internal_interface` in the engine's
/// `types.rs` — keep the two in sync.
pub fn is_internal_interface(name: &str) -> bool {
    name == "pe-inspect0" || name == "pe-inspect1"
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Abstraction over network interface discovery.
///
/// Production code uses [`SystemNetworkInfo`]; tests inject a mock.
#[cfg_attr(test, automock)]
pub trait NetworkInfo: Send + Sync {
    /// Return all network interfaces on this host.
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_interfaces_are_the_inspect_veth_pair() {
        assert!(is_internal_interface("pe-inspect0"));
        assert!(is_internal_interface("pe-inspect1"));
        assert!(!is_internal_interface("eth0"));
        assert!(!is_internal_interface("lo"));
        assert!(!is_internal_interface("pe-inspect"));
    }
}
