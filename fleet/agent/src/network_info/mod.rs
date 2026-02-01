// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

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

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Abstraction over network interface discovery.
///
/// Production code uses [`SystemNetworkInfo`]; tests inject a mock.
#[cfg_attr(test, automock)]
pub trait NetworkInfo: Send + Sync {
    /// Return all network interfaces on this host.
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>>;
}
