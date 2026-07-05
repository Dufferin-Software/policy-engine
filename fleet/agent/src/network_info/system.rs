// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Real [`NetworkInfo`] implementation that reads from the Linux kernel.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use nix::ifaddrs::getifaddrs;

use super::{AddressFamily, AddressInfo, InterfaceInfo, LinkState, NetworkInfo};

/// Reads network interfaces from the operating system.
#[derive(Default)]
pub struct SystemNetworkInfo;

impl SystemNetworkInfo {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkInfo for SystemNetworkInfo {
    fn list_interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        let mut ifaces: HashMap<String, InterfaceInfo> = HashMap::new();

        let addrs = getifaddrs().context("getifaddrs failed")?;
        for ifaddr in addrs {
            let name = ifaddr.interface_name.clone();
            if super::is_internal_interface(&name) {
                continue;
            }
            let entry = ifaces.entry(name.clone()).or_insert_with(|| InterfaceInfo {
                name: name.clone(),
                addresses: Vec::new(),
                mac_address: read_mac(&name),
                link_state: read_link_state(&name),
                ifindex: read_ifindex(&name),
            });

            // Extract IPv4/IPv6 address + netmask.
            if let Some(addr) = ifaddr.address {
                if let Some(sin) = addr.as_sockaddr_in() {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::from(sin.ip()));
                    let prefix_len = ifaddr
                        .netmask
                        .and_then(|m| {
                            m.as_sockaddr_in()
                                .map(|s| u32::from(std::net::Ipv4Addr::from(s.ip())).count_ones())
                        })
                        .unwrap_or(32);
                    entry.addresses.push(AddressInfo {
                        address: ip.to_string(),
                        prefix_len,
                        family: AddressFamily::IPv4,
                    });
                } else if let Some(sin6) = addr.as_sockaddr_in6() {
                    let ip = IpAddr::V6(sin6.ip());
                    let prefix_len = ifaddr
                        .netmask
                        .and_then(|m| {
                            m.as_sockaddr_in6().map(|s| {
                                let octets = s.ip().octets();
                                octets.iter().map(|b| b.count_ones()).sum()
                            })
                        })
                        .unwrap_or(128);
                    entry.addresses.push(AddressInfo {
                        address: ip.to_string(),
                        prefix_len,
                        family: AddressFamily::IPv6,
                    });
                }
            }
        }

        let mut result: Vec<InterfaceInfo> = ifaces.into_values().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }
}

/// Read MAC address from sysfs.
fn read_mac(iface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/address", iface);
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00")
}

/// Resolve interface name → Linux ifindex via `if_nametoindex(3)`.
/// Returns 0 if the interface vanished between enumeration and lookup, or
/// if the name contains an interior NUL (impossible for kernel-supplied names).
fn read_ifindex(iface: &str) -> u32 {
    nix::net::if_::if_nametoindex(iface).unwrap_or(0)
}

/// Read link state from sysfs.
fn read_link_state(iface: &str) -> LinkState {
    let path = format!("/sys/class/net/{}/operstate", iface);
    match std::fs::read_to_string(path) {
        Ok(s) => match s.trim() {
            "up" => LinkState::Up,
            "down" => LinkState::Down,
            _ => LinkState::Unknown,
        },
        Err(_) => LinkState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_network_info_returns_at_least_lo() {
        let info = SystemNetworkInfo::new();
        let ifaces = info.list_interfaces().unwrap();
        assert!(
            ifaces.iter().any(|i| i.name == "lo"),
            "Should always find loopback interface"
        );

        let lo = ifaces.iter().find(|i| i.name == "lo").unwrap();
        assert!(
            lo.addresses.iter().any(|a| a.address == "127.0.0.1"),
            "Loopback should have 127.0.0.1"
        );
    }

    #[test]
    fn test_read_link_state_lo() {
        // Loopback is always "unknown" operstate on most Linux kernels
        let state = read_link_state("lo");
        // Just check it doesn't panic — exact value depends on kernel
        let _ = state;
    }

    #[test]
    fn test_read_mac_nonexistent() {
        assert!(read_mac("nonexistent_iface_xyz").is_none());
    }
}
