// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Veth pair management for Suricata inspect mirroring

use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;

/// Abstraction over veth/network interface operations.
#[cfg_attr(test, automock)]
pub trait VethOps: Send + Sync {
    fn create_pair(&self, name: &str, peer: &str) -> Result<()>;
    fn destroy_pair(&self, name: &str) -> Result<()>;
    fn bring_up(&self, name: &str) -> Result<()>;
    fn get_ifindex(&self, name: &str) -> Result<u32>;
    fn interface_exists(&self, name: &str) -> bool;
}

/// Production implementation using `ip` commands and libc.
pub struct SystemVethOps;

impl VethOps for SystemVethOps {
    fn create_pair(&self, name: &str, peer: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["link", "add", name, "type", "veth", "peer", "name", peer])
            .output()
            .context("Failed to create veth pair")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // EEXIST is ok
            if !stderr.contains("File exists") {
                anyhow::bail!("Failed to create veth pair: {}", stderr);
            }
        }
        Ok(())
    }

    fn destroy_pair(&self, name: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["link", "del", name])
            .output()
            .context("Failed to delete veth pair")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("Cannot find device") {
                warn!("Failed to delete veth pair: {}", stderr);
            }
        }
        Ok(())
    }

    fn bring_up(&self, name: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["link", "set", name, "up"])
            .output()
            .with_context(|| format!("Failed to bring up {}", name))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to bring up {}: {}", name, stderr);
        }
        Ok(())
    }

    fn get_ifindex(&self, name: &str) -> Result<u32> {
        use std::ffi::CString;
        let cname = CString::new(name)?;
        let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            anyhow::bail!("Interface {} not found", name);
        }
        Ok(ifindex)
    }

    fn interface_exists(&self, name: &str) -> bool {
        Path::new(&format!("/sys/class/net/{}", name)).exists()
    }
}

/// Manages the veth pair used for mirroring packets to Suricata
pub struct VethManager {
    veth_name: String, // "pe-inspect0" (our side)
    peer_name: String, // "pe-inspect1" (Suricata's side)
    created: bool,
    ops: Arc<dyn VethOps>,
}

impl Default for VethManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VethManager {
    pub fn new() -> Self {
        Self::new_with_ops(Arc::new(SystemVethOps))
    }

    /// Construct with injected VethOps (used in unit tests).
    pub fn new_with_ops(ops: Arc<dyn VethOps>) -> Self {
        Self {
            veth_name: crate::types::INSPECT_VETH_LOCAL.to_string(),
            peer_name: crate::types::INSPECT_VETH_PEER.to_string(),
            created: false,
            ops,
        }
    }

    /// Create the veth pair
    pub fn create_pair(&mut self) -> Result<()> {
        // Check if already exists
        if self.ops.interface_exists(&self.veth_name) {
            info!("Veth pair already exists");
            self.created = true;
            return Ok(());
        }

        self.ops.create_pair(&self.veth_name, &self.peer_name)?;
        self.bring_up()?;
        self.created = true;
        info!("Created veth pair {}<->{}", self.veth_name, self.peer_name);
        Ok(())
    }

    /// Destroy the veth pair
    pub fn destroy_pair(&mut self) -> Result<()> {
        self.ops.destroy_pair(&self.veth_name)?;
        self.created = false;
        info!(
            "Destroyed veth pair {}<->{}",
            self.veth_name, self.peer_name
        );
        Ok(())
    }

    /// Get the ifindex of the local veth endpoint (pe-inspect0)
    pub fn get_ifindex(&self) -> Result<u32> {
        self.ops.get_ifindex(&self.veth_name)
    }

    /// Check if the veth pair exists and is up
    pub fn is_up(&self) -> bool {
        self.ops.interface_exists(&self.veth_name)
    }

    /// Bring both ends of the veth pair up
    pub fn bring_up(&self) -> Result<()> {
        for name in [&self.veth_name, &self.peer_name] {
            self.ops.bring_up(name)?;
        }
        debug!(
            "Brought up veth pair {}<->{}",
            self.veth_name, self.peer_name
        );
        Ok(())
    }

    /// Get the veth interface name (our side)
    pub fn veth_name(&self) -> &str {
        &self.veth_name
    }

    /// Get the peer interface name (Suricata's side)
    pub fn peer_name(&self) -> &str {
        &self.peer_name
    }

    /// Whether the pair was created by this instance
    pub fn is_created(&self) -> bool {
        self.created
    }
}

impl Drop for VethManager {
    fn drop(&mut self) {
        if self.created {
            debug!("VethManager dropped, veth pair remains");
        }
    }
}
