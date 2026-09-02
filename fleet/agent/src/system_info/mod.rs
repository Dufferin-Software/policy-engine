// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! System information abstraction.
//!
//! The [`SystemInfo`] trait provides a mockable interface for querying
//! OS identity and kernel version.  The real implementation reads from
//! `/etc/os-release` and `uname(2)`.

pub mod real;

use anyhow::Result;

#[cfg(test)]
use mockall::automock;

/// OS identity and kernel version.
#[derive(Debug, Clone, Default)]
pub struct OsInfo {
    /// Human-readable OS name, e.g. "Debian GNU/Linux 13 (trixie)".
    /// Sourced from PRETTY_NAME in /etc/os-release.
    pub os_pretty_name: String,
    /// Kernel version string, e.g. "6.12.74+deb13+1-amd64".
    /// Sourced from uname().release.
    pub kernel_version: String,
    /// DMI system vendor, e.g. "Dell Inc.".
    /// Sourced from /sys/class/dmi/id/sys_vendor. Empty if not readable.
    pub dmi_sys_vendor: String,
    /// DMI product name, e.g. "PowerEdge R340".
    /// Sourced from /sys/class/dmi/id/product_name. Empty if not readable.
    pub dmi_product_name: String,
}

/// Abstraction over OS/kernel information.
///
/// Production code uses [`RealSystemInfo`]; tests inject a mock.
#[cfg_attr(test, automock)]
pub trait SystemInfo: Send + Sync {
    /// Return OS and kernel information for this host.
    fn get_os_info(&self) -> Result<OsInfo>;
}
