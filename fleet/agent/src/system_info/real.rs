// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Real [`SystemInfo`] implementation that reads from the Linux kernel and filesystem.

use anyhow::{Context, Result};

use super::{OsInfo, SystemInfo};

/// Reads system information from the operating system.
#[derive(Default)]
pub struct RealSystemInfo;

impl RealSystemInfo {
    pub fn new() -> Self {
        Self
    }
}

impl SystemInfo for RealSystemInfo {
    fn get_os_info(&self) -> Result<OsInfo> {
        let os_pretty_name = read_os_pretty_name().unwrap_or_default();
        let kernel_version = read_kernel_version().context("Failed to read kernel version")?;
        let dmi_sys_vendor = read_dmi_field("sys_vendor").unwrap_or_default();
        let dmi_product_name = read_dmi_field("product_name").unwrap_or_default();
        Ok(OsInfo {
            os_pretty_name,
            kernel_version,
            dmi_sys_vendor,
            dmi_product_name,
        })
    }
}

/// Read a DMI field from `/sys/class/dmi/id/<name>` and trim trailing whitespace.
fn read_dmi_field(name: &str) -> Option<String> {
    let path = format!("/sys/class/dmi/id/{}", name);
    let content = std::fs::read_to_string(&path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Read PRETTY_NAME from /etc/os-release.
fn read_os_pretty_name() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            // Strip surrounding quotes if present.
            let value = value.trim_matches('"');
            return Some(value.to_string());
        }
    }
    None
}

/// Read kernel version from uname(2).
fn read_kernel_version() -> Result<String> {
    let uname = nix::sys::utsname::uname().context("uname failed")?;
    Ok(uname.release().to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_os_pretty_name() {
        // On any Linux system, /etc/os-release should exist.
        let name = read_os_pretty_name();
        assert!(name.is_some(), "Should find PRETTY_NAME in /etc/os-release");
        assert!(!name.unwrap().is_empty());
    }

    #[test]
    fn test_read_kernel_version() {
        let version = read_kernel_version().unwrap();
        assert!(!version.is_empty(), "Kernel version should not be empty");
    }

    #[test]
    fn test_real_system_info() {
        let info = RealSystemInfo::new();
        let os = info.get_os_info().unwrap();
        assert!(!os.kernel_version.is_empty());
    }

    #[test]
    fn test_read_dmi_field_missing_returns_none() {
        // A name that cannot exist under /sys/class/dmi/id/.
        assert!(read_dmi_field("__no_such_dmi_field__").is_none());
    }

    #[test]
    fn test_read_dmi_field_trims_trailing_newline() {
        // If sys_vendor is readable on this host, the value must not contain
        // a trailing newline (the kernel always terminates the file with \n).
        if let Some(v) = read_dmi_field("sys_vendor") {
            assert!(!v.ends_with('\n'));
            assert_eq!(v, v.trim());
        }
    }

    #[test]
    fn test_get_os_info_includes_dmi_fields() {
        let info = RealSystemInfo::new().get_os_info().unwrap();
        // Fields are Strings; they may be empty on VMs without DMI, but
        // must never contain raw newline-terminated kernel output.
        assert_eq!(info.dmi_sys_vendor, info.dmi_sys_vendor.trim());
        assert_eq!(info.dmi_product_name, info.dmi_product_name.trim());
    }
}
