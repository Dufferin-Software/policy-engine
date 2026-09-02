// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Kernel IP-forwarding control.
//!
//! Both uRPF and XDP FIB forwarding rely on `bpf_fib_lookup()`, whose route
//! lookup is gated on forwarding being enabled on the ingress interface (its
//! `IN_DEV_FORWARD` check is not bypassed by any lookup flag). So before either
//! feature is enabled we make sure the kernel is forwarding; otherwise uRPF
//! silently fails open and FIB-redirect never finds a route.
//!
//! This is a stopgap: a future version may subscribe to netlink route updates
//! and maintain its own per-interface source-prefix LPM trie in the XDP program,
//! removing the dependency on `bpf_fib_lookup` (and thus on forwarding) entirely.
//!
//! The trait is mockable so unit tests never write to the host's sysctls.

use anyhow::{Context, Result};

/// Enables kernel IP forwarding on a specific interface. Injected into
/// `PolicyService` so tests can substitute a no-op / mock and never touch the
/// real system.
#[cfg_attr(test, mockall::automock)]
pub trait ForwardingControl: Send + Sync {
    /// Enable forwarding so uRPF / FIB-forward work on `interface`.
    ///
    /// IPv4 is set per-interface (`net.ipv4.conf.<iface>.forwarding`) — that is
    /// the effective knob the kernel and `bpf_fib_lookup`'s `IN_DEV_FORWARD`
    /// read, so it avoids touching unrelated interfaces. IPv6 is set globally
    /// (`net.ipv6.conf.all.forwarding`): the per-interface v6 `forwarding` flag
    /// satisfies the helper's per-device `idev->cnf.forwarding` check, but the
    /// kernel's v6 route resolution only yields a forwardable result when the
    /// global master is on (confirmed against the kernel source). Setting `all`
    /// also propagates down to each interface's `cnf.forwarding`. Idempotent.
    fn enable_ip_forwarding(&self, interface: &str) -> Result<()>;
}

/// Production implementation that writes the real `/proc/sys` sysctls.
pub struct DefaultForwardingControl;

impl ForwardingControl for DefaultForwardingControl {
    fn enable_ip_forwarding(&self, interface: &str) -> Result<()> {
        // Write the /proc path directly (rather than via the `sysctl` tool) so
        // dotted interface names like "eth0.100" need no escaping.
        // IPv4 is the primary path; fail the operation if it can't be set so the
        // caller doesn't enable a feature that would silently fail open.
        write_sysctl(
            &format!("/proc/sys/net/ipv4/conf/{interface}/forwarding"),
            "1",
        )
        .with_context(|| format!("enabling IPv4 forwarding on {interface}"))?;

        // IPv6 must go through the global master (see the trait doc). May be
        // absent if IPv6 is disabled on the host — best-effort, just warn.
        if let Err(e) = write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1") {
            log::warn!("could not enable global IPv6 forwarding: {e:#}");
        }
        Ok(())
    }
}

fn write_sysctl(path: &str, value: &str) -> Result<()> {
    std::fs::write(path, value).with_context(|| format!("writing '{value}' to {path}"))
}

/// No-op control used as the default in unit-test builds so that no test can
/// accidentally write to the host's forwarding sysctls. Tests that assert the
/// enable happens inject a `MockForwardingControl` explicitly.
#[cfg(test)]
pub struct NoopForwardingControl;

#[cfg(test)]
impl ForwardingControl for NoopForwardingControl {
    fn enable_ip_forwarding(&self, _interface: &str) -> Result<()> {
        Ok(())
    }
}
