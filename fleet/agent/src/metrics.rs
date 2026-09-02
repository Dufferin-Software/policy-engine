// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Agent-process-local Prometheus metrics.
//!
//! These cover state the local policy-engine cannot observe — specifically
//! the cert-renewal task. The agent does not run a `/metrics` HTTP server;
//! instead, `render()` produces the exposition text and the
//! [`metrics_forwarder`](crate::metrics_forwarder) appends it to the
//! engine-scraped body before sending the combined buffer to the controller
//! over the management stream. That way the controller sees agent metrics on
//! the same channel as engine metrics with no new gRPC plumbing.

use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};

/// Process-local registry. Separate from any registry the local engine may
/// run — the agent and engine are different processes and do not share
/// state.
pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

/// Count of `RenewClientCert` attempts that failed for *any* reason
/// (network, controller error, file write). Monotonic over the agent's
/// lifetime; the controller does its own rate derivation.
pub static CERT_RENEWAL_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    let m = IntCounter::new(
        "fleet_node_cert_renewal_failures_total",
        "Total number of cert renewal attempts that failed since this agent process started.",
    )
    .expect("counter construction is infallible for a literal name");
    REGISTRY
        .register(Box::new(m.clone()))
        .expect("registering a fresh metric in a fresh registry is infallible");
    m
});

/// 1 when the cert is within 7 days of expiry AND the last renewal attempt
/// failed; 0 otherwise. The alert-worthy condition is "we tried, we
/// couldn't, and we're running out of cert" — a single failure when there's
/// still a month left is noise.
pub static CERT_RENEWAL_FAILING: Lazy<IntGauge> = Lazy::new(|| {
    let m = IntGauge::new(
        "fleet_node_cert_renewal_failing",
        "1 if cert renewal has failed AND the current cert is within 7d of expiry; 0 otherwise.",
    )
    .expect("gauge construction is infallible for a literal name");
    REGISTRY
        .register(Box::new(m.clone()))
        .expect("registering a fresh metric in a fresh registry is infallible");
    m
});

/// Render `REGISTRY` as Prometheus exposition text.
///
/// Returns an empty `Vec` on encoding failure so the forwarder can blindly
/// concatenate without special-casing. An encoder error here is structurally
/// impossible (counters + gauges with no labels) so the empty fallback is
/// purely a belt-and-braces against future metric additions.
pub fn render() -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    let encoder = TextEncoder::new();
    let metrics = REGISTRY.gather();
    if encoder.encode(&metrics, &mut buf).is_err() {
        return Vec::new();
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_renewal_metric_names() {
        // Touch both Lazies so they register before render().
        CERT_RENEWAL_FAILURES_TOTAL.inc_by(0);
        CERT_RENEWAL_FAILING.set(0);
        let out = String::from_utf8(render()).expect("exposition is valid UTF-8");
        assert!(
            out.contains("fleet_node_cert_renewal_failures_total"),
            "renewal-failures counter must appear in exposition, got:\n{out}"
        );
        assert!(
            out.contains("fleet_node_cert_renewal_failing"),
            "renewal-failing gauge must appear in exposition, got:\n{out}"
        );
    }
}
