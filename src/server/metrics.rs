// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Metrics collection and formatting for the `/metrics` endpoint.
//!
//! The [`MetricsFormatter`] trait abstracts the output format so that
//! different serialisations (Prometheus text, OpenMetrics, JSON, InfluxDB line
//! protocol, …) can be plugged in without touching the collection logic.
//!
//! [`MetricsSnapshot`] is a plain data structure that holds all metric values
//! gathered from the policy service.  The handler collects the snapshot once,
//! then delegates formatting to whichever [`MetricsFormatter`] is registered.
//!
//! Provided implementations:
//! - [`PrometheusFormatter`] — Prometheus text exposition format (version 0.0.4).

use std::fmt::Write as FmtWrite;
use std::sync::Arc;

use actix_web::{web, HttpResponse, Result as ActixResult};

use crate::types::{Direction, GlobalStats};

use super::graphql::AppState;

// ---------------------------------------------------------------------------
// Ethertype snapshot type
// ---------------------------------------------------------------------------

/// Ethertype packet counter for one interface + direction.
pub struct EthertypeMetrics {
    pub interface: String,
    pub direction: &'static str,
    pub ethertype: u16,
    pub ethertype_name: &'static str,
    pub packets: u64,
}

// ---------------------------------------------------------------------------
// Snapshot types — plain data, no locking
// ---------------------------------------------------------------------------

/// Traffic counters for one interface + direction pair.
pub struct InterfaceMetrics {
    pub interface: String,
    pub direction: &'static str,
    pub stats: GlobalStats,
}

/// Per-rule packet/byte counters.
pub struct RuleMetrics {
    pub rule_id: u64,
    pub direction: &'static str,
    pub packets: u64,
    pub bytes: u64,
}

/// Per-protocol packet/byte counters.
pub struct ProtoMetrics {
    pub protocol: &'static str,
    pub direction: &'static str,
    pub packets: u64,
    pub bytes: u64,
}

/// Per-QUIC-version packet/byte counters (ingress only).
pub struct QuicMetrics {
    pub version: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Pre-computed latency percentiles for one direction.
pub struct LatencyMetrics {
    pub direction: &'static str,
    pub p50_ns: i64,
    pub p90_ns: i64,
    pub p99_ns: i64,
    pub total_samples: u64,
}

/// All metric values gathered from the policy service in a single lock window.
pub struct MetricsSnapshot {
    pub interfaces: Vec<InterfaceMetrics>,
    pub rules: Vec<RuleMetrics>,
    pub protos: Vec<ProtoMetrics>,
    pub l3_protos: Vec<ProtoMetrics>,
    pub latencies: Vec<LatencyMetrics>,
    pub quic: Vec<QuicMetrics>,
    pub ethertype_stats: Vec<EthertypeMetrics>,
    pub uptime_secs: u64,
}

// ---------------------------------------------------------------------------
// MetricsFormatter trait
// ---------------------------------------------------------------------------

/// Trait for metrics output backends.
///
/// Implement this to add new serialisation formats.  The handler collects a
/// [`MetricsSnapshot`] and passes it to [`format`](MetricsFormatter::format).
pub trait MetricsFormatter: Send + Sync {
    /// Serialise `snapshot` into a byte buffer.
    fn format(&self, snapshot: &MetricsSnapshot) -> Vec<u8>;

    /// The HTTP `Content-Type` header value for this format.
    fn content_type(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// PrometheusFormatter
// ---------------------------------------------------------------------------

/// Formats metrics as Prometheus text exposition format (version 0.0.4).
pub struct PrometheusFormatter;

impl MetricsFormatter for PrometheusFormatter {
    fn content_type(&self) -> &'static str {
        "text/plain; version=0.0.4; charset=utf-8"
    }

    fn format(&self, snap: &MetricsSnapshot) -> Vec<u8> {
        let mut buf = String::with_capacity(4096);

        for im in &snap.interfaces {
            let iface = &im.interface;
            let dir = im.direction;
            let s = &im.stats;

            macro_rules! counter {
                ($name:expr, $val:expr) => {
                    let _ = writeln!(buf, "# TYPE {} counter", $name);
                    let _ = writeln!(
                        buf,
                        "{}{{interface=\"{}\",direction=\"{}\"}} {}",
                        $name, iface, dir, $val
                    );
                };
            }

            // Direction-exclusive packet/byte counters. The XDP ingress program
            // only ever populates `rx_*`; the TC egress program only `tx_*`.
            // Emitting the opposite direction's fields would publish a
            // permanently-zero shadow series (e.g. `rx_bytes` for an egress
            // interface), which a label-blind consumer — such as the fleet
            // controller summing `policy_engine_rx_bytes_total` across all
            // label sets — would fold in as if it were real traffic. Emit only
            // the fields the direction actually owns.
            if dir == dir_label(Direction::Ingress) {
                counter!("policy_engine_rx_packets_total", s.rx_packets);
                counter!("policy_engine_rx_bytes_total", s.rx_bytes);
            } else {
                counter!("policy_engine_tx_packets_total", s.tx_packets);
                counter!("policy_engine_tx_bytes_total", s.tx_bytes);
            }
            counter!("policy_engine_policy_matches_total", s.policy_matches);
            counter!("policy_engine_policy_drops_total", s.policy_drops);
            counter!("policy_engine_policy_pass_total", s.policy_pass);
            counter!("policy_engine_policy_redirects_total", s.policy_redirects);
            counter!("policy_engine_parse_errors_total", s.parse_errors);
            counter!("policy_engine_tail_calls_total", s.tail_calls);
            counter!("policy_engine_bum_packets_total", s.bum_packets);
            counter!("policy_engine_non_ip_unicast_total", s.non_ip_unicast);
            counter!("policy_engine_fragments_total", s.fragments);
            counter!(
                "policy_engine_verdict_pass_packets_total",
                s.verdict_pass_packets
            );
            counter!(
                "policy_engine_verdict_pass_bytes_total",
                s.verdict_pass_bytes
            );
            counter!(
                "policy_engine_verdict_drop_packets_total",
                s.verdict_drop_packets
            );
            counter!(
                "policy_engine_verdict_drop_bytes_total",
                s.verdict_drop_bytes
            );
            counter!(
                "policy_engine_fib_forwarded_packets_total",
                s.fib_forwarded_packets
            );
            counter!(
                "policy_engine_fib_forwarded_bytes_total",
                s.fib_forwarded_bytes
            );
            counter!(
                "policy_engine_fib_fallback_packets_total",
                s.fib_fallback_packets
            );
            counter!("policy_engine_urpf_drop_packets_total", s.urpf_drop_packets);
            counter!("policy_engine_urpf_drop_bytes_total", s.urpf_drop_bytes);
            #[cfg(feature = "suricata")]
            counter!("policy_engine_inspect_redirects_total", s.inspect_redirects);
        }

        for em in &snap.ethertype_stats {
            let _ = writeln!(buf, "# TYPE policy_engine_ethertype_packets_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_ethertype_packets_total{{interface=\"{}\",direction=\"{}\",ethertype=\"{}\",ethertype_name=\"{}\"}} {}",
                em.interface, em.direction, em.ethertype, em.ethertype_name, em.packets
            );
        }

        for rm in &snap.rules {
            let _ = writeln!(buf, "# TYPE policy_engine_rule_packets_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_rule_packets_total{{rule_id=\"{}\",direction=\"{}\"}} {}",
                rm.rule_id, rm.direction, rm.packets
            );
            let _ = writeln!(buf, "# TYPE policy_engine_rule_bytes_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_rule_bytes_total{{rule_id=\"{}\",direction=\"{}\"}} {}",
                rm.rule_id, rm.direction, rm.bytes
            );
        }

        for pm in &snap.protos {
            let _ = writeln!(buf, "# TYPE policy_engine_proto_packets_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_proto_packets_total{{protocol=\"{}\",direction=\"{}\"}} {}",
                pm.protocol, pm.direction, pm.packets
            );
            let _ = writeln!(buf, "# TYPE policy_engine_proto_bytes_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_proto_bytes_total{{protocol=\"{}\",direction=\"{}\"}} {}",
                pm.protocol, pm.direction, pm.bytes
            );
        }

        for pm in &snap.l3_protos {
            let _ = writeln!(buf, "# TYPE policy_engine_l3_proto_packets_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_l3_proto_packets_total{{protocol=\"{}\",direction=\"{}\"}} {}",
                pm.protocol, pm.direction, pm.packets
            );
            let _ = writeln!(buf, "# TYPE policy_engine_l3_proto_bytes_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_l3_proto_bytes_total{{protocol=\"{}\",direction=\"{}\"}} {}",
                pm.protocol, pm.direction, pm.bytes
            );
        }

        for qm in &snap.quic {
            let _ = writeln!(buf, "# TYPE policy_engine_quic_packets_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_quic_packets_total{{version=\"{}\"}} {}",
                qm.version, qm.packets
            );
            let _ = writeln!(buf, "# TYPE policy_engine_quic_bytes_total counter");
            let _ = writeln!(
                buf,
                "policy_engine_quic_bytes_total{{version=\"{}\"}} {}",
                qm.version, qm.bytes
            );
        }

        let _ = writeln!(buf, "# TYPE policy_engine_uptime_seconds gauge");
        let _ = writeln!(buf, "policy_engine_uptime_seconds {}", snap.uptime_secs);

        if !snap.latencies.is_empty() {
            let _ = writeln!(buf, "# TYPE policy_engine_processing_time_ns summary");
            for lm in &snap.latencies {
                let dir = lm.direction;
                if lm.total_samples == 0 {
                    // No samples yet: emit NaN so Grafana shows "no data" rather
                    // than a flat zero line that obscures other series.
                    for q in ["0.5", "0.9", "0.99"] {
                        let _ = writeln!(
                            buf,
                            "policy_engine_processing_time_ns{{direction=\"{}\",quantile=\"{}\"}} NaN",
                            dir, q
                        );
                    }
                } else {
                    for (q, val) in [("0.5", lm.p50_ns), ("0.9", lm.p90_ns), ("0.99", lm.p99_ns)] {
                        let _ = writeln!(
                            buf,
                            "policy_engine_processing_time_ns{{direction=\"{}\",quantile=\"{}\"}} {}",
                            dir, q, val
                        );
                    }
                }
                let _ = writeln!(
                    buf,
                    "policy_engine_processing_time_ns_count{{direction=\"{}\"}} {}",
                    dir, lm.total_samples
                );
            }
        }

        buf.into_bytes()
    }
}

// ---------------------------------------------------------------------------
// Snapshot collection
// ---------------------------------------------------------------------------

/// Return interface index for a named interface, or 0 if not found.
fn bucket_ns(k: usize) -> i64 {
    if k == 0 {
        return 1;
    }
    let lo = 1u64 << k;
    let mid = lo + (lo >> 1);
    mid as i64
}

fn hist_percentile(hist: &[u64], total: u64, frac: f64) -> i64 {
    let target = (total as f64 * frac).ceil() as u64;
    let mut cumulative = 0u64;
    for (k, &count) in hist.iter().enumerate() {
        cumulative += count;
        if cumulative >= target {
            return bucket_ns(k);
        }
    }
    bucket_ns(hist.len().saturating_sub(1))
}

fn compute_latency_metrics(direction: &'static str, hist: &[u64]) -> LatencyMetrics {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return LatencyMetrics {
            direction,
            p50_ns: 0,
            p90_ns: 0,
            p99_ns: 0,
            total_samples: 0,
        };
    }
    LatencyMetrics {
        direction,
        p50_ns: hist_percentile(hist, total, 0.50),
        p90_ns: hist_percentile(hist, total, 0.90),
        p99_ns: hist_percentile(hist, total, 0.99),
        total_samples: total,
    }
}

/// Return interface index for a named interface, or 0 if not found.
fn ifindex_for(name: &str) -> u32 {
    let Ok(cname) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: cname is a valid NUL-terminated string.
    unsafe { libc::if_nametoindex(cname.as_ptr()) }
}

fn dir_label(d: Direction) -> &'static str {
    match d {
        Direction::Ingress => "ingress",
        Direction::Egress => "egress",
    }
}

/// Order-preserving de-duplication of attachment records by interface name.
///
/// `PolicyService::get_interfaces` returns one record per attached direction
/// (XDP ingress and TC egress are separate attachments), so an interface
/// attached in both directions appears more than once. The snapshot collector
/// already emits both directions for every interface it visits, so it must
/// visit each interface name exactly once; otherwise it produces duplicate
/// `{interface,direction}` series and any label-blind consumer (the fleet
/// controller sums `policy_engine_rx_bytes_total` across all label sets) will
/// double-count the traffic.
fn unique_interfaces(attachments: &[crate::shared_types::InterfaceAttachment]) -> Vec<&str> {
    let mut seen = std::collections::HashSet::new();
    attachments
        .iter()
        .filter(|att| seen.insert(att.interface.as_str()))
        .map(|att| att.interface.as_str())
        .collect()
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        2 => "igmp",
        6 => "tcp",
        17 => "udp",
        33 => "dccp",
        41 => "ipv6",
        46 => "rsvp",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        58 => "icmpv6",
        88 => "eigrp",
        89 => "ospf",
        103 => "pim",
        112 => "vrrp",
        115 => "l2tp",
        132 => "sctp",
        _ => "other",
    }
}

fn l3_proto_name(bucket: usize) -> &'static str {
    match bucket {
        0 => "ipv4",
        1 => "ipv6",
        2 => "arp",
        3 => "mpls",
        _ => "other",
    }
}

async fn collect_snapshot(state: &AppState) -> MetricsSnapshot {
    let uptime_secs = state.start_time.elapsed().as_secs();
    let mut service = state.service.lock().await;

    let mut interfaces = Vec::new();
    let mut rules = Vec::new();
    let mut protos = Vec::new();
    let mut l3_protos = Vec::new();
    let mut latencies = Vec::new();
    let mut quic = Vec::new();
    let mut ethertype_stats = Vec::new();

    // Per-interface stats.
    //
    // `get_interfaces()` returns one attachment record per direction, so an
    // interface attached both XDP-ingress and TC-egress appears twice. The
    // inner loop below already emits both directions per interface, so we must
    // visit each interface name only once — otherwise we emit duplicate
    // `{interface,direction}` series, which downstream label-blind summing
    // (e.g. fleet rx/tx bandwidth) double-counts.
    let attachments = service.get_interfaces();
    for iface in unique_interfaces(&attachments) {
        let ifindex = ifindex_for(iface);
        if ifindex == 0 {
            continue;
        }
        for dir in [Direction::Ingress, Direction::Egress] {
            if !service.is_direction_loaded(dir) {
                continue;
            }
            if let Ok(stats) = service.get_global_stats(ifindex, dir) {
                interfaces.push(InterfaceMetrics {
                    interface: iface.to_string(),
                    direction: dir_label(dir),
                    stats,
                });
            }
            if let Ok(et_vec) = service.get_ethertype_stats(ifindex, dir) {
                let dir_str = dir_label(dir);
                for et in et_vec {
                    if et.packets > 0 {
                        ethertype_stats.push(EthertypeMetrics {
                            interface: iface.to_string(),
                            direction: dir_str,
                            ethertype: et.ethertype,
                            ethertype_name: et.name(),
                            packets: et.packets,
                        });
                    }
                }
            }
        }
    }

    // Per-rule stats
    for dir in [Direction::Ingress, Direction::Egress] {
        if !service.is_direction_loaded(dir) {
            continue;
        }
        let Ok((v4, v6)) = service.list_rules(dir) else {
            continue;
        };
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for (_, _, rule) in &v4 {
            seen.insert(rule.rule_id);
        }
        for (_, _, rule) in &v6 {
            seen.insert(rule.rule_id);
        }
        for rule_id in seen {
            if let Ok(Some(s)) = service.get_rule_stats(rule_id, dir) {
                rules.push(RuleMetrics {
                    rule_id,
                    direction: dir_label(dir),
                    packets: s.packets,
                    bytes: s.bytes,
                });
            }
        }
    }

    // Per-protocol stats
    for dir in [Direction::Ingress, Direction::Egress] {
        if !service.is_direction_loaded(dir) {
            continue;
        }
        let Ok(proto_vec) = service.get_proto_stats(dir) else {
            continue;
        };
        // proto stats are slot-indexed; map each slot back to its protocol
        // number (slot 0 = catch-all → proto 0 → "other").
        for (slot, ps) in proto_vec.iter().enumerate() {
            if ps.packets == 0 {
                continue;
            }
            protos.push(ProtoMetrics {
                protocol: proto_name(crate::types::IP_PROTO_SLOT_PROTOS[slot]),
                direction: dir_label(dir),
                packets: ps.packets,
                bytes: ps.bytes,
            });
        }
    }

    // L3 stats
    for dir in [Direction::Ingress, Direction::Egress] {
        if !service.is_direction_loaded(dir) {
            continue;
        }
        let Ok(l3_vec) = service.get_l3_stats(dir) else {
            continue;
        };
        for (bucket, ps) in l3_vec.iter().enumerate() {
            if ps.packets == 0 {
                continue;
            }
            l3_protos.push(ProtoMetrics {
                protocol: l3_proto_name(bucket),
                direction: dir_label(dir),
                packets: ps.packets,
                bytes: ps.bytes,
            });
        }
    }

    // Processing-time histograms (one per direction, not per interface)
    for dir in [Direction::Ingress, Direction::Egress] {
        if !service.is_direction_loaded(dir) {
            continue;
        }
        if let Ok(hist) = service.get_processing_time_hist(dir) {
            latencies.push(compute_latency_metrics(dir_label(dir), &hist));
        }
    }

    // QUIC version stats (ingress only; egress returns empty)
    if service.is_direction_loaded(Direction::Ingress) {
        if let Ok(quic_vec) = service.get_quic_stats(Direction::Ingress) {
            for (version, packets, bytes) in quic_vec {
                if packets > 0 {
                    quic.push(QuicMetrics {
                        version,
                        packets,
                        bytes,
                    });
                }
            }
        }
    }

    MetricsSnapshot {
        interfaces,
        rules,
        protos,
        l3_protos,
        latencies,
        quic,
        ethertype_stats,
        uptime_secs,
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Prometheus `/metrics` handler.
///
/// Collects a [`MetricsSnapshot`] from the policy service, then delegates
/// formatting to the [`MetricsFormatter`] registered as app data.
pub async fn metrics_handler(
    state: web::Data<Arc<AppState>>,
    formatter: web::Data<Arc<dyn MetricsFormatter>>,
) -> ActixResult<HttpResponse> {
    let snapshot = collect_snapshot(&state).await;
    let body = formatter.format(&snapshot);
    Ok(HttpResponse::Ok()
        .content_type(formatter.content_type())
        .body(body))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn attachment(interface: &str, direction: &str) -> crate::shared_types::InterfaceAttachment {
        crate::shared_types::InterfaceAttachment {
            interface: interface.to_string(),
            ifindex: 0,
            mode: String::new(),
            direction: direction.to_string(),
        }
    }

    #[test]
    fn unique_interfaces_collapses_per_direction_records() {
        // An interface attached both XDP-ingress and TC-egress shows up once
        // per direction. The snapshot collector must visit it only once, or it
        // emits duplicate `{interface,direction}` series that the fleet
        // controller's label-blind counter sum double-counts.
        let attachments = vec![
            attachment("enp1s0", "ingress"),
            attachment("enp1s0", "egress"),
        ];
        assert_eq!(unique_interfaces(&attachments), vec!["enp1s0"]);
    }

    #[test]
    fn unique_interfaces_preserves_order_across_distinct_ifaces() {
        let attachments = vec![
            attachment("enp1s0", "ingress"),
            attachment("enp2s0", "ingress"),
            attachment("enp1s0", "egress"),
            attachment("enp2s0", "egress"),
        ];
        assert_eq!(unique_interfaces(&attachments), vec!["enp1s0", "enp2s0"]);
    }

    #[test]
    fn unique_interfaces_empty() {
        assert!(unique_interfaces(&[]).is_empty());
    }

    #[test]
    fn prometheus_formatter_empty_snapshot() {
        let formatter = PrometheusFormatter;
        let snap = MetricsSnapshot {
            interfaces: vec![],
            rules: vec![],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 42,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output.contains("policy_engine_uptime_seconds 42"));
        assert!(output.contains("# TYPE policy_engine_uptime_seconds gauge"));
    }

    #[test]
    fn prometheus_formatter_interface_metrics() {
        let formatter = PrometheusFormatter;
        let snap = MetricsSnapshot {
            interfaces: vec![InterfaceMetrics {
                interface: "eth0".to_string(),
                direction: "ingress",
                stats: GlobalStats {
                    rx_packets: 1000,
                    rx_bytes: 100000,
                    policy_drops: 5,
                    ..GlobalStats::default()
                },
            }],
            rules: vec![],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 0,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output.contains(
            "policy_engine_rx_packets_total{interface=\"eth0\",direction=\"ingress\"} 1000"
        ));
        assert!(output.contains(
            "policy_engine_policy_drops_total{interface=\"eth0\",direction=\"ingress\"} 5"
        ));
        // An ingress interface must not publish tx_* shadow series — the XDP
        // path never populates them, so they would be a permanently-zero
        // counter that label-blind consumers would double-count.
        assert!(!output.contains("policy_engine_tx_packets_total"));
        assert!(!output.contains("policy_engine_tx_bytes_total"));
    }

    #[test]
    fn prometheus_formatter_egress_interface_emits_only_tx() {
        let formatter = PrometheusFormatter;
        let snap = MetricsSnapshot {
            interfaces: vec![InterfaceMetrics {
                interface: "eth0".to_string(),
                direction: "egress",
                stats: GlobalStats {
                    tx_packets: 2000,
                    tx_bytes: 200000,
                    ..GlobalStats::default()
                },
            }],
            rules: vec![],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 0,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output.contains(
            "policy_engine_tx_bytes_total{interface=\"eth0\",direction=\"egress\"} 200000"
        ));
        // An egress interface must not publish rx_* shadow series — the TC path
        // never populates them. This is the zero-valued counter that, when the
        // interface was enumerated twice, summed into the bogus 2x bandwidth.
        assert!(!output.contains("policy_engine_rx_packets_total"));
        assert!(!output.contains("policy_engine_rx_bytes_total"));
    }

    #[test]
    fn prometheus_formatter_rule_metrics() {
        let formatter = PrometheusFormatter;
        let snap = MetricsSnapshot {
            interfaces: vec![],
            rules: vec![RuleMetrics {
                rule_id: 42,
                direction: "egress",
                packets: 999,
                bytes: 12345,
            }],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 0,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output
            .contains("policy_engine_rule_packets_total{rule_id=\"42\",direction=\"egress\"} 999"));
    }

    #[test]
    fn prometheus_formatter_proto_metrics() {
        let formatter = PrometheusFormatter;
        let snap = MetricsSnapshot {
            interfaces: vec![],
            rules: vec![],
            protos: vec![ProtoMetrics {
                protocol: "tcp",
                direction: "ingress",
                packets: 500,
                bytes: 50000,
            }],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 0,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output.contains(
            "policy_engine_proto_packets_total{protocol=\"tcp\",direction=\"ingress\"} 500"
        ));
    }

    #[test]
    fn content_type_is_prometheus() {
        assert_eq!(
            PrometheusFormatter.content_type(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
    }

    /// A formatter that returns a fixed string — useful for handler tests.
    #[allow(dead_code)]
    pub struct FixedFormatter(pub &'static str);

    impl MetricsFormatter for FixedFormatter {
        fn format(&self, _: &MetricsSnapshot) -> Vec<u8> {
            self.0.as_bytes().to_vec()
        }
        fn content_type(&self) -> &'static str {
            "text/plain"
        }
    }

    #[test]
    fn latency_metrics_percentiles() {
        // Histogram: all 1000 samples in bucket 10 (mid = 1536 ns)
        let mut hist = vec![0u64; 64];
        hist[10] = 1000;
        let lm = compute_latency_metrics("ingress", &hist);
        assert_eq!(lm.p50_ns, 1536);
        assert_eq!(lm.p90_ns, 1536);
        assert_eq!(lm.p99_ns, 1536);
        assert_eq!(lm.total_samples, 1000);
    }

    #[test]
    fn prometheus_formatter_latency_metrics() {
        let formatter = PrometheusFormatter;
        let mut hist = vec![0u64; 64];
        hist[10] = 500;
        hist[15] = 500;
        let snap = MetricsSnapshot {
            interfaces: vec![],
            rules: vec![],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![compute_latency_metrics("ingress", &hist)],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 0,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output.contains("# TYPE policy_engine_processing_time_ns summary"));
        assert!(output
            .contains("policy_engine_processing_time_ns{direction=\"ingress\",quantile=\"0.5\"}"));
        assert!(output
            .contains("policy_engine_processing_time_ns{direction=\"ingress\",quantile=\"0.99\"}"));
        assert!(
            output.contains("policy_engine_processing_time_ns_count{direction=\"ingress\"} 1000")
        );
    }

    #[test]
    fn prometheus_formatter_ethertype_metrics() {
        let formatter = PrometheusFormatter;
        let snap = MetricsSnapshot {
            interfaces: vec![],
            rules: vec![],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![EthertypeMetrics {
                interface: "eth0".to_string(),
                direction: "ingress",
                ethertype: 2054,
                ethertype_name: "ARP",
                packets: 86239,
            }],
            uptime_secs: 0,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output.contains(
            "policy_engine_ethertype_packets_total{interface=\"eth0\",direction=\"ingress\",ethertype=\"2054\",ethertype_name=\"ARP\"} 86239"
        ));
    }

    #[test]
    fn prometheus_formatter_extra_global_stats() {
        let formatter = PrometheusFormatter;
        let snap = MetricsSnapshot {
            interfaces: vec![InterfaceMetrics {
                interface: "eth0".to_string(),
                direction: "ingress",
                stats: GlobalStats {
                    bum_packets: 91111,
                    policy_pass: 8927,
                    fib_forwarded_packets: 50,
                    fib_forwarded_bytes: 5000,
                    urpf_drop_packets: 77,
                    urpf_drop_bytes: 7000,
                    ..GlobalStats::default()
                },
            }],
            rules: vec![],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 0,
        };
        let output = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(output.contains(
            "policy_engine_bum_packets_total{interface=\"eth0\",direction=\"ingress\"} 91111"
        ));
        assert!(output.contains(
            "policy_engine_policy_pass_total{interface=\"eth0\",direction=\"ingress\"} 8927"
        ));
        assert!(output.contains(
            "policy_engine_fib_forwarded_packets_total{interface=\"eth0\",direction=\"ingress\"} 50"
        ));
        assert!(output.contains(
            "policy_engine_urpf_drop_packets_total{interface=\"eth0\",direction=\"ingress\"} 77"
        ));
    }

    #[test]
    fn trait_object_formatter_works() {
        let formatter: Arc<dyn MetricsFormatter> = Arc::new(PrometheusFormatter);
        let snap = MetricsSnapshot {
            interfaces: vec![],
            rules: vec![],
            protos: vec![],
            l3_protos: vec![],
            latencies: vec![],
            quic: vec![],
            ethertype_stats: vec![],
            uptime_secs: 99,
        };
        let out = String::from_utf8(formatter.format(&snap)).unwrap();
        assert!(out.contains("policy_engine_uptime_seconds 99"));
    }
}
