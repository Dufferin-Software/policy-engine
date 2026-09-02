// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Minimal Prometheus text exposition parser.
//!
//! Extracts individual counter values from raw Prometheus text by matching
//! metric name and a set of label key=value pairs.  Only the subset of the
//! format used by the policy-engine metrics endpoint is handled.

/// Extract a counter value from raw Prometheus exposition text.
///
/// Returns `None` when no line matches both the metric name and all of the
/// required labels, or when the matched value cannot be parsed as `u64`.
///
/// # Example
///
/// ```
/// let text = r#"
/// # TYPE policy_engine_rule_packets_total counter
/// policy_engine_rule_packets_total{rule_id="42",direction="ingress"} 100
/// "#;
/// let v = policy_controller::metrics_parser::parse_counter(
///     text,
///     "policy_engine_rule_packets_total",
///     &[("rule_id", "42"), ("direction", "ingress")],
/// );
/// assert_eq!(v, Some(100));
/// ```
pub fn parse_counter(text: &str, metric_name: &str, labels: &[(&str, &str)]) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // Expected format: name{labels} value [timestamp]
        let (name_part, value_part) = if let Some(brace) = line.find('{') {
            let close = line.find('}')?;
            let name = &line[..brace];
            let label_str = &line[brace + 1..close];
            let rest = line[close + 1..].trim();
            if name != metric_name {
                continue;
            }
            if !labels.iter().all(|(k, v)| label_matches(label_str, k, v)) {
                continue;
            }
            (name, rest)
        } else {
            // No labels at all
            let mut parts = line.splitn(2, ' ');
            let name = parts.next().unwrap_or("");
            if name != metric_name || !labels.is_empty() {
                continue;
            }
            (name, parts.next().unwrap_or(""))
        };
        let _ = name_part; // used for matching above
                           // value_part may be "123" or "123 <timestamp>"
        let value_str = value_part.split_whitespace().next().unwrap_or("");
        return value_str.parse::<u64>().ok();
    }
    None
}

/// Sum every counter line matching `metric_name`, regardless of its label set.
///
/// Used for fleet-wide rollups where per-label breakdowns (interface,
/// direction, …) are collapsed into a single total.  Lines whose value cannot
/// be parsed as `u64` are skipped.  Returns `0` when nothing matches.
pub fn sum_counter(text: &str, metric_name: &str) -> u64 {
    let mut total: u64 = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (name, value_part) = if let Some(brace) = line.find('{') {
            let Some(close) = line.find('}') else {
                continue;
            };
            (&line[..brace], line[close + 1..].trim())
        } else {
            let mut parts = line.splitn(2, ' ');
            (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
        };
        if name != metric_name {
            continue;
        }
        if let Some(v) = value_part
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok())
        {
            total = total.saturating_add(v);
        }
    }
    total
}

/// Rewrite every Prometheus data line to include `node_id` and optionally
/// `hostname` labels.
///
/// Comment lines (`# …`) and blank lines are passed through unchanged.
/// For lines that already have a label set (`{…}`), the new labels are
/// prepended inside the braces.  For label-less lines the label set is
/// synthesised before the value.
pub fn inject_node_label(text: &str, node_id: &str, hostname: Option<&str>) -> String {
    let mut out = String::with_capacity(text.len() + text.lines().count() * 64);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            out.push_str(line);
        } else if let Some(open) = line.find('{') {
            let close = line.find('}').unwrap_or(line.len());
            let existing = &line[open + 1..close];
            out.push_str(&line[..open + 1]); // up to and including '{'
            out.push_str("node_id=\"");
            out.push_str(node_id);
            out.push('"');
            if let Some(h) = hostname {
                out.push_str(",hostname=\"");
                out.push_str(h);
                out.push('"');
            }
            if !existing.is_empty() {
                out.push(',');
                out.push_str(existing);
            }
            out.push_str(&line[close..]); // from '}' onward
        } else if let Some(space) = line.find(' ') {
            // No label set: "metric_name value [timestamp]"
            out.push_str(&line[..space]);
            out.push_str("{node_id=\"");
            out.push_str(node_id);
            out.push('"');
            if let Some(h) = hostname {
                out.push_str(",hostname=\"");
                out.push_str(h);
                out.push('"');
            }
            out.push('}');
            out.push_str(&line[space..]);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// All global stats for one interface + direction parsed from Prometheus text.
#[derive(Default)]
pub struct InterfaceStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub policy_matches: u64,
    pub policy_drops: u64,
    pub policy_pass: u64,
    pub policy_redirects: u64,
    pub parse_errors: u64,
    pub tail_calls: u64,
    pub bum_packets: u64,
    pub non_ip_unicast: u64,
    pub inspect_redirects: u64,
    pub fragments: u64,
    pub verdict_pass_packets: u64,
    pub verdict_pass_bytes: u64,
    pub verdict_drop_packets: u64,
    pub verdict_drop_bytes: u64,
    pub fib_forwarded_packets: u64,
    pub fib_forwarded_bytes: u64,
    pub fib_fallback_packets: u64,
    pub urpf_drop_packets: u64,
    pub urpf_drop_bytes: u64,
}

/// Parse all global stats for the given interface + direction from Prometheus text.
pub fn parse_interface_stats(text: &str, interface: &str, direction: &str) -> InterfaceStats {
    let labels = &[("interface", interface), ("direction", direction)];
    let c = |name| parse_counter(text, name, labels).unwrap_or(0);
    let (packets_metric, bytes_metric) = if direction == "egress" {
        (
            "policy_engine_tx_packets_total",
            "policy_engine_tx_bytes_total",
        )
    } else {
        (
            "policy_engine_rx_packets_total",
            "policy_engine_rx_bytes_total",
        )
    };
    InterfaceStats {
        rx_packets: c(packets_metric),
        rx_bytes: c(bytes_metric),
        tx_packets: c("policy_engine_tx_packets_total"),
        tx_bytes: c("policy_engine_tx_bytes_total"),
        policy_matches: c("policy_engine_policy_matches_total"),
        policy_drops: c("policy_engine_policy_drops_total"),
        policy_pass: c("policy_engine_policy_pass_total"),
        policy_redirects: c("policy_engine_policy_redirects_total"),
        parse_errors: c("policy_engine_parse_errors_total"),
        tail_calls: c("policy_engine_tail_calls_total"),
        bum_packets: c("policy_engine_bum_packets_total"),
        non_ip_unicast: c("policy_engine_non_ip_unicast_total"),
        inspect_redirects: c("policy_engine_inspect_redirects_total"),
        fragments: c("policy_engine_fragments_total"),
        verdict_pass_packets: c("policy_engine_verdict_pass_packets_total"),
        verdict_pass_bytes: c("policy_engine_verdict_pass_bytes_total"),
        verdict_drop_packets: c("policy_engine_verdict_drop_packets_total"),
        verdict_drop_bytes: c("policy_engine_verdict_drop_bytes_total"),
        fib_forwarded_packets: c("policy_engine_fib_forwarded_packets_total"),
        fib_forwarded_bytes: c("policy_engine_fib_forwarded_bytes_total"),
        fib_fallback_packets: c("policy_engine_fib_fallback_packets_total"),
        urpf_drop_packets: c("policy_engine_urpf_drop_packets_total"),
        urpf_drop_bytes: c("policy_engine_urpf_drop_bytes_total"),
    }
}

/// One ethertype bucket parsed from Prometheus text.
pub struct EthertypeStat {
    pub ethertype: u32,
    pub ethertype_name: String,
    pub packets: u64,
}

/// Parse all ethertype counters for the given interface + direction.
pub fn parse_ethertype_stats(text: &str, interface: &str, direction: &str) -> Vec<EthertypeStat> {
    let metric = "policy_engine_ethertype_packets_total";
    let mut results = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some(brace_open) = line.find('{') else {
            continue;
        };
        let Some(brace_close) = line.find('}') else {
            continue;
        };
        let name = &line[..brace_open];
        if name != metric {
            continue;
        }
        let label_str = &line[brace_open + 1..brace_close];
        if !label_matches(label_str, "interface", interface) {
            continue;
        }
        if !label_matches(label_str, "direction", direction) {
            continue;
        }
        let value_str = line[brace_close + 1..]
            .split_whitespace()
            .next()
            .unwrap_or("");
        let Ok(packets) = value_str.parse::<u64>() else {
            continue;
        };
        let ethertype = extract_label(label_str, "ethertype")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let ethertype_name = extract_label(label_str, "ethertype_name")
            .unwrap_or("Unknown")
            .to_string();
        results.push(EthertypeStat {
            ethertype,
            ethertype_name,
            packets,
        });
    }
    results
}

/// Extract a single label value from a Prometheus label set string.
fn extract_label<'a>(label_str: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{}=\"", key);
    let start = label_str.find(&prefix)? + prefix.len();
    let end = label_str[start..].find('"')? + start;
    Some(&label_str[start..end])
}

fn label_matches(label_str: &str, key: &str, value: &str) -> bool {
    // Match key="value" anywhere in the label set.
    let pattern = format!("{}=\"{}\"", key, value);
    label_str.contains(&pattern)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# TYPE policy_engine_rx_packets_total counter
policy_engine_rx_packets_total{interface="eth0",direction="ingress"} 1000
# TYPE policy_engine_policy_drops_total counter
policy_engine_policy_drops_total{interface="eth0",direction="ingress"} 42
policy_engine_policy_drops_total{interface="eth1",direction="egress"} 7
# TYPE policy_engine_rule_packets_total counter
policy_engine_rule_packets_total{rule_id="1745000000000001",direction="ingress"} 99
policy_engine_rule_packets_total{rule_id="1745000000000002",direction="egress"} 3
# TYPE policy_engine_rule_bytes_total counter
policy_engine_rule_bytes_total{rule_id="1745000000000001",direction="ingress"} 8316
"#;

    #[test]
    fn test_parse_interface_drops() {
        let v = parse_counter(
            SAMPLE,
            "policy_engine_policy_drops_total",
            &[("interface", "eth0"), ("direction", "ingress")],
        );
        assert_eq!(v, Some(42));
    }

    #[test]
    fn test_parse_interface_drops_different_iface() {
        let v = parse_counter(
            SAMPLE,
            "policy_engine_policy_drops_total",
            &[("interface", "eth1"), ("direction", "egress")],
        );
        assert_eq!(v, Some(7));
    }

    #[test]
    fn test_parse_rule_packets() {
        let v = parse_counter(
            SAMPLE,
            "policy_engine_rule_packets_total",
            &[("rule_id", "1745000000000001"), ("direction", "ingress")],
        );
        assert_eq!(v, Some(99));
    }

    #[test]
    fn test_parse_rule_bytes() {
        let v = parse_counter(
            SAMPLE,
            "policy_engine_rule_bytes_total",
            &[("rule_id", "1745000000000001"), ("direction", "ingress")],
        );
        assert_eq!(v, Some(8316));
    }

    #[test]
    fn test_wrong_direction_returns_none() {
        let v = parse_counter(
            SAMPLE,
            "policy_engine_rule_packets_total",
            &[("rule_id", "1745000000000001"), ("direction", "egress")],
        );
        assert_eq!(v, None);
    }

    #[test]
    fn test_unknown_rule_returns_none() {
        let v = parse_counter(
            SAMPLE,
            "policy_engine_rule_packets_total",
            &[("rule_id", "9999999999999999"), ("direction", "ingress")],
        );
        assert_eq!(v, None);
    }

    #[test]
    fn test_unknown_metric_returns_none() {
        let v = parse_counter(SAMPLE, "no_such_metric", &[]);
        assert_eq!(v, None);
    }

    #[test]
    fn test_rx_packets() {
        let v = parse_counter(
            SAMPLE,
            "policy_engine_rx_packets_total",
            &[("interface", "eth0"), ("direction", "ingress")],
        );
        assert_eq!(v, Some(1000));
    }

    #[test]
    fn test_inject_node_label_with_existing_labels() {
        let input = "policy_engine_rule_packets_total{rule_id=\"42\",direction=\"ingress\"} 99\n";
        let out = inject_node_label(input, "node-abc", None);
        assert_eq!(
            out,
            "policy_engine_rule_packets_total{node_id=\"node-abc\",rule_id=\"42\",direction=\"ingress\"} 99\n"
        );
    }

    #[test]
    fn test_inject_node_label_no_existing_labels() {
        let input = "simple_counter 42\n";
        let out = inject_node_label(input, "n1", None);
        assert_eq!(out, "simple_counter{node_id=\"n1\"} 42\n");
    }

    #[test]
    fn test_inject_node_label_comment_passthrough() {
        let input = "# TYPE foo counter\nfoo{a=\"b\"} 1\n";
        let out = inject_node_label(input, "n1", None);
        assert_eq!(out, "# TYPE foo counter\nfoo{node_id=\"n1\",a=\"b\"} 1\n");
    }

    #[test]
    fn test_inject_node_label_empty_label_set() {
        let input = "metric{} 5\n";
        let out = inject_node_label(input, "n2", None);
        assert_eq!(out, "metric{node_id=\"n2\"} 5\n");
    }

    #[test]
    fn test_inject_node_label_with_hostname() {
        let input =
            "policy_engine_rx_packets_total{interface=\"eth0\",direction=\"ingress\"} 1000\n";
        let out = inject_node_label(input, "node-abc", Some("host1.example.com"));
        assert_eq!(
            out,
            "policy_engine_rx_packets_total{node_id=\"node-abc\",hostname=\"host1.example.com\",interface=\"eth0\",direction=\"ingress\"} 1000\n"
        );
    }

    #[test]
    fn test_inject_node_label_hostname_no_existing_labels() {
        let input = "simple_counter 42\n";
        let out = inject_node_label(input, "n1", Some("host1"));
        assert_eq!(
            out,
            "simple_counter{node_id=\"n1\",hostname=\"host1\"} 42\n"
        );
    }

    #[test]
    fn test_sum_counter_across_labels() {
        // Two interface/direction series for the same metric must be summed.
        assert_eq!(
            sum_counter(SAMPLE, "policy_engine_policy_drops_total"),
            42 + 7
        );
    }

    #[test]
    fn test_sum_counter_label_less() {
        let text = "simple_counter 5\nsimple_counter 7\n";
        assert_eq!(sum_counter(text, "simple_counter"), 12);
    }

    #[test]
    fn test_sum_counter_missing_is_zero() {
        assert_eq!(sum_counter(SAMPLE, "no_such_metric"), 0);
    }

    #[test]
    fn test_sum_counter_ignores_unparsable() {
        let text = "m{a=\"1\"} 10\nm{a=\"2\"} notanumber\nm{a=\"3\"} 5\n";
        assert_eq!(sum_counter(text, "m"), 15);
    }

    #[test]
    fn test_parse_interface_stats_ingress() {
        let text = r#"
policy_engine_rx_packets_total{interface="eth0",direction="ingress"} 1000
policy_engine_rx_bytes_total{interface="eth0",direction="ingress"} 100000
policy_engine_policy_drops_total{interface="eth0",direction="ingress"} 42
policy_engine_policy_pass_total{interface="eth0",direction="ingress"} 950
policy_engine_bum_packets_total{interface="eth0",direction="ingress"} 8
policy_engine_fib_forwarded_packets_total{interface="eth0",direction="ingress"} 15
"#;
        let s = parse_interface_stats(text, "eth0", "ingress");
        assert_eq!(s.rx_packets, 1000);
        assert_eq!(s.rx_bytes, 100000);
        assert_eq!(s.policy_drops, 42);
        assert_eq!(s.policy_pass, 950);
        assert_eq!(s.bum_packets, 8);
        assert_eq!(s.fib_forwarded_packets, 15);
        assert_eq!(s.parse_errors, 0);
    }

    #[test]
    fn test_parse_ethertype_stats() {
        let text = r#"
policy_engine_ethertype_packets_total{interface="eth0",direction="ingress",ethertype="2054",ethertype_name="ARP"} 86239
policy_engine_ethertype_packets_total{interface="eth0",direction="ingress",ethertype="34525",ethertype_name="IPv6"} 1234
policy_engine_ethertype_packets_total{interface="eth0",direction="egress",ethertype="2054",ethertype_name="ARP"} 5
"#;
        let entries = parse_ethertype_stats(text, "eth0", "ingress");
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.ethertype == 2054 && e.packets == 86239 && e.ethertype_name == "ARP"));
        assert!(entries
            .iter()
            .any(|e| e.ethertype == 34525 && e.packets == 1234));
        // egress entry must not appear
        assert!(!entries.iter().any(|e| e.packets == 5));
    }

    #[test]
    fn test_parse_ethertype_stats_empty() {
        let entries = parse_ethertype_stats(SAMPLE, "eth0", "ingress");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_inject_node_label_full_sample() {
        let out = inject_node_label(SAMPLE, "node-xyz", None);
        assert!(out.contains("node_id=\"node-xyz\""));
        // Comments must not be modified.
        assert!(out.contains("# TYPE policy_engine_rx_packets_total counter"));
        // parse_counter should still work on the injected output.
        let v = parse_counter(
            &out,
            "policy_engine_rule_packets_total",
            &[
                ("node_id", "node-xyz"),
                ("rule_id", "1745000000000001"),
                ("direction", "ingress"),
            ],
        );
        assert_eq!(v, Some(99));
    }
}
