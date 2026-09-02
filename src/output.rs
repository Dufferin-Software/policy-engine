// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Output formatting utilities

use crate::types::*;
use prettytable::{format, row, Table};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Format bytes to human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format packet count
pub fn format_packets(packets: u64) -> String {
    if packets >= 1_000_000_000 {
        format!("{:.2}G", packets as f64 / 1_000_000_000.0)
    } else if packets >= 1_000_000 {
        format!("{:.2}M", packets as f64 / 1_000_000.0)
    } else if packets >= 1_000 {
        format!("{:.2}K", packets as f64 / 1_000.0)
    } else {
        format!("{}", packets)
    }
}

/// Format nanosecond timestamp to human-readable duration
pub fn format_timestamp_ns(ns: u64) -> String {
    if ns == 0 {
        return "never".to_string();
    }

    // Get current monotonic time (approximation)
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    if ns > now_ns {
        return "future?".to_string();
    }

    let elapsed_ns = now_ns.saturating_sub(ns);
    let elapsed = Duration::from_nanos(elapsed_ns);

    if elapsed.as_secs() < 60 {
        format!("{}s ago", elapsed.as_secs())
    } else if elapsed.as_secs() < 3600 {
        format!("{}m ago", elapsed.as_secs() / 60)
    } else if elapsed.as_secs() < 86400 {
        format!("{}h ago", elapsed.as_secs() / 3600)
    } else {
        format!("{}d ago", elapsed.as_secs() / 86400)
    }
}

/// Print global statistics
pub fn print_stats(ifname: &str, stats: &GlobalStats) {
    println!("\nStatistics for {}:", ifname);
    println!("{}", "─".repeat(50));

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_BOX_CHARS);

    table.add_row(row!["Metric", "RX", "TX"]);
    table.add_row(row![
        "Packets",
        format_packets(stats.rx_packets),
        format_packets(stats.tx_packets)
    ]);
    table.add_row(row![
        "Bytes",
        format_bytes(stats.rx_bytes),
        format_bytes(stats.tx_bytes)
    ]);

    table.printstd();

    println!("\nPolicy Statistics:");
    let mut policy_table = Table::new();
    policy_table.set_format(*format::consts::FORMAT_BOX_CHARS);

    policy_table.add_row(row!["Metric", "Count"]);
    policy_table.add_row(row!["Policy Matches", format_packets(stats.policy_matches)]);
    policy_table.add_row(row!["Policy Pass", format_packets(stats.policy_pass)]);
    policy_table.add_row(row!["Policy Drops", format_packets(stats.policy_drops)]);
    policy_table.add_row(row![
        "Policy Redirects",
        format_packets(stats.policy_redirects)
    ]);
    policy_table.add_row(row!["Parse Errors", format_packets(stats.parse_errors)]);
    policy_table.add_row(row!["Fragments", format_packets(stats.fragments)]);
    policy_table.add_row(row!["Tail Calls", format_packets(stats.tail_calls)]);

    policy_table.printstd();
}

/// Print rule statistics
pub fn print_rule_stats(rule_id: u64, stats: &RuleStats) {
    println!("\nStatistics for Rule {}:", rule_id);
    println!("{}", "─".repeat(40));

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_BOX_CHARS);

    table.add_row(row!["Metric", "Value"]);
    table.add_row(row!["Packets", format_packets(stats.packets)]);
    table.add_row(row!["Bytes", format_bytes(stats.bytes)]);
    table.add_row(row!["Last Seen", format_timestamp_ns(stats.last_seen_ns)]);

    table.printstd();
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_bytes ─────────────────────────────────────────────────────────

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn format_bytes_below_kb() {
        assert_eq!(format_bytes(1), "1 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kb() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        // 512 KB
        assert_eq!(format_bytes(512 * 1024), "512.00 KB");
    }

    #[test]
    fn format_bytes_mb() {
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 10), "10.00 MB");
    }

    #[test]
    fn format_bytes_gb() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB");
    }

    #[test]
    fn format_bytes_tb() {
        assert_eq!(format_bytes(1024u64 * 1024 * 1024 * 1024), "1.00 TB");
        assert_eq!(format_bytes(1024u64 * 1024 * 1024 * 1024 * 5), "5.00 TB");
    }

    // ── format_packets ───────────────────────────────────────────────────────

    #[test]
    fn format_packets_zero() {
        assert_eq!(format_packets(0), "0");
    }

    #[test]
    fn format_packets_below_k() {
        assert_eq!(format_packets(1), "1");
        assert_eq!(format_packets(999), "999");
    }

    #[test]
    fn format_packets_k() {
        assert_eq!(format_packets(1_000), "1.00K");
        assert_eq!(format_packets(5_500), "5.50K");
    }

    #[test]
    fn format_packets_m() {
        assert_eq!(format_packets(1_000_000), "1.00M");
        assert_eq!(format_packets(2_500_000), "2.50M");
    }

    #[test]
    fn format_packets_g() {
        assert_eq!(format_packets(1_000_000_000), "1.00G");
        assert_eq!(format_packets(3_000_000_000), "3.00G");
    }

    // ── format_timestamp_ns ──────────────────────────────────────────────────

    #[test]
    fn format_timestamp_ns_zero_is_never() {
        assert_eq!(format_timestamp_ns(0), "never");
    }

    #[test]
    fn format_timestamp_ns_future() {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let ts = now_ns + 10_000_000_000_000; // well in the future
        assert_eq!(format_timestamp_ns(ts), "future?");
    }

    #[test]
    fn format_timestamp_ns_seconds_ago() {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let ts = now_ns.saturating_sub(10 * 1_000_000_000); // 10s ago
        let result = format_timestamp_ns(ts);
        assert!(result.ends_with("s ago"), "got: {}", result);
    }

    #[test]
    fn format_timestamp_ns_minutes_ago() {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let ts = now_ns.saturating_sub(5 * 60 * 1_000_000_000); // 5 min ago
        let result = format_timestamp_ns(ts);
        assert!(result.ends_with("m ago"), "got: {}", result);
    }

    #[test]
    fn format_timestamp_ns_hours_ago() {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let ts = now_ns.saturating_sub(2 * 3600 * 1_000_000_000); // 2h ago
        let result = format_timestamp_ns(ts);
        assert!(result.ends_with("h ago"), "got: {}", result);
    }

    #[test]
    fn format_timestamp_ns_days_ago() {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let ts = now_ns.saturating_sub(2 * 86400 * 1_000_000_000); // 2d ago
        let result = format_timestamp_ns(ts);
        assert!(result.ends_with("d ago"), "got: {}", result);
    }
}
