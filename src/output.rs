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
    policy_table.add_row(row!["Policy Redirects", format_packets(stats.policy_redirects)]);
    policy_table.add_row(row!["Parse Errors", format_packets(stats.parse_errors)]);
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

/// Print policy rules as a table
pub fn print_rules_table(rules: &[(FlowKey, PolicyValue)]) {
    if rules.is_empty() {
        println!("No policy rules configured.");
        return;
    }

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_BOX_CHARS);

    table.add_row(row![
        "ID",
        "Priority",
        "Source",
        "Destination",
        "Proto",
        "Action",
        "Flags"
    ]);

    for (key, value) in rules {
        let src = format_flow_addr(key, true);
        let dst = format_flow_addr(key, false);
        let proto = format_protocol(key.protocol);
        // Get the first action from the embedded actions list
        let action = if value.num_actions > 0 {
            PolicyAction::from(value.actions[0].action)
        } else {
            PolicyAction::Pass
        };
        let flags = format_flags(value.flags);
        // Copy values from packed struct to avoid unaligned references
        let rule_id = value.rule_id;
        let priority = value.priority;

        table.add_row(row![
            rule_id,
            priority,
            src,
            dst,
            proto,
            action,
            flags
        ]);
    }

    table.printstd();
    println!("\nTotal rules: {}", rules.len());
}

/// Print policy rules as JSON
pub fn print_rules_json(rules: &[(FlowKey, PolicyValue)]) {
    #[derive(serde::Serialize)]
    struct RuleJson {
        rule_id: u64,
        priority: u32,
        src_addr: String,
        dst_addr: String,
        src_port: u16,
        dst_port: u16,
        protocol: String,
        action: String,
        flags: Vec<String>,
    }

    let json_rules: Vec<RuleJson> = rules
        .iter()
        .map(|(key, value)| {
            let action = if value.num_actions > 0 {
                PolicyAction::from(value.actions[0].action).to_string()
            } else {
                PolicyAction::Pass.to_string()
            };
            RuleJson {
                rule_id: value.rule_id,
                priority: value.priority,
                src_addr: format_flow_addr(key, true),
                dst_addr: format_flow_addr(key, false),
                src_port: key.sport,
                dst_port: key.dport,
                protocol: format_protocol(key.protocol),
                action,
                flags: format_flags_vec(value.flags),
            }
        })
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&json_rules).unwrap_or_else(|_| "[]".to_string())
    );
}

/// Format flow address
fn format_flow_addr(key: &FlowKey, is_src: bool) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let (addr, port) = if is_src {
        (&key.saddr, key.sport)
    } else {
        (&key.daddr, key.dport)
    };

    let ip_str = if key.af == AF_INET {
        let octets: [u8; 4] = addr[..4].try_into().unwrap();
        let ip = Ipv4Addr::from(octets);
        if ip.is_unspecified() {
            "*".to_string()
        } else {
            ip.to_string()
        }
    } else {
        let octets: [u8; 16] = *addr;
        let ip = Ipv6Addr::from(octets);
        if ip.is_unspecified() {
            "*".to_string()
        } else {
            ip.to_string()
        }
    };

    if port == 0 {
        format!("{}:*", ip_str)
    } else {
        format!("{}:{}", ip_str, port)
    }
}

/// Format protocol number
fn format_protocol(proto: u8) -> String {
    match proto {
        0 => "any".to_string(),
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        _ => format!("{}", proto),
    }
}

/// Format flags as string
fn format_flags(flags: u32) -> String {
    let mut parts = Vec::new();

    if flags & flags::POLICY_FLAG_ENABLED != 0 {
        parts.push("E");
    }
    if flags & flags::POLICY_FLAG_LOG != 0 {
        parts.push("L");
    }
    if flags & flags::POLICY_FLAG_BIDIRECTIONAL != 0 {
        parts.push("B");
    }
    if flags & flags::POLICY_FLAG_CONNTRACK != 0 {
        parts.push("C");
    }

    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join("")
    }
}

/// Format flags as vector of strings
fn format_flags_vec(flags: u32) -> Vec<String> {
    let mut parts = Vec::new();

    if flags & flags::POLICY_FLAG_ENABLED != 0 {
        parts.push("enabled".to_string());
    }
    if flags & flags::POLICY_FLAG_LOG != 0 {
        parts.push("log".to_string());
    }
    if flags & flags::POLICY_FLAG_BIDIRECTIONAL != 0 {
        parts.push("bidirectional".to_string());
    }
    if flags & flags::POLICY_FLAG_CONNTRACK != 0 {
        parts.push("conntrack".to_string());
    }

    parts
}

/// Print LPM policy rules as a table
pub fn print_lpm_rules_table(
    v4_rules: &[(LpmKeyV4, LpmPolicyEntry)],
    v6_rules: &[(LpmKeyV6, LpmPolicyEntry)],
) {
    let total = v4_rules.len() + v6_rules.len();
    if total == 0 {
        println!("No LPM policy rules configured.");
        return;
    }

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_BOX_CHARS);

    table.add_row(row![
        "ID",
        "Priority",
        "Source CIDR",
        "Dest CIDR",
        "Ports",
        "Proto",
        "Action",
        "Flags"
    ]);

    // IPv4 rules
    for (key, entry) in v4_rules {
        let src_cidr = format_lpm_key_v4(key);
        let dst_cidr = format_lpm_entry_dst_v4(entry);
        let ports = format_ports(entry.sport, entry.dport);
        let proto = format_protocol(entry.protocol);
        let action = if entry.num_actions > 0 {
            PolicyAction::from(entry.actions[0].action)
        } else {
            PolicyAction::Pass
        };
        let flags = format_flags(entry.flags);
        // Copy values from packed struct to avoid unaligned references
        let rule_id = entry.rule_id;
        let priority = entry.priority;

        table.add_row(row![
            rule_id,
            priority,
            src_cidr,
            dst_cidr,
            ports,
            proto,
            action,
            flags
        ]);
    }

    // IPv6 rules
    for (key, entry) in v6_rules {
        let src_cidr = format_lpm_key_v6(key);
        let dst_cidr = format_lpm_entry_dst_v6(entry);
        let ports = format_ports(entry.sport, entry.dport);
        let proto = format_protocol(entry.protocol);
        let action = if entry.num_actions > 0 {
            PolicyAction::from(entry.actions[0].action)
        } else {
            PolicyAction::Pass
        };
        let flags = format_flags(entry.flags);
        // Copy values from packed struct to avoid unaligned references
        let rule_id = entry.rule_id;
        let priority = entry.priority;

        table.add_row(row![
            rule_id,
            priority,
            src_cidr,
            dst_cidr,
            ports,
            proto,
            action,
            flags
        ]);
    }

    table.printstd();
    println!("\nTotal LPM rules: {} (IPv4: {}, IPv6: {})", total, v4_rules.len(), v6_rules.len());
}

/// Print LPM policy rules as JSON
pub fn print_lpm_rules_json(
    v4_rules: &[(LpmKeyV4, LpmPolicyEntry)],
    v6_rules: &[(LpmKeyV6, LpmPolicyEntry)],
) {
    #[derive(serde::Serialize)]
    struct LpmRuleJson {
        rule_id: u64,
        priority: u32,
        src_cidr: String,
        dst_cidr: String,
        src_port: u16,
        dst_port: u16,
        protocol: String,
        action: String,
        flags: Vec<String>,
        address_family: String,
    }

    let mut json_rules: Vec<LpmRuleJson> = Vec::new();

    // IPv4 rules
    for (key, entry) in v4_rules {
        let action = if entry.num_actions > 0 {
            PolicyAction::from(entry.actions[0].action).to_string()
        } else {
            PolicyAction::Pass.to_string()
        };
        json_rules.push(LpmRuleJson {
            rule_id: entry.rule_id,
            priority: entry.priority,
            src_cidr: format_lpm_key_v4(key),
            dst_cidr: format_lpm_entry_dst_v4(entry),
            src_port: entry.sport,
            dst_port: entry.dport,
            protocol: format_protocol(entry.protocol),
            action,
            flags: format_flags_vec(entry.flags),
            address_family: "ipv4".to_string(),
        });
    }

    // IPv6 rules
    for (key, entry) in v6_rules {
        let action = if entry.num_actions > 0 {
            PolicyAction::from(entry.actions[0].action).to_string()
        } else {
            PolicyAction::Pass.to_string()
        };
        json_rules.push(LpmRuleJson {
            rule_id: entry.rule_id,
            priority: entry.priority,
            src_cidr: format_lpm_key_v6(key),
            dst_cidr: format_lpm_entry_dst_v6(entry),
            src_port: entry.sport,
            dst_port: entry.dport,
            protocol: format_protocol(entry.protocol),
            action,
            flags: format_flags_vec(entry.flags),
            address_family: "ipv6".to_string(),
        });
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json_rules).unwrap_or_else(|_| "[]".to_string())
    );
}

/// Format LPM key (IPv4)
fn format_lpm_key_v4(key: &LpmKeyV4) -> String {
    use std::net::Ipv4Addr;
    let prefixlen = key.prefixlen;
    let addr = Ipv4Addr::from(u32::from_be(key.addr));
    if prefixlen == 0 && addr.is_unspecified() {
        "any".to_string()
    } else {
        format!("{}/{}", addr, prefixlen)
    }
}

/// Format LPM key (IPv6)
fn format_lpm_key_v6(key: &LpmKeyV6) -> String {
    use std::net::Ipv6Addr;
    let prefixlen = key.prefixlen;
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let bytes = u32::to_be_bytes(key.addr[i]);
        octets[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    let addr = Ipv6Addr::from(octets);
    if prefixlen == 0 && addr.is_unspecified() {
        "any".to_string()
    } else {
        format!("{}/{}", addr, prefixlen)
    }
}

/// Format LPM entry destination (IPv4)
fn format_lpm_entry_dst_v4(entry: &LpmPolicyEntry) -> String {
    use std::net::Ipv4Addr;
    let octets: [u8; 4] = entry.daddr[..4].try_into().unwrap_or([0; 4]);
    let addr = Ipv4Addr::from(octets);
    let prefixlen = entry.dst_prefixlen;
    if prefixlen == 0 && addr.is_unspecified() {
        "any".to_string()
    } else {
        format!("{}/{}", addr, prefixlen)
    }
}

/// Format LPM entry destination (IPv6)
fn format_lpm_entry_dst_v6(entry: &LpmPolicyEntry) -> String {
    use std::net::Ipv6Addr;
    let addr = Ipv6Addr::from(entry.daddr);
    let prefixlen = entry.dst_prefixlen;
    if prefixlen == 0 && addr.is_unspecified() {
        "any".to_string()
    } else {
        format!("{}/{}", addr, prefixlen)
    }
}

/// Format ports for display
fn format_ports(sport: u16, dport: u16) -> String {
    let s = if sport == 0 { "*".to_string() } else { sport.to_string() };
    let d = if dport == 0 { "*".to_string() } else { dport.to_string() };
    format!("{}:{}", s, d)
}
