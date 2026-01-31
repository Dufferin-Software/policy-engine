//! Policy Engine CLI Client
//!
//! A command-line client that connects to a running policy-engine server
//! and manages XDP policies via GraphQL.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use prettytable::{format, row, Table};

use policy_engine::client::{ClientConfig, PolicyClient};
use policy_engine::shared_types::*;
use policy_engine::output::{format_bytes, format_packets};

#[derive(Parser)]
#[command(name = "policy-client")]
#[command(author, version, about = "CLI client for the XDP Policy Engine server")]
#[command(propagate_version = true)]
struct Cli {
    /// Server URL (default: http://127.0.0.1:8080/graphql)
    #[arg(short, long, global = true, default_value = "http://127.0.0.1:8080/graphql")]
    server: String,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get server status
    Status,

    /// Attach programs to interfaces
    Attach {
        #[command(subcommand)]
        command: AttachCommands,
    },

    /// Detach programs from interfaces
    Detach {
        #[command(subcommand)]
        command: DetachCommands,
    },

    /// Manage policy rules
    Rule {
        #[command(subcommand)]
        command: RuleCommands,
    },

    /// Show status and statistics
    Show {
        #[command(subcommand)]
        command: ShowCommands,
    },

    /// Configure global settings
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum AttachCommands {
    /// Attach XDP program to an interface
    Xdp {
        /// Interface name
        #[arg(short, long)]
        interface: String,

        /// XDP mode: auto (default), offload, native, or generic
        /// Auto tries offload → native → generic until one succeeds
        #[arg(short, long, default_value = "auto")]
        mode: String,
    },
}

#[derive(Subcommand)]
enum DetachCommands {
    /// Detach XDP program from an interface
    Xdp {
        /// Interface name
        #[arg(short, long)]
        interface: String,
    },

    /// Detach all programs
    All,
}

#[derive(Subcommand)]
enum RuleCommands {
    /// Add a new policy rule
    Add {
        /// Source IP/CIDR (e.g., 192.168.1.0/24 or 10.0.0.1). Defaults to 0.0.0.0/0 (any)
        #[arg(long)]
        src: Option<String>,

        /// Destination IP/CIDR (e.g., 192.168.1.0/24 or 10.0.0.1). Defaults to 0.0.0.0/0 (any)
        #[arg(long)]
        dst: Option<String>,

        /// Source port (0 for any)
        #[arg(long, default_value = "0")]
        sport: u16,

        /// Destination port (0 for any)
        #[arg(long, default_value = "0")]
        dport: u16,

        /// Protocol: tcp, udp, icmp, or any
        #[arg(long, default_value = "any")]
        proto: String,

        /// Action in format ACTION:PRIORITY (e.g., drop:0, log:1). Can be specified multiple times.
        #[arg(long = "action")]
        actions: Vec<String>,

        /// Rule ID (auto-generated if not specified)
        #[arg(long)]
        id: Option<u64>,

        /// Rule priority (lower = higher priority)
        #[arg(long, default_value = "1000")]
        priority: u32,

        /// Tail call slot (for tail-call action)
        #[arg(long)]
        tail_call_slot: Option<u32>,
    },

    /// Delete a policy rule
    Delete {
        /// Rule ID to delete
        #[arg(long)]
        id: Option<u64>,

        /// Source IP/CIDR (must match rule exactly)
        #[arg(long)]
        src: Option<String>,

        /// Destination IP/CIDR (must match rule exactly)
        #[arg(long)]
        dst: Option<String>,

        /// Source port (must match rule exactly)
        #[arg(long)]
        sport: Option<u16>,

        /// Destination port (must match rule exactly)
        #[arg(long)]
        dport: Option<u16>,

        /// Protocol (must match rule exactly)
        #[arg(long)]
        proto: Option<String>,
    },

    /// List all policy rules
    List {
        /// Output format: table, json
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Flush all rules
    Flush,
}

#[derive(Subcommand)]
enum ShowCommands {
    /// Show interface attachment status
    Interfaces,

    /// Show statistics for an interface
    Stats {
        /// Interface name
        #[arg(short, long)]
        interface: String,
    },

    /// Show all policy rules with match criteria and actions
    Rules,

    /// Show rule statistics (all rules if no ID specified)
    RuleStats {
        /// Rule ID (optional - shows all rules if not specified)
        #[arg(long)]
        id: Option<u64>,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Set default action for unmatched packets
    DefaultAction {
        /// Action: pass or drop
        #[arg(long)]
        action: String,
    },

    /// Register a tail call program
    TailCall {
        /// Slot number (0-63)
        #[arg(long)]
        slot: u32,

        /// Program name: rate_limiter, stats, logger
        #[arg(long)]
        program: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Create client
    let config = ClientConfig {
        server_url: cli.server,
    };
    let client = PolicyClient::with_config(config);

    // Handle commands
    match cli.command {
        Commands::Status => handle_status(&client),
        Commands::Attach { command } => handle_attach(&client, command),
        Commands::Detach { command } => handle_detach(&client, command),
        Commands::Rule { command } => handle_rule(&client, command),
        Commands::Show { command } => handle_show(&client, command),
        Commands::Config { command } => handle_config(&client, command),
    }
}

fn handle_status(client: &PolicyClient) -> Result<()> {
    let status = client.status()?;
    println!("Server Status:");
    println!("  Running: {}", status.running);
    println!("  Version: {}", status.version);
    println!("  Uptime: {} seconds", status.uptime_secs);
    Ok(())
}

fn handle_attach(client: &PolicyClient, cmd: AttachCommands) -> Result<()> {
    match cmd {
        AttachCommands::Xdp { interface, mode } => {
            let result = client.attach_xdp(&interface, &mode)?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }
    }
    Ok(())
}

fn handle_detach(client: &PolicyClient, cmd: DetachCommands) -> Result<()> {
    match cmd {
        DetachCommands::Xdp { interface } => {
            let result = client.detach_xdp(&interface)?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }
        DetachCommands::All => {
            let result = client.detach_all()?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }
    }
    Ok(())
}

fn handle_rule(client: &PolicyClient, cmd: RuleCommands) -> Result<()> {
    match cmd {
        RuleCommands::Add {
            src,
            dst,
            sport,
            dport,
            proto,
            actions,
            id,
            priority,
            tail_call_slot,
        } => {
            // Parse actions
            if actions.is_empty() {
                return Err(anyhow!("At least one action must be specified"));
            }

            let parsed_actions: Vec<ActionInput> = actions
                .iter()
                .map(|action_spec| {
                    let parts: Vec<&str> = action_spec.split(':').collect();
                    if parts.len() != 2 {
                        return Err(anyhow!(
                            "Action format should be ACTION:PRIORITY (e.g., drop:0), got: {}",
                            action_spec
                        ));
                    }

                    let action = match parts[0].to_lowercase().as_str() {
                        "pass" | "accept" | "allow" => GqlPolicyAction::Pass,
                        "drop" | "deny" | "reject" => GqlPolicyAction::Drop,
                        "log" => GqlPolicyAction::Log,
                        "tail-call" | "tailcall" => GqlPolicyAction::TailCall,
                        _ => return Err(anyhow!("Invalid action: {}", parts[0])),
                    };

                    let priority: u8 = parts[1]
                        .parse()
                        .map_err(|_| anyhow!("Invalid priority: {}", parts[1]))?;

                    Ok(ActionInput { action, priority })
                })
                .collect::<Result<Vec<_>>>()?;

            let input = AddRuleInput {
                src,
                dst,
                sport,
                dport,
                protocol: proto,
                actions: parsed_actions,
                id,
                priority,
                tail_call_slot,
            };

            let result = client.add_rule(input)?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }

        RuleCommands::Delete { id, src, dst, sport, dport, proto } => {
            let input = DeleteRuleInput { 
                id, 
                src, 
                dst,
                sport,
                dport,
                protocol: proto,
            };
            let result = client.delete_rule(input)?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }

        RuleCommands::List { format } => {
            let rules = client.list_rules()?;

            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&rules)?);
            } else {
                print_rules_table(&rules);
            }
        }

        RuleCommands::Flush => {
            let result = client.flush_rules()?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }
    }
    Ok(())
}

fn handle_show(client: &PolicyClient, cmd: ShowCommands) -> Result<()> {
    match cmd {
        ShowCommands::Interfaces => {
            let interfaces = client.list_interfaces()?;
            if interfaces.is_empty() {
                println!("No programs attached to any interfaces.");
            } else {
                println!("Attached XDP Programs:");
                println!("{}", "─".repeat(50));
                for iface in interfaces {
                    println!(
                        "  Interface: {} (ifindex={})",
                        iface.interface, iface.ifindex
                    );
                    println!("    Program: xdp_policy_main");
                    println!("    Mode: {}", iface.mode);
                    println!();
                }
            }
        }

        ShowCommands::Stats { interface } => {
            let stats = client.get_stats(&interface)?;
            
            // Check attachment status
            let interfaces = client.list_interfaces()?;
            let attachment = interfaces.iter().find(|i| i.interface == interface);
            
            println!("\nStatistics for {}:", interface);
            println!("{}", "─".repeat(50));
            
            // Show attachment status
            if let Some(attached) = attachment {
                println!("Status: \x1b[32m●\x1b[0m Attached (mode: {})", attached.mode);
            } else {
                println!("Status: \x1b[33m○\x1b[0m Not attached (showing cached stats)");
            }
            println!();

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
            policy_table.add_row(row!["BUM Packets", format_packets(stats.bum_packets)]);
            policy_table.add_row(row!["Non-IP Unicast", format_packets(stats.non_ip_unicast)]);
            policy_table.add_row(row!["Tail Calls", format_packets(stats.tail_calls)]);

            policy_table.printstd();

            // Show ethertype breakdown for non-IP traffic
            let ethertype_stats = client.get_ethertype_stats(&interface)?;
            if !ethertype_stats.is_empty() {
                println!("\nNon-IP Traffic by Ethertype:");
                let mut eth_table = Table::new();
                eth_table.set_format(*format::consts::FORMAT_BOX_CHARS);
                eth_table.add_row(row!["Ethertype", "Name", "Packets"]);
                for stat in ethertype_stats {
                    eth_table.add_row(row![
                        stat.ethertype_hex,
                        stat.name,
                        format_packets(stat.packets)
                    ]);
                }
                eth_table.printstd();
            }
        }

        ShowCommands::Rules => {
            let rules = client.list_rules()?;
            if rules.is_empty() {
                println!("No policy rules configured.");
            } else {
                println!("\nPolicy Rules ({} total):", rules.len());
                println!("{}", "─".repeat(80));

                for rule in &rules {
                    let ip_version = if rule.is_ipv6 { "IPv6" } else { "IPv4" };
                    println!("\nRule {} ({}):", rule.rule_id, ip_version);
                    println!("  Match:");
                    println!("    Source:      {}", rule.src_prefix);
                    println!("    Destination: {}", rule.dst_prefix);
                    let sport_str = if rule.sport == 0 { "Any".to_string() } else { rule.sport.to_string() };
                    let dport_str = if rule.dport == 0 { "Any".to_string() } else { rule.dport.to_string() };
                    println!("    Source Port: {}", sport_str);
                    println!("    Dest Port:   {}", dport_str);
                    println!("    Protocol:    {:?}", rule.protocol);
                    println!("    Priority:    {}", rule.priority);
                    println!("  Actions:");
                    for (i, action) in rule.actions.iter().enumerate() {
                        println!("    {}. {:?} (priority: {})", i + 1, action.action, action.priority);
                    }
                }
                println!();
            }
        }

        ShowCommands::RuleStats { id } => {
            match id {
                Some(rule_id) => {
                    // Show stats for specific rule
                    if let Some(stats) = client.get_rule_stats(rule_id)? {
                        println!("\nStatistics for Rule {}:", rule_id);
                        println!("{}", "─".repeat(40));
                        println!("  Packets: {}", format_packets(stats.packets));
                        println!("  Bytes: {}", format_bytes(stats.bytes));
                    } else {
                        println!("No statistics found for rule {}", rule_id);
                    }
                }
                None => {
                    // Show stats for all rules
                    let rules = client.list_rules()?;
                    if rules.is_empty() {
                        println!("No policy rules configured.");
                    } else {
                        println!("\nRule Statistics:");
                        println!("{}", "─".repeat(100));

                        let mut table = Table::new();
                        table.set_format(*format::consts::FORMAT_BOX_CHARS);
                        table.add_row(row!["Rule ID", "Src Prefix", "Dst Prefix", "Proto", "Sport", "Dport", "Packets", "Bytes"]);

                        for rule in &rules {
                            let sport_str = if rule.sport == 0 { "Any".to_string() } else { rule.sport.to_string() };
                            let dport_str = if rule.dport == 0 { "Any".to_string() } else { rule.dport.to_string() };
                            if let Some(stats) = client.get_rule_stats(rule.rule_id)? {
                                table.add_row(row![
                                    rule.rule_id,
                                    rule.src_prefix,
                                    rule.dst_prefix,
                                    format!("{:?}", rule.protocol),
                                    sport_str,
                                    dport_str,
                                    format_packets(stats.packets),
                                    format_bytes(stats.bytes)
                                ]);
                            } else {
                                table.add_row(row![
                                    rule.rule_id,
                                    rule.src_prefix,
                                    rule.dst_prefix,
                                    format!("{:?}", rule.protocol),
                                    sport_str,
                                    dport_str,
                                    "0",
                                    "0 B"
                                ]);
                            }
                        }

                        table.printstd();
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_config(client: &PolicyClient, cmd: ConfigCommands) -> Result<()> {
    match cmd {
        ConfigCommands::DefaultAction { action } => {
            let policy_action = match action.to_lowercase().as_str() {
                "pass" | "accept" | "allow" => GqlPolicyAction::Pass,
                "drop" | "deny" | "reject" => GqlPolicyAction::Drop,
                "log" => GqlPolicyAction::Log,
                "tail-call" | "tailcall" => GqlPolicyAction::TailCall,
                _ => return Err(anyhow!("Invalid action: {}", action)),
            };

            let result = client.set_default_action(policy_action)?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }

        ConfigCommands::TailCall { slot, program } => {
            let result = client.register_tail_call(slot, &program)?;
            if result.success {
                println!("✓ {}", result.message);
            } else {
                println!("✗ {}", result.message);
            }
        }
    }
    Ok(())
}

fn print_rules_table(rules: &[LpmRuleOutput]) {
    if rules.is_empty() {
        println!("No rules configured.");
        return;
    }

    println!("\nPolicy Rules:");
    println!("{}", "─".repeat(100));

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_BOX_CHARS);

    table.add_row(row![
        "ID", "Src", "Dst", "Proto", "Sport", "Dport", "Priority", "Actions"
    ]);

    for rule in rules {
        let actions_str: String = rule
            .actions
            .iter()
            .map(|a| format!("{:?}:{}", a.action, a.priority))
            .collect::<Vec<_>>()
            .join(", ");
        let sport_str = if rule.sport == 0 { "Any".to_string() } else { rule.sport.to_string() };
        let dport_str = if rule.dport == 0 { "Any".to_string() } else { rule.dport.to_string() };
        table.add_row(row![
            rule.rule_id,
            rule.src_prefix,
            rule.dst_prefix,
            format!("{:?}", rule.protocol),
            sport_str,
            dport_str,
            rule.priority,
            actions_str
        ]);
    }

    table.printstd();
}
