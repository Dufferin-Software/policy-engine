// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Policy Engine CLI Client
//!
//! A command-line client that connects to a running policy-engine server
//! and manages policies via GraphQL.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use prettytable::{format, row, Table};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;

use policy_engine_dev::output::{format_bytes, format_packets};
use policy_engine_dev::types::*;
use policy_engine_dev::{ClientConfig, PolicyClient};

#[derive(Parser)]
#[command(name = "policy-client")]
#[command(author, version, about = "CLI client for the Policy Engine server")]
#[command(propagate_version = true)]
struct Cli {
    /// Server URL (default: http://127.0.0.1:8080/graphql)
    #[arg(
        short,
        long,
        global = true,
        default_value = "http://127.0.0.1:8080/graphql"
    )]
    server: String,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output in JSON format
    #[arg(short, long, global = true)]
    json: bool,

    /// Path to a PEM-encoded CA certificate to trust (for self-signed server certs)
    #[arg(long, global = true)]
    tls_ca_cert: Option<String>,

    /// Skip TLS certificate verification — insecure, use only in development
    #[arg(long, global = true)]
    tls_insecure: bool,

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
        command: Box<RuleCommands>,
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

    /// Clear statistics
    ClearStats {
        #[command(subcommand)]
        command: ClearStatsCommands,
    },

    /// Inspect/IPS management (requires IPS/IDS server)
    Inspect {
        #[command(subcommand)]
        command: InspectCommand,
    },
    /// Suricata service management (requires IPS/IDS server)
    Suricata {
        #[command(subcommand)]
        command: SuricataCommand,
    },
}

#[derive(Subcommand)]
enum InspectCommand {
    /// Show inspect/IPS status
    Status,
    /// Enable inspect mode
    Enable {
        /// Inspect mode: ips (block matching flows) or ids (alert only)
        #[arg(long, default_value = "ips")]
        mode: String,
    },
    /// Disable inspect mode
    Disable,
    /// Show flow verdicts
    Verdicts {
        /// Direction
        #[arg(long, default_value = "ingress")]
        direction: String,
    },
    /// Clear flow verdicts
    ClearVerdicts {
        /// Direction
        #[arg(long, default_value = "ingress")]
        direction: String,
    },
}

#[derive(Subcommand)]
enum SuricataCommand {
    /// Show Suricata service status
    Status,
    /// Deploy rules to Suricata
    DeployRules {
        /// Rules file path
        #[arg(long)]
        file: String,
        /// Target filename in Suricata rules dir
        #[arg(long, default_value = "custom.rules")]
        name: String,
    },
    /// Reload Suricata rules
    Reload,
}

#[derive(Subcommand)]
enum AttachCommands {
    /// Attach ingress program to an interface
    Ingress {
        /// Interface name
        #[arg(short, long)]
        interface: String,

        /// Ingress mode: auto (default), offload, native, or generic
        /// Auto tries offload → native → generic until one succeeds
        #[arg(short, long, default_value = "auto")]
        mode: String,
    },

    /// Attach egress program to an interface
    Egress {
        /// Interface name
        #[arg(short, long)]
        interface: String,
    },
}

#[derive(Subcommand)]
enum DetachCommands {
    /// Detach ingress program from an interface
    Ingress {
        /// Interface name
        #[arg(short, long)]
        interface: String,
    },

    /// Detach egress program from an interface
    Egress {
        /// Interface name
        #[arg(short, long)]
        interface: String,
    },

    /// Detach all programs (both ingress and egress)
    All,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum RuleCommands {
    /// Add a new policy rule
    Add {
        /// Network interface the rule applies to (e.g., eth0, enp1s0)
        #[arg(long)]
        interface: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

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

        /// TLS SNI pattern to match (e.g., "example.com" or "*.example.com")
        #[arg(long)]
        sni: Option<String>,

        /// QUIC version filter: any, v1 (RFC 9000), v2 (RFC 9369)
        #[arg(long)]
        quic_version: Option<String>,

        /// Source MAC address filter (e.g., aa:bb:cc:dd:ee:ff)
        #[arg(long)]
        src_mac: Option<String>,

        /// Destination MAC address filter (e.g., aa:bb:cc:dd:ee:ff)
        #[arg(long)]
        dst_mac: Option<String>,

        /// Auto-remove rule after N seconds. Mutually exclusive with --schedule-window.
        #[arg(long)]
        expires_after_secs: Option<u32>,

        /// IANA timezone for schedule windows (default: UTC).
        /// Only used when --schedule-window is specified.
        #[arg(long, default_value = "UTC")]
        schedule_tz: String,

        /// Schedule window in DAY:HH:MM-DAY:HH:MM format where DAY is 0 (Sun) to 6 (Sat).
        /// Can be specified multiple times. Mutually exclusive with --expires-after-secs.
        /// Example: --schedule-window 0:00:00-5:00:00  (Sun midnight to Fri midnight)
        #[arg(long = "schedule-window")]
        schedule_windows: Vec<String>,
    },

    /// Delete a policy rule
    Delete {
        /// Network interface the rule is scoped to
        #[arg(long)]
        interface: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

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
        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

        /// Filter results to rules on this interface (optional)
        #[arg(long)]
        interface: Option<String>,

        /// Output format: table
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Flush all rules scoped to a specific interface+direction.
    Flush {
        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

        /// Interface to flush rules on
        #[arg(long)]
        interface: String,
    },

    /// List rules that have TTL or schedule constraints (managed rules)
    ManagedRules {
        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

        /// Filter results to rules on this interface (optional)
        #[arg(long)]
        interface: Option<String>,
    },
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

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,
    },

    /// Show all policy rules with match criteria and actions
    Rules {
        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

        /// Filter by interface name (optional)
        #[arg(long)]
        interface: Option<String>,
    },

    /// Show rule statistics (all rules if no ID specified)
    RuleStats {
        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

        /// Rule ID (optional - shows all rules if not specified)
        #[arg(long)]
        id: Option<u64>,

        /// Filter by interface name (optional)
        #[arg(long)]
        interface: Option<String>,
    },

    /// Show current default action for unmatched packets on an interface
    DefaultAction {
        /// Interface name
        #[arg(long)]
        interface: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,
    },

    /// Show server feature capabilities
    Features,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Set default action for unmatched packets on a specific interface
    DefaultAction {
        /// Interface name
        #[arg(long)]
        interface: String,

        /// Action: pass or drop
        #[arg(long)]
        action: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,
    },

    /// Register a tail call program
    TailCall {
        /// Slot number (0-63)
        #[arg(long)]
        slot: u32,

        /// Program name: rate_limiter, stats, logger
        #[arg(long)]
        program: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,
    },

    /// Enable or disable FIB forwarding ("XDP forward mode") on an interface.
    /// Ingress-only (XDP) feature.
    FibForwarding {
        /// Interface name
        #[arg(long)]
        interface: String,

        /// Enable (true) or disable (false) FIB forwarding
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },

    /// Set the uRPF (unicast Reverse Path Forwarding) mode on an interface.
    /// Ingress-only (XDP) feature.
    Urpf {
        /// Interface name
        #[arg(long)]
        interface: String,

        /// uRPF mode: off, loose, or strict
        #[arg(long)]
        mode: String,
    },
}

#[derive(Subcommand)]
enum ClearStatsCommands {
    /// Clear only the global packet/byte counters for an interface (rx, tx, policy
    /// matches/drops/pass, parse errors, tail calls, etc.). Does NOT clear ethertype
    /// or rule statistics. Use 'interface' to clear everything at once.
    Global {
        /// Interface name
        #[arg(short, long)]
        interface: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,
    },

    /// Clear ALL statistics for an interface: global counters AND ethertype stats.
    /// This is a superset of 'global' — use it when you want a complete stats reset
    /// for an interface. Rule statistics are cleared separately with 'rule'.
    Interface {
        /// Interface name
        #[arg(short, long)]
        interface: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,
    },

    /// Clear rule statistics
    Rule {
        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,

        /// Rule ID (clears all rules if not specified)
        #[arg(long)]
        id: Option<u64>,
    },

    /// Clear ethertype statistics for an interface
    Ethertype {
        /// Interface name
        #[arg(short, long)]
        interface: String,

        /// Traffic direction: ingress or egress
        #[arg(long)]
        direction: String,
    },

    /// Clear all statistics
    All,
}

/// Check if --json flag is present in command line args.
/// We need to check this before parsing because clap errors happen during parsing.
fn has_json_flag() -> bool {
    std::env::args().any(|arg| arg == "--json" || arg == "-j")
}

/// Format a clap error as JSON
fn format_clap_error_as_json(err: &clap::Error) -> String {
    // Extract the error message, removing ANSI codes and extra formatting
    let raw_message = err.to_string();
    // Take just the first line which contains the actual error
    let message = raw_message
        .lines()
        .next()
        .unwrap_or(&raw_message)
        .trim()
        .to_string();

    let error_json = json!({
        "success": false,
        "message": message,
        "error_kind": format!("{:?}", err.kind())
    });

    serde_json::to_string_pretty(&error_json)
        .unwrap_or_else(|_| format!(r#"{{"success": false, "message": "{}"}}"#, message))
}

fn main() -> Result<()> {
    // Check for --json flag before parsing (so we can format parse errors as JSON)
    let json_requested = has_json_flag();

    // Try to parse CLI args, handling errors with JSON if requested
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if json_requested {
                // Format error as JSON and exit
                println!("{}", format_clap_error_as_json(&err));
                std::process::exit(
                    if err.kind() == clap::error::ErrorKind::DisplayHelp
                        || err.kind() == clap::error::ErrorKind::DisplayVersion
                    {
                        0
                    } else {
                        2
                    },
                );
            } else {
                // Let clap handle the error normally (with colors, help, etc.)
                err.exit();
            }
        }
    };

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp(None)
        .init();

    // Create client
    let config = ClientConfig {
        server_url: cli.server,
        tls_ca_cert: cli.tls_ca_cert,
        danger_accept_invalid_certs: cli.tls_insecure,
    };
    let client = PolicyClient::with_config(config);
    let json_output = cli.json;

    // Handle commands
    match cli.command {
        Commands::Status => handle_status(&client, json_output),
        Commands::Attach { command } => handle_attach(&client, command, json_output),
        Commands::Detach { command } => handle_detach(&client, command, json_output),
        Commands::Rule { command } => handle_rule(&client, *command, json_output),
        Commands::Show { command } => handle_show(&client, command, json_output),
        Commands::Config { command } => handle_config(&client, command, json_output),
        Commands::ClearStats { command } => handle_clear_stats(&client, command, json_output),
        Commands::Inspect { command } => handle_inspect(&client, command, json_output),
        Commands::Suricata { command } => handle_suricata(&client, command, json_output),
    }
}

/// Helper to print JSON output
fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Helper to print operation result (success/failure message)
fn print_result(result: &OperationResult, json_output: bool) -> Result<()> {
    if json_output {
        print_json(result)
    } else {
        if result.success {
            println!("✓ {}", result.message);
        } else {
            println!("✗ {}", result.message);
        }
        Ok(())
    }
}

/// Helper to handle operations that return Result<OperationResult>
/// When json_output is true, errors are converted to JSON error responses
/// When json_output is false, errors propagate normally
fn handle_operation<F>(operation: F, json_output: bool) -> Result<()>
where
    F: FnOnce() -> Result<OperationResult>,
{
    match operation() {
        Ok(result) => print_result(&result, json_output),
        Err(e) => {
            if json_output {
                let error_result = OperationResult {
                    success: false,
                    message: e.to_string(),
                };
                print_result(&error_result, json_output)
            } else {
                Err(e)
            }
        }
    }
}

/// Helper to handle errors for generic operations when json_output is true
/// Returns Ok(Some(value)) on success, Ok(None) if error was handled as JSON, or Err if error should propagate
fn try_operation_json<T, F>(operation: F, json_output: bool) -> Result<Option<T>>
where
    F: FnOnce() -> Result<T>,
{
    match operation() {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            if json_output {
                let error_result = OperationResult {
                    success: false,
                    message: e.to_string(),
                };
                print_result(&error_result, json_output)?;
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

fn handle_status(client: &PolicyClient, json_output: bool) -> Result<()> {
    let status = match try_operation_json(|| client.status(), json_output)? {
        Some(s) => s,
        None => return Ok(()),
    };
    if json_output {
        print_json(&status)
    } else {
        println!("Server Status:");
        println!("  Running: {}", status.running);
        println!("  Version: {}", status.version);
        println!("  Uptime: {} seconds", status.uptime_secs);
        Ok(())
    }
}

fn handle_attach(client: &PolicyClient, cmd: AttachCommands, json_output: bool) -> Result<()> {
    match cmd {
        AttachCommands::Ingress { interface, mode } => {
            handle_operation(|| client.attach_ingress(&interface, &mode), json_output)?;
        }
        AttachCommands::Egress { interface } => {
            handle_operation(|| client.attach_tc(&interface), json_output)?;
        }
    }
    Ok(())
}

fn handle_detach(client: &PolicyClient, cmd: DetachCommands, json_output: bool) -> Result<()> {
    match cmd {
        DetachCommands::Ingress { interface } => {
            handle_operation(|| client.detach_ingress(&interface), json_output)?;
        }
        DetachCommands::Egress { interface } => {
            handle_operation(|| client.detach_tc(&interface), json_output)?;
        }
        DetachCommands::All => {
            handle_operation(|| client.detach_all(), json_output)?;
        }
    }
    Ok(())
}

fn parse_direction(direction: &str) -> Result<GqlDirection> {
    direction
        .parse()
        .map_err(|e: anyhow::Error| anyhow!("{}", e))
}

fn handle_rule(client: &PolicyClient, cmd: RuleCommands, json_output: bool) -> Result<()> {
    match cmd {
        RuleCommands::Add {
            interface,
            direction,
            src,
            dst,
            sport,
            dport,
            proto,
            actions,
            id,
            sni,
            quic_version,
            src_mac,
            dst_mac,
            expires_after_secs,
            schedule_tz,
            schedule_windows,
        } => {
            let dir = parse_direction(&direction)?;

            // Parse actions
            if actions.is_empty() {
                return Err(anyhow!("At least one action must be specified"));
            }

            let parsed_actions: Vec<ActionInput> = actions
                .iter()
                .map(|action_spec| {
                    let parts: Vec<&str> = action_spec.split(':').collect();
                    if parts.len() < 2 || parts.len() > 3 {
                        return Err(anyhow!(
                            "Action format should be ACTION:PRIORITY or ACTION:PRIORITY:PARAM_MS (e.g., drop:0, log:1:5000), got: {}",
                            action_spec
                        ));
                    }

                    let action = match parts[0].to_lowercase().as_str() {
                        "pass" | "accept" | "allow" => GqlPolicyAction::Pass,
                        "drop" | "deny" | "reject" => GqlPolicyAction::Drop,
                        "log" => GqlPolicyAction::Log,
                        "inspect" => GqlPolicyAction::Inspect,
                        _ => return Err(anyhow!("Invalid action: {}. Valid actions: pass, drop, log, inspect", parts[0])),
                    };

                    let priority: u8 = parts[1]
                        .parse()
                        .map_err(|_| anyhow!("Invalid priority: {}", parts[1]))?;

                    let param: i64 = if parts.len() == 3 {
                        parts[2].parse().map_err(|_| anyhow!("Invalid param: {}", parts[2]))?
                    } else {
                        0
                    };

                    Ok(ActionInput { action, priority, param })
                })
                .collect::<Result<Vec<_>>>()?;

            // Parse schedule windows: DAY:HH:MM-DAY:HH:MM
            let schedule = if !schedule_windows.is_empty() {
                if expires_after_secs.is_some() {
                    return Err(anyhow!(
                        "--expires-after-secs and --schedule-window are mutually exclusive"
                    ));
                }
                let mut windows = Vec::new();
                for spec in &schedule_windows {
                    let (start_str, end_str) = spec.split_once('-').ok_or_else(|| {
                        anyhow!("Schedule window must be DAY:HH:MM-DAY:HH:MM, got: {}", spec)
                    })?;
                    let parse_tp = |s: &str| -> Result<WeeklyTimePointInput> {
                        let parts: Vec<&str> = s.split(':').collect();
                        if parts.len() != 3 {
                            return Err(anyhow!(
                                "Time point must be DAY:HH:MM (e.g. 0:09:00), got: {}",
                                s
                            ));
                        }
                        let day: i32 = parts[0].parse().map_err(|_| {
                            anyhow!("Invalid day '{}': must be 0 (Sun) to 6 (Sat)", parts[0])
                        })?;
                        let hour: i32 = parts[1]
                            .parse()
                            .map_err(|_| anyhow!("Invalid hour '{}': must be 0–23", parts[1]))?;
                        let minute: i32 = parts[2]
                            .parse()
                            .map_err(|_| anyhow!("Invalid minute '{}': must be 0–59", parts[2]))?;
                        Ok(WeeklyTimePointInput {
                            day_of_week: day,
                            hour,
                            minute,
                        })
                    };
                    windows.push(WeeklyWindowInput {
                        start: parse_tp(start_str)?,
                        end: parse_tp(end_str)?,
                    });
                }
                Some(RuleScheduleInput {
                    windows,
                    timezone: schedule_tz.clone(),
                })
            } else {
                None
            };

            let input = AddRuleInput {
                interface,
                direction: dir,
                src,
                dst,
                sport,
                dport,
                protocol: proto.clone(),
                actions: parsed_actions,
                id,
                sni,
                quic_version: quic_version.clone(),
                src_mac,
                dst_mac,
                expires_after_secs: expires_after_secs.map(|s| s as i32),
                schedule,
            };

            handle_operation(
                || {
                    // SNI matching applies to TCP (in-kernel TLS SNI tail call)
                    // or UDP (userspace QUIC Initial inspection).
                    if input.sni.is_some() && input.protocol != "tcp" && input.protocol != "udp" {
                        return Err(anyhow!(
                            "SNI matching requires TCP or UDP protocol (got '{}')",
                            input.protocol
                        ));
                    }
                    // QUIC version matching only applies to UDP or any
                    if let Some(ref qv) = input.quic_version {
                        if input.protocol != "udp" && input.protocol != "any" {
                            return Err(anyhow!(
                                "QUIC version '{}' requires UDP or any protocol (got '{}')",
                                qv,
                                input.protocol
                            ));
                        }
                    }
                    client.add_rule(input.clone())
                },
                json_output,
            )?;
        }

        RuleCommands::Delete {
            interface,
            direction,
            id,
            src,
            dst,
            sport,
            dport,
            proto,
        } => {
            let dir = parse_direction(&direction)?;

            let input = DeleteRuleInput {
                interface,
                direction: dir,
                id: id.map(|v| v.to_string()),
                src,
                dst,
                sport,
                dport,
                protocol: proto,
            };
            handle_operation(|| client.delete_rule(input.clone()), json_output)?;
        }

        RuleCommands::List {
            direction,
            interface,
            format: _,
        } => {
            let dir = parse_direction(&direction)?;

            let mut rules = match try_operation_json(|| client.list_rules(dir), json_output)? {
                Some(r) => r,
                None => return Ok(()),
            };
            if let Some(ref iface) = interface {
                rules.retain(|r| &r.interface == iface);
            }
            if json_output {
                print_json(&rules)?;
            } else {
                print_rules_table(&rules);
            }
        }

        RuleCommands::Flush {
            direction,
            interface,
        } => {
            let dir = parse_direction(&direction)?;
            handle_operation(|| client.flush_rules(&interface, dir), json_output)?;
        }

        RuleCommands::ManagedRules {
            direction,
            interface,
        } => {
            let dir = parse_direction(&direction)?;
            let all_rules = client
                .managed_rules(dir)
                .map_err(|e| anyhow!("Failed to list managed rules: {}", e))?;

            // Filter by interface when requested.
            let rules: Vec<_> = if let Some(ref iface) = interface {
                all_rules
                    .into_iter()
                    .filter(|r| {
                        r.get("interface")
                            .and_then(|v| v.as_str())
                            .map(|s| s == iface)
                            .unwrap_or(false)
                    })
                    .collect()
            } else {
                all_rules
            };

            if json_output {
                println!("{}", serde_json::to_string_pretty(&rules)?);
            } else if rules.is_empty() {
                println!("No managed rules found.");
            } else {
                let mut table = Table::new();
                table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
                table.set_titles(row![
                    "Rule ID",
                    "Interface",
                    "Direction",
                    "Src",
                    "Dst",
                    "Protocol",
                    "State",
                    "Lifecycle"
                ]);
                for rule in &rules {
                    let rule_id = rule["ruleId"].as_str().unwrap_or("-");
                    let iface = rule["interface"].as_str().unwrap_or("-");
                    let direction = rule["direction"].as_str().unwrap_or("-");
                    let src = rule["srcPrefix"].as_str().unwrap_or("-");
                    let dst = rule["dstPrefix"].as_str().unwrap_or("-");
                    let proto = rule["protocol"].as_str().unwrap_or("-");
                    let state = rule["ruleState"].as_str().unwrap_or("-");
                    let lifecycle = if let Some(exp) = rule["expiresAtMs"].as_str() {
                        let ms: u64 = exp.parse().unwrap_or(0);
                        let secs = ms / 1000;
                        format!("Expires at Unix {}s", secs)
                    } else if rule["schedule"].is_object() {
                        let tz = rule["schedule"]["timezone"].as_str().unwrap_or("UTC");
                        format!("Scheduled ({})", tz)
                    } else {
                        "Permanent".to_string()
                    };
                    table.add_row(row![
                        rule_id, iface, direction, src, dst, proto, state, lifecycle
                    ]);
                }
                table.printstd();
            }
        }
    }
    Ok(())
}

/// Return an error if the server does not support IPS/IDS.
fn require_suricata(client: &PolicyClient) -> Result<()> {
    let features = client
        .server_features()
        .map_err(|e| anyhow!("Could not query server features: {}", e))?;
    if !features.suricata {
        Err(anyhow!(
            "This server does not support IPS/IDS \
             (compiled without the suricata feature). \
             Install policy-engine-ips to enable this functionality."
        ))
    } else {
        Ok(())
    }
}

fn handle_inspect(client: &PolicyClient, cmd: InspectCommand, json_output: bool) -> Result<()> {
    // Status / Enable / Disable drive the Suricata IPS pipeline and require
    // that feature on the server.  Verdicts / ClearVerdicts operate on the
    // generic flow_verdict_cache, which Phase 1 of the QUIC SNI work degated
    // from `suricata` so QUIC SNI verdicts work in plain builds — do not gate
    // them here.
    let needs_suricata = matches!(
        cmd,
        InspectCommand::Status | InspectCommand::Enable { .. } | InspectCommand::Disable
    );
    if needs_suricata {
        if let Err(e) = require_suricata(client) {
            if json_output {
                let error_result = OperationResult {
                    success: false,
                    message: e.to_string(),
                };
                print_result(&error_result, json_output)?;
                return Ok(());
            }
            return Err(e);
        }
    }
    match cmd {
        InspectCommand::Status => {
            let status = match try_operation_json(|| client.inspect_status(), json_output)? {
                Some(s) => s,
                None => return Ok(()),
            };
            if json_output {
                print_json(&status)?;
            } else {
                println!("Inspect/IPS Status:");
                println!("{}", "─".repeat(40));
                println!("  Mode:              {}", status.mode);
                println!("  Suricata Running:  {}", status.suricata_running);
                println!(
                    "  Mirror Interface:  {}",
                    status.mirror_interface.as_deref().unwrap_or("none")
                );
                println!(
                    "  Peer Interface:    {}",
                    status.peer_interface.as_deref().unwrap_or("none")
                );
                println!(
                    "  Mirror Ifindex:    {}",
                    status
                        .mirror_ifindex
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "none".to_string())
                );
                println!("  Flow Verdicts:     {}", status.flow_verdict_count);
                if let Some(ref ver) = status.suricata_version {
                    println!("  Suricata Version:  {}", ver);
                }
                if let Some(ref ver) = status.ruleset_version {
                    println!("  Ruleset Version:   {}", ver);
                }
            }
        }

        InspectCommand::Enable { mode } => {
            let inspect_mode: GqlInspectMode =
                mode.parse().map_err(|e: anyhow::Error| anyhow!("{}", e))?;
            handle_operation(|| client.configure_inspect(inspect_mode), json_output)?;
        }

        InspectCommand::Disable => {
            handle_operation(|| client.disable_inspect(), json_output)?;
        }

        InspectCommand::Verdicts { direction } => {
            let dir = parse_direction(&direction)?;
            let verdicts = match try_operation_json(|| client.flow_verdicts(dir), json_output)? {
                Some(v) => v,
                None => return Ok(()),
            };
            if json_output {
                print_json(&verdicts)?;
            } else {
                println!("Flow Verdicts ({}):", direction.to_uppercase());
                println!("{}", "─".repeat(40));
                println!("  Active Verdicts: {}", verdicts.active_verdicts);
            }
        }

        InspectCommand::ClearVerdicts { direction } => {
            let dir = parse_direction(&direction)?;
            handle_operation(|| client.clear_flow_verdicts(dir), json_output)?;
        }
    }
    Ok(())
}

fn handle_suricata(client: &PolicyClient, cmd: SuricataCommand, json_output: bool) -> Result<()> {
    if let Err(e) = require_suricata(client) {
        if json_output {
            let error_result = OperationResult {
                success: false,
                message: e.to_string(),
            };
            print_result(&error_result, json_output)?;
            return Ok(());
        }
        return Err(e);
    }
    match cmd {
        SuricataCommand::Status => {
            let status = match try_operation_json(|| client.suricata_status(), json_output)? {
                Some(s) => s,
                None => return Ok(()),
            };
            if json_output {
                print_json(&status)?;
            } else {
                println!("Suricata Status:");
                println!("{}", "─".repeat(40));
                println!("  {}", status.message);
            }
        }

        SuricataCommand::DeployRules { file, name } => {
            let rules_text = std::fs::read_to_string(&file)
                .map_err(|e| anyhow!("Failed to read file '{}': {}", file, e))?;
            handle_operation(
                || client.deploy_suricata_rules(&rules_text, &name),
                json_output,
            )?;
        }

        SuricataCommand::Reload => {
            handle_operation(|| client.reload_suricata_rules(), json_output)?;
        }
    }
    Ok(())
}

fn handle_show(client: &PolicyClient, cmd: ShowCommands, json_output: bool) -> Result<()> {
    match cmd {
        ShowCommands::Interfaces => {
            let interfaces = match try_operation_json(|| client.list_interfaces(), json_output)? {
                Some(i) => i,
                None => return Ok(()),
            };
            // uRPF and FIB forwarding ("XDP forward mode") are ingress-only (XDP)
            // features. Fetch their per-interface state so it can be shown alongside
            // the attachment info.
            let urpf: HashMap<String, String> =
                match try_operation_json(|| client.list_urpf(), json_output)? {
                    Some(u) => u.into_iter().collect(),
                    None => return Ok(()),
                };
            let fib: HashMap<String, bool> =
                match try_operation_json(|| client.list_fib_forwarding(), json_output)? {
                    Some(f) => f.into_iter().collect(),
                    None => return Ok(()),
                };
            let is_ingress =
                |iface: &InterfaceAttachment| iface.direction.eq_ignore_ascii_case("ingress");
            let urpf_mode = |iface: &InterfaceAttachment| {
                urpf.get(&iface.interface)
                    .cloned()
                    .unwrap_or_else(|| "OFF".to_string())
            };
            let fib_enabled =
                |iface: &InterfaceAttachment| fib.get(&iface.interface).copied().unwrap_or(false);

            if json_output {
                // Fold uRPF/FIB state into each ingress interface object.
                let enriched: Vec<serde_json::Value> = interfaces
                    .iter()
                    .map(|iface| {
                        let mut v = serde_json::to_value(iface).unwrap_or_default();
                        if let (true, Some(obj)) = (is_ingress(iface), v.as_object_mut()) {
                            obj.insert("urpfMode".to_string(), json!(urpf_mode(iface)));
                            obj.insert("fibForwarding".to_string(), json!(fib_enabled(iface)));
                        }
                        v
                    })
                    .collect();
                print_json(&enriched)?;
            } else if interfaces.is_empty() {
                println!("No programs attached to any interfaces.");
            } else {
                println!("Attached Programs:");
                println!("{}", "─".repeat(50));
                for iface in interfaces {
                    println!(
                        "  Interface: {} (ifindex={})",
                        iface.interface, iface.ifindex
                    );
                    println!("    Direction: {}", iface.direction);
                    println!("    Mode: {}", iface.mode);
                    if is_ingress(&iface) {
                        println!("    uRPF: {}", urpf_mode(&iface));
                        println!(
                            "    FIB Forwarding: {}",
                            if fib_enabled(&iface) {
                                "enabled"
                            } else {
                                "disabled"
                            }
                        );
                    }
                    println!();
                }
            }
        }

        ShowCommands::Stats {
            interface,
            direction,
        } => {
            let dir = parse_direction(&direction)?;
            let stats = match try_operation_json(|| client.get_stats(&interface, dir), json_output)?
            {
                Some(s) => s,
                None => return Ok(()),
            };
            let ethertype_stats = match try_operation_json(
                || client.get_ethertype_stats(&interface, dir),
                json_output,
            )? {
                Some(e) => e,
                None => return Ok(()),
            };
            // Non-IP sender stats are ingress-only; skip fetch for egress.
            let nonip_senders = if direction.to_lowercase() != "egress" {
                match try_operation_json(|| client.get_nonip_senders(&interface), json_output)? {
                    Some(s) => s,
                    None => return Ok(()),
                }
            } else {
                vec![]
            };
            let interfaces = match try_operation_json(|| client.list_interfaces(), json_output)? {
                Some(i) => i,
                None => return Ok(()),
            };
            let attachment = interfaces.iter().find(|i| {
                i.interface == interface && i.direction.to_lowercase() == direction.to_lowercase()
            });

            if json_output {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct StatsResponse {
                    interface: String,
                    direction: String,
                    program_attached: bool,
                    global_stats: GlobalStatsOutput,
                    ethertype_stats: Vec<EthertypeStatsOutput>,
                    nonip_senders: Vec<NonIpSenderOutput>,
                }
                let response = StatsResponse {
                    interface: interface.clone(),
                    direction: direction.to_uppercase(),
                    program_attached: attachment.is_some(),
                    global_stats: stats,
                    ethertype_stats,
                    nonip_senders,
                };
                print_json(&response)?;
            } else {
                println!(
                    "\n{} Statistics for {}:",
                    direction.to_uppercase(),
                    interface
                );
                println!("{}", "─".repeat(50));

                if let Some(attached) = attachment {
                    println!(
                        "Status: \x1b[32m●\x1b[0m Attached (mode: {})",
                        attached.mode
                    );
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
                if direction.to_lowercase() != "egress" {
                    policy_table.add_row(row!["BUM Packets", format_packets(stats.bum_packets)]);
                    policy_table
                        .add_row(row!["Non-IP Unicast", format_packets(stats.non_ip_unicast)]);
                }
                policy_table.add_row(row!["Tail Calls", format_packets(stats.tail_calls)]);
                // uRPF and FIB forwarding are ingress-only (XDP) features.
                if direction.to_lowercase() != "egress" {
                    policy_table
                        .add_row(row!["uRPF Drops", format_packets(stats.urpf_drop_packets)]);
                    policy_table
                        .add_row(row!["uRPF Drop Bytes", format_bytes(stats.urpf_drop_bytes)]);
                    policy_table.add_row(row![
                        "FIB Forwarded",
                        format_packets(stats.fib_forwarded_packets)
                    ]);
                    policy_table.add_row(row![
                        "FIB Fallback",
                        format_packets(stats.fib_fallback_packets)
                    ]);
                }

                policy_table.printstd();

                if direction.to_lowercase() != "egress" && !ethertype_stats.is_empty() {
                    println!("\nNon-IP Traffic by Ethertype:");
                    let mut eth_table = Table::new();
                    eth_table.set_format(*format::consts::FORMAT_BOX_CHARS);
                    eth_table.add_row(row!["Ethertype", "Name", "Packets"]);
                    for stat in ethertype_stats {
                        eth_table.add_row(row![
                            format!("0x{:04X}", stat.ethertype),
                            stat.name,
                            format_packets(stat.packets)
                        ]);
                    }
                    eth_table.printstd();
                }

                if !nonip_senders.is_empty() {
                    println!("\nNon-IP Senders (by packet count):");
                    let mut nonip_table = Table::new();
                    nonip_table.set_format(*format::consts::FORMAT_BOX_CHARS);
                    nonip_table.add_row(row!["MAC", "Ethertype", "Name", "Packets"]);
                    for sender in nonip_senders {
                        nonip_table.add_row(row![
                            sender.mac,
                            format!("0x{:04X}", sender.ethertype),
                            sender.name,
                            format_packets(sender.packets)
                        ]);
                    }
                    nonip_table.printstd();
                }
            }
        }

        ShowCommands::Rules {
            direction,
            interface,
        } => {
            let dir = parse_direction(&direction)?;
            let mut rules = match try_operation_json(|| client.list_rules(dir), json_output)? {
                Some(r) => r,
                None => return Ok(()),
            };
            if let Some(ref iface) = interface {
                rules.retain(|r| &r.interface == iface);
            }
            if json_output {
                print_json(&rules)?;
            } else if rules.is_empty() {
                println!("No {} policy rules configured.", direction.to_lowercase());
            } else {
                println!(
                    "\n{} Policy Rules ({} total):",
                    direction.to_uppercase(),
                    rules.len()
                );
                println!("{}", "─".repeat(80));

                for rule in &rules {
                    let ip_version = if rule.src_prefix.contains(':') {
                        "IPv6"
                    } else {
                        "IPv4"
                    };
                    println!("\nRule {} ({}):", rule.rule_id, ip_version);
                    println!(
                        "  Interface: {}",
                        if rule.interface.is_empty() {
                            "any"
                        } else {
                            &rule.interface
                        }
                    );
                    println!("  Match:");
                    println!("    Source:      {}", rule.src_prefix);
                    println!("    Destination: {}", rule.dst_prefix);
                    let sport_str = if rule.sport == 0 {
                        "Any".to_string()
                    } else {
                        rule.sport.to_string()
                    };
                    let dport_str = if rule.dport == 0 {
                        "Any".to_string()
                    } else {
                        rule.dport.to_string()
                    };
                    println!("    Source Port: {}", sport_str);
                    println!("    Dest Port:   {}", dport_str);
                    println!("    Protocol:    {:?}", rule.protocol);
                    println!("  Actions:");
                    for (i, action) in rule.actions.iter().enumerate() {
                        println!("    {}. {:?}", i + 1, action.action,);
                    }
                }
                println!();
            }
        }

        ShowCommands::RuleStats {
            direction,
            id,
            interface,
        } => {
            let dir = parse_direction(&direction)?;
            let interfaces = match try_operation_json(|| client.list_interfaces(), json_output)? {
                Some(i) => i,
                None => return Ok(()),
            };
            let program_attached = !interfaces.is_empty();

            match id {
                Some(rule_id) => {
                    let stats = match try_operation_json(
                        || client.get_rule_stats(rule_id, dir),
                        json_output,
                    )? {
                        Some(s) => s,
                        None => return Ok(()),
                    };
                    if json_output {
                        #[derive(Serialize)]
                        #[serde(rename_all = "camelCase")]
                        struct SingleRuleStatsResponse {
                            program_attached: bool,
                            direction: String,
                            rule_id: String,
                            stats: Option<RuleStatsOutput>,
                        }
                        let response = SingleRuleStatsResponse {
                            program_attached,
                            direction: direction.to_uppercase(),
                            rule_id: rule_id.to_string(),
                            stats,
                        };
                        print_json(&response)?;
                    } else if let Some(s) = stats {
                        println!(
                            "\nStatistics for Rule {} ({}):",
                            rule_id,
                            direction.to_uppercase()
                        );
                        println!("{}", "─".repeat(40));
                        if !program_attached {
                            println!("  \x1b[33m⚠ Warning: No program attached (showing cached stats)\x1b[0m");
                        }
                        println!("  Packets: {}", format_packets(s.packets));
                        println!("  Bytes: {}", format_bytes(s.bytes));
                    } else {
                        println!("No statistics found for rule {}", rule_id);
                    }
                }
                None => {
                    let mut rules =
                        match try_operation_json(|| client.list_rules(dir), json_output)? {
                            Some(r) => r,
                            None => return Ok(()),
                        };
                    if let Some(ref iface) = interface {
                        rules.retain(|r| &r.interface == iface);
                    }
                    if json_output {
                        #[derive(Serialize)]
                        #[serde(rename_all = "camelCase")]
                        struct RuleWithStats {
                            rule: LpmRuleOutput,
                            stats: Option<RuleStatsOutput>,
                        }
                        #[derive(Serialize)]
                        #[serde(rename_all = "camelCase")]
                        struct RuleStatsResponse {
                            program_attached: bool,
                            direction: String,
                            rules: Vec<RuleWithStats>,
                        }
                        let rules_with_stats: Vec<RuleWithStats> = rules
                            .into_iter()
                            .map(|rule| {
                                let stats = client.get_rule_stats(rule.rule_id, dir).ok().flatten();
                                RuleWithStats { rule, stats }
                            })
                            .collect();
                        let response = RuleStatsResponse {
                            program_attached,
                            direction: direction.to_uppercase(),
                            rules: rules_with_stats,
                        };
                        print_json(&response)?;
                    } else if rules.is_empty() {
                        println!("No {} policy rules configured.", direction.to_lowercase());
                    } else {
                        println!("\n{} Rule Statistics:", direction.to_uppercase());
                        println!("{}", "─".repeat(100));
                        if !program_attached {
                            println!("\x1b[33m⚠ Warning: No program attached (showing cached stats)\x1b[0m\n");
                        }

                        let mut table = Table::new();
                        table.set_format(*format::consts::FORMAT_BOX_CHARS);
                        table.add_row(row![
                            "Rule ID",
                            "Src Prefix",
                            "Dst Prefix",
                            "Proto",
                            "Sport",
                            "Dport",
                            "Packets",
                            "Bytes"
                        ]);

                        for rule in &rules {
                            let sport_str = if rule.sport == 0 {
                                "Any".to_string()
                            } else {
                                rule.sport.to_string()
                            };
                            let dport_str = if rule.dport == 0 {
                                "Any".to_string()
                            } else {
                                rule.dport.to_string()
                            };
                            let stats_result = match try_operation_json(
                                || client.get_rule_stats(rule.rule_id, dir),
                                json_output,
                            )? {
                                Some(s) => s,
                                None => return Ok(()),
                            };
                            if let Some(stats) = stats_result {
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
        ShowCommands::DefaultAction {
            interface,
            direction,
        } => {
            let dir = parse_direction(&direction)?;
            let action = match try_operation_json(
                || client.get_default_action(&interface, dir),
                json_output,
            )? {
                Some(a) => a,
                None => return Ok(()),
            };
            if json_output {
                print_json(
                    &serde_json::json!({ "interface": interface, "direction": direction, "action": action }),
                )?;
            } else {
                println!(
                    "{}/{} default action: {}",
                    interface.to_uppercase(),
                    direction.to_uppercase(),
                    action
                );
            }
        }
        ShowCommands::Features => {
            let features = match try_operation_json(|| client.server_features(), json_output)? {
                Some(f) => f,
                None => return Ok(()),
            };
            if json_output {
                print_json(&features)?;
            } else {
                println!("Server Features:");
                println!("{}", "─".repeat(30));
                println!(
                    "  IPS/IDS (Suricata): {}",
                    if features.suricata { "yes" } else { "no" }
                );
            }
        }
    }
    Ok(())
}

fn handle_config(client: &PolicyClient, cmd: ConfigCommands, json_output: bool) -> Result<()> {
    match cmd {
        ConfigCommands::DefaultAction {
            interface,
            action,
            direction,
        } => {
            let dir = parse_direction(&direction)?;
            let policy_action = match action.to_lowercase().as_str() {
                "pass" | "accept" | "allow" => GqlPolicyAction::Pass,
                "drop" | "deny" | "reject" => GqlPolicyAction::Drop,
                "log" => GqlPolicyAction::Log,
                _ => {
                    return Err(anyhow!(
                        "Invalid action: {}. Valid actions: pass, drop, log",
                        action
                    ))
                }
            };

            handle_operation(
                || client.set_default_action(policy_action, dir, &interface),
                json_output,
            )?;
        }

        ConfigCommands::TailCall {
            slot,
            program,
            direction,
        } => {
            let dir = parse_direction(&direction)?;
            handle_operation(
                || client.register_tail_call(slot, &program, dir),
                json_output,
            )?;
        }

        ConfigCommands::FibForwarding { interface, enabled } => {
            handle_operation(
                || client.set_fib_forwarding(&interface, enabled),
                json_output,
            )?;
        }

        ConfigCommands::Urpf { interface, mode } => {
            let normalized = match mode.to_lowercase().as_str() {
                "off" | "none" | "disable" | "disabled" => "OFF",
                "loose" => "LOOSE",
                "strict" => "STRICT",
                _ => {
                    return Err(anyhow!(
                        "Invalid uRPF mode: {}. Valid modes: off, loose, strict",
                        mode
                    ))
                }
            };
            handle_operation(|| client.set_urpf(&interface, normalized), json_output)?;
        }
    }
    Ok(())
}

fn handle_clear_stats(
    client: &PolicyClient,
    cmd: ClearStatsCommands,
    json_output: bool,
) -> Result<()> {
    match cmd {
        ClearStatsCommands::Global {
            interface,
            direction,
        } => {
            let dir = parse_direction(&direction)?;
            handle_operation(|| client.clear_global_stats(&interface, dir), json_output)?;
        }

        ClearStatsCommands::Interface {
            interface,
            direction,
        } => {
            let dir = parse_direction(&direction)?;
            handle_operation(
                || client.clear_interface_stats(&interface, dir),
                json_output,
            )?;
        }

        ClearStatsCommands::Rule { direction, id } => {
            let dir = parse_direction(&direction)?;
            if let Some(rule_id) = id {
                handle_operation(|| client.clear_rule_stats(rule_id, dir), json_output)?;
            } else {
                handle_operation(|| client.clear_all_rule_stats(dir), json_output)?;
            }
        }

        ClearStatsCommands::Ethertype {
            interface,
            direction,
        } => {
            let dir = parse_direction(&direction)?;
            handle_operation(
                || client.clear_ethertype_stats(&interface, dir),
                json_output,
            )?;
        }

        ClearStatsCommands::All => {
            handle_operation(|| client.clear_all_stats(), json_output)?;
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
        "ID", "Iface", "Src", "Dst", "Proto", "Sport", "Dport", "Actions", "SNI", "QUIC",
        "Src MAC", "Dst MAC"
    ]);

    for rule in rules {
        let actions_str: String = rule
            .actions
            .iter()
            .map(|a| format!("{:?}", a.action))
            .collect::<Vec<_>>()
            .join(", ");
        let sport_str = if rule.sport == 0 {
            "Any".to_string()
        } else {
            rule.sport.to_string()
        };
        let dport_str = if rule.dport == 0 {
            "Any".to_string()
        } else {
            rule.dport.to_string()
        };
        let iface_str = if rule.interface.is_empty() {
            "any"
        } else {
            &rule.interface
        };
        let sni_str = rule.sni.as_deref().unwrap_or("-");
        let quic_str = rule.quic_version.as_deref().unwrap_or("-");
        let src_mac_str = rule.src_mac.as_deref().unwrap_or("-");
        let dst_mac_str = rule.dst_mac.as_deref().unwrap_or("-");
        table.add_row(row![
            rule.rule_id,
            iface_str,
            rule.src_prefix,
            rule.dst_prefix,
            format!("{:?}", rule.protocol),
            sport_str,
            dport_str,
            actions_str,
            sni_str,
            quic_str,
            src_mac_str,
            dst_mac_str
        ]);
    }

    table.printstd();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Test that ServerStatus serializes to valid JSON
    #[test]
    fn test_server_status_json_serialization() {
        let status = ServerStatus {
            running: true,
            version: "0.1.0".to_string(),
            uptime_secs: 3600,
            program_attached: true,
            inspect_mode: None,
        };

        let json = serde_json::to_string_pretty(&status).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["running"], true);
        assert_eq!(parsed["version"], "0.1.0");
        assert_eq!(parsed["uptimeSecs"], 3600);
        assert_eq!(parsed["programAttached"], true);
    }

    /// Test that OperationResult serializes to valid JSON
    #[test]
    fn test_operation_result_json_serialization() {
        let result = OperationResult {
            success: true,
            message: "Attached ingress program to eth0 in native mode".to_string(),
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["success"], true);
        assert_eq!(
            parsed["message"],
            "Attached ingress program to eth0 in native mode"
        );
    }

    /// Test that InterfaceAttachment serializes to valid JSON
    #[test]
    fn test_interface_attachment_json_serialization() {
        let attachment = InterfaceAttachment {
            interface: "eth0".to_string(),
            ifindex: 2,
            mode: "native".to_string(),
            direction: "INGRESS".to_string(),
        };

        let json = serde_json::to_string_pretty(&attachment).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["interface"], "eth0");
        assert_eq!(parsed["ifindex"], 2);
        assert_eq!(parsed["mode"], "native");
        assert_eq!(parsed["direction"], "INGRESS");
    }

    /// Test that a list of interfaces serializes to valid JSON array
    #[test]
    fn test_interfaces_list_json_serialization() {
        let interfaces = vec![
            InterfaceAttachment {
                interface: "eth0".to_string(),
                ifindex: 2,
                mode: "native".to_string(),
                direction: "INGRESS".to_string(),
            },
            InterfaceAttachment {
                interface: "eth0".to_string(),
                ifindex: 2,
                mode: "tc".to_string(),
                direction: "EGRESS".to_string(),
            },
        ];

        let json = serde_json::to_string_pretty(&interfaces).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 2);
        assert_eq!(parsed[0]["interface"], "eth0");
        assert_eq!(parsed[0]["direction"], "INGRESS");
        assert_eq!(parsed[1]["direction"], "EGRESS");
    }

    /// Test that GlobalStatsOutput serializes to valid JSON with camelCase
    #[test]
    fn test_global_stats_json_serialization() {
        let stats = GlobalStatsOutput {
            rx_packets: 1000,
            rx_bytes: 64000,
            tx_packets: 500,
            tx_bytes: 32000,
            policy_matches: 100,
            policy_drops: 10,
            policy_pass: 90,
            policy_redirects: 0,
            parse_errors: 5,
            tail_calls: 2,
            bum_packets: 50,
            non_ip_unicast: 20,
            inspect_redirects: 0,
            fragments: 0,
            verdict_pass_packets: 0,
            verdict_pass_bytes: 0,
            verdict_drop_packets: 0,
            verdict_drop_bytes: 0,
            fib_forwarded_packets: 0,
            fib_forwarded_bytes: 0,
            fib_fallback_packets: 0,
            urpf_drop_packets: 0,
            urpf_drop_bytes: 0,
        };

        let json = serde_json::to_string_pretty(&stats).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        // Check camelCase field names
        assert_eq!(parsed["rxPackets"], 1000);
        assert_eq!(parsed["rxBytes"], 64000);
        assert_eq!(parsed["policyMatches"], 100);
        assert_eq!(parsed["policyDrops"], 10);
        assert_eq!(parsed["parseErrors"], 5);
        assert_eq!(parsed["tailCalls"], 2);
    }

    /// Test that LpmRuleOutput serializes to valid JSON
    #[test]
    fn test_lpm_rule_json_serialization() {
        let rule = LpmRuleOutput {
            rule_id: 12345,
            interface: "lo".to_string(),
            src_prefix: "192.168.1.0/24".to_string(),
            dst_prefix: "10.0.0.0/8".to_string(),
            sport: 0,
            dport: 80,
            protocol: GqlProtocol::Tcp,
            actions: vec![
                RuleActionOutput {
                    action: GqlPolicyAction::Log,
                    priority: 0,
                    param: 0,
                },
                RuleActionOutput {
                    action: GqlPolicyAction::Drop,
                    priority: 1,
                    param: 0,
                },
            ],
            sni: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
        };

        let json = serde_json::to_string_pretty(&rule).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["ruleId"], 12345);
        assert_eq!(parsed["srcPrefix"], "192.168.1.0/24");
        assert_eq!(parsed["dstPrefix"], "10.0.0.0/8");
        assert_eq!(parsed["dport"], 80);
        assert_eq!(parsed["protocol"], "TCP");
        assert!(parsed["actions"].is_array());
        assert_eq!(parsed["actions"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["actions"][0]["action"], "LOG");
        assert_eq!(parsed["actions"][1]["action"], "DROP");
    }

    /// Test that RuleStatsOutput serializes to valid JSON
    #[test]
    fn test_rule_stats_json_serialization() {
        let stats = RuleStatsOutput {
            packets: 1000,
            bytes: 64000,
            last_seen_ns: 1234567890,
        };

        let json = serde_json::to_string_pretty(&stats).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["packets"], 1000);
        assert_eq!(parsed["bytes"], 64000);
        assert_eq!(parsed["lastSeenNs"], 1234567890_u64);
    }

    /// Test that EthertypeStatsOutput serializes to valid JSON
    #[test]
    fn test_ethertype_stats_json_serialization() {
        let stats = EthertypeStatsOutput {
            ethertype: 0x0806,
            name: "ARP".to_string(),
            packets: 500,
        };

        let json = serde_json::to_string_pretty(&stats).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["ethertype"], 0x0806);
        assert_eq!(parsed["name"], "ARP");
        assert_eq!(parsed["packets"], 500);
        assert!(
            parsed.get("ethertypeHex").is_none(),
            "ethertypeHex should not exist"
        );
    }

    /// Test that empty rules list serializes to empty JSON array
    #[test]
    fn test_empty_rules_json_serialization() {
        let rules: Vec<LpmRuleOutput> = vec![];

        let json = serde_json::to_string_pretty(&rules).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    /// Test that GqlPolicyAction enum values serialize correctly
    #[test]
    fn test_policy_action_json_values() {
        let actions = vec![
            GqlPolicyAction::Pass,
            GqlPolicyAction::Drop,
            GqlPolicyAction::Log,
            GqlPolicyAction::TailCall,
        ];

        let json = serde_json::to_string(&actions).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0], "PASS");
        assert_eq!(parsed[1], "DROP");
        assert_eq!(parsed[2], "LOG");
        assert_eq!(parsed[3], "TAILCALL");
    }

    /// Test that GqlProtocol enum values serialize correctly
    #[test]
    fn test_protocol_json_values() {
        let protocols = vec![
            GqlProtocol::Any,
            GqlProtocol::Tcp,
            GqlProtocol::Udp,
            GqlProtocol::Icmp,
        ];

        let json = serde_json::to_string(&protocols).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0], "ANY");
        assert_eq!(parsed[1], "TCP");
        assert_eq!(parsed[2], "UDP");
        assert_eq!(parsed[3], "ICMP");
    }

    /// Test print_json helper produces valid JSON
    #[test]
    fn test_print_json_helper() {
        // This test verifies that print_json would not error
        // We can't easily capture stdout, but we can verify the serialization works
        let status = ServerStatus {
            running: true,
            version: "0.1.0".to_string(),
            uptime_secs: 100,
            program_attached: false,
            inspect_mode: None,
        };

        // Ensure serialization doesn't panic
        let result = serde_json::to_string_pretty(&status);
        assert!(result.is_ok());
    }

    /// Test that combined stats response (for show stats --json) works
    #[test]
    fn test_combined_stats_response_json() {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct StatsResponse {
            interface: String,
            global_stats: GlobalStatsOutput,
            ethertype_stats: Vec<EthertypeStatsOutput>,
        }

        let response = StatsResponse {
            interface: "eth0".to_string(),
            global_stats: GlobalStatsOutput {
                rx_packets: 1000,
                rx_bytes: 64000,
                tx_packets: 0,
                tx_bytes: 0,
                policy_matches: 50,
                policy_drops: 10,
                policy_pass: 40,
                policy_redirects: 0,
                parse_errors: 0,
                tail_calls: 0,
                bum_packets: 0,
                non_ip_unicast: 0,
                inspect_redirects: 0,
                fragments: 0,
                verdict_pass_packets: 0,
                verdict_pass_bytes: 0,
                verdict_drop_packets: 0,
                verdict_drop_bytes: 0,
                fib_forwarded_packets: 0,
                fib_forwarded_bytes: 0,
                fib_fallback_packets: 0,
                urpf_drop_packets: 0,
                urpf_drop_bytes: 0,
            },
            ethertype_stats: vec![EthertypeStatsOutput {
                ethertype: 0x0806,
                name: "ARP".to_string(),
                packets: 100,
            }],
        };

        let json = serde_json::to_string_pretty(&response).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["interface"], "eth0");
        assert!(parsed["globalStats"].is_object());
        assert!(parsed["ethertypeStats"].is_array());
        assert_eq!(parsed["globalStats"]["rxPackets"], 1000);
        assert_eq!(parsed["ethertypeStats"][0]["name"], "ARP");
    }

    // === Direction tests ===

    /// Test that GqlDirection serializes correctly
    #[test]
    fn test_direction_json_serialization() {
        let ingress = GqlDirection::Ingress;
        let egress = GqlDirection::Egress;

        assert_eq!(serde_json::to_string(&ingress).unwrap(), "\"INGRESS\"");
        assert_eq!(serde_json::to_string(&egress).unwrap(), "\"EGRESS\"");
    }

    /// Test that GqlDirection deserializes correctly
    #[test]
    fn test_direction_json_deserialization() {
        let ingress: GqlDirection = serde_json::from_str("\"INGRESS\"").unwrap();
        let egress: GqlDirection = serde_json::from_str("\"EGRESS\"").unwrap();

        assert_eq!(ingress, GqlDirection::Ingress);
        assert_eq!(egress, GqlDirection::Egress);
    }

    /// Test that GqlDirection FromStr works
    #[test]
    fn test_direction_from_str() {
        assert_eq!(parse_direction("ingress").unwrap(), GqlDirection::Ingress);
        assert_eq!(parse_direction("egress").unwrap(), GqlDirection::Egress);
        assert_eq!(parse_direction("INGRESS").unwrap(), GqlDirection::Ingress);
        assert_eq!(parse_direction("EGRESS").unwrap(), GqlDirection::Egress);
        assert_eq!(parse_direction("in").unwrap(), GqlDirection::Ingress);
        assert_eq!(parse_direction("out").unwrap(), GqlDirection::Egress);
    }

    /// Test that invalid direction fails
    #[test]
    fn test_direction_from_str_invalid() {
        assert!(parse_direction("invalid").is_err());
        assert!(parse_direction("").is_err());
        assert!(parse_direction("both").is_err());
    }

    /// Test that GqlDirection Display works
    #[test]
    fn test_direction_display() {
        assert_eq!(format!("{}", GqlDirection::Ingress), "INGRESS");
        assert_eq!(format!("{}", GqlDirection::Egress), "EGRESS");
    }

    /// Test AddRuleInput with direction serialization
    #[test]
    fn test_add_rule_input_with_direction() {
        let input = AddRuleInput {
            interface: "lo".to_string(),
            direction: GqlDirection::Egress,
            src: Some("10.0.0.0/8".to_string()),
            dst: None,
            sport: 0,
            dport: 80,
            protocol: "tcp".to_string(),
            actions: vec![ActionInput {
                action: GqlPolicyAction::Drop,
                priority: 0,
                param: 0,
            }],
            id: None,
            sni: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            expires_after_secs: None,
            schedule: None,
        };

        let json = serde_json::to_string_pretty(&input).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["direction"], "EGRESS");
        assert_eq!(parsed["src"], "10.0.0.0/8");
        assert_eq!(parsed["dport"], 80);
        assert_eq!(parsed["protocol"], "tcp");
    }

    /// Test DeleteRuleInput with direction serialization
    #[test]
    fn test_delete_rule_input_with_direction() {
        let input = DeleteRuleInput {
            interface: "lo".to_string(),
            direction: GqlDirection::Ingress,
            id: Some("42".to_string()),
            src: None,
            dst: None,
            sport: None,
            dport: None,
            protocol: None,
        };

        let json = serde_json::to_string_pretty(&input).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["direction"], "INGRESS");
        assert_eq!(parsed["id"], "42");
    }
}
