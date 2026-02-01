// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use policy_controller_dev::{
    AuditEntry, ClientConfig, ControllerClient, CreateRuleInput, CreateRuleMultiNodeInput,
    EnrollmentTokenInfo, IssuedEnrollmentToken, Node, NodeInterface, OperationResult,
    PendingGeneration, Rule,
};
use serde::Serialize;

/// Default controller URL.
const DEFAULT_URL: &str = "http://127.0.0.1:8443";

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "policy-controller-client",
    about = "CLI client for the policy-controller operator API",
    version
)]
struct Cli {
    /// Base URL of the controller HTTP API.
    #[arg(long, global = true, default_value = DEFAULT_URL, env = "CONTROLLER_URL")]
    url: String,

    /// Bearer token for the controller's REST + GraphQL surface. Mint with
    /// `policy-controller-mint-token`. Required against any controller with
    /// the api_tokens migration applied.
    #[arg(long, global = true, env = "POLICY_CONTROLLER_TOKEN")]
    token: Option<String>,

    /// Output raw JSON instead of a formatted table.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Node management commands.
    #[command(subcommand)]
    Nodes(NodesCmd),
    /// Rule management commands.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Interface management commands.
    #[command(subcommand)]
    Interfaces(InterfacesCmd),
    /// In-flight config generation commands.
    #[command(subcommand)]
    Pending(PendingCmd),
    /// Audit log commands.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Print the controller CA certificate (PEM).
    CaCert,
    /// ZTP bootstrap token management.
    #[command(subcommand)]
    EnrollToken(EnrollTokenCmd),
}

// ── enroll-token subcommands ──────────────────────────────────────────────────

#[derive(Subcommand)]
enum EnrollTokenCmd {
    /// Mint a new bootstrap token and print the bundle to stdout. The bundle
    /// is shown exactly once — keep it safe, then revoke if leaked.
    Create {
        /// Enrollment endpoint URL embedded in the bundle (defaults to
        /// `--controller-url` with port 7776).
        #[arg(long)]
        enrollment_url: Option<String>,
        /// Management endpoint URL embedded in the bundle.
        #[arg(long)]
        controller_url: String,
        /// Token lifetime (e.g. `1h`, `30m`, `7d`). Defaults to 1h.
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Maximum number of nodes that may redeem this token.
        #[arg(long, default_value = "50")]
        max_uses: i64,
        /// Optional CIDR restricting which source addresses may redeem.
        #[arg(long)]
        cidr: Option<String>,
        /// Optional label applied to all nodes that enrol via this token.
        #[arg(long)]
        label: Option<String>,
        /// Print only the bundle on stdout (suitable for `> bundle.b64`).
        #[arg(long)]
        bundle_only: bool,
    },
    /// List all enrollment tokens (newest first).
    List,
    /// Revoke an enrollment token by its ID.
    Revoke { token_id: String },
}

// ── nodes subcommands ─────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum NodesCmd {
    /// List nodes (optionally filtered by status).
    List {
        /// Filter by status: pending, active, decommissioned.
        #[arg(long)]
        status: Option<String>,
    },
    /// Get a single node by ID.
    Get {
        /// Node ID.
        node_id: String,
    },
    /// List all pending enrollment requests.
    Pending,
    /// Approve a pending enrollment.
    Approve {
        /// Node ID to approve.
        node_id: String,
        /// Optional human-readable label.
        #[arg(long)]
        label: Option<String>,
    },
    /// Reject a pending enrollment.
    Reject {
        /// Node ID to reject.
        node_id: String,
        /// Optional reason for rejection.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Decommission an active node (revokes cert, blocks reconnect).
    Decommission {
        /// Node ID to decommission.
        node_id: String,
    },
    /// Remove a decommissioned node from the registry.
    Remove {
        /// Node ID to remove.
        node_id: String,
    },
    /// Set a human-readable label on a node.
    Label {
        /// Node ID.
        node_id: String,
        /// Label to set.
        label: String,
    },
    /// Push the current config to a specific node.
    Push {
        /// Node ID.
        node_id: String,
    },
    /// List currently-connected node IDs.
    Online,
}

// ── rules subcommands ─────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum RulesCmd {
    /// List rules for a node, optionally filtered by interface and direction.
    List {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Filter by interface name.
        #[arg(long)]
        interface: Option<String>,
        /// Filter by direction: ingress or egress.
        #[arg(long)]
        direction: Option<String>,
    },
    /// Create a rule on a single node.
    Create {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Interface name.
        #[arg(long)]
        interface: String,
        /// Direction: ingress or egress.
        #[arg(long)]
        direction: String,
        /// Actions as a JSON array, e.g. '[{"action":"drop","priority":0}]'.
        #[arg(long)]
        actions_json: String,
        /// Source CIDR (e.g. 10.0.0.0/8).
        #[arg(long)]
        src_cidr: Option<String>,
        /// Destination CIDR.
        #[arg(long)]
        dst_cidr: Option<String>,
        /// Source port.
        #[arg(long)]
        src_port: Option<u32>,
        /// Destination port.
        #[arg(long)]
        dst_port: Option<u32>,
        /// Protocol: tcp, udp, icmp, icmpv6, any.
        #[arg(long)]
        protocol: Option<String>,
        /// SNI pattern (TLS hostname glob).
        #[arg(long)]
        sni_pattern: Option<String>,
        /// QUIC version filter.
        #[arg(long)]
        quic_version: Option<String>,
        /// Source MAC address.
        #[arg(long)]
        src_mac: Option<String>,
        /// Destination MAC address.
        #[arg(long)]
        dst_mac: Option<String>,
    },
    /// Create the same rule on multiple nodes at once (space-separated --node-ids).
    CreateMultiNode {
        /// One or more node IDs (space-separated after the flag).
        #[arg(long, num_args = 1..)]
        node_ids: Vec<String>,
        /// Interface name.
        #[arg(long)]
        interface: String,
        /// Direction: ingress or egress.
        #[arg(long)]
        direction: String,
        /// Actions as a JSON array.
        #[arg(long)]
        actions_json: String,
        /// Source CIDR.
        #[arg(long)]
        src_cidr: Option<String>,
        /// Destination CIDR.
        #[arg(long)]
        dst_cidr: Option<String>,
        /// Source port.
        #[arg(long)]
        src_port: Option<u32>,
        /// Destination port.
        #[arg(long)]
        dst_port: Option<u32>,
        /// Protocol: tcp, udp, icmp, icmpv6, any.
        #[arg(long)]
        protocol: Option<String>,
        /// SNI pattern.
        #[arg(long)]
        sni_pattern: Option<String>,
        /// QUIC version filter.
        #[arg(long)]
        quic_version: Option<String>,
        /// Source MAC address.
        #[arg(long)]
        src_mac: Option<String>,
        /// Destination MAC address.
        #[arg(long)]
        dst_mac: Option<String>,
    },
    /// Delete a rule by ID.
    Delete {
        /// Rule ID to delete.
        rule_id: String,
    },
}

// ── interfaces subcommands ────────────────────────────────────────────────────

#[derive(Subcommand)]
enum InterfacesCmd {
    /// List interfaces on a node.
    List {
        /// Node ID.
        #[arg(long)]
        node_id: String,
    },
    /// List all interfaces across all nodes.
    ListAll,
    /// Tag an interface (e.g. WAN, LAN).
    Tag {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Interface name.
        #[arg(long)]
        name: String,
        /// Tag value.
        #[arg(long)]
        tag: String,
    },
    /// Remove a tag from an interface.
    Untag {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Interface name.
        #[arg(long)]
        name: String,
    },
    /// Attach a BPF program to an interface.
    Attach {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Interface name.
        #[arg(long)]
        name: String,
        /// Direction: ingress or egress.
        #[arg(long)]
        direction: String,
    },
    /// Detach a BPF program from an interface.
    Detach {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Interface name.
        #[arg(long)]
        name: String,
        /// Direction: ingress or egress.
        #[arg(long)]
        direction: String,
    },
    /// Enable or disable XDP FIB forwarding on an interface.
    SetFibForwarding {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Interface name.
        #[arg(long)]
        name: String,
        /// Enable (true) or disable (false).
        #[arg(long)]
        enabled: bool,
    },
    /// Set the default action for unmatched packets on an interface+direction.
    SetDefaultAction {
        /// Node ID.
        #[arg(long)]
        node_id: String,
        /// Interface name.
        #[arg(long)]
        name: String,
        /// Direction: ingress or egress.
        #[arg(long)]
        direction: String,
        /// Action: pass or drop.
        #[arg(long)]
        action: String,
    },
}

// ── pending subcommands ───────────────────────────────────────────────────────

#[derive(Subcommand)]
enum PendingCmd {
    /// List all in-flight config generations.
    List,
    /// Get the in-flight config generation for a specific node.
    Get {
        /// Node ID.
        #[arg(long)]
        node_id: String,
    },
}

// ── audit subcommands ─────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum AuditCmd {
    /// List audit log entries (newest first).
    List {
        /// Maximum number of entries to return.
        #[arg(long, default_value = "50")]
        limit: i32,
        /// Offset into the audit log.
        #[arg(long, default_value = "0")]
        offset: i32,
    },
}

// ── Command handlers ──────────────────────────────────────────────────────────

fn handle_nodes(client: &ControllerClient, cmd: NodesCmd, json: bool) -> Result<()> {
    match cmd {
        NodesCmd::List { status } => {
            let nodes = client.list_nodes(status)?;
            if json {
                print_json(&nodes)
            } else {
                print_table_nodes(&nodes)
            }
        }

        NodesCmd::Get { node_id } => {
            let node = client.get_node(&node_id)?;
            if json {
                print_json(&node);
            } else {
                match node {
                    None => println!("Node not found: {}", node_id),
                    Some(n) => print_node_detail(&n),
                }
            }
        }

        NodesCmd::Pending => {
            let nodes = client.pending_enrollments()?;
            if json {
                print_json(&nodes)
            } else {
                print_table_nodes(&nodes)
            }
        }

        NodesCmd::Approve { node_id, label } => {
            let n = client.approve_enrollment(&node_id, label)?;
            if json {
                print_json(&n);
            } else {
                println!(
                    "Approved: {} (status={}, label={:?})",
                    n.id,
                    n.status.as_deref().unwrap_or("?"),
                    n.label
                );
            }
        }

        NodesCmd::Reject { node_id, reason } => {
            let result = client.reject_enrollment(&node_id, reason)?;
            print_result(&result, json);
        }

        NodesCmd::Decommission { node_id } => {
            let result = client.decommission_node(&node_id)?;
            print_result(&result, json);
        }

        NodesCmd::Remove { node_id } => {
            let result = client.remove_node(&node_id)?;
            print_result(&result, json);
        }

        NodesCmd::Label { node_id, label } => {
            let result = client.label_node(&node_id, &label)?;
            print_result(&result, json);
        }

        NodesCmd::Push { node_id } => {
            let result = client.push_config(&node_id)?;
            print_result(&result, json);
        }

        NodesCmd::Online => {
            let ids = client.online_nodes()?;
            if json {
                print_json(&ids);
            } else if ids.is_empty() {
                println!("No nodes currently online.");
            } else {
                for id in ids {
                    println!("{}", id);
                }
            }
        }
    }
    Ok(())
}

fn handle_rules(client: &ControllerClient, cmd: RulesCmd, json: bool) -> Result<()> {
    match cmd {
        RulesCmd::List {
            node_id,
            interface,
            direction,
        } => {
            let rules = client.list_rules(&node_id, interface, direction)?;
            if json {
                print_json(&rules)
            } else {
                print_table_rules(&rules)
            }
        }

        RulesCmd::Create {
            node_id,
            interface,
            direction,
            actions_json,
            src_cidr,
            dst_cidr,
            src_port,
            dst_port,
            protocol,
            sni_pattern,
            quic_version,
            src_mac,
            dst_mac,
        } => {
            serde_json::from_str::<serde_json::Value>(&actions_json)
                .map_err(|e| anyhow::anyhow!("--actions-json is not valid JSON: {}", e))?;

            let rule = client.create_rule(CreateRuleInput {
                node_id,
                interface,
                direction,
                actions_json,
                src_cidr,
                dst_cidr,
                src_port,
                dst_port,
                protocol,
                sni_pattern,
                quic_version,
                src_mac,
                dst_mac,
            })?;

            if json {
                print_json(&rule);
            } else {
                println!(
                    "Created rule: {} on {}:{} ({})",
                    rule.id,
                    rule.node_id.as_deref().unwrap_or("?"),
                    rule.interface_name.as_deref().unwrap_or("?"),
                    rule.direction.as_deref().unwrap_or("?")
                );
            }
        }

        RulesCmd::CreateMultiNode {
            node_ids,
            interface,
            direction,
            actions_json,
            src_cidr,
            dst_cidr,
            src_port,
            dst_port,
            protocol,
            sni_pattern,
            quic_version,
            src_mac,
            dst_mac,
        } => {
            serde_json::from_str::<serde_json::Value>(&actions_json)
                .map_err(|e| anyhow::anyhow!("--actions-json is not valid JSON: {}", e))?;

            let rules = client.create_rules_multi_node(CreateRuleMultiNodeInput {
                node_ids,
                interface,
                direction,
                actions_json,
                src_cidr,
                dst_cidr,
                src_port,
                dst_port,
                protocol,
                sni_pattern,
                quic_version,
                src_mac,
                dst_mac,
            })?;

            if json {
                print_json(&rules)
            } else {
                print_table_rules(&rules)
            }
        }

        RulesCmd::Delete { rule_id } => {
            let result = client.delete_rule(&rule_id)?;
            print_result(&result, json);
        }
    }
    Ok(())
}

fn handle_interfaces(client: &ControllerClient, cmd: InterfacesCmd, json: bool) -> Result<()> {
    match cmd {
        InterfacesCmd::List { node_id } => {
            let ifaces = client.node_interfaces(&node_id)?;
            if json {
                print_json(&ifaces)
            } else {
                print_table_interfaces(&ifaces)
            }
        }

        InterfacesCmd::ListAll => {
            let ifaces = client.all_node_interfaces()?;
            if json {
                print_json(&ifaces)
            } else {
                print_table_interfaces(&ifaces)
            }
        }

        InterfacesCmd::Tag { node_id, name, tag } => {
            let result = client.tag_interface(&node_id, &name, &tag)?;
            print_result(&result, json);
        }

        InterfacesCmd::Untag { node_id, name } => {
            let result = client.untag_interface(&node_id, &name)?;
            print_result(&result, json);
        }

        InterfacesCmd::Attach {
            node_id,
            name,
            direction,
        } => {
            let result = client.attach_program(&node_id, &name, &direction)?;
            print_result(&result, json);
        }

        InterfacesCmd::Detach {
            node_id,
            name,
            direction,
        } => {
            let result = client.detach_program(&node_id, &name, &direction)?;
            print_result(&result, json);
        }

        InterfacesCmd::SetFibForwarding {
            node_id,
            name,
            enabled,
        } => {
            let result = client.set_fib_forwarding(&node_id, &name, enabled)?;
            print_result(&result, json);
        }

        InterfacesCmd::SetDefaultAction {
            node_id,
            name,
            direction,
            action,
        } => {
            let result =
                client.set_interface_default_action(&node_id, &name, &direction, &action)?;
            print_result(&result, json);
        }
    }
    Ok(())
}

fn handle_pending(client: &ControllerClient, cmd: PendingCmd, json: bool) -> Result<()> {
    match cmd {
        PendingCmd::List => {
            let gens = client.pending_generations()?;
            if json {
                print_json(&gens)
            } else {
                print_table_pending(&gens)
            }
        }

        PendingCmd::Get { node_id } => {
            let gen = client.pending_generation(&node_id)?;
            if json {
                print_json(&gen);
            } else {
                match gen {
                    None => println!("No in-flight generation for node: {}", node_id),
                    Some(g) => print_table_pending(std::slice::from_ref(&g)),
                }
            }
        }
    }
    Ok(())
}

fn handle_audit(client: &ControllerClient, cmd: AuditCmd, json: bool) -> Result<()> {
    match cmd {
        AuditCmd::List { limit, offset } => {
            let entries = client.audit_log(limit, offset)?;
            if json {
                print_json(&entries)
            } else {
                print_table_audit(&entries)
            }
        }
    }
    Ok(())
}

fn handle_ca_cert(client: &ControllerClient, json: bool) -> Result<()> {
    let pem = client.ca_cert_pem()?;
    if json {
        print_json(&pem);
    } else {
        print!("{}", pem);
    }
    Ok(())
}

fn handle_enroll_token(client: &ControllerClient, cmd: EnrollTokenCmd, json: bool) -> Result<()> {
    match cmd {
        EnrollTokenCmd::Create {
            enrollment_url,
            controller_url,
            ttl,
            max_uses,
            cidr,
            label,
            bundle_only,
        } => {
            let ttl_secs = parse_duration(&ttl)?;
            // If --enrollment-url is omitted, infer it from --controller-url with
            // port 7776 (the conventional split between mgmt and enrollment).
            let enrollment_url =
                enrollment_url.unwrap_or_else(|| infer_enrollment_url(&controller_url));
            let issued = client.create_enrollment_token(
                &enrollment_url,
                &controller_url,
                ttl_secs,
                max_uses,
                cidr.as_deref(),
                label.as_deref(),
            )?;
            if bundle_only {
                println!("{}", issued.bundle);
            } else if json {
                print_json(&issued);
            } else {
                print_issued_token(&issued);
            }
        }
        EnrollTokenCmd::List => {
            let tokens = client.list_enrollment_tokens()?;
            if json {
                print_json(&tokens);
            } else {
                print_token_list(&tokens);
            }
        }
        EnrollTokenCmd::Revoke { token_id } => {
            let r = client.revoke_enrollment_token(&token_id)?;
            print_result(&r, json);
        }
    }
    Ok(())
}

fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty duration");
    }
    let (num_part, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num_part
        .parse()
        .with_context(|| format!("Invalid duration: {}", s))?;
    let mult: i64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => anyhow::bail!("Unknown duration unit '{}' — use s/m/h/d", other),
    };
    Ok(n.saturating_mul(mult))
}

fn infer_enrollment_url(controller_url: &str) -> String {
    // Best-effort: swap :7777 → :7776. If no recognizable port, return as-is.
    if controller_url.contains(":7777") {
        controller_url.replacen(":7777", ":7776", 1)
    } else {
        controller_url.to_string()
    }
}

fn print_issued_token(t: &IssuedEnrollmentToken) {
    println!("Token id   : {}", t.token_id);
    if let Some(exp) = &t.expires_at {
        println!("Expires at : {}", exp);
    }
    println!("Max uses   : {}", t.uses_remaining);
    println!();
    println!("Bundle (drop into /etc/policy-node-agent/bootstrap.bundle on target hosts):");
    println!();
    println!("{}", t.bundle);
}

fn print_token_list(tokens: &[EnrollmentTokenInfo]) {
    if tokens.is_empty() {
        println!("(no tokens)");
        return;
    }
    println!(
        "{:<36}  {:>5}  {:<24}  {:<24}  {:<10}  {}",
        "TOKEN-ID", "USES", "CREATED", "EXPIRES", "STATUS", "LABEL"
    );
    for t in tokens {
        let status = if t.revoked_at.is_some() {
            "revoked"
        } else {
            "active"
        };
        println!(
            "{:<36}  {:>5}  {:<24}  {:<24}  {:<10}  {}",
            t.token_id,
            t.uses_remaining,
            t.created_at.as_deref().unwrap_or("-"),
            t.expires_at.as_deref().unwrap_or("-"),
            status,
            t.fleet_label.as_deref().unwrap_or("-"),
        );
    }
}

// ── Output formatting ─────────────────────────────────────────────────────────

fn print_json<T: Serialize>(v: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| "null".to_string())
    );
}

fn print_result(result: &OperationResult, json: bool) {
    if json {
        print_json(result);
        if !result.success {
            std::process::exit(1);
        }
    } else {
        print_op_result(result);
    }
}

fn print_op_result(result: &OperationResult) {
    let msg = result.message.as_deref().unwrap_or("");
    if result.success {
        println!(
            "OK{}",
            if msg.is_empty() {
                String::new()
            } else {
                format!(": {msg}")
            }
        );
    } else {
        eprintln!("FAILED: {msg}");
        std::process::exit(1);
    }
}

fn print_table_nodes(nodes: &[Node]) {
    if nodes.is_empty() {
        println!("(no nodes)");
        return;
    }

    println!(
        "{:<65} {:<14} {:<20} {:<8} LAST-SEEN",
        "ID", "STATUS", "LABEL", "TPM"
    );
    println!("{}", &"-".repeat(120));

    for n in nodes {
        let status = n.status.as_deref().unwrap_or("?");
        let label = n.label.as_deref().unwrap_or("—");
        let tpm = if n.tpm_backed.unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let last_seen = n.last_seen.as_deref().unwrap_or("never");
        println!(
            "{:<65} {:<14} {:<20} {:<8} {}",
            n.id, status, label, tpm, last_seen
        );
    }
}

fn print_node_detail(n: &Node) {
    let tpm = if n.tpm_backed.unwrap_or(false) {
        "yes"
    } else {
        "no"
    };
    let fields: &[(&str, &str)] = &[
        ("ID", &n.id),
        ("Status", n.status.as_deref().unwrap_or("?")),
        ("Label", n.label.as_deref().unwrap_or("—")),
        ("Hostname", n.hostname.as_deref().unwrap_or("—")),
        ("DMI UUID", n.dmi_uuid.as_deref().unwrap_or("—")),
        ("OS", n.os_pretty_name.as_deref().unwrap_or("—")),
        ("Kernel", n.kernel_version.as_deref().unwrap_or("—")),
        ("Vendor", n.dmi_sys_vendor.as_deref().unwrap_or("—")),
        ("Product", n.dmi_product_name.as_deref().unwrap_or("—")),
        ("Agent version", n.agent_version.as_deref().unwrap_or("—")),
        ("Tenant", n.tenant_id.as_deref().unwrap_or("—")),
        ("TPM-backed", tpm),
        ("Enrolled at", n.enrolled_at.as_deref().unwrap_or("—")),
        ("Last seen", n.last_seen.as_deref().unwrap_or("never")),
        ("Cert expiry", n.cert_expiry.as_deref().unwrap_or("—")),
    ];
    for (k, v) in fields {
        println!("{k:<16} {v}");
    }
}

fn print_table_rules(rules: &[Rule]) {
    if rules.is_empty() {
        println!("(no rules)");
        return;
    }

    println!(
        "{:<22} {:<20} {:<10} {:<8} {:<8} {:<18} {:<18} ACTIONS",
        "ID", "INTERFACE", "DIRECTION", "PROTO", "DST-PORT", "SRC-CIDR", "DST-CIDR"
    );
    println!("{}", &"-".repeat(140));

    for r in rules {
        let iface = r.interface_name.as_deref().unwrap_or("?");
        let dir = r.direction.as_deref().unwrap_or("?");
        let proto = r.protocol.as_deref().unwrap_or("any");
        let dst_port = r
            .dst_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());
        let src_cidr = r.src_cidr.as_deref().unwrap_or("—");
        let dst_cidr = r.dst_cidr.as_deref().unwrap_or("—");
        let actions = r.actions_json.as_deref().unwrap_or("[]");
        println!(
            "{:<22} {:<20} {:<10} {:<8} {:<8} {:<18} {:<18} {}",
            r.id, iface, dir, proto, dst_port, src_cidr, dst_cidr, actions
        );
    }
}

fn print_table_interfaces(ifaces: &[NodeInterface]) {
    if ifaces.is_empty() {
        println!("(no interfaces)");
        return;
    }

    println!(
        "{:<20} {:<14} {:<6} {:<5} {:<5} {:<5} {:<8} {:<8} TAG",
        "NODE-ID", "NAME", "STATE", "XDP", "TC", "FIB", "INGRESS", "EGRESS"
    );
    println!("{}", &"-".repeat(120));

    for i in ifaces {
        let short_id = &i.node_id[..i.node_id.len().min(18)];
        let state = i.link_state.as_deref().unwrap_or("?");
        let xdp = bool_str(i.xdp_attached.unwrap_or(false));
        let tc = bool_str(i.tc_attached.unwrap_or(false));
        let fib = bool_str(i.fib_forwarding.unwrap_or(false));
        let ingress = i.ingress_default_action.as_deref().unwrap_or("—");
        let egress = i.egress_default_action.as_deref().unwrap_or("—");
        let tag = i.tag.as_deref().unwrap_or("—");
        println!(
            "{short_id:<20} {:<14} {state:<6} {xdp:<5} {tc:<5} {fib:<5} {ingress:<8} {egress:<8} {tag}",
            i.name
        );
    }
}

fn print_table_pending(gens: &[PendingGeneration]) {
    if gens.is_empty() {
        println!("(no pending generations)");
        return;
    }

    println!(
        "{:<38} {:<38} {:<20} ISSUED-AT",
        "GENERATION-ID", "NODE-ID", "OP"
    );
    println!("{}", &"-".repeat(120));

    for g in gens {
        let gen_id = g.generation_id.as_deref().unwrap_or("?");
        let node_id = g.node_id.as_deref().unwrap_or("?");
        let op = g.op_kind.as_deref().unwrap_or("?");
        let issued = g.issued_at.as_deref().unwrap_or("?");
        println!("{gen_id:<38} {node_id:<38} {op:<20} {issued}");
    }
}

fn print_table_audit(entries: &[AuditEntry]) {
    if entries.is_empty() {
        println!("(no audit entries)");
        return;
    }

    println!(
        "{:<6} {:<28} {:<10} {:<26} {:<16} DETAIL",
        "ID", "TIMESTAMP", "OPERATOR", "ACTION", "NODE"
    );
    println!("{}", &"-".repeat(120));

    for e in entries {
        let id = e.id.map(|i| i.to_string()).unwrap_or_default();
        let ts = e.ts.as_deref().unwrap_or("?");
        let op = e.operator.as_deref().unwrap_or("system");
        let action = e.action.as_deref().unwrap_or("?");
        let node = e
            .node_id
            .as_deref()
            .map(|s| &s[..s.len().min(14)])
            .unwrap_or("—");
        let detail = e.detail.as_deref().unwrap_or("—");
        println!("{id:<6} {ts:<28} {op:<10} {action:<26} {node:<16} {detail}");
    }
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = ControllerClient::with_config(ClientConfig {
        base_url: cli.url,
        api_token: cli.token,
    });
    let json = cli.json;

    match cli.command {
        Cmd::Nodes(cmd) => handle_nodes(&client, cmd, json),
        Cmd::Rules(cmd) => handle_rules(&client, cmd, json),
        Cmd::Interfaces(cmd) => handle_interfaces(&client, cmd, json),
        Cmd::Pending(cmd) => handle_pending(&client, cmd, json),
        Cmd::Audit(cmd) => handle_audit(&client, cmd, json),
        Cmd::CaCert => handle_ca_cert(&client, json),
        Cmd::EnrollToken(cmd) => handle_enroll_token(&client, cmd, json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_result_success_no_message() {
        print_op_result(&OperationResult {
            success: true,
            message: None,
        });
    }

    #[test]
    fn test_op_result_success_with_message() {
        print_op_result(&OperationResult {
            success: true,
            message: Some("pushed to 3 nodes".to_string()),
        });
    }
}
