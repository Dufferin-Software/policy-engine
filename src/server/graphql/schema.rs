//! GraphQL schema with queries and mutations

use std::sync::Arc;
use std::time::Instant;

use async_graphql::{Context, EmptySubscription, Object, Result, Schema};
use log::info;
use tokio::sync::Mutex;

use crate::server::BpfManager;
use crate::types::{LpmKeyV4, LpmKeyV6, LpmPolicyEntry, PolicyAction};

use super::types::*;

/// Shared state for the GraphQL server
pub struct AppState {
    pub manager: Arc<Mutex<BpfManager>>,
    pub start_time: Instant,
}

impl AppState {
    pub fn new(manager: BpfManager) -> Self {
        Self {
            manager: Arc::new(Mutex::new(manager)),
            start_time: Instant::now(),
        }
    }
}

/// GraphQL Query root
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get server status
    async fn status<'ctx>(&self, ctx: &Context<'ctx>) -> Result<ServerStatus> {
        let state = ctx.data::<Arc<AppState>>()?;
        Ok(ServerStatus {
            running: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: state.start_time.elapsed().as_secs(),
        })
    }

    /// List all attached interfaces
    async fn interfaces<'ctx>(&self, _ctx: &Context<'ctx>) -> Result<Vec<InterfaceAttachment>> {
        let pinned = BpfManager::get_pinned_attachments(None);
        Ok(pinned
            .into_iter()
            .map(|(interface, ifindex, mode)| InterfaceAttachment {
                interface,
                ifindex,
                mode,
            })
            .collect())
    }

    /// Get global statistics for an interface
    async fn stats<'ctx>(&self, ctx: &Context<'ctx>, interface: String) -> Result<GlobalStatsOutput> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;
        
        // Ensure programs are loaded
        manager.load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        let ifindex = unsafe {
            let name = std::ffi::CString::new(interface.clone())
                .map_err(|e| async_graphql::Error::new(format!("Invalid interface name: {}", e)))?;
            libc::if_nametoindex(name.as_ptr())
        };

        if ifindex == 0 {
            return Err(async_graphql::Error::new(format!(
                "Interface {} not found",
                interface
            )));
        }

        let stats = manager
            .get_global_stats(ifindex)
            .map_err(|e| async_graphql::Error::new(format!("Failed to get stats: {}", e)))?;

        Ok(GlobalStatsOutput::from(stats))
    }

    /// Get ethertype statistics for an interface (non-IP traffic breakdown)
    async fn ethertype_stats<'ctx>(&self, ctx: &Context<'ctx>, interface: String) -> Result<Vec<EthertypeStatsOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;
        
        // Ensure programs are loaded
        manager.load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        let ifindex = unsafe {
            let name = std::ffi::CString::new(interface.clone())
                .map_err(|e| async_graphql::Error::new(format!("Invalid interface name: {}", e)))?;
            libc::if_nametoindex(name.as_ptr())
        };

        if ifindex == 0 {
            return Err(async_graphql::Error::new(format!(
                "Interface {} not found",
                interface
            )));
        }

        let stats = manager
            .get_ethertype_stats(ifindex)
            .map_err(|e| async_graphql::Error::new(format!("Failed to get ethertype stats: {}", e)))?;

        Ok(stats.into_iter().map(EthertypeStatsOutput::from).collect())
    }

    /// Get statistics for a specific rule
    async fn rule_stats<'ctx>(&self, ctx: &Context<'ctx>, rule_id: u64) -> Result<Option<RuleStatsOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;
        
        manager.load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        let stats = manager
            .get_rule_stats(rule_id)
            .map_err(|e| async_graphql::Error::new(format!("Failed to get rule stats: {}", e)))?;

        Ok(stats.map(|s| RuleStatsOutput {
            rule_id,
            packets: s.packets,
            bytes: s.bytes,
            last_seen_ns: s.last_seen_ns,
        }))
    }

    /// List all policy rules
    async fn rules<'ctx>(&self, ctx: &Context<'ctx>) -> Result<Vec<LpmRuleOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;
        
        manager.load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        let mut rules = Vec::new();

        // Get IPv4 rules
        let v4_rules = manager
            .list_lpm_rules_v4()
            .map_err(|e| async_graphql::Error::new(format!("Failed to list IPv4 rules: {}", e)))?;

        for (key, entry) in v4_rules {
            rules.push(lpm_entry_to_output(&key, &entry, false));
        }

        // Get IPv6 rules
        let v6_rules = manager
            .list_lpm_rules_v6()
            .map_err(|e| async_graphql::Error::new(format!("Failed to list IPv6 rules: {}", e)))?;

        for (key, entry) in v6_rules {
            rules.push(lpm_entry_to_output_v6(&key, &entry));
        }

        Ok(rules)
    }
}

/// GraphQL Mutation root
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Attach XDP program to an interface
    /// 
    /// Mode can be: "auto" (default), "offload", "native", or "generic"
    /// Auto mode tries offload → native → generic until one succeeds
    async fn attach_xdp<'ctx>(&self, ctx: &Context<'ctx>, input: AttachXdpInput) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        // Load programs first
        manager
            .load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        // Handle "auto" mode - try offload → native → generic
        if input.mode.to_lowercase() == "auto" {
            let modes_to_try = [
                (crate::types::XdpMode::Offload, "offload"),
                (crate::types::XdpMode::Native, "native"),
                (crate::types::XdpMode::Generic, "generic"),
            ];
            
            let mut last_error = String::new();
            for (mode, mode_name) in modes_to_try {
                match manager.attach_xdp(&input.interface, mode) {
                    Ok(()) => {
                        info!("Attached XDP to {} in {} mode (auto-selected)", input.interface, mode_name);
                        return Ok(OperationResult {
                            success: true,
                            message: format!("Attached XDP program to {} in {} mode (auto-selected)", input.interface, mode_name),
                        });
                    }
                    Err(e) => {
                        info!("Failed to attach XDP in {} mode: {}, trying next...", mode_name, e);
                        last_error = e.to_string();
                    }
                }
            }
            
            return Err(async_graphql::Error::new(format!(
                "Failed to attach XDP in any mode. Last error: {}", last_error
            )));
        }

        // Parse explicit mode
        let mode: GqlXdpMode = input
            .mode
            .parse()
            .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

        // Attach with specified mode
        manager
            .attach_xdp(&input.interface, mode.into())
            .map_err(|e| async_graphql::Error::new(format!("Failed to attach XDP: {}", e)))?;

        info!("Attached XDP to {} in {:?} mode", input.interface, mode);

        Ok(OperationResult {
            success: true,
            message: format!("Attached XDP program to {} in {} mode", input.interface, input.mode),
        })
    }

    /// Detach XDP program from an interface
    async fn detach_xdp<'ctx>(&self, ctx: &Context<'ctx>, input: DetachXdpInput) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        manager
            .detach_xdp(&input.interface)
            .map_err(|e| async_graphql::Error::new(format!("Failed to detach XDP: {}", e)))?;

        info!("Detached XDP from {}", input.interface);

        Ok(OperationResult {
            success: true,
            message: format!("Detached XDP program from {}", input.interface),
        })
    }

    /// Detach all XDP programs
    async fn detach_all<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        let pinned = BpfManager::get_pinned_attachments(None);
        let mut count = 0;

        for (ifname, _ifindex, _mode) in pinned {
            if manager.detach_xdp(&ifname).is_ok() {
                count += 1;
            }
        }

        info!("Detached {} XDP program(s)", count);

        Ok(OperationResult {
            success: true,
            message: format!("Detached {} program(s)", count),
        })
    }

    /// Add a policy rule
    async fn add_rule<'ctx>(&self, ctx: &Context<'ctx>, input: AddRuleInput) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        // Check if programs are attached
        let pinned = BpfManager::get_pinned_attachments(None);
        if pinned.is_empty() {
            return Err(async_graphql::Error::new(
                "No XDP programs attached. Use attachXdp first.",
            ));
        }

        // Load programs
        manager
            .load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        // Validate and parse actions
        if input.actions.is_empty() {
            return Err(async_graphql::Error::new("At least one action must be specified"));
        }

        // Validate action priorities
        let mut parsed_actions: Vec<(PolicyAction, u8)> = input
            .actions
            .iter()
            .map(|a| (a.action.into(), a.priority))
            .collect();
        parsed_actions.sort_by_key(|(_, p)| *p);

        // Parse protocol
        let protocol: GqlProtocol = input
            .protocol
            .parse()
            .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

        // Generate rule ID if not provided
        let rule_id = input.id.unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1)
        });

        // Parse source and destination networks
        let src_str = input.src.as_deref().unwrap_or("0.0.0.0/0");
        let dst_str = input.dst.as_deref().unwrap_or("0.0.0.0/0");

        let src_net: ipnetwork::IpNetwork = src_str
            .parse()
            .map_err(|e| async_graphql::Error::new(format!("Invalid source CIDR: {}", e)))?;
        let dst_net: ipnetwork::IpNetwork = dst_str
            .parse()
            .map_err(|e| async_graphql::Error::new(format!("Invalid destination CIDR: {}", e)))?;

        // Add rule based on IP version
        match (&src_net, &dst_net) {
            (ipnetwork::IpNetwork::V4(s), ipnetwork::IpNetwork::V4(d)) => {
                let lpm_key = LpmKeyV4::new(s.network(), s.prefix());
                let mut entry = LpmPolicyEntry::new_v4(
                    s.prefix(),
                    d.network(),
                    d.prefix(),
                    input.sport,
                    input.dport,
                    protocol.to_proto_number(),
                    rule_id,
                )
                .with_priority(input.priority);

                if let Some(slot) = input.tail_call_slot {
                    entry = entry.with_tail_call(slot);
                }

                entry.set_actions(
                    &parsed_actions
                        .iter()
                        .map(|(action, priority)| (*action, *priority))
                        .collect::<Vec<_>>(),
                );

                manager
                    .add_lpm_rule_v4(&lpm_key, &entry)
                    .map_err(|e| async_graphql::Error::new(format!("Failed to add rule: {}", e)))?;
            }
            (ipnetwork::IpNetwork::V6(s), ipnetwork::IpNetwork::V6(d)) => {
                let lpm_key = LpmKeyV6::new(s.network(), s.prefix());
                let mut entry = LpmPolicyEntry::new_v6(
                    s.prefix(),
                    d.network(),
                    d.prefix(),
                    input.sport,
                    input.dport,
                    protocol.to_proto_number(),
                    rule_id,
                )
                .with_priority(input.priority);

                if let Some(slot) = input.tail_call_slot {
                    entry = entry.with_tail_call(slot);
                }

                entry.set_actions(
                    &parsed_actions
                        .iter()
                        .map(|(action, priority)| (*action, *priority))
                        .collect::<Vec<_>>(),
                );

                manager
                    .add_lpm_rule_v6(&lpm_key, &entry)
                    .map_err(|e| async_graphql::Error::new(format!("Failed to add rule: {}", e)))?;
            }
            _ => {
                return Err(async_graphql::Error::new(
                    "Source and destination must be the same IP version",
                ));
            }
        }

        info!("Added rule {} with {} action(s)", rule_id, input.actions.len());

        Ok(OperationResult {
            success: true,
            message: format!("Added rule {} with {} action(s)", rule_id, input.actions.len()),
        })
    }

    /// Delete a policy rule
    /// 
    /// Can delete by ID or by match criteria (src, dst, sport, dport, protocol)
    async fn delete_rule<'ctx>(&self, ctx: &Context<'ctx>, input: DeleteRuleInput) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        manager
            .load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        // Delete by ID - find the rule and delete it
        if let Some(rule_id) = input.id {
            // Search IPv4 rules
            let v4_rules = manager
                .list_lpm_rules_v4()
                .map_err(|e| async_graphql::Error::new(format!("Failed to list rules: {}", e)))?;
            
            for (key, entry) in &v4_rules {
                if entry.rule_id == rule_id {
                    manager
                        .delete_lpm_rule_v4(key)
                        .map_err(|e| async_graphql::Error::new(format!("Failed to delete rule: {}", e)))?;
                    return Ok(OperationResult {
                        success: true,
                        message: format!("Deleted rule {}", rule_id),
                    });
                }
            }
            
            // Search IPv6 rules
            let v6_rules = manager
                .list_lpm_rules_v6()
                .map_err(|e| async_graphql::Error::new(format!("Failed to list rules: {}", e)))?;
            
            for (key, entry) in &v6_rules {
                if entry.rule_id == rule_id {
                    manager
                        .delete_lpm_rule_v6(key)
                        .map_err(|e| async_graphql::Error::new(format!("Failed to delete rule: {}", e)))?;
                    return Ok(OperationResult {
                        success: true,
                        message: format!("Deleted rule {}", rule_id),
                    });
                }
            }
            
            return Err(async_graphql::Error::new(format!("Rule {} not found", rule_id)));
        }

        // Delete by match criteria
        if let Some(src_str) = input.src {
            let src_net: ipnetwork::IpNetwork = src_str
                .parse()
                .map_err(|e| async_graphql::Error::new(format!("Invalid source CIDR: {}", e)))?;

            match src_net {
                ipnetwork::IpNetwork::V4(s) => {
                    let lpm_key = LpmKeyV4::new(s.network(), s.prefix());
                    manager
                        .delete_lpm_rule_v4(&lpm_key)
                        .map_err(|e| async_graphql::Error::new(format!("Failed to delete rule: {}", e)))?;
                }
                ipnetwork::IpNetwork::V6(s) => {
                    let lpm_key = LpmKeyV6::new(s.network(), s.prefix());
                    manager
                        .delete_lpm_rule_v6(&lpm_key)
                        .map_err(|e| async_graphql::Error::new(format!("Failed to delete rule: {}", e)))?;
                }
            }

            Ok(OperationResult {
                success: true,
                message: "Deleted rule".to_string(),
            })
        } else {
            Err(async_graphql::Error::new("Must specify either id or src"))
        }
    }

    /// Flush all rules
    async fn flush_rules<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        manager
            .load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        let v4_rules = manager
            .list_lpm_rules_v4()
            .map_err(|e| async_graphql::Error::new(format!("Failed to list rules: {}", e)))?;
        let v6_rules = manager
            .list_lpm_rules_v6()
            .map_err(|e| async_graphql::Error::new(format!("Failed to list rules: {}", e)))?;

        let count = v4_rules.len() + v6_rules.len();

        for (key, _) in v4_rules {
            let _ = manager.delete_lpm_rule_v4(&key);
        }
        for (key, _) in v6_rules {
            let _ = manager.delete_lpm_rule_v6(&key);
        }

        info!("Flushed {} rules", count);

        Ok(OperationResult {
            success: true,
            message: format!("Flushed {} rules", count),
        })
    }

    /// Set default action for unmatched packets
    async fn set_default_action<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: DefaultActionInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        manager
            .load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        let action: PolicyAction = input.action.into();
        manager
            .set_default_action(action)
            .map_err(|e| async_graphql::Error::new(format!("Failed to set default action: {}", e)))?;

        info!("Set default action to {:?}", action);

        Ok(OperationResult {
            success: true,
            message: format!("Default action set to {:?}", action),
        })
    }

    /// Register a tail call program
    async fn register_tail_call<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: TailCallInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut manager = state.manager.lock().await;

        manager
            .load_programs()
            .map_err(|e| async_graphql::Error::new(format!("Failed to load programs: {}", e)))?;

        manager
            .register_tail_call(input.slot, &input.program)
            .map_err(|e| async_graphql::Error::new(format!("Failed to register tail call: {}", e)))?;

        info!("Registered {} at slot {}", input.program, input.slot);

        Ok(OperationResult {
            success: true,
            message: format!("Registered {} at slot {}", input.program, input.slot),
        })
    }
}

/// Convert LPM entry to GraphQL output (IPv4)
fn lpm_entry_to_output(key: &LpmKeyV4, entry: &LpmPolicyEntry, _is_v6: bool) -> LpmRuleOutput {
    use std::net::Ipv4Addr;

    // Copy values from packed struct to avoid unaligned access
    let prefixlen = key.prefixlen;
    // key.addr is stored in network byte order, use to_ne_bytes() to get the octets
    let src_addr = Ipv4Addr::from(key.addr.to_ne_bytes());
    let src_prefix = format!("{}/{}", src_addr, prefixlen);

    let dst_addr = Ipv4Addr::from(<[u8; 4]>::try_from(&entry.daddr[..4]).unwrap());
    let dst_prefixlen = entry.dst_prefixlen;
    let dst_prefix = format!("{}/{}", dst_addr, dst_prefixlen);

    let num_actions = entry.num_actions;
    let mut actions = Vec::new();
    for i in 0..num_actions as usize {
        let action = &entry.actions[i];
        let action_val = action.action;
        let priority = action.priority;
        actions.push(RuleActionOutput {
            action: PolicyAction::from(action_val).into(),
            priority,
        });
    }

    let rule_id = entry.rule_id;
    let sport = entry.sport;
    let dport = entry.dport;
    let protocol = entry.protocol;
    let priority = entry.priority;

    LpmRuleOutput {
        rule_id,
        src_prefix,
        dst_prefix,
        sport,
        dport,
        protocol: GqlProtocol::from_proto_number(protocol),
        priority,
        actions,
        is_ipv6: false,
    }
}

/// Convert LPM entry to GraphQL output (IPv6)
fn lpm_entry_to_output_v6(key: &LpmKeyV6, entry: &LpmPolicyEntry) -> LpmRuleOutput {
    use std::net::Ipv6Addr;

    // Copy values from packed struct to avoid unaligned access
    let prefixlen = key.prefixlen;
    let mut src_octets = [0u8; 16];
    for i in 0..4 {
        let bytes = u32::to_be_bytes(key.addr[i]);
        src_octets[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    let src_addr = Ipv6Addr::from(src_octets);
    let src_prefix = format!("{}/{}", src_addr, prefixlen);

    let dst_addr = Ipv6Addr::from(entry.daddr);
    let dst_prefixlen = entry.dst_prefixlen;
    let dst_prefix = format!("{}/{}", dst_addr, dst_prefixlen);

    let num_actions = entry.num_actions;
    let mut actions = Vec::new();
    for i in 0..num_actions as usize {
        let action = &entry.actions[i];
        let action_val = action.action;
        let priority = action.priority;
        actions.push(RuleActionOutput {
            action: PolicyAction::from(action_val).into(),
            priority,
        });
    }

    let rule_id = entry.rule_id;
    let sport = entry.sport;
    let dport = entry.dport;
    let protocol = entry.protocol;
    let priority = entry.priority;

    LpmRuleOutput {
        rule_id,
        src_prefix,
        dst_prefix,
        sport,
        dport,
        protocol: GqlProtocol::from_proto_number(protocol),
        priority,
        actions,
        is_ipv6: true,
    }
}

/// Build the GraphQL schema
pub type PolicyEngineSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub fn build_schema(state: Arc<AppState>) -> PolicyEngineSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(state)
        .finish()
}
