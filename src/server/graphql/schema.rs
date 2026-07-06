// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! GraphQL schema with queries and mutations
//!
//! This module provides the GraphQL API layer. All business logic is delegated
//! to PolicyService, keeping this layer thin and focused on type conversions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_graphql::{Context, EmptySubscription, Object, Result, Schema};
use log::{error, info};
use tokio::sync::Mutex;

use crate::config::AffinityPlan;
use crate::server::audit_logger::{AuditBackend, AuditEntry, NoopAuditLogger};
use crate::server::cpu_affinity::{self, DefaultNicSysIo, NicAffinityStore};
use crate::server::policy_service::{AddRuleParams, DeleteRuleParams, PolicyService};
use crate::server::rule_registry::{RuleLifecycleKind, RuleState};
#[cfg(feature = "suricata")]
use crate::server::{EveConsumer, SuricataAlert, SuricataCoordinator, VethManager};
#[cfg(feature = "suricata")]
use crate::types::InspectMode;
use crate::types::{ActionParams, Direction, PolicyAction};
#[cfg(feature = "suricata")]
use tokio::sync::broadcast;

use super::types::*;

/// Tracks bandwidth samples for estimating bytes/sec between queries.
pub struct BandwidthTracker {
    #[allow(clippy::type_complexity)]
    last: Mutex<HashMap<(String, u8), (Instant, u64, u64)>>,
}

impl BandwidthTracker {
    fn new() -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
        }
    }

    async fn sample(&self, iface: &str, direction: u8, rx: u64, tx: u64) -> (i64, i64) {
        let mut map = self.last.lock().await;
        let key = (iface.to_string(), direction);
        let now = Instant::now();
        if let Some((prev_time, prev_rx, prev_tx)) = map.get(&key).copied() {
            let elapsed = now.duration_since(prev_time).as_secs_f64();
            let rx_bps = if elapsed > 0.0 {
                ((rx.saturating_sub(prev_rx)) as f64 / elapsed) as i64
            } else {
                0
            };
            let tx_bps = if elapsed > 0.0 {
                ((tx.saturating_sub(prev_tx)) as f64 / elapsed) as i64
            } else {
                0
            };
            map.insert(key, (now, rx, tx));
            (rx_bps, tx_bps)
        } else {
            map.insert(key, (now, rx, tx));
            (0, 0)
        }
    }
}

/// Windows the cumulative processing-time histogram between polls, mirroring
/// BandwidthTracker: percentiles are computed over the samples that arrived
/// since the previous poll of the same (interface, direction).  The raw
/// histogram is cumulative since attach, so its percentiles stop moving once
/// enough history accumulates; the per-poll delta reflects current behavior.
pub struct TimingTracker {
    #[allow(clippy::type_complexity)]
    last: Mutex<HashMap<(String, u8), (Vec<u64>, TimingStatsOutput)>>,
}

impl TimingTracker {
    fn new() -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
        }
    }

    /// Compute timing stats over the histogram delta since the previous poll.
    /// The first poll falls back to the cumulative histogram; an idle window
    /// (no new samples, or counters that went backwards after a stats clear)
    /// returns the previous poll's stats so the display holds its last known
    /// value instead of flickering between windowed and lifetime numbers.
    async fn sample(&self, iface: &str, direction: u8, current: &[u64]) -> TimingStatsOutput {
        let mut map = self.last.lock().await;
        let key = (iface.to_string(), direction);
        let out = match map.get(&key) {
            Some((prev_hist, prev_out)) => {
                let delta: Vec<u64> = current
                    .iter()
                    .zip(prev_hist.iter())
                    .map(|(c, p)| c.saturating_sub(*p))
                    .collect();
                if delta.iter().any(|&v| v > 0) {
                    compute_timing_stats(&delta)
                } else {
                    prev_out.clone()
                }
            }
            None => compute_timing_stats(current),
        };
        map.insert(key, (current.to_vec(), out.clone()));
        out
    }
}

/// Shared state for the GraphQL server
pub struct AppState {
    pub service: Arc<Mutex<PolicyService>>,
    pub start_time: Instant,
    #[cfg(feature = "suricata")]
    pub veth_manager: Arc<Mutex<VethManager>>,
    #[cfg(feature = "suricata")]
    pub suricata_coordinator: Arc<SuricataCoordinator>,
    #[cfg(feature = "suricata")]
    pub eve_consumer: Arc<Mutex<EveConsumer>>,
    /// Outbound Suricata alert stream served by `/ws/alerts`. Fed by the IPS
    /// enforcement loop, which re-broadcasts every EVE alert after verdict
    /// installation with `action` rewritten to "blocked" when the flow was
    /// actually dropped (Suricata itself is never inline and always reports
    /// "allowed").
    #[cfg(feature = "suricata")]
    pub alert_stream_tx: broadcast::Sender<SuricataAlert>,
    pub bandwidth_tracker: BandwidthTracker,
    pub timing_tracker: TimingTracker,
    pub affinity: Arc<AffinityPlan>,
    /// Tracks pre-attach NIC IRQ/RPS affinity snapshots so they can be restored on detach.
    pub nic_affinity_store: Mutex<NicAffinityStore>,
    /// Audit backend — always present; defaults to [`NoopAuditLogger`].
    pub audit_logger: Arc<dyn AuditBackend>,
    /// Running total of IPFIX flow records exported by the background task.
    #[cfg(feature = "ipfix")]
    pub flows_exported_total: Arc<std::sync::atomic::AtomicU64>,
}

impl AppState {
    #[cfg(feature = "suricata")]
    pub fn new(
        service: PolicyService,
        veth_manager: VethManager,
        suricata_coordinator: SuricataCoordinator,
        eve_consumer: EveConsumer,
        affinity: Arc<AffinityPlan>,
    ) -> Self {
        Self {
            service: Arc::new(Mutex::new(service)),
            start_time: Instant::now(),
            veth_manager: Arc::new(Mutex::new(veth_manager)),
            suricata_coordinator: Arc::new(suricata_coordinator),
            eve_consumer: Arc::new(Mutex::new(eve_consumer)),
            alert_stream_tx: broadcast::channel(1024).0,
            bandwidth_tracker: BandwidthTracker::new(),
            timing_tracker: TimingTracker::new(),
            affinity,
            nic_affinity_store: Mutex::new(NicAffinityStore::new()),
            audit_logger: Arc::new(NoopAuditLogger),
            #[cfg(feature = "ipfix")]
            flows_exported_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    #[cfg(not(feature = "suricata"))]
    pub fn new(service: PolicyService, affinity: Arc<AffinityPlan>) -> Self {
        Self {
            service: Arc::new(Mutex::new(service)),
            start_time: Instant::now(),
            bandwidth_tracker: BandwidthTracker::new(),
            timing_tracker: TimingTracker::new(),
            affinity,
            nic_affinity_store: Mutex::new(NicAffinityStore::new()),
            audit_logger: Arc::new(NoopAuditLogger),
            #[cfg(feature = "ipfix")]
            flows_exported_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn with_audit_logger(mut self, logger: Arc<dyn AuditBackend>) -> Self {
        self.audit_logger = logger;
        self
    }
}

/// GraphQL Query root
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get server status
    async fn status<'ctx>(&self, ctx: &Context<'ctx>) -> Result<ServerStatus> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let status = service.get_status();

        // Get inspect mode from BPF config
        #[cfg(feature = "suricata")]
        let inspect_mode = service
            .get_inspect_config(Direction::Ingress)
            .ok()
            .and_then(|c| match InspectMode::from(c.mode) {
                InspectMode::Ips => Some("IPS".to_string()),
                InspectMode::Ids => Some("IDS".to_string()),
                InspectMode::Disabled => None,
            });
        #[cfg(not(feature = "suricata"))]
        let inspect_mode: Option<String> = None;

        #[cfg(feature = "suricata")]
        let suricata_running = Some(state.suricata_coordinator.is_running());
        #[cfg(not(feature = "suricata"))]
        let suricata_running: Option<bool> = None;

        let cpu_affinity = CpuAffinityStatus {
            disabled: state.affinity.disabled,
            control_cpus: state
                .affinity
                .control_cpus
                .iter()
                .map(|&c| c as i32)
                .collect(),
            event_cpus: state
                .affinity
                .event_cpus
                .iter()
                .map(|&c| c as i32)
                .collect(),
            dataplane_cpus: state
                .affinity
                .dataplane_cpus
                .iter()
                .map(|&c| c as i32)
                .collect(),
            actix_workers: state.affinity.actix_workers as i32,
        };

        Ok(ServerStatus {
            running: status.running,
            version: status.version,
            uptime_secs: status.uptime_secs,
            program_attached: status.program_attached,
            inspect_mode,
            suricata_running,
            cpu_affinity,
        })
    }

    /// Get server compile-time feature flags
    async fn server_features(&self) -> ServerFeaturesOutput {
        ServerFeaturesOutput {
            suricata: cfg!(feature = "suricata"),
            ipfix: cfg!(feature = "ipfix"),
        }
    }

    /// List per-interface XDP FIB forwarding state.
    async fn fib_forwarding<'ctx>(
        &self,
        ctx: &Context<'ctx>,
    ) -> Result<Vec<crate::server::graphql::types::FibForwardingEntry>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let entries = service
            .list_fib_forwarding()
            .map_err(|e| async_graphql::Error::new(format!("{:#}", e)))?;
        Ok(entries
            .into_iter()
            .map(
                |(interface, enabled)| crate::server::graphql::types::FibForwardingEntry {
                    interface,
                    enabled,
                },
            )
            .collect())
    }

    /// List per-interface uRPF (unicast Reverse Path Forwarding) mode.
    /// Only interfaces with uRPF enabled are returned.
    async fn urpf<'ctx>(
        &self,
        ctx: &Context<'ctx>,
    ) -> Result<Vec<crate::server::graphql::types::UrpfEntry>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let entries = service
            .list_urpf()
            .map_err(|e| async_graphql::Error::new(format!("{:#}", e)))?;
        Ok(entries
            .into_iter()
            .map(
                |(interface, mode)| crate::server::graphql::types::UrpfEntry {
                    interface,
                    mode: mode.into(),
                },
            )
            .collect())
    }

    /// IPFIX flow export status and configuration
    #[cfg(feature = "ipfix")]
    async fn flow_export_status<'ctx>(
        &self,
        ctx: &Context<'ctx>,
    ) -> Result<FlowExportStatusOutput> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let config = service.get_flow_export_config().clone();
        let active_count = service.get_active_flow_count();
        let exported = state
            .flows_exported_total
            .load(std::sync::atomic::Ordering::Relaxed);
        Ok(FlowExportStatusOutput {
            enabled: config.enabled,
            collector_host: config.collector_host,
            collector_port: config.collector_port as i32,
            idle_timeout_s: config.idle_timeout_s as i32,
            active_timeout_s: config.active_timeout_s as i32,
            flows_exported_total: exported as i64,
            active_flow_count: active_count as i64,
        })
    }

    /// List all attached interfaces
    async fn interfaces<'ctx>(&self, _ctx: &Context<'ctx>) -> Result<Vec<InterfaceAttachment>> {
        let state = _ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let interfaces = service.get_interfaces();

        Ok(interfaces
            .into_iter()
            .map(|i| InterfaceAttachment {
                interface: i.interface,
                ifindex: i.ifindex,
                mode: i.mode,
                direction: i.direction,
            })
            .collect())
    }

    /// List all available network interfaces on the system
    async fn available_interfaces(&self, _ctx: &Context<'_>) -> Result<Vec<String>> {
        use std::fs;
        let mut interfaces = Vec::new();
        let entries = fs::read_dir("/sys/class/net")
            .map_err(|e| async_graphql::Error::new(format!("Failed to list interfaces: {}", e)))?;
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if crate::types::is_internal_interface(&name) {
                    continue;
                }
                interfaces.push(name);
            }
        }
        interfaces.sort();
        Ok(interfaces)
    }

    /// Get global statistics for an interface
    async fn stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<GlobalStatsOutput> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut service = state.service.lock().await;

        if !service.is_direction_loaded(direction.into()) {
            return Ok(GlobalStatsOutput::from(crate::types::GlobalStats::default()));
        }

        let ifindex = get_ifindex(&interface)?;

        let stats = service
            .get_global_stats(ifindex, direction.into())
            .map_err(|e| async_graphql::Error::new(format!("Failed to get stats: {}", e)))?;

        Ok(GlobalStatsOutput::from(stats))
    }

    /// Get ethertype statistics for an interface (non-IP traffic breakdown)
    async fn ethertype_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<Vec<EthertypeStatsOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut service = state.service.lock().await;

        if !service.is_direction_loaded(direction.into()) {
            return Ok(vec![]);
        }

        let ifindex = get_ifindex(&interface)?;

        let stats = service
            .get_ethertype_stats(ifindex, direction.into())
            .map_err(|e| {
                async_graphql::Error::new(format!("Failed to get ethertype stats: {}", e))
            })?;

        Ok(stats.into_iter().map(EthertypeStatsOutput::from).collect())
    }

    /// Get non-IP sender statistics for an interface (ingress only).
    /// Returns one entry per (source MAC, ethertype) pair, sorted by packet count desc.
    async fn nonip_senders<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
    ) -> Result<Vec<NonIpSenderOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut service = state.service.lock().await;

        if !service.is_direction_loaded(Direction::Ingress) {
            return Ok(vec![]);
        }

        let ifindex = get_ifindex(&interface)?;

        let senders = service.get_nonip_senders(ifindex).map_err(|e| {
            async_graphql::Error::new(format!("Failed to get non-IP senders: {}", e))
        })?;

        Ok(senders.into_iter().map(NonIpSenderOutput::from).collect())
    }

    /// Get statistics for a specific rule
    async fn rule_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        rule_id: String,
        direction: GqlDirection,
    ) -> Result<Option<RuleStatsOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut service = state.service.lock().await;

        if !service.is_direction_loaded(direction.into()) {
            return Ok(None);
        }

        let rule_id: u64 = rule_id
            .parse()
            .map_err(|e| async_graphql::Error::new(format!("Invalid rule ID: {}", e)))?;

        let stats = service
            .get_rule_stats(rule_id, direction.into())
            .map_err(|e| async_graphql::Error::new(format!("Failed to get rule stats: {}", e)))?;

        Ok(stats.map(|s| RuleStatsOutput {
            packets: s.packets,
            bytes: s.bytes,
            last_seen_ns: s.last_seen_ns,
        }))
    }

    /// List all policy rules for a direction
    async fn rules<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        direction: GqlDirection,
    ) -> Result<Vec<LpmRuleOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut service = state.service.lock().await;

        if !service.is_direction_loaded(direction.into()) {
            return Ok(vec![]);
        }

        let dir: crate::types::Direction = direction.into();
        let (v4_rules, v6_rules) = service
            .list_rules(dir)
            .map_err(|e| async_graphql::Error::new(format!("Failed to list rules: {}", e)))?;

        let mut rules = Vec::new();

        for (src_key, dst_key, rule) in v4_rules {
            let sni = if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                service.get_sni_rule(rule.rule_id, dir)
            } else {
                None
            };
            let mac = if rule.mac_match_flags != 0 {
                service.get_mac_rule(rule.rule_id, dir)
            } else {
                None
            };
            rules.push(lpm_entry_to_output_v4(&src_key, &dst_key, &rule, sni, mac));
        }
        for (src_key, dst_key, rule) in v6_rules {
            let sni = if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                service.get_sni_rule(rule.rule_id, dir)
            } else {
                None
            };
            let mac = if rule.mac_match_flags != 0 {
                service.get_mac_rule(rule.rule_id, dir)
            } else {
                None
            };
            rules.push(lpm_entry_to_output_v6(&src_key, &dst_key, &rule, sni, mac));
        }

        Ok(rules)
    }

    /// Return the current default action for a specific interface+direction ("PASS" or "DROP").
    /// Returns "PASS" when no default has been explicitly set.
    async fn default_action<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<String> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let dir: crate::types::Direction = direction.into();
        let action = service
            .get_default_action(dir, &interface)
            .map(|a| format!("{:?}", a).to_uppercase())
            .unwrap_or_else(|| "PASS".to_string());
        Ok(action)
    }

    /// List rules that have a TTL or schedule (managed rules).
    ///
    /// Returns all managed rules regardless of their current state (active or
    /// inactive). Rules without a lifecycle constraint are not included here —
    /// use the `rules` query for those.
    async fn managed_rules<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        direction: GqlDirection,
    ) -> Result<Vec<ManagedRuleOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let dir: crate::types::Direction = direction.into();

        let managed = service.list_managed_rules();
        let mut out = Vec::new();

        for rule in managed {
            if rule.direction != dir {
                continue;
            }
            let p = &rule.params;

            // Derive prefix strings from params (default 0.0.0.0/0 if not set).
            let src_prefix = p.src.clone().unwrap_or_else(|| "0.0.0.0/0".to_string());
            let dst_prefix = p.dst.clone().unwrap_or_else(|| "0.0.0.0/0".to_string());

            let actions: Vec<RuleActionOutput> = p
                .actions
                .iter()
                .map(|(action, priority, ap)| {
                    let param_ms = match ap {
                        ActionParams::Log { rate_limit_ns } => (rate_limit_ns / 1_000_000) as i64,
                        ActionParams::None => 0,
                    };
                    RuleActionOutput {
                        action: GqlPolicyAction::from(*action),
                        priority: *priority,
                        param: param_ms,
                    }
                })
                .collect();

            let (expires_at_ms, schedule_out) = match &rule.lifecycle {
                RuleLifecycleKind::Ttl { expires_at } => {
                    let ms = expires_at.timestamp_millis().to_string();
                    (Some(ms), None)
                }
                RuleLifecycleKind::Scheduled { schedule } => {
                    let windows_out = schedule
                        .windows
                        .iter()
                        .map(|w| WeeklyWindowOutput {
                            start: WeeklyTimePointOutput {
                                day_of_week: w.start.day_of_week as i32,
                                hour: w.start.hour as i32,
                                minute: w.start.minute as i32,
                            },
                            end: WeeklyTimePointOutput {
                                day_of_week: w.end.day_of_week as i32,
                                hour: w.end.hour as i32,
                                minute: w.end.minute as i32,
                            },
                        })
                        .collect();
                    let sched_out = RuleScheduleOutput {
                        windows: windows_out,
                        timezone: schedule.timezone.clone(),
                    };
                    (None, Some(sched_out))
                }
            };

            let rule_state = match rule.state {
                RuleState::Active => "active".to_string(),
                RuleState::Inactive => "inactive".to_string(),
            };

            out.push(ManagedRuleOutput {
                rule_id: async_graphql::ID(rule.rule_id.to_string()),
                direction,
                interface: ifindex_to_name(rule.params.ifindex),
                src_prefix,
                dst_prefix,
                sport: p.sport as i32,
                dport: p.dport as i32,
                protocol: protocol_to_gql(&p.protocol),
                actions,
                sni: p.sni.clone(),
                quic_version: quic_version_to_string(p.quic_version),
                expires_at_ms,
                schedule: schedule_out,
                rule_state,
            });
        }

        Ok(out)
    }

    /// Get inspect/IPS status
    #[cfg(feature = "suricata")]
    async fn inspect_status<'ctx>(&self, ctx: &Context<'ctx>) -> Result<InspectStatusOutput> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;

        let config = service
            .get_inspect_config(Direction::Ingress)
            .unwrap_or_default();
        let verdict_count = service
            .get_flow_verdict_count(Direction::Ingress)
            .unwrap_or(0)
            + service
                .get_flow_verdict_count(Direction::Egress)
                .unwrap_or(0);

        // TC ingress clones INSPECT-matched flows to pe-inspect0 (mirror side);
        // Suricata listens on pe-inspect1 (the veth peer).
        let veth = state.veth_manager.lock().await;
        let (mirror_interface, mirror_ifindex, peer_interface) = if veth.is_up() {
            let ifidx = veth.get_ifindex().ok().map(|i| i as i32);
            (
                Some(veth.veth_name().to_string()),
                ifidx,
                Some(veth.peer_name().to_string()),
            )
        } else {
            (None, None, None)
        };
        drop(veth);

        let mode = match InspectMode::from(config.mode) {
            InspectMode::Ips => GqlInspectMode::Ips,
            InspectMode::Ids => GqlInspectMode::Ids,
            InspectMode::Disabled => GqlInspectMode::Disabled,
        };

        let custom_rule_files = state
            .suricata_coordinator
            .list_custom_rules_meta()
            .into_iter()
            .map(|meta| CustomRuleFileOutput {
                filename: meta.filename,
                rule_count: meta.rules.len() as i32,
                rules: meta.rules,
                sha256: meta.sha256,
            })
            .collect();

        let enabled_interfaces = service.list_inspect_interfaces().unwrap_or_default();

        Ok(InspectStatusOutput {
            mode,
            suricata_running: state.suricata_coordinator.is_running(),
            mirror_interface,
            mirror_ifindex,
            peer_interface,
            flow_verdict_count: verdict_count as i64,
            suricata_version: state.suricata_coordinator.suricata_version(),
            ruleset_version: state.suricata_coordinator.ruleset_version(),
            custom_rule_files,
            enabled_interfaces,
        })
    }

    /// Get flow verdict statistics for a direction
    async fn flow_verdicts<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        direction: GqlDirection,
    ) -> Result<FlowVerdictStatsOutput> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        let count = service
            .get_flow_verdict_count(direction.into())
            .unwrap_or(0);
        Ok(FlowVerdictStatsOutput {
            active_verdicts: count as i64,
        })
    }

    /// List individual flow verdict entries for a direction.
    ///
    /// Entries are returned soonest-expiring first and capped at `limit`
    /// (default 1000) to bound the response — the cache can hold tens of
    /// thousands of entries per direction.
    async fn flow_verdict_list<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        direction: GqlDirection,
        limit: Option<i32>,
    ) -> Result<Vec<FlowVerdictOutput>> {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let limit = limit.unwrap_or(1000).max(0) as usize;

        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;

        let verdicts = service
            .list_flow_verdicts(direction.into())
            .unwrap_or_default();

        // Use CLOCK_MONOTONIC to match bpf_ktime_get_ns() used for expires_ns.
        let now_ns = {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        };

        let mut result: Vec<FlowVerdictOutput> = verdicts
            .into_iter()
            .map(|(key, verdict)| {
                let (src_ip, dst_ip) = if key.af == crate::types::AF_INET {
                    let src =
                        Ipv4Addr::from(<[u8; 4]>::try_from(&key.saddr[..4]).unwrap_or_default());
                    let dst =
                        Ipv4Addr::from(<[u8; 4]>::try_from(&key.daddr[..4]).unwrap_or_default());
                    (src.to_string(), dst.to_string())
                } else {
                    let src = Ipv6Addr::from(key.saddr);
                    let dst = Ipv6Addr::from(key.daddr);
                    (src.to_string(), dst.to_string())
                };

                // Copy packed-struct fields to locals before use (E0793)
                let verdict_action = verdict.action;
                let verdict_expires_ns = verdict.expires_ns;
                let verdict_packets = verdict.packets;
                let verdict_bytes = verdict.bytes;

                let protocol = crate::types::Protocol::from(key.protocol).to_string();
                let action = crate::types::PolicyAction::from(verdict_action).to_string();
                let expired = verdict_expires_ns > 0 && now_ns >= verdict_expires_ns;

                FlowVerdictOutput {
                    src_ip,
                    dst_ip,
                    src_port: key.sport as i32,
                    dst_port: key.dport as i32,
                    protocol,
                    action,
                    expires_ns: verdict_expires_ns.to_string(),
                    expired,
                    packets: verdict_packets as i64,
                    bytes: verdict_bytes as i64,
                }
            })
            .collect();

        // Soonest-expiring first. A zero `expires_ns` means "never expires";
        // sort those last so live, time-bounded entries surface at the top.
        result.sort_by_key(|v| {
            let e: u64 = v.expires_ns.parse().unwrap_or(0);
            if e == 0 {
                u64::MAX
            } else {
                e
            }
        });
        result.truncate(limit);

        Ok(result)
    }

    /// Get Suricata service status
    #[cfg(feature = "suricata")]
    async fn suricata_status<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let running = state.suricata_coordinator.is_running();
        Ok(OperationResult {
            success: running,
            message: if running {
                "Suricata is running".to_string()
            } else {
                "Suricata is not running".to_string()
            },
        })
    }

    /// Get performance statistics (timing histogram, per-protocol stats, bandwidth)
    async fn performance_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<PerformanceStatsOutput> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut service = state.service.lock().await;

        if !service.is_direction_loaded(direction.into()) {
            return Ok(empty_perf_stats());
        }

        let dir: Direction = direction.into();
        let ifindex = get_ifindex(&interface)?;
        let global = service.get_global_stats(ifindex, dir).unwrap_or_default();

        let dir_byte: u8 = match dir {
            Direction::Ingress => 0,
            Direction::Egress => 1,
        };
        let (rx_bps, tx_bps) = state
            .bandwidth_tracker
            .sample(&interface, dir_byte, global.rx_bytes, global.tx_bytes)
            .await;

        // Timing / proto / L3 breakdowns are read from the per-interface
        // GlobalStats fetched above, so the panel is scoped to the selected
        // interface.  (These used to come from the direction-global getters,
        // which made every interface display identical values.)
        // Percentiles are windowed over the samples since the previous poll
        // (see TimingTracker) rather than the cumulative lifetime histogram.
        let timing = state
            .timing_tracker
            .sample(&interface, dir_byte, &global.proc_hist)
            .await;

        let proto_stats: Vec<ProtoStatsOutput> = global
            .proto
            .iter()
            .enumerate()
            .filter(|(_, ps)| ps.packets > 0)
            .map(|(proto, ps)| ProtoStatsOutput {
                protocol: proto as i32,
                name: proto_name(proto as u8).to_string(),
                packets: ps.packets as i64,
                bytes: ps.bytes as i64,
            })
            .collect();

        // L3 breakdown: buckets 0=IPv4, 1=IPv6, 2=ARP, 3=MPLS, 4=Other
        const L3_ETHERTYPES: [i32; 5] = [0x0800, 0x86DD, 0x0806, 0x8847, 0];
        const L3_NAMES: [&str; 5] = ["IPv4", "IPv6", "ARP", "MPLS", "Other"];
        let l3_stats: Vec<ProtoStatsOutput> = global
            .l3
            .iter()
            .enumerate()
            .filter(|(_, ps)| ps.packets > 0)
            .map(|(i, ps)| ProtoStatsOutput {
                protocol: L3_ETHERTYPES[i],
                name: L3_NAMES[i].to_string(),
                packets: ps.packets as i64,
                bytes: ps.bytes as i64,
            })
            .collect();

        Ok(PerformanceStatsOutput {
            timing,
            proto_stats,
            l3_stats,
            rx_bytes_per_sec: rx_bps,
            tx_bytes_per_sec: tx_bps,
        })
    }

    /// Query QUIC version stats (ingress only; egress returns empty)
    async fn quic_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        direction: GqlDirection,
    ) -> Result<Vec<QuicStatsOutput>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let mut service = state.service.lock().await;
        let dir: Direction = direction.into();
        let stats = service.get_quic_stats(dir).unwrap_or_default();
        Ok(stats
            .into_iter()
            .map(|(version, packets, bytes)| QuicStatsOutput {
                version,
                packets,
                bytes,
            })
            .collect())
    }

    /// Query recent audit log entries
    async fn audit_log<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        limit: Option<i32>,
    ) -> Result<Vec<AuditEntry>> {
        let state = ctx.data::<Arc<AppState>>()?;
        let limit = limit.unwrap_or(100).clamp(1, 1000) as usize;
        Ok(state.audit_logger.recent_entries(limit))
    }

    /// Export audit log entries within an optional time window.
    ///
    /// `format` selects the output (`"csv"` or `"json"`). `from`/`to` are
    /// optional inclusive RFC 3339 timestamps; either may be omitted to leave
    /// that side of the window open. Entries are read from the durable on-disk
    /// log, not just the in-memory ring.
    async fn export_audit_log<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        format: String,
        from: Option<String>,
        to: Option<String>,
    ) -> Result<AuditExport> {
        let state = ctx.data::<Arc<AppState>>()?;
        let exporter = crate::server::audit_export::exporter_for(&format)
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        let from = parse_opt_rfc3339(from.as_deref())?;
        let to = parse_opt_rfc3339(to.as_deref())?;
        let entries = state.audit_logger.entries_between(from, to);
        let data = exporter
            .export(&entries)
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(AuditExport {
            filename: format!(
                "audit-export-{}.{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
                exporter.extension()
            ),
            content_type: exporter.content_type().to_string(),
            data,
        })
    }

    /// Get the current stop behavior setting.
    async fn stop_behavior<'ctx>(&self, ctx: &Context<'ctx>) -> Result<StopBehaviorOutput> {
        let state = ctx.data::<Arc<AppState>>()?;
        let service = state.service.lock().await;
        Ok(StopBehaviorOutput {
            behavior: service.get_stop_behavior().to_string(),
        })
    }
}

/// GraphQL Mutation root
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Attach ingress program to an interface
    ///
    /// Mode can be: "auto" (default), "offload", "native", or "generic"
    /// Auto mode tries offload → native → generic until one succeeds
    async fn attach_ingress<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: AttachIngressInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let result = if input.mode.to_lowercase() == "auto" {
            service.attach_ingress_auto(&input.interface)
        } else {
            let mode: GqlIngressMode = input
                .mode
                .parse()
                .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;
            service.attach_ingress(&input.interface, mode.into())
        };

        let op = result.map_err(|e| {
            error!("{:#}", e);
            async_graphql::Error::new(format!("{:#}", e))
        })?;

        if op.success && !state.affinity.disabled {
            drop(service);
            state
                .nic_affinity_store
                .lock()
                .await
                .on_attach(&input.interface, &DefaultNicSysIo);
            cpu_affinity::apply_nic_affinity(
                &input.interface,
                &state.affinity.dataplane_cpus,
                &DefaultNicSysIo,
            );
        }

        state.audit_logger.log_event(
            "attach_ingress",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Detach ingress program from an interface
    async fn detach_ingress<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: DetachIngressInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service.detach_ingress(&input.interface).map_err(|e| {
            error!("{:#}", e);
            async_graphql::Error::new(format!("{:#}", e))
        })?;

        if op.success && !state.affinity.disabled {
            drop(service);
            if let Some(snap) = state
                .nic_affinity_store
                .lock()
                .await
                .on_detach(&input.interface)
            {
                cpu_affinity::restore_nic_affinity(&input.interface, &snap, &DefaultNicSysIo);
            }
        }

        state.audit_logger.log_event(
            "detach_ingress",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Attach egress program to an interface
    async fn attach_tc<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: AttachTcInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service.attach_tc(&input.interface).map_err(|e| {
            error!("{:#}", e);
            async_graphql::Error::new(format!("{:#}", e))
        })?;

        if op.success && !state.affinity.disabled {
            drop(service);
            state
                .nic_affinity_store
                .lock()
                .await
                .on_attach(&input.interface, &DefaultNicSysIo);
            cpu_affinity::apply_nic_affinity(
                &input.interface,
                &state.affinity.dataplane_cpus,
                &DefaultNicSysIo,
            );
        }

        state.audit_logger.log_event(
            "attach_tc",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Detach egress program from an interface
    async fn detach_tc<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: DetachTcInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service.detach_tc(&input.interface).map_err(|e| {
            error!("{:#}", e);
            async_graphql::Error::new(format!("{:#}", e))
        })?;

        if op.success && !state.affinity.disabled {
            drop(service);
            if let Some(snap) = state
                .nic_affinity_store
                .lock()
                .await
                .on_detach(&input.interface)
            {
                cpu_affinity::restore_nic_affinity(&input.interface, &snap, &DefaultNicSysIo);
            }
        }

        state.audit_logger.log_event(
            "detach_tc",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Detach all programs (both ingress and egress)
    async fn detach_all<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service.detach_all().map_err(|e| {
            error!("{:#}", e);
            async_graphql::Error::new(format!("{:#}", e))
        })?;

        if op.success && !state.affinity.disabled {
            drop(service);
            let snapshots = state.nic_affinity_store.lock().await.drain_all();
            for (ifname, snap) in snapshots {
                cpu_affinity::restore_nic_affinity(&ifname, &snap, &DefaultNicSysIo);
            }
        }

        state.audit_logger.log_event(
            "detach_all",
            serde_json::Value::Null,
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Add a policy rule
    async fn add_rule<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: AddRuleInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let params = input_to_add_params(&input)?;

        let op = service
            .add_rule(params)
            .map_err(|e| async_graphql::Error::new(format!("{:#}", e)))?;

        state.audit_logger.log_event(
            "add_rule",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Add multiple policy rules in a batch (more efficient than individual adds)
    async fn add_rules<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        rules: Vec<AddRuleInput>,
    ) -> Result<BatchAddRulesResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let total = rules.len() as u32;

        // Convert inputs to params, collecting parse errors per-rule
        let mut params_list = Vec::with_capacity(rules.len());
        let mut early_errors: Vec<(usize, String)> = Vec::new();

        for (index, input) in rules.iter().enumerate() {
            match input_to_add_params(input) {
                Ok(p) => params_list.push((index, p)),
                Err(e) => early_errors.push((index, e.message)),
            }
        }

        // Call the batch method for all successfully parsed params
        let batch_params: Vec<AddRuleParams> = params_list.iter().map(|(_, p)| p.clone()).collect();
        // Use direction from first rule (all rules in a batch target the same direction)
        let direction: Direction = batch_params
            .first()
            .map(|p| p.direction)
            .unwrap_or(Direction::Ingress);
        let batch_results = service.add_rules_batch(batch_params, direction);

        // Merge results: early parse errors + batch results
        let mut results: Vec<BatchRuleResult> = Vec::with_capacity(total as usize);
        let mut succeeded = 0u32;
        let mut failed = 0u32;

        // Build a map from original index to batch result
        let mut batch_iter = batch_results.into_iter();

        for index in 0..total as usize {
            if let Some(pos) = early_errors.iter().position(|(i, _)| *i == index) {
                let (_, ref error) = early_errors[pos];
                failed += 1;
                results.push(BatchRuleResult {
                    index: index as u32,
                    rule_id: None,
                    success: false,
                    error: Some(error.clone()),
                });
            } else if let Some(br) = batch_iter.next() {
                if br.success {
                    succeeded += 1;
                    results.push(BatchRuleResult {
                        index: index as u32,
                        rule_id: br.rule_id.map(|id| async_graphql::ID::from(id.to_string())),
                        success: true,
                        error: None,
                    });
                } else {
                    failed += 1;
                    results.push(BatchRuleResult {
                        index: index as u32,
                        rule_id: None,
                        success: false,
                        error: br.error,
                    });
                }
            }
        }

        let success = failed == 0;
        let message = if success {
            format!("Successfully added {} rules", succeeded)
        } else {
            format!("Added {} rules, {} failed", succeeded, failed)
        };

        info!("{}", message);

        state.audit_logger.log_event(
            "add_rules",
            serde_json::json!({"count": total}),
            if success { "ok" } else { "error" },
            &message,
            &source_ip,
        );
        Ok(BatchAddRulesResult {
            total,
            succeeded,
            failed,
            success,
            message,
            results,
        })
    }

    /// Delete multiple policy rules in a batch
    async fn delete_rules<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        rules: Vec<DeleteRuleInput>,
    ) -> Result<BatchDeleteRulesResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let total = rules.len() as u32;
        let mut results: Vec<BatchRuleResult> = Vec::with_capacity(rules.len());
        let mut succeeded = 0u32;
        let mut failed = 0u32;

        for (index, input) in rules.into_iter().enumerate() {
            let id = match input.id.to_string().parse::<u64>() {
                Ok(v) => v,
                Err(e) => {
                    failed += 1;
                    results.push(BatchRuleResult {
                        index: index as u32,
                        rule_id: Some(input.id.clone()),
                        success: false,
                        error: Some(format!("Invalid rule ID: {}", e)),
                    });
                    continue;
                }
            };

            let params = DeleteRuleParams {
                direction: input.direction.into(),
                id,
            };

            match service.delete_rule(params) {
                Ok(_) => {
                    succeeded += 1;
                    results.push(BatchRuleResult {
                        index: index as u32,
                        rule_id: Some(input.id),
                        success: true,
                        error: None,
                    });
                }
                Err(e) => {
                    failed += 1;
                    results.push(BatchRuleResult {
                        index: index as u32,
                        rule_id: Some(input.id),
                        success: false,
                        error: Some(format!("{}", e)),
                    });
                }
            }
        }

        let success = failed == 0;
        let message = if success {
            format!("Successfully deleted {} rules", succeeded)
        } else {
            format!("Deleted {} rules, {} failed", succeeded, failed)
        };

        state.audit_logger.log_event(
            "delete_rules",
            serde_json::json!({"count": total}),
            if success { "ok" } else { "error" },
            &message,
            &source_ip,
        );
        Ok(BatchDeleteRulesResult {
            total,
            succeeded,
            failed,
            success,
            message,
            results,
        })
    }

    /// Delete a policy rule by ID.
    async fn delete_rule<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: DeleteRuleInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let input_json = serde_json::to_value(&input).unwrap_or(serde_json::Value::Null);
        let id = input
            .id
            .to_string()
            .parse::<u64>()
            .map_err(|e| async_graphql::Error::new(format!("Invalid rule ID: {}", e)))?;

        let params = DeleteRuleParams {
            direction: input.direction.into(),
            id,
        };

        let op = service
            .delete_rule(params)
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        state.audit_logger.log_event(
            "delete_rule",
            input_json,
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Flush all rules scoped to a single interface+direction.
    async fn flush_rules<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);

        // An interface that doesn't exist can't hold any rules, so flushing it
        // is a trivial no-op rather than an error.
        let ifindex = match crate::server::graphql::resolve_ifindex(&interface) {
            Ok(ifindex) => ifindex,
            Err(_) => {
                let op = OperationResult {
                    success: true,
                    message: format!("No rules to flush; interface {} not present", interface),
                };
                state.audit_logger.log_event(
                    "flush_rules",
                    serde_json::json!({
                        "interface": interface,
                        "direction": format!("{:?}", direction),
                    }),
                    "ok",
                    &op.message,
                    &source_ip,
                );
                return Ok(op);
            }
        };

        let mut service = state.service.lock().await;

        let op = service
            .flush_rules(ifindex, direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        state.audit_logger.log_event(
            "flush_rules",
            serde_json::json!({
                "interface": interface,
                "direction": format!("{:?}", direction),
            }),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Set default action for unmatched packets on a specific interface
    async fn set_default_action<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: DefaultActionInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let ifindex = get_ifindex(&input.interface)?;
        let action: PolicyAction = input.action.into();
        let op = service
            .set_default_action(action, input.direction.into(), ifindex, &input.interface)
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        state.audit_logger.log_event(
            "set_default_action",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Register a tail call program
    async fn register_tail_call<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: TailCallInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service
            .register_tail_call(input.slot, &input.program, input.direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        state.audit_logger.log_event(
            "register_tail_call",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Enable or disable XDP FIB forwarding (line-rate packet forwarding via bpf_fib_lookup)
    async fn set_fib_forwarding<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: SetFibForwardingInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service
            .set_fib_forwarding(&input.interface, input.enabled)
            .map_err(|e| async_graphql::Error::new(format!("{:#}", e)))?;

        state.audit_logger.log_event(
            "set_fib_forwarding",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Set the uRPF (unicast Reverse Path Forwarding) mode on a single ingress
    /// interface. uRPF is ingress-only (XDP); enabling it on an interface
    /// without XDP attached (e.g. a TC egress interface) is rejected.
    async fn set_urpf<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: crate::server::graphql::types::SetUrpfInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let mode: u32 = input.mode.into();
        let op = service
            .set_urpf(&input.interface, mode)
            .map_err(|e| async_graphql::Error::new(format!("{:#}", e)))?;

        state.audit_logger.log_event(
            "set_urpf",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Set the stop behavior for the policy engine daemon.
    ///
    /// `input.stop_behavior` must be "clear-state" or "preserve-state".
    /// "clear-state" (default): detach all BPF programs and remove pinned maps on shutdown.
    /// "preserve-state": leave programs attached and maps in the kernel (traffic
    /// enforcement continues while the daemon is not running).
    async fn configure_stop_behavior<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: ConfigureStopBehaviorInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let behavior: crate::types::StopBehavior = input
            .stop_behavior
            .parse()
            .map_err(|e: anyhow::Error| async_graphql::Error::new(e.to_string()))?;

        let result = service.set_stop_behavior(behavior);
        let op = match result {
            Ok(()) => crate::server::policy_service::OperationResult::success(format!(
                "Stop behavior set to: {}",
                behavior
            )),
            Err(e) => crate::server::policy_service::OperationResult::failure(format!("{:#}", e)),
        };

        state.audit_logger.log_event(
            "configure_stop_behavior",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Enable or disable IPFIX flow export and set collector parameters
    #[cfg(feature = "ipfix")]
    async fn configure_flow_export<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: ConfigureFlowExportInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let current = service.get_flow_export_config().clone();
        let audit_value = serde_json::to_value(&input).unwrap_or(serde_json::Value::Null);
        let new_config = crate::types::FlowExportConfig {
            enabled: input.enabled,
            collector_host: input.collector_host.unwrap_or(current.collector_host),
            collector_port: input
                .collector_port
                .map(|p| p as u16)
                .unwrap_or(current.collector_port),
            idle_timeout_s: input
                .idle_timeout_s
                .map(|s| s as u32)
                .unwrap_or(current.idle_timeout_s),
            active_timeout_s: input
                .active_timeout_s
                .map(|s| s as u32)
                .unwrap_or(current.active_timeout_s),
        };

        let op = service
            .configure_flow_export(new_config)
            .map_err(|e| async_graphql::Error::new(format!("{:#}", e)))?;

        state.audit_logger.log_event(
            "configure_flow_export",
            audit_value,
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Clear global statistics for an interface
    async fn clear_global_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let ifindex = get_ifindex(&interface)?;

        let op = service
            .clear_global_stats(ifindex, direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        let msg = format!("Cleared global stats for {}", interface);
        state.audit_logger.log_event(
            "clear_global_stats",
            serde_json::json!({"interface": interface, "direction": format!("{:?}", direction)}),
            if op.success { "ok" } else { "error" },
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: msg,
        })
    }

    /// Clear statistics for a specific rule
    async fn clear_rule_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        rule_id: String,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let rule_id: u64 = rule_id
            .parse()
            .map_err(|e| async_graphql::Error::new(format!("Invalid rule ID: {}", e)))?;

        let op = service
            .clear_rule_stats(rule_id, direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        state.audit_logger.log_event(
            "clear_rule_stats",
            serde_json::json!({"rule_id": rule_id, "direction": format!("{:?}", direction)}),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Clear statistics for all rules
    async fn clear_all_rule_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service
            .clear_all_rule_stats(direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        state.audit_logger.log_event(
            "clear_all_rule_stats",
            serde_json::json!({"direction": format!("{:?}", direction)}),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Clear ethertype statistics for an interface
    async fn clear_ethertype_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let ifindex = get_ifindex(&interface)?;

        let op = service
            .clear_ethertype_stats(ifindex, direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        let msg = format!("Cleared ethertype stats for {}", interface);
        state.audit_logger.log_event(
            "clear_ethertype_stats",
            serde_json::json!({"interface": interface, "direction": format!("{:?}", direction)}),
            if op.success { "ok" } else { "error" },
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: msg,
        })
    }

    /// Clear all statistics for an interface (global + ethertype)
    async fn clear_interface_stats<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let ifindex = get_ifindex(&interface)?;

        let op = service
            .clear_interface_stats(ifindex, direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        let msg = format!("Cleared all stats for {}", interface);
        state.audit_logger.log_event(
            "clear_interface_stats",
            serde_json::json!({"interface": interface, "direction": format!("{:?}", direction)}),
            if op.success { "ok" } else { "error" },
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: msg,
        })
    }

    /// Clear all statistics
    async fn clear_all_stats<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;

        let op = service
            .clear_all_stats()
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;

        state.audit_logger.log_event(
            "clear_all_stats",
            serde_json::Value::Null,
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Configure inspect/IPS mode
    #[cfg(feature = "suricata")]
    async fn configure_inspect<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: ConfigureInspectInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);

        let mode = match input.mode {
            GqlInspectMode::Ips => InspectMode::Ips,
            GqlInspectMode::Ids => InspectMode::Ids,
            GqlInspectMode::Disabled => InspectMode::Disabled,
        };

        // Full enable/disable sequence (veth, BPF config, EVE consumer,
        // Suricata config/timer) lives in inspect_orchestrator so the
        // startup restore path runs exactly the same code.
        let op = match crate::server::inspect_orchestrator::enable_inspect(state, mode).await {
            Ok(op) => op,
            Err(e) => {
                let msg = format!("{:#}", e);
                state.audit_logger.log_event(
                    "configure_inspect",
                    serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
                    "error",
                    &msg,
                    &source_ip,
                );
                return Err(async_graphql::Error::new(msg));
            }
        };

        state.audit_logger.log_event(
            "configure_inspect",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Disable inspect/IPS mode
    #[cfg(feature = "suricata")]
    async fn disable_inspect<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);

        let op = crate::server::inspect_orchestrator::disable_inspect(state)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{:#}", e)))?;

        state.audit_logger.log_event(
            "disable_inspect",
            serde_json::Value::Null,
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Enable or disable Suricata inspection on a single interface.  Only
    /// interfaces with this flag set have their INSPECT-matched flows
    /// mirrored to Suricata; the node-global inspect mode (configureInspect)
    /// must also be active for inspection to occur.
    #[cfg(feature = "suricata")]
    async fn set_inspect_interface<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        interface: String,
        enabled: bool,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);

        let mut service = state.service.lock().await;
        let op = service
            .set_inspect_interface(&interface, enabled)
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;
        drop(service);

        state.audit_logger.log_event(
            "set_inspect_interface",
            serde_json::json!({ "interface": interface, "enabled": enabled }),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Deploy Suricata rules to the rules directory
    #[cfg(feature = "suricata")]
    async fn deploy_suricata_rules<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: DeploySuricataRulesInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        state
            .suricata_coordinator
            .write_rules(&input.filename, &input.rules)
            .map_err(|e| async_graphql::Error::new(format!("Failed to deploy rules: {}", e)))?;
        let msg = format!("Rules written to {}", input.filename);
        state.audit_logger.log_event(
            "deploy_suricata_rules",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Reload Suricata rules
    #[cfg(feature = "suricata")]
    async fn reload_suricata_rules<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        state
            .suricata_coordinator
            .reload_rules()
            .map_err(|e| async_graphql::Error::new(format!("Failed to reload: {}", e)))?;
        let msg = "Suricata rules reloaded".to_string();
        state.audit_logger.log_event(
            "reload_suricata_rules",
            serde_json::Value::Null,
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Write the AF-XDP Suricata config and systemd drop-in, then restart
    ///
    /// Derives the interface from the current veth pair (pe-inspect1).
    /// Requires that the veth pair already exists (call configureInspect first).
    #[cfg(feature = "suricata")]
    async fn apply_suricata_config<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let veth = state.veth_manager.lock().await;
        if !veth.is_up() {
            let msg = "Veth pair not ready. Enable IPS mode first.".to_string();
            state.audit_logger.log_event(
                "apply_suricata_config",
                serde_json::Value::Null,
                "error",
                &msg,
                &source_ip,
            );
            return Ok(OperationResult {
                success: false,
                message: msg,
            });
        }
        let peer = veth.peer_name().to_string();
        drop(veth);
        state
            .suricata_coordinator
            .apply_config(&peer)
            .map_err(|e| {
                async_graphql::Error::new(format!("Failed to apply Suricata config: {}", e))
            })?;
        let msg = format!("Suricata config applied for AF-XDP interface {}", peer);
        state.audit_logger.log_event(
            "apply_suricata_config",
            serde_json::Value::Null,
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Start the Suricata systemd service
    #[cfg(feature = "suricata")]
    async fn start_suricata<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        state
            .suricata_coordinator
            .start()
            .map_err(|e| async_graphql::Error::new(format!("Failed to start Suricata: {}", e)))?;
        let msg = "Suricata started".to_string();
        state.audit_logger.log_event(
            "start_suricata",
            serde_json::Value::Null,
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Stop the Suricata systemd service
    #[cfg(feature = "suricata")]
    async fn stop_suricata<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        state
            .suricata_coordinator
            .stop()
            .map_err(|e| async_graphql::Error::new(format!("Failed to stop Suricata: {}", e)))?;
        let msg = "Suricata stopped".to_string();
        state.audit_logger.log_event(
            "stop_suricata",
            serde_json::Value::Null,
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Clear flow verdicts for a direction
    async fn clear_flow_verdicts<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let mut service = state.service.lock().await;
        let op = service
            .clear_flow_verdicts(direction.into())
            .map_err(|e| async_graphql::Error::new(format!("{}", e)))?;
        state.audit_logger.log_event(
            "clear_flow_verdicts",
            serde_json::json!({"direction": format!("{:?}", direction)}),
            if op.success { "ok" } else { "error" },
            &op.message,
            &source_ip,
        );
        Ok(OperationResult {
            success: op.success,
            message: op.message,
        })
    }

    /// Add a single custom Suricata rule to a rules file
    #[cfg(feature = "suricata")]
    async fn add_custom_rule<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filename: String,
        rule: String,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        state
            .suricata_coordinator
            .add_rule(&filename, &rule)
            .map_err(|e| async_graphql::Error::new(format!("Failed to add rule: {}", e)))?;
        let msg = format!("Rule added to {}", filename);
        state.audit_logger.log_event(
            "add_custom_rule",
            serde_json::json!({"filename": filename, "rule": rule}),
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Delete custom Suricata rules by SID from a rules file
    #[cfg(feature = "suricata")]
    async fn delete_custom_rules<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        input: DeleteCustomRulesInput,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let sids: Vec<u32> = input.sids.iter().map(|&s| s.max(0) as u32).collect();
        let removed = state
            .suricata_coordinator
            .delete_rules_by_sid(&input.filename, &sids)
            .map_err(|e| async_graphql::Error::new(format!("Failed to delete rules: {}", e)))?;
        let msg = format!("Removed {} rule(s) from {}", removed, input.filename);
        state.audit_logger.log_event(
            "delete_custom_rules",
            serde_json::to_value(&input).unwrap_or(serde_json::Value::Null),
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Delete an entire custom Suricata rules file
    #[cfg(feature = "suricata")]
    async fn delete_rule_file<'ctx>(
        &self,
        ctx: &Context<'ctx>,
        filename: String,
    ) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        state
            .suricata_coordinator
            .delete_rule_file(&filename)
            .map_err(|e| async_graphql::Error::new(format!("Failed to delete rule file: {}", e)))?;
        let msg = format!("Deleted rule file {}", filename);
        state.audit_logger.log_event(
            "delete_rule_file",
            serde_json::json!({"filename": filename}),
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }

    /// Delete all custom Suricata rule files from the policy-engine rules directory
    #[cfg(feature = "suricata")]
    async fn delete_all_custom_rules<'ctx>(&self, ctx: &Context<'ctx>) -> Result<OperationResult> {
        let state = ctx.data::<Arc<AppState>>()?;
        let source_ip = get_source_ip(ctx);
        let count = state
            .suricata_coordinator
            .delete_all_custom_rules()
            .map_err(|e| async_graphql::Error::new(format!("Failed to delete rules: {}", e)))?;
        let msg = format!("Deleted {} custom rule file(s)", count);
        state.audit_logger.log_event(
            "delete_all_custom_rules",
            serde_json::Value::Null,
            "ok",
            &msg,
            &source_ip,
        );
        Ok(OperationResult {
            success: true,
            message: msg,
        })
    }
}

fn empty_perf_stats() -> PerformanceStatsOutput {
    PerformanceStatsOutput {
        timing: TimingStatsOutput {
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
            p999_ns: 0,
            total_samples: 0,
            buckets: vec![0; crate::types::HIST_BUCKETS],
        },
        proto_stats: vec![],
        l3_stats: vec![],
        rx_bytes_per_sec: 0,
        tx_bytes_per_sec: 0,
    }
}

fn compute_timing_stats(hist: &[u64]) -> TimingStatsOutput {
    let total: u64 = hist.iter().sum();
    let buckets: Vec<i64> = hist.iter().map(|&v| v as i64).collect();

    if total == 0 {
        return TimingStatsOutput {
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
            p999_ns: 0,
            total_samples: 0,
            buckets,
        };
    }

    // Linear interpolation within the log2 bucket that contains the target
    // rank.  Bucket k holds samples in [2^k, 2^(k+1)) ns (bucket 0 holds
    // 0-1 ns); returning only the bucket midpoint would snap every percentile
    // onto the 1.5*2^k lattice, making p50/p95/p99 read as exact multiples of
    // each other and hiding movement within a bucket.
    let percentile = |frac: f64| -> i64 {
        let target = ((total as f64 * frac).ceil() as u64).max(1);
        let mut cumulative = 0u64;
        for (k, &count) in hist.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let before = cumulative;
            cumulative += count;
            if cumulative >= target {
                let (lo, width) = if k == 0 {
                    (0.0, 2.0)
                } else {
                    let lo = (1u64 << k) as f64;
                    (lo, lo)
                };
                let into = (target - before) as f64 / count as f64;
                return (lo + into * width).round() as i64;
            }
        }
        // Unreachable when total > 0; keep a sane upper-bucket fallback.
        1i64 << (hist.len().saturating_sub(1).min(62))
    };

    TimingStatsOutput {
        p50_ns: percentile(0.50),
        p95_ns: percentile(0.95),
        p99_ns: percentile(0.99),
        p999_ns: percentile(0.999),
        total_samples: total as i64,
        buckets,
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        33 => "DCCP",
        41 => "IPv6",
        46 => "RSVP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        88 => "EIGRP",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        115 => "L2TP",
        132 => "SCTP",
        _ => "Other",
    }
}

/// Convert GraphQL AddRuleInput to PolicyService AddRuleParams
/// Convert a protocol string (as stored in AddRuleParams) to GqlProtocol.
fn protocol_to_gql(protocol: &str) -> GqlProtocol {
    match protocol.to_lowercase().as_str() {
        "tcp" => GqlProtocol::Tcp,
        "udp" => GqlProtocol::Udp,
        "icmp" => GqlProtocol::Icmp,
        _ => GqlProtocol::Any,
    }
}

/// Convert a raw QUIC version constant to its string representation.
fn quic_version_to_string(quic_version: u32) -> Option<String> {
    match quic_version {
        0 => None,
        v if v == crate::types::QUIC_VERSION_V1 => Some("v1".to_string()),
        v if v == crate::types::QUIC_VERSION_V2 => Some("v2".to_string()),
        _ => Some("any".to_string()),
    }
}

/// Parse a colon-hex MAC address string (e.g. "aa:bb:cc:dd:ee:ff") into 6 bytes.
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(async_graphql::Error::new(format!(
            "Invalid MAC address '{}': expected xx:xx:xx:xx:xx:xx",
            s
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
            async_graphql::Error::new(format!(
                "Invalid hex byte '{}' in MAC address '{}'",
                part, s
            ))
        })?;
    }
    Ok(mac)
}

fn input_to_add_params(input: &AddRuleInput) -> Result<AddRuleParams> {
    let ifindex = get_ifindex(&input.interface)?;
    // Convert param from milliseconds (UI) to typed ActionParams
    let actions: Vec<(PolicyAction, u8, ActionParams)> = input
        .actions
        .iter()
        .map(|a| {
            let action: PolicyAction = a.action.into();
            let params = match action {
                PolicyAction::Log if a.param > 0 => ActionParams::Log {
                    rate_limit_ns: (a.param as u64).saturating_mul(1_000_000),
                },
                _ => ActionParams::None,
            };
            (action, a.priority, params)
        })
        .collect();

    // Parse optional ID (accepts GraphQL ID scalar which can be string or int)
    let id: Option<u64> = match &input.id {
        Some(id_val) => {
            let s = id_val.to_string();
            match s.parse::<u64>() {
                Ok(v) => Some(v),
                Err(_) => return Err(async_graphql::Error::new(format!("Invalid id: {}", s))),
            }
        }
        None => None,
    };

    // Parse optional QUIC version filter
    let quic_version: u32 = match input.quic_version.as_deref() {
        None | Some("") | Some("none") => 0,
        Some("any") => crate::types::QUIC_VERSION_ANY,
        Some("v1") => crate::types::QUIC_VERSION_V1,
        Some("v2") => crate::types::QUIC_VERSION_V2,
        Some(other) => {
            return Err(async_graphql::Error::new(format!(
                "Invalid quic_version '{}': expected 'any', 'v1', 'v2', or omit",
                other
            )))
        }
    };

    // Validate lifecycle fields.
    if input.expires_after_secs.is_some() && input.schedule.is_some() {
        return Err(async_graphql::Error::new(
            "expiresAfterSecs and schedule are mutually exclusive",
        ));
    }
    if let Some(secs) = input.expires_after_secs {
        if secs <= 0 {
            return Err(async_graphql::Error::new(
                "expiresAfterSecs must be a positive integer",
            ));
        }
    }

    // Validate and convert schedule.
    let schedule = if let Some(ref sched_input) = input.schedule {
        if sched_input.windows.is_empty() {
            return Err(async_graphql::Error::new(
                "schedule must contain at least one window",
            ));
        }
        // Validate timezone.
        sched_input.timezone.parse::<chrono_tz::Tz>().map_err(|_| {
            async_graphql::Error::new(format!(
                "Invalid timezone '{}': must be a valid IANA timezone name",
                sched_input.timezone
            ))
        })?;
        // Validate window fields.
        for w in &sched_input.windows {
            for (label, tp) in [("start", &w.start), ("end", &w.end)] {
                if !(0..=6).contains(&tp.day_of_week) {
                    return Err(async_graphql::Error::new(format!(
                        "schedule window {} dayOfWeek must be 0–6 (got {})",
                        label, tp.day_of_week
                    )));
                }
                if !(0..=23).contains(&tp.hour) {
                    return Err(async_graphql::Error::new(format!(
                        "schedule window {} hour must be 0–23 (got {})",
                        label, tp.hour
                    )));
                }
                if !(0..=59).contains(&tp.minute) {
                    return Err(async_graphql::Error::new(format!(
                        "schedule window {} minute must be 0–59 (got {})",
                        label, tp.minute
                    )));
                }
            }
        }
        Some(crate::server::policy_service::RuleScheduleParams {
            windows: sched_input
                .windows
                .iter()
                .map(|w| crate::server::policy_service::WeeklyWindowParams {
                    start: crate::server::policy_service::WeeklyTimePointParams {
                        day_of_week: w.start.day_of_week as u8,
                        hour: w.start.hour as u8,
                        minute: w.start.minute as u8,
                    },
                    end: crate::server::policy_service::WeeklyTimePointParams {
                        day_of_week: w.end.day_of_week as u8,
                        hour: w.end.hour as u8,
                        minute: w.end.minute as u8,
                    },
                })
                .collect(),
            timezone: sched_input.timezone.clone(),
        })
    } else {
        None
    };

    // Parse optional MAC address filters
    let src_mac = input
        .src_mac
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(parse_mac)
        .transpose()?;
    let dst_mac = input
        .dst_mac
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(parse_mac)
        .transpose()?;

    Ok(AddRuleParams {
        direction: input.direction.into(),
        ifindex,
        id,
        src: input.src.clone(),
        dst: input.dst.clone(),
        sport: input.sport,
        dport: input.dport,
        protocol: input.protocol.clone(),
        actions,
        sni: input.sni.clone(),
        quic_version,
        src_mac,
        dst_mac,
        expires_after_secs: input.expires_after_secs.map(|s| s as u32),
        schedule,
    })
}

/// Wrapper for the request's peer address, injected into the GraphQL context.
/// `HttpRequest` is not `Send + Sync`, so we extract the address string before execution.
pub struct PeerAddr(pub String);

/// Extract the peer address from the GraphQL context.
fn get_source_ip(ctx: &Context<'_>) -> String {
    ctx.data::<PeerAddr>()
        .map(|p| p.0.clone())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Parse an optional RFC 3339 timestamp into UTC, treating `None`/empty as no
/// bound. Returns a GraphQL error on malformed input.
fn parse_opt_rfc3339(s: Option<&str>) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    match s {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| Some(t.with_timezone(&chrono::Utc)))
            .map_err(|e| async_graphql::Error::new(format!("invalid timestamp {s:?}: {e}"))),
    }
}

/// Get interface index from name
/// Resolve an interface name to its kernel ifindex, returning a GraphQL error on failure.
pub fn resolve_ifindex(interface: &str) -> Result<u32> {
    get_ifindex(interface)
}

fn get_ifindex(interface: &str) -> Result<u32> {
    let ifindex = unsafe {
        let name = std::ffi::CString::new(interface.to_string())
            .map_err(|e| async_graphql::Error::new(format!("Invalid interface name: {}", e)))?;
        libc::if_nametoindex(name.as_ptr())
    };

    if ifindex == 0 {
        return Err(async_graphql::Error::new(format!(
            "Interface {} not found",
            interface
        )));
    }

    Ok(ifindex)
}

/// Resolve an ifindex back to an interface name; returns empty string on failure.
fn ifindex_to_name(ifindex: u32) -> String {
    if ifindex == 0 {
        return String::new();
    }
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
    if p.is_null() {
        return String::new();
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..nul]).unwrap_or("").to_string()
}

/// Convert two-level LPM entry to GraphQL output (IPv4)
fn lpm_entry_to_output_v4(
    src_key: &crate::types::SrcLpmKeyV4,
    dst_key: &crate::types::LpmKeyV4,
    rule: &crate::types::L4Rule,
    sni_entry: Option<crate::types::SniRuleEntry>,
    mac_entry: Option<crate::types::MacRuleEntry>,
) -> LpmRuleOutput {
    use std::net::Ipv4Addr;

    let src_prefixlen = src_key.addr_prefixlen();
    let src_addr = Ipv4Addr::from(src_key.addr);
    let src_prefix = format!("{}/{}", src_addr, src_prefixlen);

    let dst_prefixlen = dst_key.prefixlen;
    let dst_addr = Ipv4Addr::from(dst_key.addr);
    let dst_prefix = format!("{}/{}", dst_addr, dst_prefixlen);

    let interface = ifindex_to_name(src_key.ifindex);
    l4_rule_to_output(
        interface, src_prefix, dst_prefix, rule, sni_entry, mac_entry,
    )
}

/// Convert two-level LPM entry to GraphQL output (IPv6)
fn lpm_entry_to_output_v6(
    src_key: &crate::types::SrcLpmKeyV6,
    dst_key: &crate::types::LpmKeyV6,
    rule: &crate::types::L4Rule,
    sni_entry: Option<crate::types::SniRuleEntry>,
    mac_entry: Option<crate::types::MacRuleEntry>,
) -> LpmRuleOutput {
    use std::net::Ipv6Addr;

    let src_prefixlen = src_key.addr_prefixlen();
    let src_addr = Ipv6Addr::from(src_key.addr);
    let src_prefix = format!("{}/{}", src_addr, src_prefixlen);

    let dst_prefixlen = dst_key.prefixlen;
    let dst_addr = Ipv6Addr::from(dst_key.addr);
    let dst_prefix = format!("{}/{}", dst_addr, dst_prefixlen);

    let interface = ifindex_to_name(src_key.ifindex);
    l4_rule_to_output(
        interface, src_prefix, dst_prefix, rule, sni_entry, mac_entry,
    )
}

/// Common L4Rule → GraphQL output conversion
fn l4_rule_to_output(
    interface: String,
    src_prefix: String,
    dst_prefix: String,
    rule: &crate::types::L4Rule,
    sni_entry: Option<crate::types::SniRuleEntry>,
    mac_entry: Option<crate::types::MacRuleEntry>,
) -> LpmRuleOutput {
    let rule_id = rule.rule_id;
    let num_actions = rule.num_actions;
    let mut actions = Vec::new();
    for i in 0..num_actions as usize {
        let action = &rule.actions[i];
        let action_val = action.action;
        let priority = action.priority;
        let param_ns = action.param;
        // Convert param from nanoseconds (BPF) back to milliseconds (UI)
        let param_ms = if param_ns > 0 {
            (param_ns / 1_000_000) as i64
        } else {
            0
        };
        actions.push(RuleActionOutput {
            action: crate::types::PolicyAction::from(action_val).into(),
            priority,
            param: param_ms,
        });
    }

    let sni = extract_sni_from_entry(sni_entry.as_ref());

    let quic_version = match rule.quic_version {
        0 => None,
        crate::types::QUIC_VERSION_ANY => Some("any".to_string()),
        crate::types::QUIC_VERSION_V1 => Some("v1".to_string()),
        crate::types::QUIC_VERSION_V2 => Some("v2".to_string()),
        v => Some(format!("0x{:08x}", v)),
    };

    let mac_match_flags = rule.mac_match_flags;
    let src_mac = if mac_match_flags & crate::types::MAC_MATCH_SRC != 0 {
        mac_entry.as_ref().map(|me| {
            let m = me.src_mac;
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        })
    } else {
        None
    };
    let dst_mac = if mac_match_flags & crate::types::MAC_MATCH_DST != 0 {
        mac_entry.as_ref().map(|me| {
            let m = me.dst_mac;
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        })
    } else {
        None
    };

    LpmRuleOutput {
        rule_id: async_graphql::ID::from(rule_id.to_string()),
        interface,
        src_prefix,
        dst_prefix,
        sport: rule.sport,
        dport: rule.dport,
        protocol: GqlProtocol::from_proto_number(rule.protocol),
        actions,
        sni,
        quic_version,
        src_mac,
        dst_mac,
    }
}

/// Extract SNI pattern from an SNI rule entry, if one is set
fn extract_sni_from_entry(sni_entry: Option<&crate::types::SniRuleEntry>) -> Option<String> {
    let entry = sni_entry?;
    if entry.sni_match_type == 0 || entry.sni_len == 0 {
        return None;
    }
    let len = entry.sni_len as usize;
    let pattern = &entry.sni_pattern[..len.min(entry.sni_pattern.len())];
    let s = std::str::from_utf8(pattern).ok()?.to_string();
    if entry.sni_match_type == crate::types::SNI_MATCH_SUFFIX {
        // Suffix wildcard - reconstruct the *.pattern form
        Some(format!("*.{}", s))
    } else {
        Some(s)
    }
}

/// Build the GraphQL schema
pub type PolicyEngineSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub fn build_schema(state: Arc<AppState>) -> PolicyEngineSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(state)
        .finish()
}

/// Return the GraphQL schema SDL without needing a running server.
///
/// The SDL is determined entirely by the type definitions — no BPF or system
/// resources are required.  Used by `cargo run --bin schema_export` to
/// regenerate `web/schema.graphql` after schema changes.
pub fn build_schema_sdl() -> String {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .finish()
        .sdl()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "suricata")]
    use crate::server::eve_consumer::EveConsumer;
    use crate::server::policy_service::PolicyService;
    #[cfg(feature = "suricata")]
    use crate::server::suricata_coordinator::SuricataCoordinator;
    #[cfg(feature = "suricata")]
    use crate::server::suricata_runtime::MockSuricataRuntime;
    #[cfg(feature = "suricata")]
    use crate::server::veth_manager::{MockVethOps, VethManager};
    use crate::traits::MockBpfOperations;
    use crate::types::*;
    #[cfg(feature = "suricata")]
    use std::path::PathBuf;

    // -------------------------------------------------------------------------
    // Test infrastructure helpers
    // -------------------------------------------------------------------------

    fn make_mock_bpf() -> MockBpfOperations {
        MockBpfOperations::new()
    }

    #[cfg(feature = "suricata")]
    fn make_state(mock: MockBpfOperations) -> Arc<AppState> {
        let service = PolicyService::new(Box::new(mock));

        let mut veth_ops = MockVethOps::new();
        veth_ops.expect_interface_exists().returning(|_| false);
        let veth_manager = VethManager::new_with_ops(Arc::new(veth_ops));

        let mut rt = MockSuricataRuntime::new();
        rt.expect_is_running().returning(|| false);
        rt.expect_get_version().returning(|| None);
        rt.expect_get_ruleset_version().returning(|| None);
        let coordinator = SuricataCoordinator::new_with_runtime(
            Arc::new(rt),
            PathBuf::from("/tmp/test_rules"),
            PathBuf::from("/tmp/test_eve.sock"),
            PathBuf::from("/tmp/test_cmd.sock"),
        );

        let eve = EveConsumer::new(PathBuf::from("/tmp/test_schema_eve.sock"));
        let affinity = Arc::new(AffinityPlan::disabled());

        Arc::new(AppState::new(
            service,
            veth_manager,
            coordinator,
            eve,
            affinity,
        ))
    }

    #[cfg(not(feature = "suricata"))]
    fn make_state(mock: MockBpfOperations) -> Arc<AppState> {
        let service = PolicyService::new(Box::new(mock));
        let affinity = Arc::new(AffinityPlan::disabled());
        Arc::new(AppState::new(service, affinity))
    }

    fn make_schema(mock: MockBpfOperations) -> PolicyEngineSchema {
        build_schema(make_state(mock))
    }

    // -------------------------------------------------------------------------
    // extract_sni_from_entry
    // -------------------------------------------------------------------------

    #[test]
    fn extract_sni_none_when_no_entry() {
        assert!(extract_sni_from_entry(None).is_none());
    }

    #[test]
    fn extract_sni_none_when_match_type_zero() {
        let entry = SniRuleEntry::default();
        assert!(extract_sni_from_entry(Some(&entry)).is_none());
    }

    #[test]
    fn extract_sni_exact_match() {
        let hostname = b"example.com";
        let mut pattern = [0u8; 128];
        pattern[..hostname.len()].copy_from_slice(hostname);
        let entry = SniRuleEntry {
            sni_match_type: SNI_MATCH_EXACT,
            sni_len: hostname.len() as u8,
            _pad: [0; 2],
            sni_pattern: pattern,
        };
        let result = extract_sni_from_entry(Some(&entry));
        assert_eq!(result.as_deref(), Some("example.com"));
    }

    #[test]
    fn extract_sni_suffix_match_adds_wildcard() {
        let suffix = b"example.com";
        let mut pattern = [0u8; 128];
        pattern[..suffix.len()].copy_from_slice(suffix);
        let entry = SniRuleEntry {
            sni_match_type: SNI_MATCH_SUFFIX,
            sni_len: suffix.len() as u8,
            _pad: [0; 2],
            sni_pattern: pattern,
        };
        let result = extract_sni_from_entry(Some(&entry));
        assert_eq!(result.as_deref(), Some("*.example.com"));
    }

    #[test]
    fn extract_sni_none_when_len_zero() {
        let entry = SniRuleEntry {
            sni_match_type: SNI_MATCH_EXACT,
            sni_len: 0,
            ..Default::default()
        };
        assert!(extract_sni_from_entry(Some(&entry)).is_none());
    }

    // -------------------------------------------------------------------------
    // l4_rule_to_output / lpm_entry_to_output_v4/v6
    // -------------------------------------------------------------------------

    fn make_l4_rule(rule_id: u64, sport: u16, dport: u16, proto: u8) -> L4Rule {
        let mut rule = L4Rule {
            rule_id,
            sport,
            dport,
            protocol: proto,
            sni_match_type: SNI_MATCH_NONE,
            num_actions: 1,
            ..Default::default()
        };
        rule.actions[0] = RuleAction {
            action: PolicyAction::Drop as u32,
            priority: 0,
            _pad1: 0,
            _pad2: 0,
            param: 0,
        };
        rule
    }

    #[test]
    fn l4_rule_to_output_basic() {
        let rule = make_l4_rule(42, 0, 80, libc::IPPROTO_TCP as u8);
        let out = l4_rule_to_output(
            "lo".to_string(),
            "10.0.0.0/24".to_string(),
            "0.0.0.0/0".to_string(),
            &rule,
            None,
            None,
        );
        assert_eq!(out.rule_id.to_string(), "42");
        assert_eq!(out.sport, 0);
        assert_eq!(out.dport, 80);
        assert!(out.sni.is_none());
        assert_eq!(out.actions.len(), 1);
        assert_eq!(
            out.actions[0].action,
            crate::server::graphql::types::GqlPolicyAction::Drop
        );
    }

    #[test]
    fn lpm_entry_to_output_v4_formats_addresses() {
        use crate::types::{LpmKeyV4, SrcLpmKeyV4};
        let src_key = SrcLpmKeyV4 {
            prefixlen: 32 + 24,
            ifindex: 0,
            addr: [192, 168, 1, 0],
        };
        let dst_key = LpmKeyV4 {
            prefixlen: 0,
            addr: [0, 0, 0, 0],
        };
        let rule = make_l4_rule(1, 0, 443, libc::IPPROTO_TCP as u8);
        let out = lpm_entry_to_output_v4(&src_key, &dst_key, &rule, None, None);
        assert!(
            out.src_prefix.contains("/24"),
            "src prefix: {}",
            out.src_prefix
        );
        assert!(
            out.dst_prefix.contains("/0"),
            "dst prefix: {}",
            out.dst_prefix
        );
    }

    #[test]
    fn lpm_entry_to_output_v6_formats_addresses() {
        use crate::types::{LpmKeyV6, SrcLpmKeyV6};
        let src_key = SrcLpmKeyV6 {
            prefixlen: 32 + 128,
            ifindex: 0,
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        let dst_key = LpmKeyV6 {
            prefixlen: 0,
            addr: [0u8; 16],
        };
        let rule = make_l4_rule(2, 0, 0, 0);
        let out = lpm_entry_to_output_v6(&src_key, &dst_key, &rule, None, None);
        assert!(out.src_prefix.contains("::1"), "src: {}", out.src_prefix);
        assert!(
            out.src_prefix.contains("/128"),
            "src prefix: {}",
            out.src_prefix
        );
    }

    #[test]
    fn l4_rule_log_action_converts_param_ms() {
        let mut rule = make_l4_rule(10, 0, 0, 0);
        rule.actions[0] = RuleAction {
            action: PolicyAction::Log as u32,
            priority: 0,
            _pad1: 0,
            _pad2: 0,
            param: 5_000_000_000, // 5000ms in ns
        };
        let out = l4_rule_to_output(
            "lo".to_string(),
            "0.0.0.0/0".to_string(),
            "0.0.0.0/0".to_string(),
            &rule,
            None,
            None,
        );
        assert_eq!(out.actions[0].param, 5000); // ms
    }

    // -------------------------------------------------------------------------
    // input_to_add_params
    // -------------------------------------------------------------------------

    fn make_add_rule_input(direction: GqlDirection) -> AddRuleInput {
        AddRuleInput {
            interface: "lo".to_string(),
            direction,
            src: None,
            dst: None,
            sport: 0,
            dport: 80,
            protocol: "tcp".to_string(),
            actions: vec![crate::server::graphql::types::ActionInput {
                action: crate::server::graphql::types::GqlPolicyAction::Drop,
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
        }
    }

    #[test]
    fn input_to_add_params_basic() {
        let input = make_add_rule_input(GqlDirection::Ingress);
        let params = input_to_add_params(&input).expect("should succeed");
        assert_eq!(params.direction, Direction::Ingress);
        assert_eq!(params.dport, 80);
        assert_eq!(params.protocol, "tcp");
        assert!(params.id.is_none());
        assert_eq!(params.actions.len(), 1);
        assert_eq!(params.actions[0].0, PolicyAction::Drop);
    }

    #[test]
    fn input_to_add_params_egress() {
        let input = make_add_rule_input(GqlDirection::Egress);
        let params = input_to_add_params(&input).expect("should succeed");
        assert_eq!(params.direction, Direction::Egress);
    }

    #[test]
    fn input_to_add_params_with_id() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.id = Some(async_graphql::ID::from("42".to_string()));
        let params = input_to_add_params(&input).expect("should succeed");
        assert_eq!(params.id, Some(42));
    }

    #[test]
    fn input_to_add_params_invalid_id_returns_error() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.id = Some(async_graphql::ID::from("not_a_number".to_string()));
        assert!(input_to_add_params(&input).is_err());
    }

    #[test]
    fn input_to_add_params_log_with_rate_limit_converts_to_ns() {
        let input = AddRuleInput {
            interface: "lo".to_string(),
            direction: GqlDirection::Ingress,
            src: None,
            dst: None,
            sport: 0,
            dport: 0,
            protocol: "any".to_string(),
            actions: vec![crate::server::graphql::types::ActionInput {
                action: crate::server::graphql::types::GqlPolicyAction::Log,
                priority: 0,
                param: 5000, // 5000ms
            }],
            id: None,
            sni: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            expires_after_secs: None,
            schedule: None,
        };
        let params = input_to_add_params(&input).expect("should succeed");
        match &params.actions[0].2 {
            ActionParams::Log { rate_limit_ns } => {
                assert_eq!(*rate_limit_ns, 5_000_000_000u64); // 5000ms * 1_000_000
            }
            other => panic!("expected ActionParams::Log, got {:?}", other),
        }
    }

    #[test]
    fn input_to_add_params_log_zero_param_is_none() {
        let input = AddRuleInput {
            interface: "lo".to_string(),
            direction: GqlDirection::Ingress,
            src: None,
            dst: None,
            sport: 0,
            dport: 0,
            protocol: "any".to_string(),
            actions: vec![crate::server::graphql::types::ActionInput {
                action: crate::server::graphql::types::GqlPolicyAction::Log,
                priority: 0,
                param: 0, // no rate limit
            }],
            id: None,
            sni: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            expires_after_secs: None,
            schedule: None,
        };
        let params = input_to_add_params(&input).expect("should succeed");
        assert_eq!(params.actions[0].2, ActionParams::None);
    }

    // -------------------------------------------------------------------------
    // BandwidthTracker
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn bandwidth_tracker_first_sample_returns_zero() {
        let tracker = BandwidthTracker::new();
        let (rx_bps, tx_bps) = tracker.sample("eth0", 0, 1000, 500).await;
        // First sample has no previous to compare against
        assert_eq!(rx_bps, 0);
        assert_eq!(tx_bps, 0);
    }

    #[tokio::test]
    async fn bandwidth_tracker_second_sample_returns_nonzero() {
        let tracker = BandwidthTracker::new();
        tracker.sample("eth0", 0, 0, 0).await;
        // Wait a bit so elapsed > 0
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let (rx_bps, tx_bps) = tracker.sample("eth0", 0, 1_000_000, 500_000).await;
        // Should be > 0 since bytes increased
        assert!(rx_bps > 0, "rx_bps should be positive: {}", rx_bps);
        assert!(tx_bps > 0, "tx_bps should be positive: {}", tx_bps);
    }

    #[tokio::test]
    async fn bandwidth_tracker_different_ifaces_independent() {
        let tracker = BandwidthTracker::new();
        tracker.sample("eth0", 0, 0, 0).await;
        tracker.sample("eth1", 0, 0, 0).await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let (rx0, _) = tracker.sample("eth0", 0, 1_000_000, 0).await;
        let (rx1, _) = tracker.sample("eth1", 0, 2_000_000, 0).await;
        // eth1 got more bytes, so its rate should be higher
        assert!(
            rx1 > rx0,
            "eth1 bps should be higher than eth0: {} vs {}",
            rx1,
            rx0
        );
    }

    #[tokio::test]
    async fn bandwidth_tracker_no_increase_returns_zero() {
        let tracker = BandwidthTracker::new();
        tracker.sample("eth0", 0, 1000, 500).await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        // Same byte count — no increase
        let (rx_bps, tx_bps) = tracker.sample("eth0", 0, 1000, 500).await;
        assert_eq!(rx_bps, 0);
        assert_eq!(tx_bps, 0);
    }

    // -------------------------------------------------------------------------
    // Timing stats: interpolated percentiles + per-poll windowing
    // -------------------------------------------------------------------------

    /// A histogram concentrated in one bucket must interpolate within it:
    /// percentiles move through [2^k, 2^(k+1)) instead of all snapping to the
    /// bucket midpoint (the old behavior that made p50/p95/p99 read as exact
    /// multiples of each other).
    #[test]
    fn timing_percentiles_interpolate_within_bucket() {
        let mut hist = vec![0u64; 64];
        hist[8] = 1000; // all samples in [256, 512) ns
        let t = compute_timing_stats(&hist);
        assert!(t.p50_ns > 256 && t.p50_ns < 512, "p50 {}", t.p50_ns);
        assert!(t.p95_ns > t.p50_ns, "p95 {} p50 {}", t.p95_ns, t.p50_ns);
        assert!(t.p99_ns > t.p95_ns, "p99 {} p95 {}", t.p99_ns, t.p95_ns);
        assert!(t.p999_ns <= 512, "p999 {}", t.p999_ns);
        assert_eq!(t.total_samples, 1000);
    }

    #[test]
    fn timing_percentiles_span_buckets() {
        let mut hist = vec![0u64; 64];
        hist[8] = 90; // [256, 512)
        hist[10] = 10; // [1024, 2048)
        let t = compute_timing_stats(&hist);
        assert!(t.p50_ns > 256 && t.p50_ns < 512, "p50 {}", t.p50_ns);
        // rank 95 of 100 falls 5/10 into bucket 10 → ~1536
        assert!(t.p95_ns >= 1024 && t.p95_ns < 2048, "p95 {}", t.p95_ns);
    }

    #[test]
    fn timing_empty_histogram_is_all_zero() {
        let t = compute_timing_stats(&vec![0u64; 64]);
        assert_eq!(t.p50_ns, 0);
        assert_eq!(t.p999_ns, 0);
        assert_eq!(t.total_samples, 0);
    }

    #[tokio::test]
    async fn timing_tracker_first_sample_uses_cumulative() {
        let tracker = TimingTracker::new();
        let mut hist = vec![0u64; 64];
        hist[8] = 100;
        let t = tracker.sample("eth0", 0, &hist).await;
        assert_eq!(t.total_samples, 100);
    }

    #[tokio::test]
    async fn timing_tracker_windows_between_polls() {
        let tracker = TimingTracker::new();
        let mut hist = vec![0u64; 64];
        hist[8] = 1_000_000; // large accumulated history in [256, 512)
        tracker.sample("eth0", 0, &hist).await;

        // New traffic lands exclusively in bucket 12 [4096, 8192): windowed
        // percentiles must reflect only the delta, not the lifetime histogram.
        hist[12] = 50;
        let t = tracker.sample("eth0", 0, &hist).await;
        assert_eq!(t.total_samples, 50);
        assert!(t.p50_ns >= 4096 && t.p50_ns < 8192, "p50 {}", t.p50_ns);
    }

    #[tokio::test]
    async fn timing_tracker_idle_window_repeats_last_stats() {
        let tracker = TimingTracker::new();
        let mut hist = vec![0u64; 64];
        hist[8] = 100;
        tracker.sample("eth0", 0, &hist).await;
        hist[8] = 200;
        let active = tracker.sample("eth0", 0, &hist).await;
        // No new samples since the previous poll → previous window's stats.
        let idle = tracker.sample("eth0", 0, &hist).await;
        assert_eq!(idle.total_samples, active.total_samples);
        assert_eq!(idle.p50_ns, active.p50_ns);
    }

    #[tokio::test]
    async fn timing_tracker_interfaces_independent() {
        let tracker = TimingTracker::new();
        let mut h1 = vec![0u64; 64];
        h1[8] = 100;
        let mut h2 = vec![0u64; 64];
        h2[12] = 10;
        tracker.sample("eth0", 0, &h1).await;
        let t2 = tracker.sample("eth1", 0, &h2).await;
        // eth1's first sample is its own cumulative histogram, not eth0's.
        assert_eq!(t2.total_samples, 10);
        assert!(t2.p50_ns >= 4096, "p50 {}", t2.p50_ns);
    }

    // -------------------------------------------------------------------------
    // Schema query tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn schema_status_query_returns_running() {
        let mut mock = make_mock_bpf();
        mock.expect_get_attached_interfaces().returning(Vec::new);
        #[cfg(feature = "suricata")]
        mock.expect_get_inspect_config()
            .returning(|_| Err(anyhow::anyhow!("not loaded")));

        let schema = make_schema(mock);
        let resp = schema
            .execute("{ status { running version programAttached } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["status"]["running"], true);
        assert_eq!(data["status"]["programAttached"], false);
    }

    #[tokio::test]
    async fn schema_interfaces_empty_when_no_attachments() {
        let mut mock = make_mock_bpf();
        mock.expect_get_attached_interfaces().returning(Vec::new);

        let schema = make_schema(mock);
        let resp = schema.execute("{ interfaces { interface } }").await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["interfaces"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn schema_rules_empty_when_not_loaded() {
        let mock = make_mock_bpf();
        // xdp_loaded=false → is_direction_loaded returns false → rules returns []
        let schema = make_schema(mock);
        let resp = schema
            .execute("{ rules(direction: INGRESS) { ruleId srcPrefix dstPrefix } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["rules"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn flush_rules_unknown_interface_is_noop() {
        // An interface that doesn't exist on the host can't hold any rules, so
        // flushing it must succeed as a no-op rather than erroring. The resolver
        // returns early without ever touching the BPF layer.
        let mock = make_mock_bpf();
        let schema = make_schema(mock);
        let resp = schema
            .execute(
                "mutation { flushRules(interface: \"does-not-exist-xyz0\", \
                 direction: INGRESS) { success message } }",
            )
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["flushRules"]["success"], true);
    }

    #[tokio::test]
    async fn flow_verdict_list_sorts_soonest_first_and_applies_limit() {
        // Three cached verdicts with out-of-order expiry. The resolver must
        // return them soonest-expiring first and honor `limit`.
        fn entry(sport: u16, expires_ns: u64) -> (FlowVerdictKey, FlowVerdict) {
            let mut key = FlowVerdictKey {
                af: AF_INET,
                protocol: libc::IPPROTO_TCP as u8,
                sport,
                dport: 443,
                ..Default::default()
            };
            key.saddr[..4].copy_from_slice(&[10, 0, 0, 1]);
            key.daddr[..4].copy_from_slice(&[10, 0, 0, 2]);
            let verdict = FlowVerdict {
                action: PolicyAction::Drop as u32,
                expires_ns,
                ..Default::default()
            };
            (key, verdict)
        }

        let mut mock = make_mock_bpf();
        mock.expect_list_flow_verdicts().returning(|_| {
            Ok(vec![
                entry(3000, 3_000_000_000),
                entry(1000, 1_000_000_000),
                entry(2000, 2_000_000_000),
            ])
        });
        let schema = make_schema(mock);
        let resp = schema
            .execute("{ flowVerdictList(direction: INGRESS, limit: 2) { srcPort expiresNs } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        let list = data["flowVerdictList"].as_array().unwrap();
        assert_eq!(list.len(), 2, "limit should cap to 2: {:?}", list);
        // Soonest-expiring first: sport 1000 then 2000.
        assert_eq!(list[0]["srcPort"], 1000);
        assert_eq!(list[1]["srcPort"], 2000);
    }

    #[tokio::test]
    async fn schema_stats_empty_when_not_loaded() {
        let mock = make_mock_bpf();
        let schema = make_schema(mock);
        let resp = schema
            .execute("{ stats(interface: \"eth0\", direction: INGRESS) { rxPackets } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["stats"]["rxPackets"], 0);
    }

    #[cfg(feature = "suricata")]
    #[tokio::test]
    async fn schema_inspect_status_disabled_when_not_configured() {
        let mut mock = make_mock_bpf();
        mock.expect_get_inspect_config()
            .returning(|_| Ok(InspectConfig::default()));
        mock.expect_get_flow_verdict_count().returning(|_| Ok(0));
        mock.expect_list_fib_configs().returning(|| Ok(vec![]));

        let schema = make_schema(mock);
        let resp = schema
            .execute(
                "{ inspectStatus { mode suricataRunning flowVerdictCount enabledInterfaces } }",
            )
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["inspectStatus"]["mode"], "DISABLED");
        assert_eq!(data["inspectStatus"]["flowVerdictCount"], 0);
        assert_eq!(
            data["inspectStatus"]["enabledInterfaces"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn schema_build_sdl_contains_query_type() {
        let sdl = build_schema_sdl();
        assert!(
            sdl.contains("type Query"),
            "SDL should contain Query type: {}",
            &sdl[..200]
        );
        assert!(
            sdl.contains("type Mutation"),
            "SDL should contain Mutation type"
        );
    }

    // -------------------------------------------------------------------------
    // Inspect enable/disable teardown tests
    // -------------------------------------------------------------------------

    /// Build AppState with fully customisable BPF, veth and Suricata mocks.
    /// Uses `PolicyService::new_with_state(…, true, true)` so BPF programs are
    /// considered already loaded and no `load_programs` expectation is needed.
    #[cfg(feature = "suricata")]
    fn make_state_custom(
        mock_bpf: MockBpfOperations,
        veth_ops: MockVethOps,
        rt: MockSuricataRuntime,
    ) -> Arc<AppState> {
        use crate::server::state_store::InMemoryStateStore;
        let service = PolicyService::new_with_state(
            Box::new(mock_bpf),
            Box::new(InMemoryStateStore::new()),
            true,
            true,
        );
        let veth_manager = VethManager::new_with_ops(Arc::new(veth_ops));
        let coordinator = SuricataCoordinator::new_with_runtime(
            Arc::new(rt),
            PathBuf::from("/tmp/test_rules"),
            PathBuf::from("/tmp/test_eve.sock"),
            PathBuf::from("/tmp/test_cmd.sock"),
        );
        let eve = EveConsumer::new(PathBuf::from("/tmp/test_schema_teardown_eve.sock"));
        let affinity = Arc::new(AffinityPlan::disabled());
        Arc::new(AppState::new(
            service,
            veth_manager,
            coordinator,
            eve,
            affinity,
        ))
    }

    #[cfg(feature = "suricata")]
    #[tokio::test]
    async fn disable_inspect_removes_suricata_config() {
        let mut mock_bpf = MockBpfOperations::new();
        mock_bpf
            .expect_set_inspect_config()
            .times(2)
            .returning(|_, _| Ok(()));

        let mut veth_ops = MockVethOps::new();
        // is_up() is checked before destroy_pair()
        veth_ops.expect_interface_exists().returning(|_| false); // pair not up, skip destroy
                                                                 // destroy_pair should NOT be called since is_up returns false
        veth_ops.expect_destroy_pair().times(0);

        let mut rt = MockSuricataRuntime::new();
        rt.expect_is_running().returning(|| false);
        rt.expect_get_version().returning(|| None);
        rt.expect_get_ruleset_version().returning(|| None);
        // remove_config calls remove_systemd_env then stop (never restart:
        // that would launch the stock unit with the distro default config)
        rt.expect_remove_systemd_env().times(1).returning(|| Ok(()));
        rt.expect_stop().times(1).returning(|| Ok(()));
        rt.expect_disable_update_timer()
            .times(1)
            .returning(|| Ok(()));

        let schema = build_schema(make_state_custom(mock_bpf, veth_ops, rt));
        let resp = schema
            .execute("mutation { disableInspect { success message } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["disableInspect"]["success"], true);
    }

    #[cfg(feature = "suricata")]
    #[tokio::test]
    async fn disable_inspect_destroys_veth_pair_when_up() {
        let mut mock_bpf = MockBpfOperations::new();
        mock_bpf
            .expect_set_inspect_config()
            .times(2)
            .returning(|_, _| Ok(()));

        let mut veth_ops = MockVethOps::new();
        veth_ops.expect_interface_exists().returning(|_| true); // pair is up
        veth_ops
            .expect_destroy_pair()
            .times(1)
            .returning(|_| Ok(()));

        let mut rt = MockSuricataRuntime::new();
        rt.expect_is_running().returning(|| false);
        rt.expect_get_version().returning(|| None);
        rt.expect_get_ruleset_version().returning(|| None);
        rt.expect_remove_systemd_env().times(1).returning(|| Ok(()));
        rt.expect_stop().times(1).returning(|| Ok(()));
        rt.expect_disable_update_timer()
            .times(1)
            .returning(|| Ok(()));

        let schema = build_schema(make_state_custom(mock_bpf, veth_ops, rt));
        let resp = schema
            .execute("mutation { disableInspect { success } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
    }

    #[cfg(feature = "suricata")]
    #[tokio::test]
    async fn configure_inspect_disabled_removes_suricata_config() {
        let mut mock_bpf = MockBpfOperations::new();
        // configure_inspect(DISABLED) calls set_inspect_config for both directions
        mock_bpf
            .expect_set_inspect_config()
            .times(2)
            .returning(|_, _| Ok(()));

        let mut veth_ops = MockVethOps::new();
        veth_ops.expect_interface_exists().returning(|_| false); // pair not up

        let mut rt = MockSuricataRuntime::new();
        rt.expect_is_running().returning(|| false);
        rt.expect_get_version().returning(|| None);
        rt.expect_get_ruleset_version().returning(|| None);
        // Must call remove_config as part of DISABLED teardown
        rt.expect_remove_systemd_env().times(1).returning(|| Ok(()));
        rt.expect_stop().times(1).returning(|| Ok(()));
        rt.expect_disable_update_timer()
            .times(1)
            .returning(|| Ok(()));

        let schema = build_schema(make_state_custom(mock_bpf, veth_ops, rt));
        let resp = schema
            .execute("mutation { configureInspect(input: { mode: DISABLED }) { success message } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["configureInspect"]["success"], true);
    }

    #[cfg(feature = "suricata")]
    #[tokio::test]
    async fn configure_inspect_disabled_destroys_veth_pair_when_up() {
        let mut mock_bpf = MockBpfOperations::new();
        mock_bpf
            .expect_set_inspect_config()
            .times(2)
            .returning(|_, _| Ok(()));

        let mut veth_ops = MockVethOps::new();
        veth_ops.expect_interface_exists().returning(|_| true); // pair is up
        veth_ops
            .expect_destroy_pair()
            .times(1)
            .returning(|_| Ok(()));

        let mut rt = MockSuricataRuntime::new();
        rt.expect_is_running().returning(|| false);
        rt.expect_get_version().returning(|| None);
        rt.expect_get_ruleset_version().returning(|| None);
        rt.expect_remove_systemd_env().times(1).returning(|| Ok(()));
        rt.expect_stop().times(1).returning(|| Ok(()));
        rt.expect_disable_update_timer()
            .times(1)
            .returning(|| Ok(()));

        let schema = build_schema(make_state_custom(mock_bpf, veth_ops, rt));
        let resp = schema
            .execute("mutation { configureInspect(input: { mode: DISABLED }) { success } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
    }

    #[cfg(feature = "suricata")]
    #[tokio::test]
    async fn configure_inspect_errors_when_suricata_config_write_fails() {
        let mut mock_bpf = MockBpfOperations::new();
        mock_bpf
            .expect_set_inspect_config()
            .times(2)
            .returning(|_, _| Ok(()));
        // Enabling INSPECT ensures TC is attached wherever XDP is; no interfaces
        // are attached in this test.
        mock_bpf
            .expect_get_attached_interfaces()
            .returning(Vec::new);

        let mut veth_ops = MockVethOps::new();
        veth_ops.expect_interface_exists().returning(|_| true); // pair already exists
        veth_ops.expect_get_ifindex().returning(|_| Ok(55));

        let mut rt = MockSuricataRuntime::new();
        rt.expect_is_running().returning(|| false);
        rt.expect_get_version().returning(|| None);
        rt.expect_get_ruleset_version().returning(|| None);
        // Config write fails (e.g. EACCES on /etc/suricata) — the mutation must
        // surface this instead of reporting the mode as enabled.
        rt.expect_write_systemd_env()
            .times(1)
            .returning(|_| Err(anyhow::anyhow!("Failed to write policy-engine.yaml")));
        rt.expect_restart_service().times(0);
        rt.expect_enable_update_timer().times(0);

        let schema = build_schema(make_state_custom(mock_bpf, veth_ops, rt));
        let resp = schema
            .execute("mutation { configureInspect(input: { mode: IPS }) { success } }")
            .await;
        assert!(
            !resp.errors.is_empty(),
            "config-write failure should produce a GraphQL error"
        );
        assert!(
            resp.errors[0]
                .message
                .contains("Failed to apply Suricata config"),
            "unexpected error message: {}",
            resp.errors[0].message
        );
        assert!(
            resp.errors[0].message.contains("policy-engine.yaml"),
            "error should include the underlying cause: {}",
            resp.errors[0].message
        );
    }

    // -------------------------------------------------------------------------
    // FIB forwarding tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn set_fib_forwarding_enabled() {
        let mut mock = make_mock_bpf();
        mock.expect_load_programs().times(1).returning(|| Ok(()));
        mock.expect_get_fib_config()
            .returning(|_| Ok(crate::types::FibConfig::default()));
        mock.expect_set_fib_config()
            .times(1)
            .withf(|iface, cfg| iface == "eth0" && cfg.mode == crate::types::FIB_FORWARD_ENABLED)
            .returning(|_, _| Ok(()));

        let schema = make_schema(mock);
        let resp = schema
            .execute(
                "mutation { setFibForwarding(input: { interface: \"eth0\", enabled: true }) { success message } }",
            )
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["setFibForwarding"]["success"], true);
    }

    #[tokio::test]
    async fn set_fib_forwarding_disabled() {
        let mut mock = make_mock_bpf();
        mock.expect_load_programs().times(1).returning(|| Ok(()));
        mock.expect_get_fib_config()
            .returning(|_| Ok(crate::types::FibConfig::default()));
        mock.expect_set_fib_config()
            .times(1)
            .withf(|iface, cfg| iface == "eth0" && cfg.mode == crate::types::FIB_FORWARD_DISABLED)
            .returning(|_, _| Ok(()));

        let schema = make_schema(mock);
        let resp = schema
            .execute(
                "mutation { setFibForwarding(input: { interface: \"eth0\", enabled: false }) { success message } }",
            )
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["setFibForwarding"]["success"], true);
    }

    #[tokio::test]
    async fn fib_forwarding_query_returns_empty_by_default() {
        let mut mock = make_mock_bpf();
        mock.expect_list_fib_configs()
            .times(1)
            .returning(|| Ok(Vec::new()));

        let schema = make_schema(mock);
        let resp = schema
            .execute("{ fibForwarding { interface enabled } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["fibForwarding"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn fib_forwarding_query_returns_enabled_entries() {
        let mut mock = make_mock_bpf();
        mock.expect_list_fib_configs().times(1).returning(|| {
            Ok(vec![(
                "eth0".to_string(),
                crate::types::FibConfig {
                    mode: crate::types::FIB_FORWARD_ENABLED,
                    ..Default::default()
                },
            )])
        });

        let schema = make_schema(mock);
        let resp = schema
            .execute("{ fibForwarding { interface enabled } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["fibForwarding"][0]["interface"], "eth0");
        assert_eq!(data["fibForwarding"][0]["enabled"], true);
    }

    // -------------------------------------------------------------------------
    // uRPF tests
    // -------------------------------------------------------------------------

    fn ingress_attachment(iface: &str) -> crate::shared_types::InterfaceAttachment {
        crate::shared_types::InterfaceAttachment {
            interface: iface.to_string(),
            ifindex: 2,
            mode: "xdp".to_string(),
            direction: "ingress".to_string(),
        }
    }

    #[tokio::test]
    async fn set_urpf_strict_on_xdp_interface() {
        let mut mock = make_mock_bpf();
        mock.expect_load_programs().times(1).returning(|| Ok(()));
        mock.expect_get_attached_interfaces()
            .returning(|| vec![ingress_attachment("eth0")]);
        mock.expect_get_fib_config()
            .returning(|_| Ok(crate::types::FibConfig::default()));
        mock.expect_set_fib_config()
            .times(1)
            .withf(|iface, cfg| iface == "eth0" && cfg.urpf_mode == crate::types::URPF_STRICT)
            .returning(|_, _| Ok(()));

        let schema = make_schema(mock);
        let resp = schema
            .execute(
                "mutation { setUrpf(input: { interface: \"eth0\", mode: STRICT }) { success message } }",
            )
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["setUrpf"]["success"], true);
    }

    #[tokio::test]
    async fn set_urpf_rejected_on_non_xdp_interface() {
        let mut mock = make_mock_bpf();
        mock.expect_load_programs().times(1).returning(|| Ok(()));
        // Only a TC egress attachment exists — uRPF must be rejected.
        mock.expect_get_attached_interfaces().returning(|| {
            vec![crate::shared_types::InterfaceAttachment {
                interface: "eth0".to_string(),
                ifindex: 2,
                mode: "tc".to_string(),
                direction: "egress".to_string(),
            }]
        });
        // set_fib_config must NOT be called when the interface is rejected.
        mock.expect_set_fib_config().never();

        let schema = make_schema(mock);
        let resp = schema
            .execute(
                "mutation { setUrpf(input: { interface: \"eth0\", mode: LOOSE }) { success message } }",
            )
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["setUrpf"]["success"], false);
    }

    #[tokio::test]
    async fn set_urpf_off_does_not_require_xdp() {
        let mut mock = make_mock_bpf();
        mock.expect_load_programs().times(1).returning(|| Ok(()));
        // Disabling uRPF skips the XDP-attached check entirely.
        mock.expect_get_fib_config()
            .returning(|_| Ok(crate::types::FibConfig::default()));
        mock.expect_set_fib_config()
            .times(1)
            .withf(|iface, cfg| iface == "eth0" && cfg.urpf_mode == crate::types::URPF_DISABLED)
            .returning(|_, _| Ok(()));

        let schema = make_schema(mock);
        let resp = schema
            .execute(
                "mutation { setUrpf(input: { interface: \"eth0\", mode: OFF }) { success message } }",
            )
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["setUrpf"]["success"], true);
    }

    #[tokio::test]
    async fn urpf_query_returns_enabled_entries() {
        let mut mock = make_mock_bpf();
        mock.expect_list_fib_configs().times(1).returning(|| {
            Ok(vec![
                (
                    "eth0".to_string(),
                    crate::types::FibConfig {
                        urpf_mode: crate::types::URPF_STRICT,
                        ..Default::default()
                    },
                ),
                // fib-only entry (uRPF disabled) must be filtered out.
                (
                    "eth1".to_string(),
                    crate::types::FibConfig {
                        mode: crate::types::FIB_FORWARD_ENABLED,
                        ..Default::default()
                    },
                ),
            ])
        });

        let schema = make_schema(mock);
        let resp = schema.execute("{ urpf { interface mode } }").await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        let arr = data["urpf"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(data["urpf"][0]["interface"], "eth0");
        assert_eq!(data["urpf"][0]["mode"], "STRICT");
    }

    // ── Schedule/TTL input validation ────────────────────────────────────────

    #[test]
    fn input_to_add_params_expires_after_secs_sets_field() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.expires_after_secs = Some(3600);
        let params = input_to_add_params(&input).expect("should succeed");
        assert_eq!(params.expires_after_secs, Some(3600u32));
        assert!(params.schedule.is_none());
    }

    #[test]
    fn input_to_add_params_both_ttl_and_schedule_returns_error() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.expires_after_secs = Some(60);
        input.schedule = Some(crate::server::graphql::types::RuleScheduleInput {
            windows: vec![crate::server::graphql::types::WeeklyWindowInput {
                start: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 1,
                    hour: 9,
                    minute: 0,
                },
                end: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 1,
                    hour: 17,
                    minute: 0,
                },
            }],
            timezone: "UTC".to_string(),
        });
        let result = input_to_add_params(&input);
        assert!(result.is_err());
        let msg = result.unwrap_err().message;
        assert!(
            msg.contains("mutually exclusive"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn input_to_add_params_expires_after_secs_zero_returns_error() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.expires_after_secs = Some(0);
        assert!(input_to_add_params(&input).is_err());
    }

    #[test]
    fn input_to_add_params_invalid_timezone_returns_error() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.schedule = Some(crate::server::graphql::types::RuleScheduleInput {
            windows: vec![crate::server::graphql::types::WeeklyWindowInput {
                start: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 1,
                    hour: 9,
                    minute: 0,
                },
                end: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 1,
                    hour: 17,
                    minute: 0,
                },
            }],
            timezone: "Not/A/Timezone".to_string(),
        });
        let result = input_to_add_params(&input);
        assert!(result.is_err());
        let msg = result.unwrap_err().message;
        assert!(
            msg.contains("Not/A/Timezone") && msg.contains("IANA"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn input_to_add_params_day_out_of_range_returns_error() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.schedule = Some(crate::server::graphql::types::RuleScheduleInput {
            windows: vec![crate::server::graphql::types::WeeklyWindowInput {
                start: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 7, // invalid
                    hour: 9,
                    minute: 0,
                },
                end: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 1,
                    hour: 17,
                    minute: 0,
                },
            }],
            timezone: "UTC".to_string(),
        });
        let result = input_to_add_params(&input);
        assert!(result.is_err());
        let msg = result.unwrap_err().message;
        assert!(
            msg.contains("dayOfWeek") || msg.contains("0–6"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn input_to_add_params_valid_schedule_converts_correctly() {
        let mut input = make_add_rule_input(GqlDirection::Ingress);
        input.schedule = Some(crate::server::graphql::types::RuleScheduleInput {
            windows: vec![crate::server::graphql::types::WeeklyWindowInput {
                start: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 0,
                    hour: 0,
                    minute: 0,
                },
                end: crate::server::graphql::types::WeeklyTimePointInput {
                    day_of_week: 5,
                    hour: 0,
                    minute: 0,
                },
            }],
            timezone: "America/Toronto".to_string(),
        });
        let params = input_to_add_params(&input).expect("should succeed");
        assert!(params.expires_after_secs.is_none());
        let sched = params.schedule.expect("schedule should be set");
        assert_eq!(sched.timezone, "America/Toronto");
        assert_eq!(sched.windows.len(), 1);
        assert_eq!(sched.windows[0].start.day_of_week, 0);
        assert_eq!(sched.windows[0].end.day_of_week, 5);
    }

    #[tokio::test]
    async fn managed_rules_query_returns_empty_when_no_managed_rules() {
        let mock = make_mock_bpf();
        let schema = make_schema(mock);
        let resp = schema
            .execute("{ managedRules(direction: INGRESS) { ruleId ruleState } }")
            .await;
        assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
        let data = resp.data.into_json().unwrap();
        assert_eq!(data["managedRules"], serde_json::json!([]));
    }
}
