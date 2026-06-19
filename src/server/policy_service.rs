// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Policy service - core business logic for policy management
//!
//! This module contains the core business logic separated from the GraphQL layer.
//! It accepts a BpfOperations trait object for testability.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use libc::{IPPROTO_ICMP, IPPROTO_ICMPV6};
use log::{debug, info, warn};
use std::time::Instant;
use tokio::sync::broadcast;

// ── Timer queue command ───────────────────────────────────────────────────────

/// Commands sent to the background `DelayQueue` task.
pub enum QueueCmd {
    /// Schedule a timer to fire at `at` for the given rule.
    Insert {
        rule_id: u64,
        at: tokio::time::Instant,
    },
    /// Cancel any pending timer for the given rule.
    Remove { rule_id: u64 },
}

use crate::shared_types::InterfaceAttachment;
use crate::traits::BpfOperations;
use crate::types::{StopBehavior, *};

use super::rule_events::RuleLifecycleEvent;
use super::rule_registry::{
    is_in_schedule, ManagedRule, RuleLifecycleKind, RuleRegistry, RuleSchedule, RuleState,
    WeeklyTimePoint, WeeklyWindow,
};
use super::state_store::StateStore;

// ── Clock abstraction (for testability) ──────────────────────────────────────

/// Abstraction over the system clock, injectable for unit tests.
pub trait ClockSource: Send + Sync {
    fn now_utc(&self) -> DateTime<Utc>;
}

/// Real-clock implementation.
pub struct SystemClock;

impl ClockSource for SystemClock {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Test-clock implementation: always returns a fixed timestamp.
#[cfg(test)]
pub struct MockClock {
    pub now: DateTime<Utc>,
}

#[cfg(test)]
impl ClockSource for MockClock {
    fn now_utc(&self) -> DateTime<Utc> {
        self.now
    }
}

/// Type alias for the pair of LPM rule lists returned by `list_rules()`
type LpmRuleLists = (
    Vec<(SrcLpmKeyV4, LpmKeyV4, L4Rule)>,
    Vec<(SrcLpmKeyV6, LpmKeyV6, L4Rule)>,
);

/// Result of an operation
#[derive(Debug, Clone)]
pub struct OperationResult {
    pub success: bool,
    pub message: String,
}

impl OperationResult {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
        }
    }
}

/// Server status information
#[derive(Debug, Clone)]
pub struct ServerStatus {
    pub running: bool,
    pub version: String,
    pub uptime_secs: u64,
    /// Whether any program is attached to any interface
    pub program_attached: bool,
}

/// Statistics for a specific rule
#[derive(Debug, Clone)]
pub struct RuleStatsOutput {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

// ── Schedule input types ─────────────────────────────────────────────────────

/// A single point-in-time within a week (service-layer mirror of
/// [`rule_registry::WeeklyTimePoint`], decoupled from GraphQL types).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WeeklyTimePointParams {
    pub day_of_week: u8,
    pub hour: u8,
    pub minute: u8,
}

/// A half-open window `[start, end)` within a repeating week.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WeeklyWindowParams {
    pub start: WeeklyTimePointParams,
    pub end: WeeklyTimePointParams,
}

/// A set of weekly windows plus an IANA timezone name.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleScheduleParams {
    pub windows: Vec<WeeklyWindowParams>,
    pub timezone: String,
}

impl RuleScheduleParams {
    /// Convert to the registry's [`RuleSchedule`] type.
    pub fn to_rule_schedule(&self) -> RuleSchedule {
        RuleSchedule {
            windows: self
                .windows
                .iter()
                .map(|w| WeeklyWindow {
                    start: WeeklyTimePoint {
                        day_of_week: w.start.day_of_week,
                        hour: w.start.hour,
                        minute: w.start.minute,
                    },
                    end: WeeklyTimePoint {
                        day_of_week: w.end.day_of_week,
                        hour: w.end.hour,
                        minute: w.end.minute,
                    },
                })
                .collect(),
            timezone: self.timezone.clone(),
        }
    }
}

/// Input for adding a rule
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddRuleParams {
    pub direction: Direction,
    /// Interface index the rule is scoped to. Callers resolve interface name → ifindex before calling.
    #[serde(default)]
    pub ifindex: u32,
    pub id: Option<u64>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sport: u16,
    pub dport: u16,
    pub protocol: String,
    pub actions: Vec<(PolicyAction, u8, ActionParams)>, // (action, priority, params)
    /// TLS SNI pattern to match (e.g., "example.com" or "*.example.com")
    pub sni: Option<String>,
    /// QUIC version filter (0=off, QUIC_VERSION_* constants)
    pub quic_version: u32,
    /// Source MAC address filter. `None` = no filtering. All-zeros is rejected (use `None`).
    pub src_mac: Option<[u8; 6]>,
    /// Destination MAC address filter. `None` = no filtering. All-zeros is rejected (use `None`).
    pub dst_mac: Option<[u8; 6]>,
    /// Auto-remove rule after this many seconds (mutually exclusive with `schedule`).
    pub expires_after_secs: Option<u32>,
    /// Weekly schedule windows controlling when the rule is active (mutually exclusive
    /// with `expires_after_secs`).
    pub schedule: Option<RuleScheduleParams>,
}

/// Input for deleting a rule
#[derive(Debug, Clone)]
pub struct DeleteRuleParams {
    pub direction: Direction,
    /// Interface index the rule is scoped to. Required for delete-by-src; for
    /// delete-by-id the ifindex is rediscovered from the stored src_key.
    pub ifindex: u32,
    pub id: Option<u64>,
    pub src: Option<String>,
}

/// Result for a single rule in a batch operation
#[derive(Debug, Clone)]
pub struct RuleBatchResult {
    pub index: usize,
    pub rule_id: Option<u64>,
    pub success: bool,
    pub error: Option<String>,
}

/// Policy service - manages policy rules using a BPF backend
pub struct PolicyService {
    bpf_ops: Box<dyn BpfOperations>,
    state_store: Box<dyn StateStore>,
    start_time: Instant,
    /// Whether the XDP (ingress) skeleton has been loaded successfully.
    xdp_loaded: bool,
    /// Whether the TC (egress) skeleton has been loaded successfully.
    tc_loaded: bool,
    /// Cached attachment state to avoid expensive get_attached_interfaces() on every add_rule()
    has_attachments: bool,
    /// Current flow export / IPFIX configuration (kept in memory; persisted separately)
    #[cfg(feature = "ipfix")]
    flow_export_config: FlowExportConfig,
    /// In-memory registry of rules with TTL or schedule constraints.
    rule_registry: RuleRegistry,
    /// Broadcast channel for rule lifecycle events; `None` in tests that don't need it.
    rule_event_tx: Option<broadcast::Sender<RuleLifecycleEvent>>,
    /// Injected clock source (real clock in production, mock in tests).
    clock: Box<dyn ClockSource>,
    /// What to do with BPF state when the daemon stops.
    stop_behavior: StopBehavior,
    /// Sender half of the timer background task command channel.
    /// `None` in tests that don't need timers.
    pub(crate) timer_tx: Option<tokio::sync::mpsc::Sender<QueueCmd>>,
}

/// The candidate rule's match data that lives *outside* the `L4Rule` struct:
/// the already-normalized SNI pattern (lowercased, `*.` stripped for suffix
/// matches) and the raw MAC filters. Used by the duplicate-detection helpers to
/// compare against installed rules' SNI / MAC sidecar entries.
struct CandidateMatch<'a> {
    sni: Option<&'a str>,
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
}

impl PolicyService {
    /// Create a new policy service with the given BPF operations implementation.
    ///
    /// Uses an `InMemoryStateStore` — intended for tests only.  Production code
    /// should call [`PolicyService::new_with_state`] and supply a `FileStateStore`.
    #[cfg(test)]
    pub fn new(bpf_ops: Box<dyn BpfOperations>) -> Self {
        use super::state_store::InMemoryStateStore;
        Self::new_with_state(bpf_ops, Box::new(InMemoryStateStore::new()), false, false)
    }

    /// Create a policy service with a known initial load state and storage backend.
    ///
    /// Use this when the BPF manager was already auto-loaded at startup (pins
    /// survived a server restart), so stats queries work immediately without
    /// waiting for the user to trigger an attach.
    pub fn new_with_state(
        bpf_ops: Box<dyn BpfOperations>,
        state_store: Box<dyn StateStore>,
        xdp_loaded: bool,
        tc_loaded: bool,
    ) -> Self {
        let stop_behavior = state_store.load_stop_behavior().unwrap_or_default();
        Self {
            bpf_ops,
            state_store,
            start_time: Instant::now(),
            xdp_loaded,
            tc_loaded,
            has_attachments: false,
            #[cfg(feature = "ipfix")]
            flow_export_config: load_flow_export_config().unwrap_or_default(),
            rule_registry: RuleRegistry::new(),
            rule_event_tx: None,
            clock: Box::new(SystemClock),
            stop_behavior,
            timer_tx: None,
        }
    }

    /// Restore attachments, default actions, and rules from the state store.
    ///
    /// Called at startup when BPF maps are fresh (after a reboot or BPF version
    /// change).  Not called when maps were reused from pinned state (daemon restart
    /// without reboot) — in that case the kernel already has the correct state.
    ///
    /// Errors from individual restore operations are logged as warnings and
    /// skipped rather than aborting the whole restore, so a stale entry for a
    /// removed interface does not block loading of valid rules.
    pub fn restore_from_store(&mut self) -> Result<()> {
        // 1. Restore attachments first — this loads BPF programs and sets
        //    has_attachments, both of which are required before rules can be added.
        let attachments = self
            .state_store
            .load_attachments()
            .context("restore: failed to load attachments")?;
        for attachment in attachments {
            let result = match attachment.direction {
                Direction::Ingress => {
                    let mode = attachment.mode.unwrap_or(XdpMode::Generic);
                    self.attach_ingress(&attachment.interface, mode)
                }
                Direction::Egress => self.attach_tc(&attachment.interface),
            };
            if let Err(e) = result {
                warn!(
                    "restore: failed to re-attach {} on {}: {:#} — skipping",
                    attachment.direction, attachment.interface, e
                );
            }
        }

        // 2. Restore per-interface default actions (requires programs to be loaded).
        let default_actions = self
            .state_store
            .load_default_actions()
            .context("restore: failed to load default actions")?;
        for entry in default_actions {
            let ifindex = match crate::server::graphql::resolve_ifindex(&entry.interface) {
                Ok(i) => i,
                Err(_) => {
                    warn!(
                        "restore: interface '{}' not found; skipping default action",
                        entry.interface
                    );
                    continue;
                }
            };
            if let Err(e) =
                self.set_default_action(entry.action, entry.direction, ifindex, &entry.interface)
            {
                warn!(
                    "restore: failed to set {}/{} default action to {:?}: {:#}",
                    entry.interface, entry.direction, entry.action, e
                );
            }
        }

        // 3. Restore rules (requires programs loaded and at least one attachment).
        let rules = self
            .state_store
            .load_rules()
            .context("restore: failed to load rules")?;
        let rule_count = rules.len();
        let mut restored = 0usize;
        for persisted in rules {
            // Ensure the ID is set so add_rule_inner reuses it.
            let mut params = persisted.params;
            params.id = Some(persisted.id);
            match self.add_rule(params) {
                Ok(_) => restored += 1,
                Err(e) => warn!(
                    "restore: failed to restore rule {}: {:#} — skipping",
                    persisted.id, e
                ),
            }
        }
        info!(
            "restore_from_store: restored {}/{} rules",
            restored, rule_count
        );
        Ok(())
    }

    /// Attach a rule lifecycle event broadcast sender.
    ///
    /// Called once at startup in `http.rs` after the broadcast channel has been
    /// created.  `PolicyService` will emit events on this channel whenever a
    /// managed rule changes state.
    pub fn with_rule_event_sender(mut self, tx: broadcast::Sender<RuleLifecycleEvent>) -> Self {
        self.rule_event_tx = Some(tx);
        self
    }

    /// Wire up the background timer task command sender.
    pub fn with_timer_sender(mut self, tx: tokio::sync::mpsc::Sender<QueueCmd>) -> Self {
        self.timer_tx = Some(tx);
        self
    }

    /// Fire-and-forget: ask the background timer task to schedule a wakeup for
    /// `rule_id` at `at`.  Silently logs a warning if the channel is full.
    fn send_timer_insert(&self, rule_id: u64, at: tokio::time::Instant) {
        if let Some(ref tx) = self.timer_tx {
            if let Err(e) = tx.try_send(QueueCmd::Insert { rule_id, at }) {
                warn!(
                    "timer_tx: failed to send Insert for rule {}: {}",
                    rule_id, e
                );
            }
        }
    }

    /// Fire-and-forget: ask the background timer task to cancel the timer for
    /// `rule_id`.  Silently logs a warning if the channel is full.
    fn send_timer_remove(&self, rule_id: u64) {
        if let Some(ref tx) = self.timer_tx {
            if let Err(e) = tx.try_send(QueueCmd::Remove { rule_id }) {
                warn!(
                    "timer_tx: failed to send Remove for rule {}: {}",
                    rule_id, e
                );
            }
        }
    }

    /// Replace the clock source (for testing).
    #[cfg(test)]
    pub fn with_clock(mut self, clock: Box<dyn ClockSource>) -> Self {
        self.clock = clock;
        self
    }

    pub fn get_stop_behavior(&self) -> StopBehavior {
        self.stop_behavior
    }

    pub fn set_stop_behavior(&mut self, behavior: StopBehavior) -> anyhow::Result<()> {
        self.state_store.save_stop_behavior(behavior)?;
        self.stop_behavior = behavior;
        info!("Stop behavior set to: {}", behavior);
        Ok(())
    }

    /// Called at daemon shutdown. If stop_behavior is ClearState, detaches all
    /// BPF programs and removes pinned maps so no enforcement runs while the
    /// daemon is down.
    pub fn perform_stop_cleanup(&mut self) {
        match self.stop_behavior {
            StopBehavior::ClearState => {
                info!("Stop behavior is clear-state: detaching BPF programs and removing pins");
                self.bpf_ops.clear_bpf_state();
            }
            StopBehavior::PreserveState => {
                debug!("Stop behavior is preserve-state: leaving BPF programs attached");
            }
        }
    }

    /// Get server status
    pub fn get_status(&self) -> ServerStatus {
        let interfaces = self.bpf_ops.get_attached_interfaces();
        ServerStatus {
            running: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            program_attached: !interfaces.is_empty(),
        }
    }

    /// Whether the XDP (ingress) skeleton has been loaded.
    pub fn is_xdp_loaded(&self) -> bool {
        self.xdp_loaded
    }

    /// Whether the TC (egress) skeleton has been loaded.
    pub fn is_tc_loaded(&self) -> bool {
        self.tc_loaded
    }

    /// Whether both BPF skeletons have been loaded.
    pub fn is_programs_loaded(&self) -> bool {
        self.xdp_loaded && self.tc_loaded
    }

    /// Whether the skeleton for the given direction has been loaded.
    pub fn is_direction_loaded(&self, direction: Direction) -> bool {
        match direction {
            Direction::Ingress => self.xdp_loaded,
            Direction::Egress => self.tc_loaded,
        }
    }

    /// Ensure the XDP (ingress) skeleton is loaded.
    ///
    /// `load_programs()` always loads both XDP and TC atomically, so on
    /// success both flags are set.  Callers that only need ingress can use
    /// this instead of `ensure_programs_loaded()` so that a TC load failure
    /// does not block purely ingress operations on retry.
    fn ensure_xdp_loaded(&mut self) -> Result<()> {
        if !self.xdp_loaded {
            self.bpf_ops.load_programs()?;
            self.xdp_loaded = true;
            self.tc_loaded = true;
        }
        Ok(())
    }

    /// Ensure the TC (egress) skeleton is loaded.
    fn ensure_tc_loaded(&mut self) -> Result<()> {
        if !self.tc_loaded {
            self.bpf_ops.load_programs()?;
            self.xdp_loaded = true;
            self.tc_loaded = true;
        }
        Ok(())
    }

    /// Ensure both BPF skeletons are loaded.
    pub fn ensure_programs_loaded(&mut self) -> Result<()> {
        self.ensure_xdp_loaded()?;
        self.ensure_tc_loaded()
    }

    /// Ensure the skeleton for the given direction is loaded.
    fn ensure_direction_loaded(&mut self, direction: Direction) -> Result<()> {
        match direction {
            Direction::Ingress => self.ensure_xdp_loaded(),
            Direction::Egress => self.ensure_tc_loaded(),
        }
    }

    /// Get all attached interfaces
    pub fn get_interfaces(&self) -> Vec<InterfaceAttachment> {
        self.bpf_ops.get_attached_interfaces()
    }

    /// Attach ingress program to an interface with automatic mode selection
    pub fn attach_ingress_auto(&mut self, interface: &str) -> Result<OperationResult> {
        self.ensure_xdp_loaded()?;

        let modes_to_try = [
            (XdpMode::Offload, "offload"),
            (XdpMode::Native, "native"),
            (XdpMode::Generic, "generic"),
        ];

        let mut last_error = String::new();
        for (mode, mode_name) in modes_to_try {
            match self.bpf_ops.attach_ingress(interface, mode) {
                Ok(()) => {
                    self.has_attachments = true;
                    if let Err(e) =
                        self.state_store
                            .save_attachment(interface, Direction::Ingress, Some(mode))
                    {
                        warn!(
                            "state_store: failed to persist ingress attachment for {}: {:#}",
                            interface, e
                        );
                    }
                    info!(
                        "Attached ingress to {} in {} mode (auto-selected)",
                        interface, mode_name
                    );
                    return Ok(OperationResult::success(format!(
                        "Attached ingress program to {} in {} mode (auto-selected)",
                        interface, mode_name
                    )));
                }
                Err(e) => {
                    debug!(
                        "Failed to attach ingress in {} mode: {}, trying next...",
                        mode_name, e
                    );
                    last_error = e.to_string();
                }
            }
        }

        Err(anyhow!(
            "Failed to attach ingress in any mode. Last error: {}",
            last_error
        ))
    }

    /// Attach ingress program to an interface with specific mode
    pub fn attach_ingress(&mut self, interface: &str, mode: XdpMode) -> Result<OperationResult> {
        self.ensure_xdp_loaded()?;

        self.bpf_ops
            .attach_ingress(interface, mode)
            .context("Failed to attach ingress")?;

        self.has_attachments = true;

        if let Err(e) = self
            .state_store
            .save_attachment(interface, Direction::Ingress, Some(mode))
        {
            warn!(
                "state_store: failed to persist ingress attachment for {}: {:#}",
                interface, e
            );
        }

        let mode_name = match mode {
            XdpMode::Unspec => "unspec",
            XdpMode::Native => "native",
            XdpMode::Generic => "generic",
            XdpMode::Offload => "offload",
        };

        info!("Attached ingress to {} in {:?} mode", interface, mode);

        Ok(OperationResult::success(format!(
            "Attached ingress program to {} in {} mode",
            interface, mode_name
        )))
    }

    /// Clear interface stats and per-rule stats for all rules scoped to this interface+direction.
    /// Failures are non-fatal — logged as warnings so a stat-clear hiccup cannot abort a detach.
    fn clear_stats_on_detach(&mut self, ifindex: u32, direction: Direction) {
        if let Err(e) = self.bpf_ops.clear_interface_stats(ifindex, direction) {
            warn!(
                "Failed to clear {} interface stats for ifindex {}: {:#}",
                direction, ifindex, e
            );
        }
        let v4_rules = self
            .bpf_ops
            .list_policy_rules_v4(direction)
            .unwrap_or_default();
        let v6_rules = self
            .bpf_ops
            .list_policy_rules_v6(direction)
            .unwrap_or_default();
        for (src_key, _, rule) in v4_rules {
            if src_key.ifindex == ifindex {
                let rule_id = rule.rule_id;
                if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                    warn!("Failed to clear rule {} stats: {:#}", rule_id, e);
                }
            }
        }
        for (src_key, _, rule) in v6_rules {
            if src_key.ifindex == ifindex {
                let rule_id = rule.rule_id;
                if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                    warn!("Failed to clear rule {} stats: {:#}", rule_id, e);
                }
            }
        }
    }

    /// Detach ingress program from an interface
    pub fn detach_ingress(&mut self, interface: &str) -> Result<OperationResult> {
        // Snapshot attached interfaces before detach to obtain ifindex and compute has_attachments.
        let attached = self.bpf_ops.get_attached_interfaces();
        let ifindex = attached
            .iter()
            .find(|a| a.interface == interface && a.direction == "ingress")
            .map(|a| a.ifindex as u32);

        self.bpf_ops
            .detach_ingress(interface)
            .context("Failed to detach ingress")?;

        // Compute whether any attachments remain without a second syscall.
        self.has_attachments = attached
            .iter()
            .any(|a| !(a.interface == interface && a.direction == "ingress"));

        if let Err(e) = self
            .state_store
            .delete_attachment(interface, Direction::Ingress)
        {
            warn!(
                "state_store: failed to remove ingress attachment for {}: {:#}",
                interface, e
            );
        }

        if let Some(ifindex) = ifindex {
            self.clear_stats_on_detach(ifindex, Direction::Ingress);
        }

        info!("Detached ingress from {}", interface);

        Ok(OperationResult::success(format!(
            "Detached ingress program from {}",
            interface
        )))
    }

    /// Attach egress program to an interface
    pub fn attach_tc(&mut self, interface: &str) -> Result<OperationResult> {
        self.ensure_tc_loaded()?;

        self.bpf_ops
            .attach_tc(interface)
            .context("Failed to attach egress")?;

        self.has_attachments = true;

        if let Err(e) = self
            .state_store
            .save_attachment(interface, Direction::Egress, None)
        {
            warn!(
                "state_store: failed to persist egress attachment for {}: {:#}",
                interface, e
            );
        }

        info!("Attached egress to {}", interface);

        Ok(OperationResult::success(format!(
            "Attached egress program to {}",
            interface
        )))
    }

    /// Detach egress program from an interface
    pub fn detach_tc(&mut self, interface: &str) -> Result<OperationResult> {
        // Snapshot attached interfaces before detach to obtain ifindex and compute has_attachments.
        let attached = self.bpf_ops.get_attached_interfaces();
        let ifindex = attached
            .iter()
            .find(|a| a.interface == interface && a.direction == "egress")
            .map(|a| a.ifindex as u32);

        self.bpf_ops
            .detach_tc(interface)
            .context("Failed to detach egress")?;

        // Compute whether any attachments remain without a second syscall.
        self.has_attachments = attached
            .iter()
            .any(|a| !(a.interface == interface && a.direction == "egress"));

        if let Err(e) = self
            .state_store
            .delete_attachment(interface, Direction::Egress)
        {
            warn!(
                "state_store: failed to remove egress attachment for {}: {:#}",
                interface, e
            );
        }

        if let Some(ifindex) = ifindex {
            self.clear_stats_on_detach(ifindex, Direction::Egress);
        }

        info!("Detached egress from {}", interface);

        Ok(OperationResult::success(format!(
            "Detached egress program from {}",
            interface
        )))
    }

    /// Detach all programs (both ingress and egress)
    pub fn detach_all(&mut self) -> Result<OperationResult> {
        let interfaces = self.bpf_ops.get_attached_interfaces();
        let mut count = 0;

        for iface in &interfaces {
            let ifindex = iface.ifindex as u32;
            match iface.direction.as_str() {
                "egress" => {
                    if self.bpf_ops.detach_tc(&iface.interface).is_ok() {
                        count += 1;
                        self.clear_stats_on_detach(ifindex, Direction::Egress);
                        if let Err(e) = self
                            .state_store
                            .delete_attachment(&iface.interface, Direction::Egress)
                        {
                            warn!(
                                "state_store: failed to remove egress attachment for {}: {:#}",
                                iface.interface, e
                            );
                        }
                    }
                }
                _ => {
                    if self.bpf_ops.detach_ingress(&iface.interface).is_ok() {
                        count += 1;
                        self.clear_stats_on_detach(ifindex, Direction::Ingress);
                        if let Err(e) = self
                            .state_store
                            .delete_attachment(&iface.interface, Direction::Ingress)
                        {
                            warn!(
                                "state_store: failed to remove ingress attachment for {}: {:#}",
                                iface.interface, e
                            );
                        }
                    }
                }
            }
        }

        // Refresh cache — check if external attachments remain
        self.has_attachments = !self.bpf_ops.get_attached_interfaces().is_empty();

        info!("Detached {} program(s)", count);

        Ok(OperationResult::success(format!(
            "Detached {} program(s)",
            count
        )))
    }

    /// Get global statistics for an interface
    pub fn get_global_stats(&mut self, ifindex: u32, direction: Direction) -> Result<GlobalStats> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.get_global_stats(ifindex, direction)
    }

    /// Get processing-time histogram (64 buckets, summed across CPUs)
    pub fn get_processing_time_hist(&mut self, direction: Direction) -> Result<Vec<u64>> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.get_processing_time_hist(direction)
    }

    /// Get per-protocol packet/byte stats (256 entries, summed across CPUs)
    pub fn get_proto_stats(
        &mut self,
        direction: Direction,
    ) -> Result<Vec<crate::types::ProtoStats>> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.get_proto_stats(direction)
    }

    /// Get L3 protocol stats (4 buckets: IPv4/IPv6/ARP/Other)
    pub fn get_l3_stats(&mut self, direction: Direction) -> Result<Vec<crate::types::ProtoStats>> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.get_l3_stats(direction)
    }

    /// Get per-QUIC-version stats (ingress only; egress returns empty vec)
    pub fn get_quic_stats(&mut self, direction: Direction) -> Result<Vec<(String, u64, u64)>> {
        if direction == Direction::Ingress {
            self.ensure_direction_loaded(direction)?;
        }
        self.bpf_ops.get_quic_stats(direction)
    }

    /// Get ethertype statistics for an interface
    pub fn get_ethertype_stats(
        &mut self,
        ifindex: u32,
        direction: Direction,
    ) -> Result<Vec<EthertypeStats>> {
        if direction == Direction::Egress {
            return Ok(vec![]);
        }
        self.ensure_xdp_loaded()?;
        self.bpf_ops.get_ethertype_stats(ifindex, direction)
    }

    /// Get non-IP sender statistics for an interface (ingress only).
    pub fn get_nonip_senders(&mut self, ifindex: u32) -> Result<Vec<NonIpSenderEntry>> {
        self.ensure_xdp_loaded()?;
        self.bpf_ops.get_nonip_senders(ifindex)
    }

    /// Get statistics for a specific rule
    pub fn get_rule_stats(
        &mut self,
        rule_id: u64,
        direction: Direction,
    ) -> Result<Option<RuleStatsOutput>> {
        self.ensure_direction_loaded(direction)?;

        let stats = self.bpf_ops.get_rule_stats(rule_id, direction)?;
        Ok(stats.map(|s| RuleStatsOutput {
            packets: s.packets,
            bytes: s.bytes,
            last_seen_ns: s.last_seen_ns,
        }))
    }

    /// List all policy rules (IPv4 and IPv6)
    pub fn list_rules(&mut self, direction: Direction) -> Result<LpmRuleLists> {
        self.ensure_direction_loaded(direction)?;

        let v4_rules = self.bpf_ops.list_policy_rules_v4(direction)?;
        let v6_rules = self.bpf_ops.list_policy_rules_v6(direction)?;

        Ok((v4_rules, v6_rules))
    }

    /// Check if a program is attached for the specific direction requested.
    ///
    /// Always queries the system so that attachments made (or removed) in previous
    /// server sessions are correctly detected.
    fn check_attachments(&mut self, direction: Direction) -> Result<()> {
        let dir_name = match direction {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        };

        let interfaces = self.bpf_ops.get_attached_interfaces();
        self.has_attachments = !interfaces.is_empty();

        let has_direction = interfaces.iter().any(|a| a.direction == dir_name);
        if !has_direction {
            let mutation = match direction {
                Direction::Ingress => "attachIngress",
                Direction::Egress => "attachEgress",
            };
            return Err(anyhow!(
                "No {} programs attached. Use {} first.",
                dir_name,
                mutation
            ));
        }
        Ok(())
    }

    /// Add a policy rule
    pub fn add_rule(&mut self, params: AddRuleParams) -> Result<OperationResult> {
        // Validate lifecycle params up-front.
        if params.expires_after_secs.is_some() && params.schedule.is_some() {
            return Err(anyhow!(
                "expires_after_secs and schedule are mutually exclusive"
            ));
        }

        self.check_attachments(params.direction)?;
        self.ensure_direction_loaded(params.direction)?;

        let direction = params.direction;
        let num_actions = params.actions.len();
        let lifecycle = self.build_lifecycle(&params);

        let rule_id = self.add_rule_inner(params.clone())?;

        // Register the rule if it has a lifecycle constraint.
        if let Some(lk) = lifecycle {
            let now_utc = self.clock.now_utc();
            let initially_in_window = match &lk {
                RuleLifecycleKind::Ttl { .. } => true,
                RuleLifecycleKind::Scheduled { schedule } => is_in_schedule(schedule, now_utc),
            };

            let initial_state = if initially_in_window {
                RuleState::Active
            } else {
                // Rule was installed by add_rule_inner above but the window is
                // currently closed — remove it from BPF maps immediately.
                if let Err(e) = self.delete_rule_by_id(rule_id, direction) {
                    warn!(
                        "add_rule: failed to remove out-of-window rule {}: {}",
                        rule_id, e
                    );
                }
                RuleState::Inactive
            };

            let event_type = if initial_state == RuleState::Active {
                "activated"
            } else {
                "added"
            };

            // Compute the timer instant for the background DelayQueue task.
            let timer_at: Option<tokio::time::Instant> = match &lk {
                RuleLifecycleKind::Ttl { expires_at } => {
                    let dur = (*expires_at - now_utc).to_std().unwrap_or_default();
                    Some(tokio::time::Instant::now() + dur)
                }
                RuleLifecycleKind::Scheduled { schedule } => {
                    use super::rule_registry::next_schedule_transition;
                    next_schedule_transition(schedule, now_utc).map(|t| {
                        let dur = (t - now_utc).to_std().unwrap_or_default();
                        tokio::time::Instant::now() + dur
                    })
                }
            };

            self.rule_registry.register(ManagedRule {
                rule_id,
                params,
                direction,
                lifecycle: lk,
                state: initial_state,
                delay_key: None,
            });

            if let Some(at) = timer_at {
                self.send_timer_insert(rule_id, at);
            }

            self.emit_rule_event(event_type, rule_id, direction, None);
        } else {
            // Permanent rule: always immediately active.
            self.emit_rule_event("activated", rule_id, direction, None);
        }

        Ok(OperationResult::success(format!(
            "Added rule {} with {} action(s)",
            rule_id, num_actions
        )))
    }

    /// Build a [`RuleLifecycleKind`] from the optional TTL / schedule fields of
    /// `params`.  Returns `None` for permanent rules.
    fn build_lifecycle(&self, params: &AddRuleParams) -> Option<RuleLifecycleKind> {
        if let Some(secs) = params.expires_after_secs {
            let expires_at = self.clock.now_utc() + chrono::Duration::seconds(secs as i64);
            Some(RuleLifecycleKind::Ttl { expires_at })
        } else {
            params
                .schedule
                .as_ref()
                .map(|sched| RuleLifecycleKind::Scheduled {
                    schedule: sched.to_rule_schedule(),
                })
        }
    }

    /// Delete a rule from the BPF maps by ID (helper used by the scheduler and
    /// public `delete_rule`).  Does NOT touch the registry.
    fn delete_rule_by_id(&mut self, rule_id: u64, direction: Direction) -> Result<()> {
        // Search IPv4 rules
        let v4_rules = self.bpf_ops.list_policy_rules_v4(direction)?;
        for (src_key, dst_key, rule) in &v4_rules {
            if rule.rule_id == rule_id {
                self.bpf_ops
                    .delete_policy_rule_v4(src_key, dst_key, rule_id, direction)?;
                if rule.sni_match_type != SNI_MATCH_NONE {
                    let _ = self.bpf_ops.delete_sni_rule(rule_id, direction);
                }
                if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                    warn!("Failed to clear rule {} stats on delete: {:#}", rule_id, e);
                }
                if let Err(e) = self.state_store.delete_rule(rule_id) {
                    warn!("state_store: failed to remove rule {}: {:#}", rule_id, e);
                }
                return Ok(());
            }
        }
        // Search IPv6 rules
        let v6_rules = self.bpf_ops.list_policy_rules_v6(direction)?;
        for (src_key, dst_key, rule) in &v6_rules {
            if rule.rule_id == rule_id {
                self.bpf_ops
                    .delete_policy_rule_v6(src_key, dst_key, rule_id, direction)?;
                if rule.sni_match_type != SNI_MATCH_NONE {
                    let _ = self.bpf_ops.delete_sni_rule(rule_id, direction);
                }
                if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                    warn!("Failed to clear rule {} stats on delete: {:#}", rule_id, e);
                }
                if let Err(e) = self.state_store.delete_rule(rule_id) {
                    warn!("state_store: failed to remove rule {}: {:#}", rule_id, e);
                }
                return Ok(());
            }
        }
        // Not in BPF maps (may already have been removed); treat as success.
        Ok(())
    }

    /// Emit a rule lifecycle event on the broadcast channel (no-op if no sender
    /// has been wired up, which is the case in tests that don't need events).
    fn emit_rule_event(
        &self,
        event_type: &str,
        rule_id: u64,
        direction: Direction,
        reason: Option<String>,
    ) {
        if let Some(ref tx) = self.rule_event_tx {
            let dir_str = match direction {
                Direction::Ingress => "INGRESS",
                Direction::Egress => "EGRESS",
            };
            let ev = RuleLifecycleEvent::new(event_type, rule_id, dir_str, reason);
            let _ = tx.send(ev);
        }
    }

    /// Handle a timer expiry fired by the background `DelayQueue` task.
    ///
    /// - **TTL rule**: removes the rule from the registry; if it was `Active`,
    ///   also removes it from the BPF maps.  Emits an `"expired"` event.
    ///   Returns `None` (no reschedule needed).
    ///
    /// - **Scheduled rule**: performs the appropriate state transition
    ///   (Active → deactivate, Inactive → activate) then computes the next
    ///   schedule transition and returns `Some(Instant)` so the background
    ///   task can re-insert the rule into the queue.
    ///
    /// - **Unknown rule_id** (already deleted): returns `None` silently.
    pub fn handle_timer_expiry(&mut self, rule_id: u64) -> Option<tokio::time::Instant> {
        match self.rule_registry.get(rule_id)?.lifecycle.clone() {
            RuleLifecycleKind::Ttl { .. } => {
                // Remove from registry.
                if let Some(managed) = self.rule_registry.remove(rule_id) {
                    let direction = managed.direction;
                    if managed.state == RuleState::Active {
                        if let Err(e) = self.delete_rule_by_id(rule_id, direction) {
                            warn!(
                                "handle_timer_expiry: failed to remove expired rule {}: {}",
                                rule_id, e
                            );
                        }
                    }
                    self.emit_rule_event(
                        "expired",
                        rule_id,
                        direction,
                        Some("ttl_expired".to_string()),
                    );
                }
                None
            }
            RuleLifecycleKind::Scheduled { schedule } => {
                let managed = self.rule_registry.get(rule_id).unwrap();
                let current_state = managed.state.clone();
                let direction = managed.direction;
                let params = managed.params.clone();

                let now_utc = self.clock.now_utc();

                match current_state {
                    RuleState::Active => {
                        // Window just closed — deactivate.
                        match self.delete_rule_by_id(rule_id, direction) {
                            Ok(_) => {
                                if let Some(m) = self.rule_registry.get_mut(rule_id) {
                                    m.state = RuleState::Inactive;
                                }
                                self.emit_rule_event(
                                    "deactivated",
                                    rule_id,
                                    direction,
                                    Some("schedule_window_end".to_string()),
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "handle_timer_expiry: failed to deactivate rule {}: {}",
                                    rule_id, e
                                );
                            }
                        }
                    }
                    RuleState::Inactive => {
                        // Window just opened — activate.
                        match self.add_rule_inner(params) {
                            Ok(_) => {
                                if let Some(m) = self.rule_registry.get_mut(rule_id) {
                                    m.state = RuleState::Active;
                                }
                                self.emit_rule_event(
                                    "activated",
                                    rule_id,
                                    direction,
                                    Some("schedule_window_start".to_string()),
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "handle_timer_expiry: failed to activate rule {}: {}",
                                    rule_id, e
                                );
                            }
                        }
                    }
                }

                // Compute next transition and return the instant for rescheduling.
                use super::rule_registry::next_schedule_transition;
                next_schedule_transition(&schedule, now_utc).map(|t| {
                    let dur = (t - now_utc).to_std().unwrap_or_default();
                    tokio::time::Instant::now() + dur
                })
            }
        }
    }

    /// Return a snapshot of all rules currently tracked by the registry.
    pub fn list_managed_rules(&self) -> Vec<&ManagedRule> {
        self.rule_registry.list().collect()
    }

    /// Add multiple policy rules in a batch, checking attachments and programs once.
    ///
    /// All rules in a batch must share the same direction.
    pub fn add_rules_batch(
        &mut self,
        rules: Vec<AddRuleParams>,
        direction: Direction,
    ) -> Vec<RuleBatchResult> {
        let mut results = Vec::with_capacity(rules.len());

        // Check attachments once for the entire batch
        if let Err(e) = self.check_attachments(direction) {
            for (i, params) in rules.iter().enumerate() {
                results.push(RuleBatchResult {
                    index: i,
                    rule_id: params.id,
                    success: false,
                    error: Some(e.to_string()),
                });
            }
            return results;
        }

        // Ensure the direction-appropriate skeleton is loaded once for the entire batch
        if let Err(e) = self.ensure_direction_loaded(direction) {
            for (i, params) in rules.iter().enumerate() {
                results.push(RuleBatchResult {
                    index: i,
                    rule_id: params.id,
                    success: false,
                    error: Some(e.to_string()),
                });
            }
            return results;
        }

        for (i, params) in rules.into_iter().enumerate() {
            match self.add_rule_inner(params) {
                Ok(rule_id) => {
                    results.push(RuleBatchResult {
                        index: i,
                        rule_id: Some(rule_id),
                        success: true,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(RuleBatchResult {
                        index: i,
                        rule_id: None,
                        success: false,
                        error: Some(format!("{}", e)),
                    });
                }
            }
        }

        results
    }

    /// Inner add_rule logic — skips attachment and program checks (caller must ensure).
    fn add_rule_inner(&mut self, params: AddRuleParams) -> Result<u64> {
        // Validate actions
        if params.actions.is_empty() {
            return Err(anyhow!("At least one action must be specified"));
        }

        // Validate MAC filters: all-zeros MAC with flag set is confusing (use None instead)
        if params.src_mac == Some([0u8; 6]) {
            return Err(anyhow!(
                "src_mac all-zeros is a wildcard — omit the field instead of passing 00:00:00:00:00:00"
            ));
        }
        if params.dst_mac == Some([0u8; 6]) {
            return Err(anyhow!(
                "dst_mac all-zeros is a wildcard — omit the field instead of passing 00:00:00:00:00:00"
            ));
        }

        // Parse protocol
        let protocol: Protocol = params.protocol.as_str().try_into()?;

        // Generate rule ID if not provided
        let rule_id = params.id.unwrap_or_else(|| {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(1)
        });

        // Parse source and destination networks
        let src_str = params.src.as_deref().unwrap_or("0.0.0.0/0");
        let src_net: ipnetwork::IpNetwork = src_str
            .parse()
            .map_err(|e| anyhow!("Invalid source CIDR: {}", e))?;

        let dst_str = params.dst.as_deref().unwrap_or_else(|| {
            if src_net.is_ipv6() {
                "::/0"
            } else {
                "0.0.0.0/0"
            }
        });
        let dst_net: ipnetwork::IpNetwork = dst_str
            .parse()
            .map_err(|e| anyhow!("Invalid destination CIDR: {}", e))?;

        let (src_net, dst_net) = if params.src.is_none() && dst_net.is_ipv6() {
            let src_net: ipnetwork::IpNetwork =
                "::/0".parse().expect("Failed to parse default IPv6 source");
            (src_net, dst_net)
        } else {
            (src_net, dst_net)
        };

        // Auto-convert ICMP to ICMPv6 for IPv6 rules
        let protocol = if src_net.is_ipv6() && *protocol == IPPROTO_ICMP as u8 {
            Protocol::new(IPPROTO_ICMPV6 as u8)
        } else {
            protocol
        };

        // Validate and parse SNI pattern
        let sni_config = if let Some(ref sni_pattern) = params.sni {
            let pattern = sni_pattern.trim().to_lowercase();
            if pattern.is_empty() {
                None
            } else if let Some(suffix) = pattern.strip_prefix("*.") {
                if suffix.is_empty() {
                    return Err(anyhow!("SNI wildcard pattern requires a domain after '*.'"));
                }
                if suffix.len() >= crate::types::MAX_SNI_LEN {
                    return Err(anyhow!(
                        "SNI pattern too long (max {} characters)",
                        crate::types::MAX_SNI_LEN - 1
                    ));
                }
                Some((crate::types::SNI_MATCH_SUFFIX, suffix.to_string()))
            } else {
                if pattern.len() >= crate::types::MAX_SNI_LEN {
                    return Err(anyhow!(
                        "SNI pattern too long (max {} characters)",
                        crate::types::MAX_SNI_LEN - 1
                    ));
                }
                Some((crate::types::SNI_MATCH_EXACT, pattern))
            }
        } else {
            None
        };

        // SNI matching applies to either TCP (TLS handshake, parsed in-kernel
        // by the SNI tail call) or UDP (QUIC Initial, decrypted in userspace by
        // the QUIC inspector).  Anything else has no SNI semantics.
        if sni_config.is_some()
            && *protocol != libc::IPPROTO_TCP as u8
            && *protocol != libc::IPPROTO_UDP as u8
        {
            return Err(anyhow!(
                "SNI matching requires TCP or UDP protocol (got {})",
                protocol
            ));
        }

        // QUIC version filter only makes sense for UDP or any protocol
        if params.quic_version != 0 && *protocol != libc::IPPROTO_UDP as u8 && *protocol != 0 {
            return Err(anyhow!(
                "QUIC version filter requires UDP protocol or 'any' (got {})",
                protocol
            ));
        }

        // Check for duplicate action types
        {
            let mut seen = std::collections::HashSet::new();
            for (action, _, _) in &params.actions {
                if !seen.insert(*action as u32) {
                    return Err(anyhow!("Duplicate action type: {:?}", action));
                }
            }
        }

        // Sort actions by priority
        let mut sorted_actions = params.actions.clone();
        sorted_actions.sort_by_key(|(_, p, _)| *p);

        let lpm_actions: Vec<(PolicyAction, u8, ActionParams)> = sorted_actions
            .iter()
            .map(|(a, p, params)| (*a, *p, *params))
            .collect();

        // Candidate sidecar data (SNI pattern + MAC filters) for duplicate detection.
        let candidate = CandidateMatch {
            sni: sni_config.as_ref().map(|(_, p)| p.as_str()),
            src_mac: params.src_mac,
            dst_mac: params.dst_mac,
        };

        match (&src_net, &dst_net) {
            (ipnetwork::IpNetwork::V4(s), ipnetwork::IpNetwork::V4(d)) => {
                let src_key = SrcLpmKeyV4::new(params.ifindex, s.network(), s.prefix());
                let dst_key = LpmKeyV4::new(d.network(), d.prefix());
                let mut rule = L4Rule {
                    sport: params.sport,
                    dport: params.dport,
                    protocol: *protocol,
                    sni_match_type: sni_config.as_ref().map_or(SNI_MATCH_NONE, |(mt, _)| *mt),
                    rule_id,
                    quic_version: params.quic_version,
                    ..L4Rule::default()
                };
                rule.set_actions(&lpm_actions);
                rule.set_mac_filter(params.src_mac, params.dst_mac);

                if let Some(existing_id) = self.find_duplicate_rule_v4(
                    &src_key,
                    &dst_key,
                    &rule,
                    &candidate,
                    params.direction,
                )? {
                    return Err(anyhow!(
                        "A rule with identical match criteria already exists (rule {}) on this interface/direction",
                        existing_id
                    ));
                }

                self.bpf_ops
                    .add_policy_rule_v4(&src_key, &dst_key, &rule, params.direction)
                    .context("Failed to add rule")?;
            }
            (ipnetwork::IpNetwork::V6(s), ipnetwork::IpNetwork::V6(d)) => {
                let src_key = SrcLpmKeyV6::new(params.ifindex, s.network(), s.prefix());
                let dst_key = LpmKeyV6::new(d.network(), d.prefix());
                let mut rule = L4Rule {
                    sport: params.sport,
                    dport: params.dport,
                    protocol: *protocol,
                    sni_match_type: sni_config.as_ref().map_or(SNI_MATCH_NONE, |(mt, _)| *mt),
                    rule_id,
                    quic_version: params.quic_version,
                    ..L4Rule::default()
                };
                rule.set_actions(&lpm_actions);
                rule.set_mac_filter(params.src_mac, params.dst_mac);

                if let Some(existing_id) = self.find_duplicate_rule_v6(
                    &src_key,
                    &dst_key,
                    &rule,
                    &candidate,
                    params.direction,
                )? {
                    return Err(anyhow!(
                        "A rule with identical match criteria already exists (rule {}) on this interface/direction",
                        existing_id
                    ));
                }

                self.bpf_ops
                    .add_policy_rule_v6(&src_key, &dst_key, &rule, params.direction)
                    .context("Failed to add rule")?;
            }
            _ => {
                return Err(anyhow!(
                    "Source and destination must be the same IP version"
                ));
            }
        }

        // Write SNI pattern to the dedicated sni_rules map.
        // Must happen after the LPM rule is written so the sni_match_type flag
        // in the LPM entry and the pattern in sni_rules are always in sync.
        if let Some((match_type, ref pattern)) = sni_config {
            let sni_entry = crate::types::SniRuleEntry::new(match_type, pattern);
            self.bpf_ops
                .add_sni_rule(rule_id, &sni_entry, params.direction)
                .context("Failed to add SNI rule")?;
        }

        // Write MAC addresses to the dedicated mac_rules sidecar map when
        // mac_match_flags is set in the LPM rule. Must happen after the LPM
        // write so the flag and the sidecar entry are always in sync.
        if params.src_mac.is_some() || params.dst_mac.is_some() {
            let mac_entry = crate::types::MacRuleEntry {
                src_mac: params.src_mac.unwrap_or([0u8; 6]),
                dst_mac: params.dst_mac.unwrap_or([0u8; 6]),
            };
            self.bpf_ops
                .add_mac_rule(rule_id, &mac_entry, params.direction)
                .context("Failed to add MAC rule")?;
        }

        debug!(
            "Added rule {} with {} action(s)",
            rule_id,
            params.actions.len()
        );

        // Persist with the assigned ID so restore reproduces the same rule_id.
        let mut persisted_params = params.clone();
        persisted_params.id = Some(rule_id);
        if let Err(e) = self.state_store.save_rule(rule_id, &persisted_params) {
            warn!("state_store: failed to persist rule {}: {:#}", rule_id, e);
        }

        Ok(rule_id)
    }

    /// Compare the match-relevant fields of a candidate rule against an
    /// already-installed `existing` L4 rule (ports, protocol, QUIC version, and
    /// the SNI / MAC sidecar entries). The L3 keys (ifindex + src/dst prefixes)
    /// are compared by the callers. Returns `true` when both rules would match
    /// identical traffic — i.e. they are duplicates.
    ///
    /// `new` carries the candidate's SNI pattern and MAC filters; sidecar entries
    /// for the existing rule are read back via `lookup_sni_rule` / `lookup_mac_rule`.
    fn l4_match_equal(
        &self,
        new_rule: &L4Rule,
        new: &CandidateMatch,
        existing: &L4Rule,
        direction: Direction,
    ) -> bool {
        if new_rule.sport != existing.sport
            || new_rule.dport != existing.dport
            || new_rule.protocol != existing.protocol
            || new_rule.quic_version != existing.quic_version
            || new_rule.sni_match_type != existing.sni_match_type
            || new_rule.mac_match_flags != existing.mac_match_flags
        {
            return false;
        }

        // Same SNI match *kind* — compare the actual patterns from the sidecar map.
        if existing.sni_match_type != SNI_MATCH_NONE {
            let existing_entry = match self.bpf_ops.lookup_sni_rule(existing.rule_id, direction) {
                Ok(Some(e)) => e,
                _ => return false,
            };
            let new_entry = SniRuleEntry::new(existing.sni_match_type, new.sni.unwrap_or(""));
            if new_entry.as_bytes() != existing_entry.as_bytes() {
                return false;
            }
        }

        // Same MAC match flags — compare the actual addresses from the sidecar map.
        if existing.mac_match_flags != 0 {
            let existing_mac = match self.bpf_ops.lookup_mac_rule(existing.rule_id, direction) {
                Ok(Some(m)) => m,
                _ => return false,
            };
            if new.src_mac.unwrap_or([0u8; 6]) != existing_mac.src_mac
                || new.dst_mac.unwrap_or([0u8; 6]) != existing_mac.dst_mac
            {
                return false;
            }
        }

        true
    }

    /// Return the rule_id of an already-installed IPv4 rule whose full match
    /// criteria (interface, src/dst prefix, ports, protocol, SNI, QUIC, MAC) are
    /// identical to the candidate, or `None` if no such rule exists. Rules with
    /// the same `rule_id` as the candidate are skipped so restore and scheduled
    /// re-activation never collide with themselves.
    fn find_duplicate_rule_v4(
        &self,
        src_key: &SrcLpmKeyV4,
        dst_key: &LpmKeyV4,
        rule: &L4Rule,
        new: &CandidateMatch,
        direction: Direction,
    ) -> Result<Option<u64>> {
        for (e_src, e_dst, e_rule) in self.bpf_ops.list_policy_rules_v4(direction)? {
            if e_rule.rule_id == rule.rule_id {
                continue;
            }
            if e_src.ifindex == src_key.ifindex
                && e_src.prefixlen == src_key.prefixlen
                && e_src.addr == src_key.addr
                && e_dst.prefixlen == dst_key.prefixlen
                && e_dst.addr == dst_key.addr
                && self.l4_match_equal(rule, new, &e_rule, direction)
            {
                return Ok(Some(e_rule.rule_id));
            }
        }
        Ok(None)
    }

    /// IPv6 counterpart of [`find_duplicate_rule_v4`].
    fn find_duplicate_rule_v6(
        &self,
        src_key: &SrcLpmKeyV6,
        dst_key: &LpmKeyV6,
        rule: &L4Rule,
        new: &CandidateMatch,
        direction: Direction,
    ) -> Result<Option<u64>> {
        for (e_src, e_dst, e_rule) in self.bpf_ops.list_policy_rules_v6(direction)? {
            if e_rule.rule_id == rule.rule_id {
                continue;
            }
            if e_src.ifindex == src_key.ifindex
                && e_src.prefixlen == src_key.prefixlen
                && e_src.addr == src_key.addr
                && e_dst.prefixlen == dst_key.prefixlen
                && e_dst.addr == dst_key.addr
                && self.l4_match_equal(rule, new, &e_rule, direction)
            {
                return Ok(Some(e_rule.rule_id));
            }
        }
        Ok(None)
    }

    /// Delete a policy rule by ID or source CIDR
    pub fn delete_rule(&mut self, params: DeleteRuleParams) -> Result<OperationResult> {
        let direction = params.direction;
        self.ensure_direction_loaded(direction)?;

        // Delete by ID - find the rule and delete it
        if let Some(rule_id) = params.id {
            // Search IPv4 rules
            let v4_rules = self.bpf_ops.list_policy_rules_v4(direction)?;

            for (src_key, dst_key, rule) in &v4_rules {
                if rule.rule_id == rule_id {
                    self.bpf_ops
                        .delete_policy_rule_v4(src_key, dst_key, rule_id, direction)?;
                    if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                        let _ = self.bpf_ops.delete_sni_rule(rule_id, direction);
                    }
                    if rule.mac_match_flags != 0 {
                        let _ = self.bpf_ops.delete_mac_rule(rule_id, direction);
                    }
                    if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                        warn!("Failed to clear rule {} stats on delete: {:#}", rule_id, e);
                    }
                    // Remove from managed registry if present and cancel timer.
                    self.rule_registry.remove(rule_id);
                    self.send_timer_remove(rule_id);
                    self.emit_rule_event("deleted", rule_id, direction, None);
                    return Ok(OperationResult::success(format!(
                        "Deleted rule {}",
                        rule_id
                    )));
                }
            }

            // Search IPv6 rules
            let v6_rules = self.bpf_ops.list_policy_rules_v6(direction)?;

            for (src_key, dst_key, rule) in &v6_rules {
                if rule.rule_id == rule_id {
                    self.bpf_ops
                        .delete_policy_rule_v6(src_key, dst_key, rule_id, direction)?;
                    if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                        let _ = self.bpf_ops.delete_sni_rule(rule_id, direction);
                    }
                    if rule.mac_match_flags != 0 {
                        let _ = self.bpf_ops.delete_mac_rule(rule_id, direction);
                    }
                    if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                        warn!("Failed to clear rule {} stats on delete: {:#}", rule_id, e);
                    }
                    // Remove from managed registry if present and cancel timer.
                    self.rule_registry.remove(rule_id);
                    self.send_timer_remove(rule_id);
                    self.emit_rule_event("deleted", rule_id, direction, None);
                    return Ok(OperationResult::success(format!(
                        "Deleted rule {}",
                        rule_id
                    )));
                }
            }

            // The rule might be in the registry but currently inactive (not in BPF maps).
            if self.rule_registry.remove(rule_id).is_some() {
                self.send_timer_remove(rule_id);
                self.emit_rule_event("deleted", rule_id, direction, None);
                return Ok(OperationResult::success(format!(
                    "Deleted rule {}",
                    rule_id
                )));
            }

            return Err(anyhow!("Rule {} not found", rule_id));
        }

        // Delete by source CIDR - delete all rules sharing that source prefix
        if let Some(src_str) = params.src {
            let src_net: ipnetwork::IpNetwork = src_str
                .parse()
                .map_err(|e| anyhow!("Invalid source CIDR: {}", e))?;

            let mut deleted = 0u32;
            match src_net {
                ipnetwork::IpNetwork::V4(s) => {
                    let target = SrcLpmKeyV4::new(params.ifindex, s.network(), s.prefix());
                    let rules = self.bpf_ops.list_policy_rules_v4(direction)?;
                    for (src_key, dst_key, rule) in rules {
                        if src_key.ifindex == target.ifindex
                            && src_key.prefixlen == target.prefixlen
                            && src_key.addr == target.addr
                        {
                            let rid = rule.rule_id;
                            self.bpf_ops
                                .delete_policy_rule_v4(&src_key, &dst_key, rid, direction)?;
                            if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                                let _ = self.bpf_ops.delete_sni_rule(rid, direction);
                            }
                            if rule.mac_match_flags != 0 {
                                let _ = self.bpf_ops.delete_mac_rule(rid, direction);
                            }
                            if let Err(e) = self.bpf_ops.clear_rule_stats(rid, direction) {
                                warn!("Failed to clear rule {} stats on delete: {:#}", rid, e);
                            }
                            deleted += 1;
                        }
                    }
                }
                ipnetwork::IpNetwork::V6(s) => {
                    let target = SrcLpmKeyV6::new(params.ifindex, s.network(), s.prefix());
                    let rules = self.bpf_ops.list_policy_rules_v6(direction)?;
                    for (src_key, dst_key, rule) in rules {
                        if src_key.ifindex == target.ifindex
                            && src_key.prefixlen == target.prefixlen
                            && src_key.addr == target.addr
                        {
                            let rid = rule.rule_id;
                            self.bpf_ops
                                .delete_policy_rule_v6(&src_key, &dst_key, rid, direction)?;
                            if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                                let _ = self.bpf_ops.delete_sni_rule(rid, direction);
                            }
                            if rule.mac_match_flags != 0 {
                                let _ = self.bpf_ops.delete_mac_rule(rid, direction);
                            }
                            if let Err(e) = self.bpf_ops.clear_rule_stats(rid, direction) {
                                warn!("Failed to clear rule {} stats on delete: {:#}", rid, e);
                            }
                            deleted += 1;
                        }
                    }
                }
            }

            return Ok(OperationResult::success(format!(
                "Deleted {} rule(s)",
                deleted
            )));
        }

        Err(anyhow!("Must specify either id or src"))
    }

    /// Flush all rules scoped to a single interface+direction.
    pub fn flush_rules(&mut self, ifindex: u32, direction: Direction) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;

        let v4_rules: Vec<_> = self
            .bpf_ops
            .list_policy_rules_v4(direction)?
            .into_iter()
            .filter(|(src_key, _, _)| src_key.ifindex == ifindex)
            .collect();
        let v6_rules: Vec<_> = self
            .bpf_ops
            .list_policy_rules_v6(direction)?
            .into_iter()
            .filter(|(src_key, _, _)| src_key.ifindex == ifindex)
            .collect();

        let count = v4_rules.len() + v6_rules.len();

        for (src_key, dst_key, rule) in v4_rules {
            let rule_id = rule.rule_id;
            let _ = self
                .bpf_ops
                .delete_policy_rule_v4(&src_key, &dst_key, rule_id, direction);
            if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                let _ = self.bpf_ops.delete_sni_rule(rule_id, direction);
            }
            if rule.mac_match_flags != 0 {
                let _ = self.bpf_ops.delete_mac_rule(rule_id, direction);
            }
            if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                warn!("Failed to clear rule {} stats on flush: {:#}", rule_id, e);
            }
            self.rule_registry.remove(rule_id);
            self.send_timer_remove(rule_id);
            if let Err(e) = self.state_store.delete_rule(rule_id) {
                warn!("state_store: failed to remove rule {}: {:#}", rule_id, e);
            }
            self.emit_rule_event("deleted", rule_id, direction, Some("flush".into()));
        }
        for (src_key, dst_key, rule) in v6_rules {
            let rule_id = rule.rule_id;
            let _ = self
                .bpf_ops
                .delete_policy_rule_v6(&src_key, &dst_key, rule_id, direction);
            if rule.sni_match_type != crate::types::SNI_MATCH_NONE {
                let _ = self.bpf_ops.delete_sni_rule(rule_id, direction);
            }
            if rule.mac_match_flags != 0 {
                let _ = self.bpf_ops.delete_mac_rule(rule_id, direction);
            }
            if let Err(e) = self.bpf_ops.clear_rule_stats(rule_id, direction) {
                warn!("Failed to clear rule {} stats on flush: {:#}", rule_id, e);
            }
            self.rule_registry.remove(rule_id);
            self.send_timer_remove(rule_id);
            if let Err(e) = self.state_store.delete_rule(rule_id) {
                warn!("state_store: failed to remove rule {}: {:#}", rule_id, e);
            }
            self.emit_rule_event("deleted", rule_id, direction, Some("flush".into()));
        }

        info!(
            "Flushed {} {} rules on ifindex {}",
            count, direction, ifindex
        );

        Ok(OperationResult::success(format!(
            "Flushed {} {} rules",
            count, direction
        )))
    }

    /// Set default action for unmatched packets
    pub fn set_default_action(
        &mut self,
        action: PolicyAction,
        direction: Direction,
        ifindex: u32,
        iface_name: &str,
    ) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;

        self.bpf_ops
            .set_default_action(action, direction, ifindex)?;

        if let Err(e) = self
            .state_store
            .save_default_action(iface_name, direction, action)
        {
            warn!(
                "state_store: failed to persist default action for {}/{}: {:#}",
                iface_name, direction, e
            );
        }

        info!(
            "Set {}/{} default action to {:?}",
            iface_name, direction, action
        );

        Ok(OperationResult::success(format!(
            "{}/{} default action set to {:?}",
            iface_name, direction, action
        )))
    }

    /// Return the persisted default action for an interface+direction, or `None` if never set.
    pub fn get_default_action(
        &self,
        direction: Direction,
        iface_name: &str,
    ) -> Option<PolicyAction> {
        self.state_store
            .load_default_actions()
            .ok()?
            .into_iter()
            .find(|d| d.interface == iface_name && d.direction == direction)
            .map(|d| d.action)
    }

    /// Clear global statistics for an interface
    pub fn clear_global_stats(
        &mut self,
        ifindex: u32,
        direction: Direction,
    ) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.clear_global_stats(ifindex, direction)?;
        Ok(OperationResult::success(format!(
            "Cleared {} global stats for ifindex {}",
            direction, ifindex
        )))
    }

    /// Clear statistics for a specific rule
    pub fn clear_rule_stats(
        &mut self,
        rule_id: u64,
        direction: Direction,
    ) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.clear_rule_stats(rule_id, direction)?;
        Ok(OperationResult::success(format!(
            "Cleared {} stats for rule {}",
            direction, rule_id
        )))
    }

    /// Clear statistics for all rules
    pub fn clear_all_rule_stats(&mut self, direction: Direction) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.clear_all_rule_stats(direction)?;
        Ok(OperationResult::success(format!(
            "Cleared all {} rule stats",
            direction
        )))
    }

    /// Clear ethertype statistics for an interface
    pub fn clear_ethertype_stats(
        &mut self,
        ifindex: u32,
        direction: Direction,
    ) -> Result<OperationResult> {
        if direction == Direction::Egress {
            return Ok(OperationResult::success(format!(
                "No ethertype stats for egress on ifindex {}",
                ifindex
            )));
        }
        self.ensure_xdp_loaded()?;
        self.bpf_ops.clear_ethertype_stats(ifindex, direction)?;
        Ok(OperationResult::success(format!(
            "Cleared {} ethertype stats for ifindex {}",
            direction, ifindex
        )))
    }

    /// Clear all statistics for an interface (global + ethertype)
    pub fn clear_interface_stats(
        &mut self,
        ifindex: u32,
        direction: Direction,
    ) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;
        self.bpf_ops.clear_interface_stats(ifindex, direction)?;
        Ok(OperationResult::success(format!(
            "Cleared all {} stats for ifindex {}",
            direction, ifindex
        )))
    }

    /// Clear all statistics
    pub fn clear_all_stats(&mut self) -> Result<OperationResult> {
        self.ensure_programs_loaded()?;
        self.bpf_ops.clear_all_stats()?;
        Ok(OperationResult::success("Cleared all statistics"))
    }

    /// Configure inspect mode — sets BPF inspect_config for both directions
    #[cfg(feature = "suricata")]
    pub fn configure_inspect(
        &mut self,
        mode: InspectMode,
        mirror_ifindex: u32,
    ) -> Result<OperationResult> {
        self.ensure_programs_loaded()?;
        let config = InspectConfig {
            mode: mode as u32,
            mirror_ifindex,
            _pad: [0; 2],
        };
        self.bpf_ops
            .set_inspect_config(&config, Direction::Ingress)?;
        self.bpf_ops
            .set_inspect_config(&config, Direction::Egress)?;

        // INSPECT requires TC ingress to clone packets to Suricata.  TC is
        // attached via attach_tc(), which users may not have called if they
        // only attached ingress (XDP).  Ensure TC is now attached to every
        // interface that has XDP, silently ignoring "already attached" errors.
        if mode != InspectMode::Disabled {
            let xdp_ifaces: Vec<String> = self
                .bpf_ops
                .get_attached_interfaces()
                .into_iter()
                .filter(|i| i.direction == "ingress")
                .map(|i| i.interface)
                .collect();
            for ifname in xdp_ifaces {
                if let Err(e) = self.bpf_ops.attach_tc(&ifname) {
                    // "already attached" is expected and fine; log anything else
                    let msg = e.to_string();
                    if !msg.contains("already attached") {
                        log::warn!("Failed to attach TC to {} for INSPECT: {}", ifname, e);
                    }
                }
            }
        }

        Ok(OperationResult::success(format!(
            "Inspect mode set to {}",
            mode
        )))
    }

    /// Disable inspect mode
    #[cfg(feature = "suricata")]
    pub fn disable_inspect(&mut self) -> Result<OperationResult> {
        self.ensure_programs_loaded()?;
        let config = InspectConfig::default(); // mode=0 (disabled)
        self.bpf_ops
            .set_inspect_config(&config, Direction::Ingress)?;
        self.bpf_ops
            .set_inspect_config(&config, Direction::Egress)?;

        Ok(OperationResult::success("Inspect mode disabled"))
    }

    /// Get inspect config for a direction
    #[cfg(feature = "suricata")]
    pub fn get_inspect_config(&self, direction: Direction) -> Result<InspectConfig> {
        self.bpf_ops.get_inspect_config(direction)
    }

    /// Enable or disable XDP FIB forwarding for a single ingress interface.
    pub fn set_fib_forwarding(
        &mut self,
        interface: &str,
        enabled: bool,
    ) -> Result<OperationResult> {
        self.ensure_programs_loaded()?;
        let config = FibConfig {
            mode: if enabled {
                FIB_FORWARD_ENABLED
            } else {
                FIB_FORWARD_DISABLED
            },
            ..Default::default()
        };
        self.bpf_ops.set_fib_config(interface, &config)?;
        let state = if enabled { "enabled" } else { "disabled" };
        Ok(OperationResult::success(format!(
            "FIB forwarding {} on {}",
            state, interface
        )))
    }

    /// Get current FIB forwarding state for a single interface (true = enabled).
    pub fn get_fib_forwarding(&self, interface: &str) -> Result<bool> {
        let config = self.bpf_ops.get_fib_config(interface)?;
        Ok(config.mode == FIB_FORWARD_ENABLED)
    }

    /// List all interfaces with their FIB forwarding state.
    /// Only entries present in the BPF map are returned.
    pub fn list_fib_forwarding(&self) -> Result<Vec<(String, bool)>> {
        let entries = self.bpf_ops.list_fib_configs()?;
        Ok(entries
            .into_iter()
            .map(|(name, cfg)| (name, cfg.mode == FIB_FORWARD_ENABLED))
            .collect())
    }

    /// Configure IPFIX flow export.  Updates the BPF flow cache enable bit and
    /// persists the configuration to disk so it survives daemon restarts.
    #[cfg(feature = "ipfix")]
    pub fn configure_flow_export(&mut self, config: FlowExportConfig) -> Result<OperationResult> {
        self.ensure_programs_loaded()?;
        let bpf_config = FlowCacheConfig {
            enabled: if config.enabled {
                FLOW_CACHE_ENABLED
            } else {
                FLOW_CACHE_DISABLED
            },
            ..Default::default()
        };
        self.bpf_ops.set_flow_cache_config(&bpf_config)?;
        let state = if config.enabled {
            "enabled"
        } else {
            "disabled"
        };
        self.flow_export_config = config;
        save_flow_export_config(&self.flow_export_config);
        Ok(OperationResult::success(format!("Flow export {}", state)))
    }

    /// Get the current flow export configuration.
    #[cfg(feature = "ipfix")]
    pub fn get_flow_export_config(&self) -> &FlowExportConfig {
        &self.flow_export_config
    }

    /// Return a mutable reference to the underlying BpfOperations.
    /// Used by the background IPFIX export task and the QUIC Initial
    /// inspector (which needs to read sni_rules / list policy rules and
    /// write flow verdicts from an async task).
    pub fn bpf_ops_mut(&mut self) -> &mut dyn BpfOperations {
        self.bpf_ops.as_mut()
    }

    /// Count of active entries across both flow cache maps.
    #[cfg(feature = "ipfix")]
    pub fn get_active_flow_count(&self) -> u64 {
        let ingress = self
            .bpf_ops
            .list_flow_cache_entries(Direction::Ingress)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let egress = self
            .bpf_ops
            .list_flow_cache_entries(Direction::Egress)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        ingress + egress
    }

    /// Look up an SNI rule entry by rule ID for display purposes
    pub fn get_sni_rule(
        &self,
        rule_id: u64,
        direction: Direction,
    ) -> Option<crate::types::SniRuleEntry> {
        if !self.is_programs_loaded() {
            return None;
        }
        self.bpf_ops
            .lookup_sni_rule(rule_id, direction)
            .ok()
            .flatten()
    }

    pub fn get_mac_rule(
        &self,
        rule_id: u64,
        direction: Direction,
    ) -> Option<crate::types::MacRuleEntry> {
        if !self.is_programs_loaded() {
            return None;
        }
        self.bpf_ops
            .lookup_mac_rule(rule_id, direction)
            .ok()
            .flatten()
    }

    /// Get flow verdict count
    pub fn get_flow_verdict_count(&self, direction: Direction) -> Result<u64> {
        self.bpf_ops.get_flow_verdict_count(direction)
    }

    /// Clear all flow verdicts for a direction
    pub fn clear_flow_verdicts(&mut self, direction: Direction) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;
        let verdicts = self.bpf_ops.list_flow_verdicts(direction)?;
        let count = verdicts.len();
        for (key, _) in verdicts {
            self.bpf_ops.delete_flow_verdict(&key, direction).ok();
        }
        Ok(OperationResult::success(format!(
            "Cleared {} flow verdicts",
            count
        )))
    }

    /// Update a flow verdict (used by IPS enforcement and QUIC SNI inspector)
    pub fn update_flow_verdict(
        &mut self,
        key: &FlowVerdictKey,
        verdict: &FlowVerdict,
        direction: Direction,
    ) -> Result<()> {
        self.bpf_ops.update_flow_verdict(key, verdict, direction)
    }

    /// Delete a flow verdict
    pub fn delete_flow_verdict(
        &mut self,
        key: &FlowVerdictKey,
        direction: Direction,
    ) -> Result<()> {
        self.bpf_ops.delete_flow_verdict(key, direction)
    }

    /// List flow verdicts (for cleanup)
    pub fn list_flow_verdicts(
        &self,
        direction: Direction,
    ) -> Result<Vec<(FlowVerdictKey, FlowVerdict)>> {
        self.bpf_ops.list_flow_verdicts(direction)
    }

    /// Register a tail call program at a dispatcher slot
    pub fn register_tail_call(
        &mut self,
        slot: u32,
        program: &str,
        direction: Direction,
    ) -> Result<OperationResult> {
        self.ensure_direction_loaded(direction)?;

        self.bpf_ops.register_tail_call(slot, program, direction)?;

        info!("Registered {} at {} slot {}", program, direction, slot);

        Ok(OperationResult::success(format!(
            "Registered {} at {} slot {}",
            program, direction, slot
        )))
    }
}

#[cfg(feature = "ipfix")]
const FLOW_EXPORT_CONFIG_PATH: &str = "/var/run/policy-engine/flow_export_config.json";

/// Persist the flow export config to disk so it survives daemon restarts.
#[cfg(feature = "ipfix")]
fn save_flow_export_config(config: &FlowExportConfig) {
    match serde_json::to_string_pretty(config) {
        Ok(json) => {
            if let Err(e) = std::fs::write(FLOW_EXPORT_CONFIG_PATH, json) {
                debug!("Failed to persist flow export config: {}", e);
            }
        }
        Err(e) => debug!("Failed to serialize flow export config: {}", e),
    }
}

/// Load a previously persisted flow export config from disk.
/// Returns None if the file does not exist or cannot be parsed.
#[cfg(feature = "ipfix")]
pub fn load_flow_export_config() -> Option<FlowExportConfig> {
    let data = std::fs::read_to_string(FLOW_EXPORT_CONFIG_PATH).ok()?;
    serde_json::from_str(&data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBpfOperations;
    use std::net::Ipv4Addr;

    /// Helper to create a MockBpfOperations with common expectations
    fn create_mock_with_loaded_programs() -> MockBpfOperations {
        let mut mock = MockBpfOperations::new();
        mock.expect_load_programs().returning(|| Ok(()));
        // Default: inspect mode disabled (for attach_ingress auto-mirror check)
        #[cfg(feature = "suricata")]
        mock.expect_get_inspect_config()
            .returning(|_| Ok(InspectConfig::default()));
        mock
    }

    /// Helper to create a default L4Rule for testing
    fn create_test_lpm_entry(rule_id: u64, action: PolicyAction) -> L4Rule {
        let mut rule = L4Rule {
            rule_id,
            flags: 0,
            num_actions: 1,
            ..L4Rule::default()
        };
        rule.actions[0].action = action as u32;
        rule.actions[0].priority = 0;
        rule
    }

    /// Helper to create an InterfaceAttachment with direction
    fn iface_attachment(
        name: &str,
        ifindex: i32,
        mode: &str,
        direction: &str,
    ) -> InterfaceAttachment {
        InterfaceAttachment {
            interface: name.to_string(),
            ifindex,
            mode: mode.to_string(),
            direction: direction.to_string(),
        }
    }

    mod status {
        use super::*;

        #[test]
        fn test_get_status_returns_server_info() {
            let mut mock = MockBpfOperations::new();
            mock.expect_get_attached_interfaces().returning(Vec::new);
            let service = PolicyService::new(Box::new(mock));

            let status = service.get_status();

            assert!(status.running);
            assert!(!status.version.is_empty());
            assert!(!status.program_attached);
        }

        #[test]
        fn test_get_status_with_attached_program() {
            let mut mock = MockBpfOperations::new();
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);
            let service = PolicyService::new(Box::new(mock));

            let status = service.get_status();

            assert!(status.running);
            assert!(status.program_attached);
        }
    }

    mod ingress_attachment {
        use super::*;

        #[test]
        fn test_attach_ingress_native_mode() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_attach_ingress()
                .times(1)
                .withf(|ifname, mode| ifname == "eth0" && matches!(mode, XdpMode::Native))
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.attach_ingress("eth0", XdpMode::Native);

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("eth0"));
            assert!(op_result.message.contains("native"));
        }

        #[test]
        fn test_attach_ingress_auto_tries_modes_in_order() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_attach_ingress()
                .times(1)
                .withf(|_, mode| matches!(mode, XdpMode::Offload))
                .returning(|_, _| Err(anyhow::anyhow!("Hardware offload not supported")));

            mock.expect_attach_ingress()
                .times(1)
                .withf(|_, mode| matches!(mode, XdpMode::Native))
                .returning(|_, _| Err(anyhow::anyhow!("Native not supported")));

            mock.expect_attach_ingress()
                .times(1)
                .withf(|_, mode| matches!(mode, XdpMode::Generic))
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.attach_ingress_auto("eth0");

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("generic"));
            assert!(op_result.message.contains("auto-selected"));
        }

        #[test]
        fn test_attach_ingress_auto_fails_when_all_modes_fail() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_attach_ingress()
                .times(3)
                .returning(|_, _| Err(anyhow::anyhow!("Attachment failed")));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.attach_ingress_auto("eth0");

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("any mode"));
        }

        #[test]
        fn test_detach_ingress() {
            let mut mock = MockBpfOperations::new();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_detach_ingress()
                .times(1)
                .withf(|ifname| ifname == "eth0")
                .returning(|_| Ok(()));

            mock.expect_clear_interface_stats()
                .times(1)
                .withf(|&ifindex, dir| ifindex == 2 && *dir == Direction::Ingress)
                .returning(|_, _| Ok(()));

            mock.expect_list_policy_rules_v4()
                .times(1)
                .withf(|dir| *dir == Direction::Ingress)
                .returning(|_| Ok(vec![]));

            mock.expect_list_policy_rules_v6()
                .times(1)
                .withf(|dir| *dir == Direction::Ingress)
                .returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.detach_ingress("eth0");

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("eth0"));
        }

        #[test]
        fn test_detach_ingress_clears_rule_stats_for_interface() {
            let mut mock = MockBpfOperations::new();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_detach_ingress().times(1).returning(|_| Ok(()));

            mock.expect_clear_interface_stats()
                .times(1)
                .returning(|_, _| Ok(()));

            // Return two rules: one for ifindex 2 (eth0), one for ifindex 3 (other iface)
            mock.expect_list_policy_rules_v4().times(1).returning(|_| {
                let src_eth0 = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 2,
                    addr: [0u8; 4],
                };
                let src_other = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 3,
                    addr: [0u8; 4],
                };
                let dst_key = LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                };
                let rule_eth0 = create_test_lpm_entry(100, PolicyAction::Pass);
                let rule_other = create_test_lpm_entry(200, PolicyAction::Drop);
                Ok(vec![
                    (src_eth0, dst_key, rule_eth0),
                    (src_other, dst_key, rule_other),
                ])
            });

            mock.expect_list_policy_rules_v6().times(1).returning(|_| {
                let src_eth0 = SrcLpmKeyV6 {
                    prefixlen: 32,
                    ifindex: 2,
                    addr: [0u8; 16],
                };
                let dst_key = LpmKeyV6 {
                    prefixlen: 0,
                    addr: [0u8; 16],
                };
                let rule_eth0 = create_test_lpm_entry(300, PolicyAction::Pass);
                Ok(vec![(src_eth0, dst_key, rule_eth0)])
            });

            // Only rules for ifindex 2 (eth0) should have their stats cleared.
            // Rule 100 (v4, ifindex 2) and rule 300 (v6, ifindex 2) get cleared.
            // Rule 200 (v4, ifindex 3) must NOT be cleared.
            mock.expect_clear_rule_stats()
                .times(2)
                .withf(|&rule_id, dir| {
                    (rule_id == 100 || rule_id == 300) && *dir == Direction::Ingress
                })
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.detach_ingress("eth0");

            assert!(result.is_ok());
        }

        #[test]
        fn test_detach_ingress_skips_stat_clear_when_not_tracked() {
            let mut mock = MockBpfOperations::new();

            // Interface is not in the attachment list — no ifindex found.
            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(Vec::new);

            mock.expect_detach_ingress().times(1).returning(|_| Ok(()));

            // No stat-clearing calls expected.

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.detach_ingress("eth0");

            assert!(result.is_ok());
        }

        #[test]
        fn test_get_interfaces() {
            let mut mock = MockBpfOperations::new();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let service = PolicyService::new(Box::new(mock));
            let interfaces = service.get_interfaces();

            assert_eq!(interfaces.len(), 1);
            assert_eq!(interfaces[0].interface, "eth0");
        }
    }

    mod egress_attachment {
        use super::*;

        #[test]
        fn test_attach_tc() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_attach_tc()
                .times(1)
                .withf(|ifname| ifname == "eth0")
                .returning(|_| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.attach_tc("eth0");

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("eth0"));
            assert!(op_result.message.contains("egress"));
        }

        #[test]
        fn test_attach_tc_failure_propagates() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_attach_tc()
                .times(1)
                .returning(|_| Err(anyhow::anyhow!("TC attach failed")));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.attach_tc("eth0");

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("attach egress"));
        }

        #[test]
        fn test_detach_tc() {
            let mut mock = MockBpfOperations::new();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "tc", "egress")]);

            mock.expect_detach_tc()
                .times(1)
                .withf(|ifname| ifname == "eth0")
                .returning(|_| Ok(()));

            mock.expect_clear_interface_stats()
                .times(1)
                .withf(|&ifindex, dir| ifindex == 2 && *dir == Direction::Egress)
                .returning(|_, _| Ok(()));

            mock.expect_list_policy_rules_v4()
                .times(1)
                .withf(|dir| *dir == Direction::Egress)
                .returning(|_| Ok(vec![]));

            mock.expect_list_policy_rules_v6()
                .times(1)
                .withf(|dir| *dir == Direction::Egress)
                .returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.detach_tc("eth0");

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("eth0"));
            assert!(op_result.message.contains("egress"));
        }

        #[test]
        fn test_detach_tc_clears_rule_stats_for_interface() {
            let mut mock = MockBpfOperations::new();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "tc", "egress")]);

            mock.expect_detach_tc().times(1).returning(|_| Ok(()));

            mock.expect_clear_interface_stats()
                .times(1)
                .returning(|_, _| Ok(()));

            mock.expect_list_policy_rules_v4().times(1).returning(|_| {
                let src = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 2,
                    addr: [0u8; 4],
                };
                let dst = LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                };
                Ok(vec![(
                    src,
                    dst,
                    create_test_lpm_entry(500, PolicyAction::Drop),
                )])
            });

            mock.expect_list_policy_rules_v6()
                .times(1)
                .returning(|_| Ok(vec![]));

            mock.expect_clear_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 500 && *dir == Direction::Egress)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.detach_tc("eth0");

            assert!(result.is_ok());
        }

        #[test]
        fn test_detach_tc_skips_stat_clear_when_not_tracked() {
            let mut mock = MockBpfOperations::new();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(Vec::new);

            mock.expect_detach_tc().times(1).returning(|_| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.detach_tc("eth0");

            assert!(result.is_ok());
        }

        #[test]
        fn test_detach_all_with_mixed_directions() {
            let mut mock = MockBpfOperations::new();

            let mut call_count = 0;
            mock.expect_get_attached_interfaces()
                .times(2)
                .returning(move || {
                    call_count += 1;
                    if call_count == 1 {
                        vec![
                            iface_attachment("eth0", 2, "native", "ingress"),
                            iface_attachment("eth0", 2, "tc", "egress"),
                            iface_attachment("eth1", 3, "generic", "ingress"),
                        ]
                    } else {
                        vec![]
                    }
                });

            mock.expect_detach_ingress().times(2).returning(|_| Ok(()));
            mock.expect_detach_tc().times(1).returning(|_| Ok(()));

            // clear_stats_on_detach called once per successfully detached interface (3 total)
            mock.expect_clear_interface_stats()
                .times(3)
                .returning(|_, _| Ok(()));
            mock.expect_list_policy_rules_v4()
                .times(3)
                .returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6()
                .times(3)
                .returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.detach_all();

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("3"));
        }
    }

    mod rule_management {
        use super::*;

        #[test]
        fn test_add_rule_ipv4_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .withf(|src_key, _dst_key, rule, dir| {
                    let prefixlen = src_key.addr_prefixlen();
                    prefixlen == 24 && rule.num_actions == 1 && *dir == Direction::Ingress
                })
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: Some("10.0.0.0/8".to_string()),
                sport: 0,
                dport: 80,
                protocol: "tcp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("12345"));
        }

        #[test]
        fn test_add_rule_ipv4_egress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "tc", "egress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .withf(|_src_key, _dst_key, _rule, dir| *dir == Direction::Egress)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Egress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 80,
                protocol: "tcp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_add_rule_fails_without_attached_interface() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(Vec::new);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("No ingress programs attached"));
        }

        #[test]
        fn test_add_egress_rule_fails_without_attached_interface() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(Vec::new);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Egress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("No egress programs attached"));
        }

        #[test]
        fn test_add_rule_fails_without_actions() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("At least one action"));
        }

        #[cfg(feature = "suricata")]
        #[test]
        fn test_add_rule_inspect_on_egress_accepted() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "egress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .withf(|_, _, rule, dir| rule.num_actions == 1 && *dir == Direction::Egress)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Egress,
                id: Some(12345),
                src: Some("10.0.0.0/8".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Inspect, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_ok(), "egress INSPECT should be accepted now");
        }

        #[test]
        fn test_add_rule_with_multiple_actions() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .withf(|_, _, rule, _| rule.num_actions == 2)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(54321),
                src: Some("192.168.1.100/32".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![
                    (PolicyAction::Log, 0, ActionParams::None),
                    (PolicyAction::Drop, 1, ActionParams::None),
                ],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_add_rule_sni_with_udp_accepted() {
            // UDP + SNI is the QUIC Initial inspection path (Phase 3): the
            // BPF tail call hands the packet to the userspace QUIC inspector
            // which derives Initial keys and extracts the SNI from the
            // ClientHello.  Installing a UDP rule with SNI must succeed and
            // populate the sni_rules sidecar map exactly like the TCP path.
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .withf(|_, _, rule, _| {
                    rule.sni_match_type == crate::types::SNI_MATCH_EXACT
                        && rule.protocol == libc::IPPROTO_UDP as u8
                })
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            mock.expect_add_sni_rule()
                .times(1)
                .withf(|_, sni_entry, _direction| {
                    sni_entry.sni_match_type == crate::types::SNI_MATCH_EXACT
                        && sni_entry.sni_len > 0
                })
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 443,
                protocol: "udp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: Some("example.com".to_string()),
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);
            assert!(
                result.is_ok(),
                "UDP + SNI should be accepted: {:?}",
                result.err()
            );
        }

        #[test]
        fn test_add_rule_sni_with_icmp_rejected() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "icmp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: Some("*.example.com".to_string()),
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("SNI matching requires TCP or UDP protocol"));
        }

        #[test]
        fn test_add_rule_sni_with_any_protocol_rejected() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 443,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: Some("example.com".to_string()),
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("SNI matching requires TCP or UDP protocol"));
        }

        #[test]
        fn test_add_rule_sni_with_tcp_accepted() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .withf(|_, _, rule, _| rule.sni_match_type == crate::types::SNI_MATCH_EXACT)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            mock.expect_add_sni_rule()
                .times(1)
                .withf(|_, sni_entry, _direction| {
                    sni_entry.sni_match_type == crate::types::SNI_MATCH_EXACT
                        && sni_entry.sni_len > 0
                })
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 443,
                protocol: "tcp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: Some("example.com".to_string()),
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_add_rule_sni_with_egress_accepted() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "egress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .withf(|_, _, rule, _| rule.sni_match_type == crate::types::SNI_MATCH_EXACT)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            mock.expect_add_sni_rule()
                .times(1)
                .withf(|_, sni_entry, direction| {
                    sni_entry.sni_match_type == crate::types::SNI_MATCH_EXACT
                        && sni_entry.sni_len > 0
                        && *direction == Direction::Egress
                })
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Egress,
                id: Some(99999),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 443,
                protocol: "tcp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: Some("example.com".to_string()),
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);
            assert!(result.is_ok());
        }

        #[test]
        fn test_delete_rule_by_id_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            let key = SrcLpmKeyV4::new(0, "192.168.1.0".parse::<Ipv4Addr>().unwrap(), 24);
            let entry = create_test_lpm_entry(12345, PolicyAction::Drop);

            mock.expect_list_policy_rules_v4()
                .times(1)
                .return_once(move |_| Ok(vec![(key, LpmKeyV4::any(), entry)]));

            mock.expect_delete_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_clear_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 12345 && *dir == Direction::Ingress)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));

            let params = DeleteRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: None,
            };

            let result = service.delete_rule(params);

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("12345"));
        }

        #[test]
        fn test_delete_rule_by_id_egress() {
            let mut mock = create_mock_with_loaded_programs();

            let key = SrcLpmKeyV4::new(0, "10.0.0.0".parse::<Ipv4Addr>().unwrap(), 8);
            let entry = create_test_lpm_entry(67890, PolicyAction::Drop);

            mock.expect_list_policy_rules_v4()
                .times(1)
                .withf(|dir| *dir == Direction::Egress)
                .return_once(move |_| Ok(vec![(key, LpmKeyV4::any(), entry)]));

            mock.expect_delete_policy_rule_v4()
                .times(1)
                .withf(|_, _, _, dir| *dir == Direction::Egress)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_clear_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 67890 && *dir == Direction::Egress)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));

            let params = DeleteRuleParams {
                ifindex: 0,
                direction: Direction::Egress,
                id: Some(67890),
                src: None,
            };

            let result = service.delete_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_delete_rule_by_id_not_found() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_list_policy_rules_v4()
                .times(1)
                .returning(|_| Ok(vec![]));

            mock.expect_list_policy_rules_v6()
                .times(1)
                .returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = DeleteRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(99999),
                src: None,
            };

            let result = service.delete_rule(params);

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not found"));
        }

        #[test]
        fn test_delete_rule_by_src() {
            let mut mock = create_mock_with_loaded_programs();

            let key = SrcLpmKeyV4::new(0, "192.168.1.0".parse::<Ipv4Addr>().unwrap(), 24);
            let entry = create_test_lpm_entry(12345, PolicyAction::Drop);

            mock.expect_list_policy_rules_v4()
                .times(1)
                .return_once(move |_| Ok(vec![(key, LpmKeyV4::any(), entry)]));

            mock.expect_delete_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_clear_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 12345 && *dir == Direction::Ingress)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));

            let params = DeleteRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: None,
                src: Some("192.168.1.0/24".to_string()),
            };

            let result = service.delete_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_list_rules_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            let key = SrcLpmKeyV4::new(0, "172.16.0.0".parse::<Ipv4Addr>().unwrap(), 12);
            let entry = create_test_lpm_entry(99999, PolicyAction::Pass);

            mock.expect_list_policy_rules_v4()
                .times(1)
                .withf(|dir| *dir == Direction::Ingress)
                .return_once(move |_| Ok(vec![(key, LpmKeyV4::any(), entry)]));

            mock.expect_list_policy_rules_v6()
                .times(1)
                .withf(|dir| *dir == Direction::Ingress)
                .returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));
            let (v4_rules, v6_rules) = service.list_rules(Direction::Ingress).unwrap();

            assert_eq!(v4_rules.len(), 1);
            assert_eq!(v6_rules.len(), 0);
            let prefixlen = v4_rules[0].0.addr_prefixlen();
            assert_eq!(prefixlen, 12); // src prefix
        }

        #[test]
        fn test_list_rules_egress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_list_policy_rules_v4()
                .times(1)
                .withf(|dir| *dir == Direction::Egress)
                .returning(|_| Ok(vec![]));

            mock.expect_list_policy_rules_v6()
                .times(1)
                .withf(|dir| *dir == Direction::Egress)
                .returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));
            let (v4, v6) = service.list_rules(Direction::Egress).unwrap();

            assert_eq!(v4.len(), 0);
            assert_eq!(v6.len(), 0);
        }

        #[test]
        fn test_flush_rules_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            // ifindex 5 → in scope; ifindex 9 → out of scope, must be left alone.
            let key1 = SrcLpmKeyV4::new(5, "192.168.1.0".parse::<Ipv4Addr>().unwrap(), 24);
            let entry1 = create_test_lpm_entry(111, PolicyAction::Drop);
            let key2 = SrcLpmKeyV4::new(5, "10.0.0.0".parse::<Ipv4Addr>().unwrap(), 8);
            let entry2 = create_test_lpm_entry(222, PolicyAction::Pass);
            let key_other = SrcLpmKeyV4::new(9, "172.16.0.0".parse::<Ipv4Addr>().unwrap(), 12);
            let entry_other = create_test_lpm_entry(333, PolicyAction::Pass);

            mock.expect_list_policy_rules_v4()
                .times(1)
                .return_once(move |_| {
                    Ok(vec![
                        (key1, LpmKeyV4::any(), entry1),
                        (key2, LpmKeyV4::any(), entry2),
                        (key_other, LpmKeyV4::any(), entry_other),
                    ])
                });

            mock.expect_list_policy_rules_v6()
                .times(1)
                .returning(|_| Ok(vec![]));

            mock.expect_delete_policy_rule_v4()
                .times(2)
                .withf(|_, _, &rule_id, _| rule_id == 111 || rule_id == 222)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_clear_rule_stats()
                .times(2)
                .withf(|&rule_id, dir| {
                    (rule_id == 111 || rule_id == 222) && *dir == Direction::Ingress
                })
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.flush_rules(5, Direction::Ingress);

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("2"));
            assert!(op_result.message.contains("ingress"));
        }
    }

    mod statistics {
        use super::*;

        #[test]
        fn test_get_rule_stats_existing_rule_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 12345 && *dir == Direction::Ingress)
                .returning(|_, _| {
                    Ok(Some(RuleStats {
                        packets: 1000,
                        bytes: 64000,
                        last_seen_ns: 123456789,
                        last_log_ns: 0,
                    }))
                });

            let mut service = PolicyService::new(Box::new(mock));
            let stats = service.get_rule_stats(12345, Direction::Ingress).unwrap();

            assert!(stats.is_some());
            let stats = stats.unwrap();
            assert_eq!(stats.packets, 1000);
            assert_eq!(stats.bytes, 64000);
            assert_eq!(stats.last_seen_ns, 123456789);
        }

        #[test]
        fn test_get_rule_stats_egress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 12345 && *dir == Direction::Egress)
                .returning(|_, _| {
                    Ok(Some(RuleStats {
                        packets: 500,
                        bytes: 32000,
                        last_seen_ns: 0,
                        last_log_ns: 0,
                    }))
                });

            let mut service = PolicyService::new(Box::new(mock));
            let stats = service.get_rule_stats(12345, Direction::Egress).unwrap();

            assert!(stats.is_some());
            assert_eq!(stats.unwrap().packets, 500);
        }

        #[test]
        fn test_get_rule_stats_nonexistent() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_rule_stats()
                .times(1)
                .returning(|_, _| Ok(None));

            let mut service = PolicyService::new(Box::new(mock));
            let stats = service.get_rule_stats(99999, Direction::Ingress).unwrap();

            assert!(stats.is_none());
        }

        #[test]
        fn test_get_global_stats_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_global_stats()
                .times(1)
                .withf(|&ifindex, dir| ifindex == 2 && *dir == Direction::Ingress)
                .returning(|_, _| {
                    Ok(GlobalStats {
                        rx_packets: 50000,
                        rx_bytes: 3200000,
                        tx_packets: 0,
                        tx_bytes: 0,
                        policy_matches: 100,
                        policy_drops: 25,
                        policy_pass: 75,
                        policy_redirects: 0,
                        parse_errors: 5,
                        tail_calls: 10,
                        bum_packets: 1000,
                        non_ip_unicast: 500,
                        inspect_redirects: 0,
                        fragments: 0,
                        verdict_pass_packets: 0,
                        verdict_pass_bytes: 0,
                        verdict_drop_packets: 0,
                        verdict_drop_bytes: 0,
                        fib_forwarded_packets: 0,
                        fib_forwarded_bytes: 0,
                        fib_fallback_packets: 0,
                    })
                });

            let mut service = PolicyService::new(Box::new(mock));
            let stats = service.get_global_stats(2, Direction::Ingress).unwrap();

            assert_eq!(stats.rx_packets, 50000);
            assert_eq!(stats.policy_drops, 25);
        }

        #[test]
        fn test_get_global_stats_egress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_global_stats()
                .times(1)
                .withf(|&ifindex, dir| ifindex == 2 && *dir == Direction::Egress)
                .returning(|_, _| {
                    Ok(GlobalStats {
                        tx_packets: 30000,
                        tx_bytes: 2000000,
                        ..Default::default()
                    })
                });

            let mut service = PolicyService::new(Box::new(mock));
            let stats = service.get_global_stats(2, Direction::Egress).unwrap();

            assert_eq!(stats.tx_packets, 30000);
        }

        #[test]
        fn test_get_ethertype_stats() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_ethertype_stats()
                .times(1)
                .returning(|_, _| {
                    Ok(vec![
                        EthertypeStats {
                            ethertype: 0x0806,
                            packets: 500,
                        },
                        EthertypeStats {
                            ethertype: 0x88CC,
                            packets: 100,
                        },
                    ])
                });

            let mut service = PolicyService::new(Box::new(mock));
            let stats = service.get_ethertype_stats(2, Direction::Ingress).unwrap();

            assert_eq!(stats.len(), 2);
            assert_eq!(stats[0].ethertype, 0x0806);
        }
    }

    mod configuration {
        use super::*;

        #[test]
        fn test_set_default_action_pass_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_set_default_action()
                .times(1)
                .withf(|action, dir, _ifindex| {
                    matches!(action, PolicyAction::Pass) && *dir == Direction::Ingress
                })
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result =
                service.set_default_action(PolicyAction::Pass, Direction::Ingress, 1, "lo");

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("Pass"));
        }

        #[test]
        fn test_set_default_action_drop_egress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_set_default_action()
                .times(1)
                .withf(|action, dir, _ifindex| {
                    matches!(action, PolicyAction::Drop) && *dir == Direction::Egress
                })
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.set_default_action(PolicyAction::Drop, Direction::Egress, 1, "lo");

            assert!(result.is_ok());
        }

        #[test]
        fn test_register_tail_call_content_inspect_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_register_tail_call()
                .times(1)
                .withf(|&slot, prog_name, dir| {
                    slot == 0 && prog_name == "content_inspect" && *dir == Direction::Ingress
                })
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.register_tail_call(0, "content_inspect", Direction::Ingress);

            assert!(result.is_ok());
            let op_result = result.unwrap();
            assert!(op_result.success);
            assert!(op_result.message.contains("content_inspect"));
        }

        #[test]
        fn test_register_tail_call_invalid_slot() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_register_tail_call()
                .times(1)
                .returning(|_, _, _| Err(anyhow::anyhow!("Slot 1 exceeds maximum")));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.register_tail_call(1, "content_inspect", Direction::Ingress);

            assert!(result.is_err());
        }
    }

    mod ipv6_rules {
        use super::*;
        use std::net::Ipv6Addr;

        #[test]
        fn test_add_ipv6_rule() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_add_policy_rule_v6()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(77777),
                src: Some("2001:db8::/32".to_string()),
                dst: Some("2001:db8:1::/48".to_string()),
                sport: 0,
                dport: 443,
                protocol: "tcp".to_string(),
                actions: vec![(PolicyAction::Pass, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_add_ipv6_rule_auto_converts_icmp_to_icmpv6() {
            use libc::IPPROTO_ICMPV6;

            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_add_policy_rule_v6()
                .times(1)
                .withf(move |_, _, rule, _| rule.protocol == IPPROTO_ICMPV6 as u8)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(88888),
                src: Some("2001:db8::/32".to_string()),
                dst: Some("::/0".to_string()),
                sport: 0,
                dport: 0,
                protocol: "icmp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_delete_ipv6_rule_by_id() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_list_policy_rules_v4()
                .times(1)
                .returning(|_| Ok(vec![]));

            let key = SrcLpmKeyV6::new(0, "2001:db8::".parse::<Ipv6Addr>().unwrap(), 32);
            let entry = create_test_lpm_entry(77777, PolicyAction::Drop);

            mock.expect_list_policy_rules_v6()
                .times(1)
                .return_once(move |_| Ok(vec![(key, LpmKeyV6::any(), entry)]));

            mock.expect_delete_policy_rule_v6()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            mock.expect_clear_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 77777 && *dir == Direction::Ingress)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));

            let params = DeleteRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(77777),
                src: None,
            };

            let result = service.delete_rule(params);

            assert!(result.is_ok());
        }

        #[test]
        fn test_mixed_ip_version_fails() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(88888),
                src: Some("192.168.1.0/24".to_string()),
                dst: Some("2001:db8::/32".to_string()),
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("same IP version"));
        }
    }

    mod error_handling {
        use super::*;

        #[test]
        fn test_add_rule_bpf_error_propagates() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            mock.expect_add_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Err(anyhow::anyhow!("BPF map full")));

            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("BPF map full") || err_msg.contains("Failed to add rule"),
                "Expected error about BPF map or add rule, got: {}",
                err_msg
            );
        }

        // ── duplicate match-criteria rejection ───────────────────────────────

        /// Build params for a baseline IPv4 TCP rule used by the duplicate tests.
        fn dup_test_params(id: u64) -> AddRuleParams {
            AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(id),
                src: Some("192.168.1.0/24".to_string()),
                dst: Some("10.0.0.0/8".to_string()),
                sport: 0,
                dport: 80,
                protocol: "tcp".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            }
        }

        /// An installed IPv4 rule whose keys match `dup_test_params`.
        fn dup_existing_v4(rule: L4Rule) -> (SrcLpmKeyV4, LpmKeyV4, L4Rule) {
            let src = SrcLpmKeyV4::new(0, "192.168.1.0".parse::<Ipv4Addr>().unwrap(), 24);
            let dst = LpmKeyV4::new("10.0.0.0".parse::<Ipv4Addr>().unwrap(), 8);
            (src, dst, rule)
        }

        #[test]
        fn test_add_duplicate_rule_rejected() {
            let mut mock = create_mock_with_loaded_programs();
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let existing = dup_existing_v4(L4Rule {
                dport: 80,
                protocol: libc::IPPROTO_TCP as u8,
                rule_id: 111,
                num_actions: 1,
                ..L4Rule::default()
            });
            mock.expect_list_policy_rules_v4()
                .returning(move |_| Ok(vec![existing]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            // The duplicate must never be installed.
            mock.expect_add_policy_rule_v4().times(0);

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.add_rule(dup_test_params(222));

            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("identical match criteria"),
                "expected duplicate error, got: {msg}"
            );
            assert!(
                msg.contains("111"),
                "should name existing rule id, got: {msg}"
            );
        }

        #[test]
        fn test_add_rule_different_port_allowed() {
            let mut mock = create_mock_with_loaded_programs();
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            // Existing rule matches everything except the destination port.
            let existing = dup_existing_v4(L4Rule {
                dport: 80,
                protocol: libc::IPPROTO_TCP as u8,
                rule_id: 111,
                num_actions: 1,
                ..L4Rule::default()
            });
            mock.expect_list_policy_rules_v4()
                .returning(move |_| Ok(vec![existing]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_add_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let mut params = dup_test_params(222);
            params.dport = 443; // different port → not a duplicate
            assert!(service.add_rule(params).is_ok());
        }

        #[test]
        fn test_add_rule_same_l4_different_sni_allowed() {
            let mut mock = create_mock_with_loaded_programs();
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let existing = dup_existing_v4(L4Rule {
                dport: 443,
                protocol: libc::IPPROTO_TCP as u8,
                sni_match_type: crate::types::SNI_MATCH_EXACT,
                rule_id: 111,
                num_actions: 1,
                ..L4Rule::default()
            });
            mock.expect_list_policy_rules_v4()
                .returning(move |_| Ok(vec![existing]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            // Existing rule's SNI pattern differs from the new one.
            mock.expect_lookup_sni_rule().returning(|_, _| {
                Ok(Some(SniRuleEntry::new(
                    crate::types::SNI_MATCH_EXACT,
                    "example.com",
                )))
            });
            mock.expect_add_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));
            mock.expect_add_sni_rule()
                .times(1)
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let mut params = dup_test_params(222);
            params.dport = 443;
            params.sni = Some("other.com".to_string());
            assert!(service.add_rule(params).is_ok());
        }

        #[test]
        fn test_add_rule_same_sni_pattern_rejected() {
            let mut mock = create_mock_with_loaded_programs();
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let existing = dup_existing_v4(L4Rule {
                dport: 443,
                protocol: libc::IPPROTO_TCP as u8,
                sni_match_type: crate::types::SNI_MATCH_EXACT,
                rule_id: 111,
                num_actions: 1,
                ..L4Rule::default()
            });
            mock.expect_list_policy_rules_v4()
                .returning(move |_| Ok(vec![existing]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_lookup_sni_rule().returning(|_, _| {
                Ok(Some(SniRuleEntry::new(
                    crate::types::SNI_MATCH_EXACT,
                    "example.com",
                )))
            });
            mock.expect_add_policy_rule_v4().times(0);

            let mut service = PolicyService::new(Box::new(mock));
            let mut params = dup_test_params(222);
            params.dport = 443;
            params.sni = Some("example.com".to_string()); // identical SNI → duplicate
            let result = service.add_rule(params);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("identical match criteria"));
        }

        #[test]
        fn test_add_rule_same_l4_different_mac_allowed() {
            let mut mock = create_mock_with_loaded_programs();
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let existing = dup_existing_v4(L4Rule {
                dport: 80,
                protocol: libc::IPPROTO_TCP as u8,
                mac_match_flags: crate::types::MAC_MATCH_SRC,
                rule_id: 111,
                num_actions: 1,
                ..L4Rule::default()
            });
            mock.expect_list_policy_rules_v4()
                .returning(move |_| Ok(vec![existing]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_lookup_mac_rule().returning(|_, _| {
                Ok(Some(MacRuleEntry {
                    src_mac: [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
                    dst_mac: [0u8; 6],
                }))
            });
            mock.expect_add_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));
            mock.expect_add_mac_rule()
                .times(1)
                .returning(|_, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let mut params = dup_test_params(222);
            // Same L4 tuple, but a different source MAC → not a duplicate.
            params.src_mac = Some([0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]);
            assert!(service.add_rule(params).is_ok());
        }

        #[test]
        fn test_add_rule_same_id_not_self_duplicate() {
            // Restore / scheduler re-activation re-adds a rule with the same id;
            // the existing entry with that id must not count as a duplicate.
            let mut mock = create_mock_with_loaded_programs();
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let existing = dup_existing_v4(L4Rule {
                dport: 80,
                protocol: libc::IPPROTO_TCP as u8,
                rule_id: 222,
                num_actions: 1,
                ..L4Rule::default()
            });
            mock.expect_list_policy_rules_v4()
                .returning(move |_| Ok(vec![existing]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_add_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            // Same id (222) as the installed rule → allowed.
            assert!(service.add_rule(dup_test_params(222)).is_ok());
        }

        #[test]
        fn test_attach_ingress_failure_propagates() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_attach_ingress()
                .times(1)
                .returning(|_, _| Err(anyhow::anyhow!("Interface not found")));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.attach_ingress("nonexistent", XdpMode::Native);

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("attach"));
        }

        #[test]
        fn test_invalid_protocol() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("192.168.1.0/24".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "invalid_proto".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Unknown protocol"));
        }

        #[test]
        fn test_invalid_cidr() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_get_attached_interfaces()
                .times(1)
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);

            let mut service = PolicyService::new(Box::new(mock));

            let params = AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(12345),
                src: Some("not-a-cidr".to_string()),
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Drop, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: None,
                schedule: None,
            };

            let result = service.add_rule(params);

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid source CIDR"));
        }
    }

    mod clear_stats {
        use super::*;

        #[test]
        fn test_clear_global_stats_ingress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_clear_global_stats()
                .times(1)
                .withf(|&ifindex, dir| ifindex == 2 && *dir == Direction::Ingress)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.clear_global_stats(2, Direction::Ingress);

            assert!(result.is_ok());
        }

        #[test]
        fn test_clear_rule_stats_egress() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_clear_rule_stats()
                .times(1)
                .withf(|&rule_id, dir| rule_id == 123 && *dir == Direction::Egress)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.clear_rule_stats(123, Direction::Egress);

            assert!(result.is_ok());
        }

        #[test]
        fn test_clear_all_rule_stats() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_clear_all_rule_stats()
                .times(1)
                .withf(|dir| *dir == Direction::Ingress)
                .returning(|_| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.clear_all_rule_stats(Direction::Ingress);

            assert!(result.is_ok());
        }

        #[test]
        fn test_clear_ethertype_stats() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_clear_ethertype_stats()
                .times(1)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.clear_ethertype_stats(2, Direction::Ingress);

            assert!(result.is_ok());
        }

        #[test]
        fn test_clear_interface_stats() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_clear_interface_stats()
                .times(1)
                .returning(|_, _| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.clear_interface_stats(2, Direction::Egress);

            assert!(result.is_ok());
        }

        #[test]
        fn test_clear_all_stats() {
            let mut mock = create_mock_with_loaded_programs();

            mock.expect_clear_all_stats().times(1).returning(|| Ok(()));

            let mut service = PolicyService::new(Box::new(mock));
            let result = service.clear_all_stats();

            assert!(result.is_ok());
        }
    }

    mod protocol_parsing {
        use super::*;
        use libc::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};

        #[test]
        fn test_parse_protocol_names() {
            assert_eq!(*TryInto::<Protocol>::try_into("any").unwrap(), 0);
            assert_eq!(
                *TryInto::<Protocol>::try_into("icmp").unwrap(),
                IPPROTO_ICMP as u8
            );
            assert_eq!(
                *TryInto::<Protocol>::try_into("tcp").unwrap(),
                IPPROTO_TCP as u8
            );
            assert_eq!(
                *TryInto::<Protocol>::try_into("udp").unwrap(),
                IPPROTO_UDP as u8
            );
            assert_eq!(
                *TryInto::<Protocol>::try_into("icmpv6").unwrap(),
                IPPROTO_ICMPV6 as u8
            );
        }

        #[test]
        fn test_parse_protocol_case_insensitive() {
            assert_eq!(
                *TryInto::<Protocol>::try_into("TCP").unwrap(),
                IPPROTO_TCP as u8
            );
            assert_eq!(
                *TryInto::<Protocol>::try_into("Tcp").unwrap(),
                IPPROTO_TCP as u8
            );
            assert_eq!(
                *TryInto::<Protocol>::try_into("UDP").unwrap(),
                IPPROTO_UDP as u8
            );
        }

        #[test]
        fn test_parse_protocol_numeric() {
            assert_eq!(
                *TryInto::<Protocol>::try_into("6").unwrap(),
                IPPROTO_TCP as u8
            );
            assert_eq!(
                *TryInto::<Protocol>::try_into("17").unwrap(),
                IPPROTO_UDP as u8
            );
            assert_eq!(*TryInto::<Protocol>::try_into("132").unwrap(), 132); // SCTP
        }
    }

    // ── Scheduler tests ──────────────────────────────────────────────────────

    mod scheduler {
        use super::*;
        use chrono::TimeZone;

        /// Build a minimal `AddRuleParams` for ingress PASS any/any.
        fn pass_rule_params() -> AddRuleParams {
            AddRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: None,
                src: None,
                dst: None,
                sport: 0,
                dport: 0,
                protocol: "any".to_string(),
                actions: vec![(PolicyAction::Pass, 0, ActionParams::None)],
                sni: None,
                quic_version: 0,
                src_mac: None,
                dst_mac: None,
                expires_after_secs: Some(60),
                schedule: None,
            }
        }

        /// Create a mock that accepts an `add_policy_rule_v4` call (rule install).
        fn mock_for_add() -> MockBpfOperations {
            let mut mock = MockBpfOperations::new();
            mock.expect_load_programs().returning(|| Ok(()));
            #[cfg(feature = "suricata")]
            mock.expect_get_inspect_config()
                .returning(|_| Ok(InspectConfig::default()));
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);
            mock.expect_add_policy_rule_v4()
                .returning(|_, _, _, _| Ok(()));
            mock.expect_flush_sni_rules().returning(|_| Ok(()));
            mock.expect_flush_mac_rules().returning(|_| Ok(()));
            // Duplicate-match check lists existing rules before each install.
            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock
        }

        /// Helper: build a schedule window for "Mon 09:00–Mon 17:00 UTC".
        fn mon_9_to_17() -> RuleScheduleParams {
            RuleScheduleParams {
                windows: vec![WeeklyWindowParams {
                    start: WeeklyTimePointParams {
                        day_of_week: 1,
                        hour: 9,
                        minute: 0,
                    },
                    end: WeeklyTimePointParams {
                        day_of_week: 1,
                        hour: 17,
                        minute: 0,
                    },
                }],
                timezone: "UTC".to_string(),
            }
        }

        // ── add_rule with TTL ────────────────────────────────────────────────

        #[test]
        fn test_add_rule_with_ttl_registers_in_registry() {
            let mock = mock_for_add();
            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();

            let mut service =
                PolicyService::new(Box::new(mock)).with_clock(Box::new(MockClock { now }));

            let params = pass_rule_params(); // expires_after_secs = Some(60)
            let result = service.add_rule(params);
            assert!(result.is_ok(), "{:?}", result);

            let managed = service.list_managed_rules();
            assert_eq!(managed.len(), 1);
            assert_eq!(managed[0].state, RuleState::Active);
            matches!(managed[0].lifecycle, RuleLifecycleKind::Ttl { .. });
        }

        #[test]
        fn test_add_rule_without_lifecycle_not_in_registry() {
            let mock = mock_for_add();
            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();

            let mut service =
                PolicyService::new(Box::new(mock)).with_clock(Box::new(MockClock { now }));

            let mut params = pass_rule_params();
            params.expires_after_secs = None; // permanent rule
            let result = service.add_rule(params);
            assert!(result.is_ok());

            assert!(service.list_managed_rules().is_empty());
        }

        #[test]
        fn test_add_rule_both_ttl_and_schedule_returns_error() {
            let mock = mock_for_add();
            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();

            let mut service =
                PolicyService::new(Box::new(mock)).with_clock(Box::new(MockClock { now }));

            let mut params = pass_rule_params();
            params.schedule = Some(mon_9_to_17()); // also set schedule → conflict
            let result = service.add_rule(params);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("mutually exclusive"),
                "unexpected error: {}",
                msg
            );
        }

        // ── add_rule with schedule: currently in window ──────────────────────

        #[test]
        fn test_add_scheduled_rule_active_when_in_window() {
            let mock = mock_for_add();
            // Mon 12:00 UTC — inside Mon 09:00–17:00
            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();

            let mut service =
                PolicyService::new(Box::new(mock)).with_clock(Box::new(MockClock { now }));

            let mut params = pass_rule_params();
            params.expires_after_secs = None;
            params.schedule = Some(mon_9_to_17());
            let result = service.add_rule(params);
            assert!(result.is_ok(), "{:?}", result);

            let managed = service.list_managed_rules();
            assert_eq!(managed.len(), 1);
            assert_eq!(managed[0].state, RuleState::Active);
        }

        #[test]
        fn test_add_scheduled_rule_inactive_when_outside_window() {
            // We need mock to also handle the delete that happens after add
            let mut mock = mock_for_add();
            let rule_id_holder: std::sync::Arc<std::sync::Mutex<u64>> =
                std::sync::Arc::new(std::sync::Mutex::new(0));
            let holder_clone = rule_id_holder.clone();

            // The delete path: list_policy_rules_v4 → delete_policy_rule_v4
            mock.expect_list_policy_rules_v4().returning(move |_dir| {
                let rid = *holder_clone.lock().unwrap();
                if rid == 0 {
                    return Ok(vec![]);
                }
                let src_key = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 0,
                    addr: [0u8; 4],
                };
                let dst_key = LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                };
                let rule = create_test_lpm_entry(rid, PolicyAction::Pass);
                Ok(vec![(src_key, dst_key, rule)])
            });
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_delete_policy_rule_v4()
                .returning(|_, _, _, _| Ok(()));

            // Capture the rule_id from add_policy_rule_v4 call
            let holder2 = rule_id_holder.clone();
            // We need to override add_policy_rule_v4 to capture the rule_id.
            // MockBpfOperations already set up expect_add_policy_rule_v4 in mock_for_add,
            // but we need to re-mock. Use a fresh mock instead.
            let mut mock2 = MockBpfOperations::new();
            mock2.expect_load_programs().returning(|| Ok(()));
            #[cfg(feature = "suricata")]
            mock2
                .expect_get_inspect_config()
                .returning(|_| Ok(InspectConfig::default()));
            mock2
                .expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);
            mock2
                .expect_add_policy_rule_v4()
                .returning(move |_, _, rule, _| {
                    *holder2.lock().unwrap() = rule.rule_id;
                    Ok(())
                });
            mock2.expect_flush_sni_rules().returning(|_| Ok(()));
            mock2.expect_flush_mac_rules().returning(|_| Ok(()));
            mock2.expect_list_policy_rules_v4().returning(move |_dir| {
                let rid = *rule_id_holder.lock().unwrap();
                if rid == 0 {
                    return Ok(vec![]);
                }
                let src_key = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 0,
                    addr: [0u8; 4],
                };
                let dst_key = LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                };
                let rule = create_test_lpm_entry(rid, PolicyAction::Pass);
                Ok(vec![(src_key, dst_key, rule)])
            });
            mock2
                .expect_list_policy_rules_v6()
                .returning(|_| Ok(vec![]));
            mock2
                .expect_delete_policy_rule_v4()
                .returning(|_, _, _, _| Ok(()));
            mock2.expect_clear_rule_stats().returning(|_, _| Ok(()));

            // Mon 08:00 UTC — outside Mon 09:00–17:00
            let now = Utc.with_ymd_and_hms(2024, 1, 8, 8, 0, 0).unwrap();

            let mut service =
                PolicyService::new(Box::new(mock2)).with_clock(Box::new(MockClock { now }));

            let mut params = pass_rule_params();
            params.expires_after_secs = None;
            params.schedule = Some(mon_9_to_17());
            let result = service.add_rule(params);
            assert!(result.is_ok(), "{:?}", result);

            let managed = service.list_managed_rules();
            assert_eq!(managed.len(), 1);
            assert_eq!(
                managed[0].state,
                RuleState::Inactive,
                "rule should be Inactive when added outside window"
            );
        }

        // ── handle_timer_expiry: TTL expiry ──────────────────────────────────

        #[test]
        fn test_handle_timer_expiry_ttl_removes_rule() {
            let rule_id_cell: std::sync::Arc<std::sync::Mutex<u64>> =
                std::sync::Arc::new(std::sync::Mutex::new(0));
            let cap = rule_id_cell.clone();

            let mut mock = MockBpfOperations::new();
            mock.expect_load_programs().returning(|| Ok(()));
            #[cfg(feature = "suricata")]
            mock.expect_get_inspect_config()
                .returning(|_| Ok(InspectConfig::default()));
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);
            mock.expect_add_policy_rule_v4()
                .returning(move |_, _, rule, _| {
                    *cap.lock().unwrap() = rule.rule_id;
                    Ok(())
                });
            mock.expect_flush_sni_rules().returning(|_| Ok(()));
            mock.expect_flush_mac_rules().returning(|_| Ok(()));

            let rcel = rule_id_cell.clone();
            mock.expect_list_policy_rules_v4().returning(move |_| {
                let rid = *rcel.lock().unwrap();
                if rid == 0 {
                    return Ok(vec![]);
                }
                let src = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 0,
                    addr: [0u8; 4],
                };
                let dst = LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                };
                Ok(vec![(
                    src,
                    dst,
                    create_test_lpm_entry(rid, PolicyAction::Pass),
                )])
            });
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_delete_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));
            mock.expect_clear_rule_stats()
                .times(1)
                .returning(|_, _| Ok(()));

            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
            let (tx, mut rx) = tokio::sync::broadcast::channel(16);
            let mut service = PolicyService::new(Box::new(mock))
                .with_clock(Box::new(MockClock { now }))
                .with_rule_event_sender(tx);

            service.add_rule(pass_rule_params()).unwrap();
            let rule_id = service.list_managed_rules()[0].rule_id;
            assert_eq!(service.list_managed_rules().len(), 1);
            // consume "activated" event
            let _ = rx.try_recv();

            // Simulate the timer firing
            let result = service.handle_timer_expiry(rule_id);

            assert!(
                result.is_none(),
                "TTL rule should return None (no reschedule)"
            );
            assert!(
                service.list_managed_rules().is_empty(),
                "expired rule should be removed from registry"
            );

            let ev = rx.try_recv().expect("should have an expired event");
            assert_eq!(ev.event_type, "expired");
            assert_eq!(ev.rule_id, rule_id);
        }

        #[test]
        fn test_handle_timer_expiry_missing_rule_is_noop() {
            let mock = MockBpfOperations::new();
            let mut service = PolicyService::new(Box::new(mock));

            // Calling with a non-existent rule_id must not panic and return None.
            let result = service.handle_timer_expiry(999999);
            assert!(result.is_none());
        }

        // ── handle_timer_expiry: schedule window transitions ─────────────────

        #[test]
        fn test_handle_timer_expiry_scheduled_activates_rule() {
            let mut mock = MockBpfOperations::new();
            mock.expect_load_programs().returning(|| Ok(()));
            #[cfg(feature = "suricata")]
            mock.expect_get_inspect_config()
                .returning(|_| Ok(InspectConfig::default()));
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);
            // Called once during add (immediately removed as out-of-window),
            // and once when handle_timer_expiry activates the rule.
            mock.expect_add_policy_rule_v4()
                .times(2)
                .returning(|_, _, _, _| Ok(()));
            mock.expect_flush_sni_rules().returning(|_| Ok(()));
            mock.expect_flush_mac_rules().returning(|_| Ok(()));
            // Out-of-window deactivation during add:
            mock.expect_list_policy_rules_v4().returning(|_| Ok(vec![]));
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));

            // Mon 08:00 UTC — outside Mon 09:00–17:00, so rule starts Inactive.
            let now = Utc.with_ymd_and_hms(2024, 1, 8, 8, 0, 0).unwrap();
            let mut service =
                PolicyService::new(Box::new(mock)).with_clock(Box::new(MockClock { now }));

            let mut params = pass_rule_params();
            params.expires_after_secs = None;
            params.schedule = Some(mon_9_to_17());
            service.add_rule(params).unwrap();
            let rule_id = service.list_managed_rules()[0].rule_id;
            assert_eq!(service.list_managed_rules()[0].state, RuleState::Inactive);

            // Simulate the timer firing at Mon 09:00 — window is now open.
            let at_open = Utc.with_ymd_and_hms(2024, 1, 8, 9, 0, 0).unwrap();
            service.clock = Box::new(MockClock { now: at_open });
            let next = service.handle_timer_expiry(rule_id);

            assert_eq!(
                service.list_managed_rules()[0].state,
                RuleState::Active,
                "rule should become Active when timer fires at window open"
            );
            // Should return Some(next_instant) for the window-close at 17:00.
            assert!(
                next.is_some(),
                "should schedule next transition (17:00 close)"
            );
        }

        // ── delete_rule cleans up registry ────────────────────────────────────

        #[test]
        fn test_delete_managed_rule_removes_from_registry() {
            let rule_id_cell: std::sync::Arc<std::sync::Mutex<u64>> =
                std::sync::Arc::new(std::sync::Mutex::new(0));
            let cap = rule_id_cell.clone();

            let mut mock = MockBpfOperations::new();
            mock.expect_load_programs().returning(|| Ok(()));
            #[cfg(feature = "suricata")]
            mock.expect_get_inspect_config()
                .returning(|_| Ok(InspectConfig::default()));
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);
            mock.expect_add_policy_rule_v4()
                .returning(move |_, _, rule, _| {
                    *cap.lock().unwrap() = rule.rule_id;
                    Ok(())
                });
            mock.expect_flush_sni_rules().returning(|_| Ok(()));
            mock.expect_flush_mac_rules().returning(|_| Ok(()));

            let rid_ref = rule_id_cell.clone();
            mock.expect_list_policy_rules_v4().returning(move |_| {
                let rid = *rid_ref.lock().unwrap();
                if rid == 0 {
                    return Ok(vec![]);
                }
                let src = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 0,
                    addr: [0u8; 4],
                };
                let dst = LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                };
                Ok(vec![(
                    src,
                    dst,
                    create_test_lpm_entry(rid, PolicyAction::Pass),
                )])
            });
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_delete_policy_rule_v4()
                .times(1)
                .returning(|_, _, _, _| Ok(()));
            mock.expect_clear_rule_stats().returning(|_, _| Ok(()));

            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
            let mut service =
                PolicyService::new(Box::new(mock)).with_clock(Box::new(MockClock { now }));

            service.add_rule(pass_rule_params()).unwrap();
            let rule_id = service.list_managed_rules()[0].rule_id;
            assert_eq!(service.list_managed_rules().len(), 1);

            let del_result = service.delete_rule(DeleteRuleParams {
                ifindex: 0,
                direction: Direction::Ingress,
                id: Some(rule_id),
                src: None,
            });
            assert!(del_result.is_ok());
            assert!(
                service.list_managed_rules().is_empty(),
                "managed rule should be removed on delete"
            );
        }

        // ── lifecycle event emission ─────────────────────────────────────────

        #[test]
        fn test_add_ttl_rule_emits_activated_event() {
            let mock = mock_for_add();
            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();

            let (tx, mut rx) = tokio::sync::broadcast::channel(16);

            let mut service = PolicyService::new(Box::new(mock))
                .with_clock(Box::new(MockClock { now }))
                .with_rule_event_sender(tx);

            service.add_rule(pass_rule_params()).unwrap();

            let ev = rx.try_recv().expect("should have an event");
            assert_eq!(ev.event_type, "activated");
            assert_eq!(ev.direction, "INGRESS");
        }

        #[test]
        fn test_delete_rule_emits_deleted_event() {
            let rule_id_cell: std::sync::Arc<std::sync::Mutex<u64>> =
                std::sync::Arc::new(std::sync::Mutex::new(0));
            let cap = rule_id_cell.clone();

            let mut mock = MockBpfOperations::new();
            mock.expect_load_programs().returning(|| Ok(()));
            #[cfg(feature = "suricata")]
            mock.expect_get_inspect_config()
                .returning(|_| Ok(InspectConfig::default()));
            mock.expect_get_attached_interfaces()
                .returning(|| vec![iface_attachment("eth0", 2, "native", "ingress")]);
            mock.expect_add_policy_rule_v4()
                .returning(move |_, _, rule, _| {
                    *cap.lock().unwrap() = rule.rule_id;
                    Ok(())
                });
            mock.expect_flush_sni_rules().returning(|_| Ok(()));
            mock.expect_flush_mac_rules().returning(|_| Ok(()));

            let rid_ref = rule_id_cell.clone();
            mock.expect_list_policy_rules_v4().returning(move |_| {
                let rid = *rid_ref.lock().unwrap();
                if rid == 0 {
                    return Ok(vec![]);
                }
                let src = SrcLpmKeyV4 {
                    prefixlen: 32,
                    ifindex: 0,
                    addr: [0u8; 4],
                };
                let dst = LpmKeyV4 {
                    prefixlen: 0,
                    addr: [0u8; 4],
                };
                Ok(vec![(
                    src,
                    dst,
                    create_test_lpm_entry(rid, PolicyAction::Pass),
                )])
            });
            mock.expect_list_policy_rules_v6().returning(|_| Ok(vec![]));
            mock.expect_delete_policy_rule_v4()
                .returning(|_, _, _, _| Ok(()));
            mock.expect_clear_rule_stats().returning(|_, _| Ok(()));

            let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
            let (tx, mut rx) = tokio::sync::broadcast::channel(16);

            let mut service = PolicyService::new(Box::new(mock))
                .with_clock(Box::new(MockClock { now }))
                .with_rule_event_sender(tx);

            service.add_rule(pass_rule_params()).unwrap();
            let _ = rx.try_recv(); // consume "activated" event

            let rule_id = service.list_managed_rules()[0].rule_id;
            service
                .delete_rule(DeleteRuleParams {
                    ifindex: 0,
                    direction: Direction::Ingress,
                    id: Some(rule_id),
                    src: None,
                })
                .unwrap();

            let ev = rx.try_recv().expect("should have a deleted event");
            assert_eq!(ev.event_type, "deleted");
            assert_eq!(ev.rule_id, rule_id);
        }
    }
}
