// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! In-memory registry of in-flight config generations awaiting agent confirmation.
//!
//! Each config-mutating GraphQL mutation issues a generation, captures the intended
//! store mutation as a `PendingOp`, and pushes the change to the agent. The DB is
//! only updated after the agent replies with `ConfigConfirm{APPLIED}` and the
//! controller commits. Watchdog reaping handles the case where the agent never
//! replies (marks the generation abandoned and drops the op — the agent will have
//! reverted locally).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::oneshot;

use policy_controller_proto::controller::{
    controller_message::Payload as CtrlPayload, AttachProgram, BpfDirection, BpfMode,
    ControllerMessage, DeltaConfigPush, DetachProgram, SetFibForwarding, SetInspectInterface,
    SetInspectMode, SetUrpf,
};

use crate::{
    reconciliation,
    store::{ControllerStore, Rule},
};

/// Default window the agent has to confirm before the controller gives up.
/// 30 s accommodates first-boot BPF loading (XDP verifier + JIT can take 10–25 s).
pub const DEFAULT_CONFIRM_DEADLINE_MS: u32 = 30_000;

/// Operations the controller will commit to the store once the agent confirms.
#[derive(Debug, Clone)]
pub enum PendingOp {
    CreateRule(Box<Rule>),
    DeleteRule {
        node_id: String,
        rule_id: String,
    },
    Attach {
        node_id: String,
        interface_name: String,
        direction: String, // "ingress" | "egress"
    },
    Detach {
        node_id: String,
        interface_name: String,
        direction: String,
    },
    SetFibForwarding {
        node_id: String,
        interface_name: String,
        enabled: bool,
    },
    SetUrpf {
        node_id: String,
        interface_name: String,
        /// 0 = off, 1 = loose, 2 = strict (matches URPF_* in policy_common.h).
        mode: u32,
    },
    SetInspectMode {
        node_id: String,
        /// 0 = disabled, 1 = IPS, 2 = IDS (matches engine InspectMode).
        mode: u32,
    },
    SetInspectInterface {
        node_id: String,
        interface_name: String,
        enabled: bool,
    },
    /// Operator-initiated fleet Suricata ruleset sync. The push is pre-built
    /// by suricata_sync::build_ruleset_push; the generation is stamped in
    /// to_controller_message. Commit is a no-op: desired state already lives
    /// in the assignment tables and reported state arrives with the next
    /// snapshot. Non-reverting on the agent (idempotent desired-state sync).
    PushSuricataRulesets {
        node_id: String,
        push: policy_controller_proto::controller::SuricataRulesetPush,
    },
    SetDefaultAction {
        node_id: String,
        interface_name: String,
        direction: String,
        action: String,
    },
    SetStopBehavior {
        node_id: String,
        /// "clear-state", "preserve-state", or empty string meaning "unset".
        behavior: String,
    },
    /// Bulk delete of all rules scoped to a single (node, interface, direction).
    /// The agent receives a single DeltaConfigPush listing every rule_id, deletes
    /// them locally, and on confirm the controller drops them from the store.
    FlushRules {
        node_id: String,
        interface_name: String,
        direction: String,
        rule_ids: Vec<String>,
    },
}

impl PendingOp {
    /// Stable string tag describing the op shape, for GraphQL/UI display.
    pub fn kind(&self) -> &'static str {
        match self {
            PendingOp::CreateRule(_) => "create_rule",
            PendingOp::DeleteRule { .. } => "delete_rule",
            PendingOp::Attach { .. } => "attach",
            PendingOp::Detach { .. } => "detach",
            PendingOp::SetFibForwarding { .. } => "set_fib_forwarding",
            PendingOp::SetUrpf { .. } => "set_urpf",
            PendingOp::SetInspectMode { .. } => "set_inspect_mode",
            PendingOp::SetInspectInterface { .. } => "set_inspect_interface",
            PendingOp::PushSuricataRulesets { .. } => "push_suricata_rulesets",
            PendingOp::SetDefaultAction { .. } => "set_default_action",
            PendingOp::SetStopBehavior { .. } => "set_stop_behavior",
            PendingOp::FlushRules { .. } => "flush_rules",
        }
    }

    pub fn node_id(&self) -> &str {
        match self {
            PendingOp::CreateRule(r) => &r.node_id,
            PendingOp::DeleteRule { node_id, .. }
            | PendingOp::Attach { node_id, .. }
            | PendingOp::Detach { node_id, .. }
            | PendingOp::SetFibForwarding { node_id, .. }
            | PendingOp::SetUrpf { node_id, .. }
            | PendingOp::SetInspectMode { node_id, .. }
            | PendingOp::SetInspectInterface { node_id, .. }
            | PendingOp::PushSuricataRulesets { node_id, .. }
            | PendingOp::SetDefaultAction { node_id, .. }
            | PendingOp::SetStopBehavior { node_id, .. }
            | PendingOp::FlushRules { node_id, .. } => node_id,
        }
    }

    /// The (interface, direction) this op targets, for per-control UI display.
    /// `direction` is `None` for ops that aren't direction-scoped (fib/urpf),
    /// and both are `None` for node-scoped ops (delete-by-id, stop-behavior).
    pub fn interface_target(&self) -> (Option<String>, Option<String>) {
        match self {
            PendingOp::Attach {
                interface_name,
                direction,
                ..
            }
            | PendingOp::Detach {
                interface_name,
                direction,
                ..
            }
            | PendingOp::SetDefaultAction {
                interface_name,
                direction,
                ..
            }
            | PendingOp::FlushRules {
                interface_name,
                direction,
                ..
            } => (Some(interface_name.clone()), Some(direction.clone())),
            PendingOp::SetFibForwarding { interface_name, .. }
            | PendingOp::SetUrpf { interface_name, .. }
            | PendingOp::SetInspectInterface { interface_name, .. } => {
                (Some(interface_name.clone()), None)
            }
            PendingOp::CreateRule(r) => (Some(r.interface_name.clone()), Some(r.direction.clone())),
            PendingOp::DeleteRule { .. }
            | PendingOp::SetStopBehavior { .. }
            | PendingOp::SetInspectMode { .. }
            | PendingOp::PushSuricataRulesets { .. } => (None, None),
        }
    }

    /// Build the outbound `ControllerMessage` that will drive this op on the
    /// agent. The generation_id and deadline are stamped in so the agent can
    /// correlate its `ConfigConfirm` reply.
    pub fn to_controller_message(
        &self,
        generation_id: &str,
        confirm_deadline_ms: u32,
    ) -> ControllerMessage {
        let payload = match self {
            PendingOp::CreateRule(rule) => {
                let rule_adds =
                    reconciliation::rules_to_rule_adds(std::slice::from_ref(rule.as_ref()));
                CtrlPayload::Config(DeltaConfigPush {
                    rules_to_add: rule_adds,
                    rule_ids_to_delete: Vec::new(),
                    is_full_restore: false,
                    per_interface_default_actions: std::collections::HashMap::new(),
                    generation_id: generation_id.to_string(),
                    confirm_deadline_ms,
                    stop_behavior: String::new(),
                })
            }
            PendingOp::DeleteRule { rule_id, .. } => CtrlPayload::Config(DeltaConfigPush {
                rules_to_add: Vec::new(),
                rule_ids_to_delete: vec![rule_id.clone()],
                is_full_restore: false,
                per_interface_default_actions: std::collections::HashMap::new(),
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
                stop_behavior: String::new(),
            }),
            PendingOp::Attach {
                interface_name,
                direction,
                ..
            } => CtrlPayload::Attach(AttachProgram {
                interface_name: interface_name.clone(),
                direction: direction_to_proto(direction) as i32,
                mode: BpfMode::Auto as i32,
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
            }),
            PendingOp::Detach {
                interface_name,
                direction,
                ..
            } => CtrlPayload::Detach(DetachProgram {
                interface_name: interface_name.clone(),
                direction: direction_to_proto(direction) as i32,
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
            }),
            PendingOp::SetFibForwarding {
                interface_name,
                enabled,
                ..
            } => CtrlPayload::SetFib(SetFibForwarding {
                interface_name: interface_name.clone(),
                enabled: *enabled,
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
            }),
            PendingOp::SetUrpf {
                interface_name,
                mode,
                ..
            } => CtrlPayload::SetUrpf(SetUrpf {
                interface_name: interface_name.clone(),
                mode: *mode,
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
            }),
            PendingOp::SetInspectMode { mode, .. } => CtrlPayload::SetInspectMode(SetInspectMode {
                mode: *mode,
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
            }),
            PendingOp::SetInspectInterface {
                interface_name,
                enabled,
                ..
            } => CtrlPayload::SetInspectInterface(SetInspectInterface {
                interface_name: interface_name.clone(),
                enabled: *enabled,
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
            }),
            PendingOp::PushSuricataRulesets { push, .. } => {
                let mut push = push.clone();
                push.generation_id = generation_id.to_string();
                push.confirm_deadline_ms = confirm_deadline_ms;
                CtrlPayload::SuricataRulesetPush(push)
            }
            PendingOp::SetDefaultAction {
                interface_name,
                direction,
                action,
                ..
            } => {
                let key = format!("{}:{}", interface_name, direction.to_lowercase());
                let mut map = std::collections::HashMap::new();
                map.insert(key, action.clone());
                CtrlPayload::Config(DeltaConfigPush {
                    rules_to_add: Vec::new(),
                    rule_ids_to_delete: Vec::new(),
                    is_full_restore: false,
                    per_interface_default_actions: map,
                    generation_id: generation_id.to_string(),
                    confirm_deadline_ms,
                    stop_behavior: String::new(),
                })
            }
            PendingOp::SetStopBehavior { behavior, .. } => CtrlPayload::Config(DeltaConfigPush {
                rules_to_add: Vec::new(),
                rule_ids_to_delete: Vec::new(),
                is_full_restore: false,
                per_interface_default_actions: std::collections::HashMap::new(),
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
                stop_behavior: behavior.clone(),
            }),
            PendingOp::FlushRules { rule_ids, .. } => CtrlPayload::Config(DeltaConfigPush {
                rules_to_add: Vec::new(),
                rule_ids_to_delete: rule_ids.clone(),
                is_full_restore: false,
                per_interface_default_actions: std::collections::HashMap::new(),
                generation_id: generation_id.to_string(),
                confirm_deadline_ms,
                stop_behavior: String::new(),
            }),
        };
        ControllerMessage {
            payload: Some(payload),
        }
    }

    /// Commit the pending change to the store. Called after the agent confirms.
    pub async fn commit(&self, store: &Arc<dyn ControllerStore>) -> Result<()> {
        match self {
            PendingOp::CreateRule(rule) => store.create_rule(rule).await,
            PendingOp::DeleteRule { rule_id, .. } => store.delete_rule(rule_id).await,
            PendingOp::Attach {
                node_id,
                interface_name,
                direction,
            } => {
                // Mark attachment in the node_interfaces table.
                let current = store.list_node_interfaces(node_id).await?;
                let mut attachments: Vec<(String, String)> = current
                    .iter()
                    .flat_map(|ni| {
                        let mut v = Vec::new();
                        if ni.xdp_attached {
                            v.push((ni.name.clone(), "ingress".to_string()));
                        }
                        if ni.tc_attached {
                            v.push((ni.name.clone(), "egress".to_string()));
                        }
                        v
                    })
                    .collect();
                let tuple = (interface_name.clone(), direction.clone());
                if !attachments.contains(&tuple) {
                    attachments.push(tuple);
                }
                store
                    .update_interface_attachments(node_id, &attachments)
                    .await
            }
            PendingOp::Detach {
                node_id,
                interface_name,
                direction,
            } => {
                let current = store.list_node_interfaces(node_id).await?;
                let attachments: Vec<(String, String)> = current
                    .iter()
                    .flat_map(|ni| {
                        let mut v = Vec::new();
                        if ni.xdp_attached {
                            v.push((ni.name.clone(), "ingress".to_string()));
                        }
                        if ni.tc_attached {
                            v.push((ni.name.clone(), "egress".to_string()));
                        }
                        v
                    })
                    .filter(|(iface, dir)| !(iface == interface_name && dir == direction))
                    .collect();
                store
                    .update_interface_attachments(node_id, &attachments)
                    .await
            }
            PendingOp::SetFibForwarding {
                node_id,
                interface_name,
                enabled,
            } => {
                let current = store.list_node_interfaces(node_id).await?;
                let mut enabled_ifaces: Vec<String> = current
                    .iter()
                    .filter(|ni| ni.fib_forwarding && ni.name != *interface_name)
                    .map(|ni| ni.name.clone())
                    .collect();
                if *enabled {
                    enabled_ifaces.push(interface_name.clone());
                }
                store
                    .update_interface_fib_forwarding(node_id, &enabled_ifaces)
                    .await
            }
            PendingOp::SetUrpf {
                node_id,
                interface_name,
                mode,
            } => {
                let current = store.list_node_interfaces(node_id).await?;
                // Preserve the uRPF mode of every other interface, then apply
                // the new mode for this one (mode 0 = off → simply omitted).
                let mut modes: Vec<(String, u32)> = current
                    .iter()
                    .filter(|ni| ni.urpf_mode != 0 && ni.name != *interface_name)
                    .map(|ni| (ni.name.clone(), ni.urpf_mode))
                    .collect();
                if *mode != 0 {
                    modes.push((interface_name.clone(), *mode));
                }
                store.update_interface_urpf(node_id, &modes).await
            }
            PendingOp::SetInspectMode { node_id, mode } => {
                let mode_str = match mode {
                    1 => "ips",
                    2 => "ids",
                    _ => "disabled",
                };
                store.set_node_inspect_mode(node_id, mode_str).await
            }
            PendingOp::SetInspectInterface {
                node_id,
                interface_name,
                enabled,
            } => {
                store
                    .update_interface_inspect_enabled(node_id, interface_name, *enabled)
                    .await
            }
            // Desired state is the assignment tables (already written by the
            // mutation); reported state arrives with the next snapshot.
            PendingOp::PushSuricataRulesets { .. } => Ok(()),
            PendingOp::SetDefaultAction {
                node_id,
                interface_name,
                direction,
                action,
            } => {
                store
                    .update_interface_default_action(node_id, interface_name, direction, action)
                    .await
            }
            PendingOp::SetStopBehavior { node_id, behavior } => {
                let b = if behavior.is_empty() {
                    None
                } else {
                    Some(behavior.as_str())
                };
                store.update_node_stop_behavior(node_id, b).await
            }
            PendingOp::FlushRules { rule_ids, .. } => {
                for rid in rule_ids {
                    store.delete_rule(rid).await?;
                }
                Ok(())
            }
        }
    }
}

/// Outcome of a pending generation, delivered to the waiting caller.
#[derive(Debug, Clone)]
pub enum ConfirmOutcome {
    /// Agent applied the change; controller committed to the store.
    Applied,
    /// Controller could not commit the change (store error after apply).
    CommitFailed(String),
    /// Agent refused the change; nothing was applied.
    Rejected(String),
    /// Agent applied then reverted (watchdog or ack denied).
    Reverted(String),
    /// Controller's watchdog reaped the generation before the agent confirmed.
    Abandoned,
}

/// In-flight generation awaiting confirmation from an agent.
pub struct PendingGeneration {
    pub generation_id: String,
    pub issued_at: DateTime<Utc>,
    pub deadline: Instant,
    pub op: PendingOp,
    /// Tenant the target node belongs to, captured at `try_begin` time.
    /// `list_all` / `get_for_node` filter on this so GraphQL readers can
    /// only see their own tenant's in-flight generations.
    pub tenant_slug: String,
    /// Fired exactly once when the generation resolves (success, failure, or reap).
    /// `None` after the sender has been taken.
    notify: Option<oneshot::Sender<ConfirmOutcome>>,
}

/// View of a pending generation safe to expose to GraphQL / UI (no oneshot).
#[derive(Debug, Clone)]
pub struct PendingGenerationView {
    pub generation_id: String,
    pub issued_at: DateTime<Utc>,
    pub op_kind: &'static str,
    pub node_id: String,
    pub tenant_slug: String,
    /// Interface the op targets, when it is interface-scoped. Lets the UI pin
    /// the in-flight spinner to a specific interface row across navigation.
    pub interface_name: Option<String>,
    /// "ingress" | "egress" for direction-scoped ops; `None` otherwise.
    pub direction: Option<String>,
}

impl From<&PendingGeneration> for PendingGenerationView {
    fn from(g: &PendingGeneration) -> Self {
        let (interface_name, direction) = g.op.interface_target();
        Self {
            generation_id: g.generation_id.clone(),
            issued_at: g.issued_at,
            op_kind: g.op.kind(),
            node_id: g.op.node_id().to_string(),
            tenant_slug: g.tenant_slug.clone(),
            interface_name,
            direction,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BeginError {
    #[error(
        "Node {node_id} already has a pending config generation ({existing_gen}); try again once it resolves"
    )]
    Blocked {
        node_id: String,
        existing_gen: String,
    },
}

/// Registry of in-flight generations, keyed by node_id (one pending op per node).
#[derive(Default)]
pub struct PendingRegistry {
    /// node_id → pending generation. One-per-node enforces single-writer.
    by_node: Mutex<HashMap<String, PendingGeneration>>,
    /// generation_id → node_id, for lookup when the agent replies.
    by_gen: Mutex<HashMap<String, String>>,
}

impl PendingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a generation for `op`. Returns the generation_id and a receiver
    /// that fires once the generation resolves (applied / rejected / reverted /
    /// abandoned). Fails if the node already has an in-flight generation.
    /// `tenant_slug` is the target node's tenant — derived by the caller
    /// from `NodeRecord.tenant_id` so the stored generation can be
    /// surfaced only to that tenant via the GraphQL `pendingGeneration*`
    /// queries.
    pub fn try_begin(
        &self,
        op: PendingOp,
        tenant_slug: String,
        deadline_ms: u32,
    ) -> Result<(String, oneshot::Receiver<ConfirmOutcome>), BeginError> {
        let node_id = op.node_id().to_string();
        let mut by_node = self.by_node.lock().unwrap();
        if let Some(existing) = by_node.get(&node_id) {
            return Err(BeginError::Blocked {
                node_id,
                existing_gen: existing.generation_id.clone(),
            });
        }
        let generation_id = new_generation_id();
        let (tx, rx) = oneshot::channel();
        let gen = PendingGeneration {
            generation_id: generation_id.clone(),
            issued_at: Utc::now(),
            deadline: Instant::now() + Duration::from_millis(deadline_ms as u64),
            op,
            tenant_slug,
            notify: Some(tx),
        };
        log::info!(
            "Created pending generation {} for node {}",
            generation_id,
            node_id
        );
        by_node.insert(node_id.clone(), gen);
        self.by_gen
            .lock()
            .unwrap()
            .insert(generation_id.clone(), node_id);
        Ok((generation_id, rx))
    }

    /// Remove and return the pending generation with this id (called on any outcome).
    pub fn take(&self, generation_id: &str) -> Option<PendingGeneration> {
        let node_id = self.by_gen.lock().unwrap().remove(generation_id)?;
        self.by_node.lock().unwrap().remove(&node_id)
    }

    /// Peek at the pending generation for a node, if any (UI-safe view).
    /// Returns `None` if no generation is in flight **or** if the
    /// generation belongs to a different tenant — the latter looks
    /// identical to "no pending" so a tenant A operator can't probe
    /// for tenant B activity by node id.
    pub fn get_for_node(&self, node_id: &str, tenant_slug: &str) -> Option<PendingGenerationView> {
        self.by_node
            .lock()
            .unwrap()
            .get(node_id)
            .filter(|g| g.tenant_slug == tenant_slug)
            .map(PendingGenerationView::from)
    }

    /// Snapshot in-flight generations in `tenant_slug`. Cross-tenant
    /// visibility is not supported here; the GraphQL `pendingGenerations`
    /// resolver always passes `principal.tenant_slug`. The watchdog uses
    /// `reap_expired` (no tenant filter) since reaping is fleet-wide.
    pub fn list_all(&self, tenant_slug: &str) -> Vec<PendingGenerationView> {
        self.by_node
            .lock()
            .unwrap()
            .values()
            .filter(|g| g.tenant_slug == tenant_slug)
            .map(PendingGenerationView::from)
            .collect()
    }

    /// Remove and return all generations whose deadlines have passed.
    pub fn reap_expired(&self) -> Vec<PendingGeneration> {
        let now = Instant::now();
        let mut by_node = self.by_node.lock().unwrap();
        let expired_ids: Vec<String> = by_node
            .iter()
            .filter(|(_, g)| g.deadline <= now)
            .map(|(nid, _)| nid.clone())
            .collect();
        let mut out = Vec::new();
        for nid in expired_ids {
            if let Some(gen) = by_node.remove(&nid) {
                self.by_gen.lock().unwrap().remove(&gen.generation_id);
                out.push(gen);
            }
        }
        out
    }
}

impl PendingGeneration {
    /// Fire the notification channel; silently drops if already consumed
    /// or the receiver has been dropped.
    pub fn notify(mut self, outcome: ConfirmOutcome) {
        if let Some(tx) = self.notify.take() {
            let _ = tx.send(outcome);
        }
    }
}

fn direction_to_proto(dir: &str) -> BpfDirection {
    match dir {
        "ingress" => BpfDirection::Ingress,
        "egress" => BpfDirection::Egress,
        _ => BpfDirection::Unspecified,
    }
}

fn new_generation_id() -> String {
    // Plain UUIDv4 — ordering isn't needed, uniqueness is.
    uuid::Uuid::new_v4().to_string()
}

// ── High-level drive function for GraphQL mutations ─────────────────────────

/// End-to-end: gate → push → await confirm → commit. Returns the final outcome.
///
/// The controller holds the payload in-memory until the agent confirms; only
/// then is it committed to the store. If the agent is offline, rejects, reverts,
/// or times out, the store is never touched.
pub async fn apply_pending_op(
    op: PendingOp,
    registry: &Arc<PendingRegistry>,
    sessions: &Arc<crate::session::NodeSessionManager>,
    store: &Arc<dyn ControllerStore>,
    deadline_ms: u32,
) -> Result<ConfirmOutcome, BeginError> {
    let node_id = op.node_id().to_string();

    if !sessions.is_online(&node_id) {
        // Not a gating failure — surface as its own outcome so the caller can
        // distinguish "node disconnected" from "node busy".
        return Ok(ConfirmOutcome::Rejected(format!(
            "Node {} is not currently connected",
            node_id
        )));
    }

    // Tag the pending generation with the target node's tenant so the
    // `pendingGenerations` / `pendingGeneration` read paths can filter
    // correctly. Derived from the node row rather than the caller's
    // principal: the node is authoritative for its own tenant and we
    // don't want cross-tenant writes (a separate concern) to also leak
    // into the wrong tenant's pending view.
    let tenant_slug = match store.get_node(&node_id).await {
        Ok(Some(n)) => n.tenant_id,
        Ok(None) => {
            return Ok(ConfirmOutcome::Rejected(format!(
                "Node {} has no record in the store",
                node_id
            )))
        }
        Err(e) => {
            log::warn!("apply_pending_op: tenant lookup for {node_id} failed: {e:#}");
            // Fall through to the default tenant rather than failing the
            // op — the pending view will be slightly mis-tagged but the
            // agent push proceeds. Matches the broader "default tenant
            // as the last-resort fallback" pattern used by audit writes.
            "default".to_string()
        }
    };

    let op_for_push = op.clone();
    let (generation_id, rx) = registry.try_begin(op, tenant_slug, deadline_ms)?;
    let msg = op_for_push.to_controller_message(&generation_id, deadline_ms);

    if !sessions.push(&node_id, msg).await {
        // Agent dropped between try_begin and push; take the slot back.
        if let Some(gen) = registry.take(&generation_id) {
            gen.notify(ConfirmOutcome::Rejected("agent disconnected".to_string()));
        }
        return Ok(ConfirmOutcome::Rejected(format!(
            "Failed to send config to node {} (disconnected?)",
            node_id
        )));
    }

    // Guard with a timeout slightly longer than the agent's confirm deadline
    // so the watchdog has a chance to reap first.
    let wait = Duration::from_millis(deadline_ms as u64 + 1_000);
    match tokio::time::timeout(wait, rx).await {
        Ok(Ok(outcome)) => {
            let _ = store
                .append_audit(crate::store::NewAuditEntry {
                    operator: None,
                    action: format!("config_{}", outcome_tag(&outcome)),
                    node_id: Some(node_id),
                    detail: Some(format!("generation_id={}", generation_id)),
                    tenant_id: None,
                })
                .await;
            Ok(outcome)
        }
        Ok(Err(_canceled)) => Ok(ConfirmOutcome::Abandoned),
        Err(_elapsed) => {
            // Reap defensively in case the watchdog hasn't fired yet.
            if let Some(gen) = registry.take(&generation_id) {
                gen.notify(ConfirmOutcome::Abandoned);
            }
            Ok(ConfirmOutcome::Abandoned)
        }
    }
}

fn outcome_tag(o: &ConfirmOutcome) -> &'static str {
    match o {
        ConfirmOutcome::Applied => "applied",
        ConfirmOutcome::CommitFailed(_) => "commit_failed",
        ConfirmOutcome::Rejected(_) => "rejected",
        ConfirmOutcome::Reverted(_) => "reverted",
        ConfirmOutcome::Abandoned => "abandoned",
    }
}

// ── Watchdog runner ──────────────────────────────────────────────────────────

/// Periodically reap expired generations. Runs as a tokio task for the lifetime
/// of the controller process.
pub async fn run_watchdog(
    registry: Arc<PendingRegistry>,
    store: Arc<dyn ControllerStore>,
    tick: Duration,
) {
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let expired = registry.reap_expired();
        for gen in expired {
            log::warn!(
                "Pending generation {} for node {} expired without confirmation — abandoning",
                gen.generation_id,
                gen.op.node_id()
            );
            let _ = store
                .append_audit(crate::store::NewAuditEntry {
                    operator: None,
                    action: "config_abandoned".to_string(),
                    node_id: Some(gen.op.node_id().to_string()),
                    detail: Some(format!("generation_id={}", gen.generation_id)),
                    tenant_id: None,
                })
                .await;
            gen.notify(ConfirmOutcome::Abandoned);
        }
    }
}

// ── Trait-obj convenience wrapper to make commit easier to test ──────────────

#[async_trait]
pub trait Committer: Send + Sync {
    async fn commit(&self, op: &PendingOp) -> Result<()>;
}

pub struct StoreCommitter(pub Arc<dyn ControllerStore>);

#[async_trait]
impl Committer for StoreCommitter {
    async fn commit(&self, op: &PendingOp) -> Result<()> {
        op.commit(&self.0).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryControllerStore;

    fn sample_rule(node_id: &str, rule_id: &str) -> Box<Rule> {
        Box::new(Rule {
            id: rule_id.to_string(),
            tenant_id: "default".to_string(),
            node_id: node_id.to_string(),
            interface_name: "eth0".to_string(),
            direction: "ingress".to_string(),
            src_cidr: None,
            dst_cidr: None,
            src_port: None,
            dst_port: None,
            protocol: "any".to_string(),
            sni_pattern: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            actions_json: "[]".to_string(),
            created_at: Utc::now(),
            created_by: None,
            expires_after_secs: None,
            schedule_json: None,
        })
    }

    #[test]
    fn inspect_ops_build_gated_messages() {
        let op = PendingOp::SetInspectMode {
            node_id: "n1".into(),
            mode: 1,
        };
        assert_eq!(op.kind(), "set_inspect_mode");
        assert_eq!(op.node_id(), "n1");
        assert_eq!(op.interface_target(), (None, None));
        match op.to_controller_message("GEN", 30_000).payload {
            Some(CtrlPayload::SetInspectMode(m)) => {
                assert_eq!(m.mode, 1);
                assert_eq!(m.generation_id, "GEN");
                assert_eq!(m.confirm_deadline_ms, 30_000);
            }
            other => panic!("unexpected payload: {:?}", other),
        }

        let op = PendingOp::SetInspectInterface {
            node_id: "n1".into(),
            interface_name: "eth0".into(),
            enabled: true,
        };
        assert_eq!(op.kind(), "set_inspect_interface");
        assert_eq!(op.interface_target(), (Some("eth0".to_string()), None));
        match op.to_controller_message("GEN2", 10_000).payload {
            Some(CtrlPayload::SetInspectInterface(m)) => {
                assert_eq!(m.interface_name, "eth0");
                assert!(m.enabled);
                assert_eq!(m.generation_id, "GEN2");
                assert_eq!(m.confirm_deadline_ms, 10_000);
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[tokio::test]
    async fn begin_returns_distinct_generation_ids() {
        let reg = PendingRegistry::new();
        let (g1, _rx1) = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n1", "r1")),
                "default".to_string(),
                5_000,
            )
            .unwrap();
        reg.take(&g1).unwrap();
        let (g2, _rx2) = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n1", "r2")),
                "default".to_string(),
                5_000,
            )
            .unwrap();
        assert_ne!(g1, g2);
    }

    #[tokio::test]
    async fn concurrent_pending_blocked_per_node() {
        let reg = PendingRegistry::new();
        let _ = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n1", "r1")),
                "default".to_string(),
                5_000,
            )
            .unwrap();
        let err = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n1", "r2")),
                "default".to_string(),
                5_000,
            )
            .unwrap_err();
        matches!(err, BeginError::Blocked { .. });
        // But a different node is unblocked.
        let _ = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n2", "r3")),
                "default".to_string(),
                5_000,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn take_clears_by_node_and_by_gen() {
        let reg = PendingRegistry::new();
        let (gen_id, _rx) = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n1", "r1")),
                "default".to_string(),
                5_000,
            )
            .unwrap();
        assert!(reg.get_for_node("n1", "default").is_some());
        assert!(reg.take(&gen_id).is_some());
        assert!(reg.get_for_node("n1", "default").is_none());
        assert!(reg.take(&gen_id).is_none()); // idempotent
    }

    #[tokio::test]
    async fn reap_expired_notifies_waiting_caller() {
        let reg = PendingRegistry::new();
        let (_g1, rx1) = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n1", "r1")),
                "default".to_string(),
                0,
            )
            .unwrap();
        let (_g2, _rx2) = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n2", "r2")),
                "default".to_string(),
                60_000,
            )
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let expired = reg.reap_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].op.node_id(), "n1");
        for gen in expired {
            gen.notify(ConfirmOutcome::Abandoned);
        }
        assert!(matches!(rx1.await.unwrap(), ConfirmOutcome::Abandoned));
        assert!(reg.get_for_node("n1", "default").is_none());
        assert!(reg.get_for_node("n2", "default").is_some());
    }

    #[tokio::test]
    async fn list_and_get_filter_by_tenant() {
        let reg = PendingRegistry::new();
        let _ = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n-default", "r1")),
                "default".to_string(),
                60_000,
            )
            .unwrap();
        let _ = reg
            .try_begin(
                PendingOp::CreateRule(sample_rule("n-acme", "r2")),
                "acme".to_string(),
                60_000,
            )
            .unwrap();

        let default = reg.list_all("default");
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].node_id, "n-default");

        let acme = reg.list_all("acme");
        assert_eq!(acme.len(), 1);
        assert_eq!(acme[0].node_id, "n-acme");

        // get_for_node returns None when tenant doesn't match — looks
        // identical to "no generation" so a tenant A operator can't
        // enumerate tenant B's busy nodes.
        assert!(reg.get_for_node("n-acme", "default").is_none());
        assert!(reg.get_for_node("n-default", "acme").is_none());
        assert!(reg.get_for_node("n-acme", "acme").is_some());
    }

    #[test]
    fn interface_target_exposes_scope_for_per_control_ui() {
        // Direction-scoped ops carry both interface and direction.
        let attach = PendingOp::Attach {
            node_id: "n1".to_string(),
            interface_name: "eth0".to_string(),
            direction: "ingress".to_string(),
        };
        assert_eq!(
            attach.interface_target(),
            (Some("eth0".to_string()), Some("ingress".to_string()))
        );

        // Interface-scoped but not direction-scoped: direction is None.
        let fib = PendingOp::SetFibForwarding {
            node_id: "n1".to_string(),
            interface_name: "eth1".to_string(),
            enabled: true,
        };
        assert_eq!(fib.interface_target(), (Some("eth1".to_string()), None));

        // Node-scoped ops target no interface.
        let stop = PendingOp::SetStopBehavior {
            node_id: "n1".to_string(),
            behavior: "clear-state".to_string(),
        };
        assert_eq!(stop.interface_target(), (None, None));
    }

    #[tokio::test]
    async fn pending_view_carries_interface_and_direction() {
        let reg = PendingRegistry::new();
        let _ = reg
            .try_begin(
                PendingOp::Attach {
                    node_id: "n1".to_string(),
                    interface_name: "eth0".to_string(),
                    direction: "egress".to_string(),
                },
                "default".to_string(),
                60_000,
            )
            .unwrap();
        let view = reg.get_for_node("n1", "default").unwrap();
        assert_eq!(view.op_kind, "attach");
        assert_eq!(view.interface_name.as_deref(), Some("eth0"));
        assert_eq!(view.direction.as_deref(), Some("egress"));
    }

    #[tokio::test]
    async fn commit_create_rule_persists_to_store() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let op = PendingOp::CreateRule(sample_rule("n1", "r1"));
        op.commit(&store).await.unwrap();
        assert!(store.get_rule("r1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn commit_delete_rule_removes_from_store() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        store.create_rule(&sample_rule("n1", "r1")).await.unwrap();
        let op = PendingOp::DeleteRule {
            node_id: "n1".to_string(),
            rule_id: "r1".to_string(),
        };
        op.commit(&store).await.unwrap();
        assert!(store.get_rule("r1").await.unwrap().is_none());
    }
}
