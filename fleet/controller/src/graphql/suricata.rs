// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! GraphQL resolvers for fleet-managed Suricata rulesets.
//!
//! Kept out of `schema.rs` (which only carries thin delegating methods) to
//! stop that file from growing. Follows the `alerts.rs` pattern: free
//! `resolve_*` functions pulling their dependencies from the GraphQL
//! context.
//!
//! Assigned rulesets are controller *desired* state (unlike inspect mode,
//! which is agent-authoritative): every mutation here immediately syncs
//! affected online nodes with an un-gated `SuricataRulesetPush`, and the
//! snapshot-driven drift reconcile in `grpc::management` converges nodes
//! that were offline or missed the push.

use std::sync::Arc;

use async_graphql::{Context, InputObject, Result, SimpleObject, ID};
use chrono::Utc;
use policy_controller_proto::controller::{
    controller_message::Payload as CtrlPayload, ControllerMessage,
};

use crate::rbac::Principal;
use crate::session::NodeSessionManager;
use crate::store::{ControllerStore, NewAuditEntry, SuricataAlertFilter, SuricataRuleset};
use crate::suricata_sync::{
    build_ruleset_push, canonicalize_content, rule_count, sha256_hex, validate_ruleset_name,
    MAX_RULESET_BYTES,
};

use super::schema::OperationResult;

#[derive(SimpleObject, Clone)]
pub struct SuricataRulesetOutput {
    pub id: ID,
    pub tenant_id: String,
    pub name: String,
    /// Filename this ruleset materialises as on nodes ("fleet-<name>.rules").
    pub filename: String,
    /// Full rule file content. Only fetched when selected.
    pub content: String,
    /// Hex SHA-256 over the exact content bytes (drift-detection digest).
    pub sha256: String,
    pub rule_count: i32,
    pub created_at: String,
    pub updated_at: String,
    /// IDs of nodes this ruleset is assigned to.
    pub assigned_node_ids: Vec<String>,
}

/// A ruleset as seen from one node, with its sync state.
#[derive(SimpleObject, Clone)]
pub struct AssignedRulesetOutput {
    pub id: ID,
    pub name: String,
    pub filename: String,
    pub sha256: String,
    pub rule_count: i32,
    /// True when the node's reported digest for this file matches the
    /// controller's stored digest.
    pub in_sync: bool,
}

/// One agent-reported Suricata rule file on a node.
#[derive(SimpleObject, Clone)]
pub struct NodeRuleFileOutput {
    pub filename: String,
    pub sha256: String,
    pub rule_count: i32,
    /// True for controller-managed ("fleet-*") files.
    pub fleet_managed: bool,
}

/// A persisted Suricata alert.
#[derive(SimpleObject, Clone)]
pub struct SuricataAlertOutput {
    pub id: String,
    pub node_id: String,
    /// Suricata's EVE timestamp string.
    pub timestamp: String,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<i32>,
    pub protocol: Option<String>,
    pub action: Option<String>,
    pub signature_id: Option<i32>,
    pub signature: Option<String>,
    pub category: Option<String>,
    pub severity: Option<i32>,
    /// True once an operator has acknowledged (UI "cleared") this alert.
    pub acked: bool,
}

/// Filter for the `suricataAlerts` query. Tenant scoping is applied
/// automatically from the caller's principal.
#[derive(InputObject, Default)]
pub struct SuricataAlertFilterInput {
    pub node_id: Option<String>,
    /// Only alerts at least this urgent (Suricata severity <= N).
    pub min_severity: Option<i32>,
    pub signature_id: Option<i32>,
    /// Substring match against the signature text.
    pub signature_contains: Option<String>,
    /// Also return acknowledged alerts (default false: unacked only).
    pub include_acked: Option<bool>,
}

pub async fn resolve_suricata_alerts(
    ctx: &Context<'_>,
    filter: Option<SuricataAlertFilterInput>,
    limit: Option<i32>,
) -> Result<Vec<SuricataAlertOutput>> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let f = filter.unwrap_or_default();
    let store_filter = SuricataAlertFilter {
        tenant_id: Some(principal.tenant_slug.clone()),
        node_id: f.node_id,
        min_severity: f.min_severity,
        signature_id: f.signature_id.map(|v| v as i64),
        signature_contains: f.signature_contains,
        include_acked: f.include_acked.unwrap_or(false),
    };
    let limit = limit.unwrap_or(200).clamp(1, 5000) as i64;
    Ok(store
        .list_suricata_alerts(&store_filter, limit)
        .await?
        .into_iter()
        .map(|a| SuricataAlertOutput {
            id: a.id.to_string(),
            node_id: a.node_id,
            timestamp: a.timestamp,
            src_ip: a.src_ip,
            src_port: a.src_port,
            dest_ip: a.dst_ip,
            dest_port: a.dst_port,
            protocol: a.proto,
            action: a.action,
            signature_id: a.signature_id.map(|v| v as i32),
            signature: a.signature,
            category: a.category,
            severity: a.severity,
            acked: a.acked_at.is_some(),
        })
        .collect())
}

/// Acknowledge all unacked alerts for the caller's tenant (optionally one
/// node's). Alerts stay in the store for history/retention; the default
/// alert list just stops showing them.
pub async fn resolve_ack_suricata_alerts(
    ctx: &Context<'_>,
    node_id: Option<ID>,
) -> Result<OperationResult> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let node_id = node_id.map(|n| n.0);
    let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let updated = store
        .ack_suricata_alerts(&principal.tenant_slug, node_id.as_deref(), now_ns)
        .await?;
    audit(
        store,
        principal,
        "suricata_alerts_acked",
        node_id,
        format!("acked={updated}"),
    )
    .await;
    Ok(OperationResult {
        success: true,
        message: Some(format!("Acknowledged {updated} alert(s)")),
    })
}

/// Delete persisted alerts for the caller's tenant (optionally one node's).
/// The live WebSocket stream is unaffected — this only clears history.
pub async fn resolve_clear_suricata_alerts(
    ctx: &Context<'_>,
    node_id: Option<ID>,
) -> Result<OperationResult> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let node_id = node_id.map(|n| n.0);
    let removed = store
        .clear_suricata_alerts(&principal.tenant_slug, node_id.as_deref())
        .await?;
    audit(
        store,
        principal,
        "suricata_alerts_cleared",
        node_id,
        format!("removed={removed}"),
    )
    .await;
    Ok(OperationResult {
        success: true,
        message: Some(format!("Deleted {removed} alert(s)")),
    })
}

async fn output_for(
    store: &Arc<dyn ControllerStore>,
    rs: SuricataRuleset,
) -> Result<SuricataRulesetOutput> {
    let assigned = store.list_nodes_for_suricata_ruleset(&rs.id).await?;
    Ok(SuricataRulesetOutput {
        id: ID(rs.id.clone()),
        tenant_id: rs.tenant_id.clone(),
        name: rs.name.clone(),
        filename: rs.filename(),
        content: rs.content,
        sha256: rs.sha256,
        rule_count: rs.rule_count as i32,
        created_at: rs.created_at.to_rfc3339(),
        updated_at: rs.updated_at.to_rfc3339(),
        assigned_node_ids: assigned,
    })
}

/// Load a ruleset and verify it belongs to the caller's tenant.
async fn load_tenant_ruleset(
    store: &Arc<dyn ControllerStore>,
    principal: &Principal,
    id: &str,
) -> Result<SuricataRuleset> {
    let rs = store
        .get_suricata_ruleset(id)
        .await?
        .ok_or_else(|| async_graphql::Error::new(format!("Ruleset '{}' not found", id)))?;
    if rs.tenant_id != principal.tenant_slug {
        return Err(async_graphql::Error::new(format!(
            "Ruleset '{}' not found",
            id
        )));
    }
    Ok(rs)
}

/// Best-effort immediate sync of one node's fleet-* files (un-gated push to
/// its live session). Offline or non-capable nodes are skipped — the
/// snapshot drift reconcile picks them up later.
pub async fn sync_node_now(
    store: &Arc<dyn ControllerStore>,
    sessions: &Arc<NodeSessionManager>,
    node_id: &str,
) {
    let capable = store
        .get_node(node_id)
        .await
        .ok()
        .flatten()
        .map(|n| n.capabilities.contains("\"suricata\""))
        .unwrap_or(false);
    if !capable {
        return;
    }
    let desired = match store.list_suricata_rulesets_for_node(node_id).await {
        Ok(d) => d,
        Err(e) => {
            log::warn!("sync_node_now: failed to load rulesets for {node_id}: {e:#}");
            return;
        }
    };
    let reported = store
        .list_node_suricata_rule_files(node_id)
        .await
        .unwrap_or_default();
    if let Some(push) = build_ruleset_push(&desired, &reported) {
        let sent = sessions
            .push(
                node_id,
                ControllerMessage {
                    payload: Some(CtrlPayload::SuricataRulesetPush(push)),
                },
            )
            .await;
        if !sent {
            log::debug!("sync_node_now: {node_id} offline; drift reconcile will catch up");
        }
    }
}

async fn audit(
    store: &Arc<dyn ControllerStore>,
    principal: &Principal,
    action: &str,
    node_id: Option<String>,
    detail: String,
) {
    let _ = store
        .append_audit(NewAuditEntry {
            operator: Some(principal.actor.clone()),
            action: action.to_string(),
            node_id,
            detail: Some(detail),
            tenant_id: Some(principal.tenant_slug.clone()),
        })
        .await;
}

// ── Queries ───────────────────────────────────────────────────────────────────

pub async fn resolve_suricata_rulesets(ctx: &Context<'_>) -> Result<Vec<SuricataRulesetOutput>> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let rulesets = store
        .list_suricata_rulesets(Some(&principal.tenant_slug))
        .await?;
    let mut out = Vec::with_capacity(rulesets.len());
    for rs in rulesets {
        out.push(output_for(store, rs).await?);
    }
    Ok(out)
}

pub async fn resolve_suricata_ruleset(
    ctx: &Context<'_>,
    id: ID,
) -> Result<Option<SuricataRulesetOutput>> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    match store.get_suricata_ruleset(&id.0).await? {
        Some(rs) if rs.tenant_id == principal.tenant_slug => Ok(Some(output_for(store, rs).await?)),
        _ => Ok(None),
    }
}

/// Rulesets assigned to a node, with per-file sync state.
pub async fn resolve_node_suricata_rulesets(
    ctx: &Context<'_>,
    node_id: ID,
) -> Result<Vec<AssignedRulesetOutput>> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let desired = store.list_suricata_rulesets_for_node(&node_id.0).await?;
    let reported = store.list_node_suricata_rule_files(&node_id.0).await?;
    Ok(desired
        .into_iter()
        .map(|rs| {
            let in_sync = reported
                .iter()
                .any(|f| f.filename == rs.filename() && f.sha256 == rs.sha256);
            AssignedRulesetOutput {
                id: ID(rs.id.clone()),
                name: rs.name.clone(),
                filename: rs.filename(),
                sha256: rs.sha256,
                rule_count: rs.rule_count as i32,
                in_sync,
            }
        })
        .collect())
}

/// All agent-reported Suricata rule files on a node (fleet- and local).
pub async fn resolve_node_suricata_rule_files(
    ctx: &Context<'_>,
    node_id: ID,
) -> Result<Vec<NodeRuleFileOutput>> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    Ok(store
        .list_node_suricata_rule_files(&node_id.0)
        .await?
        .into_iter()
        .map(|f| NodeRuleFileOutput {
            fleet_managed: f.filename.starts_with("fleet-"),
            filename: f.filename,
            sha256: f.sha256,
            rule_count: f.rule_count as i32,
        })
        .collect())
}

// ── Mutations ─────────────────────────────────────────────────────────────────

pub async fn resolve_create_suricata_ruleset(
    ctx: &Context<'_>,
    name: String,
    content: String,
) -> Result<SuricataRulesetOutput> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;

    validate_ruleset_name(&name).map_err(async_graphql::Error::new)?;
    let content = canonicalize_content(&content);
    if content.len() > MAX_RULESET_BYTES {
        return Err(async_graphql::Error::new(format!(
            "Ruleset content exceeds {} MiB",
            MAX_RULESET_BYTES / (1024 * 1024)
        )));
    }

    let now = Utc::now();
    let rs = SuricataRuleset {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: principal.tenant_slug.clone(),
        name: name.clone(),
        sha256: sha256_hex(&content),
        rule_count: rule_count(&content),
        content,
        created_at: now,
        updated_at: now,
    };
    store.create_suricata_ruleset(&rs).await?;
    audit(
        store,
        principal,
        "suricata_ruleset_created",
        None,
        format!("name={name}"),
    )
    .await;
    output_for(store, rs).await
}

pub async fn resolve_update_suricata_ruleset(
    ctx: &Context<'_>,
    id: ID,
    content: String,
) -> Result<SuricataRulesetOutput> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let rs = load_tenant_ruleset(store, principal, &id.0).await?;

    let content = canonicalize_content(&content);
    if content.len() > MAX_RULESET_BYTES {
        return Err(async_graphql::Error::new(format!(
            "Ruleset content exceeds {} MiB",
            MAX_RULESET_BYTES / (1024 * 1024)
        )));
    }
    let sha256 = sha256_hex(&content);
    let count = rule_count(&content);
    store
        .update_suricata_ruleset(&id.0, &content, &sha256, count, Utc::now())
        .await?;
    audit(
        store,
        principal,
        "suricata_ruleset_updated",
        None,
        format!("name={} sha256={}", rs.name, sha256),
    )
    .await;

    // Sync every assigned online node right away.
    for node_id in store.list_nodes_for_suricata_ruleset(&id.0).await? {
        sync_node_now(store, sessions, &node_id).await;
    }

    let updated = load_tenant_ruleset(store, principal, &id.0).await?;
    output_for(store, updated).await
}

pub async fn resolve_delete_suricata_ruleset(ctx: &Context<'_>, id: ID) -> Result<OperationResult> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let rs = load_tenant_ruleset(store, principal, &id.0).await?;

    let affected = store.list_nodes_for_suricata_ruleset(&id.0).await?;
    store.delete_suricata_ruleset(&id.0).await?;
    audit(
        store,
        principal,
        "suricata_ruleset_deleted",
        None,
        format!("name={}", rs.name),
    )
    .await;
    // Sync so the file is removed from nodes that carried it.
    for node_id in affected {
        sync_node_now(store, sessions, &node_id).await;
    }
    Ok(OperationResult::ok())
}

pub async fn resolve_assign_suricata_ruleset(
    ctx: &Context<'_>,
    node_id: ID,
    ruleset_id: ID,
) -> Result<OperationResult> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let rs = load_tenant_ruleset(store, principal, &ruleset_id.0).await?;

    // The node must advertise the suricata capability — mirrors
    // setInspectMode's synchronous gate.
    let node = store
        .get_node(&node_id.0)
        .await?
        .ok_or_else(|| async_graphql::Error::new(format!("Node '{}' not found", node_id.0)))?;
    if node.tenant_id != principal.tenant_slug {
        return Err(async_graphql::Error::new(format!(
            "Node '{}' not found",
            node_id.0
        )));
    }
    if !node.capabilities.contains("\"suricata\"") {
        return Ok(OperationResult::err(format!(
            "Node '{}' does not support 'suricata' (agent or engine built without the feature)",
            node_id.0
        )));
    }

    store
        .assign_suricata_ruleset(&node_id.0, &ruleset_id.0)
        .await?;
    audit(
        store,
        principal,
        "suricata_ruleset_assigned",
        Some(node_id.0.clone()),
        format!("name={}", rs.name),
    )
    .await;
    sync_node_now(store, sessions, &node_id.0).await;
    Ok(OperationResult::ok())
}

pub async fn resolve_unassign_suricata_ruleset(
    ctx: &Context<'_>,
    node_id: ID,
    ruleset_id: ID,
) -> Result<OperationResult> {
    let store = ctx.data::<Arc<dyn ControllerStore>>()?;
    let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let rs = load_tenant_ruleset(store, principal, &ruleset_id.0).await?;

    store
        .unassign_suricata_ruleset(&node_id.0, &ruleset_id.0)
        .await?;
    audit(
        store,
        principal,
        "suricata_ruleset_unassigned",
        Some(node_id.0.clone()),
        format!("name={}", rs.name),
    )
    .await;
    sync_node_now(store, sessions, &node_id.0).await;
    Ok(OperationResult::ok())
}
