// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use async_graphql::{
    Context, EmptySubscription, InputObject, Object, Result, Schema, SimpleObject, ID,
};
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    api_tokens::ApiTokenStore,
    event_pipeline::{alert_bus::AlertRuleBus, TenantScope},
    graphql::alerts::{
        resolve_alert_history, resolve_alert_rules, resolve_create_alert_rule,
        resolve_create_receiver, resolve_create_silence, resolve_delete_alert_rule,
        resolve_delete_receiver, resolve_delete_silence, resolve_receivers, resolve_silences,
        resolve_update_alert_rule, resolve_update_receiver, AlertHistoryConnection,
        AlertHistoryFilterInput, AlertRuleOutput, CreateAlertRuleInput, CreateReceiverInput,
        CreateSilenceInput, ReceiverOutput, SilenceOutput,
    },
    graphql::api_tokens::{
        resolve_api_tokens, resolve_create_api_token, resolve_revoke_api_token, ApiTokenOutput,
        ApiTokenWithSecret,
    },
    graphql::events::{
        resolve_event_aggregate, resolve_events, AggregateBucketOutput, EventConnection,
        EventFilterInput, EventGroupBy,
    },
    grpc::build_full_restore_push,
    metrics_parser,
    metrics_store::MetricsStore,
    node_registry::NodeRegistry,
    pending::{
        apply_pending_op, BeginError, ConfirmOutcome, PendingOp, PendingRegistry,
        DEFAULT_CONFIRM_DEADLINE_MS,
    },
    rbac::Require,
    reconciliation,
    rule_lifecycle_bus::{RuleLifecycleBus, RuleLifecycleEvent},
    session::NodeSessionManager,
    store::{
        AuditEntry, ControllerStore, NewAuditEntry, NodeInterface, NodeRecord, NodeStatus, Rule,
    },
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Upper bound on rows returned by a single audit export, so a wide time
/// window can't pull an unbounded result set into memory.
const AUDIT_EXPORT_CAP: u32 = 100_000;

/// Parse an optional RFC 3339 timestamp into unix epoch seconds, treating
/// `None`/empty as no bound. Returns a GraphQL error on malformed input.
fn parse_opt_rfc3339_epoch(s: Option<&str>) -> Result<Option<i64>> {
    match s {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|t| Some(t.timestamp()))
            .map_err(|e| async_graphql::Error::new(format!("invalid timestamp {s:?}: {e}"))),
    }
}

/// Generate a timestamp-based numeric rule ID.
///
/// Uses microseconds since epoch with an atomic counter to guarantee uniqueness
/// even when called multiple times in the same microsecond.
fn next_rule_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let prev = COUNTER.fetch_max(us, Ordering::SeqCst);
    let id = if prev >= us { prev + 1 } else { us };
    COUNTER.store(id, Ordering::SeqCst);
    id.to_string()
}

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(SimpleObject, Clone)]
pub struct ControlledNodeOutput {
    pub id: ID,
    pub label: Option<String>,
    pub hostname: Option<String>,
    pub dmi_uuid: Option<String>,
    pub status: String,
    /// Hex-encoded serial of the currently-issued mTLS client cert, or None if
    /// no cert has been issued yet (e.g. node is still pending).
    pub cert_serial: Option<String>,
    pub cert_expiry: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub enrolled_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent successful `RenewClientCert`. `None` until
    /// the first renewal; allows the UI to flag nodes whose certs haven't
    /// been refreshed in a long time even though they're still within TTL.
    pub last_renewed_at: Option<DateTime<Utc>>,
    pub tpm_backed: bool,
    pub agent_version: Option<String>,
    pub os_pretty_name: Option<String>,
    pub kernel_version: Option<String>,
    pub dmi_sys_vendor: Option<String>,
    pub dmi_product_name: Option<String>,
    pub tenant_id: String,
    /// Operator-configured stop behavior: "clear-state" or "preserve-state". None = controller default.
    pub stop_behavior: Option<String>,
    /// Operator-configured metrics scrape/forward interval in seconds. None = agent default.
    pub metrics_interval_secs: Option<i32>,
    /// JSON-encoded `Capabilities` from the most recent AgentHello. Raw
    /// string (not a typed sub-object) so adding fields in the proto
    /// doesn't churn the GraphQL schema. `"{}"` until the agent reconnects
    /// after step-6 was deployed.
    pub capabilities: String,
}

impl From<NodeRecord> for ControlledNodeOutput {
    fn from(n: NodeRecord) -> Self {
        Self {
            id: ID(n.id),
            label: n.label,
            hostname: n.hostname,
            dmi_uuid: n.dmi_uuid,
            status: n.status.to_string(),
            cert_serial: n.cert_serial.as_deref().map(hex::encode),
            cert_expiry: n.cert_expiry,
            last_seen: n.last_seen,
            enrolled_at: n.enrolled_at,
            last_renewed_at: n.last_renewed_at,
            tpm_backed: n.tpm_backed,
            agent_version: n.agent_version,
            os_pretty_name: n.os_pretty_name,
            kernel_version: n.kernel_version,
            dmi_sys_vendor: n.dmi_sys_vendor,
            dmi_product_name: n.dmi_product_name,
            tenant_id: n.tenant_id,
            stop_behavior: n.stop_behavior,
            metrics_interval_secs: n.metrics_interval_secs.map(|v| v as i32),
            capabilities: n.capabilities,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct RuleOutput {
    pub id: ID,
    pub tenant_id: String,
    pub node_id: String,
    pub interface_name: String,
    pub direction: String,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    pub protocol: String,
    pub sni_pattern: Option<String>,
    pub quic_version: Option<String>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub actions_json: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub expires_after_secs: Option<u32>,
    pub schedule_json: Option<String>,
}

impl From<Rule> for RuleOutput {
    fn from(r: Rule) -> Self {
        Self {
            id: ID(r.id),
            tenant_id: r.tenant_id,
            node_id: r.node_id,
            interface_name: r.interface_name,
            direction: r.direction,
            src_cidr: r.src_cidr,
            dst_cidr: r.dst_cidr,
            src_port: r.src_port,
            dst_port: r.dst_port,
            protocol: r.protocol,
            sni_pattern: r.sni_pattern,
            quic_version: r.quic_version,
            src_mac: r.src_mac,
            dst_mac: r.dst_mac,
            actions_json: r.actions_json,
            created_at: r.created_at,
            created_by: r.created_by,
            expires_after_secs: r.expires_after_secs,
            schedule_json: r.schedule_json,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct NodeInterfaceOutput {
    pub node_id: String,
    pub name: String,
    /// Linux interface index. Matches the `ifindex` reported on flow events,
    /// so the UI can join events to the human-readable interface name.
    pub ifindex: i32,
    pub mac_address: Option<String>,
    pub link_state: String,
    pub addresses_json: String,
    pub tag: Option<String>,
    pub last_reported: DateTime<Utc>,
    pub xdp_attached: bool,
    pub tc_attached: bool,
    /// True when XDP FIB forwarding is enabled on this interface (ingress only).
    /// Forwarded transit traffic bypasses the kernel stack, which also means
    /// any TC egress filtering on the outbound interface is NOT applied.
    pub fib_forwarding: bool,
    /// Controller-set default action for unmatched ingress packets ("pass" or "drop").
    /// None means no explicit default has been set (engine default is "pass").
    pub ingress_default_action: Option<String>,
    /// Controller-set default action for unmatched egress packets ("pass" or "drop").
    /// None means no explicit default has been set (engine default is "pass").
    pub egress_default_action: Option<String>,
}

impl From<NodeInterface> for NodeInterfaceOutput {
    fn from(i: NodeInterface) -> Self {
        Self {
            node_id: i.node_id,
            name: i.name,
            ifindex: i.ifindex as i32,
            mac_address: i.mac_address,
            link_state: i.link_state,
            addresses_json: i.addresses_json,
            tag: i.tag,
            last_reported: i.last_reported,
            xdp_attached: i.xdp_attached,
            tc_attached: i.tc_attached,
            fib_forwarding: i.fib_forwarding,
            ingress_default_action: i.ingress_default_action,
            egress_default_action: i.egress_default_action,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct AuditEntryOutput {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub operator: Option<String>,
    pub action: String,
    pub node_id: Option<String>,
    pub detail: Option<String>,
}

impl From<AuditEntry> for AuditEntryOutput {
    fn from(e: AuditEntry) -> Self {
        Self {
            id: e.id,
            ts: e.ts,
            operator: e.operator,
            action: e.action,
            node_id: e.node_id,
            detail: e.detail,
        }
    }
}

/// A formatted audit log export, ready for the client to download.
#[derive(SimpleObject, Clone)]
pub struct AuditExportOutput {
    /// Suggested download filename, e.g. `audit-export-20260619T120000Z.csv`.
    pub filename: String,
    /// MIME content type for the payload (e.g. `text/csv`).
    pub content_type: String,
    /// The formatted audit log as UTF-8 text.
    pub data: String,
}

/// In-flight config mutation awaiting agent confirmation.
#[derive(SimpleObject, Clone)]
pub struct PendingGenerationOutput {
    pub generation_id: String,
    pub node_id: String,
    /// One of: "create_rule", "delete_rule", "flush_rules", "attach", "detach", "set_fib_forwarding".
    pub op_kind: String,
    pub issued_at: DateTime<Utc>,
}

impl From<crate::pending::PendingGenerationView> for PendingGenerationOutput {
    fn from(v: crate::pending::PendingGenerationView) -> Self {
        Self {
            generation_id: v.generation_id,
            node_id: v.node_id,
            op_kind: v.op_kind.to_string(),
            issued_at: v.issued_at,
        }
    }
}

#[derive(SimpleObject)]
pub struct OperationResult {
    pub success: bool,
    pub message: Option<String>,
}

impl OperationResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            message: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: Some(msg.into()),
        }
    }
}

/// Per-rule packet/byte statistics read from the node's most-recent Prometheus
/// metrics snapshot.  Values reflect the state at the last scrape interval
/// (every 30 s by default).
#[derive(SimpleObject, Clone)]
pub struct NodeRuleStatsOutput {
    pub rule_id: String,
    pub direction: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Per-interface traffic statistics read from the node's most-recent Prometheus
/// metrics snapshot.
#[derive(SimpleObject, Clone)]
pub struct NodeInterfaceStatsOutput {
    pub interface: String,
    pub direction: String,
    // Traffic
    pub packets: u64,
    pub bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    // Policy
    pub policy_matches: u64,
    pub policy_drops: u64,
    pub policy_pass: u64,
    pub policy_redirects: u64,
    // Processing
    pub bum_packets: u64,
    pub non_ip_unicast: u64,
    pub fragments: u64,
    pub parse_errors: u64,
    pub tail_calls: u64,
    pub inspect_redirects: u64,
    // Verdicts
    pub verdict_pass_packets: u64,
    pub verdict_pass_bytes: u64,
    pub verdict_drop_packets: u64,
    pub verdict_drop_bytes: u64,
    // FIB
    pub fib_forwarded_packets: u64,
    pub fib_forwarded_bytes: u64,
    pub fib_fallback_packets: u64,
}

/// Fleet-wide rollup of dataplane counters, summed across the most-recent
/// Prometheus snapshot of every node in the caller's tenant.
///
/// All values are monotonic counter totals (not rates).  Clients compute
/// per-second rates by sampling this query over time and dividing the delta
/// by the elapsed wall-clock interval.
#[derive(SimpleObject, Clone, Default)]
pub struct FleetMetricsOutput {
    /// Number of nodes that have reported at least one metrics snapshot and
    /// are included in these totals.
    pub nodes_reporting: i32,
    /// Total nodes in the tenant (denominator for coverage).
    pub nodes_total: i32,
    // Traffic
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    // Policy
    pub policy_matches: u64,
    pub policy_pass: u64,
    pub policy_drops: u64,
    pub policy_redirects: u64,
    // Verdicts
    pub verdict_pass_packets: u64,
    pub verdict_pass_bytes: u64,
    pub verdict_drop_packets: u64,
    pub verdict_drop_bytes: u64,
    // Processing health
    pub parse_errors: u64,
    pub fragments: u64,
    pub inspect_redirects: u64,
}

/// Ethertype traffic breakdown from the node's most-recent Prometheus snapshot.
#[derive(SimpleObject, Clone)]
pub struct NodeEthertypeStatOutput {
    pub ethertype: u32,
    pub name: String,
    pub packets: u64,
}

// ── Input types ──────────────────────────────────────────────────────────────

#[derive(InputObject)]
pub struct CreateRuleMultiNodeInput {
    pub node_ids: Vec<String>,
    pub interface_name: String,
    /// "ingress" or "egress"
    pub direction: String,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    /// "tcp", "udp", "icmp", "icmpv6", "any"
    pub protocol: Option<String>,
    pub sni_pattern: Option<String>,
    pub quic_version: Option<String>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    /// JSON array of actions: [{"action":"drop","priority":0}]
    pub actions_json: String,
    pub expires_after_secs: Option<u32>,
    pub schedule_json: Option<String>,
}

#[derive(InputObject)]
pub struct CreateRuleInput {
    pub node_id: String,
    pub interface_name: String,
    /// "ingress" or "egress"
    pub direction: String,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    /// "tcp", "udp", "icmp", "icmpv6", "any"
    pub protocol: Option<String>,
    pub sni_pattern: Option<String>,
    pub quic_version: Option<String>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    /// JSON array of actions: [{"action":"drop","priority":0}]
    pub actions_json: String,
    /// Remove rule after this many seconds (TTL lifecycle). Mutually exclusive with schedule_json.
    pub expires_after_secs: Option<u32>,
    /// JSON-serialized schedule: {"timezone":"UTC","windows":[{"start":{"dayOfWeek":1,"hour":9,"minute":0},"end":{"dayOfWeek":1,"hour":17,"minute":0}}]}
    pub schedule_json: Option<String>,
}

// ── Enrollment token (ZTP) types ──────────────────────────────────────────────

#[derive(SimpleObject)]
pub struct EnrollmentTokenInfo {
    pub token_id: ID,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub uses_remaining: i64,
    pub cidr_scope: Option<String>,
    pub fleet_label: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Controller-derived service URLs used when minting enrollment bundles via
/// the UI. The strings are baked from `server_san` + the ports of
/// `enrollment_addr` / `management_addr` in `ControllerConfig`. The operator
/// can override them in the mint form (this is just a sensible default).
#[derive(SimpleObject, Clone)]
pub struct ServiceEndpoints {
    pub controller_url: String,
    pub enrollment_url: String,
}

/// Result of minting a new bootstrap token. `bundle` is shown to the operator
/// exactly once and must be distributed to target hosts; the raw token secret
/// cannot be retrieved afterwards.
#[derive(SimpleObject)]
pub struct IssuedEnrollmentToken {
    pub token_id: ID,
    pub bundle: String,
    pub expires_at: DateTime<Utc>,
    pub uses_remaining: i64,
}

// ── Query root ────────────────────────────────────────────────────────────────

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Query persisted policy match events (newest first, cursor paginated).
    #[graphql(guard = "Require::new(\"event:read\")")]
    async fn events(
        &self,
        ctx: &Context<'_>,
        filter: Option<EventFilterInput>,
        limit: Option<i32>,
        cursor: Option<String>,
    ) -> Result<EventConnection> {
        resolve_events(ctx, filter, limit, cursor).await
    }

    /// Aggregate persisted events into time/dimension buckets.
    #[graphql(guard = "Require::new(\"event:read\")")]
    async fn event_aggregate(
        &self,
        ctx: &Context<'_>,
        filter: Option<EventFilterInput>,
        group_by: EventGroupBy,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<Vec<AggregateBucketOutput>> {
        resolve_event_aggregate(ctx, filter, group_by, since, until).await
    }

    /// All configured alert rules for the current tenant.
    #[graphql(guard = "Require::new(\"alert:read\")")]
    async fn alert_rules(&self, ctx: &Context<'_>) -> Result<Vec<AlertRuleOutput>> {
        resolve_alert_rules(ctx).await
    }

    /// All configured notification receivers.
    #[graphql(guard = "Require::new(\"alert:read\")")]
    async fn receivers(&self, ctx: &Context<'_>) -> Result<Vec<ReceiverOutput>> {
        resolve_receivers(ctx).await
    }

    /// Notification silences. `active=true` filters to silences in effect
    /// right now; `false` or omitted returns everything.
    #[graphql(guard = "Require::new(\"alert:read\")")]
    async fn silences(
        &self,
        ctx: &Context<'_>,
        active: Option<bool>,
    ) -> Result<Vec<SilenceOutput>> {
        resolve_silences(ctx, active).await
    }

    /// Cursor-paginated alert-fire history, newest first.
    #[graphql(guard = "Require::new(\"alert:read\")")]
    async fn alert_history(
        &self,
        ctx: &Context<'_>,
        filter: Option<AlertHistoryFilterInput>,
        limit: Option<i32>,
        cursor: Option<String>,
    ) -> Result<AlertHistoryConnection> {
        resolve_alert_history(ctx, filter, limit, cursor).await
    }

    /// All API bearer tokens (does not include plaintext). Plaintext is
    /// returned exactly once on `createApiToken`.
    #[graphql(guard = "Require::new(\"token:read\")")]
    async fn api_tokens(&self, ctx: &Context<'_>) -> Result<Vec<ApiTokenOutput>> {
        resolve_api_tokens(ctx).await
    }

    /// List all controlled nodes, optionally filtered by status.
    #[graphql(guard = "Require::new(\"node:read\")")]
    async fn nodes(
        &self,
        ctx: &Context<'_>,
        status: Option<String>,
    ) -> Result<Vec<ControlledNodeOutput>> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        let filter = parse_status(status.as_deref())?;
        let nodes = registry
            .list_nodes(Some(&principal.tenant_slug), filter)
            .await?;
        Ok(nodes.into_iter().map(Into::into).collect())
    }

    /// Get a single node by ID.
    #[graphql(guard = "Require::new(\"node:read\")")]
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<ControlledNodeOutput>> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        // Treat cross-tenant hits as "no such node" — same shape as a
        // genuinely unknown id, so a tenant A operator cannot probe for
        // the existence of tenant B nodes by id.
        Ok(registry
            .get_node(&id)
            .await?
            .filter(|n| n.tenant_id == principal.tenant_slug)
            .map(Into::into))
    }

    /// Controller-derived URLs used when minting enrollment bundles via the
    /// UI. The UI uses these as form defaults; operators can edit them.
    #[graphql(guard = "Require::new(\"tenant:read\")")]
    async fn service_endpoints(&self, ctx: &Context<'_>) -> Result<ServiceEndpoints> {
        Ok(ctx.data::<ServiceEndpoints>()?.clone())
    }

    /// List all ZTP enrollment tokens, newest first. Includes revoked and
    /// expired tokens so operators can audit token usage history.
    #[graphql(guard = "Require::new(\"enrollment:read\")")]
    async fn enrollment_tokens(&self, ctx: &Context<'_>) -> Result<Vec<EnrollmentTokenInfo>> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        let tokens = registry
            .list_enrollment_tokens(Some(&principal.tenant_slug))
            .await?;
        Ok(tokens
            .into_iter()
            .map(|t| EnrollmentTokenInfo {
                token_id: ID(t.token_id),
                created_at: t.created_at,
                created_by: t.created_by,
                expires_at: t.expires_at,
                uses_remaining: t.uses_remaining,
                cidr_scope: t.cidr_scope,
                fleet_label: t.fleet_label,
                revoked_at: t.revoked_at,
            })
            .collect())
    }

    /// All pending enrollment requests.
    #[graphql(guard = "Require::new(\"enrollment:read\")")]
    async fn pending_enrollments(&self, ctx: &Context<'_>) -> Result<Vec<ControlledNodeOutput>> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        let nodes = registry
            .list_nodes(Some(&principal.tenant_slug), Some(NodeStatus::Pending))
            .await?;
        Ok(nodes.into_iter().map(Into::into).collect())
    }

    /// List rules for a node, optionally filtered by interface and direction.
    #[graphql(guard = "Require::new(\"rule:read\")")]
    async fn rules(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: Option<String>,
        direction: Option<String>,
    ) -> Result<Vec<RuleOutput>> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let rules = if let (Some(iface), Some(dir)) = (&interface_name, &direction) {
            store.list_rules_for_interface(&node_id, iface, dir).await?
        } else {
            let mut rules = store.list_rules_for_node(&node_id).await?;
            if let Some(iface) = &interface_name {
                rules.retain(|r| r.interface_name.to_lowercase() == iface.to_lowercase());
            }
            if let Some(dir) = &direction {
                rules.retain(|r| r.direction.to_lowercase() == dir.to_lowercase());
            }
            rules
        };
        Ok(rules.into_iter().map(Into::into).collect())
    }

    /// List all interfaces discovered on a node.
    #[graphql(guard = "Require::new(\"interface:read\")")]
    async fn node_interfaces(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
    ) -> Result<Vec<NodeInterfaceOutput>> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let interfaces = store.list_node_interfaces(&node_id).await?;
        Ok(interfaces.into_iter().map(Into::into).collect())
    }

    /// List all interfaces across all nodes (used by fleet rule creator for interface selection).
    #[graphql(guard = "Require::new(\"interface:read\")")]
    async fn all_node_interfaces(&self, ctx: &Context<'_>) -> Result<Vec<NodeInterfaceOutput>> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        let interfaces = store
            .list_all_node_interfaces(Some(&principal.tenant_slug))
            .await?;
        Ok(interfaces.into_iter().map(Into::into).collect())
    }

    /// Audit log, newest first.
    #[graphql(guard = "Require::new(\"audit:read\")")]
    async fn audit_log(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<AuditEntryOutput>> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        let limit = limit.unwrap_or(50).clamp(1, 500) as u32;
        let offset = offset.unwrap_or(0).max(0) as u32;
        let entries = store
            .list_audit(Some(&principal.tenant_slug), limit, offset)
            .await?;
        Ok(entries.into_iter().map(Into::into).collect())
    }

    /// Export the audit log within an optional time window, formatted for download.
    ///
    /// `format` selects the output (`"csv"` or `"json"`). `from`/`to` are
    /// optional inclusive RFC 3339 timestamps; either may be omitted to leave
    /// that side of the window open. Results are tenant-scoped and capped at
    /// [`AUDIT_EXPORT_CAP`] rows.
    #[graphql(guard = "Require::new(\"audit:read\")")]
    async fn export_audit_log(
        &self,
        ctx: &Context<'_>,
        format: String,
        from: Option<String>,
        to: Option<String>,
    ) -> Result<AuditExportOutput> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        let exporter = crate::audit_export::exporter_for(&format)
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        let from = parse_opt_rfc3339_epoch(from.as_deref())?;
        let to = parse_opt_rfc3339_epoch(to.as_deref())?;
        let entries = store
            .list_audit_between(Some(&principal.tenant_slug), from, to, AUDIT_EXPORT_CAP)
            .await?;
        let data = exporter
            .export(&entries)
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(AuditExportOutput {
            filename: format!(
                "audit-export-{}.{}",
                Utc::now().format("%Y%m%dT%H%M%SZ"),
                exporter.extension()
            ),
            content_type: exporter.content_type().to_string(),
            data,
        })
    }

    /// Controller CA certificate in PEM format. Distribute to agents.
    #[graphql(guard = "Require::new(\"tenant:read\")")]
    async fn ca_cert_pem(&self, ctx: &Context<'_>) -> Result<String> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        Ok(registry.ca_cert_pem().await)
    }

    /// IDs of currently connected agent nodes (scoped to the caller's tenant).
    #[graphql(guard = "Require::new(\"node:read\")")]
    async fn online_nodes(&self, ctx: &Context<'_>) -> Result<Vec<String>> {
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        Ok(sessions.online_nodes(&principal.tenant_slug))
    }

    /// Fleet-wide dataplane counter rollup, summed across the most-recent
    /// metrics snapshot of every node in the caller's tenant. Counters are
    /// totals; clients derive per-second rates by sampling over time.
    #[graphql(guard = "Require::new(\"node:read\")")]
    async fn fleet_metrics(&self, ctx: &Context<'_>) -> Result<FleetMetricsOutput> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let metrics_store = ctx.data::<Arc<MetricsStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;

        let nodes = registry
            .list_nodes(Some(&principal.tenant_slug), None)
            .await?;

        let mut agg = FleetMetricsOutput {
            nodes_total: nodes.len() as i32,
            ..Default::default()
        };
        for node in &nodes {
            let Some(bytes) = metrics_store.get(&node.id) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            let sum = |m: &str| metrics_parser::sum_counter(&text, m);
            agg.nodes_reporting += 1;
            agg.rx_packets += sum("policy_engine_rx_packets_total");
            agg.rx_bytes += sum("policy_engine_rx_bytes_total");
            agg.tx_packets += sum("policy_engine_tx_packets_total");
            agg.tx_bytes += sum("policy_engine_tx_bytes_total");
            agg.policy_matches += sum("policy_engine_policy_matches_total");
            agg.policy_pass += sum("policy_engine_policy_pass_total");
            agg.policy_drops += sum("policy_engine_policy_drops_total");
            agg.policy_redirects += sum("policy_engine_policy_redirects_total");
            agg.verdict_pass_packets += sum("policy_engine_verdict_pass_packets_total");
            agg.verdict_pass_bytes += sum("policy_engine_verdict_pass_bytes_total");
            agg.verdict_drop_packets += sum("policy_engine_verdict_drop_packets_total");
            agg.verdict_drop_bytes += sum("policy_engine_verdict_drop_bytes_total");
            agg.parse_errors += sum("policy_engine_parse_errors_total");
            agg.fragments += sum("policy_engine_fragments_total");
            agg.inspect_redirects += sum("policy_engine_inspect_redirects_total");
        }
        Ok(agg)
    }

    /// The in-flight (unacknowledged) config generation for a node, if any.
    ///
    /// While non-null, further config mutations targeting this node will be
    /// rejected with `BLOCKED_PENDING_CONFIRM` until the generation resolves
    /// (commit, revert, or watchdog reap).
    #[graphql(guard = "Require::new(\"rule:read\")")]
    async fn pending_generation(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
    ) -> Result<Option<PendingGenerationOutput>> {
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        Ok(pending
            .get_for_node(&node_id, &principal.tenant_slug)
            .map(Into::into))
    }

    /// In-flight config generations across nodes in the caller's tenant.
    #[graphql(guard = "Require::new(\"rule:read\")")]
    async fn pending_generations(&self, ctx: &Context<'_>) -> Result<Vec<PendingGenerationOutput>> {
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        Ok(pending
            .list_all(&principal.tenant_slug)
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Per-rule packet/byte counters from the node's most-recent Prometheus
    /// metrics snapshot.  Returns `None` when no metrics have been received
    /// for the node yet.  The rule_id must match the controller-assigned ID
    /// (the same value returned by `createRule`).
    #[graphql(guard = "Require::new(\"node:read\")")]
    async fn node_rule_stats(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        rule_id: ID,
        direction: String,
    ) -> Result<Option<NodeRuleStatsOutput>> {
        validate_direction(&direction)?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let metrics_store = ctx.data::<Arc<MetricsStore>>()?;
        let text = match metrics_store.get(&node_id.0) {
            Some(b) => String::from_utf8_lossy(&b).into_owned(),
            None => return Ok(None),
        };
        let dir = direction.to_lowercase();
        let packets = metrics_parser::parse_counter(
            &text,
            "policy_engine_rule_packets_total",
            &[("rule_id", &rule_id.0), ("direction", &dir)],
        )
        .unwrap_or(0);
        let bytes = metrics_parser::parse_counter(
            &text,
            "policy_engine_rule_bytes_total",
            &[("rule_id", &rule_id.0), ("direction", &dir)],
        )
        .unwrap_or(0);
        Ok(Some(NodeRuleStatsOutput {
            rule_id: rule_id.0,
            direction,
            packets,
            bytes,
        }))
    }

    /// Per-interface traffic counters from the node's most-recent Prometheus
    /// metrics snapshot.  Returns `None` when no metrics have been received
    /// for the node yet.
    #[graphql(guard = "Require::new(\"node:read\")")]
    async fn node_interface_stats(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        direction: String,
    ) -> Result<Option<NodeInterfaceStatsOutput>> {
        validate_direction(&direction)?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let metrics_store = ctx.data::<Arc<MetricsStore>>()?;
        let text = match metrics_store.get(&node_id.0) {
            Some(b) => String::from_utf8_lossy(&b).into_owned(),
            None => return Ok(None),
        };
        let dir = direction.to_lowercase();
        let s = metrics_parser::parse_interface_stats(&text, &interface_name, &dir);
        Ok(Some(NodeInterfaceStatsOutput {
            interface: interface_name,
            direction,
            packets: s.rx_packets,
            bytes: s.rx_bytes,
            tx_packets: s.tx_packets,
            tx_bytes: s.tx_bytes,
            policy_matches: s.policy_matches,
            policy_drops: s.policy_drops,
            policy_pass: s.policy_pass,
            policy_redirects: s.policy_redirects,
            bum_packets: s.bum_packets,
            non_ip_unicast: s.non_ip_unicast,
            fragments: s.fragments,
            parse_errors: s.parse_errors,
            tail_calls: s.tail_calls,
            inspect_redirects: s.inspect_redirects,
            verdict_pass_packets: s.verdict_pass_packets,
            verdict_pass_bytes: s.verdict_pass_bytes,
            verdict_drop_packets: s.verdict_drop_packets,
            verdict_drop_bytes: s.verdict_drop_bytes,
            fib_forwarded_packets: s.fib_forwarded_packets,
            fib_forwarded_bytes: s.fib_forwarded_bytes,
            fib_fallback_packets: s.fib_fallback_packets,
        }))
    }

    /// Ethertype traffic breakdown from the node's most-recent Prometheus snapshot.
    /// Returns an empty list when no metrics have been received for the node yet.
    #[graphql(guard = "Require::new(\"node:read\")")]
    async fn node_ethertype_stats(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        direction: String,
    ) -> Result<Vec<NodeEthertypeStatOutput>> {
        validate_direction(&direction)?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let metrics_store = ctx.data::<Arc<MetricsStore>>()?;
        let text = match metrics_store.get(&node_id.0) {
            Some(b) => String::from_utf8_lossy(&b).into_owned(),
            None => return Ok(vec![]),
        };
        let dir = direction.to_lowercase();
        let entries = metrics_parser::parse_ethertype_stats(&text, &interface_name, &dir);
        Ok(entries
            .into_iter()
            .map(|e| NodeEthertypeStatOutput {
                ethertype: e.ethertype,
                name: e.ethertype_name,
                packets: e.packets,
            })
            .collect())
    }

    /// The authenticated caller's identity, permissions, and scope set.
    /// Unguarded by design — every authenticated principal can see itself.
    async fn me(&self, ctx: &Context<'_>) -> Result<crate::graphql::iam::MeOutput> {
        crate::graphql::iam::resolve_me(ctx).await
    }

    /// All operators in the deployment.
    #[graphql(guard = "Require::new(\"iam:read\")")]
    async fn operators(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<crate::graphql::iam::OperatorOutput>> {
        crate::graphql::iam::resolve_operators(ctx).await
    }

    #[graphql(guard = "Require::new(\"iam:read\")")]
    async fn operator(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<crate::graphql::iam::OperatorOutput>> {
        crate::graphql::iam::resolve_operator(ctx, id).await
    }

    /// Roles available in the caller's tenant, with their permission sets.
    #[graphql(guard = "Require::new(\"iam:read\")")]
    async fn roles(&self, ctx: &Context<'_>) -> Result<Vec<crate::graphql::iam::RoleOutput>> {
        crate::graphql::iam::resolve_roles(ctx).await
    }
}

// ── Mutation root ─────────────────────────────────────────────────────────────

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Approve a pending enrollment. Optionally sets a human-readable label.
    #[graphql(guard = "Require::new(\"enrollment:write\")")]
    async fn approve_enrollment(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        label: Option<String>,
    ) -> Result<ControlledNodeOutput> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let node = registry
            .approve_enrollment(&node_id, label, Some("operator"))
            .await?;
        Ok(node.into())
    }

    /// Reject a pending enrollment.
    #[graphql(guard = "Require::new(\"enrollment:write\")")]
    async fn reject_enrollment(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        reason: Option<String>,
    ) -> Result<OperationResult> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        match registry
            .reject_enrollment(&node_id, reason.as_deref(), Some("operator"))
            .await
        {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(format!("{:#}", e))),
        }
    }

    /// Decommission an active node (revokes cert, blocks reconnect).
    #[graphql(guard = "Require::new(\"node:delete\")")]
    async fn decommission_node(&self, ctx: &Context<'_>, node_id: ID) -> Result<OperationResult> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        match registry.decommission_node(&node_id, Some("operator")).await {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(format!("{:#}", e))),
        }
    }

    /// Remove a decommissioned node from the registry entirely.
    #[graphql(guard = "Require::new(\"node:delete\")")]
    async fn remove_node(&self, ctx: &Context<'_>, node_id: ID) -> Result<OperationResult> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        match registry.remove_node(&node_id, Some("operator")).await {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(format!("{:#}", e))),
        }
    }

    /// Set a human-readable label on a node.
    #[graphql(guard = "Require::new(\"node:write\")")]
    async fn label_node(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        label: String,
    ) -> Result<OperationResult> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        match registry
            .label_node(&node_id, &label, Some("operator"))
            .await
        {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(format!("{:#}", e))),
        }
    }

    /// Mint a new ZTP bootstrap token. The returned `bundle` is shown exactly
    /// once and must be distributed to nodes at provisioning time. The token
    /// secret cannot be retrieved afterwards — only revoked.
    ///
    /// `enrollmentUrl` and `controllerUrl` are embedded in the bundle so the
    /// agent does not need any pre-existing config beyond receiving the bundle.
    // Each parameter is a distinct GraphQL field argument, so they cannot be
    // bundled into a struct without changing the public schema.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "Require::new(\"enrollment:write\")")]
    async fn create_enrollment_token(
        &self,
        ctx: &Context<'_>,
        enrollment_url: String,
        controller_url: String,
        ttl_seconds: i64,
        max_uses: i64,
        cidr_scope: Option<String>,
        fleet_label: Option<String>,
    ) -> Result<IssuedEnrollmentToken> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        let issued = registry
            .mint_enrollment_token(
                enrollment_url,
                controller_url,
                chrono::Duration::seconds(ttl_seconds),
                max_uses,
                cidr_scope,
                fleet_label,
                Some("operator"),
                &principal.tenant_slug,
            )
            .await?;
        Ok(IssuedEnrollmentToken {
            token_id: ID(issued.token_id),
            bundle: issued.bundle,
            expires_at: issued.expires_at,
            uses_remaining: issued.uses_remaining,
        })
    }

    /// Revoke a previously-issued enrollment token. Returns true if the token
    /// existed and was not already revoked.
    #[graphql(guard = "Require::new(\"enrollment:delete\")")]
    async fn revoke_enrollment_token(
        &self,
        ctx: &Context<'_>,
        token_id: ID,
    ) -> Result<OperationResult> {
        let registry = ctx.data::<Arc<NodeRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        match registry
            .revoke_enrollment_token(&token_id, Some("operator"), &principal.tenant_slug)
            .await
        {
            Ok(true) => Ok(OperationResult::ok()),
            Ok(false) => Ok(OperationResult::err(
                "Token not found or already revoked".to_string(),
            )),
            Err(e) => Ok(OperationResult::err(format!("{:#}", e))),
        }
    }

    /// Set the stop behavior for a node ("clear-state" or "preserve-state").
    /// Pass null to clear the override and use the node's local default.
    #[graphql(guard = "Require::new(\"node:write\")")]
    async fn set_node_stop_behavior(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        behavior: Option<String>,
    ) -> Result<OperationResult> {
        let valid = matches!(
            behavior.as_deref(),
            None | Some("clear-state") | Some("preserve-state")
        );
        if !valid {
            return Ok(OperationResult::err(
                "behavior must be \"clear-state\", \"preserve-state\", or null".to_string(),
            ));
        }
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let behavior_str = behavior.unwrap_or_default();
        match drive_pending(
            PendingOp::SetStopBehavior {
                node_id: node_id.0.clone(),
                behavior: behavior_str,
            },
            pending,
            sessions,
            store,
        )
        .await
        {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(e.message)),
        }
    }

    /// Set how often the node's agent scrapes the local engine and forwards
    /// metrics to the controller, in seconds. Pass null to clear the override so
    /// the agent reverts to its local default.
    ///
    /// The value is persisted on the node and re-sent to the agent on every
    /// (re)connect, so it survives agent restarts. If the node is offline the
    /// value is still saved and applied when it next connects.
    #[graphql(guard = "Require::new(\"node:write\")")]
    async fn set_node_metrics_interval(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        seconds: Option<i32>,
    ) -> Result<OperationResult> {
        let secs: Option<u32> = match seconds {
            None => None,
            Some(s) if (METRICS_INTERVAL_MIN_SECS..=METRICS_INTERVAL_MAX_SECS).contains(&s) => {
                Some(s as u32)
            }
            Some(_) => {
                return Ok(OperationResult::err(format!(
                    "seconds must be between {} and {}",
                    METRICS_INTERVAL_MIN_SECS, METRICS_INTERVAL_MAX_SECS
                )))
            }
        };
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;

        // Persist first so the value survives reconnects (it is re-sent on
        // connect). Clearing the override pushes the agent default so a
        // connected node reverts immediately rather than only on restart.
        store.update_node_metrics_interval(&node_id.0, secs).await?;
        let interval_secs = secs.unwrap_or(METRICS_INTERVAL_DEFAULT_SECS);
        Ok(push_set_metrics_interval(sessions, &node_id.0, interval_secs).await)
    }

    /// Create the same rule on multiple nodes at once. Each node gets its own
    /// unique rule ID. Returns the list of all created rules.
    #[graphql(guard = "Require::new(\"rule:write\")")]
    async fn create_rules_multi_node(
        &self,
        ctx: &Context<'_>,
        input: CreateRuleMultiNodeInput,
    ) -> Result<Vec<RuleOutput>> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;

        validate_direction(&input.direction)?;
        if input.node_ids.is_empty() {
            return Err(async_graphql::Error::new("node_ids must not be empty"));
        }

        for node_id in &input.node_ids {
            ensure_node_in_tenant(store, node_id, &principal.tenant_slug).await?;
        }

        // Reject the whole batch if the rule's match criteria duplicate an
        // existing rule on ANY of the selected nodes — create nothing.
        let dir_lower = input.direction.to_lowercase();
        let candidate = Rule {
            id: String::new(),
            tenant_id: principal.tenant_slug.clone(),
            node_id: String::new(),
            interface_name: input.interface_name.clone(),
            direction: dir_lower.clone(),
            src_cidr: input.src_cidr.clone(),
            dst_cidr: input.dst_cidr.clone(),
            src_port: input.src_port,
            dst_port: input.dst_port,
            protocol: input.protocol.clone().unwrap_or_else(|| "any".to_string()),
            sni_pattern: input.sni_pattern.clone(),
            quic_version: input.quic_version.clone(),
            src_mac: input.src_mac.clone(),
            dst_mac: input.dst_mac.clone(),
            actions_json: String::new(),
            created_at: Utc::now(),
            created_by: None,
            expires_after_secs: None,
            schedule_json: None,
        };
        let mut conflicts: Vec<String> = Vec::new();
        for node_id in &input.node_ids {
            let existing = store
                .list_rules_for_interface(node_id, &input.interface_name, &dir_lower)
                .await?;
            if let Some(dup) = existing
                .iter()
                .find(|e| match_criteria_equal(e, &candidate))
            {
                conflicts.push(format!("{} (rule {})", node_id, dup.id));
            }
        }
        if !conflicts.is_empty() {
            return Err(async_graphql::Error::new(format!(
                "A rule with identical match criteria already exists on: {}",
                conflicts.join(", ")
            )));
        }

        let mut created = Vec::with_capacity(input.node_ids.len());
        for node_id in &input.node_ids {
            let rule = Rule {
                id: next_rule_id(),
                tenant_id: principal.tenant_slug.clone(),
                node_id: node_id.clone(),
                interface_name: input.interface_name.clone(),
                direction: input.direction.to_lowercase(),
                src_cidr: input.src_cidr.clone(),
                dst_cidr: input.dst_cidr.clone(),
                src_port: input.src_port,
                dst_port: input.dst_port,
                protocol: input.protocol.clone().unwrap_or_else(|| "any".to_string()),
                sni_pattern: input.sni_pattern.clone(),
                quic_version: input.quic_version.clone(),
                src_mac: input.src_mac.clone(),
                dst_mac: input.dst_mac.clone(),
                actions_json: input.actions_json.clone(),
                created_at: Utc::now(),
                created_by: Some(principal.actor.clone()),
                expires_after_secs: input.expires_after_secs,
                schedule_json: input.schedule_json.clone(),
            };

            // Drive per-node. On any node's failure we still attempt the rest —
            // each node's state is independent.
            drive_pending(
                PendingOp::CreateRule(Box::new(rule.clone())),
                pending,
                sessions,
                store,
            )
            .await?;

            if let Ok(bus) = ctx.data::<Arc<RuleLifecycleBus>>() {
                bus.publish(RuleLifecycleEvent {
                    event_type: "created".to_string(),
                    rule_id: rule.id.clone(),
                    node_id: rule.node_id.clone(),
                    interface_name: rule.interface_name.clone(),
                    direction: rule.direction.to_uppercase(),
                    timestamp_ms: now_ms(),
                    reason: None,
                });
            }

            created.push(rule);
        }

        Ok(created.into_iter().map(Into::into).collect())
    }

    /// Create a rule scoped to a specific (node, interface, direction).
    #[graphql(guard = "Require::new(\"rule:write\")")]
    async fn create_rule(&self, ctx: &Context<'_>, input: CreateRuleInput) -> Result<RuleOutput> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;

        validate_direction(&input.direction)?;
        ensure_node_in_tenant(store, &input.node_id, &principal.tenant_slug).await?;

        let rule = Rule {
            id: next_rule_id(),
            tenant_id: principal.tenant_slug.clone(),
            node_id: input.node_id.clone(),
            interface_name: input.interface_name,
            direction: input.direction.to_lowercase(),
            src_cidr: input.src_cidr,
            dst_cidr: input.dst_cidr,
            src_port: input.src_port,
            dst_port: input.dst_port,
            protocol: input.protocol.unwrap_or_else(|| "any".to_string()),
            sni_pattern: input.sni_pattern,
            quic_version: input.quic_version,
            src_mac: input.src_mac,
            dst_mac: input.dst_mac,
            actions_json: input.actions_json,
            created_at: Utc::now(),
            created_by: Some(principal.actor.clone()),
            expires_after_secs: input.expires_after_secs,
            schedule_json: input.schedule_json,
        };

        // Reject a rule whose match criteria duplicate an existing rule on the
        // same (node, interface, direction).
        let existing = store
            .list_rules_for_interface(&rule.node_id, &rule.interface_name, &rule.direction)
            .await?;
        if let Some(dup) = existing.iter().find(|e| match_criteria_equal(e, &rule)) {
            return Err(async_graphql::Error::new(format!(
                "A rule with identical match criteria already exists (rule {}) on {} {}/{}",
                dup.id, rule.node_id, rule.interface_name, rule.direction
            )));
        }

        drive_pending(
            PendingOp::CreateRule(Box::new(rule.clone())),
            pending,
            sessions,
            store,
        )
        .await?;

        if let Ok(bus) = ctx.data::<Arc<RuleLifecycleBus>>() {
            bus.publish(RuleLifecycleEvent {
                event_type: "created".to_string(),
                rule_id: rule.id.clone(),
                node_id: rule.node_id.clone(),
                interface_name: rule.interface_name.clone(),
                direction: rule.direction.to_uppercase(),
                timestamp_ms: now_ms(),
                reason: None,
            });
        }

        Ok(rule.into())
    }

    /// Delete a rule by ID.
    #[graphql(guard = "Require::new(\"rule:delete\")")]
    async fn delete_rule(&self, ctx: &Context<'_>, rule_id: ID) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;

        let rule = match store.get_rule(&rule_id).await? {
            // Tenant-mismatch must be indistinguishable from "no such rule" —
            // a cross-tenant rule_id guess must not surface the row's node_id.
            Some(r) if r.tenant_id == principal.tenant_slug => r,
            _ => {
                return Ok(OperationResult::err(format!(
                    "Rule not found: {}",
                    rule_id.0
                )))
            }
        };

        match drive_pending(
            PendingOp::DeleteRule {
                node_id: rule.node_id.clone(),
                rule_id: rule_id.0.clone(),
            },
            pending,
            sessions,
            store,
        )
        .await
        {
            Ok(()) => {
                if let Ok(bus) = ctx.data::<Arc<RuleLifecycleBus>>() {
                    bus.publish(RuleLifecycleEvent {
                        event_type: "deleted".to_string(),
                        rule_id: rule_id.0.clone(),
                        node_id: rule.node_id.clone(),
                        interface_name: rule.interface_name.clone(),
                        direction: rule.direction.to_uppercase(),
                        timestamp_ms: now_ms(),
                        reason: None,
                    });
                }
                Ok(OperationResult::ok())
            }
            Err(e) => Ok(OperationResult::err(e.message)),
        }
    }

    /// Flush every rule on a single (node, interface, direction).
    /// `direction` must be "ingress" or "egress" (case-insensitive).
    #[graphql(guard = "Require::new(\"rule:delete\")")]
    async fn flush_rules(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        direction: String,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;

        let dir_lower = direction.to_lowercase();
        if dir_lower != "ingress" && dir_lower != "egress" {
            return Ok(OperationResult::err(format!(
                "direction must be 'ingress' or 'egress', got {:?}",
                direction
            )));
        }

        let rules = store
            .list_rules_for_interface(&node_id, &interface_name, &dir_lower)
            .await?;
        if rules.is_empty() {
            return Ok(OperationResult::ok());
        }
        let rule_ids: Vec<String> = rules.iter().map(|r| r.id.clone()).collect();
        let count = rule_ids.len();

        match drive_pending(
            PendingOp::FlushRules {
                node_id: node_id.0.clone(),
                interface_name: interface_name.clone(),
                direction: dir_lower.clone(),
                rule_ids: rule_ids.clone(),
            },
            pending,
            sessions,
            store,
        )
        .await
        {
            Ok(()) => {
                if let Ok(bus) = ctx.data::<Arc<RuleLifecycleBus>>() {
                    for rid in &rule_ids {
                        bus.publish(RuleLifecycleEvent {
                            event_type: "deleted".to_string(),
                            rule_id: rid.clone(),
                            node_id: node_id.0.clone(),
                            interface_name: interface_name.clone(),
                            direction: dir_lower.to_uppercase(),
                            timestamp_ms: now_ms(),
                            reason: Some("flush".to_string()),
                        });
                    }
                }
                Ok(OperationResult {
                    success: true,
                    message: Some(format!("Flushed {} rule(s)", count)),
                })
            }
            Err(e) => Ok(OperationResult::err(e.message)),
        }
    }

    /// Tag an interface on a node (e.g., "WAN", "LAN").
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn tag_interface(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        tag: String,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        match store
            .set_interface_tag(&node_id, &interface_name, &tag)
            .await
        {
            Ok(()) => {
                store
                    .append_audit(NewAuditEntry {
                        operator: Some(principal.actor.clone()),
                        action: "interface_tagged".to_string(),
                        node_id: Some(node_id.0.clone()),
                        detail: Some(format!("iface={} tag={}", interface_name, tag)),
                        tenant_id: Some(principal.tenant_slug.clone()),
                    })
                    .await?;
                Ok(OperationResult::ok())
            }
            Err(e) => Ok(OperationResult::err(format!("{:#}", e))),
        }
    }

    /// Remove a tag from an interface.
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn untag_interface(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        match store.remove_interface_tag(&node_id, &interface_name).await {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(format!("{:#}", e))),
        }
    }

    /// Push the full desired config to a single online node.
    #[graphql(guard = "Require::new(\"node:write\")")]
    async fn push_config(&self, ctx: &Context<'_>, node_id: ID) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;

        if !sessions.is_online(&node_id.0) {
            return Ok(OperationResult::err(format!(
                "Node {} is not currently connected",
                node_id.0
            )));
        }

        let rules = store.list_rules_for_node(&node_id).await?;
        let rule_adds = reconciliation::rules_to_rule_adds(&rules);
        let defaults = {
            let mut map = std::collections::HashMap::new();
            if let Ok(ifaces) = store.list_node_interfaces(&node_id.0).await {
                for iface in ifaces {
                    if let Some(ref a) = iface.ingress_default_action {
                        map.insert(format!("{}:ingress", iface.name), a.clone());
                    }
                    if let Some(ref a) = iface.egress_default_action {
                        map.insert(format!("{}:egress", iface.name), a.clone());
                    }
                }
            }
            map
        };
        let stop_behavior = store
            .get_node(&node_id.0)
            .await
            .ok()
            .flatten()
            .and_then(|n| n.stop_behavior);
        let push = build_full_restore_push(rule_adds, defaults, stop_behavior);

        let msg = policy_controller_proto::controller::ControllerMessage {
            payload: Some(
                policy_controller_proto::controller::controller_message::Payload::Config(push),
            ),
        };

        if sessions.push(&node_id.0, msg).await {
            store
                .append_audit(NewAuditEntry {
                    operator: Some(principal.actor.clone()),
                    action: "config_pushed".to_string(),
                    node_id: Some(node_id.0.clone()),
                    detail: Some(format!("{} rules", rules.len())),
                    tenant_id: Some(principal.tenant_slug.clone()),
                })
                .await?;
            Ok(OperationResult::ok())
        } else {
            Ok(OperationResult::err(format!(
                "Failed to send config to node {} (disconnected?)",
                node_id.0
            )))
        }
    }

    /// Attach a BPF program to an interface on a node.
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn attach_program(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        direction: String,
        _mode: Option<String>,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;

        let direction_norm = direction.to_lowercase();
        if direction_norm != "ingress" && direction_norm != "egress" {
            return Ok(OperationResult::err(format!(
                "Invalid direction: {}",
                direction
            )));
        }

        match drive_pending(
            PendingOp::Attach {
                node_id: node_id.0.clone(),
                interface_name,
                direction: direction_norm,
            },
            pending,
            sessions,
            store,
        )
        .await
        {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(e.message)),
        }
    }

    /// Enable or disable XDP FIB forwarding on a single ingress interface of a node.
    /// Enabling bypasses the kernel stack for transit packets, which also bypasses
    /// any TC egress filtering on the outbound interface.
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn set_fib_forwarding(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        enabled: bool,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;

        match drive_pending(
            PendingOp::SetFibForwarding {
                node_id: node_id.0.clone(),
                interface_name,
                enabled,
            },
            pending,
            sessions,
            store,
        )
        .await
        {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(e.message)),
        }
    }

    /// Record a client-initiated audit entry (e.g. events exported).
    #[graphql(guard = "Require::new(\"audit:write\")")]
    async fn log_audit_entry(
        &self,
        ctx: &Context<'_>,
        node_id: Option<ID>,
        action: String,
        detail: Option<String>,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        store
            .append_audit(NewAuditEntry {
                operator: Some(principal.actor.clone()),
                action,
                node_id: node_id.map(|id| id.0),
                detail,
                tenant_id: Some(principal.tenant_slug.clone()),
            })
            .await?;
        Ok(OperationResult::ok())
    }

    /// Detach a BPF program from an interface on a node.
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn detach_program(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        direction: String,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;

        let direction_norm = direction.to_lowercase();
        if direction_norm != "ingress" && direction_norm != "egress" {
            return Ok(OperationResult::err(format!(
                "Invalid direction: {}",
                direction
            )));
        }

        match drive_pending(
            PendingOp::Detach {
                node_id: node_id.0.clone(),
                interface_name,
                direction: direction_norm,
            },
            pending,
            sessions,
            store,
        )
        .await
        {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(e.message)),
        }
    }

    /// Set the default action for unmatched packets on a specific interface+direction of a node.
    /// `direction` must be "ingress" or "egress". `action` must be "pass" or "drop".
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn set_interface_default_action(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        direction: String,
        action: String,
    ) -> Result<OperationResult> {
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let pending = ctx.data::<Arc<PendingRegistry>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;

        let direction_norm = direction.to_lowercase();
        if direction_norm != "ingress" && direction_norm != "egress" {
            return Ok(OperationResult::err(format!(
                "Invalid direction: {}",
                direction
            )));
        }
        let action_norm = action.to_lowercase();
        if action_norm != "pass" && action_norm != "drop" {
            return Ok(OperationResult::err(format!("Invalid action: {}", action)));
        }

        match drive_pending(
            PendingOp::SetDefaultAction {
                node_id: node_id.0.clone(),
                interface_name,
                direction: direction_norm,
                action: action_norm,
            },
            pending,
            sessions,
            store,
        )
        .await
        {
            Ok(()) => Ok(OperationResult::ok()),
            Err(e) => Ok(OperationResult::err(e.message)),
        }
    }

    /// Trigger an immediate metrics push from the specified node.
    ///
    /// The controller sends a `MetricsQuery` message to the connected agent,
    /// which wakes its metrics forwarder and pushes a fresh `MetricsUpdate`
    /// without waiting for the next scheduled interval.  Returns an error if
    /// the node is not currently connected.
    #[graphql(guard = "Require::new(\"node:write\")")]
    async fn refresh_node_metrics(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
    ) -> Result<OperationResult> {
        use policy_controller_proto::controller::{
            controller_message::Payload as CtrlPayload, ControllerMessage, MetricsQuery,
        };

        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        let sent = sessions
            .push(
                &node_id.0,
                ControllerMessage {
                    payload: Some(CtrlPayload::MetricsQuery(MetricsQuery {})),
                },
            )
            .await;

        if sent {
            Ok(OperationResult::ok())
        } else {
            Ok(OperationResult::err(format!(
                "Node '{}' is not currently connected",
                node_id.0
            )))
        }
    }

    /// Clear all statistics (global + ethertype) for a single interface on a node.
    ///
    /// `direction` is "ingress"/"egress"; pass null to clear both. Fire-and-forget:
    /// stats live only in the engine's BPF maps, so nothing is committed to the
    /// controller store. Returns ok once the request is delivered to a connected
    /// agent — the UI re-queries stats to confirm they are zeroed.
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn clear_interface_stats(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        interface_name: String,
        direction: Option<String>,
    ) -> Result<OperationResult> {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        push_clear_stats(
            sessions,
            &node_id.0,
            ClearStats {
                scope: Scope::Interface as i32,
                interface_name,
                rule_id: String::new(),
                direction: direction.unwrap_or_default(),
            },
        )
        .await
    }

    /// Clear interface statistics for every attached interface on a node.
    #[graphql(guard = "Require::new(\"interface:write\")")]
    async fn clear_all_interface_stats(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
    ) -> Result<OperationResult> {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        push_clear_stats(
            sessions,
            &node_id.0,
            ClearStats {
                scope: Scope::AllInterfaces as i32,
                interface_name: String::new(),
                rule_id: String::new(),
                direction: String::new(),
            },
        )
        .await
    }

    /// Clear statistics for a single policy rule on a node.
    ///
    /// `ruleId` is the controller-assigned rule ID (which the engine also uses
    /// as its per-rule stats key). `direction` is "ingress"/"egress"; pass null
    /// to clear both. Fire-and-forget, same as the interface clears.
    #[graphql(guard = "Require::new(\"rule:write\")")]
    async fn clear_rule_stats(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        rule_id: ID,
        direction: Option<String>,
    ) -> Result<OperationResult> {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        push_clear_stats(
            sessions,
            &node_id.0,
            ClearStats {
                scope: Scope::Rule as i32,
                interface_name: String::new(),
                rule_id: rule_id.0,
                direction: direction.unwrap_or_default(),
            },
        )
        .await
    }

    /// Clear statistics for every policy rule on a node (both directions).
    #[graphql(guard = "Require::new(\"rule:write\")")]
    async fn clear_all_policy_stats(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
    ) -> Result<OperationResult> {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        push_clear_stats(
            sessions,
            &node_id.0,
            ClearStats {
                scope: Scope::AllRules as i32,
                interface_name: String::new(),
                rule_id: String::new(),
                direction: String::new(),
            },
        )
        .await
    }

    /// Clear ALL statistics on a node — every interface counter and every rule
    /// counter, in one shot.
    #[graphql(guard = "Require::new(\"node:write\")")]
    async fn clear_all_stats(&self, ctx: &Context<'_>, node_id: ID) -> Result<OperationResult> {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        let store = ctx.data::<Arc<dyn ControllerStore>>()?;
        let principal = ctx.data::<Arc<crate::rbac::Principal>>()?;
        ensure_node_in_tenant(store, &node_id, &principal.tenant_slug).await?;
        let sessions = ctx.data::<Arc<NodeSessionManager>>()?;
        push_clear_stats(
            sessions,
            &node_id.0,
            ClearStats {
                scope: Scope::All as i32,
                interface_name: String::new(),
                rule_id: String::new(),
                direction: String::new(),
            },
        )
        .await
    }

    // ── Alert pipeline (step 4) ──────────────────────────────────────────

    #[graphql(guard = "Require::new(\"alert:write\")")]
    async fn create_alert_rule(
        &self,
        ctx: &Context<'_>,
        input: CreateAlertRuleInput,
    ) -> Result<AlertRuleOutput> {
        resolve_create_alert_rule(ctx, input).await
    }

    #[graphql(guard = "Require::new(\"alert:write\")")]
    async fn update_alert_rule(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: CreateAlertRuleInput,
    ) -> Result<AlertRuleOutput> {
        resolve_update_alert_rule(ctx, id, input).await
    }

    #[graphql(guard = "Require::new(\"alert:delete\")")]
    async fn delete_alert_rule(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        resolve_delete_alert_rule(ctx, id).await
    }

    #[graphql(guard = "Require::new(\"alert:write\")")]
    async fn create_receiver(
        &self,
        ctx: &Context<'_>,
        input: CreateReceiverInput,
    ) -> Result<ReceiverOutput> {
        resolve_create_receiver(ctx, input).await
    }

    #[graphql(guard = "Require::new(\"alert:write\")")]
    async fn update_receiver(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: CreateReceiverInput,
    ) -> Result<ReceiverOutput> {
        resolve_update_receiver(ctx, id, input).await
    }

    #[graphql(guard = "Require::new(\"alert:delete\")")]
    async fn delete_receiver(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        resolve_delete_receiver(ctx, id).await
    }

    #[graphql(guard = "Require::new(\"alert:write\")")]
    async fn create_silence(
        &self,
        ctx: &Context<'_>,
        input: CreateSilenceInput,
    ) -> Result<SilenceOutput> {
        resolve_create_silence(ctx, input).await
    }

    #[graphql(guard = "Require::new(\"alert:delete\")")]
    async fn delete_silence(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        resolve_delete_silence(ctx, id).await
    }

    /// Mint a new API bearer token. The returned `plaintext` is shown once
    /// and must be captured by the caller — it is never persisted and cannot
    /// be retrieved afterwards. Only the operator-facing label, expiry, and
    /// usage metadata are queryable from then on.
    #[graphql(guard = "Require::new(\"token:write\")")]
    async fn create_api_token(
        &self,
        ctx: &Context<'_>,
        name: String,
        expires_at: Option<DateTime<Utc>>,
        #[graphql(default_with = "Vec::new()")] role_ids: Vec<ID>,
    ) -> Result<ApiTokenWithSecret> {
        resolve_create_api_token(ctx, name, expires_at, role_ids).await
    }

    /// Revoke an existing API bearer token. Subsequent authentication
    /// attempts with the corresponding plaintext are rejected.
    #[graphql(guard = "Require::new(\"token:delete\")")]
    async fn revoke_api_token(&self, ctx: &Context<'_>, id: ID) -> Result<ApiTokenOutput> {
        resolve_revoke_api_token(ctx, id).await
    }

    // ── IAM ──────────────────────────────────────────────────────────────

    #[graphql(guard = "Require::new(\"iam:write\")")]
    async fn create_operator(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: String,
        #[graphql(default_with = "Vec::new()")] role_ids: Vec<ID>,
    ) -> Result<crate::graphql::iam::OperatorOutput> {
        crate::graphql::iam::resolve_create_operator(ctx, username, password, role_ids).await
    }

    #[graphql(guard = "Require::new(\"iam:write\")")]
    async fn disable_operator(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<crate::graphql::iam::OperatorOutput> {
        crate::graphql::iam::resolve_disable_operator(ctx, id).await
    }

    #[graphql(guard = "Require::new(\"iam:write\")")]
    async fn enable_operator(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<crate::graphql::iam::OperatorOutput> {
        crate::graphql::iam::resolve_enable_operator(ctx, id).await
    }

    #[graphql(guard = "Require::new(\"iam:write\")")]
    async fn set_operator_password(
        &self,
        ctx: &Context<'_>,
        id: ID,
        new_password: String,
    ) -> Result<bool> {
        crate::graphql::iam::resolve_set_operator_password(ctx, id, new_password).await
    }

    #[graphql(guard = "Require::new(\"iam:write\")")]
    async fn grant_role(
        &self,
        ctx: &Context<'_>,
        operator_id: ID,
        role_id: ID,
    ) -> Result<crate::graphql::iam::OperatorOutput> {
        crate::graphql::iam::resolve_grant_role(ctx, operator_id, role_id).await
    }

    #[graphql(guard = "Require::new(\"iam:delete\")")]
    async fn revoke_role(
        &self,
        ctx: &Context<'_>,
        operator_id: ID,
        role_id: ID,
    ) -> Result<crate::graphql::iam::OperatorOutput> {
        crate::graphql::iam::resolve_revoke_role(ctx, operator_id, role_id).await
    }

    #[graphql(guard = "Require::new(\"iam:write\")")]
    async fn set_token_roles(
        &self,
        ctx: &Context<'_>,
        token_id: ID,
        role_ids: Vec<ID>,
    ) -> Result<ApiTokenOutput> {
        crate::graphql::iam::resolve_set_token_roles(ctx, token_id, role_ids).await
    }

    #[graphql(guard = "Require::new(\"iam:write\")")]
    async fn set_token_scopes(
        &self,
        ctx: &Context<'_>,
        token_id: ID,
        scopes: Vec<crate::graphql::iam::TokenScopeInput>,
    ) -> Result<ApiTokenOutput> {
        crate::graphql::iam::resolve_set_token_scopes(ctx, token_id, scopes).await
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// After a rule create/delete, push a full restore to the node if it's online.
/// Error returned by [`drive_pending`] — either the node was blocked by another
/// in-flight generation, or the confirm round-trip failed. Callers can convert
/// `.message` directly into a GraphQL error string.
pub struct DriveError {
    pub message: String,
}

impl From<BeginError> for DriveError {
    fn from(e: BeginError) -> Self {
        DriveError {
            message: format!("BLOCKED_PENDING_CONFIRM: {}", e),
        }
    }
}

impl From<DriveError> for async_graphql::Error {
    fn from(e: DriveError) -> Self {
        async_graphql::Error::new(e.message)
    }
}

/// Load `node_id` and confirm it belongs to `tenant_slug`. On mismatch (or
/// missing row) returns a "Node not found" GraphQL error — deliberately
/// indistinguishable from an unknown node so that a tenant A operator
/// cannot probe for the existence of tenant B node ids.
async fn ensure_node_in_tenant(
    store: &Arc<dyn ControllerStore>,
    node_id: &str,
    tenant_slug: &str,
) -> Result<NodeRecord> {
    match store.get_node(node_id).await? {
        Some(node) if node.tenant_id == tenant_slug => Ok(node),
        _ => Err(async_graphql::Error::new(format!(
            "Node not found: {}",
            node_id
        ))),
    }
}

/// Bounds for the operator-configurable metrics scrape interval (seconds).
const METRICS_INTERVAL_MIN_SECS: i32 = 1;
const METRICS_INTERVAL_MAX_SECS: i32 = 3600;
/// Mirrors the agent's compiled default (`config::default_metrics_interval_secs`).
/// Pushed when an operator clears the per-node override so a connected agent
/// reverts to the default cadence immediately rather than only on restart.
const METRICS_INTERVAL_DEFAULT_SECS: u32 = 5;

/// Push a [`SetMetricsInterval`] to a node. The value is already persisted by
/// the caller, so an offline node still picks it up on its next connect — hence
/// a successful result either way, with a note when delivery was deferred.
async fn push_set_metrics_interval(
    sessions: &Arc<NodeSessionManager>,
    node_id: &str,
    interval_secs: u32,
) -> OperationResult {
    use policy_controller_proto::controller::{
        controller_message::Payload as CtrlPayload, ControllerMessage, SetMetricsInterval,
    };
    let sent = sessions
        .push(
            node_id,
            ControllerMessage {
                payload: Some(CtrlPayload::SetMetricsInterval(SetMetricsInterval {
                    interval_secs,
                })),
            },
        )
        .await;
    if sent {
        OperationResult::ok()
    } else {
        OperationResult {
            success: true,
            message: Some("Saved; will apply when the node reconnects".to_string()),
        }
    }
}

/// Push a fire-and-forget [`ClearStats`] request to a node.
///
/// Stats live only in the engine's BPF maps — never the controller store — so
/// unlike config changes this bypasses the pending-generation/confirm machinery
/// (mirroring `refresh_node_metrics`). We deliver the message and report only
/// whether the node was connected; the operator observes the result by
/// re-querying stats.
async fn push_clear_stats(
    sessions: &Arc<NodeSessionManager>,
    node_id: &str,
    req: policy_controller_proto::controller::ClearStats,
) -> Result<OperationResult> {
    use policy_controller_proto::controller::{
        controller_message::Payload as CtrlPayload, ControllerMessage,
    };
    let sent = sessions
        .push(
            node_id,
            ControllerMessage {
                payload: Some(CtrlPayload::ClearStats(req)),
            },
        )
        .await;
    if sent {
        Ok(OperationResult::ok())
    } else {
        Ok(OperationResult::err(format!(
            "Node '{}' is not currently connected",
            node_id
        )))
    }
}

/// Gate → push → await agent confirm → commit to store.
/// Returns Ok(()) only when the agent applied AND the controller committed.
async fn drive_pending(
    op: PendingOp,
    pending: &Arc<PendingRegistry>,
    sessions: &Arc<NodeSessionManager>,
    store: &Arc<dyn ControllerStore>,
) -> std::result::Result<(), DriveError> {
    let outcome =
        apply_pending_op(op, pending, sessions, store, DEFAULT_CONFIRM_DEADLINE_MS).await?;
    match outcome {
        ConfirmOutcome::Applied => Ok(()),
        ConfirmOutcome::CommitFailed(e) => Err(DriveError {
            message: format!("Commit failed after agent applied: {}", e),
        }),
        ConfirmOutcome::Rejected(e) => Err(DriveError {
            message: format!("Agent rejected config: {}", e),
        }),
        ConfirmOutcome::Reverted(e) => Err(DriveError {
            message: format!("Agent reverted config: {}", e),
        }),
        ConfirmOutcome::Abandoned => Err(DriveError {
            message: "Agent did not confirm within the deadline — change abandoned".to_string(),
        }),
    }
}

// ── Schema builder ──────────────────────────────────────────────────────────

pub type ControllerSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
pub fn build_schema(
    registry: Arc<NodeRegistry>,
    store: Arc<dyn ControllerStore>,
    sessions: Arc<NodeSessionManager>,
    pending: Arc<PendingRegistry>,
    metrics_store: Arc<MetricsStore>,
    rule_lifecycle_bus: Arc<RuleLifecycleBus>,
    tenant_scope: Arc<TenantScope>,
    alert_rule_bus: Arc<AlertRuleBus>,
    api_token_store: Arc<ApiTokenStore>,
    operator_store: Arc<crate::operators::OperatorStore>,
    rbac_store: Arc<crate::rbac::RbacStore>,
    service_endpoints: ServiceEndpoints,
) -> ControllerSchema {
    #[allow(unused_mut)]
    let mut builder = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(registry)
        .data(store)
        .data(sessions)
        .data(pending)
        .data(metrics_store)
        .data(rule_lifecycle_bus)
        .data(tenant_scope)
        .data(alert_rule_bus)
        .data(api_token_store)
        .data(operator_store)
        .data(rbac_store)
        .data(service_endpoints);
    // Under `cargo test`, attach a wildcard-admin Principal at schema level
    // so unit tests don't all need to inject one per-request. Production
    // builds compile the lib in non-test mode and never see this branch;
    // the bearer_auth middleware injects the real per-request Principal,
    // which (per async-graphql data resolution) overrides schema-level
    // data of the same type.
    #[cfg(test)]
    {
        use std::sync::Arc;
        builder = builder.data(Arc::new(crate::rbac::Principal::test_admin()));
    }
    builder.finish()
}

fn parse_status(s: Option<&str>) -> Result<Option<NodeStatus>> {
    match s {
        None => Ok(None),
        Some("pending") => Ok(Some(NodeStatus::Pending)),
        Some("active") => Ok(Some(NodeStatus::Active)),
        Some("decommissioned") => Ok(Some(NodeStatus::Decommissioned)),
        Some(other) => Err(async_graphql::Error::new(format!(
            "Unknown node status: {}",
            other
        ))),
    }
}

fn validate_direction(direction: &str) -> Result<()> {
    match direction.to_lowercase().as_str() {
        "ingress" | "egress" => Ok(()),
        other => Err(async_graphql::Error::new(format!(
            "Invalid direction '{}': must be 'ingress' or 'egress'",
            other
        ))),
    }
}

// ── Duplicate match-criteria detection ─────────────────────────────────────────
//
// Two rules on the same (node, interface, direction) must not share identical
// match criteria — they would collide in the engine's data plane. The `id`,
// `actions`, and lifecycle (TTL / schedule) fields are NOT part of the match
// criteria and are excluded from the comparison. Normalization mirrors the
// engine's semantics so that semantically-equal inputs compare equal.

/// Canonicalize a CIDR for comparison: parse and re-emit `network/prefix` so
/// `10.0.0.1/8` and `10.0.0.0/8` compare equal (matching the engine, which
/// stores the network address). `None`/empty maps to the `*` ("any") sentinel.
fn norm_cidr(c: &Option<String>) -> String {
    match c {
        Some(s) if !s.trim().is_empty() => match s.trim().parse::<ipnetwork::IpNetwork>() {
            Ok(net) => format!("{}/{}", net.network(), net.prefix()),
            Err(_) => s.trim().to_lowercase(),
        },
        _ => "*".to_string(),
    }
}

/// A `None` or `Some(0)` port both mean "any".
fn norm_port(p: Option<u32>) -> u32 {
    p.unwrap_or(0)
}

/// Empty/whitespace protocol means "any"; comparison is case-insensitive.
fn norm_proto(p: &str) -> String {
    let t = p.trim().to_lowercase();
    if t.is_empty() {
        "any".to_string()
    } else {
        t
    }
}

/// Trim + lowercase an optional string, treating empty as absent.
fn norm_opt(s: &Option<String>) -> Option<String> {
    s.as_ref()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
}

/// True when two rules would match identical traffic (ignoring id, actions, and
/// lifecycle). Callers compare rules already scoped to the same node, interface,
/// and direction, so those fields are not re-checked here.
fn match_criteria_equal(a: &Rule, b: &Rule) -> bool {
    norm_cidr(&a.src_cidr) == norm_cidr(&b.src_cidr)
        && norm_cidr(&a.dst_cidr) == norm_cidr(&b.dst_cidr)
        && norm_port(a.src_port) == norm_port(b.src_port)
        && norm_port(a.dst_port) == norm_port(b.dst_port)
        && norm_proto(&a.protocol) == norm_proto(&b.protocol)
        && norm_opt(&a.sni_pattern) == norm_opt(&b.sni_pattern)
        && norm_opt(&a.quic_version) == norm_opt(&b.quic_version)
        && norm_opt(&a.src_mac) == norm_opt(&b.src_mac)
        && norm_opt(&a.dst_mac) == norm_opt(&b.dst_mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        node_registry::NodeRegistry,
        security::{ca::IssuedCert, MockCertificateAuthority},
        session::NodeSessionManager,
        store::memory::InMemoryControllerStore,
    };

    struct TestHarness {
        schema: ControllerSchema,
        store: Arc<dyn ControllerStore>,
        sessions: Arc<NodeSessionManager>,
        pending: Arc<PendingRegistry>,
        metrics_store: Arc<MetricsStore>,
    }

    async fn make_harness() -> TestHarness {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca
            .expect_ca_cert_pem()
            .returning(|| "CA-CERT".to_string());
        mock_ca.expect_issue_node_cert().returning(|_, _| {
            Ok(IssuedCert {
                cert_pem: "CERT".to_string(),
                key_pem: "KEY".to_string(),
                serial: vec![0xab, 0xcd],
            })
        });
        let registry = Arc::new(NodeRegistry::new(Arc::clone(&store), Arc::new(mock_ca)));
        let sessions = Arc::new(NodeSessionManager::new());
        let pending = Arc::new(PendingRegistry::new());
        let metrics_store = Arc::new(MetricsStore::new());
        // Tests don't exercise the event-pipeline queries, but build_schema
        // requires the scope; hand it a throw-away in-memory pool.
        let (tenant_scope, api_token_store, operator_store, rbac_store) = {
            let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:")
                .await
                .unwrap();
            sqlx::migrate!("./migrations").run(&pool).await.unwrap();
            let scope = Arc::new(
                crate::event_pipeline::bootstrap_default_tenant(pool.clone())
                    .await
                    .unwrap(),
            );
            let tokens = Arc::new(ApiTokenStore::new(pool.clone()));
            let ops = Arc::new(crate::operators::OperatorStore::new(pool.clone()));
            let rbac = Arc::new(crate::rbac::RbacStore::new(pool));
            (scope, tokens, ops, rbac)
        };
        let schema = build_schema(
            Arc::clone(&registry),
            Arc::clone(&store),
            Arc::clone(&sessions),
            Arc::clone(&pending),
            Arc::clone(&metrics_store),
            Arc::new(crate::rule_lifecycle_bus::RuleLifecycleBus::new()),
            tenant_scope,
            Arc::new(AlertRuleBus::new()),
            api_token_store,
            operator_store,
            rbac_store,
            ServiceEndpoints {
                controller_url: String::new(),
                enrollment_url: String::new(),
            },
        );
        TestHarness {
            schema,
            store,
            sessions,
            pending,
            metrics_store,
        }
    }

    async fn make_schema() -> ControllerSchema {
        make_harness().await.schema
    }

    /// Upsert a minimal active node in the default tenant. Required by the
    /// node-tenant guard in node-targeted mutations.
    async fn insert_default_tenant_node(store: &Arc<dyn ControllerStore>, node_id: &str) {
        let _ = store
            .upsert_node(&crate::store::NodeRecord {
                id: node_id.to_string(),
                label: None,
                public_key_der: vec![],
                dmi_uuid: None,
                status: crate::store::NodeStatus::Active,
                cert_serial: None,
                cert_expiry: None,
                last_seen: None,
                enrolled_at: None,
                decommissioned_at: None,
                last_renewed_at: None,
                enrollment_id: Some(format!("e-{node_id}")),
                tpm_backed: false,
                agent_version: None,
                hostname: None,
                os_pretty_name: None,
                kernel_version: None,
                dmi_sys_vendor: None,
                dmi_product_name: None,
                tenant_id: "default".to_string(),
                stop_behavior: None,
                metrics_interval_secs: None,
                capabilities: "{}".to_string(),
            })
            .await;
    }

    /// Register a fake online agent for `node_id` that auto-confirms any pushed
    /// config with outcome=APPLIED, so mutations complete synchronously in tests.
    async fn register_auto_confirming_agent(h: &TestHarness, node_id: &str) {
        use policy_controller_proto::controller::controller_message::Payload as P;
        use tokio::sync::mpsc;

        // Upsert a stub node so `apply_pending_op`'s tenant lookup
        // succeeds — production parity with the gRPC handler, which
        // verifies the node row exists in the store before registering
        // the session.
        insert_default_tenant_node(&h.store, node_id).await;

        let (tx, mut rx) = mpsc::channel(16);
        h.sessions
            .register(node_id.to_string(), "default".to_string(), tx);
        let pending = Arc::clone(&h.pending);
        let store = Arc::clone(&h.store);
        tokio::spawn(async move {
            while let Some(Ok(msg)) = rx.recv().await {
                let gen_id = match msg.payload {
                    Some(P::Config(c)) => Some(c.generation_id),
                    Some(P::Attach(a)) => Some(a.generation_id),
                    Some(P::Detach(d)) => Some(d.generation_id),
                    Some(P::SetFib(f)) => Some(f.generation_id),
                    _ => None,
                };
                if let Some(gen_id) = gen_id.filter(|g| !g.is_empty()) {
                    if let Some(pending_gen) = pending.take(&gen_id) {
                        let op = pending_gen.op.clone();
                        let _ = op.commit(&store).await;
                        pending_gen.notify(ConfirmOutcome::Applied);
                    }
                }
            }
        });
    }

    #[tokio::test]
    async fn test_ca_cert_pem_query() {
        let schema = make_schema().await;
        let res = schema.execute("{ caCertPem }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["caCertPem"], "CA-CERT");
    }

    #[tokio::test]
    async fn test_nodes_empty() {
        let schema = make_schema().await;
        let res = schema.execute("{ nodes { id status } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["nodes"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_fleet_metrics_empty() {
        let schema = make_schema().await;
        let res = schema
            .execute("{ fleetMetrics { nodesReporting nodesTotal policyDrops rxPackets } }")
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["fleetMetrics"]["nodesReporting"], 0);
        assert_eq!(data["fleetMetrics"]["nodesTotal"], 0);
        assert_eq!(data["fleetMetrics"]["policyDrops"], 0);
    }

    #[tokio::test]
    async fn test_fleet_metrics_aggregates_across_nodes() {
        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "node-a").await;
        insert_default_tenant_node(&h.store, "node-b").await;
        // node-c has a row but never reported metrics — counts toward total
        // but not toward nodesReporting.
        insert_default_tenant_node(&h.store, "node-c").await;

        // Two interfaces on node-a; drops must sum across labels and nodes.
        h.metrics_store.update(
            "node-a",
            1,
            concat!(
                "policy_engine_policy_drops_total{interface=\"eth0\",direction=\"ingress\"} 10\n",
                "policy_engine_policy_drops_total{interface=\"eth1\",direction=\"egress\"} 5\n",
                "policy_engine_rx_packets_total{interface=\"eth0\",direction=\"ingress\"} 1000\n",
            )
            .as_bytes()
            .to_vec(),
            None,
        );
        h.metrics_store.update(
            "node-b",
            1,
            concat!(
                "policy_engine_policy_drops_total{interface=\"eth0\",direction=\"ingress\"} 7\n",
                "policy_engine_rx_packets_total{interface=\"eth0\",direction=\"ingress\"} 200\n",
            )
            .as_bytes()
            .to_vec(),
            None,
        );

        let res = h
            .schema
            .execute("{ fleetMetrics { nodesReporting nodesTotal policyDrops rxPackets } }")
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let fm = &res.data.into_json().unwrap()["fleetMetrics"];
        assert_eq!(fm["nodesReporting"], 2);
        assert_eq!(fm["nodesTotal"], 3);
        assert_eq!(fm["policyDrops"], 10 + 5 + 7);
        assert_eq!(fm["rxPackets"], 1000 + 200);
    }

    #[tokio::test]
    async fn test_create_and_query_rule() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "node-1").await;
        let schema = &h.schema;
        let res = schema
            .execute(
                r#"mutation {
                    createRule(input: {
                        nodeId: "node-1"
                        interfaceName: "eth0"
                        direction: "ingress"
                        srcCidr: "10.0.0.0/8"
                        dstPort: 80
                        protocol: "tcp"
                        actionsJson: "[{\"action\":\"drop\",\"priority\":0}]"
                    }) {
                        id nodeId interfaceName direction srcCidr dstPort protocol createdBy
                    }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["createRule"]["nodeId"], "node-1");
        assert_eq!(data["createRule"]["interfaceName"], "eth0");
        assert_eq!(data["createRule"]["direction"], "ingress");
        // created_by records the authenticated principal, not a placeholder.
        assert_eq!(data["createRule"]["createdBy"], "operator:test-admin");

        // Query rules for node
        let res2 = schema
            .execute(r#"{ rules(nodeId: "node-1") { id direction srcCidr } }"#)
            .await;
        assert!(res2.errors.is_empty(), "{:?}", res2.errors);
        let data2 = res2.data.into_json().unwrap();
        let rules = data2["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["srcCidr"], "10.0.0.0/8");
    }

    #[tokio::test]
    async fn test_delete_rule() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "n1").await;
        let schema = &h.schema;

        // Create
        let res = schema
            .execute(
                r#"mutation {
                    createRule(input: {
                        nodeId: "n1"
                        interfaceName: "eth0"
                        direction: "egress"
                        actionsJson: "[{\"action\":\"pass\",\"priority\":0}]"
                    }) { id }
                }"#,
            )
            .await;
        let data = res.data.into_json().unwrap();
        let rule_id = data["createRule"]["id"].as_str().unwrap();

        // Delete
        let res2 = schema
            .execute(&format!(
                r#"mutation {{ deleteRule(ruleId: "{}") {{ success }} }}"#,
                rule_id
            ))
            .await;
        assert!(res2.errors.is_empty(), "{:?}", res2.errors);
        let data2 = res2.data.into_json().unwrap();
        assert!(data2["deleteRule"]["success"].as_bool().unwrap());

        // Verify gone
        let res3 = schema.execute(r#"{ rules(nodeId: "n1") { id } }"#).await;
        let data3 = res3.data.into_json().unwrap();
        assert!(data3["rules"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_clear_interface_stats_offline_node_reports_disconnected() {
        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let res = h
            .schema
            .execute(
                r#"mutation { clearInterfaceStats(nodeId: "n1", interfaceName: "eth0") { success message } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["clearInterfaceStats"]["success"], false);
        assert!(data["clearInterfaceStats"]["message"]
            .as_str()
            .unwrap()
            .contains("not currently connected"));
    }

    #[tokio::test]
    async fn test_clear_interface_stats_pushes_clear_stats_message() {
        use policy_controller_proto::controller::{
            clear_stats::Scope, controller_message::Payload as P,
        };
        use tokio::sync::mpsc;

        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let (tx, mut rx) = mpsc::channel(4);
        h.sessions
            .register("n1".to_string(), "default".to_string(), tx);

        let res = h
            .schema
            .execute(
                r#"mutation { clearInterfaceStats(nodeId: "n1", interfaceName: "eth0", direction: "ingress") { success } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert!(
            res.data.into_json().unwrap()["clearInterfaceStats"]["success"]
                .as_bool()
                .unwrap()
        );

        let msg = rx.recv().await.expect("a message").expect("ok message");
        match msg.payload {
            Some(P::ClearStats(c)) => {
                assert_eq!(c.scope, Scope::Interface as i32);
                assert_eq!(c.interface_name, "eth0");
                assert_eq!(c.direction, "ingress");
            }
            other => panic!("expected ClearStats, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_clear_all_interface_stats_pushes_all_interfaces_scope() {
        use policy_controller_proto::controller::{
            clear_stats::Scope, controller_message::Payload as P,
        };
        use tokio::sync::mpsc;

        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let (tx, mut rx) = mpsc::channel(4);
        h.sessions
            .register("n1".to_string(), "default".to_string(), tx);

        let res = h
            .schema
            .execute(r#"mutation { clearAllInterfaceStats(nodeId: "n1") { success } }"#)
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        let msg = rx.recv().await.expect("a message").expect("ok message");
        match msg.payload {
            Some(P::ClearStats(c)) => assert_eq!(c.scope, Scope::AllInterfaces as i32),
            other => panic!("expected ClearStats, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_clear_rule_stats_pushes_rule_scope() {
        use policy_controller_proto::controller::{
            clear_stats::Scope, controller_message::Payload as P,
        };
        use tokio::sync::mpsc;

        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let (tx, mut rx) = mpsc::channel(4);
        h.sessions
            .register("n1".to_string(), "default".to_string(), tx);

        let res = h
            .schema
            .execute(r#"mutation { clearRuleStats(nodeId: "n1", ruleId: "42") { success } }"#)
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        let msg = rx.recv().await.expect("a message").expect("ok message");
        match msg.payload {
            Some(P::ClearStats(c)) => {
                assert_eq!(c.scope, Scope::Rule as i32);
                assert_eq!(c.rule_id, "42");
            }
            other => panic!("expected ClearStats, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_set_node_metrics_interval_persists_and_pushes() {
        use policy_controller_proto::controller::controller_message::Payload as P;
        use tokio::sync::mpsc;

        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let (tx, mut rx) = mpsc::channel(4);
        h.sessions
            .register("n1".to_string(), "default".to_string(), tx);

        let res = h
            .schema
            .execute(
                r#"mutation { setNodeMetricsInterval(nodeId: "n1", seconds: 10) { success } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert!(
            res.data.into_json().unwrap()["setNodeMetricsInterval"]["success"]
                .as_bool()
                .unwrap()
        );

        // Persisted to the store…
        let node = h.store.get_node("n1").await.unwrap().unwrap();
        assert_eq!(node.metrics_interval_secs, Some(10));

        // …and pushed live to the connected agent.
        let msg = rx.recv().await.expect("a message").expect("ok message");
        match msg.payload {
            Some(P::SetMetricsInterval(s)) => assert_eq!(s.interval_secs, 10),
            other => panic!("expected SetMetricsInterval, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_set_node_metrics_interval_clear_pushes_default() {
        use policy_controller_proto::controller::controller_message::Payload as P;
        use tokio::sync::mpsc;

        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        h.store
            .update_node_metrics_interval("n1", Some(10))
            .await
            .unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        h.sessions
            .register("n1".to_string(), "default".to_string(), tx);

        let res = h
            .schema
            .execute(
                r#"mutation { setNodeMetricsInterval(nodeId: "n1", seconds: null) { success } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // Override cleared in the store…
        let node = h.store.get_node("n1").await.unwrap().unwrap();
        assert_eq!(node.metrics_interval_secs, None);

        // …and the agent is told to revert to the default cadence.
        let msg = rx.recv().await.expect("a message").expect("ok message");
        match msg.payload {
            Some(P::SetMetricsInterval(s)) => {
                assert_eq!(s.interval_secs, METRICS_INTERVAL_DEFAULT_SECS)
            }
            other => panic!("expected SetMetricsInterval, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_set_node_metrics_interval_rejects_out_of_range() {
        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let res = h
            .schema
            .execute(r#"mutation { setNodeMetricsInterval(nodeId: "n1", seconds: 0) { success message } }"#)
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["setNodeMetricsInterval"]["success"], false);
        // Out-of-range must not have been persisted.
        let node = h.store.get_node("n1").await.unwrap().unwrap();
        assert_eq!(node.metrics_interval_secs, None);
    }

    #[tokio::test]
    async fn test_clear_all_stats_pushes_all_scope() {
        use policy_controller_proto::controller::{
            clear_stats::Scope, controller_message::Payload as P,
        };
        use tokio::sync::mpsc;

        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let (tx, mut rx) = mpsc::channel(4);
        h.sessions
            .register("n1".to_string(), "default".to_string(), tx);

        let res = h
            .schema
            .execute(r#"mutation { clearAllStats(nodeId: "n1") { success } }"#)
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        let msg = rx.recv().await.expect("a message").expect("ok message");
        match msg.payload {
            Some(P::ClearStats(c)) => assert_eq!(c.scope, Scope::All as i32),
            other => panic!("expected ClearStats, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_direction_rejected() {
        let schema = make_schema().await;
        let res = schema
            .execute(
                r#"mutation {
                    createRule(input: {
                        nodeId: "n1"
                        interfaceName: "eth0"
                        direction: "sideways"
                        actionsJson: "[]"
                    }) { id }
                }"#,
            )
            .await;
        assert!(!res.errors.is_empty(), "Should fail with invalid direction");
    }

    #[tokio::test]
    async fn test_audit_log_populated_on_rule_create() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "n1").await;
        let schema = &h.schema;
        schema
            .execute(
                r#"mutation {
                    createRule(input: {
                        nodeId: "n1"
                        interfaceName: "eth0"
                        direction: "ingress"
                        actionsJson: "[]"
                    }) { id }
                }"#,
            )
            .await;

        let res = schema.execute("{ auditLog { action } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let actions: Vec<&str> = data["auditLog"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap())
            .collect();
        assert!(
            actions.contains(&"config_applied"),
            "audit should record successful config apply; got {:?}",
            actions
        );
    }

    #[tokio::test]
    async fn test_create_rules_multi_node() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "node-a").await;
        register_auto_confirming_agent(&h, "node-b").await;
        register_auto_confirming_agent(&h, "node-c").await;
        let schema = &h.schema;

        let res = schema
            .execute(
                r#"mutation {
                    createRulesMultiNode(input: {
                        nodeIds: ["node-a", "node-b", "node-c"]
                        interfaceName: "eth0"
                        direction: "ingress"
                        srcCidr: "10.0.0.0/8"
                        dstPort: 443
                        protocol: "tcp"
                        actionsJson: "[{\"action\":\"pass\",\"priority\":0}]"
                    }) {
                        id nodeId interfaceName direction
                    }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let rules = data["createRulesMultiNode"].as_array().unwrap();
        assert_eq!(rules.len(), 3);

        // Each rule should have a different ID and different node_id
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        let node_ids: Vec<&str> = rules
            .iter()
            .map(|r| r["nodeId"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 3);
        assert!(
            ids[0] != ids[1] && ids[1] != ids[2],
            "Rule IDs must be unique"
        );
        assert!(node_ids.contains(&"node-a"));
        assert!(node_ids.contains(&"node-b"));
        assert!(node_ids.contains(&"node-c"));

        // Verify rules for each node
        let res2 = schema
            .execute(r#"{ rules(nodeId: "node-a") { id } }"#)
            .await;
        assert!(res2.errors.is_empty());
        let data2 = res2.data.into_json().unwrap();
        assert_eq!(data2["rules"].as_array().unwrap().len(), 1);

        let res3 = schema
            .execute(r#"{ rules(nodeId: "node-b") { id } }"#)
            .await;
        assert!(res3.errors.is_empty());
        let data3 = res3.data.into_json().unwrap();
        assert_eq!(data3["rules"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_create_rules_multi_node_empty_ids_rejected() {
        let schema = make_schema().await;
        let res = schema
            .execute(
                r#"mutation {
                    createRulesMultiNode(input: {
                        nodeIds: []
                        interfaceName: "eth0"
                        direction: "ingress"
                        actionsJson: "[]"
                    }) { id }
                }"#,
            )
            .await;
        assert!(!res.errors.is_empty(), "Should reject empty node_ids");
    }

    #[tokio::test]
    async fn test_create_rule_duplicate_rejected() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "node-1").await;
        let schema = &h.schema;

        let create = r#"mutation {
            createRule(input: {
                nodeId: "node-1"
                interfaceName: "eth0"
                direction: "ingress"
                srcCidr: "10.0.0.0/8"
                dstPort: 80
                protocol: "tcp"
                actionsJson: "[{\"action\":\"drop\",\"priority\":0}]"
            }) { id }
        }"#;

        let res = schema.execute(create).await;
        assert!(res.errors.is_empty(), "first create: {:?}", res.errors);

        // Identical match criteria (different actions) must be rejected.
        let dup = r#"mutation {
            createRule(input: {
                nodeId: "node-1"
                interfaceName: "eth0"
                direction: "ingress"
                srcCidr: "10.0.0.0/8"
                dstPort: 80
                protocol: "tcp"
                actionsJson: "[{\"action\":\"pass\",\"priority\":0}]"
            }) { id }
        }"#;
        let res2 = schema.execute(dup).await;
        assert!(!res2.errors.is_empty(), "duplicate should be rejected");
        assert!(res2.errors[0].message.contains("identical match criteria"));

        // Still only one rule installed.
        let res3 = schema
            .execute(r#"{ rules(nodeId: "node-1") { id } }"#)
            .await;
        let data3 = res3.data.into_json().unwrap();
        assert_eq!(data3["rules"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_create_rule_different_criteria_allowed() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "node-1").await;
        let schema = &h.schema;

        let res = schema
            .execute(
                r#"mutation {
                    createRule(input: {
                        nodeId: "node-1"
                        interfaceName: "eth0"
                        direction: "ingress"
                        srcCidr: "10.0.0.0/8"
                        dstPort: 80
                        protocol: "tcp"
                        actionsJson: "[{\"action\":\"drop\",\"priority\":0}]"
                    }) { id }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // Different destination port → not a duplicate.
        let res2 = schema
            .execute(
                r#"mutation {
                    createRule(input: {
                        nodeId: "node-1"
                        interfaceName: "eth0"
                        direction: "ingress"
                        srcCidr: "10.0.0.0/8"
                        dstPort: 443
                        protocol: "tcp"
                        actionsJson: "[{\"action\":\"drop\",\"priority\":0}]"
                    }) { id }
                }"#,
            )
            .await;
        assert!(res2.errors.is_empty(), "{:?}", res2.errors);

        let res3 = schema
            .execute(r#"{ rules(nodeId: "node-1") { id } }"#)
            .await;
        let data3 = res3.data.into_json().unwrap();
        assert_eq!(data3["rules"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_create_rules_multi_node_duplicate_fails_wholesale() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "node-a").await;
        register_auto_confirming_agent(&h, "node-b").await;
        let schema = &h.schema;

        // Pre-create the rule on node-b only.
        let res = schema
            .execute(
                r#"mutation {
                    createRule(input: {
                        nodeId: "node-b"
                        interfaceName: "eth0"
                        direction: "ingress"
                        srcCidr: "10.0.0.0/8"
                        dstPort: 80
                        protocol: "tcp"
                        actionsJson: "[{\"action\":\"drop\",\"priority\":0}]"
                    }) { id }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // Multi-node create over [node-a, node-b]: node-b conflicts, so the
        // whole batch must fail and node-a must get nothing.
        let res2 = schema
            .execute(
                r#"mutation {
                    createRulesMultiNode(input: {
                        nodeIds: ["node-a", "node-b"]
                        interfaceName: "eth0"
                        direction: "ingress"
                        srcCidr: "10.0.0.0/8"
                        dstPort: 80
                        protocol: "tcp"
                        actionsJson: "[{\"action\":\"pass\",\"priority\":0}]"
                    }) { id }
                }"#,
            )
            .await;
        assert!(!res2.errors.is_empty(), "batch should be rejected");
        assert!(res2.errors[0].message.contains("node-b"));

        // node-a must have no rule (nothing created).
        let res3 = schema
            .execute(r#"{ rules(nodeId: "node-a") { id } }"#)
            .await;
        let data3 = res3.data.into_json().unwrap();
        assert!(data3["rules"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_online_nodes_empty() {
        let schema = make_schema().await;
        let res = schema.execute("{ onlineNodes }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["onlineNodes"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_push_config_offline_node_returns_error() {
        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "no-such-node").await;
        let schema = &h.schema;
        let res = schema
            .execute(r#"mutation { pushConfig(nodeId: "no-such-node") { success message } }"#)
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert!(!data["pushConfig"]["success"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_set_interface_default_action() {
        let h = make_harness().await;
        register_auto_confirming_agent(&h, "n1").await;
        let schema = &h.schema;

        let res = schema
            .execute(
                r#"mutation {
                    setInterfaceDefaultAction(
                        nodeId: "n1"
                        interfaceName: "eth0"
                        direction: "ingress"
                        action: "drop"
                    ) { success message }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert!(data["setInterfaceDefaultAction"]["success"]
            .as_bool()
            .unwrap());
    }

    #[tokio::test]
    async fn test_set_interface_default_action_invalid_direction() {
        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let schema = &h.schema;
        let res = schema
            .execute(
                r#"mutation {
                    setInterfaceDefaultAction(
                        nodeId: "n1"
                        interfaceName: "eth0"
                        direction: "sideways"
                        action: "drop"
                    ) { success message }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert!(!data["setInterfaceDefaultAction"]["success"]
            .as_bool()
            .unwrap());
    }

    /// Build a minimal Permission-bearing principal for guard tests. The
    /// default `make_schema` attaches a wildcard-admin Principal at schema
    /// level (see `build_schema`'s cfg(test) branch); per-request data
    /// overrides it, so injecting a viewer here proves the guard is wired.
    fn principal_with(perms: &[&str]) -> Arc<crate::rbac::Principal> {
        use crate::rbac::Permission;
        use std::collections::HashSet;
        // Build via JSON so we exercise the same parser the DB uses.
        let mut p_set = HashSet::new();
        for p in perms {
            p_set.insert(Permission::parse(p).unwrap());
        }
        // Construct a Principal directly via a small test-only helper.
        Arc::new(crate::rbac::Principal::from_test_parts(p_set))
    }

    #[tokio::test]
    async fn guard_blocks_when_principal_lacks_permission() {
        let schema = make_schema().await;
        let req =
            async_graphql::Request::new("{ nodes { id } }").data(principal_with(&["event:read"])); // no node:read
        let res = schema.execute(req).await;
        assert!(
            res.errors.iter().any(|e| e.message.contains("forbidden")),
            "expected forbidden error, got {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn guard_allows_when_principal_has_permission() {
        let schema = make_schema().await;
        let req =
            async_graphql::Request::new("{ nodes { id } }").data(principal_with(&["node:read"]));
        let res = schema.execute(req).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn guard_wildcard_permission_satisfies_everything() {
        let schema = make_schema().await;
        let req = async_graphql::Request::new("{ nodes { id } }").data(principal_with(&["*:*"]));
        let res = schema.execute(req).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn test_set_interface_default_action_invalid_action() {
        let h = make_harness().await;
        insert_default_tenant_node(&h.store, "n1").await;
        let schema = &h.schema;
        let res = schema
            .execute(
                r#"mutation {
                    setInterfaceDefaultAction(
                        nodeId: "n1"
                        interfaceName: "eth0"
                        direction: "ingress"
                        action: "banana"
                    ) { success message }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert!(!data["setInterfaceDefaultAction"]["success"]
            .as_bool()
            .unwrap());
    }
}
