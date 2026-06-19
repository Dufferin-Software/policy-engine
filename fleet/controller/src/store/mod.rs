// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use policy_controller_proto::controller::{AddressReport, InterfaceReport};
use serde::{Deserialize, Serialize};
pub mod memory;
pub mod sqlite;

pub use memory::InMemoryControllerStore;
pub use sqlite::SqliteControllerStore;

/// Convert protobuf `AddressReport` list to a JSON string for storage.
pub fn address_reports_to_json(addresses: &[AddressReport]) -> String {
    let arr: Vec<serde_json::Value> = addresses
        .iter()
        .map(|a| {
            serde_json::json!({
                "address": a.address,
                "prefix_len": a.prefix_len,
                "family": a.family,
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

// ── Core domain types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    /// Enrollment request submitted, awaiting admin approval.
    Pending,
    /// Approved, enrolled, and actively managed.
    Active,
    /// Decommissioned — cert revoked, rejected on next connect.
    Decommissioned,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Pending => write!(f, "pending"),
            NodeStatus::Active => write!(f, "active"),
            NodeStatus::Decommissioned => write!(f, "decommissioned"),
        }
    }
}

/// Persistent record for a managed node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    /// hex(SHA-256(SPKI DER)) — never changes for a given key.
    pub id: String,
    /// Human-readable label set by the operator.
    pub label: Option<String>,
    /// DER-encoded SPKI public key bytes.
    pub public_key_der: Vec<u8>,
    /// DMI system UUID, for display only.
    pub dmi_uuid: Option<String>,
    pub status: NodeStatus,
    /// DER-encoded serial number of the issued mTLS client cert.
    pub cert_serial: Option<Vec<u8>>,
    pub cert_expiry: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub decommissioned_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent successful `RenewClientCert`. `None` until
    /// the first renewal — distinguishable from "never renewed" by inspecting
    /// `cert_serial != initial-issued serial` if needed, but the timestamp is
    /// the field operators actually want surfaced in the UI.
    pub last_renewed_at: Option<DateTime<Utc>>,
    /// UUID of the pending enrollment request (present while status == Pending).
    pub enrollment_id: Option<String>,
    /// Whether the node reported a TPM-backed key.
    pub tpm_backed: bool,
    /// Agent version string reported during enrollment.
    pub agent_version: Option<String>,
    /// OS hostname reported by the agent, for display only.
    pub hostname: Option<String>,
    /// OS pretty name, e.g. "Debian GNU/Linux 13 (trixie)".
    pub os_pretty_name: Option<String>,
    /// Kernel version, e.g. "6.12.74+deb13+1-amd64".
    pub kernel_version: Option<String>,
    /// DMI sys_vendor, e.g. "Dell Inc.".
    pub dmi_sys_vendor: Option<String>,
    /// DMI product_name, e.g. "PowerEdge R340".
    pub dmi_product_name: Option<String>,
    /// Tenant for multi-tenancy support.
    pub tenant_id: String,
    /// Operator-configured stop behavior for this node ("clear-state" or "preserve-state").
    /// None means the controller has not set a preference (node uses its local default).
    pub stop_behavior: Option<String>,
    /// Operator-configured metrics scrape/forward interval in seconds.
    /// None means the controller has not set a preference (agent uses its local default).
    pub metrics_interval_secs: Option<u32>,
    /// JSON-encoded `Capabilities` from the most recent AgentHello. `"{}"`
    /// until the agent reconnects after step-6 was deployed (pre-step-6
    /// rows surface the same default).
    pub capabilities: String,
}

/// A policy rule scoped to a specific (tenant, node, interface, direction).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Timestamp-based numeric ID (stored as string for ergonomics).
    pub id: String,
    /// Tenant identifier for multi-tenancy.
    pub tenant_id: String,
    /// Node this rule belongs to.
    pub node_id: String,
    /// Network interface this rule applies to.
    pub interface_name: String,
    /// "ingress" or "egress".
    pub direction: String,
    /// Source CIDR (e.g. "10.0.0.0/8"), None = any.
    pub src_cidr: Option<String>,
    /// Destination CIDR, None = any.
    pub dst_cidr: Option<String>,
    /// Source port (0 = any).
    pub src_port: Option<u32>,
    /// Destination port (0 = any).
    pub dst_port: Option<u32>,
    /// Protocol: "tcp", "udp", "icmp", "icmpv6", "any".
    pub protocol: String,
    /// TLS SNI pattern (exact or "*.suffix").
    pub sni_pattern: Option<String>,
    /// QUIC version filter ("v1", "v2", "any").
    pub quic_version: Option<String>,
    /// Source MAC address.
    pub src_mac: Option<String>,
    /// Destination MAC address.
    pub dst_mac: Option<String>,
    /// Actions as JSON array: [{"action":"drop","priority":0}].
    pub actions_json: String,
    pub created_at: DateTime<Utc>,
    /// Operator who created this rule.
    pub created_by: Option<String>,
    /// Positive integer: remove rule after this many seconds. Mutually exclusive with schedule_json.
    pub expires_after_secs: Option<u32>,
    /// JSON-serialized schedule object with `timezone` and `windows` fields. Mutually exclusive with expires_after_secs.
    pub schedule_json: Option<String>,
}

/// A network interface discovered on a node, with optional operator-assigned tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInterface {
    pub node_id: String,
    pub name: String,
    /// Linux interface index. 0 if unknown (older agent or report omitted it).
    #[serde(default)]
    pub ifindex: u32,
    pub mac_address: Option<String>,
    pub link_state: String,
    /// JSON array of {address, prefix_len, family}.
    pub addresses_json: String,
    /// Operator-assigned tag (e.g. "WAN", "LAN").
    pub tag: Option<String>,
    pub last_reported: DateTime<Utc>,
    /// XDP ingress program attached to this interface.
    pub xdp_attached: bool,
    /// TC egress program attached to this interface.
    pub tc_attached: bool,
    /// Whether XDP FIB forwarding is enabled on this interface (ingress only).
    #[serde(default)]
    pub fib_forwarding: bool,
    /// Controller-set default action for unmatched ingress packets ("pass" or "drop").
    #[serde(default)]
    pub ingress_default_action: Option<String>,
    /// Controller-set default action for unmatched egress packets ("pass" or "drop").
    #[serde(default)]
    pub egress_default_action: Option<String>,
}

/// A ZTP enrollment token. Operators mint these via the GraphQL API; the
/// returned [`EnrollmentBundle`] is distributed to agents at provisioning time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTokenRecord {
    /// UUID identifying this token. Also embedded in the bundle.
    pub token_id: String,
    /// SHA-256 of the random token secret.
    pub token_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub uses_remaining: i64,
    pub cidr_scope: Option<String>,
    pub fleet_label: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// Tenant the token was minted under (slug, e.g. `"default"`). Inherited
    /// from the principal at mint time. `list_enrollment_tokens` filters on
    /// this so cross-tenant visibility is impossible from the GraphQL surface.
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
}

fn default_tenant() -> String {
    "default".to_string()
}

/// Outcome of attempting to redeem a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRedeemOutcome {
    /// Redemption succeeded. `fleet_label` was applied to the node if set;
    /// `tenant_id` is the slug the token was minted under, used by the
    /// enrollment path to route the new node into the correct tenant
    /// (rather than the `'default'` it was born into during the Pending
    /// submission step).
    Redeemed {
        fleet_label: Option<String>,
        tenant_id: String,
    },
    /// Token does not exist.
    Unknown,
    /// Token hash did not match.
    BadSecret,
    /// Token has expired.
    Expired,
    /// Token has been revoked.
    Revoked,
    /// Token has been used up.
    Exhausted,
}

/// Outcome counts from [`ControllerStore::replace_rules_for_node`].
///
/// Rule identity is the `id` column. A rule with the same `id` whose content
/// matches an existing row is counted as `unchanged`; a same-`id` rule whose
/// content differs is counted as `updated`. Rules present only in the new set
/// are `added`; rules present only in the existing set are `deleted`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
}

impl DiffSummary {
    /// True when nothing changed (no inserts, updates, or deletes).
    pub fn is_noop(&self) -> bool {
        self.added == 0 && self.updated == 0 && self.deleted == 0
    }
}

/// Compare two stored [`Rule`]s for content equality, ignoring identity
/// fields (`id`, `node_id`, `tenant_id`) and audit metadata
/// (`created_at`, `created_by`).
///
/// Action arrays are compared as parsed JSON so that key ordering inside
/// each action object does not cause spurious mismatches; the order of the
/// outer array is significant (it mirrors how the policy engine stores it).
pub fn rule_content_equal(a: &Rule, b: &Rule) -> bool {
    if a.interface_name != b.interface_name
        || a.direction != b.direction
        || a.src_cidr != b.src_cidr
        || a.dst_cidr != b.dst_cidr
        || a.src_port != b.src_port
        || a.dst_port != b.dst_port
        || a.protocol != b.protocol
        || a.sni_pattern != b.sni_pattern
        || a.quic_version != b.quic_version
        || a.src_mac != b.src_mac
        || a.dst_mac != b.dst_mac
        || a.expires_after_secs != b.expires_after_secs
        || a.schedule_json != b.schedule_json
    {
        return false;
    }
    let av: serde_json::Value =
        serde_json::from_str(&a.actions_json).unwrap_or(serde_json::Value::Null);
    let bv: serde_json::Value =
        serde_json::from_str(&b.actions_json).unwrap_or(serde_json::Value::Null);
    av == bv
}

/// An audit log entry recording operator actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub operator: Option<String>,
    pub action: String,
    pub node_id: Option<String>,
    pub detail: Option<String>,
    /// Tenant slug as resolved by `append_audit` (explicit > node lookup >
    /// `"default"`). Not currently surfaced on the GraphQL output type, since
    /// readers are already tenant-scoped, but stored for completeness and to
    /// keep the in-memory and sqlite implementations symmetric.
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// Persistent store for controller state.
///
/// All methods are `async` and return `Result` so that either the SQLite
/// implementation or an in-memory mock can be used transparently.
#[async_trait]
pub trait ControllerStore: Send + Sync {
    // ── Nodes ──
    async fn upsert_node(&self, node: &NodeRecord) -> Result<()>;
    async fn get_node(&self, id: &str) -> Result<Option<NodeRecord>>;
    async fn get_node_by_enrollment_id(&self, enrollment_id: &str) -> Result<Option<NodeRecord>>;
    /// `tenant_id`: `Some(slug)` restricts to one tenant; `None` is
    /// cross-tenant and is reserved for the controller's own background
    /// jobs (TTL reaper, controller-metrics). Operator-facing surfaces
    /// pass `Some(principal.tenant_slug)` so the result can't leak rows
    /// from other tenants.
    async fn list_nodes(
        &self,
        tenant_id: Option<&str>,
        status: Option<NodeStatus>,
    ) -> Result<Vec<NodeRecord>>;
    async fn update_node_status(&self, id: &str, status: NodeStatus) -> Result<()>;
    /// Re-bind a node to a tenant. Used by the enrollment path to move a
    /// freshly-submitted node (born in `'default'`) into the tenant carried
    /// on the bootstrap token, once that token has been successfully
    /// redeemed.
    async fn update_node_tenant(&self, id: &str, tenant_id: &str) -> Result<()>;
    /// Permanently delete a node record (use only after decommission).
    async fn delete_node(&self, id: &str) -> Result<()>;
    async fn update_node_last_seen(&self, id: &str, ts: DateTime<Utc>) -> Result<()>;
    /// Update live fields reported in AgentHello on each management connect.
    #[allow(clippy::too_many_arguments)]
    async fn update_node_agent_info(
        &self,
        id: &str,
        tpm_backed: bool,
        agent_version: Option<&str>,
        hostname: Option<&str>,
        os_pretty_name: Option<&str>,
        kernel_version: Option<&str>,
        dmi_sys_vendor: Option<&str>,
        dmi_product_name: Option<&str>,
        dmi_uuid: Option<&str>,
    ) -> Result<()>;
    /// Persist the JSON-encoded Capabilities blob from the most recent
    /// AgentHello. Stored opaquely as a string so adding a new capability
    /// field to the proto doesn't need a schema change.
    async fn update_node_capabilities(&self, id: &str, capabilities_json: &str) -> Result<()>;
    /// Union of `sources` advertised across all Active nodes in the tenant.
    /// Used by alert-rule write-time validation to reject rules referencing
    /// sources no node can produce. Returns an empty set when the fleet is
    /// empty so bootstrap (creating rules before enrolling the first agent)
    /// still works; the validator skips the check in that case.
    async fn list_active_node_sources(
        &self,
        tenant_id: &str,
    ) -> Result<std::collections::HashSet<String>>;
    async fn update_node_cert(
        &self,
        id: &str,
        serial: Vec<u8>,
        expiry: DateTime<Utc>,
        cert_pem: String,
    ) -> Result<()>;

    /// Update only the `cert_serial`/`cert_expiry` columns — the cert PEM
    /// blob in `node_certs` is intentionally left untouched.
    ///
    /// Used by [`NodeRegistry::renew_cert`] because the renewed private key
    /// stays on the agent; if we overwrote `node_certs` with just the new
    /// cert we'd corrupt the "key+cert" blob that
    /// `check_enrollment_status` is permitted to hand to a re-enrolling
    /// agent. The renewed cert is delivered to the agent over the
    /// `RenewClientCert` RPC response, never via `get_node_cert_pem`.
    async fn update_current_cert_meta(
        &self,
        id: &str,
        serial: Vec<u8>,
        expiry: DateTime<Utc>,
    ) -> Result<()>;

    /// Set the desired stop behavior for a node ("clear-state" or "preserve-state").
    async fn update_node_stop_behavior(&self, id: &str, behavior: Option<&str>) -> Result<()>;

    /// Set the desired metrics scrape/forward interval (seconds) for a node.
    /// `None` clears the override so the agent falls back to its local default.
    async fn update_node_metrics_interval(&self, id: &str, secs: Option<u32>) -> Result<()>;

    // ── Cert revocation ──
    async fn revoke_cert(&self, serial: &[u8]) -> Result<()>;
    async fn is_cert_revoked(&self, serial: &[u8]) -> Result<bool>;
    /// Snapshot the full set of revoked serials. Used at startup to seed the
    /// in-memory revocation mirror consulted by the TLS-handshake verifier.
    async fn list_revoked_serials(&self) -> Result<Vec<Vec<u8>>>;

    // ── Rules (per-node, per-interface, per-direction) ──
    async fn create_rule(&self, rule: &Rule) -> Result<()>;
    async fn delete_rule(&self, rule_id: &str) -> Result<()>;
    async fn get_rule(&self, rule_id: &str) -> Result<Option<Rule>>;
    async fn list_rules_for_node(&self, node_id: &str) -> Result<Vec<Rule>>;
    async fn list_rules_for_interface(
        &self,
        node_id: &str,
        interface_name: &str,
        direction: &str,
    ) -> Result<Vec<Rule>>;
    async fn delete_rules_for_node(&self, node_id: &str) -> Result<()>;

    /// Atomically replace the set of rules for a node with `new_rules`.
    ///
    /// All rules in `new_rules` must have `node_id` equal to the `node_id`
    /// argument; mixing nodes is a programming error and returns `Err`.
    ///
    /// On commit the node's rule table matches `new_rules` exactly. Existing
    /// rows with an `id` not present in `new_rules` are deleted; rows whose
    /// `id` is present and whose content differs are overwritten; rows whose
    /// `id` is present and content matches (per [`rule_content_equal`]) are
    /// left untouched. The returned [`DiffSummary`] reports the counts.
    ///
    /// SQLite implementation runs the whole operation in a single
    /// transaction so a write-back cannot leave a half-applied rule table.
    async fn replace_rules_for_node(
        &self,
        node_id: &str,
        new_rules: &[Rule],
    ) -> Result<DiffSummary>;

    // ── Node interfaces ──
    /// `tenant_id` follows the same `None` = cross-tenant convention as
    /// [`list_nodes`].
    async fn list_all_node_interfaces(&self, tenant_id: Option<&str>)
        -> Result<Vec<NodeInterface>>;
    async fn upsert_node_interfaces(
        &self,
        node_id: &str,
        interfaces: &[InterfaceReport],
    ) -> Result<()>;
    async fn list_node_interfaces(&self, node_id: &str) -> Result<Vec<NodeInterface>>;
    async fn set_interface_tag(&self, node_id: &str, interface_name: &str, tag: &str)
        -> Result<()>;
    async fn remove_interface_tag(&self, node_id: &str, interface_name: &str) -> Result<()>;
    /// Update BPF attachment state for a node's interfaces from agent-reported data.
    /// `attachments` is a list of (interface_name, direction) tuples where direction
    /// is "ingress" or "egress".
    async fn update_interface_attachments(
        &self,
        node_id: &str,
        attachments: &[(String, String)],
    ) -> Result<()>;

    /// Replace the set of interfaces with XDP FIB forwarding enabled on a node.
    /// Any interface not listed will have fib_forwarding cleared.
    async fn update_interface_fib_forwarding(
        &self,
        node_id: &str,
        enabled_interfaces: &[String],
    ) -> Result<()>;

    /// Set the default action for a specific interface+direction on a node.
    /// `direction` must be "ingress" or "egress". `action` must be "pass" or "drop".
    async fn update_interface_default_action(
        &self,
        node_id: &str,
        interface_name: &str,
        direction: &str,
        action: &str,
    ) -> Result<()>;

    // ── Issued certs (for decommission / cert query) ──
    //
    // `node_certs` stores the *initial enrollment* credentials blob
    // (`key_pem + cert_pem` concatenated) so a still-polling agent can fetch
    // them via `CheckEnrollmentStatus`. It is **not** refreshed by
    // [`NodeRegistry::renew_cert`] — renewed credentials are delivered
    // directly in the `RenewClientCert` response and the agent already
    // holds the matching private key. After enrollment the only consumer
    // is operator-driven cert export, where "current cert" is read from
    // the renewer-aware [`NodeRecord::cert_serial`] instead.
    async fn store_node_cert_pem(&self, node_id: &str, cert_pem: &str) -> Result<()>;
    async fn get_node_cert_pem(&self, node_id: &str) -> Result<Option<String>>;

    // ── Audit log ──
    async fn append_audit(&self, entry: NewAuditEntry) -> Result<()>;
    /// `tenant_id` follows the same `None` = cross-tenant convention as
    /// [`list_nodes`].
    async fn list_audit(
        &self,
        tenant_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEntry>>;

    /// Audit rows within the inclusive unix-epoch-second window `[from, to]`
    /// (either bound may be `None` to leave that side open), newest-first.
    /// `cap` bounds the number of rows returned so a wide export can't exhaust
    /// memory. `tenant_id` follows the same `None` = cross-tenant convention as
    /// [`list_audit`]. Used by the audit export.
    async fn list_audit_between(
        &self,
        tenant_id: Option<&str>,
        from: Option<i64>,
        to: Option<i64>,
        cap: u32,
    ) -> Result<Vec<AuditEntry>>;

    // ── Enrollment tokens (ZTP) ──
    async fn insert_enrollment_token(&self, token: &EnrollmentTokenRecord) -> Result<()>;
    /// `tenant_id`: `Some(slug)` restricts to one tenant; `None` is
    /// admin-only/cross-tenant. GraphQL resolvers always pass
    /// `Some(principal.tenant_slug)`.
    async fn list_enrollment_tokens(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<EnrollmentTokenRecord>>;
    async fn revoke_enrollment_token(&self, token_id: &str) -> Result<bool>;
    /// Atomically attempt to redeem `token_id` against `token_hash`.
    /// On success, decrements `uses_remaining` and returns the fleet label
    /// (if set on the token). Status outcomes do not modify the row.
    async fn redeem_enrollment_token(
        &self,
        token_id: &str,
        token_hash: &[u8],
    ) -> Result<TokenRedeemOutcome>;
}

/// Parameters for inserting a new audit entry (id is auto-assigned).
#[derive(Debug)]
pub struct NewAuditEntry {
    pub operator: Option<String>,
    pub action: String,
    pub node_id: Option<String>,
    pub detail: Option<String>,
    /// Tenant slug to attach to the row.
    ///
    /// Resolution order in `append_audit`:
    ///   1. `Some(slug)` — used verbatim. Principal-aware resolvers (IAM,
    ///      enrollment mints, anything with `principal.tenant_slug` in scope)
    ///      should always supply this so the row can't accidentally fall back
    ///      to `'default'`.
    ///   2. `None` + `Some(node_id)` — store looks up `nodes.tenant_id` and
    ///      attaches it. Covers node-scoped audits (approve, decommission,
    ///      reconciliation, gRPC management) without forcing every call site
    ///      to thread tenant context down.
    ///   3. `None` + `None` — falls back to `'default'`. Safe for the
    ///      single-tenant install; in multi-tenant deployments this is a
    ///      latent footgun for non-node, non-principal audit writes (token
    ///      reaper, retention sweep). Grep for `tenant_id: None` next to a
    ///      `None`-keyed `node_id` to find the survivors.
    pub tenant_id: Option<String>,
}
