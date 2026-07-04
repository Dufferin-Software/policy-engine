// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use policy_controller_proto::controller::InterfaceReport;
use sqlx::{sqlite::SqlitePool, Row};
use std::path::Path;

use super::{
    rule_content_equal, AuditEntry, ControllerStore, DiffSummary, EnrollmentTokenRecord,
    NewAuditEntry, NewSuricataAlert, NodeInterface, NodeRecord, NodeStatus, Rule,
    SuricataAlertFilter, SuricataAlertRecord, SuricataRuleFileReport, SuricataRuleset,
    TokenRedeemOutcome,
};

/// Production [`ControllerStore`] backed by SQLite via `sqlx`.
///
/// The database schema is managed by migrations in `migrations/`.
/// Call [`SqliteControllerStore::new`] to open (or create) the database
/// and run all pending migrations automatically.
pub struct SqliteControllerStore {
    pool: SqlitePool,
}

impl SqliteControllerStore {
    /// Open the SQLite database at `db_path` and run pending migrations.
    /// Creates the file and its parent directory if they do not exist.
    pub async fn new(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create DB directory: {}", parent.display()))?;
        }

        let url = format!("sqlite://{}?mode=rwc", db_path.display());
        let pool = SqlitePool::connect(&url)
            .await
            .with_context(|| format!("Failed to open SQLite DB: {}", db_path.display()))?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("Failed to run database migrations")?;

        Ok(Self { pool })
    }

    /// Access the underlying `SqlitePool` for modules that need to attach
    /// their own tables (currently: the event pipeline, via
    /// [`crate::event_pipeline::TenantScope`]). All such modules must go
    /// through `TenantScope` rather than the raw pool — see
    /// `docs/event-pipeline.md` "Multi-tenancy".
    pub fn pool(&self) -> sqlx::sqlite::SqlitePool {
        self.pool.clone()
    }
}

#[async_trait]
impl ControllerStore for SqliteControllerStore {
    // ── Nodes ────────────────────────────────────────────────────────────────

    async fn upsert_node(&self, node: &NodeRecord) -> Result<()> {
        let status = node.status.to_string();
        let public_key_der = hex::encode(&node.public_key_der);
        let cert_serial = node.cert_serial.as_deref().map(hex::encode);
        let cert_expiry = node.cert_expiry.map(|dt| dt.timestamp());
        let last_seen = node.last_seen.map(|dt| dt.timestamp());
        let enrolled_at = node.enrolled_at.map(|dt| dt.timestamp());
        let decommissioned_at = node.decommissioned_at.map(|dt| dt.timestamp());
        let last_renewed_at = node.last_renewed_at.map(|dt| dt.timestamp());

        sqlx::query(
            r#"
            INSERT INTO nodes
                (id, label, public_key_der, dmi_uuid, status, cert_serial, cert_expiry,
                 last_seen, enrolled_at, decommissioned_at, enrollment_id, tpm_backed,
                 agent_version, hostname, os_pretty_name, kernel_version, dmi_sys_vendor, dmi_product_name, tenant_id,
                 last_renewed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                label              = excluded.label,
                dmi_uuid           = excluded.dmi_uuid,
                status             = excluded.status,
                cert_serial        = excluded.cert_serial,
                cert_expiry        = excluded.cert_expiry,
                last_seen          = excluded.last_seen,
                enrolled_at        = excluded.enrolled_at,
                decommissioned_at  = excluded.decommissioned_at,
                enrollment_id      = excluded.enrollment_id,
                tpm_backed         = excluded.tpm_backed,
                agent_version      = excluded.agent_version,
                hostname           = excluded.hostname,
                os_pretty_name     = excluded.os_pretty_name,
                kernel_version     = excluded.kernel_version,
                dmi_sys_vendor     = excluded.dmi_sys_vendor,
                dmi_product_name   = excluded.dmi_product_name,
                last_renewed_at    = excluded.last_renewed_at
            "#,
        )
        .bind(&node.id)
        .bind(&node.label)
        .bind(&public_key_der)
        .bind(&node.dmi_uuid)
        .bind(&status)
        .bind(&cert_serial)
        .bind(cert_expiry)
        .bind(last_seen)
        .bind(enrolled_at)
        .bind(decommissioned_at)
        .bind(&node.enrollment_id)
        .bind(node.tpm_backed)
        .bind(&node.agent_version)
        .bind(&node.hostname)
        .bind(&node.os_pretty_name)
        .bind(&node.kernel_version)
        .bind(&node.dmi_sys_vendor)
        .bind(&node.dmi_product_name)
        .bind(&node.tenant_id)
        .bind(last_renewed_at)
        .execute(&self.pool)
        .await
        .context("Failed to upsert node")?;

        Ok(())
    }

    async fn get_node(&self, id: &str) -> Result<Option<NodeRecord>> {
        let row = sqlx::query(
            "SELECT id, label, public_key_der, dmi_uuid, status, cert_serial, cert_expiry, \
             last_seen, enrolled_at, decommissioned_at, enrollment_id, tpm_backed, \
             agent_version, hostname, os_pretty_name, kernel_version, dmi_sys_vendor, dmi_product_name, tenant_id, last_renewed_at, metrics_interval_secs, capabilities, inspect_mode \
             FROM nodes WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query node")?;

        row.map(row_to_node).transpose()
    }

    async fn get_node_by_enrollment_id(&self, enrollment_id: &str) -> Result<Option<NodeRecord>> {
        let row = sqlx::query(
            "SELECT id, label, public_key_der, dmi_uuid, status, cert_serial, cert_expiry, \
             last_seen, enrolled_at, decommissioned_at, enrollment_id, tpm_backed, \
             agent_version, hostname, os_pretty_name, kernel_version, dmi_sys_vendor, dmi_product_name, tenant_id, last_renewed_at, metrics_interval_secs, capabilities, inspect_mode \
             FROM nodes WHERE enrollment_id = ?",
        )
        .bind(enrollment_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query node by enrollment_id")?;

        row.map(row_to_node).transpose()
    }

    async fn list_nodes(
        &self,
        tenant_id: Option<&str>,
        status: Option<NodeStatus>,
    ) -> Result<Vec<NodeRecord>> {
        const COLS: &str = "id, label, public_key_der, dmi_uuid, status, cert_serial, cert_expiry, \
             last_seen, enrolled_at, decommissioned_at, enrollment_id, tpm_backed, \
             agent_version, hostname, os_pretty_name, kernel_version, dmi_sys_vendor, dmi_product_name, tenant_id, last_renewed_at, metrics_interval_secs, capabilities, inspect_mode";
        let mut sql = format!("SELECT {COLS} FROM nodes");
        let mut clauses: Vec<&'static str> = Vec::new();
        if status.is_some() {
            clauses.push("status = ?");
        }
        if tenant_id.is_some() {
            clauses.push("tenant_id = ?");
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        let mut q = sqlx::query(&sql);
        if let Some(s) = status {
            q = q.bind(s.to_string());
        }
        if let Some(t) = tenant_id {
            q = q.bind(t.to_string());
        }
        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to list nodes")?;
        rows.into_iter().map(row_to_node).collect()
    }

    async fn update_node_status(&self, id: &str, status: NodeStatus) -> Result<()> {
        sqlx::query("UPDATE nodes SET status = ? WHERE id = ?")
            .bind(status.to_string())
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update node status")?;
        Ok(())
    }

    async fn update_node_tenant(&self, id: &str, tenant_id: &str) -> Result<()> {
        sqlx::query("UPDATE nodes SET tenant_id = ? WHERE id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update node tenant")?;
        Ok(())
    }

    async fn delete_node(&self, id: &str) -> Result<()> {
        // Remove dependent rows first.
        sqlx::query("DELETE FROM rules WHERE node_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete node rules")?;
        sqlx::query("DELETE FROM node_interfaces WHERE node_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete node interfaces")?;
        sqlx::query("DELETE FROM node_certs WHERE node_id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete node cert")?;
        sqlx::query("DELETE FROM nodes WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete node")?;
        Ok(())
    }

    async fn update_node_last_seen(&self, id: &str, ts: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE nodes SET last_seen = ? WHERE id = ?")
            .bind(ts.timestamp())
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update node last_seen")?;
        Ok(())
    }

    async fn update_node_stop_behavior(&self, id: &str, behavior: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE nodes SET stop_behavior = ? WHERE id = ?")
            .bind(behavior)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update node stop_behavior")?;
        Ok(())
    }

    async fn update_node_metrics_interval(&self, id: &str, secs: Option<u32>) -> Result<()> {
        sqlx::query("UPDATE nodes SET metrics_interval_secs = ? WHERE id = ?")
            .bind(secs.map(|s| s as i64))
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update node metrics_interval_secs")?;
        Ok(())
    }

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
    ) -> Result<()> {
        // COALESCE so an empty AgentHello field (None) doesn't overwrite a
        // value that was populated at enrollment time. This matters for
        // dmi_uuid in particular: a node enrolled before the
        // CAP_DAC_READ_SEARCH fix shipped will have it stored, and a later
        // reconnect from an agent that still can't read product_uuid would
        // otherwise wipe it.
        sqlx::query(
            "UPDATE nodes SET tpm_backed = ?, \
             agent_version = COALESCE(?, agent_version), \
             hostname = COALESCE(?, hostname), \
             os_pretty_name = COALESCE(?, os_pretty_name), \
             kernel_version = COALESCE(?, kernel_version), \
             dmi_sys_vendor = COALESCE(?, dmi_sys_vendor), \
             dmi_product_name = COALESCE(?, dmi_product_name), \
             dmi_uuid = COALESCE(?, dmi_uuid) \
             WHERE id = ?",
        )
        .bind(tpm_backed)
        .bind(agent_version)
        .bind(hostname)
        .bind(os_pretty_name)
        .bind(kernel_version)
        .bind(dmi_sys_vendor)
        .bind(dmi_product_name)
        .bind(dmi_uuid)
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update node agent info")?;
        Ok(())
    }

    async fn update_node_capabilities(&self, id: &str, capabilities_json: &str) -> Result<()> {
        sqlx::query("UPDATE nodes SET capabilities = ? WHERE id = ?")
            .bind(capabilities_json)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update node capabilities")?;
        Ok(())
    }

    async fn list_active_node_sources(
        &self,
        tenant_id: &str,
    ) -> Result<std::collections::HashSet<String>> {
        // Pull every Active node's capabilities blob for this tenant and
        // union the `sources` arrays in Rust — the JSON is small (one row
        // per node, ~100 bytes) and SQLite's json1 isn't worth the deps.
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT capabilities FROM nodes WHERE tenant_id = ? AND status = 'active'",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list node capabilities")?;
        let mut out = std::collections::HashSet::new();
        for (json,) in rows {
            // A corrupt capabilities blob (truncated, hand-edited) shouldn't
            // make rule validation fall over — skip it and keep going so the
            // operator's mutation still proceeds against the other nodes.
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else {
                continue;
            };
            if let Some(arr) = v.get("sources").and_then(|s| s.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        out.insert(s.to_string());
                    }
                }
            }
        }
        Ok(out)
    }

    async fn update_node_cert(
        &self,
        id: &str,
        serial: Vec<u8>,
        expiry: DateTime<Utc>,
        cert_pem: String,
    ) -> Result<()> {
        sqlx::query("UPDATE nodes SET cert_serial = ?, cert_expiry = ? WHERE id = ?")
            .bind(hex::encode(&serial))
            .bind(expiry.timestamp())
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update node cert")?;

        self.store_node_cert_pem(id, &cert_pem).await?;
        Ok(())
    }

    async fn update_current_cert_meta(
        &self,
        id: &str,
        serial: Vec<u8>,
        expiry: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query("UPDATE nodes SET cert_serial = ?, cert_expiry = ? WHERE id = ?")
            .bind(hex::encode(&serial))
            .bind(expiry.timestamp())
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update current cert meta")?;
        Ok(())
    }

    // ── Cert revocation ──────────────────────────────────────────────────────

    async fn revoke_cert(&self, serial: &[u8]) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO revoked_certs (serial, revoked_at) VALUES (?, ?)")
            .bind(hex::encode(serial))
            .bind(Utc::now().timestamp())
            .execute(&self.pool)
            .await
            .context("Failed to revoke cert")?;
        Ok(())
    }

    async fn is_cert_revoked(&self, serial: &[u8]) -> Result<bool> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM revoked_certs WHERE serial = ?")
            .bind(hex::encode(serial))
            .fetch_one(&self.pool)
            .await
            .context("Failed to check cert revocation")?;
        Ok(count > 0)
    }

    async fn list_revoked_serials(&self) -> Result<Vec<Vec<u8>>> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT serial FROM revoked_certs")
            .fetch_all(&self.pool)
            .await
            .context("Failed to list revoked serials")?;
        rows.into_iter()
            .map(|(s,)| {
                hex::decode(&s)
                    .with_context(|| format!("Invalid hex serial in revoked_certs: {}", s))
            })
            .collect()
    }

    // ── Rules ────────────────────────────────────────────────────────────────

    async fn create_rule(&self, rule: &Rule) -> Result<()> {
        // Upsert on the rule id rather than a bare INSERT. A rule may legitimately
        // arrive twice for the same id: the gated create commits it after the agent
        // confirms, but a racing `apply_local_change` (driven by an agent state
        // snapshot) can persist the same rule first. A plain INSERT would fail the
        // commit on the resulting primary-key conflict; the upsert keeps the
        // operation idempotent so identical re-creates are a no-op.
        sqlx::query(
            r#"
            INSERT INTO rules
                (id, tenant_id, node_id, interface_name, direction,
                 src_cidr, dst_cidr, src_port, dst_port, protocol,
                 sni_pattern, quic_version, src_mac, dst_mac,
                 actions_json, created_at, created_by,
                 expires_after_secs, schedule_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                tenant_id          = excluded.tenant_id,
                node_id            = excluded.node_id,
                interface_name     = excluded.interface_name,
                direction          = excluded.direction,
                src_cidr           = excluded.src_cidr,
                dst_cidr           = excluded.dst_cidr,
                src_port           = excluded.src_port,
                dst_port           = excluded.dst_port,
                protocol           = excluded.protocol,
                sni_pattern        = excluded.sni_pattern,
                quic_version       = excluded.quic_version,
                src_mac            = excluded.src_mac,
                dst_mac            = excluded.dst_mac,
                actions_json       = excluded.actions_json,
                expires_after_secs = excluded.expires_after_secs,
                schedule_json      = excluded.schedule_json
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.tenant_id)
        .bind(&rule.node_id)
        .bind(&rule.interface_name)
        .bind(&rule.direction)
        .bind(&rule.src_cidr)
        .bind(&rule.dst_cidr)
        .bind(rule.src_port.map(|p| p as i64))
        .bind(rule.dst_port.map(|p| p as i64))
        .bind(&rule.protocol)
        .bind(&rule.sni_pattern)
        .bind(&rule.quic_version)
        .bind(&rule.src_mac)
        .bind(&rule.dst_mac)
        .bind(&rule.actions_json)
        .bind(rule.created_at.timestamp())
        .bind(&rule.created_by)
        .bind(rule.expires_after_secs.map(|s| s as i64))
        .bind(&rule.schedule_json)
        .execute(&self.pool)
        .await
        .context("Failed to create rule")?;
        Ok(())
    }

    async fn delete_rule(&self, rule_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM rules WHERE id = ?")
            .bind(rule_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete rule")?;
        Ok(())
    }

    async fn get_rule(&self, rule_id: &str) -> Result<Option<Rule>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, node_id, interface_name, direction, \
             src_cidr, dst_cidr, src_port, dst_port, protocol, \
             sni_pattern, quic_version, src_mac, dst_mac, \
             actions_json, created_at, created_by, \
             expires_after_secs, schedule_json \
             FROM rules WHERE id = ?",
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query rule")?;

        row.map(row_to_rule).transpose()
    }

    async fn list_rules_for_node(&self, node_id: &str) -> Result<Vec<Rule>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, node_id, interface_name, direction, \
             src_cidr, dst_cidr, src_port, dst_port, protocol, \
             sni_pattern, quic_version, src_mac, dst_mac, \
             actions_json, created_at, created_by, \
             expires_after_secs, schedule_json \
             FROM rules WHERE node_id = ? ORDER BY created_at",
        )
        .bind(node_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list rules for node")?;

        rows.into_iter().map(row_to_rule).collect()
    }

    async fn list_rules_for_interface(
        &self,
        node_id: &str,
        interface_name: &str,
        direction: &str,
    ) -> Result<Vec<Rule>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, node_id, interface_name, direction, \
             src_cidr, dst_cidr, src_port, dst_port, protocol, \
             sni_pattern, quic_version, src_mac, dst_mac, \
             actions_json, created_at, created_by, \
             expires_after_secs, schedule_json \
             FROM rules WHERE node_id = ? AND interface_name = ? AND direction = ? \
             ORDER BY created_at",
        )
        .bind(node_id)
        .bind(interface_name)
        .bind(direction)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list rules for interface")?;

        rows.into_iter().map(row_to_rule).collect()
    }

    async fn delete_rules_for_node(&self, node_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM rules WHERE node_id = ?")
            .bind(node_id)
            .execute(&self.pool)
            .await
            .context("Failed to delete rules for node")?;
        Ok(())
    }

    async fn replace_rules_for_node(
        &self,
        node_id: &str,
        new_rules: &[Rule],
    ) -> Result<DiffSummary> {
        for r in new_rules {
            if r.node_id != node_id {
                anyhow::bail!(
                    "replace_rules_for_node: rule {} has node_id {} != {}",
                    r.id,
                    r.node_id,
                    node_id
                );
            }
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        let existing_rows = sqlx::query(
            "SELECT id, tenant_id, node_id, interface_name, direction, \
             src_cidr, dst_cidr, src_port, dst_port, protocol, \
             sni_pattern, quic_version, src_mac, dst_mac, \
             actions_json, created_at, created_by, \
             expires_after_secs, schedule_json \
             FROM rules WHERE node_id = ?",
        )
        .bind(node_id)
        .fetch_all(&mut *tx)
        .await
        .context("Failed to load existing rules for replace")?;

        let existing: std::collections::HashMap<String, Rule> = existing_rows
            .into_iter()
            .map(row_to_rule)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect();

        let new_ids: std::collections::HashSet<&str> =
            new_rules.iter().map(|r| r.id.as_str()).collect();

        let mut summary = DiffSummary::default();

        for (id, _) in existing.iter() {
            if !new_ids.contains(id.as_str()) {
                sqlx::query("DELETE FROM rules WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .context("Failed to delete rule during replace")?;
                summary.deleted += 1;
            }
        }

        for rule in new_rules {
            if let Some(prev) = existing.get(&rule.id) {
                if rule_content_equal(prev, rule) {
                    summary.unchanged += 1;
                    continue;
                }
                summary.updated += 1;
            } else {
                summary.added += 1;
            }
            sqlx::query(
                r#"
                INSERT INTO rules
                    (id, tenant_id, node_id, interface_name, direction,
                     src_cidr, dst_cidr, src_port, dst_port, protocol,
                     sni_pattern, quic_version, src_mac, dst_mac,
                     actions_json, created_at, created_by,
                     expires_after_secs, schedule_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    node_id = excluded.node_id,
                    interface_name = excluded.interface_name,
                    direction = excluded.direction,
                    src_cidr = excluded.src_cidr,
                    dst_cidr = excluded.dst_cidr,
                    src_port = excluded.src_port,
                    dst_port = excluded.dst_port,
                    protocol = excluded.protocol,
                    sni_pattern = excluded.sni_pattern,
                    quic_version = excluded.quic_version,
                    src_mac = excluded.src_mac,
                    dst_mac = excluded.dst_mac,
                    actions_json = excluded.actions_json,
                    created_by = excluded.created_by,
                    expires_after_secs = excluded.expires_after_secs,
                    schedule_json = excluded.schedule_json
                "#,
            )
            .bind(&rule.id)
            .bind(&rule.tenant_id)
            .bind(&rule.node_id)
            .bind(&rule.interface_name)
            .bind(&rule.direction)
            .bind(&rule.src_cidr)
            .bind(&rule.dst_cidr)
            .bind(rule.src_port.map(|p| p as i64))
            .bind(rule.dst_port.map(|p| p as i64))
            .bind(&rule.protocol)
            .bind(&rule.sni_pattern)
            .bind(&rule.quic_version)
            .bind(&rule.src_mac)
            .bind(&rule.dst_mac)
            .bind(&rule.actions_json)
            .bind(rule.created_at.timestamp())
            .bind(&rule.created_by)
            .bind(rule.expires_after_secs.map(|s| s as i64))
            .bind(&rule.schedule_json)
            .execute(&mut *tx)
            .await
            .context("Failed to upsert rule during replace")?;
        }

        tx.commit()
            .await
            .context("Failed to commit replace_rules_for_node")?;

        Ok(summary)
    }

    // ── Node interfaces ──────────────────────────────────────────────────────

    async fn upsert_node_interfaces(
        &self,
        node_id: &str,
        interfaces: &[InterfaceReport],
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        for iface in interfaces {
            let addresses_json = super::address_reports_to_json(&iface.addresses);
            sqlx::query(
                r#"
                INSERT INTO node_interfaces
                    (node_id, interface_name, ifindex, mac_address, link_state, addresses_json, last_reported)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, interface_name) DO UPDATE SET
                    ifindex        = excluded.ifindex,
                    mac_address    = excluded.mac_address,
                    link_state     = excluded.link_state,
                    addresses_json = excluded.addresses_json,
                    last_reported  = excluded.last_reported
                "#,
            )
            .bind(node_id)
            .bind(&iface.name)
            .bind(iface.ifindex as i64)
            .bind(&iface.mac_address)
            .bind(&iface.link_state)
            .bind(&addresses_json)
            .bind(now)
            .execute(&self.pool)
            .await
            .with_context(|| format!("Failed to upsert interface {}", iface.name))?;
        }
        Ok(())
    }

    async fn list_all_node_interfaces(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<NodeInterface>> {
        // node_interfaces has no tenant_id column — interfaces inherit
        // their node's tenant. Join through `nodes` when scoping.
        let rows = if let Some(t) = tenant_id {
            sqlx::query(
                "SELECT ni.node_id, ni.interface_name, ni.ifindex, ni.mac_address, ni.link_state, ni.addresses_json, \
                 ni.tag, ni.last_reported, ni.xdp_attached, ni.tc_attached, ni.fib_forwarding, ni.urpf_mode, ni.inspect_enabled, \
                 ni.ingress_default_action, ni.egress_default_action \
                 FROM node_interfaces ni \
                 JOIN nodes n ON n.id = ni.node_id \
                 WHERE n.tenant_id = ? \
                 ORDER BY ni.node_id, ni.interface_name",
            )
            .bind(t.to_string())
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT node_id, interface_name, ifindex, mac_address, link_state, addresses_json, \
                 tag, last_reported, xdp_attached, tc_attached, fib_forwarding, urpf_mode, inspect_enabled, \
                 ingress_default_action, egress_default_action \
                 FROM node_interfaces ORDER BY node_id, interface_name",
            )
            .fetch_all(&self.pool)
            .await
        }
        .context("Failed to list all node interfaces")?;
        rows.into_iter().map(row_to_node_interface).collect()
    }

    async fn list_node_interfaces(&self, node_id: &str) -> Result<Vec<NodeInterface>> {
        let rows = sqlx::query(
            "SELECT node_id, interface_name, ifindex, mac_address, link_state, addresses_json, \
             tag, last_reported, xdp_attached, tc_attached, fib_forwarding, urpf_mode, inspect_enabled, \
             ingress_default_action, egress_default_action \
             FROM node_interfaces WHERE node_id = ? ORDER BY interface_name",
        )
        .bind(node_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list node interfaces")?;

        rows.into_iter().map(row_to_node_interface).collect()
    }

    async fn update_interface_default_action(
        &self,
        node_id: &str,
        interface_name: &str,
        direction: &str,
        action: &str,
    ) -> Result<()> {
        let col = match direction.to_lowercase().as_str() {
            "ingress" => "ingress_default_action",
            "egress" => "egress_default_action",
            _ => anyhow::bail!("Invalid direction: {}", direction),
        };
        let sql = format!(
            "UPDATE node_interfaces SET {} = ? WHERE node_id = ? AND interface_name = ?",
            col
        );
        sqlx::query(&sql)
            .bind(action)
            .bind(node_id)
            .bind(interface_name)
            .execute(&self.pool)
            .await
            .with_context(|| format!("Failed to set {} for {}/{}", col, node_id, interface_name))?;
        Ok(())
    }

    async fn set_interface_tag(
        &self,
        node_id: &str,
        interface_name: &str,
        tag: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE node_interfaces SET tag = ? WHERE node_id = ? AND interface_name = ?")
            .bind(tag)
            .bind(node_id)
            .bind(interface_name)
            .execute(&self.pool)
            .await
            .context("Failed to set interface tag")?;
        Ok(())
    }

    async fn remove_interface_tag(&self, node_id: &str, interface_name: &str) -> Result<()> {
        sqlx::query(
            "UPDATE node_interfaces SET tag = NULL WHERE node_id = ? AND interface_name = ?",
        )
        .bind(node_id)
        .bind(interface_name)
        .execute(&self.pool)
        .await
        .context("Failed to remove interface tag")?;
        Ok(())
    }

    async fn update_interface_fib_forwarding(
        &self,
        node_id: &str,
        enabled_interfaces: &[String],
    ) -> Result<()> {
        // Reset all interfaces for this node, then enable the listed ones.
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;
        sqlx::query("UPDATE node_interfaces SET fib_forwarding = 0 WHERE node_id = ?")
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .context("Failed to clear node fib_forwarding")?;
        for iface in enabled_interfaces {
            sqlx::query(
                "UPDATE node_interfaces SET fib_forwarding = 1 \
                 WHERE node_id = ? AND interface_name = ?",
            )
            .bind(node_id)
            .bind(iface)
            .execute(&mut *tx)
            .await
            .context("Failed to set interface fib_forwarding")?;
        }
        tx.commit().await.context("Failed to commit")?;
        Ok(())
    }

    async fn update_interface_urpf(
        &self,
        node_id: &str,
        interface_modes: &[(String, u32)],
    ) -> Result<()> {
        // Reset uRPF on all interfaces for this node, then apply the listed modes.
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;
        sqlx::query("UPDATE node_interfaces SET urpf_mode = 0 WHERE node_id = ?")
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .context("Failed to clear node urpf_mode")?;
        for (iface, mode) in interface_modes {
            sqlx::query(
                "UPDATE node_interfaces SET urpf_mode = ? \
                 WHERE node_id = ? AND interface_name = ?",
            )
            .bind(*mode as i64)
            .bind(node_id)
            .bind(iface)
            .execute(&mut *tx)
            .await
            .context("Failed to set interface urpf_mode")?;
        }
        tx.commit().await.context("Failed to commit")?;
        Ok(())
    }

    async fn set_node_inspect_mode(&self, node_id: &str, mode: &str) -> Result<()> {
        sqlx::query("UPDATE nodes SET inspect_mode = ? WHERE id = ?")
            .bind(mode)
            .bind(node_id)
            .execute(&self.pool)
            .await
            .context("Failed to update node inspect_mode")?;
        Ok(())
    }

    async fn update_interface_inspect(
        &self,
        node_id: &str,
        enabled_interfaces: &[String],
    ) -> Result<()> {
        // Reset the flag on all interfaces for this node, then set the listed ones.
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;
        sqlx::query("UPDATE node_interfaces SET inspect_enabled = 0 WHERE node_id = ?")
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .context("Failed to clear node inspect_enabled")?;
        for iface in enabled_interfaces {
            sqlx::query(
                "UPDATE node_interfaces SET inspect_enabled = 1 \
                 WHERE node_id = ? AND interface_name = ?",
            )
            .bind(node_id)
            .bind(iface)
            .execute(&mut *tx)
            .await
            .context("Failed to set interface inspect_enabled")?;
        }
        tx.commit().await.context("Failed to commit")?;
        Ok(())
    }

    async fn update_interface_inspect_enabled(
        &self,
        node_id: &str,
        interface_name: &str,
        enabled: bool,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE node_interfaces SET inspect_enabled = ? \
             WHERE node_id = ? AND interface_name = ?",
        )
        .bind(enabled as i64)
        .bind(node_id)
        .bind(interface_name)
        .execute(&self.pool)
        .await
        .context("Failed to set interface inspect_enabled")?;
        Ok(())
    }

    async fn create_suricata_ruleset(&self, ruleset: &SuricataRuleset) -> Result<()> {
        sqlx::query(
            "INSERT INTO suricata_rulesets \
             (id, tenant_id, name, content, sha256, rule_count, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&ruleset.id)
        .bind(&ruleset.tenant_id)
        .bind(&ruleset.name)
        .bind(&ruleset.content)
        .bind(&ruleset.sha256)
        .bind(ruleset.rule_count as i64)
        .bind(ruleset.created_at.timestamp())
        .bind(ruleset.updated_at.timestamp())
        .execute(&self.pool)
        .await
        .context("Failed to create suricata ruleset (name already in use?)")?;
        Ok(())
    }

    async fn update_suricata_ruleset(
        &self,
        id: &str,
        content: &str,
        sha256: &str,
        rule_count: u32,
        updated_at: DateTime<Utc>,
    ) -> Result<()> {
        let res = sqlx::query(
            "UPDATE suricata_rulesets \
             SET content = ?, sha256 = ?, rule_count = ?, updated_at = ? WHERE id = ?",
        )
        .bind(content)
        .bind(sha256)
        .bind(rule_count as i64)
        .bind(updated_at.timestamp())
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update suricata ruleset")?;
        anyhow::ensure!(res.rows_affected() > 0, "Ruleset '{}' not found", id);
        Ok(())
    }

    async fn delete_suricata_ruleset(&self, id: &str) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;
        sqlx::query("DELETE FROM node_suricata_rulesets WHERE ruleset_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to delete ruleset assignments")?;
        sqlx::query("DELETE FROM suricata_rulesets WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to delete suricata ruleset")?;
        tx.commit().await.context("Failed to commit")?;
        Ok(())
    }

    async fn get_suricata_ruleset(&self, id: &str) -> Result<Option<SuricataRuleset>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, content, sha256, rule_count, created_at, updated_at \
             FROM suricata_rulesets WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query suricata ruleset")?;
        row.map(row_to_suricata_ruleset).transpose()
    }

    async fn list_suricata_rulesets(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<SuricataRuleset>> {
        let rows = if let Some(t) = tenant_id {
            sqlx::query(
                "SELECT id, tenant_id, name, content, sha256, rule_count, created_at, updated_at \
                 FROM suricata_rulesets WHERE tenant_id = ? ORDER BY name",
            )
            .bind(t)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, tenant_id, name, content, sha256, rule_count, created_at, updated_at \
                 FROM suricata_rulesets ORDER BY name",
            )
            .fetch_all(&self.pool)
            .await
        }
        .context("Failed to list suricata rulesets")?;
        rows.into_iter().map(row_to_suricata_ruleset).collect()
    }

    async fn assign_suricata_ruleset(&self, node_id: &str, ruleset_id: &str) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO node_suricata_rulesets (node_id, ruleset_id) VALUES (?, ?)",
        )
        .bind(node_id)
        .bind(ruleset_id)
        .execute(&self.pool)
        .await
        .context("Failed to assign suricata ruleset")?;
        Ok(())
    }

    async fn unassign_suricata_ruleset(&self, node_id: &str, ruleset_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM node_suricata_rulesets WHERE node_id = ? AND ruleset_id = ?")
            .bind(node_id)
            .bind(ruleset_id)
            .execute(&self.pool)
            .await
            .context("Failed to unassign suricata ruleset")?;
        Ok(())
    }

    async fn list_suricata_rulesets_for_node(&self, node_id: &str) -> Result<Vec<SuricataRuleset>> {
        let rows = sqlx::query(
            "SELECT r.id, r.tenant_id, r.name, r.content, r.sha256, r.rule_count, \
             r.created_at, r.updated_at \
             FROM suricata_rulesets r \
             JOIN node_suricata_rulesets a ON a.ruleset_id = r.id \
             WHERE a.node_id = ? ORDER BY r.name",
        )
        .bind(node_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list node suricata rulesets")?;
        rows.into_iter().map(row_to_suricata_ruleset).collect()
    }

    async fn list_nodes_for_suricata_ruleset(&self, ruleset_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT node_id FROM node_suricata_rulesets WHERE ruleset_id = ? ORDER BY node_id",
        )
        .bind(ruleset_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list ruleset nodes")?;
        Ok(rows.into_iter().map(|r| r.get("node_id")).collect())
    }

    async fn replace_node_suricata_rule_files(
        &self,
        node_id: &str,
        files: &[SuricataRuleFileReport],
    ) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;
        sqlx::query("DELETE FROM node_suricata_rule_files WHERE node_id = ?")
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .context("Failed to clear node rule files")?;
        for f in files {
            sqlx::query(
                "INSERT INTO node_suricata_rule_files (node_id, filename, sha256, rule_count) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(node_id)
            .bind(&f.filename)
            .bind(&f.sha256)
            .bind(f.rule_count as i64)
            .execute(&mut *tx)
            .await
            .context("Failed to insert node rule file")?;
        }
        tx.commit().await.context("Failed to commit")?;
        Ok(())
    }

    async fn list_node_suricata_rule_files(
        &self,
        node_id: &str,
    ) -> Result<Vec<SuricataRuleFileReport>> {
        let rows = sqlx::query(
            "SELECT node_id, filename, sha256, rule_count \
             FROM node_suricata_rule_files WHERE node_id = ? ORDER BY filename",
        )
        .bind(node_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list node rule files")?;
        Ok(rows
            .into_iter()
            .map(|r| SuricataRuleFileReport {
                node_id: r.get("node_id"),
                filename: r.get("filename"),
                sha256: r.get("sha256"),
                rule_count: r.get::<i64, _>("rule_count") as u32,
            })
            .collect())
    }

    async fn insert_suricata_alerts(&self, alerts: &[NewSuricataAlert]) -> Result<()> {
        if alerts.is_empty() {
            return Ok(());
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;
        for a in alerts {
            sqlx::query(
                "INSERT INTO suricata_alerts \
                 (tenant_id, node_id, timestamp, received_ns, src_ip, src_port, dst_ip, \
                  dst_port, proto, action, signature_id, signature, category, severity, raw_json) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&a.tenant_id)
            .bind(&a.node_id)
            .bind(&a.timestamp)
            .bind(a.received_ns)
            .bind(&a.src_ip)
            .bind(a.src_port)
            .bind(&a.dst_ip)
            .bind(a.dst_port)
            .bind(&a.proto)
            .bind(&a.action)
            .bind(a.signature_id)
            .bind(&a.signature)
            .bind(&a.category)
            .bind(a.severity)
            .bind(&a.raw_json)
            .execute(&mut *tx)
            .await
            .context("Failed to insert suricata alert")?;
        }
        tx.commit().await.context("Failed to commit")?;
        Ok(())
    }

    async fn list_suricata_alerts(
        &self,
        filter: &SuricataAlertFilter,
        limit: i64,
    ) -> Result<Vec<SuricataAlertRecord>> {
        let mut sql = String::from(
            "SELECT id, tenant_id, node_id, timestamp, received_ns, src_ip, src_port, dst_ip, \
             dst_port, proto, action, signature_id, signature, category, severity, raw_json \
             FROM suricata_alerts",
        );
        let mut clauses: Vec<&'static str> = Vec::new();
        if filter.tenant_id.is_some() {
            clauses.push("tenant_id = ?");
        }
        if filter.node_id.is_some() {
            clauses.push("node_id = ?");
        }
        if filter.min_severity.is_some() {
            // Lower severity number = higher urgency in Suricata; "min_severity"
            // means "at least this urgent", i.e. severity <= N.
            clauses.push("severity <= ?");
        }
        if filter.signature_id.is_some() {
            clauses.push("signature_id = ?");
        }
        if filter.signature_contains.is_some() {
            clauses.push("signature LIKE ?");
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY received_ns DESC LIMIT ?");

        let mut q = sqlx::query(&sql);
        if let Some(ref t) = filter.tenant_id {
            q = q.bind(t);
        }
        if let Some(ref n) = filter.node_id {
            q = q.bind(n);
        }
        if let Some(s) = filter.min_severity {
            q = q.bind(s);
        }
        if let Some(sid) = filter.signature_id {
            q = q.bind(sid);
        }
        if let Some(ref sig) = filter.signature_contains {
            q = q.bind(format!("%{}%", sig));
        }
        q = q.bind(limit.max(0));

        let rows = q
            .fetch_all(&self.pool)
            .await
            .context("Failed to query suricata alerts")?;
        Ok(rows.into_iter().map(row_to_suricata_alert).collect())
    }

    async fn prune_suricata_alerts(&self, cutoff_ns: i64) -> Result<u64> {
        let res = sqlx::query("DELETE FROM suricata_alerts WHERE received_ns < ?")
            .bind(cutoff_ns)
            .execute(&self.pool)
            .await
            .context("Failed to prune suricata alerts")?;
        Ok(res.rows_affected())
    }

    async fn update_interface_attachments(
        &self,
        node_id: &str,
        attachments: &[(String, String)],
    ) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // Reset all attachments for this node first.
        sqlx::query(
            "UPDATE node_interfaces SET xdp_attached = 0, tc_attached = 0 WHERE node_id = ?",
        )
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .context("Failed to reset interface attachments")?;

        // Set the ones that are actually attached.
        for (iface, dir) in attachments {
            let (col, val) = match dir.to_lowercase().as_str() {
                "ingress" => ("xdp_attached", true),
                "egress" => ("tc_attached", true),
                _ => continue,
            };
            // Ensure the row exists — it may not yet if the agent attaches a
            // program before AgentHello's upsert_node_interfaces has run.
            sqlx::query(
                "INSERT OR IGNORE INTO node_interfaces \
                 (node_id, interface_name, last_reported) VALUES (?, ?, unixepoch())",
            )
            .bind(node_id)
            .bind(iface)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("Failed to ensure interface row for {}/{}", node_id, iface))?;
            let sql = format!(
                "UPDATE node_interfaces SET {} = ? WHERE node_id = ? AND interface_name = ?",
                col
            );
            sqlx::query(&sql)
                .bind(val)
                .bind(node_id)
                .bind(iface)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Failed to set {} for {} on {}", col, iface, node_id))?;
        }

        tx.commit().await.context("Failed to commit")?;
        Ok(())
    }

    // ── Certs ────────────────────────────────────────────────────────────────

    async fn store_node_cert_pem(&self, node_id: &str, cert_pem: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO node_certs (node_id, cert_pem) VALUES (?, ?) \
             ON CONFLICT(node_id) DO UPDATE SET cert_pem = excluded.cert_pem",
        )
        .bind(node_id)
        .bind(cert_pem)
        .execute(&self.pool)
        .await
        .context("Failed to store node cert PEM")?;
        Ok(())
    }

    async fn get_node_cert_pem(&self, node_id: &str) -> Result<Option<String>> {
        sqlx::query_scalar("SELECT cert_pem FROM node_certs WHERE node_id = ?")
            .bind(node_id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to get node cert PEM")
    }

    // ── Audit log ────────────────────────────────────────────────────────────

    async fn append_audit(&self, entry: NewAuditEntry) -> Result<()> {
        // Tenant resolution mirrors `NewAuditEntry`'s docs: explicit > derived
        // from node > 'default' fallback. The derivation runs as a subquery
        // so the whole insert is one round trip; if `nodes.id = node_id` is
        // missing (race with decommission, or a synthetic node id) the
        // COALESCE picks up the literal default.
        let explicit_tenant = entry.tenant_id.clone();
        sqlx::query(
            "INSERT INTO audit_log (ts, operator, action, node_id, detail, tenant_id) \
             VALUES ( \
                ?, ?, ?, ?, ?, \
                COALESCE( \
                    ?, \
                    (SELECT tenant_id FROM nodes WHERE id = ?), \
                    'default' \
                ) \
             )",
        )
        .bind(Utc::now().timestamp())
        .bind(&entry.operator)
        .bind(&entry.action)
        .bind(&entry.node_id)
        .bind(&entry.detail)
        .bind(&explicit_tenant)
        .bind(&entry.node_id)
        .execute(&self.pool)
        .await
        .context("Failed to append audit entry")?;
        Ok(())
    }

    async fn list_audit(
        &self,
        tenant_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEntry>> {
        let rows = if let Some(t) = tenant_id {
            sqlx::query(
                "SELECT id, ts, operator, action, node_id, detail, tenant_id FROM audit_log \
                 WHERE tenant_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            )
            .bind(t.to_string())
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, ts, operator, action, node_id, detail, tenant_id FROM audit_log \
                 ORDER BY id DESC LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
        .context("Failed to list audit log")?;

        rows.into_iter()
            .map(|row| {
                Ok(AuditEntry {
                    id: row.get("id"),
                    ts: DateTime::from_timestamp(row.get::<i64, _>("ts"), 0).unwrap_or_default(),
                    operator: row.get("operator"),
                    action: row.get("action"),
                    node_id: row.get("node_id"),
                    detail: row.get("detail"),
                    tenant_id: row.get("tenant_id"),
                })
            })
            .collect()
    }

    async fn list_audit_between(
        &self,
        tenant_id: Option<&str>,
        from: Option<i64>,
        to: Option<i64>,
        cap: u32,
    ) -> Result<Vec<AuditEntry>> {
        // Numbered placeholders so each optional bound becomes a NULL-guarded
        // clause (`?N IS NULL OR ...`) — one query covers every combination of
        // tenant/from/to without branching the SQL.
        let rows = sqlx::query(
            "SELECT id, ts, operator, action, node_id, detail, tenant_id FROM audit_log \
             WHERE (?1 IS NULL OR tenant_id = ?1) \
               AND (?2 IS NULL OR ts >= ?2) \
               AND (?3 IS NULL OR ts <= ?3) \
             ORDER BY id DESC LIMIT ?4",
        )
        .bind(tenant_id.map(|t| t.to_string()))
        .bind(from)
        .bind(to)
        .bind(cap)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list audit log window")?;

        rows.into_iter()
            .map(|row| {
                Ok(AuditEntry {
                    id: row.get("id"),
                    ts: DateTime::from_timestamp(row.get::<i64, _>("ts"), 0).unwrap_or_default(),
                    operator: row.get("operator"),
                    action: row.get("action"),
                    node_id: row.get("node_id"),
                    detail: row.get("detail"),
                    tenant_id: row.get("tenant_id"),
                })
            })
            .collect()
    }

    // ── Enrollment tokens ────────────────────────────────────────────────────

    async fn insert_enrollment_token(&self, token: &EnrollmentTokenRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO enrollment_tokens
                (token_id, token_hash, created_at, created_by, expires_at,
                 uses_remaining, cidr_scope, fleet_label, revoked_at, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&token.token_id)
        .bind(&token.token_hash)
        .bind(token.created_at.timestamp())
        .bind(&token.created_by)
        .bind(token.expires_at.timestamp())
        .bind(token.uses_remaining)
        .bind(&token.cidr_scope)
        .bind(&token.fleet_label)
        .bind(token.revoked_at.map(|dt| dt.timestamp()))
        .bind(&token.tenant_id)
        .execute(&self.pool)
        .await
        .context("Failed to insert enrollment token")?;
        Ok(())
    }

    async fn list_enrollment_tokens(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<EnrollmentTokenRecord>> {
        let base = "SELECT token_id, token_hash, created_at, created_by, expires_at, \
                    uses_remaining, cidr_scope, fleet_label, revoked_at, tenant_id \
                    FROM enrollment_tokens";
        let rows = match tenant_id {
            Some(slug) => {
                sqlx::query(&format!(
                    "{base} WHERE tenant_id = ? ORDER BY created_at DESC"
                ))
                .bind(slug)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query(&format!("{base} ORDER BY created_at DESC"))
                    .fetch_all(&self.pool)
                    .await
            }
        }
        .context("Failed to list enrollment tokens")?;

        rows.into_iter().map(row_to_enrollment_token).collect()
    }

    async fn revoke_enrollment_token(&self, token_id: &str) -> Result<bool> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE enrollment_tokens SET revoked_at = ? \
             WHERE token_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(token_id)
        .execute(&self.pool)
        .await
        .context("Failed to revoke enrollment token")?;
        Ok(result.rows_affected() > 0)
    }

    async fn redeem_enrollment_token(
        &self,
        token_id: &str,
        token_hash: &[u8],
    ) -> Result<TokenRedeemOutcome> {
        use subtle::ConstantTimeEq;

        // Single-statement atomic decrement using a guarded UPDATE.
        // We first peek at the row so we can return precise outcomes
        // (Expired/Revoked/Exhausted/BadSecret) — then the UPDATE applies
        // only if the row still matches all conditions.
        let row = sqlx::query(
            "SELECT token_hash, expires_at, uses_remaining, revoked_at, fleet_label, tenant_id \
             FROM enrollment_tokens WHERE token_id = ?",
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to look up enrollment token")?;

        let Some(row) = row else {
            return Ok(TokenRedeemOutcome::Unknown);
        };

        let stored_hash: Vec<u8> = row.get("token_hash");
        if stored_hash.ct_eq(token_hash).unwrap_u8() == 0 {
            return Ok(TokenRedeemOutcome::BadSecret);
        }
        if row.get::<Option<i64>, _>("revoked_at").is_some() {
            return Ok(TokenRedeemOutcome::Revoked);
        }
        let expires_at: i64 = row.get("expires_at");
        if expires_at <= Utc::now().timestamp() {
            return Ok(TokenRedeemOutcome::Expired);
        }
        let uses_remaining: i64 = row.get("uses_remaining");
        if uses_remaining <= 0 {
            return Ok(TokenRedeemOutcome::Exhausted);
        }

        // Conditional UPDATE: decrement only if the row is still valid.
        // Two redemptions racing will both pass the SELECT above but the
        // UPDATE's `uses_remaining > 0` guard ensures only one succeeds.
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            "UPDATE enrollment_tokens \
             SET uses_remaining = uses_remaining - 1 \
             WHERE token_id = ? \
               AND uses_remaining > 0 \
               AND expires_at > ? \
               AND revoked_at IS NULL",
        )
        .bind(token_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("Failed to decrement enrollment token uses")?;

        if result.rows_affected() == 0 {
            // Lost a race or row changed between SELECT and UPDATE.
            return Ok(TokenRedeemOutcome::Exhausted);
        }

        let fleet_label: Option<String> = row.get("fleet_label");
        let tenant_id: String = row.get("tenant_id");
        Ok(TokenRedeemOutcome::Redeemed {
            fleet_label,
            tenant_id,
        })
    }
}

// ── Row helpers ───────────────────────────────────────────────────────────────

fn row_to_node(row: sqlx::sqlite::SqliteRow) -> Result<NodeRecord> {
    let status_str: String = row.get("status");
    let status = match status_str.as_str() {
        "pending" => NodeStatus::Pending,
        "active" => NodeStatus::Active,
        "decommissioned" => NodeStatus::Decommissioned,
        other => anyhow::bail!("Unknown node status: {}", other),
    };

    let pub_key_hex: String = row.get("public_key_der");
    let public_key_der = hex::decode(&pub_key_hex).context("Failed to decode public_key_der")?;

    let cert_serial: Option<String> = row.get("cert_serial");
    let cert_serial = cert_serial
        .map(|s| hex::decode(s).context("Failed to decode cert_serial"))
        .transpose()?;

    let cert_expiry: Option<i64> = row.get("cert_expiry");
    let last_seen: Option<i64> = row.get("last_seen");
    let enrolled_at: Option<i64> = row.get("enrolled_at");
    let decommissioned_at: Option<i64> = row.get("decommissioned_at");
    let last_renewed_at: Option<i64> = row.get("last_renewed_at");

    Ok(NodeRecord {
        id: row.get("id"),
        label: row.get("label"),
        public_key_der,
        dmi_uuid: row.get("dmi_uuid"),
        status,
        cert_serial,
        cert_expiry: cert_expiry.and_then(|t| DateTime::from_timestamp(t, 0)),
        last_seen: last_seen.and_then(|t| DateTime::from_timestamp(t, 0)),
        enrolled_at: enrolled_at.and_then(|t| DateTime::from_timestamp(t, 0)),
        decommissioned_at: decommissioned_at.and_then(|t| DateTime::from_timestamp(t, 0)),
        last_renewed_at: last_renewed_at.and_then(|t| DateTime::from_timestamp(t, 0)),
        enrollment_id: row.get("enrollment_id"),
        tpm_backed: row.get("tpm_backed"),
        agent_version: row.get("agent_version"),
        hostname: row.try_get("hostname").unwrap_or(None),
        os_pretty_name: row.try_get("os_pretty_name").unwrap_or(None),
        kernel_version: row.try_get("kernel_version").unwrap_or(None),
        dmi_sys_vendor: row.try_get("dmi_sys_vendor").unwrap_or(None),
        dmi_product_name: row.try_get("dmi_product_name").unwrap_or(None),
        tenant_id: row
            .try_get("tenant_id")
            .unwrap_or_else(|_| "default".to_string()),
        stop_behavior: row.try_get("stop_behavior").unwrap_or(None),
        metrics_interval_secs: row
            .try_get::<Option<i64>, _>("metrics_interval_secs")
            .unwrap_or(None)
            .map(|v| v as u32),
        capabilities: row
            .try_get("capabilities")
            .unwrap_or_else(|_| "{}".to_string()),
        inspect_mode: row
            .try_get("inspect_mode")
            .unwrap_or_else(|_| "disabled".to_string()),
    })
}

fn row_to_rule(row: sqlx::sqlite::SqliteRow) -> Result<Rule> {
    let created_at: i64 = row.get("created_at");
    Ok(Rule {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        node_id: row.get("node_id"),
        interface_name: row.get("interface_name"),
        direction: row.get("direction"),
        src_cidr: row.get("src_cidr"),
        dst_cidr: row.get("dst_cidr"),
        src_port: row.get::<Option<i64>, _>("src_port").map(|p| p as u32),
        dst_port: row.get::<Option<i64>, _>("dst_port").map(|p| p as u32),
        protocol: row.get("protocol"),
        sni_pattern: row.get("sni_pattern"),
        quic_version: row.get("quic_version"),
        src_mac: row.get("src_mac"),
        dst_mac: row.get("dst_mac"),
        actions_json: row.get("actions_json"),
        created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
        created_by: row.get("created_by"),
        expires_after_secs: row
            .get::<Option<i64>, _>("expires_after_secs")
            .map(|s| s as u32),
        schedule_json: row.get("schedule_json"),
    })
}

fn row_to_enrollment_token(row: sqlx::sqlite::SqliteRow) -> Result<EnrollmentTokenRecord> {
    let created_at: i64 = row.get("created_at");
    let expires_at: i64 = row.get("expires_at");
    let revoked_at: Option<i64> = row.get("revoked_at");
    Ok(EnrollmentTokenRecord {
        token_id: row.get("token_id"),
        token_hash: row.get("token_hash"),
        created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
        created_by: row.get("created_by"),
        expires_at: DateTime::from_timestamp(expires_at, 0).unwrap_or_default(),
        uses_remaining: row.get("uses_remaining"),
        cidr_scope: row.get("cidr_scope"),
        fleet_label: row.get("fleet_label"),
        revoked_at: revoked_at.and_then(|t| DateTime::from_timestamp(t, 0)),
        tenant_id: row.get("tenant_id"),
    })
}

fn row_to_suricata_alert(row: sqlx::sqlite::SqliteRow) -> SuricataAlertRecord {
    SuricataAlertRecord {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        node_id: row.get("node_id"),
        timestamp: row.get("timestamp"),
        received_ns: row.get("received_ns"),
        src_ip: row.get("src_ip"),
        src_port: row.get::<Option<i64>, _>("src_port").map(|p| p as i32),
        dst_ip: row.get("dst_ip"),
        dst_port: row.get::<Option<i64>, _>("dst_port").map(|p| p as i32),
        proto: row.get("proto"),
        action: row.get("action"),
        signature_id: row.get("signature_id"),
        signature: row.get("signature"),
        category: row.get("category"),
        severity: row.get::<Option<i64>, _>("severity").map(|s| s as i32),
        raw_json: row.get("raw_json"),
    }
}

fn row_to_suricata_ruleset(row: sqlx::sqlite::SqliteRow) -> Result<SuricataRuleset> {
    let created_at: i64 = row.get("created_at");
    let updated_at: i64 = row.get("updated_at");
    Ok(SuricataRuleset {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        name: row.get("name"),
        content: row.get("content"),
        sha256: row.get("sha256"),
        rule_count: row.get::<i64, _>("rule_count") as u32,
        created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
        updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_default(),
    })
}

fn row_to_node_interface(row: sqlx::sqlite::SqliteRow) -> Result<NodeInterface> {
    let last_reported: i64 = row.get("last_reported");
    Ok(NodeInterface {
        node_id: row.get("node_id"),
        name: row.get("interface_name"),
        ifindex: row.try_get::<i64, _>("ifindex").unwrap_or(0) as u32,
        mac_address: row.get("mac_address"),
        link_state: row.get("link_state"),
        addresses_json: row.get("addresses_json"),
        tag: row.get("tag"),
        last_reported: DateTime::from_timestamp(last_reported, 0).unwrap_or_default(),
        xdp_attached: row.try_get::<bool, _>("xdp_attached").unwrap_or(false),
        tc_attached: row.try_get::<bool, _>("tc_attached").unwrap_or(false),
        fib_forwarding: row.try_get::<bool, _>("fib_forwarding").unwrap_or(false),
        urpf_mode: row.try_get::<i64, _>("urpf_mode").unwrap_or(0) as u32,
        inspect_enabled: row.try_get::<bool, _>("inspect_enabled").unwrap_or(false),
        ingress_default_action: row.try_get("ingress_default_action").unwrap_or(None),
        egress_default_action: row.try_get("egress_default_action").unwrap_or(None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    async fn temp_store() -> (SqliteControllerStore, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = SqliteControllerStore::new(&dir.path().join("controller.db"))
            .await
            .unwrap();
        (store, dir)
    }

    fn sample_node(id: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_string(),
            label: None,
            public_key_der: vec![1, 2, 3],
            dmi_uuid: None,
            status: NodeStatus::Active,
            cert_serial: None,
            cert_expiry: None,
            last_seen: None,
            enrolled_at: Some(Utc::now()),
            decommissioned_at: None,
            last_renewed_at: None,
            enrollment_id: Some(format!("e-{id}")),
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
            inspect_mode: "disabled".to_string(),
        }
    }

    // Regression: the node SELECT column lists must include the operator-config
    // columns row_to_node reads, or get_node/list_nodes silently return None for
    // them (try_get(...).unwrap_or(None)) even after a successful UPDATE.
    #[tokio::test]
    async fn metrics_interval_round_trips_through_sqlite() {
        let (store, _dir) = temp_store().await;
        store.upsert_node(&sample_node("n1")).await.unwrap();

        store
            .update_node_metrics_interval("n1", Some(15))
            .await
            .unwrap();
        assert_eq!(
            store
                .get_node("n1")
                .await
                .unwrap()
                .unwrap()
                .metrics_interval_secs,
            Some(15)
        );
        // …and via the list path (different SELECT).
        let listed = store.list_nodes(Some("default"), None).await.unwrap();
        assert_eq!(listed[0].metrics_interval_secs, Some(15));

        // Clearing the override reads back as None.
        store
            .update_node_metrics_interval("n1", None)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_node("n1")
                .await
                .unwrap()
                .unwrap()
                .metrics_interval_secs,
            None
        );
    }

    // uRPF mode persists per interface and clears interfaces not listed, via
    // both the per-node and list-all SELECT paths.
    #[tokio::test]
    async fn urpf_mode_round_trips_through_sqlite() {
        let (store, _dir) = temp_store().await;
        store.upsert_node(&sample_node("n1")).await.unwrap();
        store
            .upsert_node_interfaces(
                "n1",
                &[
                    InterfaceReport {
                        name: "eth0".to_string(),
                        addresses: vec![],
                        mac_address: String::new(),
                        link_state: "up".to_string(),
                        ifindex: 2,
                    },
                    InterfaceReport {
                        name: "eth1".to_string(),
                        addresses: vec![],
                        mac_address: String::new(),
                        link_state: "up".to_string(),
                        ifindex: 3,
                    },
                ],
            )
            .await
            .unwrap();

        // Default is off (0) for every interface.
        let ifaces = store.list_node_interfaces("n1").await.unwrap();
        assert!(ifaces.iter().all(|i| i.urpf_mode == 0));

        // Set eth0 = strict (2), eth1 = loose (1).
        store
            .update_interface_urpf("n1", &[("eth0".to_string(), 2), ("eth1".to_string(), 1)])
            .await
            .unwrap();
        let ifaces = store.list_node_interfaces("n1").await.unwrap();
        let mode = |name: &str| ifaces.iter().find(|i| i.name == name).unwrap().urpf_mode;
        assert_eq!(mode("eth0"), 2);
        assert_eq!(mode("eth1"), 1);

        // Re-applying with only eth0 listed clears eth1 back to off.
        store
            .update_interface_urpf("n1", &[("eth0".to_string(), 1)])
            .await
            .unwrap();
        let all = store.list_all_node_interfaces(None).await.unwrap();
        let mode = |name: &str| all.iter().find(|i| i.name == name).unwrap().urpf_mode;
        assert_eq!(mode("eth0"), 1);
        assert_eq!(mode("eth1"), 0);
    }

    // Inspect mode + per-interface inspect flags round-trip through the real
    // SQL columns (both the snapshot-writeback replace path and the single-
    // interface commit path).
    #[tokio::test]
    async fn inspect_state_round_trips_through_sqlite() {
        let (store, _dir) = temp_store().await;
        store.upsert_node(&sample_node("n1")).await.unwrap();
        store
            .upsert_node_interfaces(
                "n1",
                &[
                    InterfaceReport {
                        name: "eth0".to_string(),
                        addresses: vec![],
                        mac_address: String::new(),
                        link_state: "up".to_string(),
                        ifindex: 2,
                    },
                    InterfaceReport {
                        name: "eth1".to_string(),
                        addresses: vec![],
                        mac_address: String::new(),
                        link_state: "up".to_string(),
                        ifindex: 3,
                    },
                ],
            )
            .await
            .unwrap();

        // Defaults: mode disabled, no interface flagged.
        assert_eq!(
            store.get_node("n1").await.unwrap().unwrap().inspect_mode,
            "disabled"
        );
        let ifaces = store.list_node_interfaces("n1").await.unwrap();
        assert!(ifaces.iter().all(|i| !i.inspect_enabled));

        // Node-global mode.
        store.set_node_inspect_mode("n1", "ips").await.unwrap();
        assert_eq!(
            store.get_node("n1").await.unwrap().unwrap().inspect_mode,
            "ips"
        );

        // Single-interface commit path.
        store
            .update_interface_inspect_enabled("n1", "eth0", true)
            .await
            .unwrap();
        let flag = |ifaces: &[NodeInterface], name: &str| {
            ifaces
                .iter()
                .find(|i| i.name == name)
                .unwrap()
                .inspect_enabled
        };
        let ifaces = store.list_node_interfaces("n1").await.unwrap();
        assert!(flag(&ifaces, "eth0"));
        assert!(!flag(&ifaces, "eth1"));

        // Snapshot-writeback replace path: only eth1 listed → eth0 cleared.
        store
            .update_interface_inspect("n1", &["eth1".to_string()])
            .await
            .unwrap();
        let ifaces = store.list_node_interfaces("n1").await.unwrap();
        assert!(!flag(&ifaces, "eth0"));
        assert!(flag(&ifaces, "eth1"));
    }

    fn sample_rule(id: &str, node_id: &str) -> Rule {
        Rule {
            id: id.to_string(),
            tenant_id: "default".to_string(),
            node_id: node_id.to_string(),
            interface_name: "enp1s0".to_string(),
            direction: "ingress".to_string(),
            src_cidr: None,
            dst_cidr: Some("1.1.1.1/32".to_string()),
            src_port: None,
            dst_port: None,
            protocol: "icmp".to_string(),
            sni_pattern: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            actions_json: r#"[{"action":"log","priority":0}]"#.to_string(),
            created_at: Utc::now(),
            created_by: Some("operator:admin".to_string()),
            expires_after_secs: None,
            schedule_json: None,
        }
    }

    // Regression: a rule may be persisted twice for the same id — the gated
    // create commits after the agent confirms, but a racing `apply_local_change`
    // can write the same id first. A bare INSERT would fail the commit on the
    // primary-key conflict; create_rule must upsert idempotently and never
    // duplicate the row.
    #[tokio::test]
    async fn create_rule_is_idempotent_upsert() {
        let (store, _dir) = temp_store().await;
        store.upsert_node(&sample_node("n1")).await.unwrap();

        let rule = sample_rule("1718789620123456", "n1");
        store.create_rule(&rule).await.unwrap();
        // Second create with the same id must not error and must not duplicate.
        store.create_rule(&rule).await.unwrap();

        let rules = store.list_rules_for_node("n1").await.unwrap();
        assert_eq!(rules.len(), 1, "duplicate id must collapse to one row");
        assert_eq!(rules[0].dst_cidr.as_deref(), Some("1.1.1.1/32"));

        // An updated payload for the same id overwrites in place (still one row).
        let mut updated = rule.clone();
        updated.protocol = "tcp".to_string();
        updated.dst_port = Some(443);
        store.create_rule(&updated).await.unwrap();
        let rules = store.list_rules_for_node("n1").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].protocol, "tcp");
        assert_eq!(rules[0].dst_port, Some(443));
        // Provenance (created_by) is preserved on conflict — first writer wins.
        assert_eq!(rules[0].created_by.as_deref(), Some("operator:admin"));
    }
}
