// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! DB accessors for alert pipeline tables: `alert_rules`, `receivers`,
//! `silences`, `alert_history`.
//!
//! All entry points take a [`TenantScope`] so multi-tenant isolation is
//! enforced at the type level. Mirrors the pattern in [`super::store`].
//!
//! Validation happens at write time:
//!
//! - `match_json` (and `silences.matcher_json`) are compiled via
//!   [`super::matcher::MatchSpec::compile_json`] so an invalid CIDR or
//!   typo'd field is rejected before the row hits disk.
//! - `group_by` must be a JSON array of allowed low-cardinality field
//!   names (see [`ALLOWED_GROUP_BY_FIELDS`]).
//! - `receiver_ids` must reference receivers that already exist for the
//!   same tenant — prevents dangling references in the dispatcher.
//! - `severity` is one of `info`, `warning`, `critical`.
//! - `kind` (on receivers) is one of `webhook`, `email`, `alertmanager`.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, Transaction};
use std::collections::HashSet;

use super::matcher::MatchSpec;
use super::tenant::TenantScope;

/// Group-by fields the matcher will index over. `sni` and other high-
/// cardinality fields are intentionally excluded — they'd blow up the
/// per-tenant group cap (see docs/event-pipeline.md "Grouping").
pub const ALLOWED_GROUP_BY_FIELDS: &[&str] = &[
    "rule_id",
    "action",
    "proto",
    "node_id",
    "src_ip",
    "dst_ip",
    "sport",
    "dport",
    "direction",
];

pub const ALLOWED_SEVERITIES: &[&str] = &["info", "warning", "critical"];
pub const ALLOWED_RECEIVER_KINDS: &[&str] = &["webhook", "email", "alertmanager"];

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertRule {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub enabled: bool,
    pub match_json: String,
    pub group_by: String,
    /// Both `None` = per-event mode; both `Some` = threshold mode.
    pub threshold_count: Option<i64>,
    pub threshold_window_s: Option<i64>,
    pub group_wait_s: i64,
    pub group_interval_s: i64,
    pub repeat_interval_s: i64,
    pub resolve_after_s: i64,
    pub severity: String,
    pub receiver_ids: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewAlertRule {
    pub name: String,
    pub enabled: bool,
    pub match_json: String,
    pub group_by: Vec<String>,
    pub threshold_count: Option<i64>,
    pub threshold_window_s: Option<i64>,
    pub group_wait_s: i64,
    pub group_interval_s: i64,
    pub repeat_interval_s: i64,
    pub resolve_after_s: i64,
    pub severity: String,
    pub receiver_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receiver {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub kind: String,
    pub config_json: String,
}

#[derive(Debug, Clone)]
pub struct NewReceiver {
    pub name: String,
    pub kind: String,
    /// Provider config; secrets are encrypted at rest at a layer above this
    /// store (see open question 2 in docs/event-pipeline.md).
    pub config_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Silence {
    pub id: i64,
    pub tenant_id: i64,
    pub matcher_json: String,
    pub starts_at: i64,
    pub ends_at: i64,
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewSilence {
    pub matcher_json: String,
    pub starts_at: i64,
    pub ends_at: i64,
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertHistoryEntry {
    pub id: i64,
    pub tenant_id: i64,
    pub rule_id: i64,
    pub group_key: String,
    pub fired_at: i64,
    pub resolved_at: Option<i64>,
    pub event_count: i64,
    pub sample_event_ids: String,
    pub silenced: bool,
}

#[derive(Debug, Clone)]
pub struct NewAlertHistory {
    pub rule_id: i64,
    pub group_key: String,
    pub fired_at: i64,
    pub event_count: i64,
    pub sample_event_ids: Vec<i64>,
    pub silenced: bool,
}

#[derive(Debug, Clone, Default)]
pub struct HistoryFilter {
    pub rule_id: Option<i64>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub cursor: Option<i64>,
}

// ── Store ────────────────────────────────────────────────────────────────────

pub struct AlertStore<'a> {
    scope: &'a TenantScope,
}

impl<'a> AlertStore<'a> {
    pub fn new(scope: &'a TenantScope) -> Self {
        Self { scope }
    }

    // ── alert_rules ─────────────────────────────────────────────────────────

    pub async fn create_rule(&self, input: NewAlertRule, now_s: i64) -> Result<AlertRule> {
        let mut tx = self.scope.pool().begin().await.context("begin")?;
        validate_rule(&input)?;
        validate_receiver_ids_exist(&mut tx, self.scope.tenant_id(), &input.receiver_ids).await?;
        validate_rule_sources(&mut tx, self.scope.slug(), &input).await?;
        let group_by_json = serde_json::to_string(&input.group_by)?;
        let receiver_ids_json = serde_json::to_string(&input.receiver_ids)?;
        let id = sqlx::query(
            r#"
            INSERT INTO alert_rules
                (tenant_id, name, enabled, match_json, group_by,
                 threshold_count, threshold_window_s,
                 group_wait_s, group_interval_s, repeat_interval_s, resolve_after_s,
                 severity, receiver_ids, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            "#,
        )
        .bind(self.scope.tenant_id())
        .bind(&input.name)
        .bind(input.enabled as i64)
        .bind(&input.match_json)
        .bind(&group_by_json)
        .bind(input.threshold_count)
        .bind(input.threshold_window_s)
        .bind(input.group_wait_s)
        .bind(input.group_interval_s)
        .bind(input.repeat_interval_s)
        .bind(input.resolve_after_s)
        .bind(&input.severity)
        .bind(&receiver_ids_json)
        .bind(now_s)
        .bind(now_s)
        .fetch_one(&mut *tx)
        .await
        .context("insert alert_rules")?
        .try_get::<i64, _>("id")?;
        tx.commit().await?;

        self.get_rule(id)
            .await?
            .ok_or_else(|| anyhow!("Inserted alert_rule id={id} not found"))
    }

    pub async fn update_rule(&self, id: i64, input: NewAlertRule, now_s: i64) -> Result<AlertRule> {
        let mut tx = self.scope.pool().begin().await.context("begin")?;
        validate_rule(&input)?;
        validate_receiver_ids_exist(&mut tx, self.scope.tenant_id(), &input.receiver_ids).await?;
        validate_rule_sources(&mut tx, self.scope.slug(), &input).await?;
        let group_by_json = serde_json::to_string(&input.group_by)?;
        let receiver_ids_json = serde_json::to_string(&input.receiver_ids)?;
        let rows = sqlx::query(
            r#"
            UPDATE alert_rules SET
                name = ?, enabled = ?, match_json = ?, group_by = ?,
                threshold_count = ?, threshold_window_s = ?,
                group_wait_s = ?, group_interval_s = ?, repeat_interval_s = ?,
                resolve_after_s = ?, severity = ?, receiver_ids = ?,
                updated_at = ?
            WHERE id = ? AND tenant_id = ?
            "#,
        )
        .bind(&input.name)
        .bind(input.enabled as i64)
        .bind(&input.match_json)
        .bind(&group_by_json)
        .bind(input.threshold_count)
        .bind(input.threshold_window_s)
        .bind(input.group_wait_s)
        .bind(input.group_interval_s)
        .bind(input.repeat_interval_s)
        .bind(input.resolve_after_s)
        .bind(&input.severity)
        .bind(&receiver_ids_json)
        .bind(now_s)
        .bind(id)
        .bind(self.scope.tenant_id())
        .execute(&mut *tx)
        .await
        .context("update alert_rules")?
        .rows_affected();
        tx.commit().await?;
        if rows == 0 {
            bail!(
                "alert_rule id={id} not found in tenant {}",
                self.scope.tenant_id()
            );
        }
        self.get_rule(id)
            .await?
            .ok_or_else(|| anyhow!("alert_rule id={id} disappeared after update"))
    }

    pub async fn delete_rule(&self, id: i64) -> Result<bool> {
        let rows = sqlx::query("DELETE FROM alert_rules WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(self.scope.tenant_id())
            .execute(self.scope.pool())
            .await
            .context("delete alert_rules")?
            .rows_affected();
        Ok(rows > 0)
    }

    pub async fn get_rule(&self, id: i64) -> Result<Option<AlertRule>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, enabled, match_json, group_by, \
                    threshold_count, threshold_window_s, \
                    group_wait_s, group_interval_s, repeat_interval_s, resolve_after_s, \
                    severity, receiver_ids, created_at, updated_at \
             FROM alert_rules WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(self.scope.tenant_id())
        .fetch_optional(self.scope.pool())
        .await
        .context("get alert_rules")?;
        row.map(row_to_rule).transpose()
    }

    pub async fn list_rules(&self) -> Result<Vec<AlertRule>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, enabled, match_json, group_by, \
                    threshold_count, threshold_window_s, \
                    group_wait_s, group_interval_s, repeat_interval_s, resolve_after_s, \
                    severity, receiver_ids, created_at, updated_at \
             FROM alert_rules WHERE tenant_id = ? ORDER BY id ASC",
        )
        .bind(self.scope.tenant_id())
        .fetch_all(self.scope.pool())
        .await
        .context("list alert_rules")?;
        rows.into_iter().map(row_to_rule).collect()
    }

    // ── receivers ──────────────────────────────────────────────────────────

    pub async fn create_receiver(&self, input: NewReceiver) -> Result<Receiver> {
        validate_receiver(&input)?;
        let id = sqlx::query(
            "INSERT INTO receivers (tenant_id, name, kind, config_json) \
             VALUES (?, ?, ?, ?) RETURNING id",
        )
        .bind(self.scope.tenant_id())
        .bind(&input.name)
        .bind(&input.kind)
        .bind(&input.config_json)
        .fetch_one(self.scope.pool())
        .await
        .context("insert receivers")?
        .try_get::<i64, _>("id")?;
        Ok(Receiver {
            id,
            tenant_id: self.scope.tenant_id(),
            name: input.name,
            kind: input.kind,
            config_json: input.config_json,
        })
    }

    pub async fn update_receiver(&self, id: i64, input: NewReceiver) -> Result<Receiver> {
        validate_receiver(&input)?;
        let rows = sqlx::query(
            "UPDATE receivers SET name = ?, kind = ?, config_json = ? \
             WHERE id = ? AND tenant_id = ?",
        )
        .bind(&input.name)
        .bind(&input.kind)
        .bind(&input.config_json)
        .bind(id)
        .bind(self.scope.tenant_id())
        .execute(self.scope.pool())
        .await
        .context("update receivers")?
        .rows_affected();
        if rows == 0 {
            bail!(
                "receiver id={id} not found in tenant {}",
                self.scope.tenant_id()
            );
        }
        Ok(Receiver {
            id,
            tenant_id: self.scope.tenant_id(),
            name: input.name,
            kind: input.kind,
            config_json: input.config_json,
        })
    }

    pub async fn delete_receiver(&self, id: i64) -> Result<bool> {
        // Refuse to orphan an alert_rule's receiver_ids JSON. We could do
        // this via a trigger but the JSON form means the FK has to be
        // checked in code.
        if self.receiver_in_use(id).await? {
            bail!("receiver id={id} is referenced by one or more alert_rules");
        }
        let rows = sqlx::query("DELETE FROM receivers WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(self.scope.tenant_id())
            .execute(self.scope.pool())
            .await
            .context("delete receivers")?
            .rows_affected();
        Ok(rows > 0)
    }

    pub async fn list_receivers(&self) -> Result<Vec<Receiver>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, kind, config_json \
             FROM receivers WHERE tenant_id = ? ORDER BY id ASC",
        )
        .bind(self.scope.tenant_id())
        .fetch_all(self.scope.pool())
        .await
        .context("list receivers")?;
        rows.into_iter().map(row_to_receiver).collect()
    }

    /// Slow path: scans `alert_rules.receiver_ids` JSON arrays for a match.
    /// Fine — delete is a rare operator action, and the JSON layout is
    /// already an opaque blob to SQL.
    async fn receiver_in_use(&self, id: i64) -> Result<bool> {
        let rules = self.list_rules().await?;
        for r in rules {
            let ids: Vec<i64> = serde_json::from_str(&r.receiver_ids)
                .with_context(|| format!("Corrupt receiver_ids on alert_rule {}", r.id))?;
            if ids.contains(&id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ── silences ───────────────────────────────────────────────────────────

    pub async fn create_silence(&self, input: NewSilence) -> Result<Silence> {
        validate_silence(&input)?;
        let id = sqlx::query(
            "INSERT INTO silences \
                (tenant_id, matcher_json, starts_at, ends_at, created_by, comment) \
             VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(self.scope.tenant_id())
        .bind(&input.matcher_json)
        .bind(input.starts_at)
        .bind(input.ends_at)
        .bind(input.created_by.as_deref())
        .bind(input.comment.as_deref())
        .fetch_one(self.scope.pool())
        .await
        .context("insert silences")?
        .try_get::<i64, _>("id")?;
        Ok(Silence {
            id,
            tenant_id: self.scope.tenant_id(),
            matcher_json: input.matcher_json,
            starts_at: input.starts_at,
            ends_at: input.ends_at,
            created_by: input.created_by,
            comment: input.comment,
        })
    }

    pub async fn delete_silence(&self, id: i64) -> Result<bool> {
        let rows = sqlx::query("DELETE FROM silences WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(self.scope.tenant_id())
            .execute(self.scope.pool())
            .await
            .context("delete silences")?
            .rows_affected();
        Ok(rows > 0)
    }

    /// `active_at_s = Some(now)` filters to silences active at that wall
    /// time. `None` returns everything.
    pub async fn list_silences(&self, active_at_s: Option<i64>) -> Result<Vec<Silence>> {
        let rows = match active_at_s {
            None => {
                sqlx::query(
                    "SELECT id, tenant_id, matcher_json, starts_at, ends_at, \
                            created_by, comment \
                     FROM silences WHERE tenant_id = ? ORDER BY id ASC",
                )
                .bind(self.scope.tenant_id())
                .fetch_all(self.scope.pool())
                .await
            }
            Some(now) => {
                sqlx::query(
                    "SELECT id, tenant_id, matcher_json, starts_at, ends_at, \
                            created_by, comment \
                     FROM silences \
                     WHERE tenant_id = ? AND starts_at <= ? AND ends_at > ? \
                     ORDER BY id ASC",
                )
                .bind(self.scope.tenant_id())
                .bind(now)
                .bind(now)
                .fetch_all(self.scope.pool())
                .await
            }
        }
        .context("list silences")?;
        rows.into_iter().map(row_to_silence).collect()
    }

    // ── alert_history ──────────────────────────────────────────────────────

    pub async fn append_history(&self, entry: NewAlertHistory) -> Result<i64> {
        // Cap sample_event_ids at 5 to match alert_history doc-comment.
        let mut samples = entry.sample_event_ids;
        samples.truncate(5);
        let samples_json = serde_json::to_string(&samples)?;
        let id = sqlx::query(
            "INSERT INTO alert_history \
                (tenant_id, rule_id, group_key, fired_at, event_count, \
                 sample_event_ids, silenced) \
             VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(self.scope.tenant_id())
        .bind(entry.rule_id)
        .bind(&entry.group_key)
        .bind(entry.fired_at)
        .bind(entry.event_count)
        .bind(&samples_json)
        .bind(entry.silenced as i64)
        .fetch_one(self.scope.pool())
        .await
        .context("insert alert_history")?
        .try_get::<i64, _>("id")?;
        Ok(id)
    }

    pub async fn resolve_history(&self, id: i64, resolved_at: i64) -> Result<bool> {
        let rows = sqlx::query(
            "UPDATE alert_history SET resolved_at = ? \
             WHERE id = ? AND tenant_id = ? AND resolved_at IS NULL",
        )
        .bind(resolved_at)
        .bind(id)
        .bind(self.scope.tenant_id())
        .execute(self.scope.pool())
        .await
        .context("resolve alert_history")?
        .rows_affected();
        Ok(rows > 0)
    }

    pub async fn list_history(
        &self,
        filter: &HistoryFilter,
        limit: i64,
    ) -> Result<Vec<AlertHistoryEntry>> {
        let mut q = String::from(
            "SELECT id, tenant_id, rule_id, group_key, fired_at, resolved_at, \
                    event_count, sample_event_ids, silenced \
             FROM alert_history WHERE tenant_id = ?",
        );
        if filter.rule_id.is_some() {
            q.push_str(" AND rule_id = ?");
        }
        if filter.since.is_some() {
            q.push_str(" AND fired_at >= ?");
        }
        if filter.until.is_some() {
            q.push_str(" AND fired_at < ?");
        }
        if filter.cursor.is_some() {
            q.push_str(" AND id < ?");
        }
        q.push_str(" ORDER BY id DESC LIMIT ?");

        let mut query = sqlx::query(&q).bind(self.scope.tenant_id());
        if let Some(v) = filter.rule_id {
            query = query.bind(v);
        }
        if let Some(v) = filter.since {
            query = query.bind(v);
        }
        if let Some(v) = filter.until {
            query = query.bind(v);
        }
        if let Some(v) = filter.cursor {
            query = query.bind(v);
        }
        let rows = query
            .bind(limit)
            .fetch_all(self.scope.pool())
            .await
            .context("list alert_history")?;
        rows.into_iter().map(row_to_history).collect()
    }
}

// ── Validation helpers ───────────────────────────────────────────────────────

fn validate_rule(r: &NewAlertRule) -> Result<()> {
    if r.name.trim().is_empty() {
        bail!("alert_rule.name must not be empty");
    }
    // Compile MatchSpec — rejects unknown fields, invalid CIDRs, bad globs.
    MatchSpec::compile_json(&r.match_json).context("invalid match_json")?;
    if r.group_by.is_empty() {
        bail!("alert_rule.group_by must contain at least one field");
    }
    let allowed: HashSet<&str> = ALLOWED_GROUP_BY_FIELDS.iter().copied().collect();
    for f in &r.group_by {
        if !allowed.contains(f.as_str()) {
            bail!("alert_rule.group_by: '{f}' is not an allowed field");
        }
    }
    match (r.threshold_count, r.threshold_window_s) {
        (None, None) => {}              // per-event mode
        (Some(c), Some(w)) if c > 0 && w > 0 => {} // threshold mode
        _ => bail!(
            "threshold_count and threshold_window_s must both be set (with positive values) or both NULL"
        ),
    }
    if !ALLOWED_SEVERITIES.contains(&r.severity.as_str()) {
        bail!(
            "alert_rule.severity '{}' is not one of {:?}",
            r.severity,
            ALLOWED_SEVERITIES
        );
    }
    if r.receiver_ids.is_empty() {
        bail!("alert_rule.receiver_ids must contain at least one receiver");
    }
    for s in [
        ("group_wait_s", r.group_wait_s),
        ("group_interval_s", r.group_interval_s),
        ("repeat_interval_s", r.repeat_interval_s),
        ("resolve_after_s", r.resolve_after_s),
    ] {
        if s.1 <= 0 {
            bail!("{} must be positive (got {})", s.0, s.1);
        }
    }
    Ok(())
}

fn validate_receiver(r: &NewReceiver) -> Result<()> {
    if r.name.trim().is_empty() {
        bail!("receiver.name must not be empty");
    }
    if !ALLOWED_RECEIVER_KINDS.contains(&r.kind.as_str()) {
        bail!(
            "receiver.kind '{}' is not one of {:?}",
            r.kind,
            ALLOWED_RECEIVER_KINDS
        );
    }
    // Just check it parses — provider-specific schema is the provider's job.
    serde_json::from_str::<serde_json::Value>(&r.config_json)
        .context("receiver.config_json is not valid JSON")?;
    Ok(())
}

fn validate_silence(s: &NewSilence) -> Result<()> {
    MatchSpec::compile_json(&s.matcher_json).context("invalid silence.matcher_json")?;
    if s.ends_at <= s.starts_at {
        bail!("silence.ends_at must be after starts_at");
    }
    Ok(())
}

/// Reject rules that reference an event source no node in the fleet
/// advertises in its `Capabilities.sources`. An empty fleet (zero Active
/// nodes) is treated as "validation skipped" so bootstrap (creating rules
/// before the first agent enrolls) still works — the operator will see
/// rules sit idle until a capable node comes online, which is the same
/// failure mode as a typo in `match_json`.
async fn validate_rule_sources(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_slug: &str,
    rule: &NewAlertRule,
) -> Result<()> {
    let required = required_sources_for_rule(rule);
    // Nodes are scoped by the slug column on the `nodes` table (TEXT,
    // default "default"), not the i64 FK used inside the event-pipeline
    // tables — those are two distinct identifiers.
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT capabilities FROM nodes WHERE tenant_id = ? AND status = 'active'")
            .bind(tenant_slug)
            .fetch_all(&mut **tx)
            .await
            .context("load fleet capabilities")?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut advertised: HashSet<String> = HashSet::new();
    for (json,) in &rows {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
            continue;
        };
        if let Some(arr) = v.get("sources").and_then(|s| s.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    advertised.insert(s.to_string());
                }
            }
        }
    }
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|s| !advertised.contains(*s))
        .collect();
    if !missing.is_empty() {
        bail!(
            "alert rule references source(s) {:?} that no node in tenant '{}' advertises (advertised: {:?})",
            missing,
            tenant_slug,
            advertised
        );
    }
    Ok(())
}

/// What event sources does this rule need to ever fire? Today every
/// `match_json` field maps to PolicyEvents, so the answer is always
/// `{"policy_events"}`. When ipfix/suricata/quic-inspect MatchSpec
/// variants land, branch here.
///
/// Suricata alerts are persisted and streamed (`/ws/alerts`,
/// `suricataAlerts` query) but are not yet a MatchSpec source — matching
/// alert *rules* on signature/severity needs a new MatchSpec variant and a
/// matcher branch over the alert channel. When that lands, a rule referencing
/// suricata fields must return `"suricata_alerts"` here so the capability-
/// union validation (agents already advertise the source) gates it.
fn required_sources_for_rule(_rule: &NewAlertRule) -> Vec<&'static str> {
    vec!["policy_events"]
}

async fn validate_receiver_ids_exist(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: i64,
    ids: &[i64],
) -> Result<()> {
    for id in ids {
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT id FROM receivers WHERE id = ? AND tenant_id = ?")
                .bind(id)
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await
                .context("validate receiver id")?;
        if exists.is_none() {
            bail!("receiver id={id} does not exist in tenant {tenant_id}");
        }
    }
    Ok(())
}

// ── Row → struct ─────────────────────────────────────────────────────────────

fn row_to_rule(r: sqlx::sqlite::SqliteRow) -> Result<AlertRule> {
    Ok(AlertRule {
        id: r.try_get("id")?,
        tenant_id: r.try_get("tenant_id")?,
        name: r.try_get("name")?,
        enabled: r.try_get::<i64, _>("enabled")? != 0,
        match_json: r.try_get("match_json")?,
        group_by: r.try_get("group_by")?,
        threshold_count: r.try_get("threshold_count")?,
        threshold_window_s: r.try_get("threshold_window_s")?,
        group_wait_s: r.try_get("group_wait_s")?,
        group_interval_s: r.try_get("group_interval_s")?,
        repeat_interval_s: r.try_get("repeat_interval_s")?,
        resolve_after_s: r.try_get("resolve_after_s")?,
        severity: r.try_get("severity")?,
        receiver_ids: r.try_get("receiver_ids")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

fn row_to_receiver(r: sqlx::sqlite::SqliteRow) -> Result<Receiver> {
    Ok(Receiver {
        id: r.try_get("id")?,
        tenant_id: r.try_get("tenant_id")?,
        name: r.try_get("name")?,
        kind: r.try_get("kind")?,
        config_json: r.try_get("config_json")?,
    })
}

fn row_to_silence(r: sqlx::sqlite::SqliteRow) -> Result<Silence> {
    Ok(Silence {
        id: r.try_get("id")?,
        tenant_id: r.try_get("tenant_id")?,
        matcher_json: r.try_get("matcher_json")?,
        starts_at: r.try_get("starts_at")?,
        ends_at: r.try_get("ends_at")?,
        created_by: r.try_get("created_by")?,
        comment: r.try_get("comment")?,
    })
}

fn row_to_history(r: sqlx::sqlite::SqliteRow) -> Result<AlertHistoryEntry> {
    Ok(AlertHistoryEntry {
        id: r.try_get("id")?,
        tenant_id: r.try_get("tenant_id")?,
        rule_id: r.try_get("rule_id")?,
        group_key: r.try_get("group_key")?,
        fired_at: r.try_get("fired_at")?,
        resolved_at: r.try_get("resolved_at")?,
        event_count: r.try_get("event_count")?,
        sample_event_ids: r.try_get("sample_event_ids")?,
        silenced: r.try_get::<i64, _>("silenced")? != 0,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::bootstrap_default_tenant;
    use sqlx::sqlite::SqlitePool;

    async fn scope() -> TenantScope {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        bootstrap_default_tenant(pool).await.unwrap()
    }

    fn rcv(name: &str) -> NewReceiver {
        NewReceiver {
            name: name.into(),
            kind: "webhook".into(),
            config_json: r#"{"url":"https://hooks.example/abc"}"#.into(),
        }
    }

    fn rule(name: &str, receiver_id: i64) -> NewAlertRule {
        NewAlertRule {
            name: name.into(),
            enabled: true,
            match_json: r#"{"action":["drop"]}"#.into(),
            group_by: vec!["rule_id".into()],
            threshold_count: None,
            threshold_window_s: None,
            group_wait_s: 30,
            group_interval_s: 300,
            repeat_interval_s: 14_400,
            resolve_after_s: 1_500,
            severity: "warning".into(),
            receiver_ids: vec![receiver_id],
        }
    }

    #[tokio::test]
    async fn receivers_create_list_update_delete() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        assert_eq!(r.name, "ops");
        let all = store.list_receivers().await.unwrap();
        assert_eq!(all.len(), 1);
        let updated = store
            .update_receiver(
                r.id,
                NewReceiver {
                    name: "ops2".into(),
                    ..rcv("_")
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "ops2");
        assert!(store.delete_receiver(r.id).await.unwrap());
        assert_eq!(store.list_receivers().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn cannot_create_rule_with_unknown_receiver() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let err = store.create_rule(rule("r1", 999), 0).await.unwrap_err();
        assert!(err.to_string().contains("receiver id=999"));
    }

    #[tokio::test]
    async fn cannot_delete_receiver_in_use() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        store.create_rule(rule("r1", r.id), 0).await.unwrap();
        let err = store.delete_receiver(r.id).await.unwrap_err();
        assert!(err.to_string().contains("referenced"));
    }

    #[tokio::test]
    async fn rule_round_trip_and_update() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        let rule_row = store.create_rule(rule("r1", r.id), 100).await.unwrap();
        assert_eq!(rule_row.name, "r1");
        assert_eq!(rule_row.created_at, 100);
        assert_eq!(rule_row.updated_at, 100);

        let mut updated_input = rule("r1", r.id);
        updated_input.enabled = false;
        updated_input.severity = "critical".into();
        let updated = store
            .update_rule(rule_row.id, updated_input, 200)
            .await
            .unwrap();
        assert!(!updated.enabled);
        assert_eq!(updated.severity, "critical");
        assert_eq!(updated.created_at, 100); // unchanged
        assert_eq!(updated.updated_at, 200);

        assert!(store.delete_rule(rule_row.id).await.unwrap());
        assert!(store.get_rule(rule_row.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rule_validation_rejects_bad_inputs() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();

        // Bad MatchSpec — typo'd field.
        let mut bad = rule("r1", r.id);
        bad.match_json = r#"{"actoin":["drop"]}"#.into();
        assert!(store.create_rule(bad, 0).await.is_err());

        // Disallowed group_by field.
        let mut bad = rule("r1", r.id);
        bad.group_by = vec!["sni".into()];
        let err = store.create_rule(bad, 0).await.unwrap_err();
        assert!(err.to_string().contains("not an allowed field"));

        // Unknown severity.
        let mut bad = rule("r1", r.id);
        bad.severity = "panic".into();
        assert!(store.create_rule(bad, 0).await.is_err());

        // Half-set threshold mode.
        let mut bad = rule("r1", r.id);
        bad.threshold_count = Some(5);
        let err = store.create_rule(bad, 0).await.unwrap_err();
        assert!(err.to_string().contains("threshold"));

        // Empty receiver_ids.
        let mut bad = rule("r1", r.id);
        bad.receiver_ids = vec![];
        assert!(store.create_rule(bad, 0).await.is_err());

        // Non-positive timing.
        let mut bad = rule("r1", r.id);
        bad.group_wait_s = 0;
        assert!(store.create_rule(bad, 0).await.is_err());
    }

    #[tokio::test]
    async fn unique_constraint_on_rule_name_per_tenant() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        store.create_rule(rule("r1", r.id), 0).await.unwrap();
        let err = store.create_rule(rule("r1", r.id), 0).await.unwrap_err();
        let msg = format!("{err:#}").to_lowercase();
        assert!(
            msg.contains("unique") || msg.contains("constraint"),
            "expected unique-constraint error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn silences_active_filter() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let s_old = store
            .create_silence(NewSilence {
                matcher_json: r#"{"action":["drop"]}"#.into(),
                starts_at: 0,
                ends_at: 100,
                created_by: None,
                comment: None,
            })
            .await
            .unwrap();
        let _s_now = store
            .create_silence(NewSilence {
                matcher_json: r#"{"action":["log"]}"#.into(),
                starts_at: 50,
                ends_at: 500,
                created_by: Some("alice".into()),
                comment: Some("maintenance".into()),
            })
            .await
            .unwrap();
        let all = store.list_silences(None).await.unwrap();
        assert_eq!(all.len(), 2);
        let active = store.list_silences(Some(200)).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_ne!(active[0].id, s_old.id);
    }

    #[tokio::test]
    async fn silence_validation() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let err = store
            .create_silence(NewSilence {
                matcher_json: r#"{"actoin":["drop"]}"#.into(),
                starts_at: 0,
                ends_at: 100,
                created_by: None,
                comment: None,
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("matcher_json"));

        let err = store
            .create_silence(NewSilence {
                matcher_json: "{}".into(),
                starts_at: 100,
                ends_at: 100,
                created_by: None,
                comment: None,
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ends_at"));
    }

    #[tokio::test]
    async fn history_append_list_resolve() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        let rule_row = store.create_rule(rule("r1", r.id), 0).await.unwrap();
        let h1 = store
            .append_history(NewAlertHistory {
                rule_id: rule_row.id,
                group_key: "k1".into(),
                fired_at: 1_000,
                event_count: 3,
                sample_event_ids: vec![1, 2, 3, 4, 5, 6, 7], // capped to 5
                silenced: false,
            })
            .await
            .unwrap();
        let _h2 = store
            .append_history(NewAlertHistory {
                rule_id: rule_row.id,
                group_key: "k2".into(),
                fired_at: 2_000,
                event_count: 1,
                sample_event_ids: vec![10],
                silenced: true,
            })
            .await
            .unwrap();
        let all = store
            .list_history(&HistoryFilter::default(), 100)
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        // Newest first.
        assert_eq!(all[0].fired_at, 2_000);
        // sample cap honoured.
        let stored: Vec<i64> = serde_json::from_str(&all[1].sample_event_ids).unwrap();
        assert_eq!(stored, vec![1, 2, 3, 4, 5]);

        assert!(store.resolve_history(h1, 3_000).await.unwrap());
        // Idempotent: a second resolve on the same id is a no-op (resolved_at
        // is already non-null).
        assert!(!store.resolve_history(h1, 4_000).await.unwrap());
    }

    #[tokio::test]
    async fn history_filter_by_rule_and_time() {
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        let r1 = store.create_rule(rule("r1", r.id), 0).await.unwrap();
        let r2 = store.create_rule(rule("r2", r.id), 0).await.unwrap();
        for &(rid, t) in &[(r1.id, 100), (r1.id, 200), (r2.id, 150)] {
            store
                .append_history(NewAlertHistory {
                    rule_id: rid,
                    group_key: "k".into(),
                    fired_at: t,
                    event_count: 1,
                    sample_event_ids: vec![],
                    silenced: false,
                })
                .await
                .unwrap();
        }
        let only_r1 = store
            .list_history(
                &HistoryFilter {
                    rule_id: Some(r1.id),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(only_r1.len(), 2);
        let window = store
            .list_history(
                &HistoryFilter {
                    since: Some(150),
                    until: Some(200),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(window.len(), 1);
        assert_eq!(window[0].fired_at, 150);
    }

    /// Insert a minimally-valid `nodes` row with the given capabilities
    /// JSON. The other columns are required NOT NULL — we set just enough
    /// to satisfy the schema. Used by the source-validation tests.
    async fn insert_active_node(scope: &TenantScope, id: &str, capabilities_json: &str) {
        sqlx::query(
            "INSERT INTO nodes (id, public_key_der, status, tenant_id, capabilities) \
             VALUES (?, '00', 'active', ?, ?)",
        )
        .bind(id)
        .bind(scope.slug())
        .bind(capabilities_json)
        .execute(scope.pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rule_create_skipped_when_fleet_empty() {
        // No nodes at all → validation is a no-op so bootstrap works.
        let s = scope().await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        store.create_rule(rule("r1", r.id), 0).await.unwrap();
    }

    #[tokio::test]
    async fn rule_create_passes_when_a_node_advertises_source() {
        let s = scope().await;
        insert_active_node(&s, "n1", r#"{"sources":["policy_events"]}"#).await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        store.create_rule(rule("r1", r.id), 0).await.unwrap();
    }

    #[tokio::test]
    async fn rule_create_rejected_when_no_node_advertises_source() {
        let s = scope().await;
        // The only node speaks ipfix but not policy_events.
        insert_active_node(&s, "n1", r#"{"sources":["ipfix"]}"#).await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        let err = store.create_rule(rule("r1", r.id), 0).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("policy_events"),
            "expected error to mention the missing source, got: {msg}"
        );
    }

    #[tokio::test]
    async fn rule_update_revalidates_against_fleet() {
        let s = scope().await;
        // Fleet starts capable, rule is created, then fleet is replaced
        // with a non-capable node — update must reject.
        insert_active_node(&s, "n1", r#"{"sources":["policy_events"]}"#).await;
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        let created = store.create_rule(rule("r1", r.id), 0).await.unwrap();
        // Swap the node out for one that no longer advertises the source.
        sqlx::query("UPDATE nodes SET capabilities = ? WHERE id = ?")
            .bind(r#"{"sources":["ipfix"]}"#)
            .bind("n1")
            .execute(s.pool())
            .await
            .unwrap();
        let err = store
            .update_rule(created.id, rule("r1-renamed", r.id), 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("policy_events"));
    }

    #[tokio::test]
    async fn rule_create_ignores_pending_nodes() {
        // Only Active nodes count toward the advertised set — a Pending
        // node enrolling for the first time mustn't satisfy validation
        // since it can't actually forward events yet.
        let s = scope().await;
        sqlx::query(
            "INSERT INTO nodes (id, public_key_der, status, tenant_id, capabilities) \
             VALUES ('n_pending', '00', 'pending', ?, ?)",
        )
        .bind(s.slug())
        .bind(r#"{"sources":["policy_events"]}"#)
        .execute(s.pool())
        .await
        .unwrap();
        let store = AlertStore::new(&s);
        let r = store.create_receiver(rcv("ops")).await.unwrap();
        // With zero *Active* nodes the helper treats the fleet as empty
        // and skips validation — bootstrap-friendly. The rule is accepted.
        store.create_rule(rule("r1", r.id), 0).await.unwrap();
    }
}
