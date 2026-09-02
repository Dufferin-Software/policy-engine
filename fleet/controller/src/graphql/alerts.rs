// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! GraphQL surface for the alert pipeline.
//!
//! Read paths (`alert_rules`, `receivers`, `silences`, `alert_history`)
//! delegate to [`crate::event_pipeline::alert_store::AlertStore`]; write
//! paths additionally publish on [`AlertRuleBus`] so the in-process matcher
//! can hot-reload affected rules (docs/event-pipeline.md "Hot reload").
//!
//! `match_json` / `matcher_json` / `config_json` cross the wire as raw JSON
//! strings rather than nested input objects: it keeps the GraphQL surface
//! stable as the MatchSpec evolves and matches what the store actually
//! persists.

use async_graphql::{Context, InputObject, Result, SimpleObject, ID};
use chrono::{DateTime, TimeZone, Utc};
use std::sync::Arc;

use crate::{
    event_pipeline::{
        alert_bus::{AlertRuleBus, AlertRuleChange},
        alert_store::{
            AlertHistoryEntry, AlertRule, AlertStore, HistoryFilter, NewAlertHistory, NewAlertRule,
            NewReceiver, NewSilence, Receiver, Silence,
        },
        TenantScope,
    },
    rbac::Principal,
};

/// Build a per-request [`TenantScope`] from the schema-level singleton
/// (which carries the pool) and the request's [`Principal`] (which
/// carries the tenant id + slug). Resolvers use this instead of grabbing
/// the schema-level scope directly so they isolate to the caller's tenant.
fn scope_for(ctx: &Context<'_>) -> Result<TenantScope> {
    let base = ctx.data::<Arc<TenantScope>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    Ok(base.for_principal(principal))
}

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(SimpleObject, Clone)]
pub struct AlertRuleOutput {
    pub id: ID,
    pub name: String,
    pub enabled: bool,
    pub match_json: String,
    pub group_by: Vec<String>,
    pub threshold_count: Option<i32>,
    pub threshold_window_s: Option<i32>,
    pub group_wait_s: i32,
    pub group_interval_s: i32,
    pub repeat_interval_s: i32,
    pub resolve_after_s: i32,
    pub severity: String,
    pub receiver_ids: Vec<ID>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(SimpleObject, Clone)]
pub struct ReceiverOutput {
    pub id: ID,
    pub name: String,
    pub kind: String,
    pub config_json: String,
}

#[derive(SimpleObject, Clone)]
pub struct SilenceOutput {
    pub id: ID,
    pub matcher_json: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct AlertHistoryOutput {
    pub id: ID,
    pub rule_id: ID,
    pub group_key: String,
    pub fired_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub event_count: i32,
    pub sample_event_ids: Vec<ID>,
    pub silenced: bool,
}

#[derive(SimpleObject, Clone)]
pub struct AlertHistoryConnection {
    pub items: Vec<AlertHistoryOutput>,
    /// `id` of the oldest item in this page; pass as `cursor` for the next
    /// page (returns rows with smaller IDs). `None` when no more rows.
    pub next_cursor: Option<String>,
}

// ── Input types ──────────────────────────────────────────────────────────────

#[derive(InputObject)]
pub struct CreateAlertRuleInput {
    pub name: String,
    #[graphql(default = true)]
    pub enabled: bool,
    /// MatchSpec wire JSON; validated server-side via `MatchSpec::compile_json`.
    pub match_json: String,
    pub group_by: Vec<String>,
    pub threshold_count: Option<i32>,
    pub threshold_window_s: Option<i32>,
    #[graphql(default = 30)]
    pub group_wait_s: i32,
    #[graphql(default = 300)]
    pub group_interval_s: i32,
    #[graphql(default = 14400)]
    pub repeat_interval_s: i32,
    #[graphql(default = 1500)]
    pub resolve_after_s: i32,
    /// One of `info`, `warning`, `critical`.
    pub severity: String,
    pub receiver_ids: Vec<ID>,
}

#[derive(InputObject)]
pub struct CreateReceiverInput {
    pub name: String,
    /// One of `webhook`, `email`, `alertmanager`.
    pub kind: String,
    /// Provider-specific config JSON (e.g. `{"url": "https://..."}` for
    /// webhook).
    pub config_json: String,
}

#[derive(InputObject)]
pub struct CreateSilenceInput {
    pub matcher_json: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub comment: Option<String>,
}

#[derive(InputObject, Default)]
pub struct AlertHistoryFilterInput {
    pub rule_id: Option<ID>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

// ── Conversions ──────────────────────────────────────────────────────────────

impl TryFrom<AlertRule> for AlertRuleOutput {
    type Error = async_graphql::Error;
    fn try_from(r: AlertRule) -> Result<Self> {
        let group_by: Vec<String> = serde_json::from_str(&r.group_by)
            .map_err(|e| async_graphql::Error::new(format!("Corrupt group_by: {e}")))?;
        let receiver_ids: Vec<i64> = serde_json::from_str(&r.receiver_ids)
            .map_err(|e| async_graphql::Error::new(format!("Corrupt receiver_ids: {e}")))?;
        Ok(AlertRuleOutput {
            id: ID(r.id.to_string()),
            name: r.name,
            enabled: r.enabled,
            match_json: r.match_json,
            group_by,
            threshold_count: r.threshold_count.map(|v| v as i32),
            threshold_window_s: r.threshold_window_s.map(|v| v as i32),
            group_wait_s: r.group_wait_s as i32,
            group_interval_s: r.group_interval_s as i32,
            repeat_interval_s: r.repeat_interval_s as i32,
            resolve_after_s: r.resolve_after_s as i32,
            severity: r.severity,
            receiver_ids: receiver_ids
                .into_iter()
                .map(|id| ID(id.to_string()))
                .collect(),
            created_at: Utc
                .timestamp_opt(r.created_at, 0)
                .single()
                .unwrap_or_else(Utc::now),
            updated_at: Utc
                .timestamp_opt(r.updated_at, 0)
                .single()
                .unwrap_or_else(Utc::now),
        })
    }
}

impl From<Receiver> for ReceiverOutput {
    fn from(r: Receiver) -> Self {
        Self {
            id: ID(r.id.to_string()),
            name: r.name,
            kind: r.kind,
            config_json: r.config_json,
        }
    }
}

impl From<Silence> for SilenceOutput {
    fn from(s: Silence) -> Self {
        Self {
            id: ID(s.id.to_string()),
            matcher_json: s.matcher_json,
            starts_at: Utc
                .timestamp_opt(s.starts_at, 0)
                .single()
                .unwrap_or_else(Utc::now),
            ends_at: Utc
                .timestamp_opt(s.ends_at, 0)
                .single()
                .unwrap_or_else(Utc::now),
            created_by: s.created_by,
            comment: s.comment,
        }
    }
}

impl TryFrom<AlertHistoryEntry> for AlertHistoryOutput {
    type Error = async_graphql::Error;
    fn try_from(h: AlertHistoryEntry) -> Result<Self> {
        let samples: Vec<i64> = serde_json::from_str(&h.sample_event_ids)
            .map_err(|e| async_graphql::Error::new(format!("Corrupt sample_event_ids: {e}")))?;
        Ok(Self {
            id: ID(h.id.to_string()),
            rule_id: ID(h.rule_id.to_string()),
            group_key: h.group_key,
            fired_at: Utc
                .timestamp_opt(h.fired_at, 0)
                .single()
                .unwrap_or_else(Utc::now),
            resolved_at: h.resolved_at.and_then(|t| Utc.timestamp_opt(t, 0).single()),
            event_count: h.event_count as i32,
            sample_event_ids: samples.into_iter().map(|i| ID(i.to_string())).collect(),
            silenced: h.silenced,
        })
    }
}

impl CreateAlertRuleInput {
    fn into_new(self) -> Result<NewAlertRule> {
        let receiver_ids = self
            .receiver_ids
            .into_iter()
            .map(|id| {
                id.0.parse::<i64>()
                    .map_err(|e| async_graphql::Error::new(format!("Invalid receiver id: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(NewAlertRule {
            name: self.name,
            enabled: self.enabled,
            match_json: self.match_json,
            group_by: self.group_by,
            threshold_count: self.threshold_count.map(|v| v as i64),
            threshold_window_s: self.threshold_window_s.map(|v| v as i64),
            group_wait_s: self.group_wait_s as i64,
            group_interval_s: self.group_interval_s as i64,
            repeat_interval_s: self.repeat_interval_s as i64,
            resolve_after_s: self.resolve_after_s as i64,
            severity: self.severity,
            receiver_ids,
        })
    }
}

fn parse_id(id: &ID, field: &str) -> Result<i64> {
    id.0.parse::<i64>()
        .map_err(|e| async_graphql::Error::new(format!("Invalid {field}: {e}")))
}

fn now_unix_s() -> i64 {
    Utc::now().timestamp()
}

// ── Query resolvers ──────────────────────────────────────────────────────────

pub async fn resolve_alert_rules(ctx: &Context<'_>) -> Result<Vec<AlertRuleOutput>> {
    let scope = scope_for(ctx)?;
    AlertStore::new(&scope)
        .list_rules()
        .await?
        .into_iter()
        .map(AlertRuleOutput::try_from)
        .collect()
}

pub async fn resolve_receivers(ctx: &Context<'_>) -> Result<Vec<ReceiverOutput>> {
    let scope = scope_for(ctx)?;
    Ok(AlertStore::new(&scope)
        .list_receivers()
        .await?
        .into_iter()
        .map(ReceiverOutput::from)
        .collect())
}

pub async fn resolve_silences(
    ctx: &Context<'_>,
    active: Option<bool>,
) -> Result<Vec<SilenceOutput>> {
    let scope = scope_for(ctx)?;
    let active_at = if active == Some(true) {
        Some(now_unix_s())
    } else {
        None
    };
    Ok(AlertStore::new(&scope)
        .list_silences(active_at)
        .await?
        .into_iter()
        .map(SilenceOutput::from)
        .collect())
}

const HISTORY_MAX_LIMIT: i32 = 1_000;

pub async fn resolve_alert_history(
    ctx: &Context<'_>,
    filter: Option<AlertHistoryFilterInput>,
    limit: Option<i32>,
    cursor: Option<String>,
) -> Result<AlertHistoryConnection> {
    let scope = scope_for(ctx)?;
    let filter = filter.unwrap_or_default();
    let rule_id = filter
        .rule_id
        .as_ref()
        .map(|id| parse_id(id, "rule_id"))
        .transpose()?;
    let cursor_id = cursor
        .map(|c| c.parse::<i64>())
        .transpose()
        .map_err(|e| async_graphql::Error::new(format!("Invalid cursor: {e}")))?;
    let internal = HistoryFilter {
        rule_id,
        since: filter.since.map(|t| t.timestamp()),
        until: filter.until.map(|t| t.timestamp()),
        cursor: cursor_id,
    };
    let limit = limit.unwrap_or(100).clamp(1, HISTORY_MAX_LIMIT) as i64;
    let rows = AlertStore::new(&scope)
        .list_history(&internal, limit)
        .await?;
    let next_cursor = rows.last().map(|r| r.id.to_string());
    let items = rows
        .into_iter()
        .map(AlertHistoryOutput::try_from)
        .collect::<Result<Vec<_>>>()?;
    Ok(AlertHistoryConnection { items, next_cursor })
}

// ── Mutation resolvers ───────────────────────────────────────────────────────

pub async fn resolve_create_alert_rule(
    ctx: &Context<'_>,
    input: CreateAlertRuleInput,
) -> Result<AlertRuleOutput> {
    let scope = scope_for(ctx)?;
    let bus = ctx.data::<Arc<AlertRuleBus>>()?;
    let new = input.into_new()?;
    let row = AlertStore::new(&scope)
        .create_rule(new, now_unix_s())
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    bus.publish(AlertRuleChange::Created(row.id));
    AlertRuleOutput::try_from(row)
}

pub async fn resolve_update_alert_rule(
    ctx: &Context<'_>,
    id: ID,
    input: CreateAlertRuleInput,
) -> Result<AlertRuleOutput> {
    let scope = scope_for(ctx)?;
    let bus = ctx.data::<Arc<AlertRuleBus>>()?;
    let rid = parse_id(&id, "id")?;
    let new = input.into_new()?;
    let row = AlertStore::new(&scope)
        .update_rule(rid, new, now_unix_s())
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    bus.publish(AlertRuleChange::Updated(row.id));
    AlertRuleOutput::try_from(row)
}

pub async fn resolve_delete_alert_rule(ctx: &Context<'_>, id: ID) -> Result<bool> {
    let scope = scope_for(ctx)?;
    let bus = ctx.data::<Arc<AlertRuleBus>>()?;
    let rid = parse_id(&id, "id")?;
    let removed = AlertStore::new(&scope).delete_rule(rid).await?;
    if removed {
        bus.publish(AlertRuleChange::Deleted(rid));
    }
    Ok(removed)
}

pub async fn resolve_create_receiver(
    ctx: &Context<'_>,
    input: CreateReceiverInput,
) -> Result<ReceiverOutput> {
    let scope = scope_for(ctx)?;
    let row = AlertStore::new(&scope)
        .create_receiver(NewReceiver {
            name: input.name,
            kind: input.kind,
            config_json: input.config_json,
        })
        .await?;
    Ok(row.into())
}

pub async fn resolve_update_receiver(
    ctx: &Context<'_>,
    id: ID,
    input: CreateReceiverInput,
) -> Result<ReceiverOutput> {
    let scope = scope_for(ctx)?;
    let rid = parse_id(&id, "id")?;
    let row = AlertStore::new(&scope)
        .update_receiver(
            rid,
            NewReceiver {
                name: input.name,
                kind: input.kind,
                config_json: input.config_json,
            },
        )
        .await?;
    Ok(row.into())
}

pub async fn resolve_delete_receiver(ctx: &Context<'_>, id: ID) -> Result<bool> {
    let scope = scope_for(ctx)?;
    let rid = parse_id(&id, "id")?;
    Ok(AlertStore::new(&scope).delete_receiver(rid).await?)
}

pub async fn resolve_create_silence(
    ctx: &Context<'_>,
    input: CreateSilenceInput,
) -> Result<SilenceOutput> {
    let scope = scope_for(ctx)?;
    let row = AlertStore::new(&scope)
        .create_silence(NewSilence {
            matcher_json: input.matcher_json,
            starts_at: input.starts_at.timestamp(),
            ends_at: input.ends_at.timestamp(),
            created_by: input.created_by,
            comment: input.comment,
        })
        .await?;
    Ok(row.into())
}

pub async fn resolve_delete_silence(ctx: &Context<'_>, id: ID) -> Result<bool> {
    let scope = scope_for(ctx)?;
    let sid = parse_id(&id, "id")?;
    Ok(AlertStore::new(&scope).delete_silence(sid).await?)
}

// Internal helper exposed for the dispatcher (step-4 follow-up). Not
// wired into the GraphQL surface — operators never write history directly.
#[allow(dead_code)]
pub async fn append_history_internal(scope: &TenantScope, entry: NewAlertHistory) -> Result<i64> {
    AlertStore::new(scope)
        .append_history(entry)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::bootstrap_default_tenant;
    use async_graphql::{EmptySubscription, Object, Schema};
    use sqlx::sqlite::SqlitePool;

    // Mini-schema that only exposes the alert resolvers. Lets us test the
    // alert surface without dragging in the controller's full schema
    // (nodes, sessions, pending — none of which are relevant here).
    struct Q;
    #[Object]
    impl Q {
        async fn alert_rules(&self, ctx: &Context<'_>) -> Result<Vec<AlertRuleOutput>> {
            resolve_alert_rules(ctx).await
        }
        async fn receivers(&self, ctx: &Context<'_>) -> Result<Vec<ReceiverOutput>> {
            resolve_receivers(ctx).await
        }
        async fn silences(
            &self,
            ctx: &Context<'_>,
            active: Option<bool>,
        ) -> Result<Vec<SilenceOutput>> {
            resolve_silences(ctx, active).await
        }
    }

    struct M;
    #[Object]
    impl M {
        async fn create_alert_rule(
            &self,
            ctx: &Context<'_>,
            input: CreateAlertRuleInput,
        ) -> Result<AlertRuleOutput> {
            resolve_create_alert_rule(ctx, input).await
        }
        async fn delete_alert_rule(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
            resolve_delete_alert_rule(ctx, id).await
        }
        async fn create_receiver(
            &self,
            ctx: &Context<'_>,
            input: CreateReceiverInput,
        ) -> Result<ReceiverOutput> {
            resolve_create_receiver(ctx, input).await
        }
        async fn create_silence(
            &self,
            ctx: &Context<'_>,
            input: CreateSilenceInput,
        ) -> Result<SilenceOutput> {
            resolve_create_silence(ctx, input).await
        }
    }

    async fn schema_with_data() -> (Schema<Q, M, EmptySubscription>, Arc<AlertRuleBus>) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let scope = Arc::new(bootstrap_default_tenant(pool).await.unwrap());
        let bus = Arc::new(AlertRuleBus::new());
        let principal = Arc::new(Principal::test_admin());
        let schema = Schema::build(Q, M, EmptySubscription)
            .data(scope)
            .data(Arc::clone(&bus))
            .data(principal)
            .finish();
        (schema, bus)
    }

    fn ok_data(resp: async_graphql::Response) -> serde_json::Value {
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        serde_json::to_value(&resp.data).unwrap()
    }

    #[tokio::test]
    async fn create_receiver_then_rule_round_trip_publishes_on_bus() {
        let (schema, bus) = schema_with_data().await;
        let mut rx = bus.subscribe();

        let resp = schema
            .execute(
                r#"mutation { createReceiver(input: {
                       name: "ops", kind: "webhook",
                       configJson: "{\"url\":\"https://hooks.example/x\"}"
                   }) { id name kind } }"#,
            )
            .await;
        let data = ok_data(resp);
        let rcv_id = data["createReceiver"]["id"].as_str().unwrap().to_string();

        let resp = schema
            .execute(format!(
                r#"mutation {{ createAlertRule(input: {{
                       name: "drops-from-untrusted",
                       matchJson: "{{\"action\":[\"drop\"]}}",
                       groupBy: ["rule_id"],
                       severity: "warning",
                       receiverIds: ["{rcv_id}"]
                   }}) {{ id name enabled severity groupBy receiverIds }} }}"#
            ))
            .await;
        let data = ok_data(resp);
        let rule = &data["createAlertRule"];
        assert_eq!(rule["name"], "drops-from-untrusted");
        assert_eq!(rule["enabled"], true);
        assert_eq!(rule["severity"], "warning");
        assert_eq!(rule["groupBy"][0], "rule_id");
        assert_eq!(rule["receiverIds"][0], rcv_id);

        // Bus should have received Created with the new rule's id.
        let got = rx.recv().await.unwrap();
        let rule_id: i64 = rule["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(got, AlertRuleChange::Created(rule_id));

        // List query reports it.
        let resp = schema.execute(r#"{ alertRules { id name } }"#).await;
        let data = ok_data(resp);
        assert_eq!(data["alertRules"].as_array().unwrap().len(), 1);

        // Delete fires Deleted on the bus.
        let resp = schema
            .execute(format!(
                r#"mutation {{ deleteAlertRule(id: "{rule_id}") }}"#
            ))
            .await;
        let data = ok_data(resp);
        assert_eq!(data["deleteAlertRule"], true);
        let got = rx.recv().await.unwrap();
        assert_eq!(got, AlertRuleChange::Deleted(rule_id));
    }

    #[tokio::test]
    async fn create_alert_rule_rejects_bad_match_json() {
        let (schema, _bus) = schema_with_data().await;
        let resp = schema
            .execute(
                r#"mutation { createReceiver(input: {
                       name: "ops", kind: "webhook", configJson: "{}"
                   }) { id } }"#,
            )
            .await;
        let rcv_id = ok_data(resp)["createReceiver"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let resp = schema
            .execute(format!(
                r#"mutation {{ createAlertRule(input: {{
                       name: "bad",
                       matchJson: "{{\"actoin\":[\"drop\"]}}",
                       groupBy: ["rule_id"],
                       severity: "warning",
                       receiverIds: ["{rcv_id}"]
                   }}) {{ id }} }}"#
            ))
            .await;
        assert!(!resp.errors.is_empty());
        let msg = format!("{:?}", resp.errors);
        assert!(
            msg.contains("match_json") || msg.contains("unknown field"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn silences_active_filter_via_graphql() {
        let (schema, _bus) = schema_with_data().await;
        // One old (already-ended) silence and one current.
        let now = chrono::Utc::now();
        let past_start = now - chrono::Duration::hours(2);
        let past_end = now - chrono::Duration::hours(1);
        let future = now + chrono::Duration::hours(1);
        for (s, e) in [
            (past_start, past_end),
            (now - chrono::Duration::minutes(1), future),
        ] {
            let resp = schema
                .execute(format!(
                    r#"mutation {{ createSilence(input: {{
                           matcherJson: "{{\"action\":[\"drop\"]}}",
                           startsAt: "{}",
                           endsAt: "{}"
                       }}) {{ id }} }}"#,
                    s.to_rfc3339(),
                    e.to_rfc3339()
                ))
                .await;
            ok_data(resp);
        }
        let all = ok_data(schema.execute("{ silences { id } }").await);
        assert_eq!(all["silences"].as_array().unwrap().len(), 2);
        let active = ok_data(schema.execute("{ silences(active: true) { id } }").await);
        assert_eq!(active["silences"].as_array().unwrap().len(), 1);
    }
}
