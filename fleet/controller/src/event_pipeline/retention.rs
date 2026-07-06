// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Background retention task: deletes alert rows older than the tenant's
//! `retention_s` (chunked to avoid long write locks on SQLite) and ages
//! out buffered in-memory policy events on the same window.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::Row;
use tokio::time;

use super::metrics::EventPipelineMetrics;
use super::store::EventStore;
use super::tenant::TenantScope;

const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const CHUNK: i64 = 10_000;

/// Spawn the retention loop. Runs forever until the runtime drops it.
pub fn spawn_retention(
    scope: TenantScope,
    events: Arc<EventStore>,
    metrics: Arc<EventPipelineMetrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(scope, events, metrics).await;
    })
}

async fn run(scope: TenantScope, events: Arc<EventStore>, metrics: Arc<EventPipelineMetrics>) {
    let mut ticker = time::interval(SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    log::info!("event retention task started (interval={SWEEP_INTERVAL:?})");

    loop {
        ticker.tick().await;
        if let Err(e) = sweep_once(&scope, &events, &metrics).await {
            log::error!("event retention sweep failed: {e:#}");
        }
    }
}

/// Run a single retention pass. Pulled out for direct test coverage.
pub async fn sweep_once(
    scope: &TenantScope,
    events: &EventStore,
    metrics: &Arc<EventPipelineMetrics>,
) -> Result<u64> {
    let retention_s = retention_seconds(scope).await?;
    let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let cutoff = now_ns.saturating_sub(retention_s.saturating_mul(1_000_000_000));

    let mut total: u64 = events.prune_older_than(scope.tenant_id(), cutoff);

    // Suricata alerts share the tenant's retention window. Acked or not,
    // history past the cutoff goes — the UI "clear" only acknowledges.
    for _ in 0..100 {
        let removed = prune_suricata_alerts(scope, cutoff, CHUNK).await?;
        if removed == 0 {
            break;
        }
        total += removed;
    }

    // Fired-alert history: same window, but only resolved rows — a
    // still-firing alert must never vanish mid-incident, however old.
    // `alert_history` timestamps are seconds, not ns.
    let cutoff_s = cutoff / 1_000_000_000;
    for _ in 0..100 {
        let removed = prune_alert_history(scope, cutoff_s, CHUNK).await?;
        if removed == 0 {
            break;
        }
        total += removed;
    }

    if total > 0 {
        metrics.record_pruned(total);
        log::debug!("event retention pruned {total} rows older than {cutoff} ns");
    }
    Ok(total)
}

/// One chunked delete of Suricata alerts past the cutoff. Same portable
/// `rowid IN (SELECT … LIMIT)` shape as [`EventStore::prune_older_than`];
/// `suricata_alerts.tenant_id` holds the tenant slug, not the numeric id.
async fn prune_suricata_alerts(scope: &TenantScope, cutoff_ns: i64, chunk: i64) -> Result<u64> {
    let res = sqlx::query(
        "DELETE FROM suricata_alerts WHERE id IN ( \
            SELECT id FROM suricata_alerts \
            WHERE tenant_id = ? AND received_ns < ? \
            ORDER BY id ASC LIMIT ? \
         )",
    )
    .bind(scope.slug())
    .bind(cutoff_ns)
    .bind(chunk)
    .execute(scope.pool())
    .await
    .context("Failed to prune suricata alerts")?;
    Ok(res.rows_affected())
}

/// One chunked delete of resolved alert-history rows past the cutoff.
/// Unresolved rows are kept regardless of age (open incidents), and rows
/// age from `resolved_at`, not `fired_at`.
async fn prune_alert_history(scope: &TenantScope, cutoff_s: i64, chunk: i64) -> Result<u64> {
    let res = sqlx::query(
        "DELETE FROM alert_history WHERE id IN ( \
            SELECT id FROM alert_history \
            WHERE tenant_id = ? AND resolved_at IS NOT NULL AND resolved_at < ? \
            ORDER BY id ASC LIMIT ? \
         )",
    )
    .bind(scope.tenant_id())
    .bind(cutoff_s)
    .bind(chunk)
    .execute(scope.pool())
    .await
    .context("Failed to prune alert history")?;
    Ok(res.rows_affected())
}

async fn retention_seconds(scope: &TenantScope) -> Result<i64> {
    let row = sqlx::query("SELECT retention_s FROM tenants WHERE id = ?")
        .bind(scope.tenant_id())
        .fetch_one(scope.pool())
        .await
        .context("Failed to read tenant retention")?;
    Ok(row.try_get("retention_s")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::{
        store::EventFilter, tenant::bootstrap_default_tenant, types::Action, types::Direction,
        types::PolicyEvent,
    };
    use sqlx::sqlite::SqlitePool;

    async fn scope_with_retention(secs: i64) -> TenantScope {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query("UPDATE tenants SET retention_s = ? WHERE slug = 'default'")
            .bind(secs)
            .execute(&pool)
            .await
            .unwrap();
        bootstrap_default_tenant(pool).await.unwrap()
    }

    fn old_event(ts_ns: i64) -> PolicyEvent {
        PolicyEvent {
            ts_ns,
            node_id: "n1".into(),
            rule_id: 1,
            action: Action::Drop,
            verdict: 1,
            direction: Direction::Ingress,
            ifindex: 1,
            proto: 6,
            src_ip: vec![10, 0, 0, 1],
            dst_ip: vec![10, 0, 0, 2],
            sport: 1,
            dport: 2,
            pkt_len: 64,
            flags: None,
            sni: None,
        }
    }

    #[tokio::test]
    async fn sweep_deletes_old_keeps_recent() {
        // 1-second retention so "now - 10s" is past the cutoff.
        let scope = scope_with_retention(1).await;
        let events = EventStore::new();
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap();
        events.insert_batch(
            scope.tenant_id(),
            &[
                old_event(now_ns - 10_000_000_000), // 10s old
                old_event(now_ns),                  // just now
            ],
        );

        let metrics = Arc::new(EventPipelineMetrics::new());
        let pruned = sweep_once(&scope, &events, &metrics).await.unwrap();
        assert_eq!(pruned, 1);
        let remaining = events.list(scope.tenant_id(), &EventFilter::default(), 10);
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn sweep_prunes_resolved_alert_history_only() {
        let scope = scope_with_retention(1).await;
        let now_s = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO alert_rules \
             (id, tenant_id, name, match_json, group_by, severity, receiver_ids, \
              created_at, updated_at) \
             VALUES (1, ?, 'r', '{}', '[]', 'info', '[]', 0, 0)",
        )
        .bind(scope.tenant_id())
        .execute(scope.pool())
        .await
        .unwrap();
        // (group_key, fired_at, resolved_at): resolved-old is pruned;
        // unresolved-old and resolved-fresh survive.
        for (key, fired, resolved) in [
            ("resolved-old", now_s - 20, Some(now_s - 10)),
            ("unresolved-old", now_s - 20, None),
            ("resolved-fresh", now_s - 20, Some(now_s)),
        ] {
            sqlx::query(
                "INSERT INTO alert_history \
                 (tenant_id, rule_id, group_key, fired_at, resolved_at, \
                  event_count, sample_event_ids) \
                 VALUES (?, 1, ?, ?, ?, 1, '[]')",
            )
            .bind(scope.tenant_id())
            .bind(key)
            .bind(fired)
            .bind(resolved)
            .execute(scope.pool())
            .await
            .unwrap();
        }

        let metrics = Arc::new(EventPipelineMetrics::new());
        let pruned = sweep_once(&scope, &EventStore::new(), &metrics)
            .await
            .unwrap();
        assert_eq!(pruned, 1);
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT group_key FROM alert_history ORDER BY id")
                .fetch_all(scope.pool())
                .await
                .unwrap();
        assert_eq!(remaining, vec!["unresolved-old", "resolved-fresh"]);
    }

    #[tokio::test]
    async fn sweep_prunes_old_suricata_alerts() {
        let scope = scope_with_retention(1).await;
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap();
        for (node, received_ns) in [("n1", now_ns - 10_000_000_000), ("n2", now_ns)] {
            sqlx::query(
                "INSERT INTO suricata_alerts \
                 (tenant_id, node_id, timestamp, received_ns, raw_json) \
                 VALUES ('default', ?, 't', ?, '{}')",
            )
            .bind(node)
            .bind(received_ns)
            .execute(scope.pool())
            .await
            .unwrap();
        }

        let metrics = Arc::new(EventPipelineMetrics::new());
        let pruned = sweep_once(&scope, &EventStore::new(), &metrics)
            .await
            .unwrap();
        assert_eq!(pruned, 1);
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT node_id FROM suricata_alerts ORDER BY id")
                .fetch_all(scope.pool())
                .await
                .unwrap();
        assert_eq!(remaining, vec!["n2".to_string()]);
    }
}
