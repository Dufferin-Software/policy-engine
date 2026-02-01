// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Background retention task: deletes events older than the tenant's
//! `retention_s`. Chunked to avoid long write locks on SQLite.

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
    metrics: Arc<EventPipelineMetrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(scope, metrics).await;
    })
}

async fn run(scope: TenantScope, metrics: Arc<EventPipelineMetrics>) {
    let mut ticker = time::interval(SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    log::info!("event retention task started (interval={SWEEP_INTERVAL:?})");

    loop {
        ticker.tick().await;
        if let Err(e) = sweep_once(&scope, &metrics).await {
            log::error!("event retention sweep failed: {e:#}");
        }
    }
}

/// Run a single retention pass. Pulled out for direct test coverage.
pub async fn sweep_once(scope: &TenantScope, metrics: &Arc<EventPipelineMetrics>) -> Result<u64> {
    let retention_s = retention_seconds(scope).await?;
    let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let cutoff = now_ns.saturating_sub(retention_s.saturating_mul(1_000_000_000));

    let store = EventStore::new(scope);
    let mut total: u64 = 0;
    // Chunk in a loop so a backlog drains without holding any single lock
    // for long. Bound the loop so a misconfigured retention can't pin the
    // task on this tenant.
    for _ in 0..100 {
        let removed = store.prune_older_than(cutoff, CHUNK).await?;
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
        let store = EventStore::new(&scope);
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap();
        store
            .insert_batch(&[
                old_event(now_ns - 10_000_000_000), // 10s old
                old_event(now_ns),                  // just now
            ])
            .await
            .unwrap();

        let metrics = Arc::new(EventPipelineMetrics::new());
        let pruned = sweep_once(&scope, &metrics).await.unwrap();
        assert_eq!(pruned, 1);
        let remaining = store.list(&EventFilter::default(), 10).await.unwrap();
        assert_eq!(remaining.len(), 1);
    }
}
