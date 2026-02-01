// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Background task that subscribes to the event bus, parses each batch
//! into typed [`PolicyEvent`]s, and flushes them to SQLite in bounded
//! batches.
//!
//! Flush triggers: 500 rows queued OR 100 ms since last flush.
//! Backpressure: if the bounded internal buffer overflows we drop events
//! and increment `event_ingest_dropped_total{reason="persist_overflow"}` —
//! we never block the bus thread.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use tokio::time;

use crate::event_bus::{EventBus, TaggedEventBatch};

use super::metrics::{DropReason, EventPipelineMetrics, SkipReason};
use super::store::EventStore;
use super::tenant::TenantScope;
use super::types::{parse_policy_event, ParseSkip, PolicyEvent};

#[derive(Debug, Clone)]
pub struct PersisterConfig {
    /// Flush when this many rows are queued.
    pub flush_batch_size: usize,
    /// Flush at least this often, even if the batch isn't full.
    pub flush_interval: Duration,
    /// Maximum in-flight buffer size before dropping events.
    pub max_buffered: usize,
}

impl Default for PersisterConfig {
    fn default() -> Self {
        Self {
            flush_batch_size: 500,
            flush_interval: Duration::from_millis(100),
            // 10× flush batch — gives the writer headroom without unbounded growth.
            max_buffered: 5_000,
        }
    }
}

/// Spawn the persister task. Returns the `JoinHandle` so the caller can
/// shut it down with the rest of the controller.
pub fn spawn_persister(
    event_bus: Arc<EventBus>,
    scope: TenantScope,
    metrics: Arc<EventPipelineMetrics>,
    config: PersisterConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(event_bus, scope, metrics, config).await;
    })
}

async fn run(
    event_bus: Arc<EventBus>,
    scope: TenantScope,
    metrics: Arc<EventPipelineMetrics>,
    config: PersisterConfig,
) {
    let mut rx = event_bus.subscribe();
    let mut buf: Vec<PolicyEvent> = Vec::with_capacity(config.flush_batch_size);
    let mut ticker = time::interval(config.flush_interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    log::info!(
        "event persister started (batch={}, interval={:?})",
        config.flush_batch_size,
        config.flush_interval
    );

    loop {
        tokio::select! {
            biased;

            // Periodic flush — fires even when no new batches arrive so a
            // trickle of events isn't held in memory forever.
            _ = ticker.tick() => {
                if !buf.is_empty() {
                    flush(&scope, &metrics, &mut buf).await;
                }
            }

            recv = rx.recv() => match recv {
                Ok(batch) => {
                    ingest(batch, &mut buf, &metrics, &config);
                    if buf.len() >= config.flush_batch_size {
                        flush(&scope, &metrics, &mut buf).await;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("event persister lagged, dropped {n} broadcast messages");
                    metrics.record_dropped(DropReason::PersistOverflow, n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    log::info!("event bus closed, persister exiting");
                    if !buf.is_empty() {
                        flush(&scope, &metrics, &mut buf).await;
                    }
                    return;
                }
            }
        }
    }
}

fn ingest(
    batch: TaggedEventBatch,
    buf: &mut Vec<PolicyEvent>,
    metrics: &EventPipelineMetrics,
    config: &PersisterConfig,
) {
    metrics.record_received(&batch.node_id, batch.events_json.len() as u64);

    for blob in &batch.events_json {
        // Backpressure: stop appending once the bound is hit. Subsequent
        // events in this batch (and later batches) are dropped until the
        // flusher catches up.
        if buf.len() >= config.max_buffered {
            metrics.record_dropped(DropReason::PersistOverflow, 1);
            continue;
        }
        match parse_policy_event(&batch.node_id, blob) {
            Ok(Some(ev)) => buf.push(ev),
            Ok(None) => {
                metrics.record_skipped(SkipReason::NonPersistableAction, 1);
            }
            Err(ParseSkip::BadJson) => {
                metrics.record_dropped(DropReason::BadJson, 1);
            }
            Err(ParseSkip::BadIp) => {
                metrics.record_dropped(DropReason::BadIp, 1);
            }
            Err(ParseSkip::BadDirection) => {
                metrics.record_dropped(DropReason::BadDirection, 1);
            }
            Err(ParseSkip::PassOrUnknown) => { /* counted as not-an-error */ }
        }
    }
}

async fn flush(scope: &TenantScope, metrics: &EventPipelineMetrics, buf: &mut Vec<PolicyEvent>) {
    let start = Instant::now();
    let store = EventStore::new(scope);
    match store.insert_batch(buf).await {
        Ok(n) => {
            metrics.record_inserted(n as u64);
            metrics.record_persist_batch(start.elapsed());
            log::trace!("event persister flushed {n} rows in {:?}", start.elapsed());
        }
        Err(e) => {
            log::error!("event persister failed to insert {} rows: {e:#}", buf.len());
            metrics.record_dropped(DropReason::PersistOverflow, buf.len() as u64);
        }
    }
    buf.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::tenant::bootstrap_default_tenant;
    use sqlx::sqlite::SqlitePool;

    async fn fresh_scope() -> TenantScope {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        bootstrap_default_tenant(pool).await.unwrap()
    }

    fn drop_event_json() -> Vec<u8> {
        serde_json::json!({
            "timestamp_ns": 1u64,
            "rule_id": 1,
            "action": "drop",
            "ifindex": 1,
            "interface_name": "eth0",
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "sport": 1,
            "dport": 2,
            "protocol": "tcp",
            "af": 2,
            "pkt_len": 64,
            "verdict": "drop",
            "direction": "ingress",
            "fragment": false,
            "sni": null,
            "quic_version": null
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn end_to_end_publish_persists() {
        let scope = fresh_scope().await;
        let bus = Arc::new(EventBus::new());
        let metrics = Arc::new(EventPipelineMetrics::new());
        let _h = spawn_persister(
            Arc::clone(&bus),
            scope.clone(),
            Arc::clone(&metrics),
            PersisterConfig {
                flush_batch_size: 2,
                flush_interval: Duration::from_millis(20),
                max_buffered: 100,
            },
        );

        // Tiny pause to let the subscriber attach before publishing.
        tokio::time::sleep(Duration::from_millis(5)).await;

        bus.publish(TaggedEventBatch {
            node_id: "n1".to_string(),
            timestamp_ns: 0,
            events_json: vec![drop_event_json(), drop_event_json()],
        });

        // Wait long enough for the flush tick.
        tokio::time::sleep(Duration::from_millis(80)).await;

        let store = EventStore::new(&scope);
        let rows = store
            .list(&super::super::store::EventFilter::default(), 10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn malformed_json_counted_as_dropped() {
        let scope = fresh_scope().await;
        let bus = Arc::new(EventBus::new());
        let metrics = Arc::new(EventPipelineMetrics::new());
        let _h = spawn_persister(
            Arc::clone(&bus),
            scope,
            Arc::clone(&metrics),
            PersisterConfig::default(),
        );
        tokio::time::sleep(Duration::from_millis(5)).await;

        bus.publish(TaggedEventBatch {
            node_id: "n1".to_string(),
            timestamp_ns: 0,
            events_json: vec![b"not json".to_vec()],
        });

        tokio::time::sleep(Duration::from_millis(150)).await;

        let txt = metrics.render("default");
        assert!(txt.contains("reason=\"bad_json\""));
    }
}
