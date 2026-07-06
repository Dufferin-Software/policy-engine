// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Background task that subscribes to the event bus, parses each batch
//! into typed [`PolicyEvent`]s, and appends them to the in-memory
//! [`EventStore`].
//!
//! Events are not persisted — the store is a bounded per-tenant ring
//! buffer. When the buffer is full the oldest events are evicted and
//! counted as `event_ingest_dropped_total{reason="persist_overflow"}`.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;

use crate::event_bus::{EventBus, TaggedEventBatch};

use super::metrics::{DropReason, EventPipelineMetrics, SkipReason};
use super::store::EventStore;
use super::types::{parse_policy_event, ParseSkip, PolicyEvent};

/// Spawn the ingest task. Returns the `JoinHandle` so the caller can
/// shut it down with the rest of the controller.
pub fn spawn_persister(
    event_bus: Arc<EventBus>,
    tenant_id: i64,
    events: Arc<EventStore>,
    metrics: Arc<EventPipelineMetrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(event_bus, tenant_id, events, metrics).await;
    })
}

async fn run(
    event_bus: Arc<EventBus>,
    tenant_id: i64,
    events: Arc<EventStore>,
    metrics: Arc<EventPipelineMetrics>,
) {
    let mut rx = event_bus.subscribe();

    log::info!("event ingest task started (in-memory buffer)");

    loop {
        match rx.recv().await {
            Ok(batch) => ingest(batch, tenant_id, &events, &metrics),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                log::warn!("event ingest lagged, dropped {n} broadcast messages");
                metrics.record_dropped(DropReason::PersistOverflow, n);
            }
            Err(broadcast::error::RecvError::Closed) => {
                log::info!("event bus closed, ingest task exiting");
                return;
            }
        }
    }
}

fn ingest(
    batch: TaggedEventBatch,
    tenant_id: i64,
    events: &EventStore,
    metrics: &EventPipelineMetrics,
) {
    metrics.record_received(&batch.node_id, batch.events_json.len() as u64);

    let mut parsed: Vec<PolicyEvent> = Vec::with_capacity(batch.events_json.len());
    for blob in &batch.events_json {
        match parse_policy_event(&batch.node_id, blob) {
            Ok(Some(ev)) => parsed.push(ev),
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
    if parsed.is_empty() {
        return;
    }

    let start = Instant::now();
    let stats = events.insert_batch(tenant_id, &parsed);
    metrics.record_inserted(stats.inserted as u64);
    if stats.evicted > 0 {
        metrics.record_dropped(DropReason::PersistOverflow, stats.evicted as u64);
    }
    metrics.record_persist_batch(start.elapsed());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TENANT: i64 = 1;

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
    async fn end_to_end_publish_buffers() {
        let bus = Arc::new(EventBus::new());
        let events = Arc::new(EventStore::new());
        let metrics = Arc::new(EventPipelineMetrics::new());
        let _h = spawn_persister(
            Arc::clone(&bus),
            TENANT,
            Arc::clone(&events),
            Arc::clone(&metrics),
        );

        // Tiny pause to let the subscriber attach before publishing.
        tokio::time::sleep(Duration::from_millis(5)).await;

        bus.publish(TaggedEventBatch {
            node_id: "n1".to_string(),
            timestamp_ns: 0,
            events_json: vec![drop_event_json(), drop_event_json()],
        });

        // Wait for the ingest task to drain the bus.
        for _ in 0..50 {
            if events
                .list(TENANT, &super::super::store::EventFilter::default(), 10)
                .len()
                == 2
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("events were not buffered");
    }

    #[tokio::test]
    async fn malformed_json_counted_as_dropped() {
        let bus = Arc::new(EventBus::new());
        let events = Arc::new(EventStore::new());
        let metrics = Arc::new(EventPipelineMetrics::new());
        let _h = spawn_persister(Arc::clone(&bus), TENANT, events, Arc::clone(&metrics));
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
