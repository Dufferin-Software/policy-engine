// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Background task that subscribes to the Suricata alert channel, parses each
//! batch of engine EVE alerts, and flushes them to the `suricata_alerts`
//! table in bounded batches.
//!
//! Mirrors [`super::persister`] but writes through the `ControllerStore`
//! trait (rather than the raw event-pipeline pool) so it stays testable with
//! the in-memory store. Backpressure: broadcast lag drops whole batches with
//! a warning; we never block the bus.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::broadcast;
use tokio::time;

use crate::event_bus::{EventBus, TaggedSuricataAlertBatch};
use crate::store::{ControllerStore, NewSuricataAlert};

const FLUSH_BATCH_SIZE: usize = 500;
const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

/// The subset of the engine's `SuricataAlert` JSON we destructure into
/// columns. Unknown fields are ignored; the full blob is kept in `raw_json`.
#[derive(Debug, Deserialize)]
struct EveAlert {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    src_ip: String,
    #[serde(default)]
    dest_ip: String,
    #[serde(default)]
    src_port: u16,
    #[serde(default)]
    dest_port: u16,
    #[serde(default)]
    proto: String,
    #[serde(default)]
    alert: Option<EveAlertInfo>,
}

#[derive(Debug, Deserialize)]
struct EveAlertInfo {
    #[serde(default)]
    action: String,
    #[serde(default)]
    signature_id: u64,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    severity: u32,
}

fn none_if_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Parse one raw EVE-alert JSON blob into a `NewSuricataAlert` row.
/// `received_ns` orders alerts that share an EVE timestamp string.
fn parse_alert(
    tenant_id: &str,
    node_id: &str,
    received_ns: i64,
    blob: &[u8],
) -> Option<NewSuricataAlert> {
    let parsed: EveAlert = serde_json::from_slice(blob)
        .map_err(|e| log::debug!("skipping unparseable suricata alert: {e}"))
        .ok()?;
    let info = parsed.alert;
    Some(NewSuricataAlert {
        tenant_id: tenant_id.to_string(),
        node_id: node_id.to_string(),
        timestamp: parsed.timestamp,
        received_ns,
        src_ip: none_if_empty(parsed.src_ip),
        src_port: Some(parsed.src_port as i32),
        dst_ip: none_if_empty(parsed.dest_ip),
        dst_port: Some(parsed.dest_port as i32),
        proto: none_if_empty(parsed.proto),
        action: info.as_ref().map(|i| i.action.clone()),
        signature_id: info.as_ref().map(|i| i.signature_id as i64),
        signature: info.as_ref().map(|i| i.signature.clone()),
        category: info.as_ref().map(|i| i.category.clone()),
        severity: info.as_ref().map(|i| i.severity as i32),
        raw_json: String::from_utf8_lossy(blob).into_owned(),
    })
}

fn ingest(batch: TaggedSuricataAlertBatch, buf: &mut Vec<NewSuricataAlert>) {
    for blob in &batch.alerts_json {
        if let Some(row) = parse_alert(
            &batch.tenant_id,
            &batch.node_id,
            batch.timestamp_ns as i64,
            blob,
        ) {
            buf.push(row);
        }
    }
}

async fn flush(store: &Arc<dyn ControllerStore>, buf: &mut Vec<NewSuricataAlert>) {
    if buf.is_empty() {
        return;
    }
    let rows = std::mem::take(buf);
    let n = rows.len();
    if let Err(e) = store.insert_suricata_alerts(&rows).await {
        log::warn!("failed to persist {n} suricata alerts: {e:#}");
    }
}

/// Spawn the Suricata alert persister. Returns the `JoinHandle`.
pub fn spawn_suricata_alert_persister(
    event_bus: Arc<EventBus>,
    store: Arc<dyn ControllerStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(event_bus, store).await;
    })
}

async fn run(event_bus: Arc<EventBus>, store: Arc<dyn ControllerStore>) {
    let mut rx = event_bus.subscribe_suricata_alerts();
    let mut buf: Vec<NewSuricataAlert> = Vec::with_capacity(FLUSH_BATCH_SIZE);
    let mut ticker = time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    log::info!("suricata alert persister started");

    loop {
        tokio::select! {
            biased;
            _ = ticker.tick() => {
                flush(&store, &mut buf).await;
            }
            recv = rx.recv() => match recv {
                Ok(batch) => {
                    ingest(batch, &mut buf);
                    if buf.len() >= FLUSH_BATCH_SIZE {
                        flush(&store, &mut buf).await;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("suricata alert persister lagged, dropped {n} batches");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    flush(&store, &mut buf).await;
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InMemoryControllerStore, SuricataAlertFilter};

    #[test]
    fn parse_full_alert() {
        let blob = br#"{"timestamp":"2026-07-04T00:00:00Z","src_ip":"10.0.0.1",
            "dest_ip":"10.0.0.2","src_port":1234,"dest_port":80,"proto":"TCP",
            "event_type":"alert","alert":{"action":"allowed","signature_id":2001,
            "signature":"ET SCAN","category":"Attempted Recon","severity":2}}"#;
        let a = parse_alert("default", "n1", 42, blob).unwrap();
        assert_eq!(a.node_id, "n1");
        assert_eq!(a.received_ns, 42);
        assert_eq!(a.src_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(a.dst_port, Some(80));
        assert_eq!(a.signature_id, Some(2001));
        assert_eq!(a.signature.as_deref(), Some("ET SCAN"));
        assert_eq!(a.severity, Some(2));
    }

    #[test]
    fn malformed_json_is_skipped() {
        assert!(parse_alert("default", "n1", 0, b"not json").is_none());
    }

    #[test]
    fn alert_without_alert_object_still_persists_5tuple() {
        let blob = br#"{"timestamp":"t","src_ip":"1.1.1.1","dest_ip":"2.2.2.2",
            "src_port":1,"dest_port":2,"proto":"UDP","event_type":"alert"}"#;
        let a = parse_alert("default", "n1", 0, blob).unwrap();
        assert!(a.signature_id.is_none());
        assert_eq!(a.proto.as_deref(), Some("UDP"));
    }

    #[tokio::test]
    async fn ingest_and_flush_writes_rows() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let mut buf = Vec::new();
        ingest(
            TaggedSuricataAlertBatch {
                node_id: "n1".to_string(),
                tenant_id: "default".to_string(),
                timestamp_ns: 100,
                alerts_json: vec![
                    br#"{"timestamp":"t","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","alert":{"signature_id":5,"signature":"X","severity":1}}"#.to_vec(),
                    b"garbage".to_vec(),
                ],
            },
            &mut buf,
        );
        assert_eq!(buf.len(), 1, "malformed alert dropped, valid one kept");
        flush(&store, &mut buf).await;

        let got = store
            .list_suricata_alerts(&SuricataAlertFilter::default(), 10)
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].signature_id, Some(5));
    }
}
