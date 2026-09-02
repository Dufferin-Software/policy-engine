// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use tokio::sync::{broadcast, watch};

/// Capacity of the broadcast channel. Old events are dropped if subscribers
/// fall too far behind (lag), which is acceptable for a live event stream.
const CHANNEL_CAPACITY: usize = 1_000;

/// A BPF event batch received from one node.
#[derive(Clone, Debug)]
pub struct TaggedEventBatch {
    pub node_id: String,
    pub timestamp_ns: u64,
    /// Each entry is a JSON-encoded BPF event (raw bytes from the agent).
    pub events_json: Vec<Vec<u8>>,
}

/// A Suricata EVE alert batch received from one node.
///
/// Kept on its own broadcast channel (not folded into the BPF event stream):
/// alerts have a different schema (signature/category/severity), a dedicated
/// persister/table, and their own operator WebSocket endpoint.
#[derive(Clone, Debug)]
pub struct TaggedSuricataAlertBatch {
    pub node_id: String,
    pub tenant_id: String,
    pub timestamp_ns: u64,
    /// Each entry is one JSON-encoded engine `SuricataAlert`.
    pub alerts_json: Vec<Vec<u8>>,
}

/// Fan-out bus for BPF events arriving from all agents.
///
/// The gRPC management handler calls `publish()` for every `EventBatch` it
/// receives. WebSocket handlers subscribe via `subscribe()` and stream the
/// events to browser or tooling clients.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<TaggedEventBatch>,
    suricata_tx: broadcast::Sender<TaggedSuricataAlertBatch>,
    /// Set to `true` on server shutdown so long-lived subscribers (the
    /// `/ws/events`, `/ws/rule-events` and `/ws/alerts` WebSocket tasks) can
    /// close their sessions promptly instead of holding connections open
    /// until the HTTP server's `shutdown_timeout` elapses.
    shutdown_tx: watch::Sender<bool>,
}

impl Default for EventBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (suricata_tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            tx,
            suricata_tx,
            shutdown_tx,
        }
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a batch of events from a node.
    ///
    /// Returns silently if there are no active subscribers.
    pub fn publish(&self, batch: TaggedEventBatch) {
        let _ = self.tx.send(batch);
    }

    /// Subscribe to the event stream.
    ///
    /// The returned receiver will lag if the subscriber can't keep up;
    /// lagged messages are silently dropped (a warning is the caller's
    /// responsibility).
    pub fn subscribe(&self) -> broadcast::Receiver<TaggedEventBatch> {
        self.tx.subscribe()
    }

    /// Publish a batch of Suricata alerts from a node.
    pub fn publish_suricata_alerts(&self, batch: TaggedSuricataAlertBatch) {
        let _ = self.suricata_tx.send(batch);
    }

    /// Subscribe to the Suricata alert stream (same lag semantics as
    /// [`EventBus::subscribe`]).
    pub fn subscribe_suricata_alerts(&self) -> broadcast::Receiver<TaggedSuricataAlertBatch> {
        self.suricata_tx.subscribe()
    }

    /// Subscribe to the shutdown signal.
    ///
    /// `changed()` on the returned receiver resolves (and the value becomes
    /// `true`) when [`EventBus::shutdown`] is called. WebSocket handlers
    /// select on this so they can close their session the moment shutdown
    /// begins, rather than blocking the server's graceful drain.
    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Signal all subscribers that the server is shutting down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_received_by_subscriber() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        bus.publish(TaggedEventBatch {
            node_id: "n1".to_string(),
            timestamp_ns: 12345,
            events_json: vec![b"{}".to_vec()],
        });

        let received = rx.recv().await.unwrap();
        assert_eq!(received.node_id, "n1");
        assert_eq!(received.events_json.len(), 1);
    }

    #[tokio::test]
    async fn test_publish_no_subscribers_is_ok() {
        let bus = EventBus::new();
        // Should not panic
        bus.publish(TaggedEventBatch {
            node_id: "n1".to_string(),
            timestamp_ns: 0,
            events_json: vec![],
        });
    }

    #[tokio::test]
    async fn test_multiple_subscribers_both_receive() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.publish(TaggedEventBatch {
            node_id: "n1".to_string(),
            timestamp_ns: 1,
            events_json: vec![],
        });

        assert_eq!(rx1.recv().await.unwrap().node_id, "n1");
        assert_eq!(rx2.recv().await.unwrap().node_id, "n1");
    }

    #[tokio::test]
    async fn test_suricata_alerts_channel_is_independent() {
        let bus = EventBus::new();
        let mut alerts = bus.subscribe_suricata_alerts();
        let mut events = bus.subscribe();

        bus.publish_suricata_alerts(TaggedSuricataAlertBatch {
            node_id: "n1".to_string(),
            tenant_id: "default".to_string(),
            timestamp_ns: 7,
            alerts_json: vec![b"{}".to_vec()],
        });

        let got = alerts.recv().await.unwrap();
        assert_eq!(got.node_id, "n1");
        assert_eq!(got.tenant_id, "default");
        // The BPF event channel must NOT receive alert batches.
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_shutdown_signal_notifies_subscriber() {
        let bus = EventBus::new();
        let mut shutdown = bus.subscribe_shutdown();
        assert!(!*shutdown.borrow());

        bus.shutdown();

        // changed() resolves and the value flips to true.
        shutdown.changed().await.unwrap();
        assert!(*shutdown.borrow());
    }

    #[tokio::test]
    async fn test_node_filter_in_caller() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        bus.publish(TaggedEventBatch {
            node_id: "n1".to_string(),
            timestamp_ns: 1,
            events_json: vec![],
        });
        bus.publish(TaggedEventBatch {
            node_id: "n2".to_string(),
            timestamp_ns: 2,
            events_json: vec![],
        });

        let a = rx.recv().await.unwrap();
        let b = rx.recv().await.unwrap();
        // Both arrive; filtering is done by the WebSocket handler.
        assert_ne!(a.node_id, b.node_id);
    }
}
