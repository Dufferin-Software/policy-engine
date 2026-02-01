// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use tokio::sync::broadcast;

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

/// Fan-out bus for BPF events arriving from all agents.
///
/// The gRPC management handler calls `publish()` for every `EventBatch` it
/// receives. WebSocket handlers subscribe via `subscribe()` and stream the
/// events to browser or tooling clients.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<TaggedEventBatch>,
}

impl Default for EventBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
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
