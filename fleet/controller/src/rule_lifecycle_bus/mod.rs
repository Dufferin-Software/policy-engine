// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use serde::Serialize;
use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 1_000;

/// A controller-side rule lifecycle event broadcast to UI subscribers.
#[derive(Clone, Debug, Serialize)]
pub struct RuleLifecycleEvent {
    pub event_type: String, // "created" | "deleted" | "expired"
    pub rule_id: String,
    pub node_id: String,
    pub interface_name: String,
    pub direction: String, // "INGRESS" | "EGRESS"
    pub timestamp_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Fan-out bus for rule lifecycle events.
///
/// GraphQL mutations and the TTL reaper call `publish()`.
/// WebSocket handlers subscribe via `subscribe()`.
#[derive(Clone)]
pub struct RuleLifecycleBus {
    tx: broadcast::Sender<RuleLifecycleEvent>,
}

impl Default for RuleLifecycleBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }
}

impl RuleLifecycleBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&self, event: RuleLifecycleEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RuleLifecycleEvent> {
        self.tx.subscribe()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_received_by_subscriber() {
        let bus = RuleLifecycleBus::new();
        let mut rx = bus.subscribe();

        bus.publish(RuleLifecycleEvent {
            event_type: "created".to_string(),
            rule_id: "100".to_string(),
            node_id: "node-1".to_string(),
            interface_name: "eth0".to_string(),
            direction: "INGRESS".to_string(),
            timestamp_ms: 12345,
            reason: None,
        });

        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.event_type, "created");
        assert_eq!(ev.rule_id, "100");
    }

    #[tokio::test]
    async fn test_publish_no_subscribers_is_ok() {
        let bus = RuleLifecycleBus::new();
        bus.publish(RuleLifecycleEvent {
            event_type: "expired".to_string(),
            rule_id: "1".to_string(),
            node_id: "n1".to_string(),
            interface_name: "eth0".to_string(),
            direction: "EGRESS".to_string(),
            timestamp_ms: 0,
            reason: Some("ttl_expired".to_string()),
        });
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = RuleLifecycleBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.publish(RuleLifecycleEvent {
            event_type: "deleted".to_string(),
            rule_id: "42".to_string(),
            node_id: "n1".to_string(),
            interface_name: "eth0".to_string(),
            direction: "INGRESS".to_string(),
            timestamp_ms: 1,
            reason: None,
        });

        assert_eq!(rx1.recv().await.unwrap().rule_id, "42");
        assert_eq!(rx2.recv().await.unwrap().rule_id, "42");
    }
}
