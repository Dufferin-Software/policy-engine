// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Mutex};

/// Most-recent metrics snapshot for one node.
pub struct NodeMetrics {
    pub received_at: DateTime<Utc>,
    pub timestamp_ns: u64,
    /// Raw Prometheus exposition text (UTF-8, but stored as bytes).
    pub prometheus_text: Vec<u8>,
    /// Hostname reported by the node agent, if known.
    pub hostname: Option<String>,
}

/// Stores the most-recent Prometheus metrics snapshot per node.
///
/// The gRPC management handler calls `update()` each time a `MetricsUpdate`
/// arrives. HTTP handlers call `get()` or `all_node_ids()` to serve the data.
#[derive(Default)]
pub struct MetricsStore {
    data: Mutex<HashMap<String, NodeMetrics>>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store (or replace) the latest metrics snapshot for `node_id`.
    pub fn update(
        &self,
        node_id: &str,
        timestamp_ns: u64,
        prometheus_text: Vec<u8>,
        hostname: Option<String>,
    ) {
        self.data.lock().unwrap().insert(
            node_id.to_string(),
            NodeMetrics {
                received_at: Utc::now(),
                timestamp_ns,
                prometheus_text,
                hostname,
            },
        );
    }

    /// Retrieve the latest metrics text for a node. Returns `None` if no data
    /// has been received yet.
    pub fn get(&self, node_id: &str) -> Option<Vec<u8>> {
        self.data
            .lock()
            .unwrap()
            .get(node_id)
            .map(|m| m.prometheus_text.clone())
    }

    /// Retrieve the hostname for a node. Returns `None` if no data has been
    /// received yet or no hostname was reported.
    pub fn get_hostname(&self, node_id: &str) -> Option<String> {
        self.data
            .lock()
            .unwrap()
            .get(node_id)
            .and_then(|m| m.hostname.clone())
    }

    /// IDs of all nodes for which at least one metrics snapshot has been stored.
    pub fn all_node_ids(&self) -> Vec<String> {
        self.data.lock().unwrap().keys().cloned().collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_missing_returns_none() {
        let store = MetricsStore::new();
        assert!(store.get("no-such-node").is_none());
    }

    #[test]
    fn test_update_and_get() {
        let store = MetricsStore::new();
        store.update("n1", 1_000_000, b"# metrics\ncounter 42\n".to_vec(), None);
        let data = store.get("n1").unwrap();
        assert_eq!(&data, b"# metrics\ncounter 42\n");
    }

    #[test]
    fn test_update_replaces_previous() {
        let store = MetricsStore::new();
        store.update("n1", 1, b"old".to_vec(), None);
        store.update("n1", 2, b"new".to_vec(), None);
        assert_eq!(&store.get("n1").unwrap(), b"new");
    }

    #[test]
    fn test_all_node_ids() {
        let store = MetricsStore::new();
        store.update("n1", 0, vec![], None);
        store.update("n2", 0, vec![], None);
        let mut ids = store.all_node_ids();
        ids.sort();
        assert_eq!(ids, vec!["n1", "n2"]);
    }

    #[test]
    fn test_get_hostname_none_when_not_set() {
        let store = MetricsStore::new();
        store.update("n1", 0, vec![], None);
        assert!(store.get_hostname("n1").is_none());
    }

    #[test]
    fn test_get_hostname_returns_stored_value() {
        let store = MetricsStore::new();
        store.update("n1", 0, vec![], Some("node1.example.com".to_string()));
        assert_eq!(
            store.get_hostname("n1"),
            Some("node1.example.com".to_string())
        );
    }
}
