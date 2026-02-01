// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use std::{collections::HashMap, sync::Mutex};
use tokio::sync::mpsc;
use tonic::Status;

use policy_controller_proto::controller::ControllerMessage;

// ── Session state for one connected agent ────────────────────────────────────

struct NodeSession {
    tx: mpsc::Sender<Result<ControllerMessage, Status>>,
    /// Tenant slug the node belongs to, captured from `NodeRecord.tenant_id`
    /// at registration time. Used to filter `online_nodes(tenant_slug)`
    /// without an extra DB lookup. If a node is later re-bound to a
    /// different tenant (operator action), the value here goes stale
    /// until the agent reconnects — acceptable because tenant moves are
    /// rare and the controller does not currently push tenant changes
    /// down to live sessions.
    tenant_slug: String,
}

// ── Manager ───────────────────────────────────────────────────────────────────

/// Tracks all currently connected agents and allows the controller to push
/// `ControllerMessage`s to individual nodes or all nodes.
///
/// Thread-safe via a `std::sync::Mutex` — all operations on the map are brief
/// (no async work while holding the lock).
#[derive(Default)]
pub struct NodeSessionManager {
    sessions: Mutex<HashMap<String, NodeSession>>,
}

impl NodeSessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly connected agent. Replaces any existing session for the
    /// same node (previous connection was dropped). `tenant_slug` is the
    /// node's tenant at register time — used by `online_nodes(tenant_slug)`
    /// so the GraphQL surface can scope the list without a DB hit.
    pub fn register(
        &self,
        node_id: String,
        tenant_slug: String,
        tx: mpsc::Sender<Result<ControllerMessage, Status>>,
    ) {
        let mut map = self.sessions.lock().unwrap();
        log::info!("Node {} registered (tenant={})", node_id, tenant_slug);
        map.insert(node_id, NodeSession { tx, tenant_slug });
    }

    /// Remove the session for a node that has disconnected.
    pub fn unregister(&self, node_id: &str) {
        self.sessions.lock().unwrap().remove(node_id);
        log::info!("Node {} unregistered", node_id);
    }

    /// Remove the session only if the map still holds *this* stream's sender.
    ///
    /// When a node reconnects before its old stream is cleaned up, the map is
    /// already overwritten with the new sender.  Calling plain `unregister`
    /// from the old stream's teardown would evict the live session.
    /// `unregister_if_sender` avoids that by comparing channel identity.
    pub fn unregister_if_sender(
        &self,
        node_id: &str,
        tx: &mpsc::Sender<Result<ControllerMessage, Status>>,
    ) {
        let mut map = self.sessions.lock().unwrap();
        if let Some(session) = map.get(node_id) {
            if session.tx.same_channel(tx) {
                map.remove(node_id);
                log::info!("Node {} unregistered via unregister_if_sender", node_id);
            }
        }
    }

    /// Push a message to a single connected agent.
    ///
    /// Returns `true` if the node was online and the message was queued,
    /// `false` if the node is not currently connected.
    pub async fn push(&self, node_id: &str, msg: ControllerMessage) -> bool {
        // Clone the sender while holding the (sync) lock, then send outside it.
        let tx = {
            let map = self.sessions.lock().unwrap();
            map.get(node_id).map(|s| s.tx.clone())
        };
        match tx {
            Some(tx) => tx.send(Ok(msg)).await.is_ok(),
            None => false,
        }
    }

    /// Push a message to all currently connected agents.
    /// Returns the count of nodes that were sent to.
    pub async fn push_all(&self, msg: ControllerMessage) -> usize {
        let senders: Vec<(String, mpsc::Sender<Result<ControllerMessage, Status>>)> = {
            let map = self.sessions.lock().unwrap();
            map.iter()
                .map(|(id, s)| (id.clone(), s.tx.clone()))
                .collect()
        };
        let mut count = 0;
        for (_, tx) in senders {
            if tx.send(Ok(msg.clone())).await.is_ok() {
                count += 1;
            }
        }
        count
    }

    /// Return the IDs of currently connected nodes in `tenant_slug`.
    /// Cross-tenant visibility is not supported on this surface — the
    /// GraphQL `onlineNodes` resolver always passes
    /// `principal.tenant_slug`. Background tasks that need the full
    /// fleet view (controller-internal reconciliation, metrics) should
    /// hold an `Arc<NodeSessionManager>` directly and add a separate
    /// admin-scoped accessor if a use case arises.
    pub fn online_nodes(&self, tenant_slug: &str) -> Vec<String> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| s.tenant_slug == tenant_slug)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Total number of connected agents across all tenants. Intended for
    /// fleet-wide internal metrics (Prometheus exporter) — not exposed
    /// through any tenant-scoped surface. Anything user-facing should go
    /// through `online_nodes(tenant_slug)`.
    pub fn online_count_all_tenants(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Returns `true` if the node is currently connected.
    pub fn is_online(&self, node_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(node_id)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use policy_controller_proto::controller::{controller_message::Payload, Disconnect};

    fn test_msg(reason: &str) -> ControllerMessage {
        ControllerMessage {
            payload: Some(Payload::Disconnect(Disconnect {
                reason: reason.to_string(),
            })),
        }
    }

    #[tokio::test]
    async fn test_register_and_online() {
        let mgr = NodeSessionManager::new();
        assert!(!mgr.is_online("n1"));
        assert!(mgr.online_nodes("default").is_empty());

        let (tx, _rx) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx);

        assert!(mgr.is_online("n1"));
        assert_eq!(mgr.online_nodes("default"), vec!["n1"]);
        // Other tenants can't see this node.
        assert!(mgr.online_nodes("acme").is_empty());
    }

    #[tokio::test]
    async fn test_online_nodes_filters_by_tenant() {
        let mgr = NodeSessionManager::new();
        let (tx_a, _rx_a) = mpsc::channel(8);
        let (tx_b, _rx_b) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx_a);
        mgr.register("n2".to_string(), "acme".to_string(), tx_b);

        assert_eq!(mgr.online_nodes("default"), vec!["n1"]);
        assert_eq!(mgr.online_nodes("acme"), vec!["n2"]);
    }

    #[tokio::test]
    async fn test_unregister() {
        let mgr = NodeSessionManager::new();
        let (tx, _rx) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx);
        mgr.unregister("n1");
        assert!(!mgr.is_online("n1"));
    }

    #[tokio::test]
    async fn test_push_to_connected_node() {
        let mgr = NodeSessionManager::new();
        let (tx, mut rx) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx);

        let sent = mgr.push("n1", test_msg("hello")).await;
        assert!(sent, "Should succeed for connected node");

        let received = rx.recv().await.unwrap().unwrap();
        assert!(matches!(received.payload, Some(Payload::Disconnect(_))));
    }

    #[tokio::test]
    async fn test_push_to_offline_node() {
        let mgr = NodeSessionManager::new();
        let sent = mgr.push("n1", test_msg("hello")).await;
        assert!(!sent, "Should fail for offline node");
    }

    #[tokio::test]
    async fn test_push_all() {
        let mgr = NodeSessionManager::new();
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx1);
        mgr.register("n2".to_string(), "default".to_string(), tx2);

        let count = mgr.push_all(test_msg("broadcast")).await;
        assert_eq!(count, 2);
        assert!(rx1.recv().await.is_some());
        assert!(rx2.recv().await.is_some());
    }

    #[tokio::test]
    async fn test_replace_session_on_reconnect() {
        let mgr = NodeSessionManager::new();
        let (tx_old, _rx_old) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx_old);

        // Re-register (reconnect) — new sender
        let (tx_new, mut rx_new) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx_new);

        mgr.push("n1", test_msg("via new session")).await;
        assert!(rx_new.recv().await.is_some());
        // Still only one node
        assert_eq!(mgr.online_nodes("default").len(), 1);
    }

    #[tokio::test]
    async fn test_unregister_if_sender_matches() {
        let mgr = NodeSessionManager::new();
        let (tx, _rx) = mpsc::channel(8);
        mgr.register("n1".to_string(), "default".to_string(), tx.clone());

        mgr.unregister_if_sender("n1", &tx);
        assert!(
            !mgr.is_online("n1"),
            "Session should be removed when tx matches"
        );
    }

    #[tokio::test]
    async fn test_unregister_if_sender_does_not_remove_newer_session() {
        let mgr = NodeSessionManager::new();
        let (tx_old, _rx_old) = mpsc::channel(8);
        let (tx_new, _rx_new) = mpsc::channel(8);

        mgr.register("n1".to_string(), "default".to_string(), tx_old.clone());
        // Reconnect overwrites the old session
        mgr.register("n1".to_string(), "default".to_string(), tx_new.clone());

        // Old stream teardown: should NOT evict the new session
        mgr.unregister_if_sender("n1", &tx_old);
        assert!(
            mgr.is_online("n1"),
            "New session must survive teardown of the old stream"
        );
    }
}
