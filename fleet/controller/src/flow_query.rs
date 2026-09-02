// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Correlation registry for live flow-verdict-cache queries.
//!
//! The flow verdict cache is live BPF state on each node, not part of the
//! Prometheus snapshot the agent pushes. To read it on demand the controller
//! sends a [`FlowVerdictQuery`](policy_controller_proto::controller::FlowVerdictQuery)
//! to the agent over the management stream and waits for the matching
//! [`FlowVerdictSnapshot`](policy_controller_proto::controller::FlowVerdictSnapshot)
//! reply. This registry bridges the two halves: the GraphQL resolver registers
//! a request and awaits a oneshot; the gRPC stream handler resolves it when the
//! agent's reply arrives.

use std::collections::HashMap;
use std::sync::Mutex;

use policy_controller_proto::controller::FlowVerdictSnapshot;
use tokio::sync::oneshot;
use uuid::Uuid;

/// Tracks in-flight flow-verdict queries keyed by a unique request ID.
#[derive(Default)]
pub struct FlowQueryRegistry {
    waiters: Mutex<HashMap<String, oneshot::Sender<FlowVerdictSnapshot>>>,
}

impl FlowQueryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new query. Returns the generated request ID (to put in the
    /// outgoing `FlowVerdictQuery`) and the receiver to await the reply on.
    pub fn register(&self) -> (String, oneshot::Receiver<FlowVerdictSnapshot>) {
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().unwrap().insert(request_id.clone(), tx);
        (request_id, rx)
    }

    /// Resolve a pending query with the agent's reply. No-op if the request ID
    /// is unknown (already resolved, timed out, or never registered here).
    pub fn resolve(&self, snapshot: FlowVerdictSnapshot) {
        let waiter = self.waiters.lock().unwrap().remove(&snapshot.request_id);
        if let Some(tx) = waiter {
            // Receiver may have dropped (caller timed out) — ignore send error.
            let _ = tx.send(snapshot);
        }
    }

    /// Drop a pending waiter without resolving it. Called by the resolver path
    /// when its await times out, so the map doesn't leak entries for replies
    /// that never arrive.
    pub fn cancel(&self, request_id: &str) {
        self.waiters.lock().unwrap().remove(request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_controller_proto::controller::FlowVerdictEntryProto;

    fn snapshot(request_id: &str) -> FlowVerdictSnapshot {
        FlowVerdictSnapshot {
            request_id: request_id.to_string(),
            direction: "ingress".to_string(),
            ok: true,
            error: String::new(),
            entries: vec![FlowVerdictEntryProto {
                src_ip: "10.0.0.1".to_string(),
                dst_ip: "10.0.0.2".to_string(),
                src_port: 1234,
                dst_port: 443,
                protocol: "tcp".to_string(),
                action: "DROP".to_string(),
                expires_ns: 0,
                expired: false,
                packets: 1,
                bytes: 64,
            }],
        }
    }

    #[tokio::test]
    async fn register_then_resolve_delivers_snapshot() {
        let reg = FlowQueryRegistry::new();
        let (id, rx) = reg.register();
        reg.resolve(snapshot(&id));
        let got = rx.await.expect("waiter should receive snapshot");
        assert!(got.ok);
        assert_eq!(got.entries.len(), 1);
    }

    #[tokio::test]
    async fn resolve_unknown_id_is_noop() {
        let reg = FlowQueryRegistry::new();
        let (_id, rx) = reg.register();
        reg.resolve(snapshot("some-other-id"));
        // Our waiter is still pending; cancel it so rx errors rather than hangs.
        drop(reg);
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn cancel_removes_waiter() {
        let reg = FlowQueryRegistry::new();
        let (id, rx) = reg.register();
        reg.cancel(&id);
        // A late reply now finds no waiter and is dropped.
        reg.resolve(snapshot(&id));
        assert!(rx.await.is_err());
    }
}
