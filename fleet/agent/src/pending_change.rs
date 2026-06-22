// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Agent-side pending-change registry.
//!
//! Tracks locally-applied config pushes that have not yet been acknowledged as
//! committed by the controller. Each pending change carries the inverse ops
//! needed to roll back and a watchdog task that fires revert + `REVERTED`
//! confirm if the controller's `CommitAck` is not received in time.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use policy_controller_proto::controller::{
    agent_message::Payload as AgentPayload, config_confirm::Outcome, AgentMessage, ConfigConfirm,
};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::config_applier::{ConfigApplier, InverseOp};

/// Per-generation state retained until a `CommitAck` arrives or the watchdog fires.
struct Entry {
    inverse_ops: Vec<InverseOp>,
    watchdog: JoinHandle<()>,
}

/// Registry of locally-applied, not-yet-acknowledged config generations.
#[derive(Default)]
pub struct PendingChangeRegistry {
    inner: Mutex<HashMap<String, Entry>>,
}

/// Grace added to the controller's confirm deadline to derive the agent-side
/// watchdog deadline.
///
/// The controller commits as soon as the agent's `ConfigConfirm{APPLIED}`
/// arrives (any time up to *its* deadline) and only then sends `CommitAck`,
/// which must still travel back to the agent. If the agent's watchdog used the
/// same deadline, a `CommitAck` for a genuinely-committed change could arrive
/// *after* the watchdog already reverted — a false revert that leaves the
/// controller (committed) and node (reverted) in disagreement. Waiting an extra
/// grace period gives a successful `CommitAck` time to return. If the controller
/// instead abandoned the change (channel dead), no `CommitAck` ever comes and
/// the watchdog still fires — just `REVERT_GRACE_MS` later.
pub const REVERT_GRACE_MS: u32 = 60_000;

/// Derive the agent-side watchdog deadline from the controller's confirm
/// deadline by adding [`REVERT_GRACE_MS`].
pub fn watchdog_deadline_ms(controller_deadline_ms: u32) -> u32 {
    controller_deadline_ms.saturating_add(REVERT_GRACE_MS)
}

impl PendingChangeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly applied change. Spawns a watchdog that will revert
    /// the change and emit `ConfigConfirm{REVERTED}` if `CommitAck` does not
    /// arrive within `deadline_ms`.
    pub fn register(
        self: &Arc<Self>,
        generation_id: String,
        inverse_ops: Vec<InverseOp>,
        deadline_ms: u32,
        applier: Arc<ConfigApplier>,
        outbound_tx: mpsc::Sender<AgentMessage>,
    ) {
        // Clamp to a sane range to avoid 0-second or multi-hour deadlines. The
        // ceiling accommodates the controller deadline plus REVERT_GRACE_MS.
        let deadline_ms = deadline_ms.clamp(500, 300_000);

        let registry = Arc::clone(self);
        let gen_id_for_task = generation_id.clone();
        let watchdog = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(deadline_ms as u64)).await;

            // Remove ourselves from the registry. If we're already gone, a
            // CommitAck raced us and claimed the entry — nothing to do.
            let Some(entry) = registry.take(&gen_id_for_task) else {
                return;
            };

            log::warn!(
                "pending_change: watchdog fired for generation {} after {}ms — reverting",
                gen_id_for_task,
                deadline_ms
            );
            applier.apply_inverse(&entry.inverse_ops).await;

            let _ = outbound_tx
                .send(AgentMessage {
                    payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                        generation_id: gen_id_for_task,
                        outcome: Outcome::Reverted as i32,
                        error_message: "agent watchdog: commit ack not received in time"
                            .to_string(),
                    })),
                })
                .await;
        });

        let entry = Entry {
            inverse_ops,
            watchdog,
        };
        // Replacement is unexpected but harmless: drop the old watchdog.
        if let Some(prev) = self
            .inner
            .lock()
            .unwrap()
            .insert(generation_id.clone(), entry)
        {
            prev.watchdog.abort();
            log::warn!(
                "pending_change: generation {} re-registered; aborting prior watchdog",
                generation_id
            );
        }
    }

    /// Called on `CommitAck{committed=true}`: drop the entry and cancel its watchdog.
    pub fn commit(&self, generation_id: &str) {
        if let Some(entry) = self.take(generation_id) {
            entry.watchdog.abort();
        } else {
            log::debug!(
                "pending_change: commit for unknown generation {} (likely already reverted)",
                generation_id
            );
        }
    }

    /// Called on `CommitAck{committed=false}` or externally: apply the inverse
    /// ops and cancel the watchdog. Returns `true` if the generation was known.
    pub async fn revert(
        &self,
        generation_id: &str,
        applier: &ConfigApplier,
        outbound_tx: &mpsc::Sender<AgentMessage>,
        reason: &str,
    ) -> bool {
        let Some(entry) = self.take(generation_id) else {
            return false;
        };
        entry.watchdog.abort();
        applier.apply_inverse(&entry.inverse_ops).await;
        let _ = outbound_tx
            .send(AgentMessage {
                payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                    generation_id: generation_id.to_string(),
                    outcome: Outcome::Reverted as i32,
                    error_message: reason.to_string(),
                })),
            })
            .await;
        true
    }

    /// Drain all pending changes and revert them immediately.
    ///
    /// Must be called when the controller stream terminates. Without this, a
    /// reconnected agent may accept a new gated mutation while a prior
    /// applied-but-unacknowledged change (e.g. a blackhole rule that severed
    /// the stream) is still pending. Any confirm sent for the new mutation
    /// would be swallowed by the stale rule, causing the controller to abandon
    /// it too.
    pub async fn drain_and_revert(&self, applier: &ConfigApplier) {
        let entries: Vec<(String, Entry)> = {
            let mut guard = self.inner.lock().unwrap();
            guard.drain().collect()
        };
        if entries.is_empty() {
            return;
        }
        log::warn!(
            "pending_change: stream closed with {} pending generation(s) — reverting all",
            entries.len()
        );
        for (gen_id, entry) in entries {
            entry.watchdog.abort();
            log::warn!(
                "pending_change: reverting generation {} on stream close",
                gen_id
            );
            applier.apply_inverse(&entry.inverse_ops).await;
        }
    }

    fn take(&self, generation_id: &str) -> Option<Entry> {
        self.inner.lock().unwrap().remove(generation_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_applier::LocalPolicyClient;
    use anyhow::Result;
    use async_trait::async_trait;

    #[derive(Default)]
    struct NoopClient;

    #[async_trait]
    impl LocalPolicyClient for NoopClient {
        async fn flush_rules(&self, _i: &str, _d: &str) -> Result<()> {
            Ok(())
        }
        async fn add_rule_json(&self, _j: &str) -> Result<()> {
            Ok(())
        }
        async fn delete_rule(&self, _id: u64, _iface: &str, _dir: &str) -> Result<()> {
            Ok(())
        }
        async fn set_default_action(&self, _i: &str, _d: &str, _a: &str) -> Result<()> {
            Ok(())
        }
        async fn attach_ingress(&self, _i: &str, _m: &str) -> Result<()> {
            Ok(())
        }
        async fn attach_tc(&self, _i: &str) -> Result<()> {
            Ok(())
        }
        async fn list_attachments(&self) -> Result<Vec<(String, String, String)>> {
            Ok(vec![])
        }
        async fn list_rules_json(&self, _d: &str) -> Result<Vec<(u64, String)>> {
            Ok(vec![])
        }
        async fn configure_stop_behavior(&self, _behavior: &str) -> Result<()> {
            Ok(())
        }
        async fn get_stop_behavior(&self) -> Result<String> {
            Ok(String::new())
        }
        async fn set_urpf(&self, _i: &str, _m: &str) -> Result<()> {
            Ok(())
        }
        async fn get_urpf(&self, _i: &str) -> Result<String> {
            Ok("off".to_string())
        }
        async fn detach_ingress(&self, _i: &str) -> Result<()> {
            Ok(())
        }
        async fn detach_tc(&self, _i: &str) -> Result<()> {
            Ok(())
        }
        async fn set_fib_forwarding(&self, _i: &str, _e: bool) -> Result<()> {
            Ok(())
        }
        async fn get_fib_forwarding(&self, _i: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn test_commit_removes_entry() {
        let reg = Arc::new(PendingChangeRegistry::new());
        let (tx, _rx) = mpsc::channel(4);
        let applier = Arc::new(ConfigApplier::new(Arc::new(NoopClient)));
        reg.register("g1".to_string(), vec![], 10_000, applier, tx);
        assert!(reg.inner.lock().unwrap().contains_key("g1"));
        reg.commit("g1");
        assert!(!reg.inner.lock().unwrap().contains_key("g1"));
    }

    #[tokio::test]
    async fn test_drain_and_revert_reverts_pending() {
        use crate::config_applier::InverseOp;

        #[derive(Default)]
        struct TrackingClient {
            deleted: Mutex<Vec<u64>>,
        }

        #[async_trait]
        impl LocalPolicyClient for TrackingClient {
            async fn flush_rules(&self, _i: &str, _d: &str) -> Result<()> {
                Ok(())
            }
            async fn add_rule_json(&self, _j: &str) -> Result<()> {
                Ok(())
            }
            async fn delete_rule(&self, id: u64, _i: &str, _d: &str) -> Result<()> {
                self.deleted.lock().unwrap().push(id);
                Ok(())
            }
            async fn set_default_action(&self, _i: &str, _d: &str, _a: &str) -> Result<()> {
                Ok(())
            }
            async fn attach_ingress(&self, _i: &str, _m: &str) -> Result<()> {
                Ok(())
            }
            async fn attach_tc(&self, _i: &str) -> Result<()> {
                Ok(())
            }
            async fn list_attachments(&self) -> Result<Vec<(String, String, String)>> {
                Ok(vec![])
            }
            async fn list_rules_json(&self, _d: &str) -> Result<Vec<(u64, String)>> {
                Ok(vec![])
            }
            async fn configure_stop_behavior(&self, _behavior: &str) -> Result<()> {
                Ok(())
            }
            async fn get_stop_behavior(&self) -> Result<String> {
                Ok(String::new())
            }
            async fn set_urpf(&self, _i: &str, _m: &str) -> Result<()> {
                Ok(())
            }
            async fn get_urpf(&self, _i: &str) -> Result<String> {
                Ok("off".to_string())
            }
            async fn detach_ingress(&self, _i: &str) -> Result<()> {
                Ok(())
            }
            async fn detach_tc(&self, _i: &str) -> Result<()> {
                Ok(())
            }
            async fn set_fib_forwarding(&self, _i: &str, _e: bool) -> Result<()> {
                Ok(())
            }
            async fn get_fib_forwarding(&self, _i: &str) -> Result<bool> {
                Ok(false)
            }
        }

        let client = Arc::new(TrackingClient::default());
        let applier = Arc::new(ConfigApplier::new(
            Arc::clone(&client) as Arc<dyn LocalPolicyClient>
        ));
        let reg = Arc::new(PendingChangeRegistry::new());
        let (tx, _rx) = mpsc::channel(4);

        // Register a generation with an inverse op (delete rule 99).
        let inverse = vec![InverseOp::DeleteRule {
            id: 99,
            interface: "eth0".to_string(),
            direction: "EGRESS".to_string(),
        }];
        reg.register(
            "g-drain".to_string(),
            inverse,
            60_000,
            Arc::clone(&applier),
            tx,
        );

        // drain_and_revert should apply the inverse and clear the registry.
        reg.drain_and_revert(&applier).await;

        assert!(
            reg.inner.lock().unwrap().is_empty(),
            "Registry should be empty after drain"
        );
        let deleted = client.deleted.lock().unwrap();
        assert_eq!(
            *deleted,
            vec![99u64],
            "Inverse op (delete rule 99) must have been applied"
        );
    }

    #[tokio::test]
    async fn test_watchdog_fires_reverted_confirm() {
        let reg = Arc::new(PendingChangeRegistry::new());
        let (tx, mut rx) = mpsc::channel(4);
        let applier = Arc::new(ConfigApplier::new(Arc::new(NoopClient)));
        reg.register("g2".to_string(), vec![], 500, applier, tx);
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("watchdog did not fire")
            .expect("channel closed");
        match msg.payload {
            Some(AgentPayload::ConfigConfirm(c)) => {
                assert_eq!(c.generation_id, "g2");
                assert_eq!(c.outcome, Outcome::Reverted as i32);
            }
            other => panic!("Expected ConfigConfirm, got {:?}", other),
        }
    }

    #[test]
    fn test_watchdog_deadline_adds_grace() {
        // The agent waits the controller's deadline plus the grace, so a
        // CommitAck for a genuinely-committed change has time to return before
        // the watchdog reverts.
        assert_eq!(watchdog_deadline_ms(30_000), 30_000 + REVERT_GRACE_MS);
        // Saturates rather than overflowing for an absurd controller deadline.
        assert_eq!(watchdog_deadline_ms(u32::MAX), u32::MAX);
    }
}
