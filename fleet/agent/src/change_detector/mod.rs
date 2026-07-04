// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Detects local config changes on the policy-engine (e.g., rules added via CLI)
//! by comparing current state against a known baseline.

use policy_controller_proto::controller::{PersistedRule, StateSnapshot};
use std::collections::HashSet;

/// Detected local changes relative to the baseline.
#[derive(Debug, Clone)]
pub struct LocalChanges {
    pub added_rules: Vec<PersistedRule>,
    pub deleted_rule_ids: Vec<u64>,
}

/// Detects changes between the local policy-engine state and a known baseline.
#[cfg_attr(test, mockall::automock)]
pub trait ChangeDetector: Send + Sync {
    /// Diff the supplied `current` rules against the baseline. Returns
    /// `Some(changes)` if they differ, `None` if in sync.
    ///
    /// The caller fetches the current engine state and passes it in so that the
    /// diff decision, the reported `LocalChange` payload, and the new baseline
    /// all derive from a *single* consistent read. Splitting the read (one for
    /// the diff, another for the payload) lets the agent report a rule as
    /// deleted while shipping a snapshot that still lists it, so the deletion
    /// re-fires every tick and never converges.
    fn diff_against_baseline(&self, current: &[PersistedRule]) -> Option<LocalChanges>;

    /// Update the baseline to match the given snapshot (called after config push
    /// is applied or after a successful poll).
    fn update_baseline(&self, snapshot: &StateSnapshot);
}

/// Default implementation that diffs engine snapshots against a baseline.
///
/// The caller (the change-detector tick) owns the GraphQL fetch and hands the
/// resulting snapshot to [`ChangeDetector::diff_against_baseline`], so the
/// detector itself holds only the baseline.
#[derive(Default)]
pub struct PollingChangeDetector {
    baseline: std::sync::Mutex<Vec<PersistedRule>>,
}

impl PollingChangeDetector {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ChangeDetector for PollingChangeDetector {
    fn diff_against_baseline(&self, current: &[PersistedRule]) -> Option<LocalChanges> {
        let baseline = self.baseline.lock().unwrap().clone();

        let baseline_ids: HashSet<u64> = baseline.iter().map(|r| r.id).collect();
        let current_ids: HashSet<u64> = current.iter().map(|r| r.id).collect();

        let added: Vec<PersistedRule> = current
            .iter()
            .filter(|r| !baseline_ids.contains(&r.id))
            .cloned()
            .collect();

        let deleted: Vec<u64> = baseline_ids
            .iter()
            .filter(|id| !current_ids.contains(id))
            .copied()
            .collect();

        if added.is_empty() && deleted.is_empty() {
            None
        } else {
            Some(LocalChanges {
                added_rules: added,
                deleted_rule_ids: deleted,
            })
        }
    }

    fn update_baseline(&self, snapshot: &StateSnapshot) {
        let mut baseline = self.baseline.lock().unwrap();
        *baseline = snapshot.rules.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: u64) -> PersistedRule {
        PersistedRule {
            id,
            params_json: vec![],
        }
    }

    #[test]
    fn test_update_baseline() {
        let detector = PollingChangeDetector::new();

        let snapshot = StateSnapshot {
            rules: vec![make_rule(1), make_rule(2)],
            attachments: vec![],
            default_actions: Default::default(),
            fib_forwarding_interfaces: Vec::new(),
            per_interface_default_actions: Default::default(),
            stop_behavior: String::new(),
            urpf_interfaces: Default::default(),
            ..Default::default()
        };

        detector.update_baseline(&snapshot);
        let baseline = detector.baseline.lock().unwrap();
        assert_eq!(baseline.len(), 2);
    }
}
