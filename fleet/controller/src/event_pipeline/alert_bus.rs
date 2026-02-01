// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Broadcast bus for alert-rule mutations.
//!
//! GraphQL CRUD mutations publish on this bus; the matcher subscribes and
//! rebuilds its compiled `MatchSpec` for the affected rule atomically (see
//! docs/event-pipeline.md "Hot reload"). Kept distinct from
//! `RuleLifecycleBus`, which broadcasts *policy*-rule lifecycle events
//! (node/interface/direction) for the existing data-plane UI.

use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlertRuleChange {
    Created(i64),
    Updated(i64),
    /// Matcher should drop the compiled rule + emit RESOLVED for any group
    /// keyed off it (see grouper "deleted_rule_drops_group_silently").
    Deleted(i64),
}

impl AlertRuleChange {
    pub fn rule_id(&self) -> i64 {
        match self {
            AlertRuleChange::Created(id)
            | AlertRuleChange::Updated(id)
            | AlertRuleChange::Deleted(id) => *id,
        }
    }
}

#[derive(Clone)]
pub struct AlertRuleBus {
    tx: broadcast::Sender<AlertRuleChange>,
}

impl Default for AlertRuleBus {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }
}

impl AlertRuleBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Best-effort publish: returns the number of receivers that got the
    /// message. Zero subscribers is fine — the matcher just isn't running
    /// in this process (e.g. tests).
    pub fn publish(&self, change: AlertRuleChange) -> usize {
        self.tx.send(change).unwrap_or(0)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AlertRuleChange> {
        self.tx.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_reaches_subscribers() {
        let bus = AlertRuleBus::new();
        let mut rx = bus.subscribe();
        let delivered = bus.publish(AlertRuleChange::Created(7));
        assert_eq!(delivered, 1);
        let got = rx.recv().await.unwrap();
        assert_eq!(got, AlertRuleChange::Created(7));
        assert_eq!(got.rule_id(), 7);
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_ok() {
        let bus = AlertRuleBus::new();
        // No-op (returns 0). Important: we shouldn't crash when GraphQL
        // mutations run before the matcher task has subscribed.
        assert_eq!(bus.publish(AlertRuleChange::Updated(1)), 0);
    }

    #[tokio::test]
    async fn multiple_subscribers_all_receive() {
        let bus = AlertRuleBus::new();
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
        bus.publish(AlertRuleChange::Deleted(42));
        assert_eq!(a.recv().await.unwrap(), AlertRuleChange::Deleted(42));
        assert_eq!(b.recv().await.unwrap(), AlertRuleChange::Deleted(42));
    }
}
