// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Notification providers for the alert dispatcher.
//!
//! Each provider implements [`Notifier`] and is keyed by the
//! `receivers.kind` column (`webhook`, `email`, `alertmanager`). The
//! dispatcher looks up the implementation at dispatch time, parses the
//! receiver's `config_json` into the provider-specific schema, and hands
//! it a [`NotificationPayload`] to deliver.
//!
//! Providers should be allocation-light per call (one network round trip
//! plus its serialisation) and must return an error rather than panicking
//! on a bad config — the dispatcher's retry/DLQ logic depends on it.

pub mod alertmanager;
pub mod email;
pub mod webhook;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::alert_store::Receiver;
use super::grouper::NotificationKind;

/// Wire payload handed to providers. Kept provider-agnostic — each provider
/// is responsible for shaping it into its own outbound schema.
///
/// Fields mirror what we persist in `alert_history`, plus the rule context
/// the operator configured so receivers can include human-friendly text.
#[derive(Debug, Clone, Serialize)]
pub struct NotificationPayload {
    pub rule_id: i64,
    pub rule_name: String,
    pub severity: String,
    pub group_key: String,
    pub kind: NotificationKindStr,
    pub fired_at: DateTime<Utc>,
    pub event_count: i64,
    pub sample_event_ids: Vec<i64>,
}

/// String form of [`NotificationKind`] for the wire — providers shouldn't
/// have to import the grouper's enum just to render it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationKindStr {
    Initial,
    Refire,
    Resolve,
}

impl From<NotificationKind> for NotificationKindStr {
    fn from(k: NotificationKind) -> Self {
        match k {
            NotificationKind::InitialFire => NotificationKindStr::Initial,
            NotificationKind::Refire => NotificationKindStr::Refire,
            NotificationKind::Resolve => NotificationKindStr::Resolve,
        }
    }
}

/// Outcome the dispatcher's retry loop interprets.
///
/// `Err` is always retryable (transient network / 5xx / timeout); the
/// dispatcher decides whether to give up based on attempt count. For
/// permanent failures (4xx, bad config), providers should still return
/// `Err` — the dispatcher's max_retries cap covers both cases.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Provider name (`webhook`, `email`, `alertmanager`). Used for
    /// dispatcher logging and the receiver-kind lookup.
    fn kind(&self) -> &'static str;

    async fn send(&self, receiver: &Receiver, payload: &NotificationPayload) -> anyhow::Result<()>;
}

#[cfg(test)]
pub mod testing {
    //! Test-only mock notifier. Lives in a `pub mod` so dispatcher tests in
    //! sibling modules can construct it without re-implementing the trait.

    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records every `send()` call. Configurable to fail the first N
    /// attempts so retry tests can exercise the backoff path.
    #[derive(Clone, Default)]
    pub struct MockNotifier {
        pub kind_str: &'static str,
        pub fail_first_n: Arc<Mutex<usize>>,
        pub calls: Arc<Mutex<Vec<(Receiver, NotificationPayload)>>>,
    }

    impl MockNotifier {
        pub fn new(kind: &'static str) -> Self {
            Self {
                kind_str: kind,
                fail_first_n: Arc::new(Mutex::new(0)),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
        pub fn fail_first(self, n: usize) -> Self {
            *self.fail_first_n.lock().unwrap() = n;
            self
        }
        pub fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
        pub fn calls(&self) -> Vec<(Receiver, NotificationPayload)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Notifier for MockNotifier {
        fn kind(&self) -> &'static str {
            self.kind_str
        }
        async fn send(
            &self,
            receiver: &Receiver,
            payload: &NotificationPayload,
        ) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((receiver.clone(), payload.clone()));
            let mut fails = self.fail_first_n.lock().unwrap();
            if *fails > 0 {
                *fails -= 1;
                anyhow::bail!("mock transient failure (remaining={})", *fails);
            }
            Ok(())
        }
    }
}
