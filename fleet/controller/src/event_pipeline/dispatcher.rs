// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Notification dispatcher.
//!
//! Sits between the grouper and the provider impls (`providers::*`). For
//! each [`grouper::Notification`] the dispatcher:
//!
//! 1. Loads the alert rule + its routed receivers.
//! 2. Applies any active silences (best-effort — see "Silences" below).
//! 3. For each receiver, looks up the provider by `kind` and runs the
//!    send with exponential-backoff retry.
//! 4. Writes an `alert_history` row recording the outcome.
//!
//! Per-receiver bounded queues + worker pool are listed in the spec but
//! deferred to a step-4 follow-up; the synchronous `dispatch()` here is
//! adequate while the grouper runs on a single tokio task and notifications
//! are sparse. When that stops being true, slot a per-receiver
//! `mpsc::Sender<DispatchJob>` in front of `send_with_retry`.
//!
//! ## Silences
//!
//! A silence is an event-shaped `MatchSpec` plus a `[starts_at, ends_at)`
//! window. The grouper carries a `sample_event` on every notification (the
//! first matching event captured when the group was created); the
//! dispatcher compiles each active silence's `matcher_json` and evaluates
//! it against that sample. First match wins → the notification is
//! suppressed, `notifications_silenced_total` ticks, and the
//! `alert_history` row records `silenced=1`.
//!
//! Caveats:
//! - **Compile errors are tolerated.** A bad silence is logged and skipped
//!   so one fat-fingered MatchSpec can't black-hole every alert. Writes go
//!   through `MatchSpec::compile_json` already (alert_store), so this is
//!   defensive against drift / hand-edited rows.
//! - **`sample_event = None` → not silenced.** Defensive; shouldn't happen
//!   from the current grouper, but if a synthetic Notification ever lands
//!   here without one, silences silently disengage rather than firing
//!   randomly.
//! - **Fields outside `group_by` may differ within the group.** The sample
//!   is the *first* event; later events may carry e.g. a different
//!   `src_ip`. A silence keyed on a non-group-by field can therefore
//!   suppress a notification representing some events that wouldn't have
//!   matched the silence individually. Document expectations in the
//!   user-facing silence docs when the UI ships.

use anyhow::{Context, Result};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::alert_metrics::AlertPipelineMetrics;
use super::alert_store::{AlertRule, AlertStore, NewAlertHistory, Receiver, Silence};
use super::grouper::Notification;
use super::matcher::MatchSpec;
use super::providers::{NotificationKindStr, NotificationPayload, Notifier};
use super::tenant::TenantScope;

#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    pub max_attempts: u32,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
        }
    }
}

#[derive(Debug)]
pub struct ReceiverOutcome {
    pub receiver_id: i64,
    pub attempts: u32,
    /// `Err(s)` carries the final-attempt error message — sufficient for
    /// metrics + operator logs.
    pub result: std::result::Result<(), String>,
}

#[derive(Debug)]
pub struct DispatchOutcome {
    pub silenced: bool,
    /// `None` only when persisting the history row itself failed.
    pub history_id: Option<i64>,
    pub per_receiver: Vec<ReceiverOutcome>,
}

pub struct AlertDispatcher {
    scope: Arc<TenantScope>,
    /// Keyed by `receivers.kind`. The dispatcher does not invent providers
    /// — a receiver pointing at an unregistered kind fails dispatch loudly
    /// rather than silently dropping.
    notifiers: HashMap<String, Arc<dyn Notifier>>,
    config: DispatcherConfig,
    metrics: Arc<AlertPipelineMetrics>,
}

impl AlertDispatcher {
    pub fn new(
        scope: Arc<TenantScope>,
        notifiers: HashMap<String, Arc<dyn Notifier>>,
        config: DispatcherConfig,
        metrics: Arc<AlertPipelineMetrics>,
    ) -> Self {
        Self {
            scope,
            notifiers,
            config,
            metrics,
        }
    }

    pub async fn dispatch(&self, notification: Notification) -> Result<DispatchOutcome> {
        let store = AlertStore::new(&self.scope);
        let rule = store
            .get_rule(notification.rule_id)
            .await?
            .with_context(|| format!("alert_rule id={} no longer exists", notification.rule_id))?;
        let receiver_ids: Vec<i64> = serde_json::from_str(&rule.receiver_ids)
            .context("corrupt receiver_ids on alert_rule")?;
        // Load every routed receiver. Missing IDs are surfaced as a per-
        // receiver failure rather than aborting the whole dispatch — one
        // misconfigured route shouldn't black-hole the others.
        let all_receivers = store.list_receivers().await?;
        let by_id: HashMap<i64, Receiver> = all_receivers.into_iter().map(|r| (r.id, r)).collect();

        let active_silences = store
            .list_silences(Some(notification.at_ns / 1_000_000_000))
            .await
            .unwrap_or_default();
        let silenced = is_silenced(&rule, &notification, &active_silences);
        if silenced {
            self.metrics.record_silenced();
        }

        let payload = build_payload(&rule, &notification);

        let mut per_receiver = Vec::with_capacity(receiver_ids.len());
        if !silenced {
            for rid in &receiver_ids {
                let outcome = match by_id.get(rid) {
                    Some(receiver) => self.send_one(receiver, &payload).await,
                    None => ReceiverOutcome {
                        receiver_id: *rid,
                        attempts: 0,
                        result: Err(format!("receiver id={rid} not found")),
                    },
                };
                let kind = by_id.get(rid).map(|r| r.kind.as_str()).unwrap_or("unknown");
                self.metrics.record_dispatched(
                    kind,
                    outcome.result.is_ok(),
                    outcome.attempts.max(1),
                );
                per_receiver.push(outcome);
            }
        }

        let history_id = store
            .append_history(NewAlertHistory {
                rule_id: rule.id,
                group_key: notification.group_key.0.clone(),
                fired_at: notification.at_ns / 1_000_000_000,
                event_count: notification.event_count,
                sample_event_ids: notification.sample_event_ids.clone(),
                silenced,
            })
            .await
            .ok();

        Ok(DispatchOutcome {
            silenced,
            history_id,
            per_receiver,
        })
    }

    async fn send_one(
        &self,
        receiver: &Receiver,
        payload: &NotificationPayload,
    ) -> ReceiverOutcome {
        let notifier = match self.notifiers.get(&receiver.kind) {
            Some(n) => n,
            None => {
                return ReceiverOutcome {
                    receiver_id: receiver.id,
                    attempts: 0,
                    result: Err(format!(
                        "no provider registered for kind '{}'",
                        receiver.kind
                    )),
                };
            }
        };
        let mut last_err: Option<String> = None;
        for attempt in 1..=self.config.max_attempts {
            match notifier.send(receiver, payload).await {
                Ok(()) => {
                    return ReceiverOutcome {
                        receiver_id: receiver.id,
                        attempts: attempt,
                        result: Ok(()),
                    };
                }
                Err(e) => {
                    last_err = Some(format!("{e:#}"));
                    if attempt == self.config.max_attempts {
                        break;
                    }
                    let delay_ms = backoff_ms(
                        attempt,
                        self.config.base_backoff_ms,
                        self.config.max_backoff_ms,
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
        ReceiverOutcome {
            receiver_id: receiver.id,
            attempts: self.config.max_attempts,
            result: Err(last_err.unwrap_or_else(|| "unknown error".into())),
        }
    }
}

fn build_payload(rule: &AlertRule, n: &Notification) -> NotificationPayload {
    NotificationPayload {
        rule_id: rule.id,
        rule_name: rule.name.clone(),
        severity: rule.severity.clone(),
        group_key: n.group_key.0.clone(),
        kind: NotificationKindStr::from(n.kind),
        fired_at: chrono::Utc
            .timestamp_opt(n.at_ns / 1_000_000_000, (n.at_ns % 1_000_000_000) as u32)
            .single()
            .unwrap_or_else(chrono::Utc::now),
        event_count: n.event_count,
        sample_event_ids: n.sample_event_ids.clone(),
    }
}

use chrono::TimeZone;

/// Exponential backoff with full jitter: delay = rand(0, min(cap, base * 2^n)).
/// `attempt` is 1-indexed; the first retry uses `attempt=1`.
fn backoff_ms(attempt: u32, base_ms: u64, cap_ms: u64) -> u64 {
    let exp = base_ms.saturating_mul(1u64 << attempt.min(20));
    let bound = exp.min(cap_ms).max(1);
    rand::thread_rng().gen_range(0..bound)
}

/// True if any of `active` matches the notification's sample event. See the
/// module-level "Silences" section for the design rationale and caveats.
fn is_silenced(_rule: &AlertRule, n: &Notification, active: &[Silence]) -> bool {
    let Some(ev) = n.sample_event.as_ref() else {
        return false;
    };
    for s in active {
        match MatchSpec::compile_json(&s.matcher_json) {
            Ok(compiled) => {
                if compiled.matches(ev) {
                    return true;
                }
            }
            Err(e) => {
                // Compile failures here mean the row drifted from what
                // alert_store accepts — log and skip rather than wedging
                // dispatch on one bad row.
                log::warn!(
                    "dispatcher: skipping silence id={} (compile failed): {e:#}",
                    s.id
                );
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::{
        alert_store::{NewAlertRule, NewReceiver, NewSilence},
        bootstrap_default_tenant,
        grouper::{GroupKey, NotificationKind},
        providers::testing::MockNotifier,
        types::{Action, Direction, PolicyEvent},
    };
    use sqlx::sqlite::SqlitePool;

    fn stub_event() -> PolicyEvent {
        PolicyEvent {
            ts_ns: 1_700_000_000_000_000_000,
            node_id: "n1".into(),
            rule_id: 42,
            action: Action::Drop,
            verdict: 1,
            direction: Direction::Ingress,
            ifindex: 1,
            proto: 6,
            src_ip: vec![10, 0, 0, 1],
            dst_ip: vec![10, 0, 0, 2],
            sport: 51000,
            dport: 22,
            pkt_len: 64,
            flags: None,
            sni: Some("login.evil.com".into()),
        }
    }

    async fn setup() -> (Arc<TenantScope>, i64, i64) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let scope = Arc::new(bootstrap_default_tenant(pool).await.unwrap());
        let store = AlertStore::new(&scope);
        let r = store
            .create_receiver(NewReceiver {
                name: "ops".into(),
                kind: "webhook".into(),
                config_json: r#"{"url":"https://example.invalid"}"#.into(),
            })
            .await
            .unwrap();
        let rule = store
            .create_rule(
                NewAlertRule {
                    name: "r1".into(),
                    enabled: true,
                    match_json: r#"{"action":["drop"]}"#.into(),
                    group_by: vec!["rule_id".into()],
                    threshold_count: None,
                    threshold_window_s: None,
                    group_wait_s: 30,
                    group_interval_s: 300,
                    repeat_interval_s: 14_400,
                    resolve_after_s: 1_500,
                    severity: "warning".into(),
                    receiver_ids: vec![r.id],
                },
                0,
            )
            .await
            .unwrap();
        (scope, rule.id, r.id)
    }

    fn notif(rule_id: i64) -> Notification {
        Notification {
            rule_id,
            group_key: GroupKey("k1".into()),
            kind: NotificationKind::InitialFire,
            at_ns: 1_700_000_000_000_000_000,
            event_count: 3,
            sample_event_ids: vec![1, 2, 3],
            sample_event: Some(stub_event()),
        }
    }

    fn dispatcher(
        scope: Arc<TenantScope>,
        mock: Arc<MockNotifier>,
    ) -> (AlertDispatcher, Arc<AlertPipelineMetrics>) {
        let mut notifiers: HashMap<String, Arc<dyn Notifier>> = HashMap::new();
        notifiers.insert("webhook".into(), mock as Arc<dyn Notifier>);
        let metrics = Arc::new(AlertPipelineMetrics::new());
        let d = AlertDispatcher::new(
            scope,
            notifiers,
            DispatcherConfig {
                // Tests should not sleep for seconds.
                max_attempts: 3,
                base_backoff_ms: 1,
                max_backoff_ms: 2,
            },
            Arc::clone(&metrics),
        );
        (d, metrics)
    }

    #[tokio::test]
    async fn dispatch_success_writes_history_and_calls_notifier() {
        let (scope, rule_id, _r) = setup().await;
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert!(!out.silenced);
        assert!(out.history_id.is_some());
        assert_eq!(out.per_receiver.len(), 1);
        assert!(out.per_receiver[0].result.is_ok());
        assert_eq!(out.per_receiver[0].attempts, 1);
        assert_eq!(mock.call_count(), 1);
        let calls = mock.calls();
        assert_eq!(calls[0].1.rule_id, rule_id);
        assert_eq!(calls[0].1.group_key, "k1");
        assert_eq!(calls[0].1.severity, "warning");
        assert_eq!(calls[0].1.sample_event_ids, vec![1, 2, 3]);
        assert_eq!(calls[0].1.kind, NotificationKindStr::Initial);
        // History row reflects silenced=false and the event count.
        let hist = AlertStore::new(&scope)
            .list_history(&Default::default(), 10)
            .await
            .unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].event_count, 3);
        assert!(!hist[0].silenced);
    }

    #[tokio::test]
    async fn retries_on_transient_failure_then_succeeds() {
        let (scope, rule_id, _r) = setup().await;
        let mock = Arc::new(MockNotifier::new("webhook").fail_first(2));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert!(out.per_receiver[0].result.is_ok());
        // 2 failures + 1 success = 3 attempts == max_attempts; still ok.
        assert_eq!(out.per_receiver[0].attempts, 3);
        assert_eq!(mock.call_count(), 3);
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let (scope, rule_id, _r) = setup().await;
        let mock = Arc::new(MockNotifier::new("webhook").fail_first(10));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert!(out.per_receiver[0].result.is_err());
        assert_eq!(out.per_receiver[0].attempts, 3); // max_attempts
        assert_eq!(mock.call_count(), 3);
        // Even on failure we record the firing — the history row is how
        // the UI shows "we tried to alert but it didn't get through".
        assert!(out.history_id.is_some());
    }

    #[tokio::test]
    async fn unknown_receiver_kind_fails_without_attempt() {
        let (scope, rule_id, r_id) = setup().await;
        // Mutate the receiver in-place to a kind no provider is registered
        // for. Validation forbids creating one this way, so go via the
        // store with raw SQL — we want to test the dispatcher branch, not
        // the input validation.
        sqlx::query("UPDATE receivers SET kind = 'pagerduty' WHERE id = ?")
            .bind(r_id)
            .execute(scope.pool())
            .await
            .unwrap();
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert_eq!(mock.call_count(), 0);
        assert!(out.per_receiver[0]
            .result
            .as_ref()
            .err()
            .unwrap()
            .contains("no provider registered"));
    }

    #[tokio::test]
    async fn missing_receiver_id_is_per_route_failure_not_dispatch_abort() {
        let (scope, rule_id, r_id) = setup().await;
        // Delete the receiver out from under the rule. The store refuses
        // delete_receiver while in use, so do it via raw SQL.
        sqlx::query("DELETE FROM receivers WHERE id = ?")
            .bind(r_id)
            .execute(scope.pool())
            .await
            .unwrap();
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert_eq!(out.per_receiver.len(), 1);
        assert!(out.per_receiver[0]
            .result
            .as_ref()
            .err()
            .unwrap()
            .contains("not found"));
        // Still wrote history — operator visibility matters even when
        // routes are broken.
        assert!(out.history_id.is_some());
    }

    #[tokio::test]
    async fn matching_silence_suppresses_dispatch() {
        // Silence on action=drop, sample event is action=drop → notifier
        // must not be called, history must record silenced=true, and the
        // notifications_silenced_total metric must tick.
        let (scope, rule_id, _r) = setup().await;
        AlertStore::new(&scope)
            .create_silence(NewSilence {
                matcher_json: r#"{"action":["drop"]}"#.into(),
                starts_at: 0,
                ends_at: i64::MAX / 2,
                created_by: None,
                comment: None,
            })
            .await
            .unwrap();
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert!(out.silenced);
        assert_eq!(mock.call_count(), 0);
        assert!(
            out.per_receiver.is_empty(),
            "no per-receiver attempts when silenced"
        );
        let hist = AlertStore::new(&scope)
            .list_history(&Default::default(), 10)
            .await
            .unwrap();
        assert_eq!(hist.len(), 1);
        assert!(hist[0].silenced);
        let txt = metrics.render("default");
        assert!(
            txt.contains("notifications_silenced_total{tenant=\"default\"} 1"),
            "silenced counter not incremented:\n{txt}"
        );
    }

    #[tokio::test]
    async fn non_matching_silence_does_not_suppress() {
        // Silence on action=log; sample event is action=drop → dispatches
        // normally and silenced=false.
        let (scope, rule_id, _r) = setup().await;
        AlertStore::new(&scope)
            .create_silence(NewSilence {
                matcher_json: r#"{"action":["log"]}"#.into(),
                starts_at: 0,
                ends_at: i64::MAX / 2,
                created_by: None,
                comment: None,
            })
            .await
            .unwrap();
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert!(!out.silenced);
        assert_eq!(mock.call_count(), 1);
        let txt = metrics.render("default");
        assert!(
            txt.contains("notifications_silenced_total{tenant=\"default\"} 0"),
            "silenced counter should be 0 for non-matching silence:\n{txt}"
        );
    }

    #[tokio::test]
    async fn notification_without_sample_event_is_not_silenced() {
        // Defensive: if a Notification reaches us with no sample event we
        // can't evaluate event-shaped silences, so we let it through rather
        // than dropping it on the floor.
        let (scope, rule_id, _r) = setup().await;
        AlertStore::new(&scope)
            .create_silence(NewSilence {
                matcher_json: r#"{"action":["drop"]}"#.into(),
                starts_at: 0,
                ends_at: i64::MAX / 2,
                created_by: None,
                comment: None,
            })
            .await
            .unwrap();
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let mut n = notif(rule_id);
        n.sample_event = None;
        let out = d.dispatch(n).await.unwrap();
        assert!(!out.silenced);
        assert_eq!(mock.call_count(), 1);
    }
}
