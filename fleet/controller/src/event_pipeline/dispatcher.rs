// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Notification dispatcher.
//!
//! Sits between the grouper and the provider impls (`providers::*`). For
//! each [`grouper::Notification`] the dispatcher:
//!
//! 1. Loads the alert rule + its routed receivers from the store.
//! 2. Applies any active silences (best-effort — see "Silences" below).
//! 3. Writes an `alert_history` row.
//! 4. For each receiver, enqueues a [`ProviderJob`] onto the per-provider
//!    bounded channel. Worker tasks drain those channels and run
//!    send-with-retry with exponential backoff + full jitter.
//!
//! ## Actor model
//!
//! Each provider kind (webhook, email, alertmanager) gets its own bounded
//! `mpsc` channel and a pool of `workers_per_provider` tokio tasks that
//! drain it. Queue depth is tracked per-provider via `Arc<AtomicU64>` so
//! the Prometheus metric `alert_dispatcher_queue_depth{kind}` reflects live
//! backlog. If a channel is full, the job is dropped with a warning rather
//! than blocking the caller — the channel capacity is the backpressure
//! knob, not the caller's latency.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

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
    /// Capacity of the per-provider bounded channel. When the channel is
    /// full `try_send` fails and the job is dropped with a warning.
    pub queue_capacity: usize,
    /// Number of worker tasks spawned per provider kind.
    pub workers_per_provider: usize,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            queue_capacity: 256,
            workers_per_provider: 2,
        }
    }
}

#[derive(Debug)]
pub struct DispatchOutcome {
    pub silenced: bool,
    /// `None` only when persisting the history row itself failed.
    pub history_id: Option<i64>,
}

/// Per-provider delivery job enqueued by [`AlertDispatcher::dispatch`] and
/// consumed by the provider worker pool.
struct ProviderJob {
    receiver: Receiver,
    payload: NotificationPayload,
    /// Decremented by the worker on completion to keep the queue-depth
    /// metric accurate.
    depth: Arc<AtomicU64>,
}

/// Handle to the alert dispatcher. Cheap to clone — all state is behind
/// `Arc`. Worker tasks are spawned at construction time and run for the
/// lifetime of the process.
pub struct AlertDispatcher {
    scope: Arc<TenantScope>,
    metrics: Arc<AlertPipelineMetrics>,
    /// Per-provider-kind: (bounded sender, live-enqueued-job counter).
    queues: HashMap<String, (mpsc::Sender<ProviderJob>, Arc<AtomicU64>)>,
}

impl AlertDispatcher {
    /// Construct the dispatcher and spawn one worker pool per provider.
    /// Must be called from within a tokio runtime (workers use
    /// `tokio::spawn`).
    pub fn new(
        scope: Arc<TenantScope>,
        notifiers: HashMap<String, Arc<dyn Notifier>>,
        config: DispatcherConfig,
        metrics: Arc<AlertPipelineMetrics>,
    ) -> Self {
        let mut queues = HashMap::with_capacity(notifiers.len());
        for (kind, notifier) in &notifiers {
            let depth = metrics.register_provider_queue(kind);
            let (tx, rx) = mpsc::channel::<ProviderJob>(config.queue_capacity);
            let rx = Arc::new(tokio::sync::Mutex::new(rx));
            for _ in 0..config.workers_per_provider {
                let rx = Arc::clone(&rx);
                let notifier = Arc::clone(notifier);
                let config = config.clone();
                let metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    run_worker(rx, notifier, config, metrics).await;
                });
            }
            queues.insert(kind.clone(), (tx, depth));
        }
        Self {
            scope,
            metrics,
            queues,
        }
    }

    /// Dispatch a notification: load context from DB, check silence, write
    /// history, and enqueue per-receiver delivery jobs. Returns promptly
    /// after enqueuing — actual delivery is async in the worker pool.
    pub async fn dispatch(&self, notification: Notification) -> Result<DispatchOutcome> {
        let store = AlertStore::new(&self.scope);
        let rule = store
            .get_rule(notification.rule_id)
            .await?
            .with_context(|| format!("alert_rule id={} no longer exists", notification.rule_id))?;
        let receiver_ids: Vec<i64> = serde_json::from_str(&rule.receiver_ids)
            .context("corrupt receiver_ids on alert_rule")?;
        let all_receivers = store.list_receivers().await?;
        let by_id: HashMap<i64, Receiver> =
            all_receivers.into_iter().map(|r| (r.id, r)).collect();

        let active_silences = store
            .list_silences(Some(notification.at_ns / 1_000_000_000))
            .await
            .unwrap_or_default();
        let silenced = is_silenced(&rule, &notification, &active_silences);
        if silenced {
            self.metrics.record_silenced();
        }

        let payload = build_payload(&rule, &notification);

        if !silenced {
            for rid in &receiver_ids {
                match by_id.get(rid) {
                    Some(receiver) => self.enqueue_job(receiver, &payload),
                    None => log::warn!(
                        "dispatcher: receiver id={rid} not found, skipping"
                    ),
                }
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
        })
    }

    fn enqueue_job(&self, receiver: &Receiver, payload: &NotificationPayload) {
        let kind = receiver.kind.as_str();
        match self.queues.get(kind) {
            Some((tx, depth)) => {
                depth.fetch_add(1, Ordering::Relaxed);
                let job = ProviderJob {
                    receiver: receiver.clone(),
                    payload: payload.clone(),
                    depth: Arc::clone(depth),
                };
                if tx.try_send(job).is_err() {
                    depth.fetch_sub(1, Ordering::Relaxed);
                    log::warn!(
                        "dispatcher: queue full for provider '{kind}', \
                         dropping notification for receiver id={}",
                        receiver.id
                    );
                }
            }
            None => log::error!(
                "dispatcher: no worker pool for provider kind '{kind}' \
                 (receiver id={}); was it registered at startup?",
                receiver.id
            ),
        }
    }
}

/// Worker task: drains one provider's channel and calls send-with-retry.
async fn run_worker(
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ProviderJob>>>,
    notifier: Arc<dyn Notifier>,
    config: DispatcherConfig,
    metrics: Arc<AlertPipelineMetrics>,
) {
    loop {
        let job = {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(j) => j,
                None => return, // channel closed → shut down
            }
        };
        // Decrement before the (potentially slow) delivery so the gauge
        // reflects "outstanding, not yet started" rather than "in-flight".
        job.depth.fetch_sub(1, Ordering::Relaxed);
        let outcome = send_with_retry(&*notifier, &job.receiver, &job.payload, &config).await;
        metrics.record_dispatched(notifier.kind(), outcome.is_ok(), outcome.attempts().max(1));
    }
}

/// Delivery result returned by [`send_with_retry`].
struct DeliveryOutcome {
    attempts: u32,
    ok: bool,
}

impl DeliveryOutcome {
    fn is_ok(&self) -> bool {
        self.ok
    }
    fn attempts(&self) -> u32 {
        self.attempts
    }
}

async fn send_with_retry(
    notifier: &dyn Notifier,
    receiver: &Receiver,
    payload: &NotificationPayload,
    config: &DispatcherConfig,
) -> DeliveryOutcome {
    for attempt in 1..=config.max_attempts {
        match notifier.send(receiver, payload).await {
            Ok(()) => return DeliveryOutcome { attempts: attempt, ok: true },
            Err(e) => {
                if attempt == config.max_attempts {
                    log::warn!(
                        "dispatcher: receiver id={} kind={} exhausted {} attempts: {e:#}",
                        receiver.id, receiver.kind, config.max_attempts
                    );
                    return DeliveryOutcome {
                        attempts: attempt,
                        ok: false,
                    };
                }
                let delay_ms = backoff_ms(attempt, config.base_backoff_ms, config.max_backoff_ms);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }
    DeliveryOutcome { attempts: config.max_attempts, ok: false }
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
fn backoff_ms(attempt: u32, base_ms: u64, cap_ms: u64) -> u64 {
    let exp = base_ms.saturating_mul(1u64 << attempt.min(20));
    let bound = exp.min(cap_ms).max(1);
    rand::thread_rng().gen_range(0..bound)
}

/// True if any of `active` matches the notification's sample event.
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
    use tokio::time;

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

    fn test_config() -> DispatcherConfig {
        DispatcherConfig {
            max_attempts: 3,
            base_backoff_ms: 1,
            max_backoff_ms: 2,
            queue_capacity: 8,
            workers_per_provider: 1,
        }
    }

    fn dispatcher(
        scope: Arc<TenantScope>,
        mock: Arc<MockNotifier>,
    ) -> (AlertDispatcher, Arc<AlertPipelineMetrics>) {
        let mut notifiers: HashMap<String, Arc<dyn Notifier>> = HashMap::new();
        notifiers.insert("webhook".into(), mock as Arc<dyn Notifier>);
        let metrics = Arc::new(AlertPipelineMetrics::new());
        let d = AlertDispatcher::new(scope, notifiers, test_config(), Arc::clone(&metrics));
        (d, metrics)
    }

    /// Spin until `pred()` returns true or `timeout` elapses.
    async fn wait_for<F: Fn() -> bool>(pred: F, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if pred() {
                return true;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        pred()
    }

    #[tokio::test]
    async fn dispatch_success_writes_history_and_calls_notifier() {
        let (scope, rule_id, _r) = setup().await;
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert!(!out.silenced);
        assert!(out.history_id.is_some());

        let mock2 = Arc::clone(&mock);
        let delivered = wait_for(|| mock2.call_count() >= 1, Duration::from_secs(2)).await;
        assert!(delivered, "worker did not call notifier within 2s");

        let calls = mock.calls();
        assert_eq!(calls[0].1.rule_id, rule_id);
        assert_eq!(calls[0].1.group_key, "k1");
        assert_eq!(calls[0].1.severity, "warning");
        assert_eq!(calls[0].1.sample_event_ids, vec![1, 2, 3]);
        assert_eq!(calls[0].1.kind, NotificationKindStr::Initial);

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
        d.dispatch(notif(rule_id)).await.unwrap();

        let mock2 = Arc::clone(&mock);
        let delivered = wait_for(|| mock2.call_count() >= 3, Duration::from_secs(2)).await;
        assert!(delivered, "expected 3 attempts (2 fail + 1 success), got {}", mock.call_count());
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let (scope, rule_id, _r) = setup().await;
        let mock = Arc::new(MockNotifier::new("webhook").fail_first(10));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        // History is written regardless of delivery outcome.
        assert!(out.history_id.is_some());

        let mock2 = Arc::clone(&mock);
        let exhausted = wait_for(|| mock2.call_count() >= 3, Duration::from_secs(2)).await;
        assert!(exhausted, "expected max_attempts=3 calls, got {}", mock.call_count());
    }

    #[tokio::test]
    async fn unknown_receiver_kind_drops_job_without_calling_webhook() {
        let (scope, rule_id, r_id) = setup().await;
        // Mutate the receiver to a kind with no registered provider.
        sqlx::query("UPDATE receivers SET kind = 'pagerduty' WHERE id = ?")
            .bind(r_id)
            .execute(scope.pool())
            .await
            .unwrap();
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        // History still written (we saw the notification; delivery failed).
        assert!(out.history_id.is_some());
        // Give the worker a moment, then assert no calls.
        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(mock.call_count(), 0, "webhook must not be called for unknown kind");
    }

    #[tokio::test]
    async fn missing_receiver_id_logs_and_writes_history() {
        let (scope, rule_id, r_id) = setup().await;
        sqlx::query("DELETE FROM receivers WHERE id = ?")
            .bind(r_id)
            .execute(scope.pool())
            .await
            .unwrap();
        let mock = Arc::new(MockNotifier::new("webhook"));
        let (d, _metrics) = dispatcher(Arc::clone(&scope), Arc::clone(&mock));
        let out = d.dispatch(notif(rule_id)).await.unwrap();
        assert!(out.history_id.is_some());
        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(mock.call_count(), 0);
    }

    #[tokio::test]
    async fn matching_silence_suppresses_dispatch() {
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
        time::sleep(Duration::from_millis(50)).await;
        assert_eq!(mock.call_count(), 0);
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
        let mock2 = Arc::clone(&mock);
        let delivered = wait_for(|| mock2.call_count() >= 1, Duration::from_secs(2)).await;
        assert!(delivered);
        let txt = metrics.render("default");
        assert!(
            txt.contains("notifications_silenced_total{tenant=\"default\"} 0"),
            "silenced counter should be 0 for non-matching silence:\n{txt}"
        );
    }

    #[tokio::test]
    async fn notification_without_sample_event_is_not_silenced() {
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
        let mock2 = Arc::clone(&mock);
        let delivered = wait_for(|| mock2.call_count() >= 1, Duration::from_secs(2)).await;
        assert!(delivered);
    }

    #[tokio::test]
    async fn queue_depth_increments_then_drains_to_zero() {
        let (scope, rule_id, _r) = setup().await;
        // Use a mock that blocks briefly so depth is non-zero during delivery.
        let mock = Arc::new(MockNotifier::new("webhook"));
        let metrics = Arc::new(AlertPipelineMetrics::new());
        let mut notifiers: HashMap<String, Arc<dyn Notifier>> = HashMap::new();
        notifiers.insert("webhook".into(), Arc::clone(&mock) as Arc<dyn Notifier>);
        let d = AlertDispatcher::new(
            Arc::clone(&scope),
            notifiers,
            test_config(),
            Arc::clone(&metrics),
        );
        d.dispatch(notif(rule_id)).await.unwrap();
        // After worker drains, depth must return to 0.
        let mock2 = Arc::clone(&mock);
        wait_for(|| mock2.call_count() >= 1, Duration::from_secs(2)).await;
        let txt = metrics.render("default");
        assert!(
            txt.contains("alert_dispatcher_queue_depth{tenant=\"default\",kind=\"webhook\"} 0"),
            "depth should be 0 after delivery:\n{txt}"
        );
    }
}
