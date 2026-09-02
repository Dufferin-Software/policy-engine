// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Long-running task that ties the alert pipeline together.
//!
//! ```text
//! EventBus  ─┐
//!            ├──► [match] ──► [grouper.observe] ──► [grouper.tick (every Ns)]
//! AlertBus  ─┘                                              │
//!                                                           ▼
//!                                                  AlertDispatcher
//! ```
//!
//! Responsibilities:
//!
//! 1. **Load rules** from `alert_rules` at startup. Compile each rule's
//!    `match_json` into a [`CompiledMatchSpec`].
//! 2. **Subscribe to `EventBus`**, parse each batch, run every enabled
//!    rule's matcher, and on a hit call `grouper.observe()` with the
//!    group key derived from `rule.group_by`.
//! 3. **Subscribe to `AlertRuleBus`** for hot-reload: `Created`/`Updated`
//!    reload that rule from the store; `Deleted` drops the compiled spec.
//!    The grouper deletes orphaned groups silently on its next tick (see
//!    `grouper::deleted_rule_drops_group_silently`).
//! 4. **Tick** every `tick_interval` (default 1 s). Each notification the
//!    grouper produces is handed to [`AlertDispatcher::dispatch`] on its
//!    own `tokio::spawn` so a slow receiver can't stall the tick loop.
//!
//! Disabled rules (`enabled = 0`) are loaded but skipped during matching;
//! flipping `enabled` via GraphQL only needs the AlertBus signal — no
//! restart.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;
use tokio::time;

use crate::event_bus::{EventBus, TaggedEventBatch};

use super::alert_bus::{AlertRuleBus, AlertRuleChange};
use super::alert_metrics::{AlertPipelineMetrics, FireKind};
use super::alert_store::{AlertRule, AlertStore};
use super::dispatcher::{AlertDispatcher, DispatcherConfig};
use super::grouper::{GroupKey, NotificationKind, RuleParams, TenantGrouper, Threshold};
use super::matcher::{CompiledMatchSpec, MatchSpec};
use super::providers::Notifier;
use super::tenant::TenantScope;
use super::types::{parse_policy_event, Action, Direction, PolicyEvent};

#[derive(Debug, Clone)]
pub struct AlertEngineConfig {
    pub tick_interval: Duration,
    pub max_groups_per_tenant: usize,
    pub dispatcher: DispatcherConfig,
}

impl Default for AlertEngineConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(1),
            max_groups_per_tenant: 10_000,
            dispatcher: DispatcherConfig::default(),
        }
    }
}

/// Spawn the alert engine task. Returns the `JoinHandle` so the controller
/// can join it during shutdown.
pub fn spawn_alert_engine(
    event_bus: Arc<EventBus>,
    alert_rule_bus: Arc<AlertRuleBus>,
    scope: Arc<TenantScope>,
    notifiers: HashMap<String, Arc<dyn Notifier>>,
    metrics: Arc<AlertPipelineMetrics>,
    config: AlertEngineConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(event_bus, alert_rule_bus, scope, notifiers, metrics, config).await {
            log::error!("alert engine exited: {e:#}");
        }
    })
}

struct Compiled {
    rule: AlertRule,
    spec: CompiledMatchSpec,
    params: RuleParams,
    group_by: Vec<String>,
}

async fn load_compiled(scope: &TenantScope) -> Result<HashMap<i64, Compiled>> {
    let store = AlertStore::new(scope);
    let rules = store.list_rules().await.context("load alert_rules")?;
    let mut out = HashMap::with_capacity(rules.len());
    for rule in rules {
        match compile_one(rule) {
            Ok(c) => {
                out.insert(c.rule.id, c);
            }
            Err((id, e)) => {
                // A bad rule mid-table shouldn't kill the engine — log
                // loudly so the operator notices via journal/metrics.
                log::warn!("alert engine: skipping rule id={id}: {e:#}");
            }
        }
    }
    Ok(out)
}

fn compile_one(rule: AlertRule) -> std::result::Result<Compiled, (i64, anyhow::Error)> {
    let id = rule.id;
    let spec = MatchSpec::compile_json(&rule.match_json).map_err(|e| (id, e))?;
    let group_by: Vec<String> =
        serde_json::from_str(&rule.group_by).map_err(|e| (id, anyhow::Error::from(e)))?;
    // `alert_store::validate` guarantees that threshold_count and
    // threshold_window_s are either both `Some` (with positive values) or
    // both `None`, so the half-set case can't reach us here.
    let threshold = match (rule.threshold_count, rule.threshold_window_s) {
        (Some(count), Some(window_s)) => Some(Threshold { count, window_s }),
        _ => None,
    };
    let params = RuleParams {
        rule_id: rule.id,
        group_wait_s: rule.group_wait_s,
        group_interval_s: rule.group_interval_s,
        repeat_interval_s: rule.repeat_interval_s,
        resolve_after_s: rule.resolve_after_s,
        threshold,
    };
    Ok(Compiled {
        rule,
        spec,
        params,
        group_by,
    })
}

async fn run(
    event_bus: Arc<EventBus>,
    alert_rule_bus: Arc<AlertRuleBus>,
    scope: Arc<TenantScope>,
    notifiers: HashMap<String, Arc<dyn Notifier>>,
    metrics: Arc<AlertPipelineMetrics>,
    config: AlertEngineConfig,
) -> Result<()> {
    let mut compiled = load_compiled(&scope).await?;
    let mut grouper = TenantGrouper::new(config.max_groups_per_tenant);
    let dispatcher = Arc::new(AlertDispatcher::new(
        Arc::clone(&scope),
        notifiers,
        config.dispatcher.clone(),
        Arc::clone(&metrics),
    ));

    let mut events_rx = event_bus.subscribe();
    let mut rules_rx = alert_rule_bus.subscribe();
    let mut ticker = time::interval(config.tick_interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    log::info!(
        "alert engine started ({} rule(s) loaded, tick={:?})",
        compiled.len(),
        config.tick_interval
    );

    loop {
        tokio::select! {
            biased;

            _ = ticker.tick() => {
                tick_once(&compiled, &mut grouper, &dispatcher, &metrics).await;
            }

            change = rules_rx.recv() => match change {
                Ok(c) => apply_change(&scope, c, &mut compiled).await,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // We can't safely incrementally apply changes if we
                    // dropped some — reload from disk instead of guessing.
                    log::warn!("alert engine: lagged {n} rule-change events, reloading all");
                    match load_compiled(&scope).await {
                        Ok(c) => compiled = c,
                        Err(e) => log::error!("alert engine reload failed: {e:#}"),
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    log::info!("alert rule bus closed, alert engine exiting");
                    return Ok(());
                }
            },

            batch = events_rx.recv() => match batch {
                Ok(b) => ingest_batch(b, &compiled, &mut grouper, &metrics),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("alert engine: lagged {n} event broadcast messages");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    log::info!("event bus closed, alert engine exiting");
                    return Ok(());
                }
            },
        }
    }
}

fn ingest_batch(
    batch: TaggedEventBatch,
    compiled: &HashMap<i64, Compiled>,
    grouper: &mut TenantGrouper,
    metrics: &AlertPipelineMetrics,
) {
    if compiled.is_empty() {
        return;
    }
    for blob in &batch.events_json {
        let ev = match parse_policy_event(&batch.node_id, blob) {
            Ok(Some(ev)) => ev,
            _ => continue,
        };
        // Per-event ID isn't on PolicyEvent (the row's `id` is only assigned
        // at insert time). Use the event's monotonic-ish ts_ns as a stand-in
        // for sample IDs — collisions in the same nanosecond are rare and
        // the field is only used for operator drill-down, not aggregation.
        let event_id = ev.ts_ns;
        let now_ns = ev.ts_ns;
        for c in compiled.values() {
            if !c.rule.enabled {
                continue;
            }
            if c.spec.matches(&ev) {
                metrics.record_matched(c.rule.id, 1);
                let key = GroupKey(build_group_key(&ev, &c.group_by));
                grouper.observe(&c.params, key, &ev, event_id, now_ns);
            }
        }
    }
}

async fn tick_once(
    compiled: &HashMap<i64, Compiled>,
    grouper: &mut TenantGrouper,
    dispatcher: &Arc<AlertDispatcher>,
    metrics: &AlertPipelineMetrics,
) {
    let rules_map: HashMap<i64, RuleParams> = compiled
        .values()
        .map(|c| (c.rule.id, c.params.clone()))
        .collect();
    let now_ns = now_ns();
    let notifications = grouper.tick(&rules_map, now_ns);
    // Publish gauges after every tick so dashboards always see fresh
    // values even when nothing fired.
    metrics.set_groups_active(grouper.active_groups() as u64);
    metrics.set_groups_evicted(grouper.evicted_total());
    for n in notifications {
        metrics.record_fired(n.rule_id, fire_kind(n.kind));
        let d = Arc::clone(dispatcher);
        // Spawn so a slow / retrying dispatch doesn't stall the tick loop.
        tokio::spawn(async move {
            if let Err(e) = d.dispatch(n).await {
                log::error!("alert dispatcher error: {e:#}");
            }
        });
    }
}

fn fire_kind(k: NotificationKind) -> FireKind {
    match k {
        NotificationKind::InitialFire => FireKind::Initial,
        NotificationKind::Refire => FireKind::Refire,
        NotificationKind::Resolve => FireKind::Resolve,
    }
}

async fn apply_change(
    scope: &TenantScope,
    change: AlertRuleChange,
    compiled: &mut HashMap<i64, Compiled>,
) {
    let id = change.rule_id();
    match change {
        AlertRuleChange::Deleted(_) => {
            compiled.remove(&id);
            log::info!("alert engine: dropped rule id={id}");
        }
        AlertRuleChange::Created(_) | AlertRuleChange::Updated(_) => {
            match AlertStore::new(scope).get_rule(id).await {
                Ok(Some(rule)) => match compile_one(rule) {
                    Ok(c) => {
                        compiled.insert(id, c);
                        log::info!("alert engine: (re)loaded rule id={id}");
                    }
                    Err((_, e)) => {
                        log::warn!("alert engine: rule id={id} failed to compile, dropping: {e:#}")
                    }
                },
                Ok(None) => {
                    compiled.remove(&id);
                }
                Err(e) => log::error!("alert engine: reload rule id={id} failed: {e:#}"),
            }
        }
    }
}

/// Build a stable, low-cardinality string from the event's group_by fields.
/// Order follows the rule's `group_by` array so the same logical group
/// always produces the same key string.
fn build_group_key(ev: &PolicyEvent, group_by: &[String]) -> String {
    let mut out = String::with_capacity(group_by.len() * 16);
    for (i, field) in group_by.iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        out.push_str(field);
        out.push('=');
        match field.as_str() {
            "rule_id" => out.push_str(&ev.rule_id.to_string()),
            "action" => out.push_str(action_label(ev.action)),
            "proto" => out.push_str(&ev.proto.to_string()),
            "node_id" => out.push_str(&ev.node_id),
            "src_ip" => push_ip(&mut out, &ev.src_ip),
            "dst_ip" => push_ip(&mut out, &ev.dst_ip),
            "sport" => out.push_str(&ev.sport.to_string()),
            "dport" => out.push_str(&ev.dport.to_string()),
            "direction" => out.push_str(direction_label(ev.direction)),
            // Validation rejects unknown fields at write time, so this
            // is unreachable in practice — but bail to a literal rather
            // than panicking if a future schema change slips one through.
            other => {
                out.push('?');
                out.push_str(other);
            }
        }
    }
    out
}

fn action_label(a: Action) -> &'static str {
    a.as_str()
}

fn direction_label(d: Direction) -> &'static str {
    d.as_str()
}

fn push_ip(out: &mut String, bytes: &[u8]) {
    use std::net::IpAddr;
    let s = match bytes.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(bytes);
            IpAddr::from(a).to_string()
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            IpAddr::from(a).to_string()
        }
        _ => "?".into(),
    };
    out.push_str(&s);
}

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::{
        alert_store::{NewAlertRule, NewReceiver},
        bootstrap_default_tenant,
        providers::testing::MockNotifier,
    };
    use sqlx::sqlite::SqlitePool;

    async fn fresh_scope() -> Arc<TenantScope> {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        Arc::new(bootstrap_default_tenant(pool).await.unwrap())
    }

    fn ev(rule_id: i64, action: &str, ts_ns: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "timestamp_ns": ts_ns,
            "rule_id": rule_id,
            "action": action,
            "ifindex": 1,
            "interface_name": "eth0",
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "sport": 1234,
            "dport": 22,
            "protocol": "tcp",
            "af": 2,
            "pkt_len": 64,
            "verdict": "drop",
            "direction": "ingress",
            "fragment": false,
        }))
        .unwrap()
    }

    async fn seed_rule(scope: &TenantScope, name: &str) -> i64 {
        let store = AlertStore::new(scope);
        let r = store
            .create_receiver(NewReceiver {
                name: name.into(),
                kind: "webhook".into(),
                config_json: r#"{"url":"https://example.invalid"}"#.into(),
            })
            .await
            .unwrap();
        let rule = store
            .create_rule(
                NewAlertRule {
                    name: name.into(),
                    enabled: true,
                    match_json: r#"{"action":["drop"]}"#.into(),
                    group_by: vec!["rule_id".into(), "src_ip".into()],
                    threshold_count: None,
                    threshold_window_s: None,
                    // Sub-second values: validation requires `> 0` and the
                    // grouper measures in seconds — so 1 is the smallest
                    // unit that still exercises the PENDING→FIRING path.
                    group_wait_s: 1,
                    group_interval_s: 1,
                    repeat_interval_s: 3_600,
                    resolve_after_s: 10,
                    severity: "warning".into(),
                    receiver_ids: vec![r.id],
                },
                0,
            )
            .await
            .unwrap();
        rule.id
    }

    #[test]
    fn group_key_format_matches_rule_order() {
        let p = PolicyEvent {
            ts_ns: 0,
            node_id: "n1".into(),
            rule_id: 42,
            action: Action::Drop,
            verdict: 1,
            direction: Direction::Ingress,
            ifindex: 0,
            proto: 6,
            src_ip: vec![10, 0, 0, 1],
            dst_ip: vec![192, 168, 1, 5],
            sport: 1234,
            dport: 22,
            pkt_len: 0,
            flags: None,
            sni: None,
        };
        assert_eq!(
            build_group_key(&p, &["rule_id".into(), "src_ip".into()]),
            "rule_id=42|src_ip=10.0.0.1"
        );
        assert_eq!(
            build_group_key(&p, &["action".into(), "dport".into(), "direction".into()]),
            "action=drop|dport=22|direction=ingress"
        );
    }

    /// Poll until `pred()` returns true or `timeout` elapses. Spinning on
    /// real time keeps the test free of tokio's `test-util` feature.
    async fn wait_for<F: Fn() -> bool>(pred: F, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if pred() {
                return true;
            }
            time::sleep(Duration::from_millis(50)).await;
        }
        pred()
    }

    #[tokio::test]
    async fn end_to_end_event_to_dispatch() {
        let scope = fresh_scope().await;
        seed_rule(&scope, "drops").await;

        let event_bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(AlertRuleBus::new());
        let mock = Arc::new(MockNotifier::new("webhook"));
        let mut notifiers: HashMap<String, Arc<dyn Notifier>> = HashMap::new();
        notifiers.insert("webhook".into(), Arc::clone(&mock) as Arc<dyn Notifier>);

        let cfg = AlertEngineConfig {
            tick_interval: Duration::from_millis(100),
            max_groups_per_tenant: 100,
            dispatcher: DispatcherConfig {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                queue_capacity: 8,
                workers_per_provider: 1,
            },
        };
        let handle = spawn_alert_engine(
            Arc::clone(&event_bus),
            Arc::clone(&rule_bus),
            Arc::clone(&scope),
            notifiers,
            Arc::new(AlertPipelineMetrics::new()),
            cfg,
        );
        // Engine needs a moment to subscribe before we publish.
        time::sleep(Duration::from_millis(100)).await;

        event_bus.publish(TaggedEventBatch {
            node_id: "n1".into(),
            timestamp_ns: 0,
            events_json: vec![ev(42, "drop", now_ns())],
        });

        // group_wait_s=1 → expect a dispatch within ~1.5s of publish.
        let mock2 = Arc::clone(&mock);
        let fired = wait_for(|| mock2.call_count() >= 1, Duration::from_secs(3)).await;
        assert!(fired, "no dispatch within 3s");
        let calls = mock.calls();
        assert_eq!(calls[0].1.severity, "warning");
        assert!(
            calls[0].1.group_key.contains("src_ip=10.0.0.1"),
            "group_key = {:?}",
            calls[0].1.group_key
        );

        handle.abort();
    }

    #[tokio::test]
    async fn metrics_increment_through_full_pipeline() {
        let scope = fresh_scope().await;
        let rule_id = seed_rule(&scope, "metricstest").await;
        let event_bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(AlertRuleBus::new());
        let mock = Arc::new(MockNotifier::new("webhook"));
        let mut notifiers: HashMap<String, Arc<dyn Notifier>> = HashMap::new();
        notifiers.insert("webhook".into(), Arc::clone(&mock) as Arc<dyn Notifier>);
        let metrics = Arc::new(AlertPipelineMetrics::new());
        let cfg = AlertEngineConfig {
            tick_interval: Duration::from_millis(100),
            max_groups_per_tenant: 100,
            dispatcher: DispatcherConfig {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                queue_capacity: 8,
                workers_per_provider: 1,
            },
        };
        let handle = spawn_alert_engine(
            Arc::clone(&event_bus),
            Arc::clone(&rule_bus),
            Arc::clone(&scope),
            notifiers,
            Arc::clone(&metrics),
            cfg,
        );
        time::sleep(Duration::from_millis(100)).await;

        for _ in 0..3 {
            event_bus.publish(TaggedEventBatch {
                node_id: "n1".into(),
                timestamp_ns: 0,
                events_json: vec![ev(rule_id, "drop", now_ns())],
            });
        }

        let mock2 = Arc::clone(&mock);
        let fired = wait_for(|| mock2.call_count() >= 1, Duration::from_secs(3)).await;
        assert!(fired, "expected dispatch");
        // Give one more tick so the gauges get published.
        time::sleep(Duration::from_millis(150)).await;

        let txt = metrics.render("default");
        // 3 events × 1 matching rule = 3 matches.
        assert!(
            txt.contains(&format!(
                "alert_matched_total{{tenant=\"default\",rule_id=\"{rule_id}\"}} 3"
            )),
            "matched counter missing/wrong:\n{txt}"
        );
        // At least one initial fire.
        assert!(
            txt.contains(&format!(
                "alert_fired_total{{tenant=\"default\",rule_id=\"{rule_id}\",kind=\"initial\"}} 1"
            )),
            "fired counter missing:\n{txt}"
        );
        // Webhook dispatch succeeded.
        assert!(
            txt.contains(
                "alert_dispatched_total{tenant=\"default\",kind=\"webhook\",result=\"ok\"} 1"
            ),
            "dispatch ok counter missing:\n{txt}"
        );
        // Group is still active (resolve_after_s=10).
        assert!(
            txt.contains("alert_groups_active{tenant=\"default\"} 1"),
            "active gauge wrong:\n{txt}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn rule_bus_created_loads_new_rule_without_restart() {
        let scope = fresh_scope().await;
        let event_bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(AlertRuleBus::new());
        let mock = Arc::new(MockNotifier::new("webhook"));
        let mut notifiers: HashMap<String, Arc<dyn Notifier>> = HashMap::new();
        notifiers.insert("webhook".into(), Arc::clone(&mock) as Arc<dyn Notifier>);

        let cfg = AlertEngineConfig {
            tick_interval: Duration::from_millis(100),
            max_groups_per_tenant: 100,
            dispatcher: DispatcherConfig {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
                queue_capacity: 8,
                workers_per_provider: 1,
            },
        };
        let handle = spawn_alert_engine(
            Arc::clone(&event_bus),
            Arc::clone(&rule_bus),
            Arc::clone(&scope),
            notifiers,
            Arc::new(AlertPipelineMetrics::new()),
            cfg,
        );
        time::sleep(Duration::from_millis(100)).await;

        // No rules yet — matching is a no-op even with matching traffic.
        event_bus.publish(TaggedEventBatch {
            node_id: "n1".into(),
            timestamp_ns: 0,
            events_json: vec![ev(99, "drop", now_ns())],
        });
        time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            mock.call_count(),
            0,
            "engine should have no rules loaded yet"
        );

        // Add a rule and signal the bus.
        let rule_id = seed_rule(&scope, "later").await;
        rule_bus.publish(AlertRuleChange::Created(rule_id));
        time::sleep(Duration::from_millis(100)).await; // bus delivery

        event_bus.publish(TaggedEventBatch {
            node_id: "n1".into(),
            timestamp_ns: 0,
            events_json: vec![ev(rule_id, "drop", now_ns())],
        });

        let mock2 = Arc::clone(&mock);
        let fired = wait_for(|| mock2.call_count() >= 1, Duration::from_secs(3)).await;
        assert!(
            fired,
            "expected hot-reloaded rule to fire, got {} dispatch(es)",
            mock.call_count()
        );
        handle.abort();
    }
}
