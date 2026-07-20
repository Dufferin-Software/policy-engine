// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Prometheus counters for the alert pipeline.
//!
//! Mirrors the design of [`super::metrics::EventPipelineMetrics`]: plain
//! atomics + tiny per-label maps under `Mutex`, rendered to text by hand.
//! Avoids the `prometheus` / `metrics-rs` dependency footprint while the
//! cardinality is small enough that hand-rolling is fine.
//!
//! Counter list comes from docs/event-pipeline.md "Metrics":
//!
//! - `alert_matched_total{rule_id}`
//! - `alert_fired_total{rule_id, kind=initial|refire|resolve}`
//! - `alert_groups_active` (gauge)
//! - `alert_groups_evicted_total`
//! - `alert_dispatched_total{kind, result=ok|err}`
//! - `alert_dispatch_retries_total{kind}`
//! - `alert_dispatch_failed_total{kind}`
//! - `alert_dispatcher_queue_depth{kind}` (gauge — per-provider, live
//!   backlog of enqueued-but-not-yet-delivered jobs)
//! - `notifications_silenced_total` (incremented by `dispatcher::is_silenced`
//!   when an active silence's MatchSpec matches a notification's sample event)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FireKind {
    Initial,
    Refire,
    Resolve,
}

impl FireKind {
    fn as_str(self) -> &'static str {
        match self {
            FireKind::Initial => "initial",
            FireKind::Refire => "refire",
            FireKind::Resolve => "resolve",
        }
    }
}

#[derive(Debug, Default)]
struct LabeledCounter {
    inner: Mutex<HashMap<String, u64>>,
}

impl LabeledCounter {
    fn inc(&self, key: &str, by: u64) {
        if by == 0 {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        *g.entry(key.to_string()).or_insert(0) += by;
    }

    fn snapshot(&self) -> Vec<(String, u64)> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<_> = g.iter().map(|(k, v)| (k.clone(), *v)).collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

/// All alert-pipeline counters for one controller process. Shared across
/// the matcher, grouper, and dispatcher tasks via `Arc`.
#[derive(Debug, Default)]
pub struct AlertPipelineMetrics {
    matched: LabeledCounter,          // by rule_id
    fired: LabeledCounter,            // by "rule_id,kind"
    dispatched: LabeledCounter,       // by "kind,result"
    dispatch_retries: LabeledCounter, // by kind
    dispatch_failed: LabeledCounter,  // by kind
    silenced: AtomicU64,
    groups_active: AtomicU64,
    groups_evicted: AtomicU64,
    /// Per-provider live enqueued-job gauges. Registered by
    /// [`register_provider_queue`] at dispatcher construction time; the
    /// returned `Arc<AtomicU64>` is owned jointly by the dispatcher (to
    /// increment on enqueue) and the worker (to decrement on delivery).
    queue_depths: Mutex<HashMap<String, Arc<AtomicU64>>>,
}

impl AlertPipelineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_matched(&self, rule_id: i64, n: u64) {
        self.matched.inc(&rule_id.to_string(), n);
    }

    pub fn record_fired(&self, rule_id: i64, kind: FireKind) {
        self.fired.inc(&format!("{rule_id},{}", kind.as_str()), 1);
    }

    /// `attempts >= 1`. Retries = `attempts - 1`. Result captured separately
    /// so dashboards can show success vs failure on the same axis.
    pub fn record_dispatched(&self, kind: &str, success: bool, attempts: u32) {
        let result = if success { "ok" } else { "err" };
        self.dispatched.inc(&format!("{kind},{result}"), 1);
        if attempts > 1 {
            self.dispatch_retries.inc(kind, (attempts - 1) as u64);
        }
        if !success {
            self.dispatch_failed.inc(kind, 1);
        }
    }

    pub fn record_silenced(&self) {
        self.silenced.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_groups_active(&self, n: u64) {
        self.groups_active.store(n, Ordering::Relaxed);
    }

    pub fn set_groups_evicted(&self, n: u64) {
        self.groups_evicted.store(n, Ordering::Relaxed);
    }

    /// Register a per-provider queue-depth gauge and return the shared
    /// `Arc<AtomicU64>`. The dispatcher increments it on enqueue; the
    /// worker decrements it on delivery. Call once per provider kind at
    /// dispatcher construction time.
    pub fn register_provider_queue(&self, kind: &str) -> Arc<AtomicU64> {
        let mut g = self.queue_depths.lock().unwrap();
        Arc::clone(g.entry(kind.to_string()).or_insert_with(|| Arc::new(AtomicU64::new(0))))
    }

    pub fn render(&self, tenant_slug: &str) -> String {
        let t = tenant_slug;
        let mut out = String::new();

        out.push_str("# HELP alert_matched_total Events matched by an alert rule.\n");
        out.push_str("# TYPE alert_matched_total counter\n");
        for (rid, v) in self.matched.snapshot() {
            out.push_str(&format!(
                "alert_matched_total{{tenant=\"{t}\",rule_id=\"{rid}\"}} {v}\n"
            ));
        }
        out.push('\n');

        out.push_str("# HELP alert_fired_total Notifications emitted by the grouper, by kind.\n");
        out.push_str("# TYPE alert_fired_total counter\n");
        for (k, v) in self.fired.snapshot() {
            if let Some((rid, kind)) = k.split_once(',') {
                out.push_str(&format!(
                    "alert_fired_total{{tenant=\"{t}\",rule_id=\"{rid}\",kind=\"{kind}\"}} {v}\n"
                ));
            }
        }
        out.push('\n');

        let active = self.groups_active.load(Ordering::Relaxed);
        out.push_str("# HELP alert_groups_active Current count of live grouper groups.\n");
        out.push_str("# TYPE alert_groups_active gauge\n");
        out.push_str(&format!(
            "alert_groups_active{{tenant=\"{t}\"}} {active}\n\n"
        ));

        let evicted = self.groups_evicted.load(Ordering::Relaxed);
        out.push_str("# HELP alert_groups_evicted_total Grouper LRU evictions.\n");
        out.push_str("# TYPE alert_groups_evicted_total counter\n");
        out.push_str(&format!(
            "alert_groups_evicted_total{{tenant=\"{t}\"}} {evicted}\n\n"
        ));

        out.push_str(
            "# HELP alert_dispatched_total Notification dispatch attempts, by kind and result.\n",
        );
        out.push_str("# TYPE alert_dispatched_total counter\n");
        for (k, v) in self.dispatched.snapshot() {
            if let Some((kind, result)) = k.split_once(',') {
                out.push_str(&format!(
                    "alert_dispatched_total{{tenant=\"{t}\",kind=\"{kind}\",result=\"{result}\"}} {v}\n"
                ));
            }
        }
        out.push('\n');

        out.push_str("# HELP alert_dispatch_retries_total Retry attempts beyond the first try.\n");
        out.push_str("# TYPE alert_dispatch_retries_total counter\n");
        for (kind, v) in self.dispatch_retries.snapshot() {
            out.push_str(&format!(
                "alert_dispatch_retries_total{{tenant=\"{t}\",kind=\"{kind}\"}} {v}\n"
            ));
        }
        out.push('\n');

        out.push_str("# HELP alert_dispatch_failed_total Dispatches that exhausted all retries.\n");
        out.push_str("# TYPE alert_dispatch_failed_total counter\n");
        for (kind, v) in self.dispatch_failed.snapshot() {
            out.push_str(&format!(
                "alert_dispatch_failed_total{{tenant=\"{t}\",kind=\"{kind}\"}} {v}\n"
            ));
        }
        out.push('\n');

        let silenced = self.silenced.load(Ordering::Relaxed);
        out.push_str(
            "# HELP notifications_silenced_total Notifications suppressed by an active silence.\n",
        );
        out.push_str("# TYPE notifications_silenced_total counter\n");
        out.push_str(&format!(
            "notifications_silenced_total{{tenant=\"{t}\"}} {silenced}\n\n"
        ));

        out.push_str(
            "# HELP alert_dispatcher_queue_depth Per-provider enqueued-but-not-yet-delivered jobs (gauge).\n",
        );
        out.push_str("# TYPE alert_dispatcher_queue_depth gauge\n");
        let depths = self.queue_depths.lock().unwrap();
        let mut kinds: Vec<&String> = depths.keys().collect();
        kinds.sort();
        for kind in kinds {
            let depth = depths[kind].load(Ordering::Relaxed);
            out.push_str(&format!(
                "alert_dispatcher_queue_depth{{tenant=\"{t}\",kind=\"{kind}\"}} {depth}\n"
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_render_with_labels() {
        let m = AlertPipelineMetrics::new();
        m.record_matched(42, 3);
        m.record_matched(42, 2);
        m.record_matched(99, 1);
        m.record_fired(42, FireKind::Initial);
        m.record_fired(42, FireKind::Refire);
        m.record_fired(42, FireKind::Refire);
        m.record_fired(42, FireKind::Resolve);
        m.record_dispatched("webhook", true, 1);
        m.record_dispatched("webhook", true, 3); // 2 retries
        m.record_dispatched("webhook", false, 5); // 4 retries, final fail
        m.record_silenced();
        m.set_groups_active(17);
        m.set_groups_evicted(4);
        let wh_depth = m.register_provider_queue("webhook");
        let em_depth = m.register_provider_queue("email");
        wh_depth.store(3, Ordering::Relaxed);
        em_depth.store(0, Ordering::Relaxed);

        let txt = m.render("default");
        assert!(txt.contains("alert_matched_total{tenant=\"default\",rule_id=\"42\"} 5"));
        assert!(txt.contains("alert_matched_total{tenant=\"default\",rule_id=\"99\"} 1"));
        assert!(
            txt.contains("alert_fired_total{tenant=\"default\",rule_id=\"42\",kind=\"initial\"} 1")
        );
        assert!(
            txt.contains("alert_fired_total{tenant=\"default\",rule_id=\"42\",kind=\"refire\"} 2")
        );
        assert!(txt.contains("alert_groups_active{tenant=\"default\"} 17"));
        assert!(txt.contains("alert_groups_evicted_total{tenant=\"default\"} 4"));
        assert!(txt.contains(
            "alert_dispatched_total{tenant=\"default\",kind=\"webhook\",result=\"ok\"} 2"
        ));
        assert!(txt.contains(
            "alert_dispatched_total{tenant=\"default\",kind=\"webhook\",result=\"err\"} 1"
        ));
        // Retries: 2 + 4 = 6
        assert!(txt.contains("alert_dispatch_retries_total{tenant=\"default\",kind=\"webhook\"} 6"));
        assert!(txt.contains("alert_dispatch_failed_total{tenant=\"default\",kind=\"webhook\"} 1"));
        assert!(txt.contains("notifications_silenced_total{tenant=\"default\"} 1"));
        // Per-provider depth — sorted alphabetically: email then webhook.
        assert!(
            txt.contains("alert_dispatcher_queue_depth{tenant=\"default\",kind=\"email\"} 0"),
            "email depth missing:\n{txt}"
        );
        assert!(
            txt.contains("alert_dispatcher_queue_depth{tenant=\"default\",kind=\"webhook\"} 3"),
            "webhook depth missing:\n{txt}"
        );
    }

    #[test]
    fn no_calls_renders_empty_per_label_blocks_but_keeps_help() {
        let m = AlertPipelineMetrics::new();
        let txt = m.render("default");
        assert!(txt.contains("# TYPE alert_matched_total counter"));
        assert!(txt.contains("alert_groups_active{tenant=\"default\"} 0"));
        // No providers registered yet → depth block has HELP/TYPE but no lines.
        assert!(txt.contains("# TYPE alert_dispatcher_queue_depth gauge"));
    }
}
