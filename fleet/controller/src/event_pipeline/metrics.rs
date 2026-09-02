// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Atomic-counter store for event-pipeline metrics.
//!
//! The controller renders Prometheus text by hand (see
//! `controller_metrics`), so we keep counters as plain atomics rather than
//! pulling in `prometheus` / `metrics-rs`. Labels with cardinality only
//! ever covering "tenant slug" or "reason" are flattened into per-key maps
//! protected by a `Mutex`; the maps are tiny and only touched on insert/
//! drop so contention is irrelevant.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Why an ingested event was dropped before persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// JSON didn't parse.
    BadJson,
    /// Address fields couldn't be parsed as v4/v6.
    BadIp,
    /// Direction not in {ingress, egress}.
    BadDirection,
    /// Persister queue full — backpressure dropped the event.
    PersistOverflow,
}

impl DropReason {
    fn as_str(self) -> &'static str {
        match self {
            DropReason::BadJson => "bad_json",
            DropReason::BadIp => "bad_ip",
            DropReason::BadDirection => "bad_direction",
            DropReason::PersistOverflow => "persist_overflow",
        }
    }
}

/// Why an ingested event was skipped (not an error — common case for non-
/// persisted actions like `pass`). Separate from `DropReason` so dashboards
/// can distinguish "expected skip" from "something broke".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// Action wasn't in {drop, log}. Includes `pass` and any unrecognised
    /// string (catches version skew between agent and controller).
    NonPersistableAction,
}

impl SkipReason {
    fn as_str(self) -> &'static str {
        match self {
            SkipReason::NonPersistableAction => "non_persistable_action",
        }
    }
}

#[derive(Debug, Default)]
struct LabeledCounter {
    inner: Mutex<HashMap<String, u64>>,
}

impl LabeledCounter {
    fn inc(&self, key: &str, by: u64) {
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

/// Aggregated counters for the event pipeline. One shared instance per
/// controller process, handed to the persister and retention tasks via
/// `Arc`.
#[derive(Debug, Default)]
pub struct EventPipelineMetrics {
    received_by_node: LabeledCounter,
    inserted: AtomicU64,
    dropped: LabeledCounter,
    skipped: LabeledCounter,
    retention_pruned: AtomicU64,
    persist_batch_seconds_count: AtomicU64,
    persist_batch_seconds_sum_micros: AtomicU64,
}

impl EventPipelineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_received(&self, node_id: &str, n: u64) {
        if n > 0 {
            self.received_by_node.inc(node_id, n);
        }
    }

    pub fn record_inserted(&self, n: u64) {
        self.inserted.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_dropped(&self, reason: DropReason, n: u64) {
        if n > 0 {
            self.dropped.inc(reason.as_str(), n);
        }
    }

    pub fn record_skipped(&self, reason: SkipReason, n: u64) {
        if n > 0 {
            self.skipped.inc(reason.as_str(), n);
        }
    }

    pub fn record_pruned(&self, n: u64) {
        self.retention_pruned.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_persist_batch(&self, elapsed: std::time::Duration) {
        self.persist_batch_seconds_count
            .fetch_add(1, Ordering::Relaxed);
        self.persist_batch_seconds_sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }

    /// Render as Prometheus text. Called from the `/metrics` handler.
    pub fn render(&self, tenant_slug: &str) -> String {
        let mut out = String::new();

        out.push_str("# HELP event_ingest_received_total Events received from agents over gRPC.\n");
        out.push_str("# TYPE event_ingest_received_total counter\n");
        for (node, v) in self.received_by_node.snapshot() {
            out.push_str(&format!(
                "event_ingest_received_total{{tenant=\"{tenant_slug}\",node=\"{node}\"}} {v}\n"
            ));
        }
        out.push('\n');

        out.push_str(
            "# HELP event_ingest_dropped_total Events discarded before persistence by reason.\n",
        );
        out.push_str("# TYPE event_ingest_dropped_total counter\n");
        for (reason, v) in self.dropped.snapshot() {
            out.push_str(&format!(
                "event_ingest_dropped_total{{tenant=\"{tenant_slug}\",reason=\"{reason}\"}} {v}\n"
            ));
        }
        out.push('\n');

        out.push_str(
            "# HELP event_ingest_skipped_total Events received but not persisted (expected: pass/non-persisted actions).\n",
        );
        out.push_str("# TYPE event_ingest_skipped_total counter\n");
        for (reason, v) in self.skipped.snapshot() {
            out.push_str(&format!(
                "event_ingest_skipped_total{{tenant=\"{tenant_slug}\",reason=\"{reason}\"}} {v}\n"
            ));
        }
        out.push('\n');

        let inserted = self.inserted.load(Ordering::Relaxed);
        out.push_str("# HELP event_persist_inserted_total Rows inserted into the events table.\n");
        out.push_str("# TYPE event_persist_inserted_total counter\n");
        out.push_str(&format!(
            "event_persist_inserted_total{{tenant=\"{tenant_slug}\"}} {inserted}\n\n"
        ));

        let pruned = self.retention_pruned.load(Ordering::Relaxed);
        out.push_str("# HELP event_retention_pruned_total Rows deleted by the retention task.\n");
        out.push_str("# TYPE event_retention_pruned_total counter\n");
        out.push_str(&format!(
            "event_retention_pruned_total{{tenant=\"{tenant_slug}\"}} {pruned}\n\n"
        ));

        let count = self.persist_batch_seconds_count.load(Ordering::Relaxed);
        let sum_us = self
            .persist_batch_seconds_sum_micros
            .load(Ordering::Relaxed);
        // Render as a Prometheus summary surrogate (count + sum) — proper
        // histograms can wait until we adopt a metrics crate.
        out.push_str(
            "# HELP event_persist_batch_seconds Time spent committing one batch of events.\n",
        );
        out.push_str("# TYPE event_persist_batch_seconds summary\n");
        out.push_str(&format!(
            "event_persist_batch_seconds_count{{tenant=\"{tenant_slug}\"}} {count}\n"
        ));
        out.push_str(&format!(
            "event_persist_batch_seconds_sum{{tenant=\"{tenant_slug}\"}} {:.6}\n",
            (sum_us as f64) / 1_000_000.0
        ));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let m = EventPipelineMetrics::new();
        m.record_received("n1", 3);
        m.record_received("n1", 2);
        m.record_inserted(4);
        m.record_dropped(DropReason::BadJson, 1);
        m.record_skipped(SkipReason::NonPersistableAction, 2);
        m.record_pruned(7);
        m.record_persist_batch(std::time::Duration::from_micros(500));

        let txt = m.render("default");
        assert!(txt.contains("event_ingest_received_total{tenant=\"default\",node=\"n1\"} 5"));
        assert!(txt.contains("event_persist_inserted_total{tenant=\"default\"} 4"));
        assert!(
            txt.contains("event_ingest_dropped_total{tenant=\"default\",reason=\"bad_json\"} 1")
        );
        assert!(txt.contains(
            "event_ingest_skipped_total{tenant=\"default\",reason=\"non_persistable_action\"} 2"
        ));
        assert!(txt.contains("event_retention_pruned_total{tenant=\"default\"} 7"));
        assert!(txt.contains("event_persist_batch_seconds_count{tenant=\"default\"} 1"));
    }
}
