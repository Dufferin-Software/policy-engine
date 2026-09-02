// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Attribute flow-verdict-cache traffic to per-rule statistics.
//!
//! The XDP/TC fast path no longer touches `rule_stats` on a verdict-cache hit
//! (that cost a HASH lookup plus two shared atomic adds per packet).  Instead,
//! each `flow_verdict` entry accumulates per-flow packets/bytes/last_seen_ns
//! and carries the `rule_id` that produced the verdict; userspace folds the
//! *deltas* of those counters into the `rule_stats` / `tc_rule_stats` maps
//! whenever it walks the verdict cache (the 30 s expiry sweep, any verdict
//! listing, the pre-flush walk on rule changes) and, rate-limited, on
//! `get_rule_stats` reads.
//!
//! [`VerdictHarvestState`] holds the per-flow counter baselines from the last
//! fold so each packet is attributed exactly once.  A verdict entry can be
//! *replaced* in place (rule-change flush followed by a re-seed, or an SNI /
//! IPS writer overwriting a policy verdict), which restarts its counters from
//! zero; replacement is detected by comparing the entry's identity
//! (`timestamp_ns`, `rule_id`) against the baseline, in which case the full
//! counter value is the delta.
//!
//! Known, accepted loss windows (all bounded by the harvest cadence):
//!  - an LRU-evicted entry takes its unharvested delta with it;
//!  - counters accumulated while the daemon is down (pinned programs keep
//!    running) are absorbed by [`VerdictHarvestState::fold`]'s priming pass on
//!    the first walk after a restart rather than re-attributed, since they may
//!    already have been folded before the restart.

use std::collections::HashMap;
use std::time::Instant;

use crate::types::{FlowVerdict, FlowVerdictKey};

/// Per-rule counter deltas produced by one [`VerdictHarvestState::fold`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RuleDelta {
    pub packets: u64,
    pub bytes: u64,
    /// Most recent cache hit across the rule's flows (0 = none observed).
    pub last_seen_ns: u64,
}

/// A flow's verdict-entry counters as of the last fold, plus the identity
/// fields used to detect in-place replacement of the entry.
#[derive(Debug, Clone, Copy)]
struct Baseline {
    timestamp_ns: u64,
    rule_id: u64,
    packets: u64,
    bytes: u64,
}

impl Baseline {
    fn of(v: &FlowVerdict) -> Self {
        Self {
            timestamp_ns: v.timestamp_ns,
            rule_id: v.rule_id,
            packets: v.packets,
            bytes: v.bytes,
        }
    }

    fn matches(&self, v: &FlowVerdict) -> bool {
        self.timestamp_ns == v.timestamp_ns && self.rule_id == v.rule_id
    }
}

/// Tracks verdict-cache counter baselines for one direction (one BPF map).
pub struct VerdictHarvestState {
    baselines: HashMap<Vec<u8>, Baseline>,
    /// False until the first walk.  The first walk only records baselines:
    /// on a same-version daemon restart the pinned cache survives with
    /// counters that were (mostly) folded by the previous process, so
    /// attributing them again would double-count.
    primed: bool,
    /// When the last fold ran — lets read paths rate-limit full cache walks.
    last_fold: Option<Instant>,
}

impl Default for VerdictHarvestState {
    fn default() -> Self {
        Self::new()
    }
}

impl VerdictHarvestState {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            primed: false,
            last_fold: None,
        }
    }

    /// Duration since the last fold, or `None` if none has run yet.
    pub fn elapsed_since_fold(&self) -> Option<std::time::Duration> {
        self.last_fold.map(|t| t.elapsed())
    }

    /// Fold a full listing of the direction's verdict cache: return the
    /// per-rule packet/byte deltas accrued since the previous fold and advance
    /// the baselines to the current counters.  Entries whose `rule_id` is 0
    /// (default action / SNI / IPS verdicts) update baselines only.
    ///
    /// The first call after construction primes the baselines and returns no
    /// deltas (see the field comment on `primed`).
    pub fn fold(&mut self, verdicts: &[(FlowVerdictKey, FlowVerdict)]) -> HashMap<u64, RuleDelta> {
        let mut deltas: HashMap<u64, RuleDelta> = HashMap::new();
        let mut new_baselines: HashMap<Vec<u8>, Baseline> = HashMap::with_capacity(verdicts.len());

        for (key, v) in verdicts {
            let key_bytes = key.as_bytes().to_vec();
            let (d_packets, d_bytes) = match self.baselines.get(&key_bytes) {
                Some(b) if b.matches(v) => (
                    v.packets.saturating_sub(b.packets),
                    v.bytes.saturating_sub(b.bytes),
                ),
                // New flow, or the entry was replaced in place and its
                // counters restarted from zero — the full value is the delta.
                _ => (v.packets, v.bytes),
            };
            new_baselines.insert(key_bytes, Baseline::of(v));

            if self.primed && v.rule_id != 0 && d_packets > 0 {
                let d = deltas.entry(v.rule_id).or_default();
                d.packets += d_packets;
                d.bytes += d_bytes;
                d.last_seen_ns = d.last_seen_ns.max(v.last_seen_ns);
            }
        }

        // Flows absent from this walk were deleted or LRU-evicted; dropping
        // their baselines here is what makes eviction's delta loss bounded by
        // the walk cadence instead of permanent staleness.
        self.baselines = new_baselines;
        self.primed = true;
        self.last_fold = Some(Instant::now());
        deltas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(sport: u16) -> FlowVerdictKey {
        let mut k = FlowVerdictKey::default();
        k.saddr[..4].copy_from_slice(&[10, 0, 0, 1]);
        k.daddr[..4].copy_from_slice(&[10, 0, 0, 2]);
        k.sport = sport;
        k.dport = 443;
        k.protocol = 17;
        k.af = crate::types::AF_INET;
        k
    }

    fn verdict(rule_id: u64, packets: u64, bytes: u64, last_seen_ns: u64) -> FlowVerdict {
        FlowVerdict {
            action: crate::types::PolicyAction::Pass as u32,
            _pad: 0,
            timestamp_ns: 1000,
            expires_ns: 0,
            packets,
            bytes,
            last_seen_ns,
            rule_id,
        }
    }

    #[test]
    fn first_fold_primes_and_returns_nothing() {
        let mut s = VerdictHarvestState::new();
        let listing = vec![(key(1), verdict(7, 100, 6400, 5000))];
        assert!(s.fold(&listing).is_empty());
        // Second fold with unchanged counters: still nothing.
        assert!(s.fold(&listing).is_empty());
    }

    #[test]
    fn fold_attributes_deltas_since_baseline() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[(key(1), verdict(7, 100, 6400, 5000))]);
        let deltas = s.fold(&[(key(1), verdict(7, 150, 9600, 9000))]);
        assert_eq!(
            deltas[&7],
            RuleDelta {
                packets: 50,
                bytes: 3200,
                last_seen_ns: 9000
            }
        );
        // Deltas were consumed; folding the same listing again yields nothing.
        assert!(s.fold(&[(key(1), verdict(7, 150, 9600, 9000))]).is_empty());
    }

    #[test]
    fn new_flow_after_priming_counts_from_zero() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[]);
        let deltas = s.fold(&[(key(2), verdict(9, 40, 2560, 100))]);
        assert_eq!(
            deltas[&9],
            RuleDelta {
                packets: 40,
                bytes: 2560,
                last_seen_ns: 100
            }
        );
    }

    #[test]
    fn multiple_flows_same_rule_accumulate() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[]);
        let deltas = s.fold(&[
            (key(1), verdict(7, 10, 640, 100)),
            (key(2), verdict(7, 5, 320, 900)),
            (key(3), verdict(8, 1, 64, 50)),
        ]);
        assert_eq!(
            deltas[&7],
            RuleDelta {
                packets: 15,
                bytes: 960,
                last_seen_ns: 900
            }
        );
        assert_eq!(deltas[&8].packets, 1);
    }

    #[test]
    fn rule_id_zero_is_never_attributed() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[]);
        let deltas = s.fold(&[(key(1), verdict(0, 500, 32000, 100))]);
        assert!(deltas.is_empty());
    }

    #[test]
    fn replaced_entry_counts_full_value_not_negative() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[]);
        s.fold(&[(key(1), verdict(7, 100, 6400, 100))]);
        // Entry replaced in place: different timestamp_ns identity, counters
        // restarted below the old baseline.
        let mut replaced = verdict(7, 30, 1920, 200);
        replaced.timestamp_ns = 2000;
        let deltas = s.fold(&[(key(1), replaced)]);
        assert_eq!(deltas[&7].packets, 30);
        assert_eq!(deltas[&7].bytes, 1920);
    }

    #[test]
    fn rule_id_change_resets_baseline_and_attributes_to_new_rule() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[]);
        s.fold(&[(key(1), verdict(7, 100, 6400, 100))]);
        // Same key re-seeded for a different rule after a policy change.
        let deltas = s.fold(&[(key(1), verdict(9, 20, 1280, 300))]);
        assert!(!deltas.contains_key(&7));
        assert_eq!(deltas[&9].packets, 20);
    }

    #[test]
    fn evicted_flow_baseline_is_pruned() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[]);
        s.fold(&[(key(1), verdict(7, 100, 6400, 100))]);
        // Entry evicted (absent), then a new flow reuses the same 5-tuple.
        s.fold(&[]);
        let deltas = s.fold(&[(key(1), verdict(7, 10, 640, 100))]);
        assert_eq!(deltas[&7].packets, 10);
    }

    #[test]
    fn counter_regression_on_same_identity_saturates_to_zero() {
        let mut s = VerdictHarvestState::new();
        s.fold(&[]);
        s.fold(&[(key(1), verdict(7, 100, 6400, 100))]);
        // Same identity but counters below baseline (e.g. torn read of a
        // racing snapshot): must not attribute a bogus huge delta.
        let deltas = s.fold(&[(key(1), verdict(7, 99, 6336, 100))]);
        assert!(deltas.is_empty());
    }
}
