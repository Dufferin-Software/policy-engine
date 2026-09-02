// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Per-tenant alert grouper.
//!
//! Consumes matched events (after [`matcher::CompiledMatchSpec::matches`])
//! and runs each `(rule_id, group_key)` through the lifecycle described in
//! docs/event-pipeline.md "Group lifecycle":
//!
//! ```text
//! IDLE ──first event──► PENDING ──group_wait_s──► FIRING
//!                                                  │
//!                       no events for ─────────────┤
//!                       resolve_after_s            │ events keep arriving
//!                       → emit RESOLVED            │ → emit FIRE every
//!                                                  │   group_interval_s
//!                                                  │ otherwise heartbeat
//!                                                  │ every repeat_interval_s
//! ```
//!
//! Two modes:
//!
//! - **Per-event** (`RuleParams.threshold = None`): PENDING → FIRING gated
//!   solely on `group_wait_s`.
//! - **Threshold** (`Some(Threshold { count, window_s })`): PENDING →
//!   FIRING gated on a 10-bucket sliding-window count reaching `count`
//!   within `window_s`. `group_wait_s` is ignored in this mode — the
//!   threshold *is* the firing predicate. Once firing, `group_interval_s`
//!   / `repeat_interval_s` / `resolve_after_s` behave the same as per-event
//!   mode. Bucket width = `window_s / 10`, so the count is accurate to
//!   within ~10% at window boundaries — fine for alerting.
//!
//! Per-tenant LRU cap (default 10k) protects against runaway cardinality.
//! Eviction is rare in practice; on eviction the next event for that group
//! re-pends from zero — fine, just delays a fire by `group_wait_s`.
//!
//! State is in-memory only. On controller restart, pending groups re-pend
//! on the next event and firing groups re-fire once (a duplicate
//! notification). Receivers are expected to dedupe on
//! `(rule_id, group_key)` — Alertmanager and PagerDuty do.

use std::collections::HashMap;

use super::types::PolicyEvent;

/// Opaque per-group key. Built externally by stringifying the rule's
/// `group_by` tuple — the grouper doesn't interpret it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupKey(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Firing,
}

/// Threshold-mode parameters. When set on a [`RuleParams`], PENDING →
/// FIRING is gated on the sliding-window event count reaching `count`
/// within `window_s` instead of on `group_wait_s` elapsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub count: i64,
    pub window_s: i64,
}

/// Subset of `alert_rules` columns needed to advance group state. The full
/// alert-rule row carries more (match spec, receivers, severity, ...) but
/// the grouper only cares about timing.
#[derive(Debug, Clone)]
pub struct RuleParams {
    pub rule_id: i64,
    /// PENDING → FIRING delay in per-event mode. Lets nearby events
    /// coalesce into the first notification. Ignored when
    /// `threshold` is set.
    pub group_wait_s: i64,
    /// Minimum gap between successive notifications for the same firing
    /// group when new events keep arriving.
    pub group_interval_s: i64,
    /// Heartbeat re-notify cadence even when no new events arrive.
    pub repeat_interval_s: i64,
    /// Idle time after which a firing group resolves and is dropped.
    pub resolve_after_s: i64,
    /// `None` = per-event mode; `Some` = threshold mode.
    pub threshold: Option<Threshold>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationKind {
    /// PENDING → FIRING transition: the first notification for this group.
    InitialFire,
    /// Subsequent notification while still firing — either a batch of new
    /// events flushed at `group_interval_s`, or a heartbeat at
    /// `repeat_interval_s`.
    Refire,
    /// FIRING → RESOLVED. State is dropped after this is emitted.
    Resolve,
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub rule_id: i64,
    pub group_key: GroupKey,
    pub kind: NotificationKind,
    pub at_ns: i64,
    /// Events accumulated for this notification window. For `InitialFire`,
    /// the count since PENDING began; for `Refire`, since the previous
    /// notification; for `Resolve`, the count seen in the final window.
    pub event_count: i64,
    /// Up to 5 representative event IDs, capped over the group's lifetime
    /// (matches `alert_history.sample_event_ids`).
    pub sample_event_ids: Vec<i64>,
    /// The first matching event seen for this group, cloned at observe time.
    /// Used by the dispatcher to evaluate silences (which are event-shaped
    /// MatchSpecs). One-per-group, not refreshed — silence semantics treat
    /// the group as homogeneous along its group_by dims; fields outside
    /// group_by may differ across events in the group, which is a known
    /// limitation documented in docs/event-pipeline.md.
    pub sample_event: Option<PolicyEvent>,
}

const MAX_SAMPLE_EVENT_IDS: usize = 5;
const THRESHOLD_BUCKETS: usize = 10;

/// Sliding-window event counter used to gate threshold-mode firing.
/// 10 buckets covering `window_s`; bucket width = `window_s / 10` seconds
/// (rounded up to ≥ 1 ns so very small windows still work). Stale buckets
/// are zeroed lazily as time advances, keeping the sum monotonically
/// reflecting only the last `window_s` of activity.
#[derive(Debug)]
struct ThresholdWindow {
    bucket_width_ns: i64,
    /// Epoch (`ns / bucket_width_ns`) of `counts[head_idx]`.
    head_epoch: i64,
    head_idx: u8,
    counts: [u32; THRESHOLD_BUCKETS],
}

impl ThresholdWindow {
    fn new(window_s: i64, now_ns: i64) -> Self {
        let total_ns = window_s.saturating_mul(1_000_000_000).max(1);
        let bucket_width_ns = (total_ns / THRESHOLD_BUCKETS as i64).max(1);
        Self {
            bucket_width_ns,
            head_epoch: now_ns / bucket_width_ns,
            head_idx: 0,
            counts: [0; THRESHOLD_BUCKETS],
        }
    }

    /// Advance `head` to the bucket containing `now_ns`, zeroing any
    /// buckets we skip past so they don't carry stale counts back into the
    /// next window.
    fn advance_to(&mut self, now_ns: i64) {
        let target = now_ns / self.bucket_width_ns;
        if target <= self.head_epoch {
            return;
        }
        let steps = (target - self.head_epoch).min(THRESHOLD_BUCKETS as i64) as usize;
        for _ in 0..steps {
            self.head_idx = ((self.head_idx as usize + 1) % THRESHOLD_BUCKETS) as u8;
            self.counts[self.head_idx as usize] = 0;
        }
        self.head_epoch = target;
    }

    fn record(&mut self, now_ns: i64) {
        self.advance_to(now_ns);
        let c = &mut self.counts[self.head_idx as usize];
        *c = c.saturating_add(1);
    }

    fn sum(&mut self, now_ns: i64) -> u64 {
        self.advance_to(now_ns);
        self.counts.iter().map(|c| *c as u64).sum()
    }
}

#[derive(Debug)]
struct Group {
    state: State,
    /// When the group first transitioned out of IDLE.
    pending_since_ns: i64,
    /// Most recent matching event; drives the resolve timeout.
    last_event_ns: i64,
    /// `None` until the InitialFire notification has been emitted.
    last_notified_ns: Option<i64>,
    /// Events since the last notification was emitted (or since PENDING
    /// began, before the first fire).
    events_since_notify: i64,
    sample_event_ids: Vec<i64>,
    /// First matching event for the group, captured once and carried on
    /// every emitted notification.
    sample_event: Option<PolicyEvent>,
    /// LRU bookkeeping: updated on `observe` and on every notification we
    /// emit for this group. Eviction picks the smallest value.
    last_touched_ns: i64,
    /// Threshold-mode sliding window. `Some` iff the rule has threshold
    /// params set; lazily allocated on first observe so per-event groups
    /// pay nothing.
    window: Option<ThresholdWindow>,
}

pub struct TenantGrouper {
    max_groups: usize,
    groups: HashMap<(i64, GroupKey), Group>,
    evicted_total: u64,
}

impl TenantGrouper {
    pub fn new(max_groups: usize) -> Self {
        Self {
            max_groups,
            groups: HashMap::new(),
            evicted_total: 0,
        }
    }

    pub fn active_groups(&self) -> usize {
        self.groups.len()
    }

    pub fn evicted_total(&self) -> u64 {
        self.evicted_total
    }

    /// Record a matched event. May evict an older group if the cap is hit.
    /// Notifications are emitted by [`tick`] once timers expire, not here —
    /// keeps the hot ingest path allocation-free except for the
    /// once-per-group `PolicyEvent` clone captured as the silence sample.
    pub fn observe(
        &mut self,
        rule: &RuleParams,
        key: GroupKey,
        ev: &PolicyEvent,
        event_id: i64,
        now_ns: i64,
    ) {
        let map_key = (rule.rule_id, key);
        if let Some(g) = self.groups.get_mut(&map_key) {
            g.last_event_ns = now_ns;
            g.events_since_notify = g.events_since_notify.saturating_add(1);
            if g.sample_event_ids.len() < MAX_SAMPLE_EVENT_IDS {
                g.sample_event_ids.push(event_id);
            }
            g.last_touched_ns = now_ns;
            if let Some(w) = g.window.as_mut() {
                w.record(now_ns);
            }
            return;
        }
        // New group — enforce LRU cap before inserting.
        if self.groups.len() >= self.max_groups {
            self.evict_one();
        }
        let window = rule.threshold.map(|t| {
            let mut w = ThresholdWindow::new(t.window_s, now_ns);
            w.record(now_ns);
            w
        });
        self.groups.insert(
            map_key,
            Group {
                state: State::Pending,
                pending_since_ns: now_ns,
                last_event_ns: now_ns,
                last_notified_ns: None,
                events_since_notify: 1,
                sample_event_ids: vec![event_id],
                sample_event: Some(ev.clone()),
                last_touched_ns: now_ns,
                window,
            },
        );
    }

    /// Advance every group's timers and emit any notifications that fall
    /// out. `rules` lets the caller look up the timing params per `rule_id`;
    /// groups whose rule has been deleted are dropped silently.
    pub fn tick(&mut self, rules: &HashMap<i64, RuleParams>, now_ns: i64) -> Vec<Notification> {
        let mut out = Vec::new();
        let mut to_remove: Vec<(i64, GroupKey)> = Vec::new();

        for (k, g) in self.groups.iter_mut() {
            let Some(rule) = rules.get(&k.0) else {
                // Rule deleted out from under us — drop the group. No
                // RESOLVED notification: the dispatcher would have nowhere
                // to route it anyway.
                to_remove.push(k.clone());
                continue;
            };
            match g.state {
                State::Pending => {
                    let ready = match (rule.threshold, g.window.as_mut()) {
                        (Some(t), Some(w)) => w.sum(now_ns) >= t.count.max(0) as u64,
                        // Per-event mode (or threshold params dropped mid-life
                        // via hot-reload — treat as per-event from here).
                        _ => ns_age_s(now_ns, g.pending_since_ns) >= rule.group_wait_s,
                    };
                    if ready {
                        out.push(Notification {
                            rule_id: rule.rule_id,
                            group_key: k.1.clone(),
                            kind: NotificationKind::InitialFire,
                            at_ns: now_ns,
                            event_count: g.events_since_notify,
                            sample_event_ids: g.sample_event_ids.clone(),
                            sample_event: g.sample_event.clone(),
                        });
                        g.state = State::Firing;
                        g.last_notified_ns = Some(now_ns);
                        g.events_since_notify = 0;
                        g.last_touched_ns = now_ns;
                    }
                }
                State::Firing => {
                    let idle_s = ns_age_s(now_ns, g.last_event_ns);
                    if idle_s >= rule.resolve_after_s {
                        out.push(Notification {
                            rule_id: rule.rule_id,
                            group_key: k.1.clone(),
                            kind: NotificationKind::Resolve,
                            at_ns: now_ns,
                            event_count: g.events_since_notify,
                            sample_event_ids: g.sample_event_ids.clone(),
                            sample_event: g.sample_event.clone(),
                        });
                        to_remove.push(k.clone());
                        continue;
                    }
                    let since_notify_s =
                        ns_age_s(now_ns, g.last_notified_ns.unwrap_or(g.pending_since_ns));
                    // New events arrived since last notify and group_interval
                    // has elapsed → flush an update batch.
                    let should_update =
                        g.events_since_notify > 0 && since_notify_s >= rule.group_interval_s;
                    // No new events but heartbeat cadence elapsed → re-notify.
                    let should_heartbeat =
                        g.events_since_notify == 0 && since_notify_s >= rule.repeat_interval_s;
                    if should_update || should_heartbeat {
                        out.push(Notification {
                            rule_id: rule.rule_id,
                            group_key: k.1.clone(),
                            kind: NotificationKind::Refire,
                            at_ns: now_ns,
                            event_count: g.events_since_notify,
                            sample_event_ids: g.sample_event_ids.clone(),
                            sample_event: g.sample_event.clone(),
                        });
                        g.last_notified_ns = Some(now_ns);
                        g.events_since_notify = 0;
                        g.last_touched_ns = now_ns;
                    }
                }
            }
        }
        for k in to_remove {
            self.groups.remove(&k);
        }
        out
    }

    /// Drop the group that was last touched the longest ago. O(n) scan; n
    /// is bounded by `max_groups` (default 10k) and eviction should be a
    /// cold path, so the simple scan is intentional.
    fn evict_one(&mut self) {
        let Some(oldest) = self
            .groups
            .iter()
            .min_by_key(|(_, g)| g.last_touched_ns)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        self.groups.remove(&oldest);
        self.evicted_total = self.evicted_total.saturating_add(1);
    }
}

fn ns_age_s(now_ns: i64, then_ns: i64) -> i64 {
    (now_ns.saturating_sub(then_ns)) / 1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::types::{Action, Direction};

    const NS: i64 = 1_000_000_000;

    /// Test stub PolicyEvent. Field values are only meaningful for tests
    /// that read sample_event back through Notification; the timing tests
    /// don't care, they just need *some* event to pass to `observe`.
    fn stub_event() -> PolicyEvent {
        PolicyEvent {
            ts_ns: 0,
            node_id: "n1".into(),
            rule_id: 1,
            action: Action::Drop,
            verdict: 1,
            direction: Direction::Ingress,
            ifindex: 0,
            proto: 6,
            src_ip: vec![10, 0, 0, 1],
            dst_ip: vec![10, 0, 0, 2],
            sport: 1234,
            dport: 22,
            pkt_len: 64,
            flags: None,
            sni: None,
        }
    }

    fn rule(id: i64) -> RuleParams {
        RuleParams {
            rule_id: id,
            group_wait_s: 30,
            group_interval_s: 300,
            repeat_interval_s: 14_400,
            resolve_after_s: 1_500,
            threshold: None,
        }
    }

    fn rules(rs: &[&RuleParams]) -> HashMap<i64, RuleParams> {
        rs.iter().map(|r| (r.rule_id, (*r).clone())).collect()
    }

    fn key(s: &str) -> GroupKey {
        GroupKey(s.into())
    }

    #[test]
    fn first_event_pends_no_notification() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("a"), &stub_event(), 100, 0);
        // No notification before group_wait_s.
        assert!(g.tick(&rules(&[&r]), 10 * NS).is_empty());
        assert_eq!(g.active_groups(), 1);
    }

    #[test]
    fn initial_fire_after_group_wait() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("a"), &stub_event(), 100, 0);
        g.observe(&r, key("a"), &stub_event(), 101, 5 * NS);
        let n = g.tick(&rules(&[&r]), 30 * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::InitialFire);
        assert_eq!(n[0].event_count, 2);
        assert_eq!(n[0].sample_event_ids, vec![100, 101]);
        // Already fired — another tick at the same time emits nothing.
        assert!(g.tick(&rules(&[&r]), 30 * NS).is_empty());
    }

    #[test]
    fn refire_after_group_interval_with_new_events() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        // Initial fire at group_wait.
        let _ = g.tick(&rules(&[&r]), 30 * NS);
        // New events arrive but group_interval (300s) hasn't elapsed.
        g.observe(&r, key("a"), &stub_event(), 2, 60 * NS);
        assert!(g.tick(&rules(&[&r]), 100 * NS).is_empty());
        // After group_interval since last notify → refire with the new event.
        let n = g.tick(&rules(&[&r]), (30 + 300) * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::Refire);
        assert_eq!(n[0].event_count, 1);
    }

    #[test]
    fn heartbeat_after_repeat_interval_with_no_events() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        let _ = g.tick(&rules(&[&r]), 30 * NS);
        // No new events; well past group_interval but inside resolve_after.
        // group_interval=300 alone shouldn't refire (no new events), and
        // repeat_interval=14400 > resolve_after=1500 so we'd resolve first.
        // Use a rule with short resolve_after disabled by setting it huge,
        // and short repeat_interval to exercise the heartbeat branch.
        let r2 = RuleParams {
            rule_id: 2,
            group_wait_s: 30,
            group_interval_s: 300,
            repeat_interval_s: 600,
            resolve_after_s: 10_000,
            threshold: None,
        };
        let mut g = TenantGrouper::new(10);
        g.observe(&r2, key("a"), &stub_event(), 1, 0);
        let _ = g.tick(&rules(&[&r2]), 30 * NS);
        // No events between 30s and 700s → heartbeat at 30 + 600 = 630s.
        assert!(g.tick(&rules(&[&r2]), 500 * NS).is_empty());
        let n = g.tick(&rules(&[&r2]), 700 * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::Refire);
        assert_eq!(n[0].event_count, 0);
    }

    #[test]
    fn resolves_after_idle_window() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        let _ = g.tick(&rules(&[&r]), 30 * NS);
        // No events for resolve_after_s (1500) → resolve.
        let n = g.tick(&rules(&[&r]), 2000 * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::Resolve);
        assert_eq!(g.active_groups(), 0);
    }

    #[test]
    fn deleted_rule_drops_group_silently() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        // Rules map omits rule 1 — group is silently dropped, no RESOLVED.
        let n = g.tick(&HashMap::new(), 30 * NS);
        assert!(n.is_empty());
        assert_eq!(g.active_groups(), 0);
    }

    #[test]
    fn sample_event_ids_capped_at_five() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        for i in 0..10 {
            g.observe(&r, key("a"), &stub_event(), 100 + i, (i * NS) / 10);
        }
        let n = g.tick(&rules(&[&r]), 30 * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].sample_event_ids, vec![100, 101, 102, 103, 104]);
        assert_eq!(n[0].event_count, 10);
    }

    #[test]
    fn lru_eviction_when_cap_hit() {
        let mut g = TenantGrouper::new(2);
        let r = rule(1);
        // a@0, b@1s, c@2s — cap=2 so adding c evicts a (oldest touched).
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        g.observe(&r, key("b"), &stub_event(), 2, NS);
        g.observe(&r, key("c"), &stub_event(), 3, 2 * NS);
        assert_eq!(g.active_groups(), 2);
        assert_eq!(g.evicted_total(), 1);
        assert!(!g.groups.contains_key(&(1, key("a"))));
        // Touch b so it's now the newest — c becomes oldest.
        g.observe(&r, key("b"), &stub_event(), 4, 3 * NS);
        // Adding d should now evict c, not b.
        g.observe(&r, key("d"), &stub_event(), 5, 4 * NS);
        assert_eq!(g.evicted_total(), 2);
        assert!(g.groups.contains_key(&(1, key("b"))));
        assert!(g.groups.contains_key(&(1, key("d"))));
        assert!(!g.groups.contains_key(&(1, key("c"))));
    }

    #[test]
    fn observing_in_firing_state_accumulates_until_group_interval() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        let _ = g.tick(&rules(&[&r]), 30 * NS);
        g.observe(&r, key("a"), &stub_event(), 2, 35 * NS);
        g.observe(&r, key("a"), &stub_event(), 3, 40 * NS);
        // Check that the next notification reports both new events (not the
        // original one — that was counted in InitialFire).
        let n = g.tick(&rules(&[&r]), (30 + 300) * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].event_count, 2);
        // Samples were filled by ID 1 / 2 / 3; lifetime cap of 5 not yet hit.
        assert_eq!(n[0].sample_event_ids, vec![1, 2, 3]);
    }

    #[test]
    fn distinct_group_keys_are_independent() {
        let mut g = TenantGrouper::new(10);
        let r = rule(1);
        g.observe(&r, key("src=10.0.0.1"), &stub_event(), 1, 0);
        g.observe(&r, key("src=10.0.0.2"), &stub_event(), 2, 0);
        let n = g.tick(&rules(&[&r]), 30 * NS);
        assert_eq!(n.len(), 2);
        // Either ordering is fine — assert both keys fired exactly once.
        let mut keys: Vec<&str> = n.iter().map(|x| x.group_key.0.as_str()).collect();
        keys.sort();
        assert_eq!(keys, vec!["src=10.0.0.1", "src=10.0.0.2"]);
    }

    fn threshold_rule(id: i64, count: i64, window_s: i64) -> RuleParams {
        RuleParams {
            rule_id: id,
            // group_wait_s deliberately huge: in threshold mode it must be
            // ignored, so a passing test proves the threshold path fires
            // before group_wait_s could.
            group_wait_s: 86_400,
            group_interval_s: 300,
            repeat_interval_s: 14_400,
            resolve_after_s: 1_500,
            threshold: Some(Threshold { count, window_s }),
        }
    }

    #[test]
    fn threshold_fires_when_count_reached_inside_window() {
        let mut g = TenantGrouper::new(10);
        let r = threshold_rule(1, 5, 60);
        // 5 events spread across the first 30 s — well inside the 60 s window.
        for i in 0..5 {
            g.observe(&r, key("a"), &stub_event(), 100 + i, i * 5 * NS);
        }
        // group_wait_s=86400 would normally gate firing; threshold mode
        // overrides it, so a tick right after the 5th event must fire.
        let n = g.tick(&rules(&[&r]), 21 * NS);
        assert_eq!(n.len(), 1, "expected initial fire once threshold reached");
        assert_eq!(n[0].kind, NotificationKind::InitialFire);
        assert_eq!(n[0].event_count, 5);
    }

    #[test]
    fn threshold_does_not_fire_below_count() {
        let mut g = TenantGrouper::new(10);
        let r = threshold_rule(1, 5, 60);
        // 4 events in 20 s — under threshold.
        for i in 0..4 {
            g.observe(&r, key("a"), &stub_event(), 100 + i, i * 5 * NS);
        }
        let n = g.tick(&rules(&[&r]), 21 * NS);
        assert!(n.is_empty());
        assert_eq!(g.active_groups(), 1);
    }

    #[test]
    fn threshold_window_ages_out_old_events() {
        let mut g = TenantGrouper::new(10);
        let r = threshold_rule(1, 5, 60);
        // 3 events early, then a long pause, then 3 more. The first 3
        // age out of the 60 s window before the count is checked, so
        // total in-window is 3 < 5 → no fire.
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        g.observe(&r, key("a"), &stub_event(), 2, 2 * NS);
        g.observe(&r, key("a"), &stub_event(), 3, 4 * NS);
        // Long enough that the original 3 fall outside the 60 s window.
        g.observe(&r, key("a"), &stub_event(), 4, 200 * NS);
        g.observe(&r, key("a"), &stub_event(), 5, 205 * NS);
        g.observe(&r, key("a"), &stub_event(), 6, 210 * NS);
        let n = g.tick(&rules(&[&r]), 211 * NS);
        assert!(n.is_empty(), "old events should not count toward threshold");
        // events_since_notify still accumulates (it's a separate counter
        // used for the InitialFire payload, not the threshold gate).
    }

    #[test]
    fn threshold_fires_across_bucket_boundaries() {
        let mut g = TenantGrouper::new(10);
        // window=60s, count=5 → bucket width = 6 s. Spread one event per
        // bucket across 30 s; all five buckets are within the window.
        let r = threshold_rule(1, 5, 60);
        for i in 0..5 {
            g.observe(&r, key("a"), &stub_event(), 100 + i, i * 7 * NS);
        }
        let n = g.tick(&rules(&[&r]), 30 * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::InitialFire);
    }

    #[test]
    fn threshold_mode_still_refires_and_resolves() {
        let mut g = TenantGrouper::new(10);
        let r = threshold_rule(1, 2, 60);
        // Hit threshold immediately.
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        g.observe(&r, key("a"), &stub_event(), 2, NS);
        let n = g.tick(&rules(&[&r]), 2 * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::InitialFire);
        // Refire on group_interval (300 s) with new events.
        g.observe(&r, key("a"), &stub_event(), 3, 100 * NS);
        let n = g.tick(&rules(&[&r]), 305 * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::Refire);
        // Resolve after idle window.
        let n = g.tick(&rules(&[&r]), (305 + 1_500) * NS);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::Resolve);
        assert_eq!(g.active_groups(), 0);
    }

    #[test]
    fn threshold_sub_ten_second_window_still_works() {
        // window_s=1 → bucket_width = 100 ms. The bucket math used to
        // collapse to 0 ns if we naively did `window_s/10` in seconds;
        // ThresholdWindow::new converts to nanoseconds first then divides.
        let mut g = TenantGrouper::new(10);
        let r = threshold_rule(1, 3, 1);
        g.observe(&r, key("a"), &stub_event(), 1, 0);
        g.observe(&r, key("a"), &stub_event(), 2, NS / 4);
        g.observe(&r, key("a"), &stub_event(), 3, NS / 2);
        let n = g.tick(&rules(&[&r]), NS / 2);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].kind, NotificationKind::InitialFire);
    }
}
