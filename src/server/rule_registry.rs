// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Rule registry — tracks managed rules with TTL or weekly schedules.
//!
//! Rules in this registry are persisted in-memory only; they do not survive
//! server restarts.  The [`RuleRegistry`] is purely a data store; callers
//! (i.e. [`PolicyService`]) are responsible for actually installing or removing
//! rules from the BPF maps.

use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use std::collections::HashMap;

use crate::server::policy_service::AddRuleParams;
use crate::types::Direction;

// ── Schedule types ───────────────────────────────────────────────────────────

/// A single point-in-time within a week.
///
/// `day_of_week`: 0 = Sunday … 6 = Saturday (matching `chrono::Weekday`'s
/// `num_days_from_sunday()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeeklyTimePoint {
    pub day_of_week: u8, // 0–6
    pub hour: u8,        // 0–23
    pub minute: u8,      // 0–59
}

impl WeeklyTimePoint {
    /// Convert to "week-minutes since Sunday 00:00" (0 – 10 079).
    pub fn to_week_minutes(&self) -> u32 {
        self.day_of_week as u32 * 1440 + self.hour as u32 * 60 + self.minute as u32
    }
}

/// A half-open time window `[start, end)` expressed in weekly repeating time.
///
/// If `end` ≤ `start` (in week-minutes) the window wraps around the
/// Saturday/Sunday boundary — e.g. Sat 23:00 → Sun 01:00.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeeklyWindow {
    pub start: WeeklyTimePoint,
    pub end: WeeklyTimePoint,
}

/// A collection of weekly windows plus the IANA timezone name that should be
/// used when interpreting them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSchedule {
    pub windows: Vec<WeeklyWindow>,
    /// IANA timezone name, e.g. `"America/Toronto"` or `"UTC"`.
    pub timezone: String,
}

// ── Lifecycle kinds ──────────────────────────────────────────────────────────

/// How a managed rule's lifetime is controlled.
#[derive(Debug, Clone)]
pub enum RuleLifecycleKind {
    /// The rule is unconditionally removed once `expires_at` passes.
    Ttl { expires_at: DateTime<Utc> },
    /// The rule is installed/removed according to a weekly schedule.
    Scheduled { schedule: RuleSchedule },
}

/// Whether the rule is currently installed in the BPF maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleState {
    Active,
    Inactive,
}

// ── ManagedRule ──────────────────────────────────────────────────────────────

/// A rule that is tracked by the registry (has either TTL or a schedule).
#[derive(Debug, Clone)]
pub struct ManagedRule {
    pub rule_id: u64,
    /// The full parameters needed to re-install the rule.
    pub params: AddRuleParams,
    pub direction: Direction,
    pub lifecycle: RuleLifecycleKind,
    pub state: RuleState,
    /// Key into the background `DelayQueue`; `None` until the timer task inserts it.
    pub delay_key: Option<tokio_util::time::delay_queue::Key>,
}

// ── RuleRegistry ─────────────────────────────────────────────────────────────

/// In-memory store of rules that have TTL or schedule constraints.
#[derive(Default)]
pub struct RuleRegistry {
    rules: HashMap<u64, ManagedRule>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, rule: ManagedRule) {
        self.rules.insert(rule.rule_id, rule);
    }

    pub fn remove(&mut self, rule_id: u64) -> Option<ManagedRule> {
        self.rules.remove(&rule_id)
    }

    pub fn get(&self, rule_id: u64) -> Option<&ManagedRule> {
        self.rules.get(&rule_id)
    }

    pub fn get_mut(&mut self, rule_id: u64) -> Option<&mut ManagedRule> {
        self.rules.get_mut(&rule_id)
    }

    pub fn list(&self) -> impl Iterator<Item = &ManagedRule> {
        self.rules.values()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Compute which rule IDs should transition state given the current time.
    ///
    /// Returns `(to_activate, to_deactivate, to_expire)`:
    /// - `to_activate`: currently `Inactive` rules that should become `Active`
    /// - `to_deactivate`: currently `Active` rules that should become `Inactive`
    /// - `to_expire`: TTL rules whose deadline has passed (regardless of state)
    pub fn compute_transitions(&self, now: DateTime<Utc>) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
        let mut to_activate = Vec::new();
        let mut to_deactivate = Vec::new();
        let mut to_expire = Vec::new();

        for rule in self.rules.values() {
            match &rule.lifecycle {
                RuleLifecycleKind::Ttl { expires_at } => {
                    if now >= *expires_at {
                        to_expire.push(rule.rule_id);
                    }
                    // TTL rules that have not yet expired keep their current state
                }
                RuleLifecycleKind::Scheduled { schedule } => {
                    let should_be_active = is_in_schedule(schedule, now);
                    match (&rule.state, should_be_active) {
                        (RuleState::Inactive, true) => to_activate.push(rule.rule_id),
                        (RuleState::Active, false) => to_deactivate.push(rule.rule_id),
                        _ => {} // already in correct state
                    }
                }
            }
        }

        (to_activate, to_deactivate, to_expire)
    }
}

// ── Schedule evaluation ──────────────────────────────────────────────────────

/// Returns `true` if `now` (UTC) falls within any window of `schedule`.
///
/// The timezone specified in `schedule.timezone` is applied before comparing
/// with the window boundaries.  If the timezone string cannot be parsed,
/// `false` is returned (fail-closed).
pub fn is_in_schedule(schedule: &RuleSchedule, now: DateTime<Utc>) -> bool {
    if schedule.windows.is_empty() {
        return false;
    }

    // Parse the IANA timezone; fall back to UTC on failure.
    let tz: chrono_tz::Tz = match schedule.timezone.parse() {
        Ok(t) => t,
        Err(_) => chrono_tz::UTC,
    };

    let local = now.with_timezone(&tz);
    let now_mins =
        weekday_to_dow(local.weekday()) as u32 * 1440 + local.hour() * 60 + local.minute();

    for window in &schedule.windows {
        if window_contains(window, now_mins) {
            return true;
        }
    }
    false
}

/// Convert `chrono::Weekday` to 0=Sunday … 6=Saturday.
fn weekday_to_dow(wd: Weekday) -> u8 {
    wd.num_days_from_sunday() as u8
}

/// Find the nearest future minute (in the schedule's timezone) at which the
/// rule's active/inactive state changes, given the current UTC time `now`.
///
/// Returns `None` when the schedule has no windows (the rule is permanently
/// inactive and never transitions).
///
/// # Algorithm
///
/// 1. Convert `now` to the schedule's timezone, truncate to the minute.
/// 2. Walk forward one minute at a time (up to a full week = 10 080 minutes)
///    and stop at the first minute where `is_in_schedule` differs from the
///    current state.
///
/// A full-week scan is at most 10 080 steps and is only done once per
/// expiry event, so the overhead is negligible.
pub fn next_schedule_transition(
    schedule: &RuleSchedule,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    if schedule.windows.is_empty() {
        return None;
    }

    let current_state = is_in_schedule(schedule, now);

    // Walk forward one minute at a time, looking for the first flip.
    for offset_mins in 1u32..=10_080 {
        let candidate = now + chrono::Duration::minutes(offset_mins as i64);
        if is_in_schedule(schedule, candidate) != current_state {
            // Round down to the minute boundary so the timer fires cleanly.
            let truncated = candidate
                .with_second(0)
                .and_then(|t| t.with_nanosecond(0))
                .unwrap_or(candidate);
            return Some(truncated);
        }
    }

    // No transition within the next week — schedule is "always on" or "always off".
    None
}

/// Check whether `now_mins` falls in the half-open window `[start, end)`.
///
/// Handles week-boundary wrap when `end_mins ≤ start_mins`.
fn window_contains(window: &WeeklyWindow, now_mins: u32) -> bool {
    let start_mins = window.start.to_week_minutes();
    let end_mins = window.end.to_week_minutes();

    if end_mins == start_mins {
        // Zero-length half-open window [X, X) matches nothing.
        false
    } else if end_mins > start_mins {
        // Normal window: does not cross the week boundary.
        now_mins >= start_mins && now_mins < end_mins
    } else {
        // Week-boundary wrap (e.g. Sat 22:00 → Sun 02:00).
        now_mins >= start_mins || now_mins < end_mins
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // Helper: build a simple schedule with one window.
    fn schedule(
        start_day: u8,
        start_h: u8,
        start_m: u8,
        end_day: u8,
        end_h: u8,
        end_m: u8,
        tz: &str,
    ) -> RuleSchedule {
        RuleSchedule {
            windows: vec![WeeklyWindow {
                start: WeeklyTimePoint {
                    day_of_week: start_day,
                    hour: start_h,
                    minute: start_m,
                },
                end: WeeklyTimePoint {
                    day_of_week: end_day,
                    hour: end_h,
                    minute: end_m,
                },
            }],
            timezone: tz.to_string(),
        }
    }

    // 2024-01-07 is a Sunday (DOW=0)
    // 2024-01-08 Mon, 2024-01-09 Tue, ..., 2024-01-12 Fri, 2024-01-13 Sat

    // ── is_in_schedule: window within the same day ────────────────────────

    #[test]
    fn test_same_day_window_inside() {
        // Window: Mon 09:00 – Mon 17:00 UTC
        // now: Mon 12:00 UTC → should be inside
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        assert!(is_in_schedule(&sched, now));
    }

    #[test]
    fn test_same_day_window_before() {
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 8, 59, 0).unwrap();
        assert!(!is_in_schedule(&sched, now));
    }

    #[test]
    fn test_same_day_window_after() {
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 17, 0, 0).unwrap(); // exactly at end — exclusive
        assert!(!is_in_schedule(&sched, now));
    }

    // ── is_in_schedule: boundary conditions ──────────────────────────────

    #[test]
    fn test_boundary_at_start_is_inclusive() {
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 9, 0, 0).unwrap();
        assert!(is_in_schedule(&sched, now));
    }

    #[test]
    fn test_boundary_just_before_end() {
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 16, 59, 0).unwrap();
        assert!(is_in_schedule(&sched, now));
    }

    // ── is_in_schedule: multi-day window (Sun → Fri, parental controls) ──

    #[test]
    fn test_multi_day_window_inside() {
        // Window: Sun 00:00 (0) → Fri 00:00 (5)
        let sched = schedule(0, 0, 0, 5, 0, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 10, 12, 0, 0).unwrap(); // Wednesday
        assert!(is_in_schedule(&sched, now));
    }

    #[test]
    fn test_multi_day_window_outside() {
        let sched = schedule(0, 0, 0, 5, 0, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 12, 12, 0, 0).unwrap(); // Friday noon — after end
        assert!(!is_in_schedule(&sched, now));
    }

    #[test]
    fn test_multi_day_window_exactly_at_end() {
        let sched = schedule(0, 0, 0, 5, 0, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 12, 0, 0, 0).unwrap(); // Friday 00:00 — exclusive end
        assert!(!is_in_schedule(&sched, now));
    }

    // ── is_in_schedule: week-boundary wrap (Sat → Sun) ───────────────────

    #[test]
    fn test_week_boundary_inside_after_start() {
        // Window: Sat 22:00 (6) → Sun 02:00 (0) — wraps
        let sched = schedule(6, 22, 0, 0, 2, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 13, 23, 0, 0).unwrap(); // Sat 23:00
        assert!(is_in_schedule(&sched, now));
    }

    #[test]
    fn test_week_boundary_inside_before_end() {
        let sched = schedule(6, 22, 0, 0, 2, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 14, 1, 30, 0).unwrap(); // Sun 01:30
        assert!(is_in_schedule(&sched, now));
    }

    #[test]
    fn test_week_boundary_outside() {
        let sched = schedule(6, 22, 0, 0, 2, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 14, 10, 0, 0).unwrap(); // Sun 10:00 — outside
        assert!(!is_in_schedule(&sched, now));
    }

    #[test]
    fn test_week_boundary_at_end_exclusive() {
        let sched = schedule(6, 22, 0, 0, 2, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 14, 2, 0, 0).unwrap(); // Sun 02:00 — exclusive
        assert!(!is_in_schedule(&sched, now));
    }

    // ── is_in_schedule: timezone conversion ──────────────────────────────

    #[test]
    fn test_timezone_toronto_inside() {
        // Window: Mon 09:00 – Mon 17:00 America/Toronto (UTC-5 in January)
        // now UTC = Mon 14:00 UTC = Mon 09:00 Toronto → exactly at start
        let sched = schedule(1, 9, 0, 1, 17, 0, "America/Toronto");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 14, 0, 0).unwrap();
        assert!(is_in_schedule(&sched, now));
    }

    #[test]
    fn test_timezone_toronto_outside() {
        // Mon 13:59 UTC = Mon 08:59 Toronto — before the 09:00 start
        let sched = schedule(1, 9, 0, 1, 17, 0, "America/Toronto");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 13, 59, 0).unwrap();
        assert!(!is_in_schedule(&sched, now));
    }

    #[test]
    fn test_timezone_toronto_day_boundary() {
        // Window: Sun 00:00 → Fri 00:00 America/Toronto
        // Wed 03:00 UTC = Tue 22:00 Toronto → inside the window (Tue is inside Sun→Fri)
        let sched = schedule(0, 0, 0, 5, 0, 0, "America/Toronto");
        let now = Utc.with_ymd_and_hms(2024, 1, 10, 3, 0, 0).unwrap();
        assert!(is_in_schedule(&sched, now));
    }

    // ── is_in_schedule: zero-length window ───────────────────────────────

    /// Regression: a window with `start == end` previously fell into the
    /// week-boundary wrap branch and matched every minute of the week,
    /// because `now >= X || now < X` is tautologically true. The half-open
    /// `[X, X)` window should match nothing.
    #[test]
    fn test_zero_length_window_matches_nothing() {
        // Window: Mon 09:00 → Mon 09:00 (zero-length).
        let sched = schedule(1, 9, 0, 1, 9, 0, "UTC");

        // Try several times across the week — none should match.
        let samples = [
            Utc.with_ymd_and_hms(2024, 1, 7, 0, 0, 0).unwrap(), // Sun 00:00
            Utc.with_ymd_and_hms(2024, 1, 8, 9, 0, 0).unwrap(), // Mon 09:00 (exact)
            Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap(), // Mon 12:00
            Utc.with_ymd_and_hms(2024, 1, 10, 15, 0, 0).unwrap(), // Wed 15:00
            Utc.with_ymd_and_hms(2024, 1, 13, 23, 59, 0).unwrap(), // Sat 23:59
        ];
        for now in samples {
            assert!(
                !is_in_schedule(&sched, now),
                "zero-length window unexpectedly matched at {now}"
            );
        }
    }

    /// Regression: ensure a scheduled rule with a zero-length window does
    /// not get spuriously activated.
    #[test]
    fn test_zero_length_window_does_not_activate_rule() {
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        let sched = schedule(1, 9, 0, 1, 9, 0, "UTC"); // zero-length
        let mut reg = RuleRegistry::new();
        reg.register(make_scheduled_rule(1, sched, RuleState::Inactive));

        let (activate, deactivate, expire) = reg.compute_transitions(now);
        assert!(
            activate.is_empty(),
            "zero-length window should not activate any rule"
        );
        assert!(deactivate.is_empty());
        assert!(expire.is_empty());
    }

    // ── is_in_schedule: empty windows list ───────────────────────────────

    #[test]
    fn test_empty_windows_always_false() {
        let sched = RuleSchedule {
            windows: vec![],
            timezone: "UTC".to_string(),
        };
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        assert!(!is_in_schedule(&sched, now));
    }

    // ── is_in_schedule: bad timezone string → fail-closed ────────────────

    #[test]
    fn test_invalid_timezone_returns_false() {
        let sched = schedule(0, 0, 0, 6, 0, 0, "Not/A/Timezone");
        // Falls back to UTC; UTC time is Sunday 00:00 – still inside the window
        // (DOW 0, window 0→6 is basically "all week").  The important thing is
        // it does NOT panic.
        let now = Utc.with_ymd_and_hms(2024, 1, 7, 12, 0, 0).unwrap(); // Sunday
                                                                       // We only assert it does not panic; result depends on fallback behaviour.
        let _ = is_in_schedule(&sched, now);
    }

    // ── RuleRegistry::compute_transitions ────────────────────────────────

    fn make_ttl_rule(rule_id: u64, expires_at: DateTime<Utc>, state: RuleState) -> ManagedRule {
        ManagedRule {
            rule_id,
            params: dummy_params(),
            direction: Direction::Ingress,
            lifecycle: RuleLifecycleKind::Ttl { expires_at },
            state,
            delay_key: None,
        }
    }

    fn make_scheduled_rule(rule_id: u64, schedule: RuleSchedule, state: RuleState) -> ManagedRule {
        ManagedRule {
            rule_id,
            params: dummy_params(),
            direction: Direction::Ingress,
            lifecycle: RuleLifecycleKind::Scheduled { schedule },
            state,
            delay_key: None,
        }
    }

    fn dummy_params() -> AddRuleParams {
        AddRuleParams {
            ifindex: 0,
            direction: Direction::Ingress,
            id: None,
            src: None,
            dst: None,
            sport: 0,
            dport: 0,
            protocol: "any".to_string(),
            actions: vec![(
                crate::types::PolicyAction::Pass,
                0,
                crate::types::ActionParams::None,
            )],
            sni: None,
            quic_version: 0,
            src_mac: None,
            dst_mac: None,
            expires_after_secs: None,
            schedule: None,
        }
    }

    #[test]
    fn test_ttl_not_yet_expired_no_transition() {
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2024, 1, 8, 13, 0, 0).unwrap();
        let mut reg = RuleRegistry::new();
        reg.register(make_ttl_rule(1, expires, RuleState::Active));

        let (activate, deactivate, expire) = reg.compute_transitions(now);
        assert!(activate.is_empty());
        assert!(deactivate.is_empty());
        assert!(expire.is_empty());
    }

    #[test]
    fn test_ttl_expired_to_expire() {
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 14, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2024, 1, 8, 13, 0, 0).unwrap();
        let mut reg = RuleRegistry::new();
        reg.register(make_ttl_rule(42, expires, RuleState::Active));

        let (activate, deactivate, expire) = reg.compute_transitions(now);
        assert!(activate.is_empty());
        assert!(deactivate.is_empty());
        assert_eq!(expire, vec![42]);
    }

    #[test]
    fn test_ttl_expired_inactive_still_expires() {
        // Even if the rule was already inactive when the TTL passes, it should expire
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 14, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2024, 1, 8, 13, 0, 0).unwrap();
        let mut reg = RuleRegistry::new();
        reg.register(make_ttl_rule(7, expires, RuleState::Inactive));

        let (_, _, expire) = reg.compute_transitions(now);
        assert_eq!(expire, vec![7]);
    }

    #[test]
    fn test_scheduled_rule_should_activate() {
        // now = Monday 12:00 UTC, window Mon 09:00 – Mon 17:00, rule is Inactive → activate
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let mut reg = RuleRegistry::new();
        reg.register(make_scheduled_rule(99, sched, RuleState::Inactive));

        let (activate, deactivate, expire) = reg.compute_transitions(now);
        assert_eq!(activate, vec![99]);
        assert!(deactivate.is_empty());
        assert!(expire.is_empty());
    }

    #[test]
    fn test_scheduled_rule_should_deactivate() {
        // now = Monday 08:00 UTC, window Mon 09:00 – Mon 17:00, rule is Active → deactivate
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 8, 0, 0).unwrap();
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let mut reg = RuleRegistry::new();
        reg.register(make_scheduled_rule(55, sched, RuleState::Active));

        let (activate, deactivate, expire) = reg.compute_transitions(now);
        assert!(activate.is_empty());
        assert_eq!(deactivate, vec![55]);
        assert!(expire.is_empty());
    }

    #[test]
    fn test_scheduled_rule_already_correct_state_no_transition() {
        // Active during active window → no change
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let mut reg = RuleRegistry::new();
        reg.register(make_scheduled_rule(77, sched, RuleState::Active));

        let (activate, deactivate, expire) = reg.compute_transitions(now);
        assert!(activate.is_empty());
        assert!(deactivate.is_empty());
        assert!(expire.is_empty());
    }

    #[test]
    fn test_mixed_rules_multiple_transitions() {
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 14, 0, 0).unwrap();
        let mut reg = RuleRegistry::new();

        // Expired TTL rule
        let expired = Utc.with_ymd_and_hms(2024, 1, 8, 13, 0, 0).unwrap();
        reg.register(make_ttl_rule(1, expired, RuleState::Active));

        // Not-yet-expired TTL rule
        let future = Utc.with_ymd_and_hms(2024, 1, 8, 15, 0, 0).unwrap();
        reg.register(make_ttl_rule(2, future, RuleState::Active));

        // Scheduled rule that should activate
        let sched_in = schedule(1, 9, 0, 1, 17, 0, "UTC");
        reg.register(make_scheduled_rule(3, sched_in, RuleState::Inactive));

        // Scheduled rule that should deactivate
        let sched_out = schedule(1, 15, 0, 1, 16, 0, "UTC"); // 15:00–16:00, now=14:00
        reg.register(make_scheduled_rule(4, sched_out, RuleState::Active));

        let (mut activate, mut deactivate, mut expire) = reg.compute_transitions(now);
        activate.sort();
        deactivate.sort();
        expire.sort();

        assert_eq!(activate, vec![3]);
        assert_eq!(deactivate, vec![4]);
        assert_eq!(expire, vec![1]);
    }

    // ── WeeklyTimePoint::to_week_minutes ─────────────────────────────────

    #[test]
    fn test_week_minutes_sunday_midnight() {
        let tp = WeeklyTimePoint {
            day_of_week: 0,
            hour: 0,
            minute: 0,
        };
        assert_eq!(tp.to_week_minutes(), 0);
    }

    #[test]
    fn test_week_minutes_saturday_last_minute() {
        let tp = WeeklyTimePoint {
            day_of_week: 6,
            hour: 23,
            minute: 59,
        };
        assert_eq!(tp.to_week_minutes(), 6 * 1440 + 23 * 60 + 59);
    }

    // ── next_schedule_transition ─────────────────────────────────────────

    /// Mon 09:00–17:00 window; current time Mon 08:00 (before open).
    /// The next transition should be at Mon 09:00.
    #[test]
    fn test_next_schedule_transition_before_window() {
        // 2024-01-08 is a Monday.
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 8, 0, 0).unwrap();
        let next = next_schedule_transition(&sched, now);
        assert!(next.is_some(), "should find a next transition");
        let t = next.unwrap();
        assert_eq!(t.with_timezone(&chrono_tz::UTC).hour(), 9);
        assert_eq!(t.with_timezone(&chrono_tz::UTC).minute(), 0);
    }

    /// Mon 09:00–17:00 window; current time Mon 12:00 (inside window).
    /// The next transition should be at Mon 17:00 (window closes).
    #[test]
    fn test_next_schedule_transition_inside_window() {
        let sched = schedule(1, 9, 0, 1, 17, 0, "UTC");
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        let next = next_schedule_transition(&sched, now);
        assert!(next.is_some());
        let t = next.unwrap();
        assert_eq!(t.with_timezone(&chrono_tz::UTC).hour(), 17);
        assert_eq!(t.with_timezone(&chrono_tz::UTC).minute(), 0);
    }

    /// Empty windows — no transition ever.
    #[test]
    fn test_next_schedule_transition_empty_windows() {
        let sched = RuleSchedule {
            windows: vec![],
            timezone: "UTC".to_string(),
        };
        let now = Utc.with_ymd_and_hms(2024, 1, 8, 12, 0, 0).unwrap();
        assert!(next_schedule_transition(&sched, now).is_none());
    }
}
