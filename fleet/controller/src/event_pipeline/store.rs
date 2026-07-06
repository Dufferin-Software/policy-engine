// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! In-memory, per-tenant policy-event buffer.
//!
//! Policy match events are deliberately NOT persisted: they are operational
//! telemetry, not audit data. Each tenant gets a bounded ring buffer — the
//! oldest events are evicted once [`EventStore::capacity`] is reached, and
//! everything is gone on controller restart. The GraphQL `events` /
//! `eventAggregate` queries and the Grafana REST projections all read from
//! this buffer, so their filter/pagination semantics match the old
//! SQLite-backed store.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

use super::types::{Action, Direction, PolicyEvent};

/// Default per-tenant buffer capacity. At roughly 150 bytes per event this
/// bounds the controller to a few tens of MB per tenant worst-case.
pub const DEFAULT_EVENT_CAPACITY: usize = 100_000;

/// One buffered event.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub id: i64,
    pub tenant_id: i64,
    pub node_id: String,
    pub ts_ns: i64,
    pub rule_id: i64,
    pub action: Action,
    pub verdict: i64,
    pub direction: Direction,
    pub ifindex: i64,
    pub proto: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub sport: i64,
    pub dport: i64,
    pub pkt_len: i64,
    pub flags: Option<i64>,
    pub sni: Option<String>,
}

/// Filter for [`EventStore::list`] / [`EventStore::aggregate`]. Optional
/// fields are ANDed. Empty filter matches everything in the tenant.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
    pub action: Option<Action>,
    pub rule_id: Option<i64>,
    pub node_id: Option<String>,
    pub sport: Option<i64>,
    pub dport: Option<i64>,
    pub proto: Option<i64>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    /// SQL-LIKE pattern (`%`/`_` wildcards, case-insensitive) on the SNI.
    pub sni_like: Option<String>,
    /// Pagination: only rows with id < cursor (descending order).
    pub cursor: Option<i64>,
}

impl EventFilter {
    fn matches(&self, e: &StoredEvent) -> bool {
        if let Some(v) = self.since_ns {
            if e.ts_ns < v {
                return false;
            }
        }
        if let Some(v) = self.until_ns {
            if e.ts_ns >= v {
                return false;
            }
        }
        if let Some(a) = self.action {
            if e.action != a {
                return false;
            }
        }
        if let Some(v) = self.rule_id {
            if e.rule_id != v {
                return false;
            }
        }
        if let Some(ref v) = self.node_id {
            if e.node_id != *v {
                return false;
            }
        }
        if let Some(v) = self.sport {
            if e.sport != v {
                return false;
            }
        }
        if let Some(v) = self.dport {
            if e.dport != v {
                return false;
            }
        }
        if let Some(v) = self.proto {
            if e.proto != v {
                return false;
            }
        }
        if let Some(v) = self.src_ip {
            if e.src_ip != v {
                return false;
            }
        }
        if let Some(v) = self.dst_ip {
            if e.dst_ip != v {
                return false;
            }
        }
        if let Some(ref pat) = self.sni_like {
            match e.sni.as_deref() {
                Some(sni) => {
                    if !like_match(pat, sni) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if let Some(c) = self.cursor {
            if e.id >= c {
                return false;
            }
        }
        true
    }
}

/// Case-insensitive SQL LIKE: `%` matches any run, `_` any single char.
/// Greedy match with backtracking on the last `%`.
fn like_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '_' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '%' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '%' {
        pi += 1;
    }
    pi == p.len()
}

/// Grouping axis for [`EventStore::aggregate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    RuleId,
    Action,
    NodeId,
    SrcIp,
    DstIp,
    Minute,
    Hour,
}

impl GroupBy {
    fn key(self, e: &StoredEvent) -> String {
        match self {
            GroupBy::RuleId => e.rule_id.to_string(),
            GroupBy::Action => e.action.as_str().to_string(),
            GroupBy::NodeId => e.node_id.clone(),
            GroupBy::SrcIp => e.src_ip.to_string(),
            GroupBy::DstIp => e.dst_ip.to_string(),
            // ts_ns is nanoseconds since epoch; bucket index in that unit.
            GroupBy::Minute => (e.ts_ns / 60_000_000_000).to_string(),
            GroupBy::Hour => (e.ts_ns / 3_600_000_000_000).to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AggregateBucket {
    /// User-facing group key (rule ID, action name, dotted IP, or bucket
    /// index for `minute`/`hour`).
    pub key: String,
    pub count: i64,
}

/// Counters returned by [`EventStore::insert_batch`].
#[derive(Debug, Clone, Copy, Default)]
pub struct InsertStats {
    pub inserted: usize,
    /// Oldest events evicted to stay within capacity.
    pub evicted: usize,
}

#[derive(Default)]
struct TenantBuf {
    next_id: i64,
    buf: VecDeque<StoredEvent>,
}

/// Process-wide event buffer, shared via `Arc`. All methods take the caller's
/// tenant id explicitly so multi-tenant isolation cannot be forgotten at a
/// call site.
pub struct EventStore {
    tenants: Mutex<HashMap<i64, TenantBuf>>,
    capacity: usize,
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_EVENT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tenants: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Append a batch of parsed events. Events with malformed IP payloads
    /// are skipped (they should never survive [`super::types::parse_policy_event`]).
    pub fn insert_batch(&self, tenant_id: i64, events: &[PolicyEvent]) -> InsertStats {
        let mut stats = InsertStats::default();
        if events.is_empty() {
            return stats;
        }
        let mut tenants = self.tenants.lock().unwrap();
        let t = tenants.entry(tenant_id).or_default();
        for ev in events {
            let (Some(src_ip), Some(dst_ip)) = (blob_to_ip(&ev.src_ip), blob_to_ip(&ev.dst_ip))
            else {
                continue;
            };
            t.next_id += 1;
            t.buf.push_back(StoredEvent {
                id: t.next_id,
                tenant_id,
                node_id: ev.node_id.clone(),
                ts_ns: ev.ts_ns,
                rule_id: ev.rule_id,
                action: ev.action,
                verdict: ev.verdict,
                direction: ev.direction,
                ifindex: ev.ifindex,
                proto: ev.proto,
                src_ip,
                dst_ip,
                sport: ev.sport,
                dport: ev.dport,
                pkt_len: ev.pkt_len,
                flags: ev.flags,
                sni: ev.sni.clone(),
            });
            stats.inserted += 1;
            if t.buf.len() > self.capacity {
                t.buf.pop_front();
                stats.evicted += 1;
            }
        }
        stats
    }

    /// Events matching `filter`, newest first (descending id).
    pub fn list(&self, tenant_id: i64, filter: &EventFilter, limit: i64) -> Vec<StoredEvent> {
        let limit = limit.max(0) as usize;
        let tenants = self.tenants.lock().unwrap();
        let Some(t) = tenants.get(&tenant_id) else {
            return Vec::new();
        };
        t.buf
            .iter()
            .rev()
            .filter(|e| filter.matches(e))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Bucket events matching `filter` by `group_by`, keys ascending.
    pub fn aggregate(
        &self,
        tenant_id: i64,
        filter: &EventFilter,
        group_by: GroupBy,
    ) -> Vec<AggregateBucket> {
        let tenants = self.tenants.lock().unwrap();
        let Some(t) = tenants.get(&tenant_id) else {
            return Vec::new();
        };
        let mut counts: std::collections::BTreeMap<String, i64> = Default::default();
        for e in t.buf.iter().filter(|e| filter.matches(e)) {
            *counts.entry(group_by.key(e)).or_insert(0) += 1;
        }
        counts
            .into_iter()
            .map(|(key, count)| AggregateBucket { key, count })
            .collect()
    }

    /// Drop events older than `cutoff_ns`. Returns the number removed.
    pub fn prune_older_than(&self, tenant_id: i64, cutoff_ns: i64) -> u64 {
        let mut tenants = self.tenants.lock().unwrap();
        let Some(t) = tenants.get_mut(&tenant_id) else {
            return 0;
        };
        let before = t.buf.len();
        t.buf.retain(|e| e.ts_ns >= cutoff_ns);
        (before - t.buf.len()) as u64
    }

    /// Empty the tenant's buffer, optionally only events from one node.
    /// Returns the number removed.
    pub fn clear(&self, tenant_id: i64, node_id: Option<&str>) -> u64 {
        let mut tenants = self.tenants.lock().unwrap();
        let Some(t) = tenants.get_mut(&tenant_id) else {
            return 0;
        };
        let before = t.buf.len();
        match node_id {
            Some(n) => t.buf.retain(|e| e.node_id != n),
            None => t.buf.clear(),
        }
        (before - t.buf.len()) as u64
    }
}

fn blob_to_ip(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Some(IpAddr::from(a))
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(IpAddr::from(a))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: i64 = 1;

    fn evt(ts_ns: i64, action: Action) -> PolicyEvent {
        PolicyEvent {
            ts_ns,
            node_id: "n1".into(),
            rule_id: 42,
            action,
            verdict: action as i64,
            direction: Direction::Ingress,
            ifindex: 3,
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

    #[test]
    fn insert_then_list_round_trips() {
        let store = EventStore::new();
        let stats = store.insert_batch(TENANT, &[evt(1000, Action::Drop), evt(2000, Action::Log)]);
        assert_eq!(stats.inserted, 2);
        assert_eq!(stats.evicted, 0);
        let rows = store.list(TENANT, &EventFilter::default(), 10);
        assert_eq!(rows.len(), 2);
        // Newest first.
        assert_eq!(rows[0].ts_ns, 2000);
    }

    #[test]
    fn list_filters_by_action() {
        let store = EventStore::new();
        store.insert_batch(TENANT, &[evt(1, Action::Drop), evt(2, Action::Log)]);
        let drops = store.list(
            TENANT,
            &EventFilter {
                action: Some(Action::Drop),
                ..Default::default()
            },
            10,
        );
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].action, Action::Drop);
    }

    #[test]
    fn list_filters_by_src_and_dst_ip() {
        let store = EventStore::new();
        let mut e_other = evt(1, Action::Drop);
        e_other.src_ip = vec![192, 168, 1, 1];
        e_other.dst_ip = vec![192, 168, 1, 2];
        store.insert_batch(TENANT, &[evt(2, Action::Drop), e_other]);

        let by_src = store.list(
            TENANT,
            &EventFilter {
                src_ip: Some("10.0.0.1".parse().unwrap()),
                ..Default::default()
            },
            10,
        );
        assert_eq!(by_src.len(), 1);
        assert_eq!(by_src[0].src_ip.to_string(), "10.0.0.1");

        let by_dst = store.list(
            TENANT,
            &EventFilter {
                dst_ip: Some("192.168.1.2".parse().unwrap()),
                ..Default::default()
            },
            10,
        );
        assert_eq!(by_dst.len(), 1);
        assert_eq!(by_dst[0].dst_ip.to_string(), "192.168.1.2");
    }

    #[test]
    fn cursor_paginates_descending() {
        let store = EventStore::new();
        store.insert_batch(
            TENANT,
            &[
                evt(1, Action::Drop),
                evt(2, Action::Drop),
                evt(3, Action::Drop),
            ],
        );
        let page1 = store.list(TENANT, &EventFilter::default(), 2);
        assert_eq!(page1.len(), 2);
        let cursor = page1.last().unwrap().id;
        let page2 = store.list(
            TENANT,
            &EventFilter {
                cursor: Some(cursor),
                ..Default::default()
            },
            2,
        );
        assert_eq!(page2.len(), 1);
        assert!(page2[0].id < cursor);
    }

    #[test]
    fn aggregate_by_action_buckets() {
        let store = EventStore::new();
        store.insert_batch(
            TENANT,
            &[
                evt(1, Action::Drop),
                evt(2, Action::Drop),
                evt(3, Action::Log),
            ],
        );
        let buckets = store.aggregate(TENANT, &EventFilter::default(), GroupBy::Action);
        let map: HashMap<_, _> = buckets.into_iter().map(|b| (b.key, b.count)).collect();
        assert_eq!(map.get("drop").copied(), Some(2));
        assert_eq!(map.get("log").copied(), Some(1));
    }

    #[test]
    fn aggregate_by_src_ip_returns_dotted_string() {
        let store = EventStore::new();
        store.insert_batch(TENANT, &[evt(1, Action::Drop), evt(2, Action::Drop)]);
        let buckets = store.aggregate(TENANT, &EventFilter::default(), GroupBy::SrcIp);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].key, "10.0.0.1");
        assert_eq!(buckets[0].count, 2);
    }

    #[test]
    fn aggregate_by_minute_buckets_by_index() {
        let store = EventStore::new();
        // Two events in minute 1, one in minute 2.
        store.insert_batch(
            TENANT,
            &[
                evt(60_000_000_000, Action::Drop),
                evt(61_000_000_000, Action::Drop),
                evt(120_000_000_000, Action::Drop),
            ],
        );
        let buckets = store.aggregate(TENANT, &EventFilter::default(), GroupBy::Minute);
        assert_eq!(buckets.len(), 2);
        assert_eq!((buckets[0].key.as_str(), buckets[0].count), ("1", 2));
        assert_eq!((buckets[1].key.as_str(), buckets[1].count), ("2", 1));
    }

    #[test]
    fn capacity_evicts_oldest() {
        let store = EventStore::with_capacity(2);
        let stats = store.insert_batch(
            TENANT,
            &[
                evt(1, Action::Drop),
                evt(2, Action::Drop),
                evt(3, Action::Drop),
            ],
        );
        assert_eq!(stats.inserted, 3);
        assert_eq!(stats.evicted, 1);
        let rows = store.list(TENANT, &EventFilter::default(), 10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].ts_ns, 3);
        assert_eq!(rows[1].ts_ns, 2);
    }

    #[test]
    fn prune_deletes_old_rows() {
        let store = EventStore::new();
        store.insert_batch(TENANT, &[evt(100, Action::Drop), evt(200, Action::Drop)]);
        let removed = store.prune_older_than(TENANT, 150);
        assert_eq!(removed, 1);
        let remaining = store.list(TENANT, &EventFilter::default(), 10);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].ts_ns, 200);
    }

    #[test]
    fn clear_empties_tenant_buffer() {
        let store = EventStore::new();
        store.insert_batch(TENANT, &[evt(1, Action::Drop), evt(2, Action::Drop)]);
        store.insert_batch(2, &[evt(3, Action::Drop)]);
        assert_eq!(store.clear(TENANT, None), 2);
        assert!(store.list(TENANT, &EventFilter::default(), 10).is_empty());
        // Other tenants untouched.
        assert_eq!(store.list(2, &EventFilter::default(), 10).len(), 1);
    }

    #[test]
    fn clear_scoped_to_node() {
        let store = EventStore::new();
        let mut e2 = evt(2, Action::Drop);
        e2.node_id = "n2".into();
        store.insert_batch(TENANT, &[evt(1, Action::Drop), e2]);
        assert_eq!(store.clear(TENANT, Some("n1")), 1);
        let rows = store.list(TENANT, &EventFilter::default(), 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].node_id, "n2");
    }

    #[test]
    fn tenants_are_isolated() {
        let store = EventStore::new();
        store.insert_batch(1, &[evt(1, Action::Drop)]);
        store.insert_batch(2, &[evt(2, Action::Drop), evt(3, Action::Drop)]);
        assert_eq!(store.list(1, &EventFilter::default(), 10).len(), 1);
        assert_eq!(store.list(2, &EventFilter::default(), 10).len(), 2);
    }

    #[test]
    fn sni_like_matches_sql_semantics() {
        let store = EventStore::new();
        let mut e = evt(1, Action::Drop);
        e.sni = Some("www.Example.com".into());
        let mut e2 = evt(2, Action::Drop);
        e2.sni = Some("api.other.net".into());
        store.insert_batch(TENANT, &[e, e2]);

        let f = |pat: &str| EventFilter {
            sni_like: Some(pat.to_string()),
            ..Default::default()
        };
        assert_eq!(store.list(TENANT, &f("%example.com"), 10).len(), 1);
        assert_eq!(store.list(TENANT, &f("www.%"), 10).len(), 1);
        assert_eq!(store.list(TENANT, &f("%.com"), 10).len(), 1);
        assert_eq!(store.list(TENANT, &f("api.other.ne_"), 10).len(), 1);
        assert_eq!(store.list(TENANT, &f("%nomatch%"), 10).len(), 0);
        // No-SNI events never match a LIKE filter.
        store.insert_batch(TENANT, &[evt(3, Action::Drop)]);
        assert_eq!(store.list(TENANT, &f("%"), 10).len(), 2);
    }

    #[test]
    fn like_match_edge_cases() {
        assert!(like_match("%", ""));
        assert!(like_match("", ""));
        assert!(!like_match("", "a"));
        assert!(like_match("a%b%c", "aXXbYYc"));
        assert!(!like_match("a%b%c", "aXXbYY"));
        assert!(like_match("_", "x"));
        assert!(!like_match("_", ""));
    }
}
