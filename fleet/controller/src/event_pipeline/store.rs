// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! DB accessors for the `events` table.
//!
//! All entry points take a [`TenantScope`] so multi-tenant isolation cannot
//! be forgotten at a call site.

use anyhow::{Context, Result};
use sqlx::{Row, Sqlite, Transaction};
use std::net::IpAddr;

use super::tenant::TenantScope;
use super::types::{Action, Direction, PolicyEvent};

/// One row read back from the `events` table.
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
    /// Exact-match src IP, encoded as the on-disk blob (4 or 16 bytes).
    pub src_ip: Option<Vec<u8>>,
    /// Exact-match dst IP, encoded as the on-disk blob (4 or 16 bytes).
    pub dst_ip: Option<Vec<u8>>,
    pub sni_like: Option<String>,
    /// Pagination: only rows with id < cursor (descending order).
    pub cursor: Option<i64>,
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
    /// Convert the raw SQL group key into the user-facing label. Action stays
    /// as the wire-format string (`drop`/`log`) instead of the on-disk int;
    /// IPs come back from `hex(blob)` and need to be re-parsed into addresses.
    /// Other variants pass through unchanged.
    pub fn label_key(self, raw: &str) -> String {
        match self {
            GroupBy::Action => raw
                .parse::<i64>()
                .ok()
                .and_then(Action::from_db)
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| raw.to_string()),
            GroupBy::SrcIp | GroupBy::DstIp => {
                hex_to_ip_string(raw).unwrap_or_else(|| raw.to_string())
            }
            _ => raw.to_string(),
        }
    }
}

fn hex_to_ip_string(hex: &str) -> Option<String> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    match bytes.len() {
        4 => {
            let a: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::from(a).to_string())
        }
        16 => {
            let a: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::from(a).to_string())
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct AggregateBucket {
    /// User-facing group key (rule ID, action name, dotted IP, or bucket
    /// index for `minute`/`hour`). Already labelised by [`GroupBy::label_key`]
    /// so callers can pass it through to the wire format unchanged.
    pub key: String,
    pub count: i64,
}

/// Newtype for the [`TenantScope`]-wrapped event accessors. Keeping it a
/// struct (rather than a bag of free functions) makes "you forgot the scope"
/// a compile error rather than a runtime one.
pub struct EventStore<'a> {
    scope: &'a TenantScope,
}

impl<'a> EventStore<'a> {
    pub fn new(scope: &'a TenantScope) -> Self {
        Self { scope }
    }

    /// Insert a batch of events in a single transaction. Returns the row
    /// count inserted (== `events.len()` on success).
    pub async fn insert_batch(&self, events: &[PolicyEvent]) -> Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        let mut tx: Transaction<'_, Sqlite> = self
            .scope
            .pool()
            .begin()
            .await
            .context("Failed to begin events insert tx")?;
        let tenant_id = self.scope.tenant_id();

        for ev in events {
            sqlx::query(
                r#"
                INSERT INTO events
                    (tenant_id, node_id, ts_ns, rule_id, action, verdict, direction,
                     ifindex, proto, src_ip, dst_ip, sport, dport, pkt_len, flags, sni)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(tenant_id)
            .bind(&ev.node_id)
            .bind(ev.ts_ns)
            .bind(ev.rule_id)
            .bind(ev.action as i64)
            .bind(ev.verdict)
            .bind(ev.direction as i64)
            .bind(ev.ifindex)
            .bind(ev.proto)
            .bind(ev.src_ip.as_slice())
            .bind(ev.dst_ip.as_slice())
            .bind(ev.sport)
            .bind(ev.dport)
            .bind(ev.pkt_len)
            .bind(ev.flags)
            .bind(ev.sni.as_deref())
            .execute(&mut *tx)
            .await
            .context("Failed to insert event row")?;
        }

        tx.commit().await.context("Failed to commit events batch")?;
        Ok(events.len())
    }

    /// Read events matching `filter`, newest first.
    pub async fn list(&self, filter: &EventFilter, limit: i64) -> Result<Vec<StoredEvent>> {
        let mut q = String::from(
            "SELECT id, tenant_id, node_id, ts_ns, rule_id, action, verdict, direction, \
                    ifindex, proto, src_ip, dst_ip, sport, dport, pkt_len, flags, sni \
             FROM events WHERE tenant_id = ?",
        );
        push_filter_sql(&mut q, filter);
        q.push_str(" ORDER BY id DESC LIMIT ?");

        let mut query = sqlx::query(&q).bind(self.scope.tenant_id());
        query = bind_filter(query, filter);
        let rows = query
            .bind(limit)
            .fetch_all(self.scope.pool())
            .await
            .context("Failed to list events")?;

        rows.into_iter().map(row_to_event).collect()
    }

    /// Bucket events by `group_by` between `[since_ns, until_ns)`.
    pub async fn aggregate(
        &self,
        filter: &EventFilter,
        group_by: GroupBy,
    ) -> Result<Vec<AggregateBucket>> {
        let key_expr = match group_by {
            GroupBy::RuleId => "CAST(rule_id AS TEXT)",
            GroupBy::Action => "CAST(action AS TEXT)",
            GroupBy::NodeId => "node_id",
            GroupBy::SrcIp => "hex(src_ip)",
            GroupBy::DstIp => "hex(dst_ip)",
            // ts_ns is nanoseconds since epoch; divide to seconds then bucket.
            GroupBy::Minute => "CAST(ts_ns / 60000000000 AS TEXT)",
            GroupBy::Hour => "CAST(ts_ns / 3600000000000 AS TEXT)",
        };
        let mut q = format!(
            "SELECT {key_expr} AS k, COUNT(*) AS c \
             FROM events WHERE tenant_id = ?"
        );
        push_filter_sql(&mut q, filter);
        q.push_str(" GROUP BY k ORDER BY k ASC");

        let mut query = sqlx::query(&q).bind(self.scope.tenant_id());
        query = bind_filter(query, filter);
        let rows = query
            .fetch_all(self.scope.pool())
            .await
            .context("Failed to aggregate events")?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let raw = r.try_get::<String, _>("k").unwrap_or_default();
                AggregateBucket {
                    key: group_by.label_key(&raw),
                    count: r.try_get::<i64, _>("c").unwrap_or(0),
                }
            })
            .collect())
    }

    /// Delete up to `chunk` events older than `cutoff_ns`. Returns rows
    /// affected; caller loops until the result is zero.
    pub async fn prune_older_than(&self, cutoff_ns: i64, chunk: i64) -> Result<u64> {
        // SQLite supports DELETE … LIMIT only if compiled with
        // SQLITE_ENABLE_UPDATE_DELETE_LIMIT, which the bundled sqlx feature
        // doesn't guarantee. Use the portable rowid IN (SELECT … LIMIT) form.
        let res = sqlx::query(
            "DELETE FROM events WHERE id IN ( \
                SELECT id FROM events \
                WHERE tenant_id = ? AND ts_ns < ? \
                ORDER BY id ASC LIMIT ? \
             )",
        )
        .bind(self.scope.tenant_id())
        .bind(cutoff_ns)
        .bind(chunk)
        .execute(self.scope.pool())
        .await
        .context("Failed to prune events")?;
        Ok(res.rows_affected())
    }
}

fn push_filter_sql(q: &mut String, f: &EventFilter) {
    if f.since_ns.is_some() {
        q.push_str(" AND ts_ns >= ?");
    }
    if f.until_ns.is_some() {
        q.push_str(" AND ts_ns < ?");
    }
    if f.action.is_some() {
        q.push_str(" AND action = ?");
    }
    if f.rule_id.is_some() {
        q.push_str(" AND rule_id = ?");
    }
    if f.node_id.is_some() {
        q.push_str(" AND node_id = ?");
    }
    if f.sport.is_some() {
        q.push_str(" AND sport = ?");
    }
    if f.dport.is_some() {
        q.push_str(" AND dport = ?");
    }
    if f.proto.is_some() {
        q.push_str(" AND proto = ?");
    }
    if f.src_ip.is_some() {
        q.push_str(" AND src_ip = ?");
    }
    if f.dst_ip.is_some() {
        q.push_str(" AND dst_ip = ?");
    }
    if f.sni_like.is_some() {
        q.push_str(" AND sni LIKE ?");
    }
    if f.cursor.is_some() {
        q.push_str(" AND id < ?");
    }
}

fn bind_filter<'q>(
    mut query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    f: &'q EventFilter,
) -> sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    if let Some(v) = f.since_ns {
        query = query.bind(v);
    }
    if let Some(v) = f.until_ns {
        query = query.bind(v);
    }
    if let Some(a) = f.action {
        query = query.bind(a as i64);
    }
    if let Some(v) = f.rule_id {
        query = query.bind(v);
    }
    if let Some(ref v) = f.node_id {
        query = query.bind(v.as_str());
    }
    if let Some(v) = f.sport {
        query = query.bind(v);
    }
    if let Some(v) = f.dport {
        query = query.bind(v);
    }
    if let Some(v) = f.proto {
        query = query.bind(v);
    }
    if let Some(ref v) = f.src_ip {
        query = query.bind(v.as_slice());
    }
    if let Some(ref v) = f.dst_ip {
        query = query.bind(v.as_slice());
    }
    if let Some(ref v) = f.sni_like {
        query = query.bind(v.as_str());
    }
    if let Some(v) = f.cursor {
        query = query.bind(v);
    }
    query
}

fn row_to_event(row: sqlx::sqlite::SqliteRow) -> Result<StoredEvent> {
    let src_blob: Vec<u8> = row.try_get("src_ip")?;
    let dst_blob: Vec<u8> = row.try_get("dst_ip")?;
    let action_i: i64 = row.try_get("action")?;
    let direction_i: i64 = row.try_get("direction")?;
    Ok(StoredEvent {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        node_id: row.try_get("node_id")?,
        ts_ns: row.try_get("ts_ns")?,
        rule_id: row.try_get("rule_id")?,
        action: Action::from_db(action_i)
            .ok_or_else(|| anyhow::anyhow!("Unknown action discriminator {action_i}"))?,
        verdict: row.try_get("verdict")?,
        direction: Direction::from_db(direction_i)
            .ok_or_else(|| anyhow::anyhow!("Unknown direction discriminator {direction_i}"))?,
        ifindex: row.try_get("ifindex")?,
        proto: row.try_get("proto")?,
        src_ip: blob_to_ip(&src_blob)?,
        dst_ip: blob_to_ip(&dst_blob)?,
        sport: row.try_get("sport")?,
        dport: row.try_get("dport")?,
        pkt_len: row.try_get("pkt_len")?,
        flags: row.try_get("flags").ok(),
        sni: row.try_get("sni").ok(),
    })
}

fn blob_to_ip(b: &[u8]) -> Result<IpAddr> {
    match b.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Ok(IpAddr::from(a))
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Ok(IpAddr::from(a))
        }
        n => Err(anyhow::anyhow!("Unexpected IP blob length: {n}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::tenant::bootstrap_default_tenant;
    use sqlx::sqlite::SqlitePool;

    async fn scope() -> TenantScope {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        bootstrap_default_tenant(pool).await.unwrap()
    }

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

    #[tokio::test]
    async fn insert_then_list_round_trips() {
        let scope = scope().await;
        let store = EventStore::new(&scope);
        let n = store
            .insert_batch(&[evt(1000, Action::Drop), evt(2000, Action::Log)])
            .await
            .unwrap();
        assert_eq!(n, 2);
        let rows = store.list(&EventFilter::default(), 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        // Newest first.
        assert_eq!(rows[0].ts_ns, 2000);
    }

    #[tokio::test]
    async fn list_filters_by_action() {
        let scope = scope().await;
        let store = EventStore::new(&scope);
        store
            .insert_batch(&[evt(1, Action::Drop), evt(2, Action::Log)])
            .await
            .unwrap();
        let drops = store
            .list(
                &EventFilter {
                    action: Some(Action::Drop),
                    ..Default::default()
                },
                10,
            )
            .await
            .unwrap();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].action, Action::Drop);
    }

    #[tokio::test]
    async fn list_filters_by_src_and_dst_ip() {
        let scope = scope().await;
        let store = EventStore::new(&scope);
        let mut e_other = evt(1, Action::Drop);
        e_other.src_ip = vec![192, 168, 1, 1];
        e_other.dst_ip = vec![192, 168, 1, 2];
        store
            .insert_batch(&[evt(2, Action::Drop), e_other])
            .await
            .unwrap();

        let by_src = store
            .list(
                &EventFilter {
                    src_ip: Some(vec![10, 0, 0, 1]),
                    ..Default::default()
                },
                10,
            )
            .await
            .unwrap();
        assert_eq!(by_src.len(), 1);
        assert_eq!(by_src[0].src_ip.to_string(), "10.0.0.1");

        let by_dst = store
            .list(
                &EventFilter {
                    dst_ip: Some(vec![192, 168, 1, 2]),
                    ..Default::default()
                },
                10,
            )
            .await
            .unwrap();
        assert_eq!(by_dst.len(), 1);
        assert_eq!(by_dst[0].dst_ip.to_string(), "192.168.1.2");
    }

    #[tokio::test]
    async fn aggregate_by_action_buckets() {
        let scope = scope().await;
        let store = EventStore::new(&scope);
        store
            .insert_batch(&[
                evt(1, Action::Drop),
                evt(2, Action::Drop),
                evt(3, Action::Log),
            ])
            .await
            .unwrap();
        let buckets = store
            .aggregate(&EventFilter::default(), GroupBy::Action)
            .await
            .unwrap();
        let map: std::collections::HashMap<_, _> =
            buckets.into_iter().map(|b| (b.key, b.count)).collect();
        assert_eq!(map.get("drop").copied(), Some(2));
        assert_eq!(map.get("log").copied(), Some(1));
    }

    #[tokio::test]
    async fn aggregate_by_src_ip_returns_dotted_string() {
        let scope = scope().await;
        let store = EventStore::new(&scope);
        store
            .insert_batch(&[evt(1, Action::Drop), evt(2, Action::Drop)])
            .await
            .unwrap();
        let buckets = store
            .aggregate(&EventFilter::default(), GroupBy::SrcIp)
            .await
            .unwrap();
        // evt() in this test module always uses 10.0.0.1 as the source.
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].key, "10.0.0.1");
        assert_eq!(buckets[0].count, 2);
    }

    #[test]
    fn label_key_passthrough_and_conversions() {
        assert_eq!(GroupBy::RuleId.label_key("42"), "42");
        assert_eq!(GroupBy::NodeId.label_key("n1"), "n1");
        assert_eq!(GroupBy::Minute.label_key("28333333"), "28333333");
        assert_eq!(GroupBy::Action.label_key("1"), "drop");
        assert_eq!(GroupBy::Action.label_key("2"), "log");
        // Unknown action code stays as-is rather than blowing up.
        assert_eq!(GroupBy::Action.label_key("99"), "99");
        assert_eq!(GroupBy::SrcIp.label_key("0A000001"), "10.0.0.1");
        // Malformed hex falls through unchanged.
        assert_eq!(GroupBy::SrcIp.label_key("notahex"), "notahex");
    }

    #[tokio::test]
    async fn prune_deletes_old_rows() {
        let scope = scope().await;
        let store = EventStore::new(&scope);
        store
            .insert_batch(&[evt(100, Action::Drop), evt(200, Action::Drop)])
            .await
            .unwrap();
        let removed = store.prune_older_than(150, 100).await.unwrap();
        assert_eq!(removed, 1);
        let remaining = store.list(&EventFilter::default(), 10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].ts_ns, 200);
    }
}
