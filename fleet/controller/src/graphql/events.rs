// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! GraphQL types and resolver helpers for the event pipeline.
//!
//! The actual `events` / `eventAggregate` query methods live on
//! [`crate::graphql::schema::QueryRoot`]; this module owns the input/output
//! types and the translation between GraphQL inputs and
//! [`crate::event_pipeline::store::EventFilter`].

use async_graphql::{Context, Enum, InputObject, Result, SimpleObject, ID};
use chrono::{DateTime, TimeZone, Utc};
use std::sync::Arc;

use crate::{
    event_pipeline::{
        store::{AggregateBucket, EventFilter, EventStore, GroupBy, StoredEvent},
        types::Action,
    },
    rbac::Principal,
};

use super::schema::OperationResult;

#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum EventAction {
    Drop,
    Log,
}

impl EventAction {
    fn as_internal(self) -> Action {
        match self {
            EventAction::Drop => Action::Drop,
            EventAction::Log => Action::Log,
        }
    }
}

#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum EventGroupBy {
    RuleId,
    Action,
    NodeId,
    SrcIp,
    DstIp,
    Minute,
    Hour,
}

impl EventGroupBy {
    fn as_internal(self) -> GroupBy {
        match self {
            EventGroupBy::RuleId => GroupBy::RuleId,
            EventGroupBy::Action => GroupBy::Action,
            EventGroupBy::NodeId => GroupBy::NodeId,
            EventGroupBy::SrcIp => GroupBy::SrcIp,
            EventGroupBy::DstIp => GroupBy::DstIp,
            EventGroupBy::Minute => GroupBy::Minute,
            EventGroupBy::Hour => GroupBy::Hour,
        }
    }
}

#[derive(InputObject, Default)]
pub struct EventFilterInput {
    /// Earliest event time to include (inclusive).
    pub since: Option<DateTime<Utc>>,
    /// Latest event time (exclusive).
    pub until: Option<DateTime<Utc>>,
    pub action: Option<EventAction>,
    pub rule_id: Option<String>,
    pub node_id: Option<String>,
    pub sport: Option<i32>,
    pub dport: Option<i32>,
    /// Numeric IP protocol (6 = tcp, 17 = udp).
    pub proto: Option<i32>,
    /// Exact-match source IP (dotted IPv4 or IPv6 textual form).
    pub src_ip: Option<String>,
    /// Exact-match destination IP (dotted IPv4 or IPv6 textual form).
    pub dst_ip: Option<String>,
    /// SQL LIKE pattern on the SNI column.
    pub sni_like: Option<String>,
}

fn parse_ip_filter(field: &str, s: &str) -> async_graphql::Result<std::net::IpAddr> {
    s.parse()
        .map_err(|e| async_graphql::Error::new(format!("Invalid {field}: {e}")))
}

impl EventFilterInput {
    pub fn to_internal(&self, cursor: Option<i64>) -> Result<EventFilter> {
        let rule_id = self
            .rule_id
            .as_deref()
            .map(|s| s.parse::<i64>())
            .transpose()
            .map_err(|e| async_graphql::Error::new(format!("Invalid rule_id: {e}")))?;
        Ok(EventFilter {
            since_ns: self.since.map(|t| t.timestamp_nanos_opt().unwrap_or(0)),
            until_ns: self.until.map(|t| t.timestamp_nanos_opt().unwrap_or(0)),
            action: self.action.map(EventAction::as_internal),
            rule_id,
            node_id: self.node_id.clone(),
            sport: self.sport.map(|v| v as i64),
            dport: self.dport.map(|v| v as i64),
            proto: self.proto.map(|v| v as i64),
            src_ip: self
                .src_ip
                .as_deref()
                .map(|s| parse_ip_filter("src_ip", s))
                .transpose()?,
            dst_ip: self
                .dst_ip
                .as_deref()
                .map(|s| parse_ip_filter("dst_ip", s))
                .transpose()?,
            sni_like: self.sni_like.clone(),
            cursor,
        })
    }
}

#[derive(SimpleObject, Clone)]
pub struct EventOutput {
    /// Opaque numeric ID — also the pagination cursor.
    pub id: String,
    pub timestamp: DateTime<Utc>,
    /// Wall-clock time at which the controller received this event's batch.
    /// Compare with `timestamp` to detect clock skew between agent and
    /// controller.
    pub received_at: DateTime<Utc>,
    pub node_id: String,
    pub rule_id: String,
    pub action: String,
    pub verdict: String,
    pub direction: String,
    pub ifindex: i32,
    pub proto: i32,
    pub src_ip: String,
    pub dst_ip: String,
    pub sport: i32,
    pub dport: i32,
    pub pkt_len: i32,
    pub flags: Option<i32>,
    pub sni: Option<String>,
}

impl From<StoredEvent> for EventOutput {
    fn from(e: StoredEvent) -> Self {
        let verdict = Action::from_db(e.verdict)
            .map(|a| a.as_str().to_string())
            .unwrap_or_else(|| "pass".to_string());
        Self {
            id: e.id.to_string(),
            timestamp: Utc.timestamp_nanos(e.ts_ns),
            received_at: Utc.timestamp_nanos(e.received_at_ns),
            node_id: e.node_id,
            rule_id: e.rule_id.to_string(),
            action: e.action.as_str().to_string(),
            verdict,
            direction: e.direction.as_str().to_string(),
            ifindex: e.ifindex as i32,
            proto: e.proto as i32,
            src_ip: e.src_ip.to_string(),
            dst_ip: e.dst_ip.to_string(),
            sport: e.sport as i32,
            dport: e.dport as i32,
            pkt_len: e.pkt_len as i32,
            flags: e.flags.map(|v| v as i32),
            sni: e.sni,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct EventConnection {
    pub items: Vec<EventOutput>,
    /// `id` of the oldest item in this page; pass as `cursor` to fetch the
    /// next page (returns rows with smaller IDs). `None` when no more rows.
    pub next_cursor: Option<String>,
}

#[derive(SimpleObject, Clone)]
pub struct AggregateBucketOutput {
    pub key: String,
    pub count: i32,
}

impl From<AggregateBucket> for AggregateBucketOutput {
    fn from(b: AggregateBucket) -> Self {
        Self {
            key: b.key,
            count: b.count as i32,
        }
    }
}

const MAX_LIMIT: i32 = 1000;

pub async fn resolve_events(
    ctx: &Context<'_>,
    filter: Option<EventFilterInput>,
    limit: Option<i32>,
    cursor: Option<String>,
) -> Result<EventConnection> {
    let events = ctx.data::<Arc<EventStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let filter = filter.unwrap_or_default();
    let cursor_id = cursor
        .map(|c| c.parse::<i64>())
        .transpose()
        .map_err(|e| async_graphql::Error::new(format!("Invalid cursor: {e}")))?;
    let limit = limit.unwrap_or(100).clamp(1, MAX_LIMIT) as i64;
    let internal = filter.to_internal(cursor_id)?;
    let rows = events.list(principal.tenant_id, &internal, limit);
    let next_cursor = rows.last().map(|r| r.id.to_string());
    Ok(EventConnection {
        items: rows.into_iter().map(EventOutput::from).collect(),
        next_cursor,
    })
}

pub async fn resolve_event_aggregate(
    ctx: &Context<'_>,
    filter: Option<EventFilterInput>,
    group_by: EventGroupBy,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<Vec<AggregateBucketOutput>> {
    let events = ctx.data::<Arc<EventStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let mut filter = filter.unwrap_or_default();
    // Spec: `since` and `until` on the aggregate call are required and
    // override any time bounds the caller put in `filter`.
    filter.since = Some(since);
    filter.until = Some(until);
    let internal = filter.to_internal(None)?;
    let buckets = events.aggregate(principal.tenant_id, &internal, group_by.as_internal());
    Ok(buckets.into_iter().map(Into::into).collect())
}

/// Empty the tenant's in-memory event buffer, optionally scoped to one node.
/// Backs the "Clear" action on the global Events page.
pub async fn resolve_clear_events(
    ctx: &Context<'_>,
    node_id: Option<ID>,
) -> Result<OperationResult> {
    let events = ctx.data::<Arc<EventStore>>()?;
    let store = ctx.data::<Arc<dyn crate::store::ControllerStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let node_id = node_id.map(|n| n.0);
    let removed = events.clear(principal.tenant_id, node_id.as_deref());
    crate::graphql::suricata::audit(
        store,
        principal,
        "events_cleared",
        node_id,
        format!("removed={removed}"),
    )
    .await;
    Ok(OperationResult {
        success: true,
        message: Some(format!("Cleared {removed} event(s)")),
    })
}
