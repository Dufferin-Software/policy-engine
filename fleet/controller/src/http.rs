// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use actix_cors::Cors;
use actix_files::Files;
use actix_web::{
    dev::Server,
    middleware::{from_fn, Logger},
    web::{self, Data, Query},
    App, HttpMessage, HttpRequest, HttpResponse, HttpServer,
};
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::broadcast;

use crate::{
    api_tokens::ApiTokenStore,
    auth::{bearer_auth, BearerAuthState},
    event_bus::EventBus,
    event_pipeline::{
        alert_store::{AlertStore, HistoryFilter},
        store::{EventFilter, EventStore, GroupBy},
        types::{Action, Direction},
        EventPipelineMetrics, TenantScope,
    },
    graphql::ControllerSchema,
    metrics_store::MetricsStore,
    operators::{OperatorStore, SESSION_TTL_S},
    rbac::{Principal, RbacStore},
    rule_lifecycle_bus::RuleLifecycleBus,
    session::NodeSessionManager,
    store::ControllerStore,
};

// ── GraphQL handlers ──────────────────────────────────────────────────────────

async fn graphql_handler(
    http_req: HttpRequest,
    schema: Data<ControllerSchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    // Lift the Principal that bearer_auth attached to the actix request and
    // inject it as per-request data so resolver guards (rbac::Require) and
    // the resolvers themselves can read it via ctx.data::<Arc<Principal>>().
    let mut inner = req.into_inner();
    if let Some(principal) = http_req.extensions().get::<Arc<Principal>>().cloned() {
        inner = inner.data(principal);
    }
    schema.execute(inner).await.into()
}

async fn graphql_playground(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(playground_source(GraphQLPlaygroundConfig::new("/graphql")))
}

async fn health(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

// ── WebSocket event stream ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EventsQuery {
    /// If present, only forward events from this node ID.
    node: Option<String>,
    /// Bearer token. Browsers can't set custom headers on a WebSocket
    /// connect, so the token rides in the query string. Header-based auth
    /// (as on `/graphql` and REST) would be preferable; the WS spec doesn't
    /// allow it.
    token: Option<String>,
}

/// Validate a `?token=…` against the same `ApiTokenStore` used by the
/// `Authorization: Bearer …` middleware. Returns the unauthorized response
/// to send back when validation fails.
async fn authorize_ws_token(
    bearer_state: &BearerAuthState,
    token: Option<&str>,
) -> std::result::Result<(), HttpResponse> {
    let Some(t) = token.filter(|s| !s.is_empty()) else {
        return Err(
            HttpResponse::Unauthorized().json(serde_json::json!({"error": "missing token"}))
        );
    };
    match bearer_state.store.authenticate(t).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            Err(HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid token"})))
        }
        Err(err) => {
            log::error!("ws bearer auth DB error: {err:#}");
            Err(HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "auth backend error"})))
        }
    }
}

/// WebSocket handler that streams BPF events to clients.
///
/// Subscribes to the `EventBus` and forwards each `TaggedEventBatch` to the
/// connected WebSocket client as individual text frames (one per JSON event).
/// An optional `?node=<id>` query parameter filters to a single node.
async fn ws_events_handler(
    req: HttpRequest,
    body: web::Payload,
    event_bus: Data<Arc<EventBus>>,
    bearer_auth: Data<BearerAuthState>,
    query: Query<EventsQuery>,
) -> actix_web::Result<HttpResponse> {
    let q = query.into_inner();
    if let Err(resp) = authorize_ws_token(&bearer_auth, q.token.as_deref()).await {
        return Ok(resp);
    }
    let (response, mut session, _msg_stream) = actix_ws::handle(&req, body)?;

    let node_filter = q.node;
    let mut rx = event_bus.subscribe();
    let mut shutdown = event_bus.subscribe_shutdown();

    actix_web::rt::spawn(async move {
        loop {
            let recv = tokio::select! {
                _ = shutdown.changed() => {
                    // Send a Close frame so clients see an orderly shutdown
                    // rather than a TCP RST.
                    let _ = session.close(Some(actix_ws::CloseReason {
                        code: actix_ws::CloseCode::Away,
                        description: Some("server shutting down".into()),
                    }))
                    .await;
                    return;
                }
                recv = rx.recv() => recv,
            };
            match recv {
                Ok(batch) => {
                    // Apply node filter if set.
                    if let Some(ref nid) = node_filter {
                        if &batch.node_id != nid {
                            continue;
                        }
                    }
                    // Send each JSON event as a separate text frame. The
                    // agent-emitted JSON does not carry node_id (each agent
                    // only sends its own events); inject it here so live-tail
                    // consumers — especially the global Events view that
                    // aggregates across nodes — can attribute rows back to a
                    // node. Fall back to raw bytes if the JSON isn't parseable.
                    for event_bytes in &batch.events_json {
                        let text = match std::str::from_utf8(event_bytes) {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        let with_node = match serde_json::from_str::<serde_json::Value>(text) {
                            Ok(serde_json::Value::Object(mut map)) => {
                                map.insert(
                                    "node_id".to_string(),
                                    serde_json::Value::String(batch.node_id.clone()),
                                );
                                serde_json::to_string(&serde_json::Value::Object(map))
                                    .unwrap_or_else(|_| text.to_string())
                            }
                            _ => text.to_string(),
                        };
                        if session.text(with_node).await.is_err() {
                            return; // client disconnected
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("WebSocket event subscriber lagged, dropped {} messages", n);
                }
            }
        }
    });

    Ok(response)
}

// ── WebSocket rule lifecycle event stream ─────────────────────────────────────

/// WebSocket handler that streams controller-side rule lifecycle events.
///
/// An optional `?node=<id>` query parameter filters events to a single node.
async fn ws_rule_events_handler(
    req: HttpRequest,
    body: web::Payload,
    rule_lifecycle_bus: Data<Arc<RuleLifecycleBus>>,
    event_bus: Data<Arc<EventBus>>,
    bearer_auth: Data<BearerAuthState>,
    query: Query<EventsQuery>,
) -> actix_web::Result<HttpResponse> {
    let q = query.into_inner();
    if let Err(resp) = authorize_ws_token(&bearer_auth, q.token.as_deref()).await {
        return Ok(resp);
    }
    let (response, mut session, _msg_stream) = actix_ws::handle(&req, body)?;

    let node_filter = q.node;
    let mut rx = rule_lifecycle_bus.subscribe();
    let mut shutdown = event_bus.subscribe_shutdown();

    actix_web::rt::spawn(async move {
        loop {
            let recv = tokio::select! {
                _ = shutdown.changed() => {
                    // Send a Close frame so clients see an orderly shutdown
                    // rather than a TCP RST.
                    let _ = session.close(Some(actix_ws::CloseReason {
                        code: actix_ws::CloseCode::Away,
                        description: Some("server shutting down".into()),
                    }))
                    .await;
                    return;
                }
                recv = rx.recv() => recv,
            };
            match recv {
                Ok(event) => {
                    if let Some(ref nid) = node_filter {
                        if &event.node_id != nid {
                            continue;
                        }
                    }
                    if let Ok(json) = serde_json::to_string(&event) {
                        if session.text(json).await.is_err() {
                            return;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!(
                        "Rule lifecycle WebSocket subscriber lagged, dropped {} messages",
                        n
                    );
                }
            }
        }
    });

    Ok(response)
}

// ── WebSocket Suricata alert stream ───────────────────────────────────────────

/// WebSocket handler that streams Suricata EVE alerts to operator clients.
///
/// Subscribes to the alert channel of the `EventBus` and forwards each alert
/// as a text frame, annotated with its `node_id`. An optional `?node=<id>`
/// filters to a single node. Same auth/shutdown handling as `/ws/events`.
async fn ws_alerts_handler(
    req: HttpRequest,
    body: web::Payload,
    event_bus: Data<Arc<EventBus>>,
    bearer_auth: Data<BearerAuthState>,
    query: Query<EventsQuery>,
) -> actix_web::Result<HttpResponse> {
    let q = query.into_inner();
    if let Err(resp) = authorize_ws_token(&bearer_auth, q.token.as_deref()).await {
        return Ok(resp);
    }
    let (response, mut session, _msg_stream) = actix_ws::handle(&req, body)?;

    let node_filter = q.node;
    let mut rx = event_bus.subscribe_suricata_alerts();
    let mut shutdown = event_bus.subscribe_shutdown();

    actix_web::rt::spawn(async move {
        loop {
            let recv = tokio::select! {
                _ = shutdown.changed() => {
                    let _ = session.close(Some(actix_ws::CloseReason {
                        code: actix_ws::CloseCode::Away,
                        description: Some("server shutting down".into()),
                    }))
                    .await;
                    return;
                }
                recv = rx.recv() => recv,
            };
            match recv {
                Ok(batch) => {
                    if let Some(ref nid) = node_filter {
                        if &batch.node_id != nid {
                            continue;
                        }
                    }
                    // Annotate each alert with its node_id (the engine's JSON
                    // carries none — each agent only forwards its own alerts).
                    for alert_bytes in &batch.alerts_json {
                        let text = match std::str::from_utf8(alert_bytes) {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        let with_node = match serde_json::from_str::<serde_json::Value>(text) {
                            Ok(serde_json::Value::Object(mut map)) => {
                                map.insert(
                                    "node_id".to_string(),
                                    serde_json::Value::String(batch.node_id.clone()),
                                );
                                serde_json::to_string(&serde_json::Value::Object(map))
                                    .unwrap_or_else(|_| text.to_string())
                            }
                            _ => text.to_string(),
                        };
                        if session.text(with_node).await.is_err() {
                            return;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("WebSocket alert subscriber lagged, dropped {} messages", n);
                }
            }
        }
    });

    Ok(response)
}

// ── Prometheus metrics endpoints ──────────────────────────────────────────────

/// Serve the most-recent Prometheus metrics for one node.
///
/// Each metric line is rewritten to include a `node_id="<id>"` label so that
/// a Prometheus server scraping this endpoint can distinguish per-node series.
async fn metrics_node_handler(
    path: web::Path<String>,
    metrics_store: Data<Arc<MetricsStore>>,
) -> HttpResponse {
    let node_id = path.into_inner();
    match metrics_store.get(&node_id) {
        Some(bytes) => {
            let raw = std::str::from_utf8(&bytes).unwrap_or("");
            let hostname = metrics_store.get_hostname(&node_id);
            let labeled =
                crate::metrics_parser::inject_node_label(raw, &node_id, hostname.as_deref());
            HttpResponse::Ok()
                .content_type("text/plain; version=0.0.4; charset=utf-8")
                .body(labeled)
        }
        None => HttpResponse::NotFound().body(format!("No metrics stored for node '{}'", node_id)),
    }
}

/// Serve the most-recent Prometheus metrics for ALL nodes, concatenated, plus
/// controller-native fleet metrics.
///
/// Each node's block is preceded by a `# node: <id>` comment header and every
/// metric line carries a `node_id="<id>"` label, so a single Prometheus scrape
/// of this endpoint yields properly-labelled multi-node series.  After the
/// forwarded engine metrics, a `fleet_*` block is appended with state that only
/// the controller knows: online/offline status, rule counts, cert expiry, etc.
async fn metrics_all_handler(
    metrics_store: Data<Arc<MetricsStore>>,
    store: Data<Arc<dyn ControllerStore>>,
    sessions: Data<Arc<NodeSessionManager>>,
    tenant_scope: Data<Arc<TenantScope>>,
    event_metrics: Data<Arc<EventPipelineMetrics>>,
    alert_metrics: Data<Arc<crate::event_pipeline::alert_metrics::AlertPipelineMetrics>>,
) -> HttpResponse {
    let mut all_text = String::new();
    let mut node_ids = metrics_store.all_node_ids();
    node_ids.sort(); // deterministic order

    for node_id in node_ids {
        if let Some(bytes) = metrics_store.get(&node_id) {
            all_text.push_str(&format!("# node: {}\n", node_id));
            let hostname = metrics_store.get_hostname(&node_id);
            match std::str::from_utf8(&bytes) {
                Ok(s) => all_text.push_str(&crate::metrics_parser::inject_node_label(
                    s,
                    &node_id,
                    hostname.as_deref(),
                )),
                Err(_) => all_text.push_str("# (non-UTF-8 metrics, skipped)\n"),
            }
            all_text.push('\n');
        }
    }

    // Append controller-native fleet metrics.
    let fleet_text = crate::controller_metrics::render(&store, &sessions).await;
    if !fleet_text.is_empty() {
        all_text.push_str("# controller fleet metrics\n");
        all_text.push_str(&fleet_text);
    }

    // Event pipeline counters.
    all_text.push_str("\n# event pipeline metrics\n");
    all_text.push_str(&event_metrics.render(tenant_scope.slug()));

    // Alert pipeline counters.
    all_text.push_str("\n# alert pipeline metrics\n");
    all_text.push_str(&alert_metrics.render(tenant_scope.slug()));

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(all_text)
}

// ── REST: events (Grafana Infinity + ad-hoc scripting) ───────────────────────

#[derive(Deserialize)]
struct EventsRestQuery {
    /// RFC3339 inclusive lower bound.
    since: Option<String>,
    /// RFC3339 exclusive upper bound.
    until: Option<String>,
    action: Option<String>,
    rule_id: Option<i64>,
    node_id: Option<String>,
    sport: Option<i64>,
    dport: Option<i64>,
    /// Numeric IP protocol number (6 = tcp, 17 = udp).
    proto: Option<i64>,
    /// SQL LIKE pattern.
    sni_like: Option<String>,
    limit: Option<i64>,
    cursor: Option<i64>,
    /// `table` (default) or `logs`. `logs` returns a JSON array of objects
    /// suitable for Grafana's "Logs" panel.
    format: Option<String>,
}

fn parse_rfc3339_ns(s: &str) -> std::result::Result<i64, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|e| format!("Invalid timestamp '{s}': {e}"))
        .and_then(|t| {
            t.with_timezone(&chrono::Utc)
                .timestamp_nanos_opt()
                .ok_or_else(|| format!("Timestamp out of range: {s}"))
        })
}

fn parse_action(s: &str) -> std::result::Result<Action, String> {
    Action::from_wire(s).ok_or_else(|| format!("Unknown action '{s}' (expected drop|log)"))
}

fn build_filter(q: &EventsRestQuery) -> std::result::Result<EventFilter, String> {
    Ok(EventFilter {
        since_ns: q.since.as_deref().map(parse_rfc3339_ns).transpose()?,
        until_ns: q.until.as_deref().map(parse_rfc3339_ns).transpose()?,
        action: q.action.as_deref().map(parse_action).transpose()?,
        rule_id: q.rule_id,
        node_id: q.node_id.clone(),
        sport: q.sport,
        dport: q.dport,
        proto: q.proto,
        src_ip: None,
        dst_ip: None,
        sni_like: q.sni_like.clone(),
        cursor: q.cursor,
    })
}

async fn rest_events_handler(
    tenant_scope: Data<Arc<TenantScope>>,
    query: Query<EventsRestQuery>,
) -> HttpResponse {
    let q = query.into_inner();
    let filter = match build_filter(&q) {
        Ok(f) => f,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 10_000);
    let store = EventStore::new(&tenant_scope);
    let rows = match store.list(&filter, limit).await {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().body(format!("{e:#}")),
    };

    match q.format.as_deref() {
        Some("logs") => HttpResponse::Ok().json(rows_as_logs(&rows)),
        // Default: Grafana Infinity "table" shape.
        _ => HttpResponse::Ok().json(rows_as_table(&rows)),
    }
}

fn rows_as_table(rows: &[crate::event_pipeline::store::StoredEvent]) -> serde_json::Value {
    use serde_json::json;
    let columns = json!([
        {"text": "id",        "type": "string"},
        {"text": "timestamp", "type": "time"},
        {"text": "node_id",   "type": "string"},
        {"text": "rule_id",   "type": "string"},
        {"text": "action",    "type": "string"},
        {"text": "direction", "type": "string"},
        {"text": "src_ip",    "type": "string"},
        {"text": "dst_ip",    "type": "string"},
        {"text": "sport",     "type": "number"},
        {"text": "dport",     "type": "number"},
        {"text": "proto",     "type": "number"},
        {"text": "pkt_len",   "type": "number"},
        {"text": "sni",       "type": "string"},
    ]);
    let rows_json: Vec<serde_json::Value> = rows
        .iter()
        .map(|e| {
            json!([
                e.id.to_string(),
                e.ts_ns / 1_000_000, // Grafana wants ms
                e.node_id,
                e.rule_id.to_string(),
                e.action.as_str(),
                e.direction.as_str(),
                e.src_ip.to_string(),
                e.dst_ip.to_string(),
                e.sport,
                e.dport,
                e.proto,
                e.pkt_len,
                e.sni.as_deref().unwrap_or(""),
            ])
        })
        .collect();
    json!({"columns": columns, "rows": rows_json})
}

fn rows_as_logs(rows: &[crate::event_pipeline::store::StoredEvent]) -> serde_json::Value {
    use serde_json::json;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|e| {
            json!({
                "id":        e.id.to_string(),
                "timestamp": e.ts_ns / 1_000_000,
                "node_id":   e.node_id,
                "rule_id":   e.rule_id.to_string(),
                "action":    e.action.as_str(),
                "direction": e.direction.as_str(),
                "src_ip":    e.src_ip.to_string(),
                "dst_ip":    e.dst_ip.to_string(),
                "sport":     e.sport,
                "dport":     e.dport,
                "proto":     e.proto,
                "pkt_len":   e.pkt_len,
                "sni":       e.sni,
            })
        })
        .collect();
    json!(items)
}

#[derive(Deserialize)]
struct AggregateRestQuery {
    #[serde(flatten)]
    base: EventsRestQuery,
    /// Required: one of rule_id, action, node_id, src_ip, dst_ip, minute, hour.
    group_by: String,
    /// Output shape: `table` (default) or `timeseries`.
    format: Option<String>,
}

fn parse_group_by(s: &str) -> std::result::Result<GroupBy, String> {
    match s {
        "rule_id" => Ok(GroupBy::RuleId),
        "action" => Ok(GroupBy::Action),
        "node_id" => Ok(GroupBy::NodeId),
        "src_ip" => Ok(GroupBy::SrcIp),
        "dst_ip" => Ok(GroupBy::DstIp),
        "minute" => Ok(GroupBy::Minute),
        "hour" => Ok(GroupBy::Hour),
        other => Err(format!("Unknown group_by '{other}'")),
    }
}

async fn rest_events_aggregate_handler(
    tenant_scope: Data<Arc<TenantScope>>,
    query: Query<AggregateRestQuery>,
) -> HttpResponse {
    let q = query.into_inner();
    let gb = match parse_group_by(&q.group_by) {
        Ok(g) => g,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };
    let filter = match build_filter(&q.base) {
        Ok(f) => f,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };
    let store = EventStore::new(&tenant_scope);
    let buckets = match store.aggregate(&filter, gb).await {
        Ok(b) => b,
        Err(e) => return HttpResponse::InternalServerError().body(format!("{e:#}")),
    };

    match q.format.as_deref() {
        Some("timeseries") => {
            // [{"target": "<group_by>", "datapoints": [[value, ts_ms], ...]}]
            // For time buckets (minute/hour) the key is the bucket index in
            // those units; convert to ms for Grafana.
            let multiplier_ms: i64 = match gb {
                GroupBy::Minute => 60_000,
                GroupBy::Hour => 3_600_000,
                _ => 1,
            };
            let datapoints: Vec<serde_json::Value> = buckets
                .iter()
                .map(|b| {
                    let bucket_idx = b.key.parse::<i64>().unwrap_or(0);
                    let ts_ms = bucket_idx * multiplier_ms;
                    serde_json::json!([b.count, ts_ms])
                })
                .collect();
            HttpResponse::Ok().json(serde_json::json!([{
                "target": q.group_by,
                "datapoints": datapoints,
            }]))
        }
        _ => {
            let rows: Vec<serde_json::Value> = buckets
                .iter()
                .map(|b| serde_json::json!([b.key, b.count]))
                .collect();
            HttpResponse::Ok().json(serde_json::json!({
                "columns": [
                    {"text": q.group_by, "type": "string"},
                    {"text": "count",   "type": "number"},
                ],
                "rows": rows,
            }))
        }
    }
}

// Silence "unused" on Direction — it's re-exported for completeness even
// though the REST layer reads direction off StoredEvent.
#[allow(dead_code)]
fn _direction_keepalive(_: Direction) {}

// ── REST: alert history (Grafana annotations + Infinity) ─────────────────────

#[derive(Deserialize)]
struct AlertHistoryRestQuery {
    /// RFC3339 inclusive lower bound on fired_at.
    since: Option<String>,
    /// RFC3339 exclusive upper bound on fired_at.
    until: Option<String>,
    rule_id: Option<i64>,
    limit: Option<i64>,
    cursor: Option<i64>,
    /// `table` (default), `annotations` (Grafana annotation list), or
    /// `logs` (JSON array of objects).
    format: Option<String>,
}

fn parse_rfc3339_s(s: &str) -> std::result::Result<i64, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|e| format!("Invalid timestamp '{s}': {e}"))
        .map(|t| t.with_timezone(&chrono::Utc).timestamp())
}

async fn rest_alert_history_handler(
    tenant_scope: Data<Arc<TenantScope>>,
    query: Query<AlertHistoryRestQuery>,
) -> HttpResponse {
    let q = query.into_inner();
    let since = match q.since.as_deref().map(parse_rfc3339_s).transpose() {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };
    let until = match q.until.as_deref().map(parse_rfc3339_s).transpose() {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };
    let limit = q.limit.unwrap_or(500).clamp(1, 10_000);
    let store = AlertStore::new(&tenant_scope);
    let entries = match store
        .list_history(
            &HistoryFilter {
                rule_id: q.rule_id,
                since,
                until,
                cursor: q.cursor,
            },
            limit,
        )
        .await
    {
        Ok(e) => e,
        Err(e) => return HttpResponse::InternalServerError().body(format!("{e:#}")),
    };

    // Annotation/text rendering wants rule name, not just id. One query for
    // the rule list is cheap relative to N round-trips.
    let rule_names: std::collections::HashMap<i64, (String, String)> =
        match store.list_rules().await {
            Ok(rules) => rules
                .into_iter()
                .map(|r| (r.id, (r.name, r.severity)))
                .collect(),
            Err(e) => return HttpResponse::InternalServerError().body(format!("{e:#}")),
        };

    match q.format.as_deref() {
        Some("annotations") => {
            HttpResponse::Ok().json(history_as_annotations(&entries, &rule_names))
        }
        Some("logs") => HttpResponse::Ok().json(history_as_logs(&entries, &rule_names)),
        _ => HttpResponse::Ok().json(history_as_table(&entries, &rule_names)),
    }
}

fn history_as_annotations(
    entries: &[crate::event_pipeline::alert_store::AlertHistoryEntry],
    rule_names: &std::collections::HashMap<i64, (String, String)>,
) -> serde_json::Value {
    use serde_json::json;
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let (name, severity) = rule_names
                .get(&e.rule_id)
                .cloned()
                .unwrap_or_else(|| (format!("rule:{}", e.rule_id), "info".into()));
            let time_ms = e.fired_at * 1_000;
            let time_end_ms = e.resolved_at.map(|t| t * 1_000).unwrap_or(time_ms);
            let mut tags = vec![
                format!("severity:{severity}"),
                format!("rule:{}", e.rule_id),
            ];
            if e.silenced {
                tags.push("silenced".into());
            }
            json!({
                "time": time_ms,
                "timeEnd": time_end_ms,
                "title": name,
                "text": format!(
                    "group={} events={}{}",
                    e.group_key,
                    e.event_count,
                    if e.silenced { " (silenced)" } else { "" }
                ),
                "tags": tags,
            })
        })
        .collect();
    json!(items)
}

fn history_as_table(
    entries: &[crate::event_pipeline::alert_store::AlertHistoryEntry],
    rule_names: &std::collections::HashMap<i64, (String, String)>,
) -> serde_json::Value {
    use serde_json::json;
    let columns = json!([
        {"text": "id",           "type": "string"},
        {"text": "fired_at",     "type": "time"},
        {"text": "resolved_at",  "type": "time"},
        {"text": "rule_id",      "type": "string"},
        {"text": "rule_name",    "type": "string"},
        {"text": "severity",     "type": "string"},
        {"text": "group_key",    "type": "string"},
        {"text": "event_count",  "type": "number"},
        {"text": "silenced",     "type": "number"},
    ]);
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let (name, severity) = rule_names
                .get(&e.rule_id)
                .cloned()
                .unwrap_or_else(|| (format!("rule:{}", e.rule_id), "info".into()));
            json!([
                e.id.to_string(),
                e.fired_at * 1_000,
                e.resolved_at.map(|t| t * 1_000),
                e.rule_id.to_string(),
                name,
                severity,
                e.group_key,
                e.event_count,
                e.silenced as i64,
            ])
        })
        .collect();
    json!({"columns": columns, "rows": rows})
}

fn history_as_logs(
    entries: &[crate::event_pipeline::alert_store::AlertHistoryEntry],
    rule_names: &std::collections::HashMap<i64, (String, String)>,
) -> serde_json::Value {
    use serde_json::json;
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let (name, severity) = rule_names
                .get(&e.rule_id)
                .cloned()
                .unwrap_or_else(|| (format!("rule:{}", e.rule_id), "info".into()));
            json!({
                "id":           e.id.to_string(),
                "fired_at":     e.fired_at * 1_000,
                "resolved_at":  e.resolved_at.map(|t| t * 1_000),
                "rule_id":      e.rule_id.to_string(),
                "rule_name":    name,
                "severity":     severity,
                "group_key":    e.group_key,
                "event_count":  e.event_count,
                "silenced":     e.silenced,
            })
        })
        .collect();
    json!(items)
}

#[cfg(test)]
mod rest_tests {
    use super::*;
    use crate::event_pipeline::{
        bootstrap_default_tenant,
        types::{Action as A, Direction as D, PolicyEvent},
    };
    use actix_web::{test, App};
    use sqlx::sqlite::SqlitePool;

    async fn setup_scope_with_rows() -> Arc<TenantScope> {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let scope = Arc::new(bootstrap_default_tenant(pool).await.unwrap());
        let store = EventStore::new(&scope);
        store
            .insert_batch(&[
                PolicyEvent {
                    ts_ns: 1_700_000_000_000_000_000,
                    node_id: "n1".into(),
                    rule_id: 42,
                    action: A::Drop,
                    verdict: 1,
                    direction: D::Ingress,
                    ifindex: 3,
                    proto: 6,
                    src_ip: vec![10, 0, 0, 1],
                    dst_ip: vec![10, 0, 0, 2],
                    sport: 1234,
                    dport: 22,
                    pkt_len: 64,
                    flags: None,
                    sni: None,
                },
                PolicyEvent {
                    ts_ns: 1_700_000_000_000_000_001,
                    node_id: "n1".into(),
                    rule_id: 42,
                    action: A::Log,
                    verdict: 2,
                    direction: D::Egress,
                    ifindex: 3,
                    proto: 6,
                    src_ip: vec![10, 0, 0, 1],
                    dst_ip: vec![10, 0, 0, 2],
                    sport: 1234,
                    dport: 80,
                    pkt_len: 128,
                    flags: None,
                    sni: None,
                },
            ])
            .await
            .unwrap();
        scope
    }

    #[actix_web::test]
    async fn rest_events_returns_table() {
        let scope = setup_scope_with_rows().await;
        let app = test::init_service(
            App::new()
                .app_data(Data::new(scope))
                .route("/api/v1/events", web::get().to(rest_events_handler)),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/v1/events").to_request();
        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp["columns"][0]["text"], "id");
        assert_eq!(resp["rows"].as_array().unwrap().len(), 2);
    }

    #[actix_web::test]
    async fn rest_events_filters_action() {
        let scope = setup_scope_with_rows().await;
        let app = test::init_service(
            App::new()
                .app_data(Data::new(scope))
                .route("/api/v1/events", web::get().to(rest_events_handler)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/events?action=drop")
            .to_request();
        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        let rows = resp["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][4], "drop");
    }

    #[actix_web::test]
    async fn rest_alert_history_annotations_shape() {
        use crate::event_pipeline::alert_store::{
            AlertStore, NewAlertHistory, NewAlertRule, NewReceiver,
        };

        let scope = setup_scope_with_rows().await;
        let astore = AlertStore::new(&scope);
        let r = astore
            .create_receiver(NewReceiver {
                name: "ops".into(),
                kind: "webhook".into(),
                config_json: r#"{"url":"https://hooks.example/abc"}"#.into(),
            })
            .await
            .unwrap();
        let rule = astore
            .create_rule(
                NewAlertRule {
                    name: "drops on n1".into(),
                    enabled: true,
                    match_json: r#"{"action":["drop"]}"#.into(),
                    group_by: vec!["rule_id".into()],
                    threshold_count: None,
                    threshold_window_s: None,
                    group_wait_s: 30,
                    group_interval_s: 300,
                    repeat_interval_s: 14_400,
                    resolve_after_s: 1_500,
                    severity: "critical".into(),
                    receiver_ids: vec![r.id],
                },
                0,
            )
            .await
            .unwrap();
        astore
            .append_history(NewAlertHistory {
                rule_id: rule.id,
                group_key: "rule_id=42".into(),
                fired_at: 1_700_000_000,
                event_count: 7,
                sample_event_ids: vec![1, 2, 3],
                silenced: false,
            })
            .await
            .unwrap();

        let app = test::init_service(App::new().app_data(Data::new(scope)).route(
            "/api/v1/alerts/history",
            web::get().to(rest_alert_history_handler),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/alerts/history?format=annotations")
            .to_request();
        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        let items = resp.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["title"], "drops on n1");
        assert_eq!(items[0]["time"], 1_700_000_000_000i64);
        let tags: Vec<String> = items[0]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect();
        assert!(tags.contains(&"severity:critical".to_string()));
        assert!(tags.iter().any(|t| t.starts_with("rule:")));
    }

    #[actix_web::test]
    async fn rest_alert_history_table_default_and_rule_filter() {
        use crate::event_pipeline::alert_store::{
            AlertStore, NewAlertHistory, NewAlertRule, NewReceiver,
        };

        let scope = setup_scope_with_rows().await;
        let astore = AlertStore::new(&scope);
        let r = astore
            .create_receiver(NewReceiver {
                name: "ops".into(),
                kind: "webhook".into(),
                config_json: r#"{"url":"https://hooks.example/abc"}"#.into(),
            })
            .await
            .unwrap();
        let rule_a = astore
            .create_rule(
                NewAlertRule {
                    name: "rule a".into(),
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
        let rule_b = astore
            .create_rule(
                NewAlertRule {
                    name: "rule b".into(),
                    enabled: true,
                    match_json: r#"{"action":["log"]}"#.into(),
                    group_by: vec!["rule_id".into()],
                    threshold_count: None,
                    threshold_window_s: None,
                    group_wait_s: 30,
                    group_interval_s: 300,
                    repeat_interval_s: 14_400,
                    resolve_after_s: 1_500,
                    severity: "info".into(),
                    receiver_ids: vec![r.id],
                },
                0,
            )
            .await
            .unwrap();
        for (rid, fired) in [
            (rule_a.id, 1_000i64),
            (rule_b.id, 2_000),
            (rule_a.id, 3_000),
        ] {
            astore
                .append_history(NewAlertHistory {
                    rule_id: rid,
                    group_key: "k".into(),
                    fired_at: fired,
                    event_count: 1,
                    sample_event_ids: vec![],
                    silenced: false,
                })
                .await
                .unwrap();
        }

        let app = test::init_service(App::new().app_data(Data::new(scope)).route(
            "/api/v1/alerts/history",
            web::get().to(rest_alert_history_handler),
        ))
        .await;

        // Default table shape returns all 3 rows, newest first.
        let req = test::TestRequest::get()
            .uri("/api/v1/alerts/history")
            .to_request();
        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp["columns"][0]["text"], "id");
        let rows = resp["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        // fired_at column (index 1) of first row is newest in ms.
        assert_eq!(rows[0][1], 3_000_000i64);

        // rule_id filter narrows to rule_a.
        let req = test::TestRequest::get()
            .uri(&format!("/api/v1/alerts/history?rule_id={}", rule_a.id))
            .to_request();
        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp["rows"].as_array().unwrap().len(), 2);
    }

    #[actix_web::test]
    async fn rest_aggregate_by_action() {
        let scope = setup_scope_with_rows().await;
        let app = test::init_service(App::new().app_data(Data::new(scope)).route(
            "/api/v1/events/aggregate",
            web::get().to(rest_events_aggregate_handler),
        ))
        .await;

        let req = test::TestRequest::get()
            .uri("/api/v1/events/aggregate?group_by=action")
            .to_request();
        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        let rows = resp["rows"].as_array().unwrap();
        // One bucket per action discriminator (1=drop, 2=log).
        assert_eq!(rows.len(), 2);
    }
}

#[cfg(test)]
mod ws_auth_tests {
    use super::*;
    use crate::api_tokens::ApiTokenStore;
    use actix_web::{test, App};
    use sqlx::sqlite::SqlitePool;

    async fn make_state() -> (BearerAuthState, Arc<ApiTokenStore>) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let store = Arc::new(ApiTokenStore::new(pool.clone()));
        let rbac = Arc::new(crate::rbac::RbacStore::new(pool));
        (BearerAuthState::new(Arc::clone(&store), rbac), store)
    }

    fn build_app(
        state: BearerAuthState,
        bus: Arc<EventBus>,
        rule_bus: Arc<RuleLifecycleBus>,
    ) -> App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
            Error = actix_web::Error,
            InitError = (),
        >,
    > {
        App::new()
            .app_data(Data::new(bus))
            .app_data(Data::new(rule_bus))
            .app_data(Data::new(state))
            .route("/ws/events", web::get().to(ws_events_handler))
            .route("/ws/rule-events", web::get().to(ws_rule_events_handler))
            .route("/ws/alerts", web::get().to(ws_alerts_handler))
    }

    #[actix_web::test]
    async fn ws_events_rejects_missing_token() {
        let (state, _store) = make_state().await;
        let bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(RuleLifecycleBus::new());
        let app = test::init_service(build_app(state, bus, rule_bus)).await;
        let req = test::TestRequest::get().uri("/ws/events").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn ws_events_rejects_invalid_token() {
        let (state, _store) = make_state().await;
        let bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(RuleLifecycleBus::new());
        let app = test::init_service(build_app(state, bus, rule_bus)).await;
        let req = test::TestRequest::get()
            .uri("/ws/events?token=dsw_garbage")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn ws_events_accepts_valid_token() {
        let (state, store) = make_state().await;
        let (_row, plaintext) = store.create("grafana", 1, None, None).await.unwrap();
        let bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(RuleLifecycleBus::new());
        let app = test::init_service(build_app(state, bus, rule_bus)).await;
        let req = test::TestRequest::get()
            .uri(&format!("/ws/events?token={plaintext}"))
            .insert_header(("connection", "upgrade"))
            .insert_header(("upgrade", "websocket"))
            .insert_header(("sec-websocket-version", "13"))
            .insert_header(("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="))
            .to_request();
        let resp = test::call_service(&app, req).await;
        // Valid token: the WS handshake succeeds (101 Switching Protocols).
        // The unauthorized paths above return 401 from the same surface.
        assert_eq!(resp.status(), 101);
    }

    #[actix_web::test]
    async fn ws_rule_events_rejects_invalid_token() {
        let (state, _store) = make_state().await;
        let bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(RuleLifecycleBus::new());
        let app = test::init_service(build_app(state, bus, rule_bus)).await;
        let req = test::TestRequest::get()
            .uri("/ws/rule-events?token=dsw_garbage")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn ws_rule_events_rejects_revoked_token() {
        let (state, store) = make_state().await;
        let (row, plaintext) = store.create("grafana", 1, None, None).await.unwrap();
        store.revoke(row.id, 1).await.unwrap();
        let bus = Arc::new(EventBus::new());
        let rule_bus = Arc::new(RuleLifecycleBus::new());
        let app = test::init_service(build_app(state, bus, rule_bus)).await;
        let req = test::TestRequest::get()
            .uri(&format!("/ws/rule-events?token={plaintext}"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }
}

// ── Operator login / logout ───────────────────────────────────────────────────
//
// See docs/login-flow.md. Login is unauthenticated (it's the entry point);
// logout is bearer-gated and revokes the caller's own session token.

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(serde::Serialize)]
struct LoginResponse {
    /// The plaintext `dsw_…` session token. Clients store this and send it
    /// as `Authorization: Bearer …` on subsequent requests (and as
    /// `?token=` on the WS endpoints).
    token: String,
    /// Unix seconds. The client SHOULD discard the token at this time and
    /// prompt for re-login. The server enforces it regardless.
    expires_at: i64,
    username: String,
}

async fn login_handler(
    operators: Data<Arc<OperatorStore>>,
    tokens: Data<Arc<ApiTokenStore>>,
    rbac: Data<Arc<RbacStore>>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    let req = body.into_inner();

    // OperatorStore::verify_password returns Ok(None) for unknown user,
    // bad password, AND disabled account — we mirror that with a single
    // generic 401 to avoid user enumeration.
    let operator = match operators
        .verify_password(&req.username, &req.password)
        .await
    {
        Ok(Some(op)) => op,
        Ok(None) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "invalid credentials"}))
        }
        Err(err) => {
            log::error!("login verify error: {err:#}");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "auth backend error"}));
        }
    };

    // Pick the tenant the session token will operate in. Operator's role
    // bindings carry tenant_id; in the single-tenant install this collapses
    // to `[1]`. Multi-tenant operators are rejected here because the UI
    // doesn't yet have a tenant picker — when it does, this becomes a
    // login-request input that we validate against the membership list.
    let tenant_id = match rbac.operator_tenant_ids(operator.id).await {
        Ok(ids) if ids.is_empty() => 1,
        Ok(ids) if ids.len() == 1 => ids[0],
        Ok(_) => {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "operator has role bindings in multiple tenants; \
                          tenant selection on login is not yet implemented"
            }));
        }
        Err(err) => {
            log::error!("login load operator tenants error: {err:#}");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "auth backend error"}));
        }
    };

    let now = now_s();
    let expires_at = now + SESSION_TTL_S;
    // Token name must be unique; include a unix-ts suffix so the same
    // operator can hold multiple concurrent sessions (laptop + workstation).
    let name = format!("session:{}:{}", operator.username, now);
    let created_by = format!("login:{}", operator.username);

    let (row, plaintext) = match tokens
        .create_session(&name, tenant_id, expires_at, &created_by, operator.id)
        .await
    {
        Ok(out) => out,
        Err(err) => {
            log::error!("login mint-session error: {err:#}");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "session mint failed"}));
        }
    };

    // Snapshot the operator's current roles onto the session token. The
    // intersection rule in rbac::RbacStore::resolve means subsequent role
    // changes on the operator immediately apply to this session without
    // requiring re-login or a token mutation.
    let role_ids = match rbac.operator_role_ids(operator.id).await {
        Ok(ids) => ids,
        Err(err) => {
            log::error!("login load operator roles error: {err:#}");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "session mint failed"}));
        }
    };
    if let Err(err) = rbac.set_token_roles(row.id, &role_ids).await {
        log::error!("login bind session roles error: {err:#}");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "session mint failed"}));
    }

    if let Err(err) = operators.touch_last_login(operator.id, now).await {
        // Non-fatal: the user is in. Just log it.
        log::warn!("touch last_login_at failed: {err:#}");
    }

    HttpResponse::Ok().json(LoginResponse {
        token: plaintext,
        expires_at,
        username: operator.username,
    })
}

/// Revoke the caller's bearer token. The auth middleware has already
/// authenticated the request and stashed the row in extensions; we just
/// flip `revoked_at` so a stolen-but-noticed token can be invalidated
/// from the same browser session that holds it.
async fn logout_handler(req: HttpRequest, tokens: Data<Arc<ApiTokenStore>>) -> HttpResponse {
    let plaintext = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
        .map(|s| s.trim().to_string());

    let Some(plaintext) = plaintext else {
        // Should be unreachable because logout sits behind bearer_auth,
        // but treat it as a no-op success rather than a 500.
        return HttpResponse::Ok().json(serde_json::json!({"revoked": false}));
    };

    match tokens.revoke_by_plaintext(&plaintext).await {
        Ok(revoked) => HttpResponse::Ok().json(serde_json::json!({"revoked": revoked})),
        Err(err) => {
            log::error!("logout revoke error: {err:#}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "logout failed"}))
        }
    }
}

fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Server builder ────────────────────────────────────────────────────────────

/// Build and bind the HTTP server, returning a `Server` handle that can be
/// awaited or spawned. The `Server` is `Send`; the factory closure is not, so
/// this function must be called from the main thread before any `tokio::spawn`.
#[allow(clippy::too_many_arguments)]
pub fn start_http_server(
    bind: SocketAddr,
    schema: ControllerSchema,
    event_bus: Arc<EventBus>,
    metrics_store: Arc<MetricsStore>,
    rule_lifecycle_bus: Arc<RuleLifecycleBus>,
    store: Arc<dyn ControllerStore>,
    sessions: Arc<NodeSessionManager>,
    tenant_scope: Arc<TenantScope>,
    event_metrics: Arc<EventPipelineMetrics>,
    alert_metrics: Arc<crate::event_pipeline::alert_metrics::AlertPipelineMetrics>,
    bearer_auth_state: BearerAuthState,
    operator_store: Arc<OperatorStore>,
    api_token_store: Arc<ApiTokenStore>,
    rbac_store: Arc<RbacStore>,
    web_root: Option<PathBuf>,
) -> std::io::Result<Server> {
    let schema_data = Data::new(schema);
    let event_bus_data = Data::new(event_bus);
    let metrics_data = Data::new(metrics_store);
    let rule_lifecycle_data = Data::new(rule_lifecycle_bus);
    let store_data = Data::new(store);
    let sessions_data = Data::new(sessions);
    let tenant_scope_data = Data::new(tenant_scope);
    let event_metrics_data = Data::new(event_metrics);
    let alert_metrics_data = Data::new(alert_metrics);
    let bearer_auth_data = Data::new(bearer_auth_state);
    let operator_store_data = Data::new(operator_store);
    let api_token_store_data = Data::new(api_token_store);
    let rbac_store_data = Data::new(rbac_store);

    log::info!("Controller HTTP API listening on {}", bind);
    match &web_root {
        Some(root) => log::info!("Serving web UI from {}", root.display()),
        None => log::warn!(
            "web_root is None — no static file serving. \
             Set web_root in config or use --web-root"
        ),
    }

    let server = HttpServer::new(move || {
        let cors = Cors::permissive();
        let mut app = App::new()
            .wrap(Logger::new("%a \"%r\" %s %b %Dms"))
            .wrap(cors)
            .app_data(schema_data.clone())
            .app_data(event_bus_data.clone())
            .app_data(metrics_data.clone())
            .app_data(rule_lifecycle_data.clone())
            .app_data(store_data.clone())
            .app_data(sessions_data.clone())
            .app_data(tenant_scope_data.clone())
            .app_data(event_metrics_data.clone())
            .app_data(alert_metrics_data.clone())
            .app_data(bearer_auth_data.clone())
            .app_data(operator_store_data.clone())
            .app_data(api_token_store_data.clone())
            .app_data(rbac_store_data.clone())
            // Health
            .route("/health", web::get().to(health))
            // Operator login — unauthenticated; see docs/login-flow.md.
            .route("/api/v1/login", web::post().to(login_handler))
            // WebSocket event streams. Bearer auth via `?token=dsw_…` query
            // string — browsers can't set custom headers on a WS connect,
            // so the token can't ride in `Authorization:` like it does on
            // /graphql and REST.
            .route("/ws/events", web::get().to(ws_events_handler))
            .route("/ws/rule-events", web::get().to(ws_rule_events_handler))
            .route("/ws/alerts", web::get().to(ws_alerts_handler))
            // Prometheus metrics (unauthenticated — scraped by Prometheus
            // over a separate trust boundary; aggregate counters only).
            .route("/metrics", web::get().to(metrics_all_handler))
            .route(
                "/metrics/node/{node_id}",
                web::get().to(metrics_node_handler),
            )
            // Bearer-auth-protected endpoints. Wrapped per-resource rather
            // than via `web::scope("")` because an empty-prefix scope
            // matches every request (including `/`) and its middleware
            // runs before route matching — so unmatched paths would 401
            // instead of falling through to the SPA's `Files` handler.
            .service(
                web::resource("/graphql")
                    .wrap(from_fn(bearer_auth))
                    .route(web::post().to(graphql_handler)),
            )
            .service(
                web::resource("/playground")
                    .wrap(from_fn(bearer_auth))
                    .route(web::get().to(graphql_playground)),
            )
            // Logout — bearer-authed so we know whose token to revoke.
            .service(
                web::resource("/api/v1/logout")
                    .wrap(from_fn(bearer_auth))
                    .route(web::post().to(logout_handler)),
            )
            // REST events API (Grafana Infinity datasource + scripting)
            .service(
                web::resource("/api/v1/events")
                    .wrap(from_fn(bearer_auth))
                    .route(web::get().to(rest_events_handler)),
            )
            .service(
                web::resource("/api/v1/events/aggregate")
                    .wrap(from_fn(bearer_auth))
                    .route(web::get().to(rest_events_aggregate_handler)),
            )
            // REST alerts history (Grafana annotations + Infinity)
            .service(
                web::resource("/api/v1/alerts/history")
                    .wrap(from_fn(bearer_auth))
                    .route(web::get().to(rest_alert_history_handler)),
            );

        // Serve the built web UI at `/` when a root dir is configured.
        if let Some(ref root) = web_root {
            let index = root.join("index.html");
            app = app.service(
                Files::new("/", root)
                    .index_file("index.html")
                    .default_handler(web::to(move || {
                        let index = index.clone();
                        async move { actix_files::NamedFile::open_async(index).await }
                    })),
            );
        }

        app
    })
    // Cap the graceful drain. Normal HTTP requests finish in well under a
    // second; the only long-lived connections are the /ws/* streams, which
    // close themselves via the EventBus shutdown signal. This is the backstop
    // if a connection doesn't close in time — without it actix defaults to
    // 30s, which is the entire shutdown delay we used to observe.
    .shutdown_timeout(5)
    .bind(bind)?
    .run();

    Ok(server)
}
