# Event Pipeline & Alerting

Design for ingesting policy match events from the fleet, persisting them on the
controller, exposing them to operators (UI, GraphQL, REST, Grafana), and firing
notifications when configurable conditions are met.

This document is the source of truth for the implementation work that follows.
Out-of-scope items are listed explicitly so they don't sneak in.

## Scope

In scope (v1):

- Policy match events with `action ∈ {drop, log}` flowing agent → controller.
- Persistence on the controller with bounded retention.
- GraphQL + REST query API (history, aggregates).
- controller-web "Events" view (live tail + history + chart).
- Grafana integration via shipped dashboards using the Infinity datasource.
- Capability negotiation so the controller knows which agents support what.
- Alert pipeline: matcher → grouper → dispatcher → providers.
- Providers: webhook, email (SMTP), alertmanager.
- Silences.
- Multi-tenancy as a structural concern (single `default` tenant bootstrapped).

Explicitly out of scope (deferred):

- Suricata alert forwarding to the controller (gated behind `suricata` feature).
- IPFIX flow forwarding to the controller (gated behind `ipfix` feature).
  Note: agent forwarders for both must be designed so they slot in without
  re-architecting the bus.
- PASS-action event emission — IPFIX will cover the "every flow" need.
- DB migrations. The DB is destroyable; schema changes drop and recreate.
- Tenant admin UI, signup, quotas, billing.
- Inhibition (Alertmanager-style "critical X suppresses warning Y").
- SMS / PagerDuty / Opsgenie / Slack native providers — covered via webhook for now.
- Loki / Elasticsearch / ClickHouse backends — SQLite first, Postgres opt-in later.
- Group state persistence across controller restarts.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Agent (one per node)                                                    │
│                                                                         │
│   engine /ws/events ──► event_forwarder ──► gRPC EventBatch ─────┐      │
│                                                                  │      │
└──────────────────────────────────────────────────────────────────┼──────┘
                                                                   │
                                                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Controller                                                              │
│                                                                         │
│  gRPC ingest ──► event_bus (broadcast<Signal>) ──┬──► WS /ws/events     │
│                                                  │                      │
│                                                  ├──► persister ──► DB  │
│                                                  │                      │
│                                                  └──► matcher           │
│                                                         │               │
│                                                         ▼               │
│                                                      grouper            │
│                                                         │               │
│                                                         ▼               │
│                                                     dispatcher          │
│                                                         │               │
│                                       ┌─────────────────┼──────────────┐│
│                                       ▼                 ▼              ▼│
│                                    webhook            email      alertmanager
│                                                                         │
│  REST /api/v1/events, /events/aggregate, /alerts/history                │
│  GraphQL events, eventAggregate, alertRules, receivers, silences        │
│  Prometheus /metrics                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

Same event_bus, same DB, same query layer powers both controller-web and
Grafana. No "Grafana adapter" — if the UI works, Grafana works.

## Capability negotiation

Agent registration / heartbeat carries a capabilities document:

```
Capabilities {
  features: ["ipfix"?, "suricata"?, "quic-inspect"?, ...]   // cargo features
  versions: { engine, agent }
  sources:  ["policy_events", ...]                          // streams supported
}
```

Stored per node, exposed on `node.capabilities` in GraphQL. The controller uses
it to:

- Warn on alert rules that reference fields/sources unavailable in the fleet.
- Activate optional forwarders (when those exist) only when (a) feature
  compiled in AND (b) controller has subscribed.

Capabilities are immutable per agent restart; refresh on reconnect.

## Multi-tenancy

Structural now, surface later.

- Every persistence table includes `tenant_id` (denormalised on `events` —
  no FK, queried via `(tenant_id, ts_ns DESC)` composite index).
- A `default` tenant is bootstrapped on first start.
- Every DB-touching function takes a `TenantScope` wrapper; raw `Pool` access
  is forbidden in handler code. This is the invariant that keeps multi-tenancy
  honest as the codebase grows.
- Auth resolves to a tenant (today: always `default`). Agent enrolment tokens
  bind a node to exactly one tenant — single-tenant-per-node is a structural
  assumption.
- No tenant CRUD APIs or admin UI in v1.

## Event model

Unified `PolicyEvent` carried over the existing gRPC `EventBatch` channel.
Action is constrained to `{drop, log}`. PASS is omitted (IPFIX will cover the
"every flow" use case later).

```
PolicyEvent {
  ts_ns, node_id, rule_id, action, verdict, direction,
  ifindex, src_ip, dst_ip, sport, dport, proto, pkt_len,
  flags?, sni?
}
```

`ts_ns` is the agent's clock. Acceptable for v1; revisit if clock skew across
nodes becomes a problem (cheap fix: stamp `received_at_ns` on the controller).

## Persistence

SQLite-first, Postgres opt-in. Same schema, same SQL, same code; flip a
connection string when the deployment outgrows SQLite. Estimated regimes:

| Regime | Events/sec/node | Backend |
|---|---|---|
| Light (<100) | SQLite WAL, single file on controller |
| Medium (100–10k) | PostgreSQL with composite indexes |
| Heavy (10k+) | Future: ClickHouse / Loki, defer |

### Schema

```sql
CREATE TABLE tenants (
  id          INTEGER PRIMARY KEY,
  slug        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  retention_s INTEGER NOT NULL DEFAULT 604800,   -- 7 days
  created_at  INTEGER NOT NULL
);

CREATE TABLE nodes (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id),
  node_uid      TEXT NOT NULL,
  hostname      TEXT NOT NULL,
  capabilities  TEXT NOT NULL,        -- JSON
  last_seen     INTEGER NOT NULL,
  UNIQUE(tenant_id, node_uid)
);

CREATE TABLE events (
  id          INTEGER PRIMARY KEY,
  tenant_id   INTEGER NOT NULL,       -- denormalised, no FK (hot path)
  node_id     INTEGER NOT NULL,
  ts_ns       INTEGER NOT NULL,
  rule_id     INTEGER NOT NULL,
  action      INTEGER NOT NULL,       -- 1=drop, 2=log
  verdict     INTEGER NOT NULL,
  direction   INTEGER NOT NULL,
  ifindex     INTEGER NOT NULL,
  proto       INTEGER NOT NULL,
  src_ip      BLOB NOT NULL,          -- 4 or 16 bytes
  dst_ip      BLOB NOT NULL,
  sport       INTEGER NOT NULL,
  dport       INTEGER NOT NULL,
  pkt_len     INTEGER NOT NULL,
  flags       INTEGER,
  sni         TEXT
);

CREATE INDEX events_tenant_ts          ON events(tenant_id, ts_ns DESC);
CREATE INDEX events_tenant_rule_ts     ON events(tenant_id, rule_id, ts_ns DESC);
CREATE INDEX events_tenant_action_ts   ON events(tenant_id, action,  ts_ns DESC);

CREATE TABLE alert_rules (
  id                  INTEGER PRIMARY KEY,
  tenant_id           INTEGER NOT NULL REFERENCES tenants(id),
  name                TEXT NOT NULL,
  enabled             INTEGER NOT NULL DEFAULT 1,
  match_json          TEXT NOT NULL,        -- MatchSpec (see Matcher section)
  group_by            TEXT NOT NULL,        -- JSON array of field names
  threshold_count     INTEGER,              -- NULL = per-event mode
  threshold_window_s  INTEGER,
  group_wait_s        INTEGER NOT NULL DEFAULT 30,
  group_interval_s    INTEGER NOT NULL DEFAULT 300,
  repeat_interval_s   INTEGER NOT NULL DEFAULT 14400,
  resolve_after_s     INTEGER NOT NULL DEFAULT 1500,
  severity            TEXT NOT NULL,        -- info | warning | critical
  receiver_ids        TEXT NOT NULL,        -- JSON array
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL,
  UNIQUE(tenant_id, name)
);

CREATE TABLE receivers (
  id          INTEGER PRIMARY KEY,
  tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,                -- webhook | email | alertmanager
  config_json TEXT NOT NULL,                -- secrets encrypted at rest
  UNIQUE(tenant_id, name)
);

CREATE TABLE silences (
  id           INTEGER PRIMARY KEY,
  tenant_id    INTEGER NOT NULL REFERENCES tenants(id),
  matcher_json TEXT NOT NULL,               -- subset of MatchSpec
  starts_at    INTEGER NOT NULL,
  ends_at      INTEGER NOT NULL,
  created_by   TEXT,
  comment      TEXT
);
CREATE INDEX silences_tenant_active ON silences(tenant_id, ends_at);

CREATE TABLE alert_history (
  id               INTEGER PRIMARY KEY,
  tenant_id        INTEGER NOT NULL,
  rule_id          INTEGER NOT NULL REFERENCES alert_rules(id),
  group_key        TEXT NOT NULL,
  fired_at         INTEGER NOT NULL,
  resolved_at      INTEGER,
  event_count      INTEGER NOT NULL,
  sample_event_ids TEXT NOT NULL,           -- JSON array (cap 5)
  silenced         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alert_history_tenant_fired ON alert_history(tenant_id, fired_at DESC);
```

Notes:

- `ts_ns` as INTEGER — sortable, indexable, tz-free. UI converts.
- `src_ip`/`dst_ip` as BLOB — 4 or 16 bytes; uniform v4/v6 storage.
- Three event indexes only; resist adding more until query patterns prove it.
- `match_json` is opaque to SQL; validated to typed `MatchSpec` in code.

### Write path

```
gRPC EventBatch
  → event_bus broadcast<Signal>
    → persister task
      → bounded buffer (500 rows or 100ms)
        → INSERT … one prepared stmt, one txn per batch
```

SQLite specifics: `journal_mode=WAL`, `synchronous=NORMAL`, single writer task.
If the persister falls behind, **drop with a counter** (`event_persist_dropped_total`).
Never block ingest, never grow memory unbounded.

### Retention

Background task, every 60s:

```sql
DELETE FROM events WHERE ts_ns < (now_ns - retention_ns) LIMIT 10000;
```

Chunked to avoid long locks. Per-tenant `retention_s` already in `tenants`.

## Query API

GraphQL is primary for controller-web; REST is a thin projection of the same
resolvers for Grafana and scripting. Both go through `TenantScope`.

### GraphQL

```graphql
events(
  filter: EventFilter
  limit: Int = 100
  cursor: String
): EventConnection

eventAggregate(
  filter: EventFilter
  groupBy: [EventGroupBy!]!   # RULE_ID | ACTION | SRC_IP | DST_IP | MINUTE | HOUR
  since: Timestamp!
  until: Timestamp!
): [AggregateBucket!]!

alertRules: [AlertRule!]!
receivers: [Receiver!]!
silences(active: Boolean): [Silence!]!
alertHistory(filter: AlertHistoryFilter, limit: Int, cursor: String): AlertHistoryConnection
```

Mutations: CRUD for `alertRules`, `receivers`, `silences`. Mutations emit a
`RuleChanged(rule_id)` on a tokio broadcast that the matcher subscribes to —
hot reload, no polling.

### REST (Grafana / scripting)

```
GET /api/v1/events?since=&until=&action=&rule_id=&node_id=
                  &src_cidr=&dst_cidr=&dport=&sport=&proto=&sni_like=
                  &limit=&cursor=&format=table|logs

GET /api/v1/events/aggregate?<filters>&group_by=&interval=1m&format=timeseries

GET /api/v1/alerts/history?<filters>&format=annotations
```

Response shapes match Grafana's Simple JSON / Infinity conventions:

- `table` — `{"columns":[{text,type}], "rows":[[…]]}`
- `timeseries` — `[{"target":"…","datapoints":[[value, ts_ms], …]}]`
- `annotations` — `[{"time","timeEnd","title","tags","text"}]`

Tenant resolution: `X-Tenant` header preferred, `?tenant=` query parameter
fallback. Auth rejects requests whose API key isn't authorised for the
claimed tenant — same rule as the GraphQL path.

Pagination: cursor (`?cursor=<event_id>`); Grafana ignores it and truncates
at `limit`.

## Matcher / Grouper / Dispatcher

```
Signal → [Matcher] → Incident → [Grouper] → Notification → [Dispatcher] → Provider
                       │            │                          │
                  (none yet)   dedupe/batch/threshold     retry, backoff, DLQ,
                                                         silence check
```

### MatchSpec

Declarative, finite, ANDed across fields. Each field is an optional equality
or set test. No OR, no NOT, no expression language.

```json
{
  "action":      ["drop"],
  "rule_id":    [42, 43],
  "node_id":    [7],
  "proto":      ["tcp"],
  "dport":      [22, 23],
  "sport_range": [1024, 65535],
  "src_cidr":   ["10.0.0.0/8"],
  "dst_cidr":   ["0.0.0.0/0"],
  "sni_glob":   ["*.evil.com"],
  "direction":  ["ingress"]
}
```

Validated at write time into a typed `MatchSpec`. Compiled CIDRs/globs cached.
Evaluation is O(fields-set) with no allocation. For OR logic, the user writes
two rules.

### Grouping

`group_by` is an array of low-cardinality fields:
`rule_id`, `action`, `proto`, `node_id`, `src_ip`, `dst_ip`, `sport`, `dport`,
`direction`. `sni` and free-form fields are disallowed (cardinality traps).

Group key = `(alert_rule_id, tuple_of_group_by_values)`.

Per-tenant cap on live groups (default 10k) with LRU eviction; counter
`groups_evicted_total{tenant,rule}`. Eviction = next event recreates state
from zero (fine; just delays a fire decision).

### Two modes

**Per-event** (`threshold_count = NULL`): fire on first match.

**Threshold** (`threshold_count`, `threshold_window_s` set): fire only when
at least `count` events occur within `window_s` for the same group key.
Implementation: 10-bucket sliding window ring buffer per group (~40 bytes).
Up to 10% imprecision at window boundaries; fine for alerting.

### Group lifecycle

```
IDLE ──first event──► PENDING ──group_wait_s──► FIRING
                       (threshold: until                │
                        count reached)                  │
                                                        │
        ┌───────────────────────┬──────────────────────┤
        │ no events for         │ events keep arriving │ every
        │ resolve_after_s       │ → notify each        │ repeat_interval_s
        │ → emit resolved       │   group_interval_s   │ → re-notify
        │   drop state          │                      │
        ▼                       ▼                      ▼
     RESOLVED (transient; state dropped)
```

In-memory state per group: ~200 bytes. 10k groups ≈ 2 MB. State is lost on
controller restart; pending groups re-pend on next event (worst case: extra
`group_wait_s` of delay); firing groups re-fire (a duplicate notification).
Receivers should be idempotent on `(rule_id, group_key)` — Alertmanager and
PagerDuty are.

### Hot reload

Mutation handlers broadcast `RuleChanged(rule_id)`. Matcher rebuilds the
compiled `MatchSpec` and swaps atomically. Existing group state is kept
unless `group_by` changed (groups become incomparable). Rule disable =
stop matching, drop state, emit any pending firing as resolved.

### Silences

Active silence with a matcher that matches the notification suppresses the
**outbound notification only**. The match still happens, the group still
tracks, history still records (with `silenced=1` plus a
`notifications_silenced_total` counter). This preserves "what would have
fired during the maintenance window."

### Dispatcher

Per-route bounded queue + worker pool. Each worker:

1. Looks up route → list of receivers.
2. Renders template per receiver.
3. Calls provider. On failure: exponential backoff + jitter, max N retries,
   then DLQ + `alert_dispatch_failed_total{provider,reason}`.

Per-provider concurrency caps. Bounded queues give backpressure visibility
via `alert_dispatcher_queue_depth{provider}` and bound memory growth when a
provider is down.

### Notification payload

```rust
Notification {
    rule:          AlertRuleSnapshot,         // id, name, severity
    group_key:     Vec<(String, Value)>,
    fired_at:      Timestamp,
    event_count:   u64,                       // since last notify
    sample_events: Vec<EventId>,              // cap 5, deep-linked
    status:        Firing | Resolved,
    is_repeat:     bool,
}
```

Persisted to `alert_history` so the UI can render "this alert covered these
events" with deep links into the Events view.

## Providers (v1)

| Kind | Notes |
|---|---|
| `webhook` | Generic HTTP POST with JSON body; covers Slack, Teams, Datadog, Splunk HEC, custom. `reqwest`. |
| `email` | SMTP via `lettre`. TLS, auth, recipient list. |
| `alertmanager` | Forward to existing Alertmanager so users keep their routing/escalation. |

Trait:

```rust
#[async_trait]
trait Notifier: Send + Sync {
    fn kind(&self) -> &'static str;
    async fn send(&self, n: &Notification) -> Result<(), NotifyError>;
}
```

Secret storage: `receivers.config_json` is encrypted at rest using an age
key loaded from controller config (≈50 lines with the `age` crate). Decrypted
only inside the dispatcher process.

## Visualization

### controller-web

New "Events" view:

- Filter form bound to GraphQL `events()`.
- Time-bucketed bar chart from `eventAggregate()`.
- Live tail using the existing `/ws/events` for the most recent slice.
- Click chart bucket → drill into matching rows.

New "Alerts" view:

- Active/recent fires from `alertHistory`.
- Rule CRUD, receiver CRUD, silence CRUD.

### Grafana

Two-stage rollout:

**v1 (now): Infinity datasource + shipped dashboards.**

One merged dashboard in `grafana/`:

`controller-events.json` — Prometheus (upper "Pipeline overview" rows) +
Infinity (lower "REST drill-in" rows). Pipeline overview works on day zero
once Prometheus scrapes the controller's `/metrics`. Drill-in adds an events
table, alert history table, per-minute filtered timeseries, and dashboard-wide
alert annotations from `/api/v1/alerts/history?format=annotations` — bound to
template variables `$action`, `$rule_id`, `$src_ip`, `$node_id`. Requires the
Infinity datasource plugin for the lower section (the Prometheus section keeps
working without it).

Alert annotations on every panel: `/api/v1/alerts/history?format=annotations`
overlays "alert fired" markers. Disproportionate UX value for one endpoint.

**v2 (when justified): custom datasource plugin.**

`@grafana/create-plugin` (TypeScript). Native query editor with dropdowns
populated from controller list endpoints. Same REST protocol — the plugin
is a UX wrapper, not a redesign. Defer until v1 validates the shape.

## Metrics

Add to the controller's existing `/metrics`:

```
event_ingest_received_total{tenant,node}
event_ingest_dropped_total{tenant,reason}
event_persist_inserted_total{tenant}
event_persist_dropped_total{tenant}
event_persist_batch_seconds (histogram)
event_retention_pruned_total{tenant}

alert_matched_total{tenant,rule}
alert_fired_total{tenant,rule,severity}
alert_groups_active{tenant,rule}
alert_groups_evicted_total{tenant,rule}
alert_dispatcher_queue_depth{provider}
alert_dispatched_total{tenant,provider,result}
alert_dispatch_retries_total{tenant,provider}
alert_dispatch_failed_total{tenant,provider,reason}
notifications_silenced_total{tenant,rule}
```

## Build order

Each step is independently shippable.

1. **Persistence + query API.** Schema, persister, retention, GraphQL
   `events`/`eventAggregate`, REST projections.
2. **controller-web Events view.** Live tail + history + chart.
3. **Grafana v1.** Ship `controller-events.json` (merged Prometheus overview +
   Infinity REST drill-in). Pipeline overview works immediately; drill-in rows
   come online once REST endpoints are in.
4. **Alert pipeline.** MatchSpec, matcher, grouper (per-event mode first),
   dispatcher, webhook + email + alertmanager providers, silences.
5. **Threshold mode.** Add sliding-window counter to grouper.
6. **Capability negotiation surfaced.** Reject/warn on alert rules referencing
   unavailable sources. (The plumbing should be there from step 1; this step
   is just enforcement and UI affordances.)

## Open questions

1. **Auth method for Grafana → controller.** Per-tenant bearer token with a
   scope claim is the easiest fit for Grafana's datasource config. Confirm
   against existing auth.
2. **Receiver secret key management.** age-encrypted with a key from
   controller config is the v1 plan. Confirm there isn't a project-wide
   secret store we should integrate with instead.
3. **Group state persistence on restart.** Accepted as lost in v1. If the
   duplicate-notification rate proves annoying, persist *only* the firing
   set (small) to a `firing_groups` table. Pending/threshold counters never
   worth the IO.
4. **Severity semantics.** Label only (string carried to receivers), or does
   the matcher do anything with it? Default: label only.
5. **Cross-rule dedup.** Two rules matching the same event produce two
   notifications. Intended (different rules = different on-calls); document.

## Non-goals reiterated

The following will be asked for and should be declined for v1:

- "Just add a small expression language to MatchSpec." No. Add a field.
- "Persist group state for correctness." No. Receivers are idempotent.
- "Add inhibition." No. Debugging cost outweighs benefit.
- "Build the Grafana plugin first." No. Validate the REST shape via Infinity.
- "Add Loki." No. Revisit when full-text search on event fields is justified.
