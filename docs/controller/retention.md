# Controller Data Retention

The controller accumulates high-volume operational data (policy events, IDS
alerts, fired-alert history) in its SQLite database. This document describes
what bounds that growth, what operators can and cannot delete, and the
design rule behind it:

> **Operator actions never delete history. Deletion is time-based only.**
>
> The UI/API "clear" verbs acknowledge or hide records; the retention sweep
> is the single thing that removes rows, on the tenant's retention window.
> The one exception is the explicitly named admin purge (see
> [Operator-facing verbs](#operator-facing-verbs)).

## The retention window

Retention is per tenant: `tenants.retention_s`, default **604800 s (7 days)**.
It is set at tenant creation (`bootstrap-tenant --retention-s <secs>`, or the
seeded default tenant) and can be changed with a direct SQL update:

```sql
UPDATE tenants SET retention_s = 2592000 WHERE slug = 'default';  -- 30 days
```

There is currently no GraphQL mutation for it; the sweep re-reads the value
on every pass, so a change takes effect within a minute and needs no restart.

## The retention sweep

`event_pipeline/retention.rs` spawns one background task per controller
process (`spawn_retention` in `bin/controller.rs`). Every **60 seconds** it
computes `cutoff = now - retention_s` and prunes each covered table in
chunks of **10,000 rows** (portable `id IN (SELECT … LIMIT)` deletes, so no
long SQLite write locks), bounded at 100 chunks per table per pass so a
misconfigured window cannot pin the task.

Rows deleted are counted in the Prometheus counter
`event_retention_pruned_total{tenant}` (see
[prometheus-metrics.md](../prometheus-metrics.md)).

## What the sweep prunes

| Table | Age column | Unit | Extra condition |
|---|---|---|---|
| `events` | `ts_ns` | ns | — |
| `suricata_alerts` | `received_ns` | ns | none — acked and unacked alike |
| `alert_history` | `resolved_at` | **seconds** | `resolved_at IS NOT NULL` |

Notes:

- **`events`** — raw policy events (BPF drop/pass records). No acknowledge
  concept: they are telemetry, filtered and paged in the UI, never cleared.
- **`suricata_alerts`** — IDS alerts. The UI "Clear" button acknowledges
  (`acked_at` stamp) rather than deletes; acknowledged alerts stay queryable
  (`includeAcked: true`) until the sweep ages them out.
- **`alert_history`** — fired alert-engine notifications. Rows age from
  `resolved_at`, not `fired_at`, and unresolved rows are kept regardless of
  age: an alert that is still firing must never vanish mid-incident.
  Timestamps here are epoch **seconds**, unlike the ns columns above.

## What is deliberately not pruned

- **`audit_log`** — the compliance trail (see [audit-log.md](../audit-log.md)).
  It must never be operator-clearable, and it is currently exempt from
  retention entirely. If unbounded growth becomes a problem, the plan is a
  separate, much longer `audit_retention_s` knob — not reuse of the event
  window.
- Configuration and identity tables (nodes, rules, rulesets, tokens, roles,
  tenants, …) — bounded by fleet size, not time.

## Operator-facing verbs

| Verb | Permission | Effect |
|---|---|---|
| `ackSuricataAlerts(nodeId)` | `alert:write` | Stamps `acked_at` on all unacked IDS alerts (optionally one node's). Hides them from the default list; nothing is deleted. Backs the UI "Clear" button and `client alerts ack`. |
| `clearSuricataAlerts(nodeId)` | `alert:delete` | **Admin purge**: permanently deletes stored IDS alerts. API/CLI only (`client alerts clear`); the UI never calls it. Audit-logged. |

Both are tenant-scoped from the caller's principal and write `audit_log`
entries (`suricata_alerts_acked` / `suricata_alerts_cleared`).

## Adding a new accumulating table

If a feature adds a table that grows with traffic or time rather than fleet
size:

1. Give it a monotonic age column (prefer ns since epoch, and document the
   unit if it differs).
2. Add a chunked prune helper to `event_pipeline/retention.rs::sweep_once`,
   following `prune_suricata_alerts` / `prune_alert_history`. Mind which
   tenant key the table uses: `events` and `alert_history` store the numeric
   `tenants.id`; `suricata_alerts` stores the slug.
3. If operators need to dismiss rows from a UI, add an acknowledge flag and
   a `*:write`-guarded mutation — not a delete.
4. Cover it with a `sweep_*` test in `retention.rs`.
