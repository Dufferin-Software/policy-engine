# Audit Log

The system keeps **two independent audit trails**, depending on which surface a
change is made through:

| Audit log | Where it lives | Records | Backing store |
|---|---|---|---|
| [policy-engine (standalone)](#policy-engine-standalone) | Each enforcement node | GraphQL **mutations** against the local engine API | NDJSON file + in-memory ring buffer |
| [policy-controller (fleet)](#policy-controller-fleet) | The central controller | Operator API actions + fleet lifecycle events (enrollment, certs, config push, ZTP tokens) | SQLite `audit_log` table |

They do not overlap: the engine log captures direct, node-local API changes;
the controller log captures fleet-management actions. A node managed by a
controller still writes its own engine-side audit log for any mutation that
reaches its local API (including those pushed by the agent).

Both satisfy the tamper-evidence requirements of PCI-DSS, SOC 2 Type II, and
similar frameworks.

---

# policy-engine (standalone)

policy-engine writes an append-only audit log that records every mutation
executed against the GraphQL API — who called it, what they sent, and whether
it succeeded.

## Log file location

```
/var/log/policy-engine/audit.log
```

The daemon creates the directory on startup if it doesn't exist.  If creation
fails (e.g. permission denied), the audit log is **disabled but the daemon
continues to run** — a warning is emitted:

```
WARN  Audit log disabled: Permission denied (os error 13)
```

## Format

Each event is a single JSON object followed by a newline (JSON Lines / NDJSON):

```json
{
  "timestamp": "2026-03-17T14:23:01.452Z",
  "operation": "attach_ingress",
  "input_json": { "interface": "eth0", "mode": "auto" },
  "result": "ok",
  "message": "Attached ingress program to eth0 in native mode (auto-selected)",
  "source_ip": "127.0.0.1:54321"
}
```

| Field | Type | Description |
|---|---|---|
| `timestamp` | RFC 3339 string | Wall-clock time of the event (UTC) |
| `operation` | string | GraphQL mutation name (snake_case) |
| `input_json` | JSON object or null | Serialised mutation input, redacted for clarity (see below) |
| `result` | `"ok"` or `"error"` | Whether the mutation succeeded |
| `message` | string | Human-readable result message from the daemon |
| `source_ip` | string | Client IP address and port (`IP:port`), or `"unknown"` |

### input_json redaction

The `input_json` field contains the full mutation input as supplied by the
caller.  There are no automatic redactions — if a mutation carries sensitive
data (e.g. Suricata rule content in `deploySuricataRules`), that content
appears in the log.  Ensure the log file has appropriate access controls (see
below).

Mutations with no structured input (e.g. `detachAll`, `disableInspect`,
`deleteAllCustomRules`) record `null` for `input_json`.

## What is logged

Every GraphQL mutation is logged.  The full list:

| Operation | Logged input |
|---|---|
| `attachIngress` | interface, mode |
| `detachIngress` | interface |
| `attachTc` | interface |
| `detachTc` | interface |
| `detachAll` | _(none)_ |
| `addRule` | full rule input |
| `addRules` | array of rule inputs |
| `deleteRule` | rule id / src |
| `deleteRules` | array of delete inputs |
| `flushRules` | direction |
| `setDefaultAction` | action, direction |
| `registerTailCall` | slot, program, direction |
| `clearGlobalStats` | interface, direction |
| `clearRuleStats` | rule_id, direction |
| `clearAllRuleStats` | direction |
| `clearEthertypeStats` | interface, direction |
| `clearInterfaceStats` | interface, direction |
| `clearAllStats` | _(none)_ |
| `configureInspect` | mode |
| `disableInspect` | _(none)_ |
| `deploySuricataRules` | filename, rules content |
| `reloadSuricataRules` | _(none)_ |
| `applySuricataConfig` | _(none)_ |
| `startSuricata` | _(none)_ |
| `stopSuricata` | _(none)_ |
| `clearFlowVerdicts` | direction |
| `addCustomRule` | filename, rule text |
| `deleteCustomRules` | filename, SIDs |
| `deleteRuleFile` | filename |
| `deleteAllCustomRules` | _(none)_ |

GraphQL **queries** are not logged — only mutations (state-changing operations).

## Querying the audit log via GraphQL

The in-memory ring buffer (last 1000 events) is accessible through the
`auditLog` query:

```graphql
{
  auditLog(limit: 20) {
    timestamp
    operation
    inputJson
    result
    message
    sourceIp
  }
}
```

`limit` is clamped to `[1, 1000]`, defaulting to 100.  This is useful for
real-time review in the GraphQL Playground or from a monitoring script, but is
**not a substitute for the on-disk log** — the ring buffer is lost on daemon
restart.

## Exporting the audit log

The `exportAuditLog` query renders the audit log in a downloadable format over
an optional time window. Unlike `auditLog`, it reads the **full on-disk NDJSON
log**, not the in-memory ring, so it is not limited to the last 1000 events.

```graphql
{
  exportAuditLog(
    format: "csv"                       # "csv" or "json"
    from: "2026-03-01T00:00:00Z"        # optional, inclusive, RFC 3339
    to:   "2026-03-31T23:59:59Z"        # optional, inclusive, RFC 3339
  ) {
    filename       # suggested download name, e.g. audit-export-20260619T120000Z.csv
    contentType    # MIME type, e.g. text/csv
    data           # the formatted log (UTF-8 text)
  }
}
```

Either time bound may be omitted to leave that side of the window open; omit
both to export everything. The **Audit** tab in the web UI wraps this query with
a format picker and from/to fields and downloads the result.

Formats are pluggable: each is an implementation of the `AuditExporter` trait
(`src/server/audit_export.rs`), resolved by name in `exporter_for`. Adding a new
format (e.g. NDJSON, syslog) is a single new `impl` plus a match arm — the query
and UI are unchanged. The CSV exporter serialises `input_json` into a single
quoted cell.

## Persistence

> **Current status**: the audit log file at `/var/log/policy-engine/audit.log`
> is append-only and survives daemon restarts.  The log is **not** automatically
> rotated or shipped to an external system.
>
> The in-memory ring buffer (1000 entries) is **not** persistent — it is empty
> after every daemon restart.  The on-disk log retains the full history.
>
> Log rotation and shipping to a SIEM are planned for a future release.  In the
> meantime, use `logrotate` (see below).

## Log rotation with logrotate

Create `/etc/logrotate.d/policy-engine`:

```
/var/log/policy-engine/audit.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        # No signal needed — the daemon re-opens the file on each write
        # because it holds the fd in append mode. The OS handles this
        # correctly with copytruncate on Linux.
    endscript
    copytruncate
}
```

> `copytruncate` is used because the daemon holds the log file open
> continuously.  This means there is a small window where a few lines may be
> lost during rotation.  For zero-loss rotation a future version will support
> `SIGHUP`-triggered log re-open.

## File permissions

The daemon writes as root.  Restrict read access to the audit log:

```bash
chmod 640 /var/log/policy-engine/audit.log
chown root:adm /var/log/policy-engine/audit.log
```

Grant read access only to roles that require it (security team, compliance
tooling).

## Shipping to a SIEM

The NDJSON format is directly ingested by most SIEM platforms:

**Elasticsearch / OpenSearch (Filebeat):**

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/policy-engine/audit.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      service: policy-engine
      log_type: audit
```

**Splunk (Universal Forwarder):**

```ini
[monitor:///var/log/policy-engine/audit.log]
sourcetype = _json
index = security
source = policy-engine-audit
```

**Loki (Promtail):**

```yaml
scrape_configs:
  - job_name: policy_engine_audit
    static_configs:
      - targets: [localhost]
        labels:
          job: policy-engine
          __path__: /var/log/policy-engine/audit.log
    pipeline_stages:
      - json:
          expressions:
            operation: operation
            result: result
            source_ip: source_ip
      - labels:
          operation:
          result:
```

## Example: alerting on privilege escalation

Using the Loki query below in a Grafana alert to detect any mutation that
attaches or detaches programs — useful for detecting unexpected configuration
changes:

```logql
{job="policy-engine"}
  | json
  | operation =~ "attach_ingress|detach_ingress|attach_tc|detach_tc|detach_all"
```

---

# policy-controller (fleet)

The controller records fleet-management actions — operator API mutations and
agent/system lifecycle events — to the `audit_log` table in its SQLite database
(`/var/lib/policy-controller/controller.db`). Unlike the engine's NDJSON file,
this log is queried through the controller's operator API and is **RBAC-gated
and tenant-scoped**.

## Storage and schema

Schema lives in `fleet/controller/migrations/0001_initial.sql`:

```sql
CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,          -- unix epoch seconds (UTC)
    operator  TEXT,                       -- who/what initiated; NULL = system/agent
    action    TEXT NOT NULL,              -- action name (snake_case)
    node_id   TEXT,                       -- target node, when node-scoped
    detail    TEXT,                       -- free-form context string
    tenant_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX idx_audit_log_ts   ON audit_log(ts);
CREATE INDEX idx_audit_log_node ON audit_log(node_id);
```

In code the rows map to `store::AuditEntry`, written via
`ControllerStore::append_audit(NewAuditEntry)` and read via
`ControllerStore::list_audit(...)`. Both the SQLite and in-memory store
implementations behave identically (the in-memory one is used by tests).

### The `operator` field

`operator` records who initiated the action:

| Value | Meaning |
|---|---|
| `operator:<username>` | A session token tied to an operator account. Written by the GraphQL operator mutations (`interface_tagged`, `config_pushed`, client-logged entries), which now record the authenticated principal's identity via `principal.actor`. |
| `token:<name>` | A static API token (e.g. `token:grafana-prod`); falls back to `token:<id>` if the token row can't be named. |
| Operator username (bare) | Set by node-registry actions that thread the caller through directly (enrollment approve/reject, labelling, decommission, token mint/revoke). |
| `"ztp-bootstrap"` | A node auto-redeeming a ZTP enrollment token. |
| `NULL` | System- or agent-originated events (enrollment submission, cert renewal, config-apply results, watchdog reaps, revoked-cert rejections, local-change detection). |

The `principal.actor` identity is resolved once in `RbacStore::resolve`:
`operator:<username>` for a session token (looked up from `operators.username`),
otherwise `token:<name>` from `api_tokens.name`.

## What is logged

Each row is one `action` with a free-form `detail` string. Actions by origin:

### Operator API actions

| `action` | Trigger | `detail` |
|---|---|---|
| `enrollment_approved` | Operator approves a pending enrollment | `label=<l>` (if set) |
| `enrollment_rejected` | Operator rejects a pending enrollment | `reason=<r>` (if given) |
| `node_labelled` | Operator sets a node's label | `label=<l>` |
| `node_decommissioned` | Operator decommissions a node | _(none)_ |
| `node_removed` | Operator deletes a node record | _(none)_ |
| `interface_tagged` | Operator tags a node interface | `iface=<i> tag=<t>` |
| `config_pushed` | Operator pushes a ruleset to a node | `<N> rules` |
| `enrollment_token_created` | Operator mints a ZTP bootstrap token | `token_id=<id> max_uses=<n> expires_at=<ts>` |
| `enrollment_token_revoked` | Operator revokes a ZTP token | `token_id=<id>` |

### Agent / system lifecycle events

| `action` | Trigger | `detail` |
|---|---|---|
| `enrollment_submitted` | A node submits an enrollment request | `enrollment_id=<id>` |
| `enrollment_token_redeemed` | A node auto-redeems a valid ZTP token | `token_id=<id> tenant_id=<t>` |
| `enrollment_token_rejected` | A token redemption fails (invalid/expired/exhausted) | `token_id=<id> outcome=<o>` |
| `cert_renewed` | Agent renews its mTLS client cert on the management channel | `old_serial=<hex>` |
| `revoked_cert_reject` | A revoked client cert was presented on the management channel and rejected | `serial=<hex>` |
| `config_applied` / `config_apply_failed` | Agent reports the result of a `ConfigPush` | `error=<msg>` on failure |
| `config_applied`, `config_commit_failed`, `config_rejected`, `config_reverted`, `config_abandoned` | Confirm-and-rollback lifecycle for a pushed config generation (see [config-confirm-and-rollback.md](config-confirm-and-rollback.md)) | `generation_id=<id>` |
| `config_abandoned` | Watchdog reaps an unconfirmed config generation that timed out | `generation_id=<id>` |
| `local_change_detected` | Agent reports an out-of-band local change on the node | `source=<s> added=<n> updated=<n> deleted=<n> …` |

### Client-logged entries

The `logAuditEntry` mutation (guarded by `audit:write`) lets a client record an
arbitrary entry — e.g. the agent noting that events were exported. The caller
supplies `action` and `detail` directly; `node_id` is optional.

## Tenant scoping

Every row carries a `tenant_id` slug, and the `auditLog` reader filters by the
caller's `principal.tenant_slug` — operators only ever see their own tenant's
audit history.

`NewAuditEntry.tenant_id: Option<String>` resolves at write time, in this
order (`append_audit` does the resolution as a single SQL `COALESCE`):

1. **Explicit slug** — passed by principal-aware resolvers (IAM, enrollment
   token mint/revoke, the operator GraphQL mutations). These should always
   supply it so the row can't fall back to `'default'`.
2. **Derived from `node_id`** — when the entry is node-scoped and no explicit
   slug was passed, the store reads `nodes.tenant_id` and attaches it. Covers
   approve, decommission, reconciliation, and the gRPC management surface
   without forcing every call site to thread tenant context down. (If the node
   row is missing — e.g. a race with decommission — the `COALESCE` picks the
   literal default.)
3. **Fallback to `'default'`** — when neither is available (token reaper, other
   background tasks). Safe for single-tenant installs; in multi-tenant
   deployments these rows are visible only to the default tenant's auditors.

## Access control (RBAC)

Reading and writing the controller audit log is gated by permissions:

| Permission | Guards | Held by built-in roles |
|---|---|---|
| `audit:read` | the `auditLog` query | `operator`, `viewer`, `security-admin`, `auditor` (and `admin` via `*:*`) |
| `audit:write` | the `logAuditEntry` mutation | only `admin` (`*:*`); grant explicitly to service tokens that need it |

## Querying via GraphQL

```graphql
{
  auditLog(limit: 50, offset: 0) {
    id
    ts
    operator
    action
    nodeId
    detail
  }
}
```

- Results are **newest-first** (`ORDER BY id DESC`).
- `limit` defaults to 50 and is clamped to `[1, 500]`; `offset` defaults to 0
  (use it to page back through history).
- Results are automatically restricted to the caller's tenant. `tenant_id` is
  stored on every row but not surfaced on the output type, since readers are
  already tenant-scoped.

The same query is available from the controller CLI:

```bash
policy-controller-client audit list --limit 50 --offset 0
```

## Exporting the audit log

The `exportAuditLog` query (also guarded by `audit:read`) renders the log in a
downloadable format over an optional time window. Results are **tenant-scoped**
to the caller and capped at 100,000 rows per export.

```graphql
{
  exportAuditLog(
    format: "csv"                       # "csv" or "json"
    from: "2026-03-01T00:00:00Z"        # optional, inclusive, RFC 3339
    to:   "2026-03-31T23:59:59Z"        # optional, inclusive, RFC 3339
  ) {
    filename       # suggested download name, e.g. audit-export-20260619T120000Z.csv
    contentType    # MIME type, e.g. text/csv
    data           # the formatted log (UTF-8 text)
  }
}
```

Either time bound may be omitted to leave that side open; omit both to export
the whole (tenant-scoped) history up to the cap. The **Audit Log** tab in the
controller web UI wraps this query with a format picker and from/to fields and
downloads the result. Exports carry the same columns as `auditLog`
(`id, ts, operator, action, node_id, detail`); `tenant_id` is never exported,
since readers are already tenant-scoped.

Formats are pluggable: each is an implementation of the `AuditExporter` trait
(`fleet/controller/src/audit_export.rs`), resolved by name in `exporter_for`.
Adding a new format is a single new `impl` plus a match arm.

## Persistence and retention

Rows live in the controller's SQLite database and survive restarts. There is
**no automatic pruning or rotation** — the table grows unbounded. For long-lived
deployments, back up `controller.db` as part of normal database backups and, if
needed, archive and trim old rows out of band (e.g. a scheduled
`DELETE FROM audit_log WHERE ts < ?` against a maintenance copy). Automatic
retention is planned for a future release.
