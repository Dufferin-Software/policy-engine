# Audit Log

policy-engine writes an append-only audit log that records every mutation
executed against the GraphQL API — who called it, what they sent, and whether
it succeeded.  This satisfies the tamper-evidence requirements of PCI-DSS,
SOC 2 Type II, and similar frameworks.

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

### Tenant scoping (controller)

Controller-side `audit_log` rows carry a `tenant_id` slug and the
`auditLog` resolver filters by `principal.tenant_slug` — operators
only see their own tenant's audit history.

`NewAuditEntry.tenant_id: Option<String>` resolves at write time in
this order:

1. **Explicit slug** — passed by principal-aware resolvers (IAM, enrollment
   mints, the few resolvers that have `principal.tenant_slug` in scope).
2. **Derived from `node_id`** — when the audit entry is node-scoped and
   no explicit slug was passed, the store reads `nodes.tenant_id` and
   attaches it. Covers approve, decommission, reconciliation, and the
   gRPC management surface without forcing every call site to thread
   tenant context down.
3. **Fallback to `'default'`** — when neither is available (token
   reaper, retention sweep, other background tasks). Safe for
   single-tenant installs; in multi-tenant deployments these rows are
   visible only to the default tenant's auditors.

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
