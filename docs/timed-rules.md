# Timed Rules

Policy rules can have a lifecycle constraint — either a **TTL** (auto-remove
after N seconds) or a **weekly schedule** (active only during recurring time
windows). Rules with either constraint are called *managed rules* and are
tracked separately from permanent rules in the rule registry.

TTL and schedule are mutually exclusive: a single rule cannot have both.

## TTL rules

A TTL rule is automatically removed from the BPF maps once its deadline
passes. The scheduler checks for expired TTL rules every 30 seconds, so
removal may lag by up to that interval.

TTL rules are always `active` from the moment they are added until they
expire or are manually deleted.

### Adding a TTL rule via GraphQL

```graphql
mutation {
  addRule(input: {
    direction: INGRESS
    src: "198.51.100.1/32"
    protocol: "any"
    actions: [{ action: DROP, priority: 0 }]
    expiresAfterSecs: 3600
  }) {
    success
    message
  }
}
```

`expiresAfterSecs` must be a positive integer. Zero is rejected.

### Adding a TTL rule via the CLI

```bash
policy-client rule add --direction ingress \
    --src 198.51.100.1/32 --action drop:0 \
    --expires-after-secs 3600
```

## Scheduled rules

A scheduled rule is installed into (or removed from) the BPF maps according
to a set of weekly recurring time windows. The scheduler evaluates windows
every 30 seconds.

- While *inside* a window, the rule state is `active` and the rule is present
  in the BPF maps.
- While *outside* all windows, the rule state is `inactive` and the rule is
  absent from the BPF maps but remains registered (it will be reinstalled at
  the next window start).

Time windows are specified in local time using an IANA timezone name. The
default timezone is `UTC`.

### Window format

Each window is a half-open interval `[start, end)` expressed as a day-of-week
and time pair:

| Field | Values |
|---|---|
| `dayOfWeek` | 0 = Sunday … 6 = Saturday |
| `hour` | 0–23 |
| `minute` | 0–59 |

A window where `end` ≤ `start` (in week-minutes) wraps across the
Saturday/Sunday boundary — for example, Saturday 23:00 → Sunday 01:00.

Multiple windows may be specified; the rule is active if the current time
falls within *any* of them.

### Adding a scheduled rule via GraphQL

```graphql
mutation {
  addRule(input: {
    direction: INGRESS
    src: "10.0.0.0/8"
    protocol: "any"
    actions: [{ action: DROP, priority: 0 }]
    schedule: {
      windows: [
        {
          start: { dayOfWeek: 1, hour: 9, minute: 0 }
          end:   { dayOfWeek: 1, hour: 17, minute: 0 }
        }
      ]
      timezone: "America/Toronto"
    }
  }) {
    success
    message
  }
}
```

### Adding a scheduled rule via the CLI

Window format on the command line is `DAY:HH:MM-DAY:HH:MM` where `DAY` is
0 (Sunday) to 6 (Saturday). Multiple `--schedule-window` flags are OR-ed
together.

```bash
# Block 10.0.0.0/8 on weekdays 09:00–17:00 Eastern Time
policy-client rule add --direction ingress \
    --src 10.0.0.0/8 --action drop:0 \
    --schedule-window 1:09:00-5:17:00 \
    --schedule-tz "America/Toronto"

# Wrap-around window: Saturday 23:00 through Sunday 01:00 UTC
policy-client rule add --direction ingress \
    --src 0.0.0.0/0 --action drop:0 \
    --schedule-window 6:23:00-0:01:00
```

## Querying managed rules

Permanent rules (no lifecycle constraint) are returned by the `rules` query.
Managed rules are returned by the separate `managedRules` query, which
includes lifecycle metadata.

### GraphQL

```graphql
query {
  managedRules(direction: INGRESS) {
    ruleId
    srcPrefix
    dstPrefix
    sport
    dport
    protocol
    actions { action priority param }
    ruleState        # "active" or "inactive"
    expiresAtMs      # ms since epoch (TTL rules only, null otherwise)
    schedule {       # schedule rules only, null otherwise
      timezone
      windows {
        start { dayOfWeek hour minute }
        end   { dayOfWeek hour minute }
      }
    }
  }
}
```

### CLI

```bash
policy-client rule managed-rules --direction ingress
```

## Deleting a managed rule

Deleting a managed rule by ID removes it from the registry and from the BPF
maps immediately.

```bash
policy-client rule delete --direction ingress --id 9001
```

```graphql
mutation {
  deleteRule(input: { direction: INGRESS, id: "9001" }) {
    success
    message
  }
}
```

## Rule lifecycle event stream

Every state change to a managed (or permanent) rule is broadcast as a JSON
event over a WebSocket endpoint.

### Endpoint

```
GET /ws/rule-events
```

Upgrade to WebSocket with a standard `Upgrade: websocket` handshake. The
server sends a heartbeat ping every 15 seconds. On server shutdown a
`Close(1001 Away)` frame is sent.

If the server is behind TLS the endpoint is `wss://`.

### Event message format

Each message is a JSON object:

```json
{
  "event_type":   "activated",
  "rule_id":      9001,
  "direction":    "INGRESS",
  "timestamp_ms": 1712345678000,
  "reason":       "schedule_window_start"
}
```

| Field | Type | Description |
|---|---|---|
| `event_type` | string | `"activated"` \| `"deactivated"` \| `"deleted"` \| `"expired"` |
| `rule_id` | integer | The rule ID |
| `direction` | string | `"INGRESS"` or `"EGRESS"` |
| `timestamp_ms` | integer | Unix timestamp in milliseconds |
| `reason` | string \| absent | Human-readable cause (see below) |

Common `reason` values:

| Reason | Trigger |
|---|---|
| `ttl_expired` | TTL deadline passed; rule removed by scheduler |
| `schedule_window_start` | Entered a schedule window; rule installed in BPF maps |
| `schedule_window_end` | Left all schedule windows; rule removed from BPF maps |
| _(absent)_ | Permanent rule activated or rule deleted by API call |

### Behaviour

- **Fan-out**: all connected clients receive every event.
- **No replay**: only events emitted after a client connects are delivered.
- **Lag protection**: if a client falls more than 256 events behind, missed
  events are silently skipped and a warning is logged server-side.
- **Reconnection**: the web UI reconnects automatically with exponential
  backoff (1 s → 30 s max).

### Example: subscribe with `websocat`

```bash
websocat ws://127.0.0.1:8080/ws/rule-events
```

### Example: subscribe with JavaScript

```javascript
const ws = new WebSocket('ws://127.0.0.1:8080/ws/rule-events')
ws.onmessage = (e) => {
  const ev = JSON.parse(e.data)
  console.log(ev.event_type, ev.rule_id, ev.direction, ev.reason)
}
```

## Persistence

The rule registry is **in-memory only** and does not survive server restarts.
Managed rules must be re-added after a restart. This also means that a server
restart clears all TTL and schedule state; any partially-elapsed TTL resets.

## Scheduler timing

The scheduler runs every 30 seconds. For TTL rules with a short expiry (less
than 30 seconds), actual removal may occur up to 30 seconds after the
deadline. Scheduled rules may enter or leave a window up to 30 seconds late.
