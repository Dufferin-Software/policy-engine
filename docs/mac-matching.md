# MAC Address Matching

Policy rules support Layer 2 MAC address filtering as an optional extension to
the IP 5-tuple, giving full **7-tuple matching**:

| Field | Type | Wildcard |
|---|---|---|
| `src` | IP prefix (CIDR) | `0.0.0.0/0` or omit |
| `dst` | IP prefix (CIDR) | `0.0.0.0/0` or omit |
| `sport` | port number | `0` or omit |
| `dport` | port number | `0` or omit |
| `protocol` | `tcp` / `udp` / `icmp` / `any` | `any` |
| `srcMac` | 6-byte MAC address | omit |
| `dstMac` | 6-byte MAC address | omit |

MAC fields are **always optional**. Omitting a MAC field matches any MAC
address (wildcard). Both fields may be set simultaneously — in that case
**both must match** for the rule to fire.

## Format

MAC addresses are expressed as colon-separated lowercase hexadecimal octets:
`aa:bb:cc:dd:ee:ff`.

All-zeros (`00:00:00:00:00:00`) is not a valid filter value — it means wildcard
in the BPF representation. Pass the field as `null` / omit it instead.

## Direction

MAC matching works on both ingress (XDP) and egress (TC) directions:

- **Ingress**: `srcMac` is the MAC of the sender; `dstMac` is the MAC of the
  receiving interface.
- **Egress**: `srcMac` is the MAC of the sending interface; `dstMac` is the
  MAC of the next-hop (peer NIC on the same L2 segment).

## CLI

```bash
# Drop all inbound traffic from a specific MAC
policy-client rule add --direction ingress \
    --src 0.0.0.0/0 --action drop:0 \
    --src-mac aa:bb:cc:dd:ee:ff

# Drop outbound traffic to a specific destination MAC
policy-client rule add --direction egress \
    --src 0.0.0.0/0 --action drop:0 \
    --dst-mac 11:22:33:44:55:66

# Combine src and dst — both must match
policy-client rule add --direction ingress \
    --src 10.0.0.0/8 --action drop:0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --dst-mac 11:22:33:44:55:66

# List rules — MAC columns are shown in the output table
policy-client rule list --direction ingress
```

## GraphQL

```graphql
mutation {
  addRule(input: {
    direction: INGRESS
    src: "0.0.0.0/0"
    protocol: "any"
    actions: [{ action: DROP, priority: 0 }]
    srcMac: "aa:bb:cc:dd:ee:ff"
  }) {
    success
    message
  }
}
```

```graphql
# Both src and dst MAC
mutation {
  addRule(input: {
    direction: INGRESS
    src: "10.0.0.0/8"
    protocol: "any"
    actions: [{ action: DROP, priority: 0 }]
    srcMac: "aa:bb:cc:dd:ee:ff"
    dstMac: "11:22:33:44:55:66"
  }) {
    success
    message
  }
}
```

## Querying rules

MAC fields appear in both the `rules` and `managedRules` query responses:

```graphql
query {
  rules(direction: INGRESS) {
    ruleId
    srcPrefix
    dstPrefix
    sport
    dport
    protocol
    actions { action priority }
    srcMac     # null if no MAC filter
    dstMac     # null if no MAC filter
  }
}
```

## Combining with other match fields

MAC filtering composes orthogonally with all other rule fields. For example:

```graphql
# Drop TCP port 443 outbound from a specific MAC
mutation {
  addRule(input: {
    direction: EGRESS
    src: "192.168.1.0/24"
    protocol: "tcp"
    dport: 443
    actions: [{ action: DROP, priority: 0 }]
    srcMac: "aa:bb:cc:dd:ee:ff"
  }) { success message }
}
```

```graphql
# SNI + MAC: drop TLS to *.example.com from a specific source MAC
mutation {
  addRule(input: {
    direction: EGRESS
    src: "192.168.1.0/24"
    protocol: "tcp"
    dport: 443
    actions: [{ action: DROP, priority: 0 }]
    sni: "*.example.com"
    srcMac: "aa:bb:cc:dd:ee:ff"
  }) { success message }
}
```

## Implementation notes

MAC fields live in a **sidecar BPF hash map** (`mac_rules` for ingress,
`tc_mac_rules` for egress), keyed by `rule_id`. This keeps the main
`l4_rule` struct at 96 bytes and avoids exceeding the BPF branch-range
limit (±32 767 instructions) in the aggressively-unrolled rule loops.

The check is performed after the L4 match, in a dedicated `__noinline` BPF
subprogram (`check_mac_rule_xdp` / `check_mac_rule_tc`), so each call from
the rule scan loop is a single BPF call instruction rather than inline code.

Rules without MAC fields (`mac_match_flags == 0`) incur only a single
predicted-not-taken branch — effectively zero overhead at XDP line rates.

## Limitations

- **Exact match only** — OUI/prefix matching (e.g. `aa:bb:cc:xx:xx:xx/24`) is
  not supported in v1. The sidecar map value has reserved bytes for a future
  prefix-length field.
- **IP LPM required** — a pure L2 MAC rule (no IP constraint) still requires
  an IP LPM entry to reach the rule. Use `src: "0.0.0.0/0"` and
  `dst: "0.0.0.0/0"` to match any IP when MAC is the only criterion.
- **VLAN transparency** — `eth->h_source` and `eth->h_dest` are at Ethernet
  frame offset 0 regardless of VLAN tags, so MAC matching is correct for both
  tagged and untagged frames.
