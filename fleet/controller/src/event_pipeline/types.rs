// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Wire-format → typed `PolicyEvent` parsing.
//!
//! Agents serialise events with the shape defined in
//! `src/server/event_stream.rs::EventJson`. The controller parses that JSON
//! into the typed form below for insertion into the `events` table.
//!
//! Action is constrained to `{drop, log}`; PASS events are dropped at parse
//! time (see docs/event-pipeline.md "Event model").

use serde::Deserialize;
use std::net::IpAddr;

/// Persisted action discriminator. Numeric so it indexes well and stays
/// small on disk; the GraphQL/REST layer maps back to strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Action {
    Drop = 1,
    Log = 2,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Drop => "drop",
            Action::Log => "log",
        }
    }

    pub fn from_db(v: i64) -> Option<Self> {
        match v {
            1 => Some(Action::Drop),
            2 => Some(Action::Log),
            _ => None,
        }
    }

    // Case-insensitive: the engine's Display impl uppercases ("DROP", "LOG"),
    // earlier docs assumed lowercase. Accept both rather than coupling the
    // wire format to one side.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "drop" => Some(Action::Drop),
            "log" => Some(Action::Log),
            _ => None,
        }
    }
}

/// Direction discriminator (1 = ingress, 2 = egress).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Direction {
    Ingress = 1,
    Egress = 2,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        }
    }

    pub fn from_db(v: i64) -> Option<Self> {
        match v {
            1 => Some(Direction::Ingress),
            2 => Some(Direction::Egress),
            _ => None,
        }
    }

    pub fn from_wire(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ingress" => Some(Direction::Ingress),
            "egress" => Some(Direction::Egress),
            _ => None,
        }
    }
}

/// Numeric IP protocol for the `proto` column.
///
/// Mirrors `/etc/protocols` numbers — kept here to avoid pulling in libc
/// constants. Anything outside this set lands as `0` (unknown) which still
/// indexes consistently.
pub(crate) fn proto_to_num(s: &str) -> i64 {
    match s.to_ascii_lowercase().as_str() {
        "icmp" => 1,
        "tcp" => 6,
        "udp" => 17,
        "icmpv6" => 58,
        _ => 0,
    }
}

/// Typed in-memory representation of a policy event ready for insertion.
#[derive(Debug, Clone)]
pub struct PolicyEvent {
    pub ts_ns: i64,
    pub node_id: String,
    pub rule_id: i64,
    pub action: Action,
    pub verdict: i64,
    pub direction: Direction,
    pub ifindex: i64,
    pub proto: i64,
    pub src_ip: Vec<u8>,
    pub dst_ip: Vec<u8>,
    pub sport: i64,
    pub dport: i64,
    pub pkt_len: i64,
    pub flags: Option<i64>,
    pub sni: Option<String>,
}

#[derive(Deserialize)]
struct EventJsonWire {
    timestamp_ns: u64,
    rule_id: u64,
    action: String,
    ifindex: u32,
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    protocol: String,
    pkt_len: u32,
    verdict: String,
    direction: String,
    #[serde(default)]
    sni: Option<String>,
    // `EventJson` carries `fragment: bool` and `quic_version: Option<String>`
    // separately. We pack them into the optional `flags` column so the
    // alert matcher can filter on them without two more columns.
    #[serde(default)]
    fragment: bool,
    #[serde(default)]
    quic_version: Option<String>,
}

/// Pack the boolean side-channels (`fragment`, QUIC version) into the
/// `flags` column. Bit layout matches the BPF-side `FLOW_FLAG_*` constants
/// so a future direct-from-binary path stays compatible.
fn pack_flags(fragment: bool, quic_version: Option<&str>) -> Option<i64> {
    const FRAGMENT: i64 = 1 << 0;
    const QUIC: i64 = 1 << 1;
    const QUIC_V1: i64 = 1 << 2;
    const QUIC_V2: i64 = 1 << 3;

    let mut v: i64 = 0;
    if fragment {
        v |= FRAGMENT;
    }
    match quic_version {
        Some("v1") => v |= QUIC | QUIC_V1,
        Some("v2") => v |= QUIC | QUIC_V2,
        Some(_) => v |= QUIC,
        None => {}
    }
    if v == 0 {
        None
    } else {
        Some(v)
    }
}

fn ip_bytes(s: &str) -> Option<Vec<u8>> {
    let ip: IpAddr = s.parse().ok()?;
    Some(match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    })
}

/// Why an event JSON blob was skipped. Returned so the persister can label
/// the drop counter — handy when chasing parse-rate regressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseSkip {
    /// Malformed JSON.
    BadJson,
    /// Action not in {drop, log} (PASS or unknown).
    PassOrUnknown,
    /// Unparseable IP address in src or dst.
    BadIp,
    /// Direction not in {ingress, egress}.
    BadDirection,
}

/// Parse one wire-format event JSON blob for one node.
///
/// Returns `Ok(None)` for `pass` and other non-persisted actions; this is
/// the common path and not an error. `Err` is only used for malformed input.
pub fn parse_policy_event(
    node_id: &str,
    blob: &[u8],
) -> std::result::Result<Option<PolicyEvent>, ParseSkip> {
    let wire: EventJsonWire = serde_json::from_slice(blob).map_err(|_| ParseSkip::BadJson)?;

    let action = match Action::from_wire(&wire.action) {
        Some(a) => a,
        None => return Ok(None),
    };
    let direction = Direction::from_wire(&wire.direction).ok_or(ParseSkip::BadDirection)?;
    let src_ip = ip_bytes(&wire.src).ok_or(ParseSkip::BadIp)?;
    let dst_ip = ip_bytes(&wire.dst).ok_or(ParseSkip::BadIp)?;
    let verdict = Action::from_wire(&wire.verdict)
        .map(|a| a as i64)
        .unwrap_or(0);

    Ok(Some(PolicyEvent {
        ts_ns: wire.timestamp_ns as i64,
        node_id: node_id.to_string(),
        rule_id: wire.rule_id as i64,
        action,
        verdict,
        direction,
        ifindex: wire.ifindex as i64,
        proto: proto_to_num(&wire.protocol),
        src_ip,
        dst_ip,
        sport: wire.sport as i64,
        dport: wire.dport as i64,
        pkt_len: wire.pkt_len as i64,
        flags: pack_flags(wire.fragment, wire.quic_version.as_deref()),
        sni: wire.sni.filter(|s| !s.is_empty()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json(action: &str) -> Vec<u8> {
        serde_json::json!({
            "timestamp_ns": 1700000000000000000u64,
            "rule_id": 42,
            "action": action,
            "ifindex": 3,
            "interface_name": "eth0",
            "src": "10.0.0.1",
            "dst": "192.168.1.1",
            "sport": 12345,
            "dport": 22,
            "protocol": "tcp",
            "af": 2,
            "pkt_len": 64,
            "verdict": action,
            "direction": "ingress",
            "fragment": false,
            "sni": null,
            "quic_version": null
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn parses_drop_event() {
        let ev = parse_policy_event("node-x", &sample_json("drop"))
            .unwrap()
            .unwrap();
        assert_eq!(ev.action, Action::Drop);
        assert_eq!(ev.direction, Direction::Ingress);
        assert_eq!(ev.src_ip, vec![10, 0, 0, 1]);
        assert_eq!(ev.dst_ip, vec![192, 168, 1, 1]);
        assert_eq!(ev.proto, 6);
        assert_eq!(ev.dport, 22);
    }

    #[test]
    fn parses_log_event() {
        let ev = parse_policy_event("node-x", &sample_json("log"))
            .unwrap()
            .unwrap();
        assert_eq!(ev.action, Action::Log);
    }

    #[test]
    fn parses_uppercase_action_and_direction() {
        // The live engine's Display impl emits uppercase ("LOG", "DROP",
        // "INGRESS"); accepting both shields the controller from that drift.
        let mut json: serde_json::Value = serde_json::from_slice(&sample_json("LOG")).unwrap();
        json["direction"] = serde_json::Value::String("INGRESS".to_string());
        let ev = parse_policy_event("node-x", &json.to_string().into_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(ev.action, Action::Log);
        assert_eq!(ev.direction, Direction::Ingress);
    }

    #[test]
    fn pass_returns_none() {
        let out = parse_policy_event("node-x", &sample_json("pass")).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn bad_json_errors() {
        let err = parse_policy_event("node-x", b"not json").unwrap_err();
        assert_eq!(err, ParseSkip::BadJson);
    }

    #[test]
    fn ipv6_round_trips() {
        let mut json: serde_json::Value = serde_json::from_slice(&sample_json("drop")).unwrap();
        json["src"] = serde_json::Value::String("2001:db8::1".to_string());
        json["dst"] = serde_json::Value::String("2001:db8::2".to_string());
        let bytes = json.to_string().into_bytes();
        let ev = parse_policy_event("n", &bytes).unwrap().unwrap();
        assert_eq!(ev.src_ip.len(), 16);
        assert_eq!(ev.dst_ip.len(), 16);
    }

    #[test]
    fn flags_pack_quic_v1() {
        let mut json: serde_json::Value = serde_json::from_slice(&sample_json("drop")).unwrap();
        json["quic_version"] = serde_json::Value::String("v1".to_string());
        let ev = parse_policy_event("n", &json.to_string().into_bytes())
            .unwrap()
            .unwrap();
        // QUIC + QUIC_V1 = bits 1 and 2.
        assert_eq!(ev.flags, Some((1 << 1) | (1 << 2)));
    }
}
