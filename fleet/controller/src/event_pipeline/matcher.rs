// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Alert-rule matcher.
//!
//! `MatchSpec` is the wire-format JSON stored in `alert_rules.match_json`. It
//! is declarative, finite, ANDed across fields — no OR, no NOT, no expression
//! language. For OR logic, write two rules.
//!
//! At write time the spec is validated and compiled into [`CompiledMatchSpec`]
//! once (CIDRs parsed, globs compiled). Evaluation against a [`PolicyEvent`]
//! is then O(fields-set) with no allocation — only the fields actually present
//! in the spec are checked, and the first field that fails to match short-
//! circuits the whole evaluation.
//!
//! See docs/event-pipeline.md "Matcher / Grouper / Dispatcher" for the
//! design rationale.

use anyhow::{anyhow, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::net::IpAddr;

use super::types::{proto_to_num, Action, Direction, PolicyEvent};

/// Wire-format MatchSpec. All fields are optional; absent / empty fields
/// mean "no constraint on this field". An empty MatchSpec matches every
/// event.
///
/// Unknown JSON fields are rejected so a typo in a rule write doesn't
/// silently match everything.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    #[serde(default)]
    pub action: Vec<String>,
    #[serde(default)]
    pub rule_id: Vec<i64>,
    #[serde(default)]
    pub node_id: Vec<String>,
    #[serde(default)]
    pub proto: Vec<String>,
    #[serde(default)]
    pub sport: Vec<i64>,
    #[serde(default)]
    pub dport: Vec<i64>,
    /// Inclusive `[lo, hi]`. Use `sport`/`dport` for an exact set instead.
    #[serde(default)]
    pub sport_range: Option<[i64; 2]>,
    #[serde(default)]
    pub dport_range: Option<[i64; 2]>,
    #[serde(default)]
    pub src_cidr: Vec<String>,
    #[serde(default)]
    pub dst_cidr: Vec<String>,
    #[serde(default)]
    pub sni_glob: Vec<String>,
    #[serde(default)]
    pub direction: Vec<String>,
}

/// Pre-validated, ready-to-evaluate form. Built by [`MatchSpec::compile`].
///
/// `None` on a field means "no constraint" so `matches()` can skip it with
/// a single `is_some()` check — that's the source of the O(fields-set) cost.
#[derive(Debug, Clone, Default)]
pub struct CompiledMatchSpec {
    action: Option<Vec<Action>>,
    rule_id: Option<Vec<i64>>,
    node_id: Option<Vec<String>>,
    proto: Option<Vec<i64>>,
    sport: Option<Vec<i64>>,
    dport: Option<Vec<i64>>,
    sport_range: Option<(i64, i64)>,
    dport_range: Option<(i64, i64)>,
    src_cidr: Option<Vec<IpNetwork>>,
    dst_cidr: Option<Vec<IpNetwork>>,
    sni_glob: Option<GlobSet>,
    direction: Option<Vec<Direction>>,
}

impl MatchSpec {
    /// Convenience for callers reading from `alert_rules.match_json`.
    pub fn compile_json(json: &str) -> Result<CompiledMatchSpec> {
        let spec: MatchSpec =
            serde_json::from_str(json).context("Failed to parse MatchSpec JSON")?;
        spec.compile()
    }

    pub fn compile(self) -> Result<CompiledMatchSpec> {
        let action = vec_to_opt(
            self.action
                .iter()
                .map(|s| Action::from_wire(s).ok_or_else(|| anyhow!("Unknown action '{s}'")))
                .collect::<Result<Vec<_>>>()?,
        );
        let direction = vec_to_opt(
            self.direction
                .iter()
                .map(|s| Direction::from_wire(s).ok_or_else(|| anyhow!("Unknown direction '{s}'")))
                .collect::<Result<Vec<_>>>()?,
        );
        // Reject unknown proto names rather than silently mapping to 0 — at
        // write time we should fail loudly. (proto_to_num maps unknown ->
        // 0, which is fine on the hot ingest path but wrong here.)
        let proto = vec_to_opt(
            self.proto
                .iter()
                .map(|s| {
                    let n = proto_to_num(s);
                    if n == 0 {
                        Err(anyhow!("Unknown proto '{s}'"))
                    } else {
                        Ok(n)
                    }
                })
                .collect::<Result<Vec<_>>>()?,
        );
        let src_cidr = vec_to_opt(parse_cidrs(&self.src_cidr, "src_cidr")?);
        let dst_cidr = vec_to_opt(parse_cidrs(&self.dst_cidr, "dst_cidr")?);
        let sni_glob = compile_globs(&self.sni_glob)?;

        Ok(CompiledMatchSpec {
            action,
            rule_id: vec_to_opt(self.rule_id),
            node_id: vec_to_opt(self.node_id),
            proto,
            sport: vec_to_opt(self.sport),
            dport: vec_to_opt(self.dport),
            sport_range: range_to_tuple(self.sport_range, "sport_range")?,
            dport_range: range_to_tuple(self.dport_range, "dport_range")?,
            src_cidr,
            dst_cidr,
            sni_glob,
            direction,
        })
    }
}

impl CompiledMatchSpec {
    /// AND across every set constraint. Returns true iff *every* field that
    /// is constrained matches the event.
    pub fn matches(&self, ev: &PolicyEvent) -> bool {
        if let Some(set) = &self.action {
            if !set.contains(&ev.action) {
                return false;
            }
        }
        if let Some(set) = &self.direction {
            if !set.contains(&ev.direction) {
                return false;
            }
        }
        if let Some(set) = &self.rule_id {
            if !set.contains(&ev.rule_id) {
                return false;
            }
        }
        if let Some(set) = &self.node_id {
            if !set.iter().any(|n| n == &ev.node_id) {
                return false;
            }
        }
        if let Some(set) = &self.proto {
            if !set.contains(&ev.proto) {
                return false;
            }
        }
        if let Some(set) = &self.sport {
            if !set.contains(&ev.sport) {
                return false;
            }
        }
        if let Some(set) = &self.dport {
            if !set.contains(&ev.dport) {
                return false;
            }
        }
        if let Some((lo, hi)) = self.sport_range {
            if ev.sport < lo || ev.sport > hi {
                return false;
            }
        }
        if let Some((lo, hi)) = self.dport_range {
            if ev.dport < lo || ev.dport > hi {
                return false;
            }
        }
        if let Some(nets) = &self.src_cidr {
            match blob_to_ip(&ev.src_ip) {
                Some(ip) if nets.iter().any(|n| n.contains(ip)) => {}
                _ => return false,
            }
        }
        if let Some(nets) = &self.dst_cidr {
            match blob_to_ip(&ev.dst_ip) {
                Some(ip) if nets.iter().any(|n| n.contains(ip)) => {}
                _ => return false,
            }
        }
        if let Some(globs) = &self.sni_glob {
            match &ev.sni {
                Some(sni) if globs.is_match(sni) => {}
                _ => return false,
            }
        }
        true
    }
}

fn vec_to_opt<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn parse_cidrs(raw: &[String], field: &str) -> Result<Vec<IpNetwork>> {
    raw.iter()
        .map(|s| {
            s.parse::<IpNetwork>()
                .with_context(|| format!("Invalid CIDR in {field}: '{s}'"))
        })
        .collect()
}

fn compile_globs(raw: &[String]) -> Result<Option<GlobSet>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut b = GlobSetBuilder::new();
    for pat in raw {
        let g = Glob::new(pat).with_context(|| format!("Invalid sni_glob pattern '{pat}'"))?;
        b.add(g);
    }
    Ok(Some(b.build().context("Failed to compile sni_glob set")?))
}

fn range_to_tuple(r: Option<[i64; 2]>, field: &str) -> Result<Option<(i64, i64)>> {
    match r {
        None => Ok(None),
        Some([lo, hi]) if lo <= hi => Ok(Some((lo, hi))),
        Some([lo, hi]) => Err(anyhow!(
            "{field} must be [lo, hi] with lo <= hi (got [{lo}, {hi}])"
        )),
    }
}

fn blob_to_ip(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => {
            let a: [u8; 4] = b.try_into().ok()?;
            Some(IpAddr::from(a))
        }
        16 => {
            let a: [u8; 16] = b.try_into().ok()?;
            Some(IpAddr::from(a))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt() -> PolicyEvent {
        PolicyEvent {
            ts_ns: 1,
            node_id: "n1".into(),
            rule_id: 42,
            action: Action::Drop,
            verdict: 1,
            direction: Direction::Ingress,
            ifindex: 3,
            proto: 6, // tcp
            src_ip: vec![10, 0, 0, 1],
            dst_ip: vec![192, 168, 1, 5],
            sport: 51000,
            dport: 22,
            pkt_len: 64,
            flags: None,
            sni: Some("login.evil.com".into()),
        }
    }

    fn compile(json: &str) -> CompiledMatchSpec {
        MatchSpec::compile_json(json).unwrap()
    }

    #[test]
    fn empty_spec_matches_everything() {
        let c = compile("{}");
        assert!(c.matches(&evt()));
    }

    #[test]
    fn action_set_filters() {
        let c = compile(r#"{"action":["drop"]}"#);
        assert!(c.matches(&evt()));
        let c = compile(r#"{"action":["log"]}"#);
        assert!(!c.matches(&evt()));
    }

    #[test]
    fn rule_id_and_node_id_anded() {
        let c = compile(r#"{"rule_id":[42],"node_id":["n1"]}"#);
        assert!(c.matches(&evt()));
        // Right rule, wrong node → no match (AND).
        let c = compile(r#"{"rule_id":[42],"node_id":["other"]}"#);
        assert!(!c.matches(&evt()));
    }

    #[test]
    fn proto_validates_at_compile_time() {
        let c = compile(r#"{"proto":["tcp"]}"#);
        assert!(c.matches(&evt()));
        // Unknown proto names are rejected, not silently mapped to 0.
        let err = MatchSpec::compile_json(r#"{"proto":["bogon"]}"#).unwrap_err();
        assert!(err.to_string().contains("Unknown proto"));
    }

    #[test]
    fn dport_set_and_range() {
        let c = compile(r#"{"dport":[22,23]}"#);
        assert!(c.matches(&evt()));
        let c = compile(r#"{"dport":[80,443]}"#);
        assert!(!c.matches(&evt()));

        let c = compile(r#"{"sport_range":[1024,65535]}"#);
        assert!(c.matches(&evt()));
        let c = compile(r#"{"sport_range":[0,1023]}"#);
        assert!(!c.matches(&evt()));
    }

    #[test]
    fn invalid_range_rejected() {
        let err = MatchSpec::compile_json(r#"{"sport_range":[100,50]}"#).unwrap_err();
        assert!(err.to_string().contains("lo <= hi"));
    }

    #[test]
    fn cidr_membership_v4() {
        let c = compile(r#"{"src_cidr":["10.0.0.0/8"]}"#);
        assert!(c.matches(&evt()));
        let c = compile(r#"{"src_cidr":["192.168.0.0/16"]}"#);
        assert!(!c.matches(&evt()));
        // Multiple CIDRs: OR within the field (any match wins), still ANDed
        // against other fields.
        let c = compile(r#"{"src_cidr":["172.16.0.0/12","10.0.0.0/8"]}"#);
        assert!(c.matches(&evt()));
    }

    #[test]
    fn cidr_v6_does_not_match_v4_event() {
        let c = compile(r#"{"src_cidr":["fd00::/8"]}"#);
        assert!(!c.matches(&evt()));
    }

    #[test]
    fn invalid_cidr_rejected() {
        let err = MatchSpec::compile_json(r#"{"src_cidr":["not-a-cidr"]}"#).unwrap_err();
        assert!(err.to_string().contains("Invalid CIDR"));
    }

    #[test]
    fn sni_glob_matches_suffix() {
        let c = compile(r#"{"sni_glob":["*.evil.com"]}"#);
        assert!(c.matches(&evt()));
        let c = compile(r#"{"sni_glob":["*.good.com"]}"#);
        assert!(!c.matches(&evt()));
    }

    #[test]
    fn sni_glob_with_no_sni_in_event_fails() {
        let c = compile(r#"{"sni_glob":["*"]}"#);
        let mut ev = evt();
        ev.sni = None;
        assert!(!c.matches(&ev));
    }

    #[test]
    fn direction_filters() {
        let c = compile(r#"{"direction":["ingress"]}"#);
        assert!(c.matches(&evt()));
        let c = compile(r#"{"direction":["egress"]}"#);
        assert!(!c.matches(&evt()));
    }

    #[test]
    fn unknown_field_rejected() {
        // Typoed field names must fail loudly — silently matching everything
        // because of a typo would be a footgun.
        let err = MatchSpec::compile_json(r#"{"actoin":["drop"]}"#).unwrap_err();
        assert!(err.to_string().contains("unknown field") || err.to_string().contains("MatchSpec"));
    }

    #[test]
    fn all_fields_together_anded() {
        let c = compile(
            r#"{
              "action":["drop"],
              "rule_id":[42],
              "node_id":["n1"],
              "proto":["tcp"],
              "dport":[22],
              "sport_range":[1024,65535],
              "src_cidr":["10.0.0.0/8"],
              "dst_cidr":["192.168.0.0/16"],
              "sni_glob":["*.evil.com"],
              "direction":["ingress"]
            }"#,
        );
        assert!(c.matches(&evt()));
        // Flip one field and the AND fails.
        let mut ev = evt();
        ev.dport = 80;
        assert!(!c.matches(&ev));
    }
}
