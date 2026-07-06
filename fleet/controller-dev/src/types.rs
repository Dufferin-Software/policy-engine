// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use serde::{Deserialize, Serialize};

/// A managed node returned by the controller API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    pub label: Option<String>,
    pub hostname: Option<String>,
    pub dmi_uuid: Option<String>,
    pub status: Option<String>,
    pub cert_expiry: Option<String>,
    pub last_seen: Option<String>,
    pub enrolled_at: Option<String>,
    pub tpm_backed: Option<bool>,
    pub agent_version: Option<String>,
    pub os_pretty_name: Option<String>,
    pub kernel_version: Option<String>,
    pub dmi_sys_vendor: Option<String>,
    pub dmi_product_name: Option<String>,
    pub tenant_id: Option<String>,
    pub stop_behavior: Option<String>,
}

/// A policy rule scoped to a node, interface, and direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub node_id: Option<String>,
    pub interface_name: Option<String>,
    pub direction: Option<String>,
    pub protocol: Option<String>,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    pub sni_pattern: Option<String>,
    pub quic_version: Option<String>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub actions_json: Option<String>,
    pub created_at: Option<String>,
    pub created_by: Option<String>,
}

impl Rule {
    /// A `Display`-able, compact summary of this rule's match criteria,
    /// e.g. `tcp dst:443 sni:*.example.com`. Catch-all CIDRs (`0.0.0.0/0`,
    /// `::/0`) are omitted since they match anything.
    pub fn criteria(&self) -> RuleCriteria<'_> {
        RuleCriteria(self)
    }

    /// A human-readable rendering of this rule's actions, ordered by
    /// priority, e.g. `log, drop` or `log(rate:500ms), drop`. Falls back to
    /// the raw JSON if it cannot be parsed.
    pub fn actions_summary(&self) -> String {
        let raw = match self.actions_json.as_deref() {
            Some(s) => s,
            None => return "—".to_string(),
        };
        let mut actions: Vec<RuleActionJson> = match serde_json::from_str(raw) {
            Ok(a) => a,
            Err(_) => return raw.to_string(),
        };
        if actions.is_empty() {
            return "—".to_string();
        }
        actions.sort_by_key(|a| a.priority);
        actions
            .iter()
            .map(RuleActionJson::summary)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// One entry in a rule's `actions_json` array.
#[derive(Debug, Clone, Deserialize)]
struct RuleActionJson {
    action: String,
    #[serde(default)]
    param: i64,
    #[serde(default)]
    priority: i64,
}

impl RuleActionJson {
    fn summary(&self) -> String {
        let name = self.action.to_ascii_lowercase();
        // For LOG, `param` is the rate-limit interval in milliseconds
        // (0 = unlimited); surface it so operators can see throttling.
        if name == "log" && self.param > 0 {
            format!("log(rate:{}ms)", self.param)
        } else {
            name
        }
    }
}

/// Borrowed view over a [`Rule`]'s match criteria, rendered by its
/// [`Display`](std::fmt::Display) impl as a compact human-readable summary.
pub struct RuleCriteria<'a>(&'a Rule);

impl std::fmt::Display for RuleCriteria<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = self.0;
        let mut parts: Vec<String> = Vec::new();

        if let Some(proto) = r.protocol.as_deref() {
            if !proto.is_empty() && !proto.eq_ignore_ascii_case("any") {
                parts.push(proto.to_ascii_lowercase());
            }
        }
        if let Some(cidr) = r.src_cidr.as_deref() {
            if !is_any_cidr(cidr) {
                parts.push(format!("src:{cidr}"));
            }
        }
        if let Some(cidr) = r.dst_cidr.as_deref() {
            if !is_any_cidr(cidr) {
                parts.push(format!("dst:{cidr}"));
            }
        }
        if let Some(p) = r.src_port {
            parts.push(format!("sport:{p}"));
        }
        if let Some(p) = r.dst_port {
            parts.push(format!("dport:{p}"));
        }
        if let Some(sni) = r.sni_pattern.as_deref() {
            if !sni.is_empty() {
                parts.push(format!("sni:{sni}"));
            }
        }
        if let Some(q) = r.quic_version.as_deref() {
            if !q.is_empty() {
                parts.push(format!("quic:{q}"));
            }
        }
        if let Some(m) = r.src_mac.as_deref() {
            if !m.is_empty() {
                parts.push(format!("smac:{m}"));
            }
        }
        if let Some(m) = r.dst_mac.as_deref() {
            if !m.is_empty() {
                parts.push(format!("dmac:{m}"));
            }
        }

        if parts.is_empty() {
            write!(f, "any")
        } else {
            write!(f, "{}", parts.join(" "))
        }
    }
}

/// Whether `cidr` matches every address (`0.0.0.0/0` or `::/0`).
fn is_any_cidr(cidr: &str) -> bool {
    matches!(cidr.trim(), "0.0.0.0/0" | "::/0")
}

/// A network interface discovered on a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInterface {
    pub node_id: String,
    pub name: String,
    pub mac_address: Option<String>,
    pub link_state: Option<String>,
    pub tag: Option<String>,
    pub xdp_attached: Option<bool>,
    pub tc_attached: Option<bool>,
    pub fib_forwarding: Option<bool>,
    /// uRPF mode (ingress only): "off", "loose", or "strict".
    pub urpf_mode: Option<String>,
    pub ingress_default_action: Option<String>,
    pub egress_default_action: Option<String>,
    pub last_reported: Option<String>,
}

/// A single cached flow verdict entry read live from a node's BPF verdict cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeFlowVerdict {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: i32,
    pub dst_port: i32,
    pub protocol: String,
    pub action: String,
    /// Expiry time in nanoseconds (CLOCK_MONOTONIC); string to avoid precision loss.
    pub expires_ns: String,
    pub expired: bool,
    pub packets: u64,
    pub bytes: u64,
}

/// An audit log entry recording an operator action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: Option<i64>,
    pub ts: Option<String>,
    pub operator: Option<String>,
    pub action: Option<String>,
    pub node_id: Option<String>,
    pub detail: Option<String>,
}

/// An in-flight config mutation awaiting agent confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingGeneration {
    pub generation_id: Option<String>,
    pub node_id: Option<String>,
    pub op_kind: Option<String>,
    pub issued_at: Option<String>,
}

/// The result of a mutating operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    pub success: bool,
    pub message: Option<String>,
}

/// A persisted Suricata alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataAlert {
    pub id: String,
    pub node_id: String,
    pub timestamp: String,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<i32>,
    pub protocol: Option<String>,
    pub action: Option<String>,
    pub signature_id: Option<i32>,
    pub signature: Option<String>,
    pub category: Option<String>,
    pub severity: Option<i32>,
    /// True once an operator has acknowledged this alert.
    #[serde(default)]
    pub acked: bool,
}

/// A fleet-managed Suricata ruleset (listing form, no content).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataRulesetInfo {
    pub id: String,
    pub name: String,
    pub filename: String,
    pub sha256: String,
    pub rule_count: i32,
    pub assigned_node_ids: Vec<String>,
}

/// A fleet-managed Suricata ruleset with its full content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuricataRulesetDetail {
    pub id: String,
    pub name: String,
    pub filename: String,
    pub sha256: String,
    pub rule_count: i32,
    pub content: String,
    pub assigned_node_ids: Vec<String>,
}

/// Suricata inspect status for a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInspectStatus {
    /// Node-global inspect mode: "disabled", "ips", or "ids".
    pub inspect_mode: String,
    /// Raw JSON capabilities blob from the node's most recent AgentHello.
    pub capabilities: String,
    /// (interface name, inspection enabled) pairs.
    pub interfaces: Vec<(String, bool)>,
}

/// A ZTP enrollment token as listed by the controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentTokenInfo {
    pub token_id: String,
    pub created_at: Option<String>,
    pub created_by: Option<String>,
    pub expires_at: Option<String>,
    pub uses_remaining: i64,
    pub cidr_scope: Option<String>,
    pub fleet_label: Option<String>,
    pub revoked_at: Option<String>,
}

/// The result of minting a new ZTP token. `bundle` is shown to the operator
/// exactly once and must be distributed to target hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedEnrollmentToken {
    pub token_id: String,
    pub bundle: String,
    pub expires_at: Option<String>,
    pub uses_remaining: i64,
}

/// Input for creating a rule on a single node.
#[derive(Debug, Clone)]
pub struct CreateRuleInput {
    pub node_id: String,
    pub interface: String,
    pub direction: String,
    pub actions_json: String,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    pub protocol: Option<String>,
    pub sni_pattern: Option<String>,
    pub quic_version: Option<String>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
}

/// Input for creating the same rule on multiple nodes simultaneously.
#[derive(Debug, Clone)]
pub struct CreateRuleMultiNodeInput {
    pub node_ids: Vec<String>,
    pub interface: String,
    pub direction: String,
    pub actions_json: String,
    pub src_cidr: Option<String>,
    pub dst_cidr: Option<String>,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    pub protocol: Option<String>,
    pub sni_pattern: Option<String>,
    pub quic_version: Option<String>,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_rule() -> Rule {
        Rule {
            id: "1".into(),
            node_id: None,
            interface_name: None,
            direction: None,
            protocol: None,
            src_cidr: None,
            dst_cidr: None,
            src_port: None,
            dst_port: None,
            sni_pattern: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            actions_json: None,
            created_at: None,
            created_by: None,
        }
    }

    #[test]
    fn criteria_omits_catch_all_cidrs_and_any_proto() {
        let mut r = blank_rule();
        r.protocol = Some("tcp".into());
        r.src_cidr = Some("0.0.0.0/0".into());
        r.dst_cidr = Some("::/0".into());
        r.dst_port = Some(443);
        assert_eq!(r.criteria().to_string(), "tcp dport:443");

        r.protocol = Some("any".into());
        r.dst_port = None;
        r.src_cidr = None;
        r.dst_cidr = None;
        assert_eq!(r.criteria().to_string(), "any");
    }

    #[test]
    fn criteria_includes_sni_and_specific_cidr() {
        let mut r = blank_rule();
        r.protocol = Some("TCP".into());
        r.dst_port = Some(443);
        r.sni_pattern = Some("*.example.com".into());
        r.dst_cidr = Some("10.0.0.0/8".into());
        assert_eq!(
            r.criteria().to_string(),
            "tcp dst:10.0.0.0/8 dport:443 sni:*.example.com"
        );
    }

    #[test]
    fn actions_summary_orders_by_priority_and_shows_log_rate() {
        let mut r = blank_rule();
        r.actions_json = Some(
            r#"[{"action":"drop","param":0,"priority":1},{"action":"log","param":500,"priority":0}]"#
                .into(),
        );
        assert_eq!(r.actions_summary(), "log(rate:500ms), drop");
    }

    #[test]
    fn actions_summary_handles_empty_and_invalid() {
        let mut r = blank_rule();
        r.actions_json = Some("[]".into());
        assert_eq!(r.actions_summary(), "—");

        r.actions_json = None;
        assert_eq!(r.actions_summary(), "—");

        r.actions_json = Some("not json".into());
        assert_eq!(r.actions_summary(), "not json");
    }
}
