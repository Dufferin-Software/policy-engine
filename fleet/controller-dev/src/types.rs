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
    pub ingress_default_action: Option<String>,
    pub egress_default_action: Option<String>,
    pub last_reported: Option<String>,
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
