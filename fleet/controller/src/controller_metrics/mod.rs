// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Controller-native Prometheus metrics.
//!
//! Generates a Prometheus text exposition block covering state that only the
//! controller possesses: fleet-level node counts, per-node online/offline
//! status, rule counts, certificate expiry, and node info labels.
//!
//! The output is appended to the `/metrics` response after the forwarded
//! per-node engine metrics, so a single Prometheus scrape job on the
//! controller endpoint captures the entire fleet.

use std::sync::Arc;

use crate::{
    session::NodeSessionManager,
    store::{ControllerStore, NodeStatus},
};

/// Escape a string for use as a Prometheus label value.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Render controller-native Prometheus metrics as UTF-8 text.
///
/// Queries the store once for all nodes and once per active node for rule
/// counts; online/offline state is read from the in-memory session manager
/// without a database round-trip.
pub async fn render(
    store: &Arc<dyn ControllerStore>,
    sessions: &Arc<NodeSessionManager>,
) -> String {
    // None = cross-tenant: controller_metrics emits fleet-wide gauges,
    // not per-tenant. See ControllerStore::list_nodes.
    let nodes = match store.list_nodes(None, None).await {
        Ok(n) => n,
        Err(e) => {
            log::error!("controller_metrics: failed to list nodes: {e}");
            return String::new();
        }
    };

    let mut out = String::new();

    // ── Fleet-level totals ─────────────────────────────────────────────────────

    let mut pending_count: u64 = 0;
    let mut active_count: u64 = 0;
    let mut decommissioned_count: u64 = 0;
    for node in &nodes {
        match node.status {
            NodeStatus::Pending => pending_count += 1,
            NodeStatus::Active => active_count += 1,
            NodeStatus::Decommissioned => decommissioned_count += 1,
        }
    }
    let online_count = sessions.online_count_all_tenants() as u64;

    out.push_str("# HELP fleet_nodes_total Number of managed nodes by enrollment status.\n");
    out.push_str("# TYPE fleet_nodes_total gauge\n");
    out.push_str(&format!(
        "fleet_nodes_total{{status=\"active\"}} {active_count}\n"
    ));
    out.push_str(&format!(
        "fleet_nodes_total{{status=\"pending\"}} {pending_count}\n"
    ));
    out.push_str(&format!(
        "fleet_nodes_total{{status=\"decommissioned\"}} {decommissioned_count}\n"
    ));
    out.push('\n');

    out.push_str(
        "# HELP fleet_nodes_online_total Number of nodes currently connected to the controller.\n",
    );
    out.push_str("# TYPE fleet_nodes_online_total gauge\n");
    out.push_str(&format!("fleet_nodes_online_total {online_count}\n"));
    out.push('\n');

    // ── Per-node metrics (active nodes only) ───────────────────────────────────

    let active_nodes: Vec<_> = nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Active)
        .collect();

    if active_nodes.is_empty() {
        return out;
    }

    // fleet_node_online
    out.push_str("# HELP fleet_node_online Whether a node is currently connected to the controller (1 = online, 0 = offline).\n");
    out.push_str("# TYPE fleet_node_online gauge\n");
    for node in &active_nodes {
        let online = u8::from(sessions.is_online(&node.id));
        let hostname = escape_label(node.hostname.as_deref().unwrap_or(""));
        let label = escape_label(node.label.as_deref().unwrap_or(""));
        out.push_str(&format!(
            "fleet_node_online{{node_id=\"{}\",hostname=\"{hostname}\",label=\"{label}\"}} {online}\n",
            node.id
        ));
    }
    out.push('\n');

    // fleet_node_rule_count
    out.push_str("# HELP fleet_node_rule_count Number of rules currently assigned to the node.\n");
    out.push_str("# TYPE fleet_node_rule_count gauge\n");
    for node in &active_nodes {
        match store.list_rules_for_node(&node.id).await {
            Ok(rules) => {
                let count = rules.len();
                let hostname = escape_label(node.hostname.as_deref().unwrap_or(""));
                let label = escape_label(node.label.as_deref().unwrap_or(""));
                out.push_str(&format!(
                    "fleet_node_rule_count{{node_id=\"{}\",hostname=\"{hostname}\",label=\"{label}\"}} {count}\n",
                    node.id
                ));
            }
            Err(e) => {
                log::warn!(
                    "controller_metrics: failed to list rules for node {}: {e}",
                    node.id
                );
            }
        }
    }
    out.push('\n');

    // fleet_node_cert_expiry_seconds
    out.push_str("# HELP fleet_node_cert_expiry_seconds Unix timestamp of the node mTLS certificate expiry.\n");
    out.push_str("# TYPE fleet_node_cert_expiry_seconds gauge\n");
    for node in &active_nodes {
        if let Some(expiry) = node.cert_expiry {
            let hostname = escape_label(node.hostname.as_deref().unwrap_or(""));
            out.push_str(&format!(
                "fleet_node_cert_expiry_seconds{{node_id=\"{}\",hostname=\"{hostname}\"}} {}\n",
                node.id,
                expiry.timestamp()
            ));
        }
    }
    out.push('\n');

    // fleet_node_last_seen_seconds
    out.push_str("# HELP fleet_node_last_seen_seconds Unix timestamp of the last heartbeat received from the node.\n");
    out.push_str("# TYPE fleet_node_last_seen_seconds gauge\n");
    for node in &active_nodes {
        if let Some(last_seen) = node.last_seen {
            let hostname = escape_label(node.hostname.as_deref().unwrap_or(""));
            out.push_str(&format!(
                "fleet_node_last_seen_seconds{{node_id=\"{}\",hostname=\"{hostname}\"}} {}\n",
                node.id,
                last_seen.timestamp()
            ));
        }
    }
    out.push('\n');

    // fleet_node_info
    out.push_str(
        "# HELP fleet_node_info Static information about a managed node (value is always 1).\n",
    );
    out.push_str("# TYPE fleet_node_info gauge\n");
    for node in &active_nodes {
        let hostname = escape_label(node.hostname.as_deref().unwrap_or(""));
        let label = escape_label(node.label.as_deref().unwrap_or(""));
        let agent_version = escape_label(node.agent_version.as_deref().unwrap_or(""));
        let os_pretty_name = escape_label(node.os_pretty_name.as_deref().unwrap_or(""));
        let kernel_version = escape_label(node.kernel_version.as_deref().unwrap_or(""));
        let tpm_backed = if node.tpm_backed { "true" } else { "false" };
        out.push_str(&format!(
            "fleet_node_info{{node_id=\"{}\",hostname=\"{hostname}\",label=\"{label}\",agent_version=\"{agent_version}\",os_pretty_name=\"{os_pretty_name}\",kernel_version=\"{kernel_version}\",tpm_backed=\"{tpm_backed}\"}} 1\n",
            node.id
        ));
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InMemoryControllerStore, NodeRecord, NodeStatus};

    fn active_node(id: &str, hostname: &str, label: Option<&str>) -> NodeRecord {
        NodeRecord {
            id: id.to_string(),
            label: label.map(str::to_string),
            public_key_der: vec![],
            dmi_uuid: None,
            status: NodeStatus::Active,
            cert_serial: None,
            cert_expiry: None,
            last_seen: None,
            enrolled_at: None,
            decommissioned_at: None,

            last_renewed_at: None,
            enrollment_id: None,
            tpm_backed: false,
            agent_version: Some("1.0.0".to_string()),
            hostname: Some(hostname.to_string()),
            os_pretty_name: Some("Debian GNU/Linux 13".to_string()),
            kernel_version: Some("6.12.0".to_string()),
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
        }
    }

    #[tokio::test]
    async fn test_empty_fleet() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let sessions = Arc::new(NodeSessionManager::new());

        let out = render(&store, &sessions).await;

        assert!(out.contains("fleet_nodes_total{status=\"active\"} 0"));
        assert!(out.contains("fleet_nodes_total{status=\"pending\"} 0"));
        assert!(out.contains("fleet_nodes_online_total 0"));
        // No per-node blocks when there are no active nodes.
        assert!(!out.contains("fleet_node_online{"));
    }

    #[tokio::test]
    async fn test_online_node() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let sessions = Arc::new(NodeSessionManager::new());

        store
            .upsert_node(&active_node("n1", "host1.example.com", Some("fw-01")))
            .await
            .unwrap();

        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        sessions.register("n1".to_string(), "default".to_string(), tx);

        let out = render(&store, &sessions).await;

        assert!(out.contains("fleet_nodes_total{status=\"active\"} 1"));
        assert!(out.contains("fleet_nodes_online_total 1"));
        assert!(out.contains(
            "fleet_node_online{node_id=\"n1\",hostname=\"host1.example.com\",label=\"fw-01\"} 1"
        ));
        assert!(out.contains("fleet_node_rule_count{node_id=\"n1\""));
        assert!(out.contains(
            "fleet_node_info{node_id=\"n1\",hostname=\"host1.example.com\",label=\"fw-01\""
        ));
    }

    #[tokio::test]
    async fn test_offline_node() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let sessions = Arc::new(NodeSessionManager::new());

        store
            .upsert_node(&active_node("n1", "host1", None))
            .await
            .unwrap();
        // Node exists but is not connected.

        let out = render(&store, &sessions).await;

        assert!(out.contains("fleet_nodes_online_total 0"));
        assert!(out.contains("fleet_node_online{node_id=\"n1\",hostname=\"host1\",label=\"\"} 0"));
    }

    #[test]
    fn test_escape_label_backslash() {
        assert_eq!(escape_label("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_escape_label_quote() {
        assert_eq!(escape_label(r#"say "hi""#), r#"say \"hi\""#);
    }

    #[test]
    fn test_escape_label_newline() {
        assert_eq!(escape_label("line\nbreak"), "line\\nbreak");
    }

    #[test]
    fn test_escape_label_clean() {
        assert_eq!(escape_label("hostname.example.com"), "hostname.example.com");
    }
}
