// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use policy_controller_proto::controller::InterfaceReport;
use std::collections::HashMap;
use std::sync::Mutex;

use super::{
    rule_content_equal, AuditEntry, ControllerStore, DiffSummary, EnrollmentTokenRecord,
    NewAuditEntry, NewSuricataAlert, NodeInterface, NodeRecord, NodeStatus, Rule,
    SuricataAlertFilter, SuricataAlertRecord, SuricataRuleFileReport, SuricataRuleset,
    TokenRedeemOutcome,
};

/// In-memory implementation of [`ControllerStore`] for use in unit tests.
///
/// All data is lost when the store is dropped. Thread-safe via `Mutex`.
#[derive(Default)]
pub struct InMemoryControllerStore {
    inner: Mutex<InMemoryState>,
}

#[derive(Default)]
struct InMemoryState {
    nodes: HashMap<String, NodeRecord>,
    /// Maps enrollment_id → node_id
    enrollment_index: HashMap<String, String>,
    rules: HashMap<String, Rule>,
    revoked_serials: Vec<Vec<u8>>,
    /// Maps node_id → cert PEM
    node_certs: HashMap<String, String>,
    /// Maps (node_id, interface_name) → NodeInterface
    interfaces: HashMap<(String, String), NodeInterface>,
    audit_log: Vec<AuditEntry>,
    next_audit_id: i64,
    enrollment_tokens: HashMap<String, EnrollmentTokenRecord>,
    suricata_rulesets: HashMap<String, SuricataRuleset>,
    /// (node_id, ruleset_id) assignment pairs.
    suricata_assignments: Vec<(String, String)>,
    /// Maps node_id → agent-reported rule files.
    suricata_rule_files: HashMap<String, Vec<SuricataRuleFileReport>>,
    suricata_alerts: Vec<SuricataAlertRecord>,
    next_alert_id: i64,
}

impl InMemoryControllerStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ControllerStore for InMemoryControllerStore {
    // ── Nodes ────────────────────────────────────────────────────────────────

    async fn upsert_node(&self, node: &NodeRecord) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        if let Some(ref eid) = node.enrollment_id {
            state.enrollment_index.insert(eid.clone(), node.id.clone());
        }
        state.nodes.insert(node.id.clone(), node.clone());
        Ok(())
    }

    async fn get_node(&self, id: &str) -> Result<Option<NodeRecord>> {
        Ok(self.inner.lock().unwrap().nodes.get(id).cloned())
    }

    async fn get_node_by_enrollment_id(&self, enrollment_id: &str) -> Result<Option<NodeRecord>> {
        let state = self.inner.lock().unwrap();
        let node_id = match state.enrollment_index.get(enrollment_id) {
            Some(id) => id.clone(),
            None => return Ok(None),
        };
        Ok(state.nodes.get(&node_id).cloned())
    }

    async fn list_nodes(
        &self,
        tenant_id: Option<&str>,
        status: Option<NodeStatus>,
    ) -> Result<Vec<NodeRecord>> {
        let state = self.inner.lock().unwrap();
        Ok(state
            .nodes
            .values()
            .filter(|n| status.as_ref().is_none_or(|s| &n.status == s))
            .filter(|n| tenant_id.is_none_or(|t| n.tenant_id == t))
            .cloned()
            .collect())
    }

    async fn update_node_status(&self, id: &str, status: NodeStatus) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?
            .status = status;
        Ok(())
    }

    async fn update_node_tenant(&self, id: &str, tenant_id: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?
            .tenant_id = tenant_id.to_string();
        Ok(())
    }

    async fn delete_node(&self, id: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        if state.nodes.remove(id).is_none() {
            anyhow::bail!("Node not found: {}", id);
        }
        state.rules.retain(|_, r| r.node_id != id);
        state.interfaces.retain(|(nid, _), _| nid != id);
        state.node_certs.remove(id);
        state.enrollment_index.retain(|_, v| v != id);
        Ok(())
    }

    async fn update_node_stop_behavior(&self, id: &str, behavior: Option<&str>) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?
            .stop_behavior = behavior.map(|s| s.to_string());
        Ok(())
    }

    async fn update_node_metrics_interval(&self, id: &str, secs: Option<u32>) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?
            .metrics_interval_secs = secs;
        Ok(())
    }

    async fn update_node_last_seen(&self, id: &str, ts: DateTime<Utc>) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?
            .last_seen = Some(ts);
        Ok(())
    }

    async fn update_node_agent_info(
        &self,
        id: &str,
        tpm_backed: bool,
        agent_version: Option<&str>,
        hostname: Option<&str>,
        os_pretty_name: Option<&str>,
        kernel_version: Option<&str>,
        dmi_sys_vendor: Option<&str>,
        dmi_product_name: Option<&str>,
        dmi_uuid: Option<&str>,
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let node = state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?;
        node.tpm_backed = tpm_backed;
        // COALESCE-style: only overwrite when caller has a value, mirroring
        // the SQLite path so an agent that can't read a field (e.g.
        // product_uuid before CAP_DAC_READ_SEARCH) doesn't wipe what
        // enrollment populated.
        if let Some(v) = agent_version {
            node.agent_version = Some(v.to_string());
        }
        if let Some(v) = hostname {
            node.hostname = Some(v.to_string());
        }
        if let Some(v) = os_pretty_name {
            node.os_pretty_name = Some(v.to_string());
        }
        if let Some(v) = kernel_version {
            node.kernel_version = Some(v.to_string());
        }
        if let Some(v) = dmi_sys_vendor {
            node.dmi_sys_vendor = Some(v.to_string());
        }
        if let Some(v) = dmi_product_name {
            node.dmi_product_name = Some(v.to_string());
        }
        if let Some(v) = dmi_uuid {
            node.dmi_uuid = Some(v.to_string());
        }
        Ok(())
    }

    async fn update_node_capabilities(&self, id: &str, capabilities_json: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let node = state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?;
        node.capabilities = capabilities_json.to_string();
        Ok(())
    }

    async fn list_active_node_sources(
        &self,
        tenant_id: &str,
    ) -> Result<std::collections::HashSet<String>> {
        let state = self.inner.lock().unwrap();
        let mut out = std::collections::HashSet::new();
        for node in state.nodes.values() {
            if node.tenant_id != tenant_id || node.status != NodeStatus::Active {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&node.capabilities) else {
                continue;
            };
            if let Some(arr) = v.get("sources").and_then(|s| s.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        out.insert(s.to_string());
                    }
                }
            }
        }
        Ok(out)
    }

    async fn update_node_cert(
        &self,
        id: &str,
        serial: Vec<u8>,
        expiry: DateTime<Utc>,
        cert_pem: String,
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let node = state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?;
        node.cert_serial = Some(serial);
        node.cert_expiry = Some(expiry);
        state.node_certs.insert(id.to_string(), cert_pem);
        Ok(())
    }

    async fn update_current_cert_meta(
        &self,
        id: &str,
        serial: Vec<u8>,
        expiry: DateTime<Utc>,
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let node = state
            .nodes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Node not found: {}", id))?;
        node.cert_serial = Some(serial);
        node.cert_expiry = Some(expiry);
        Ok(())
    }

    // ── Cert revocation ──────────────────────────────────────────────────────

    async fn revoke_cert(&self, serial: &[u8]) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .revoked_serials
            .push(serial.to_vec());
        Ok(())
    }

    async fn is_cert_revoked(&self, serial: &[u8]) -> Result<bool> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .revoked_serials
            .contains(&serial.to_vec()))
    }

    async fn list_revoked_serials(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.inner.lock().unwrap().revoked_serials.clone())
    }

    // ── Rules ────────────────────────────────────────────────────────────────

    async fn create_rule(&self, rule: &Rule) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .rules
            .insert(rule.id.clone(), rule.clone());
        Ok(())
    }

    async fn delete_rule(&self, rule_id: &str) -> Result<()> {
        self.inner.lock().unwrap().rules.remove(rule_id);
        Ok(())
    }

    async fn get_rule(&self, rule_id: &str) -> Result<Option<Rule>> {
        Ok(self.inner.lock().unwrap().rules.get(rule_id).cloned())
    }

    async fn list_rules_for_node(&self, node_id: &str) -> Result<Vec<Rule>> {
        let state = self.inner.lock().unwrap();
        Ok(state
            .rules
            .values()
            .filter(|r| r.node_id == node_id)
            .cloned()
            .collect())
    }

    async fn list_rules_for_interface(
        &self,
        node_id: &str,
        interface_name: &str,
        direction: &str,
    ) -> Result<Vec<Rule>> {
        let state = self.inner.lock().unwrap();
        Ok(state
            .rules
            .values()
            .filter(|r| {
                r.node_id == node_id
                    && r.interface_name == interface_name
                    && r.direction == direction
            })
            .cloned()
            .collect())
    }

    async fn delete_rules_for_node(&self, node_id: &str) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .rules
            .retain(|_, r| r.node_id != node_id);
        Ok(())
    }

    async fn replace_rules_for_node(
        &self,
        node_id: &str,
        new_rules: &[Rule],
    ) -> Result<DiffSummary> {
        for r in new_rules {
            if r.node_id != node_id {
                anyhow::bail!(
                    "replace_rules_for_node: rule {} has node_id {} != {}",
                    r.id,
                    r.node_id,
                    node_id
                );
            }
        }

        let mut state = self.inner.lock().unwrap();
        let mut summary = DiffSummary::default();
        let new_ids: std::collections::HashSet<&str> =
            new_rules.iter().map(|r| r.id.as_str()).collect();

        let to_delete: Vec<String> = state
            .rules
            .values()
            .filter(|r| r.node_id == node_id && !new_ids.contains(r.id.as_str()))
            .map(|r| r.id.clone())
            .collect();
        for id in &to_delete {
            state.rules.remove(id);
        }
        summary.deleted = to_delete.len();

        for rule in new_rules {
            match state.rules.get(&rule.id) {
                Some(existing) if rule_content_equal(existing, rule) => {
                    summary.unchanged += 1;
                }
                Some(_) => {
                    state.rules.insert(rule.id.clone(), rule.clone());
                    summary.updated += 1;
                }
                None => {
                    state.rules.insert(rule.id.clone(), rule.clone());
                    summary.added += 1;
                }
            }
        }

        Ok(summary)
    }

    // ── Node interfaces ──────────────────────────────────────────────────────

    async fn upsert_node_interfaces(
        &self,
        node_id: &str,
        interfaces: &[InterfaceReport],
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let now = Utc::now();
        for iface in interfaces {
            let addresses_json = super::address_reports_to_json(&iface.addresses);
            let key = (node_id.to_string(), iface.name.clone());
            let existing = state.interfaces.get(&key);
            let existing_tag = existing.and_then(|i| i.tag.clone());
            let xdp = existing.is_some_and(|i| i.xdp_attached);
            let tc = existing.is_some_and(|i| i.tc_attached);
            let fib = existing.is_some_and(|i| i.fib_forwarding);
            let urpf = existing.map(|i| i.urpf_mode).unwrap_or(0);
            let inspect = existing.is_some_and(|i| i.inspect_enabled);
            let ingress_da = existing.and_then(|i| i.ingress_default_action.clone());
            let egress_da = existing.and_then(|i| i.egress_default_action.clone());
            state.interfaces.insert(
                key,
                NodeInterface {
                    node_id: node_id.to_string(),
                    name: iface.name.clone(),
                    ifindex: iface.ifindex,
                    mac_address: if iface.mac_address.is_empty() {
                        None
                    } else {
                        Some(iface.mac_address.clone())
                    },
                    link_state: iface.link_state.clone(),
                    addresses_json,
                    tag: existing_tag,
                    last_reported: now,
                    xdp_attached: xdp,
                    tc_attached: tc,
                    fib_forwarding: fib,
                    urpf_mode: urpf,
                    inspect_enabled: inspect,
                    ingress_default_action: ingress_da,
                    egress_default_action: egress_da,
                },
            );
        }
        Ok(())
    }

    async fn list_all_node_interfaces(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<NodeInterface>> {
        let state = self.inner.lock().unwrap();
        let mut result: Vec<NodeInterface> = state
            .interfaces
            .values()
            .filter(|i| match tenant_id {
                None => true,
                Some(t) => state
                    .nodes
                    .get(&i.node_id)
                    .map(|n| n.tenant_id == t)
                    .unwrap_or(false),
            })
            .cloned()
            .collect();
        result.sort_by(|a, b| a.node_id.cmp(&b.node_id).then(a.name.cmp(&b.name)));
        Ok(result)
    }

    async fn list_node_interfaces(&self, node_id: &str) -> Result<Vec<NodeInterface>> {
        let state = self.inner.lock().unwrap();
        let mut result: Vec<NodeInterface> = state
            .interfaces
            .values()
            .filter(|i| i.node_id == node_id)
            .cloned()
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn set_interface_tag(
        &self,
        node_id: &str,
        interface_name: &str,
        tag: &str,
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let key = (node_id.to_string(), interface_name.to_string());
        state
            .interfaces
            .get_mut(&key)
            .ok_or_else(|| anyhow!("Interface not found: {}:{}", node_id, interface_name))?
            .tag = Some(tag.to_string());
        Ok(())
    }

    async fn remove_interface_tag(&self, node_id: &str, interface_name: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let key = (node_id.to_string(), interface_name.to_string());
        if let Some(iface) = state.interfaces.get_mut(&key) {
            iface.tag = None;
        }
        Ok(())
    }

    async fn update_interface_fib_forwarding(
        &self,
        node_id: &str,
        enabled_interfaces: &[String],
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let enabled: std::collections::HashSet<&str> =
            enabled_interfaces.iter().map(|s| s.as_str()).collect();
        for iface in state.interfaces.values_mut() {
            if iface.node_id == node_id {
                iface.fib_forwarding = enabled.contains(iface.name.as_str());
            }
        }
        Ok(())
    }

    async fn update_interface_urpf(
        &self,
        node_id: &str,
        interface_modes: &[(String, u32)],
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let modes: std::collections::HashMap<&str, u32> = interface_modes
            .iter()
            .map(|(name, mode)| (name.as_str(), *mode))
            .collect();
        for iface in state.interfaces.values_mut() {
            if iface.node_id == node_id {
                iface.urpf_mode = modes.get(iface.name.as_str()).copied().unwrap_or(0);
            }
        }
        Ok(())
    }

    async fn set_node_inspect_mode(&self, node_id: &str, mode: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        if let Some(node) = state.nodes.get_mut(node_id) {
            node.inspect_mode = mode.to_string();
        }
        Ok(())
    }

    async fn update_interface_inspect(
        &self,
        node_id: &str,
        enabled_interfaces: &[String],
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let enabled: std::collections::HashSet<&str> =
            enabled_interfaces.iter().map(|s| s.as_str()).collect();
        for iface in state.interfaces.values_mut() {
            if iface.node_id == node_id {
                iface.inspect_enabled = enabled.contains(iface.name.as_str());
            }
        }
        Ok(())
    }

    async fn update_interface_inspect_enabled(
        &self,
        node_id: &str,
        interface_name: &str,
        enabled: bool,
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        for iface in state.interfaces.values_mut() {
            if iface.node_id == node_id && iface.name == interface_name {
                iface.inspect_enabled = enabled;
            }
        }
        Ok(())
    }

    async fn create_suricata_ruleset(&self, ruleset: &SuricataRuleset) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        if state
            .suricata_rulesets
            .values()
            .any(|r| r.tenant_id == ruleset.tenant_id && r.name == ruleset.name)
        {
            anyhow::bail!("Ruleset name '{}' already in use", ruleset.name);
        }
        state
            .suricata_rulesets
            .insert(ruleset.id.clone(), ruleset.clone());
        Ok(())
    }

    async fn update_suricata_ruleset(
        &self,
        id: &str,
        content: &str,
        sha256: &str,
        rule_count: u32,
        updated_at: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let rs = state
            .suricata_rulesets
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("Ruleset '{}' not found", id))?;
        rs.content = content.to_string();
        rs.sha256 = sha256.to_string();
        rs.rule_count = rule_count;
        rs.updated_at = updated_at;
        Ok(())
    }

    async fn delete_suricata_ruleset(&self, id: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        state.suricata_rulesets.remove(id);
        state.suricata_assignments.retain(|(_, r)| r != id);
        Ok(())
    }

    async fn get_suricata_ruleset(&self, id: &str) -> Result<Option<SuricataRuleset>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .suricata_rulesets
            .get(id)
            .cloned())
    }

    async fn list_suricata_rulesets(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<SuricataRuleset>> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<SuricataRuleset> = state
            .suricata_rulesets
            .values()
            .filter(|r| tenant_id.is_none_or(|t| r.tenant_id == t))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn assign_suricata_ruleset(&self, node_id: &str, ruleset_id: &str) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let pair = (node_id.to_string(), ruleset_id.to_string());
        if !state.suricata_assignments.contains(&pair) {
            state.suricata_assignments.push(pair);
        }
        Ok(())
    }

    async fn unassign_suricata_ruleset(&self, node_id: &str, ruleset_id: &str) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .suricata_assignments
            .retain(|(n, r)| !(n == node_id && r == ruleset_id));
        Ok(())
    }

    async fn list_suricata_rulesets_for_node(&self, node_id: &str) -> Result<Vec<SuricataRuleset>> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<SuricataRuleset> = state
            .suricata_assignments
            .iter()
            .filter(|(n, _)| n == node_id)
            .filter_map(|(_, r)| state.suricata_rulesets.get(r).cloned())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn list_nodes_for_suricata_ruleset(&self, ruleset_id: &str) -> Result<Vec<String>> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<String> = state
            .suricata_assignments
            .iter()
            .filter(|(_, r)| r == ruleset_id)
            .map(|(n, _)| n.clone())
            .collect();
        out.sort();
        Ok(out)
    }

    async fn replace_node_suricata_rule_files(
        &self,
        node_id: &str,
        files: &[SuricataRuleFileReport],
    ) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .suricata_rule_files
            .insert(node_id.to_string(), files.to_vec());
        Ok(())
    }

    async fn list_node_suricata_rule_files(
        &self,
        node_id: &str,
    ) -> Result<Vec<SuricataRuleFileReport>> {
        let mut out = self
            .inner
            .lock()
            .unwrap()
            .suricata_rule_files
            .get(node_id)
            .cloned()
            .unwrap_or_default();
        out.sort_by(|a, b| a.filename.cmp(&b.filename));
        Ok(out)
    }

    async fn insert_suricata_alerts(&self, alerts: &[NewSuricataAlert]) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        for a in alerts {
            let id = state.next_alert_id;
            state.next_alert_id += 1;
            state.suricata_alerts.push(SuricataAlertRecord {
                id,
                tenant_id: a.tenant_id.clone(),
                node_id: a.node_id.clone(),
                timestamp: a.timestamp.clone(),
                received_ns: a.received_ns,
                src_ip: a.src_ip.clone(),
                src_port: a.src_port,
                dst_ip: a.dst_ip.clone(),
                dst_port: a.dst_port,
                proto: a.proto.clone(),
                action: a.action.clone(),
                signature_id: a.signature_id,
                signature: a.signature.clone(),
                category: a.category.clone(),
                severity: a.severity,
                raw_json: a.raw_json.clone(),
                acked_at: None,
            });
        }
        Ok(())
    }

    async fn list_suricata_alerts(
        &self,
        filter: &SuricataAlertFilter,
        limit: i64,
    ) -> Result<Vec<SuricataAlertRecord>> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<SuricataAlertRecord> = state
            .suricata_alerts
            .iter()
            .filter(|a| filter.include_acked || a.acked_at.is_none())
            .filter(|a| filter.tenant_id.as_ref().is_none_or(|t| &a.tenant_id == t))
            .filter(|a| filter.node_id.as_ref().is_none_or(|n| &a.node_id == n))
            .filter(|a| {
                filter
                    .min_severity
                    .is_none_or(|s| a.severity.is_some_and(|v| v <= s))
            })
            .filter(|a| {
                filter
                    .signature_id
                    .is_none_or(|sid| a.signature_id == Some(sid))
            })
            .filter(|a| {
                filter
                    .signature_contains
                    .as_ref()
                    .is_none_or(|sig| a.signature.as_ref().is_some_and(|s| s.contains(sig)))
            })
            .cloned()
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.received_ns));
        out.truncate(limit.max(0) as usize);
        Ok(out)
    }

    async fn ack_suricata_alerts(
        &self,
        tenant_id: &str,
        node_id: Option<&str>,
        acked_ns: i64,
    ) -> Result<u64> {
        let mut state = self.inner.lock().unwrap();
        let mut updated = 0;
        for a in state.suricata_alerts.iter_mut().filter(|a| {
            a.acked_at.is_none()
                && a.tenant_id == tenant_id
                && node_id.is_none_or(|n| a.node_id == n)
        }) {
            a.acked_at = Some(acked_ns);
            updated += 1;
        }
        Ok(updated)
    }

    async fn clear_suricata_alerts(&self, tenant_id: &str, node_id: Option<&str>) -> Result<u64> {
        let mut state = self.inner.lock().unwrap();
        let before = state.suricata_alerts.len();
        state
            .suricata_alerts
            .retain(|a| a.tenant_id != tenant_id || node_id.is_some_and(|n| a.node_id != n));
        Ok((before - state.suricata_alerts.len()) as u64)
    }

    async fn update_interface_attachments(
        &self,
        node_id: &str,
        attachments: &[(String, String)],
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        // Reset all attachments for this node.
        for iface in state.interfaces.values_mut() {
            if iface.node_id == node_id {
                iface.xdp_attached = false;
                iface.tc_attached = false;
            }
        }
        // Set the ones that are actually attached.
        for (iface_name, dir) in attachments {
            let key = (node_id.to_string(), iface_name.clone());
            if let Some(iface) = state.interfaces.get_mut(&key) {
                match dir.to_lowercase().as_str() {
                    "ingress" => iface.xdp_attached = true,
                    "egress" => iface.tc_attached = true,
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn update_interface_default_action(
        &self,
        node_id: &str,
        interface_name: &str,
        direction: &str,
        action: &str,
    ) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        let key = (node_id.to_string(), interface_name.to_string());
        let iface = state
            .interfaces
            .get_mut(&key)
            .ok_or_else(|| anyhow!("Interface not found: {}:{}", node_id, interface_name))?;
        match direction.to_lowercase().as_str() {
            "ingress" => iface.ingress_default_action = Some(action.to_string()),
            "egress" => iface.egress_default_action = Some(action.to_string()),
            _ => anyhow::bail!("Invalid direction: {}", direction),
        }
        Ok(())
    }

    // ── Certs ────────────────────────────────────────────────────────────────

    async fn store_node_cert_pem(&self, node_id: &str, cert_pem: &str) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .node_certs
            .insert(node_id.to_string(), cert_pem.to_string());
        Ok(())
    }

    async fn get_node_cert_pem(&self, node_id: &str) -> Result<Option<String>> {
        Ok(self.inner.lock().unwrap().node_certs.get(node_id).cloned())
    }

    // ── Audit log ────────────────────────────────────────────────────────────

    async fn append_audit(&self, entry: NewAuditEntry) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        // Same resolution order as sqlite::append_audit (see NewAuditEntry
        // docs): explicit > derived from node > 'default'.
        let tenant_id = entry
            .tenant_id
            .or_else(|| {
                entry
                    .node_id
                    .as_deref()
                    .and_then(|nid| state.nodes.get(nid).map(|n| n.tenant_id.clone()))
            })
            .unwrap_or_else(|| "default".to_string());
        let id = state.next_audit_id;
        state.next_audit_id += 1;
        state.audit_log.push(AuditEntry {
            id,
            ts: Utc::now(),
            operator: entry.operator,
            action: entry.action,
            node_id: entry.node_id,
            detail: entry.detail,
            tenant_id,
        });
        Ok(())
    }

    async fn list_audit(
        &self,
        tenant_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditEntry>> {
        let state = self.inner.lock().unwrap();
        let entries: Vec<AuditEntry> = state
            .audit_log
            .iter()
            .rev()
            .filter(|e| tenant_id.is_none_or(|t| e.tenant_id == t))
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(entries)
    }

    async fn list_audit_between(
        &self,
        tenant_id: Option<&str>,
        from: Option<i64>,
        to: Option<i64>,
        cap: u32,
    ) -> Result<Vec<AuditEntry>> {
        let state = self.inner.lock().unwrap();
        let entries: Vec<AuditEntry> = state
            .audit_log
            .iter()
            .rev()
            .filter(|e| tenant_id.is_none_or(|t| e.tenant_id == t))
            .filter(|e| {
                let ts = e.ts.timestamp();
                from.is_none_or(|f| ts >= f) && to.is_none_or(|t| ts <= t)
            })
            .take(cap as usize)
            .cloned()
            .collect();
        Ok(entries)
    }

    // ── Enrollment tokens ────────────────────────────────────────────────────

    async fn insert_enrollment_token(&self, token: &EnrollmentTokenRecord) -> Result<()> {
        let mut state = self.inner.lock().unwrap();
        if state.enrollment_tokens.contains_key(&token.token_id) {
            anyhow::bail!("Duplicate enrollment token id: {}", token.token_id);
        }
        state
            .enrollment_tokens
            .insert(token.token_id.clone(), token.clone());
        Ok(())
    }

    async fn list_enrollment_tokens(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<EnrollmentTokenRecord>> {
        let state = self.inner.lock().unwrap();
        let mut out: Vec<_> = state
            .enrollment_tokens
            .values()
            .filter(|t| tenant_id.is_none_or(|slug| t.tenant_id == slug))
            .cloned()
            .collect();
        out.sort_by_key(|t| std::cmp::Reverse(t.created_at));
        Ok(out)
    }

    async fn revoke_enrollment_token(&self, token_id: &str) -> Result<bool> {
        let mut state = self.inner.lock().unwrap();
        if let Some(t) = state.enrollment_tokens.get_mut(token_id) {
            if t.revoked_at.is_none() {
                t.revoked_at = Some(Utc::now());
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn redeem_enrollment_token(
        &self,
        token_id: &str,
        token_hash: &[u8],
    ) -> Result<TokenRedeemOutcome> {
        use subtle::ConstantTimeEq;
        let mut state = self.inner.lock().unwrap();
        let Some(t) = state.enrollment_tokens.get_mut(token_id) else {
            return Ok(TokenRedeemOutcome::Unknown);
        };
        if t.token_hash.as_slice().ct_eq(token_hash).unwrap_u8() == 0 {
            return Ok(TokenRedeemOutcome::BadSecret);
        }
        if t.revoked_at.is_some() {
            return Ok(TokenRedeemOutcome::Revoked);
        }
        if t.expires_at <= Utc::now() {
            return Ok(TokenRedeemOutcome::Expired);
        }
        if t.uses_remaining <= 0 {
            return Ok(TokenRedeemOutcome::Exhausted);
        }
        t.uses_remaining -= 1;
        Ok(TokenRedeemOutcome::Redeemed {
            fleet_label: t.fleet_label.clone(),
            tenant_id: t.tenant_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_node(id: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_string(),
            label: None,
            public_key_der: vec![1, 2, 3],
            dmi_uuid: None,
            status: NodeStatus::Pending,
            cert_serial: None,
            cert_expiry: None,
            last_seen: None,
            enrolled_at: None,
            decommissioned_at: None,

            last_renewed_at: None,
            enrollment_id: Some(format!("enroll-{}", id)),
            tpm_backed: false,
            agent_version: Some("0.1.0".to_string()),
            hostname: None,
            os_pretty_name: None,
            kernel_version: None,
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
            inspect_mode: "disabled".to_string(),
        }
    }

    fn sample_rule(id: &str, node_id: &str, iface: &str, direction: &str) -> Rule {
        Rule {
            id: id.to_string(),
            tenant_id: "default".to_string(),
            node_id: node_id.to_string(),
            interface_name: iface.to_string(),
            direction: direction.to_string(),
            src_cidr: Some("10.0.0.0/8".to_string()),
            dst_cidr: None,
            src_port: None,
            dst_port: Some(80),
            protocol: "tcp".to_string(),
            sni_pattern: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            actions_json: r#"[{"action":"drop","priority":0}]"#.to_string(),
            created_at: Utc::now(),
            created_by: Some("test".to_string()),
            expires_after_secs: None,
            schedule_json: None,
        }
    }

    #[tokio::test]
    async fn test_upsert_and_get_node() {
        let store = InMemoryControllerStore::new();
        let node = sample_node("abc123");
        store.upsert_node(&node).await.unwrap();

        let got = store.get_node("abc123").await.unwrap().unwrap();
        assert_eq!(got.id, "abc123");
        assert_eq!(got.status, NodeStatus::Pending);
    }

    #[tokio::test]
    async fn test_get_missing_node_returns_none() {
        let store = InMemoryControllerStore::new();
        assert!(store.get_node("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_update_node_status() {
        let store = InMemoryControllerStore::new();
        store.upsert_node(&sample_node("n1")).await.unwrap();
        store
            .update_node_status("n1", NodeStatus::Active)
            .await
            .unwrap();

        let node = store.get_node("n1").await.unwrap().unwrap();
        assert_eq!(node.status, NodeStatus::Active);
    }

    #[tokio::test]
    async fn test_list_nodes_with_status_filter() {
        let store = InMemoryControllerStore::new();
        store.upsert_node(&sample_node("p1")).await.unwrap();
        let mut active = sample_node("a1");
        active.status = NodeStatus::Active;
        store.upsert_node(&active).await.unwrap();

        let pending = store
            .list_nodes(None, Some(NodeStatus::Pending))
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "p1");

        let all = store.list_nodes(None, None).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_cert_revocation() {
        let store = InMemoryControllerStore::new();
        let serial = vec![1, 2, 3, 4];
        assert!(!store.is_cert_revoked(&serial).await.unwrap());
        store.revoke_cert(&serial).await.unwrap();
        assert!(store.is_cert_revoked(&serial).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_crud() {
        let store = InMemoryControllerStore::new();
        let rule = sample_rule("r1", "n1", "eth0", "ingress");
        store.create_rule(&rule).await.unwrap();

        let got = store.get_rule("r1").await.unwrap().unwrap();
        assert_eq!(got.node_id, "n1");
        assert_eq!(got.interface_name, "eth0");

        let node_rules = store.list_rules_for_node("n1").await.unwrap();
        assert_eq!(node_rules.len(), 1);

        let iface_rules = store
            .list_rules_for_interface("n1", "eth0", "ingress")
            .await
            .unwrap();
        assert_eq!(iface_rules.len(), 1);

        let empty = store
            .list_rules_for_interface("n1", "eth0", "egress")
            .await
            .unwrap();
        assert!(empty.is_empty());

        store.delete_rule("r1").await.unwrap();
        assert!(store.get_rule("r1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_delete_rules_for_node() {
        let store = InMemoryControllerStore::new();
        store
            .create_rule(&sample_rule("r1", "n1", "eth0", "ingress"))
            .await
            .unwrap();
        store
            .create_rule(&sample_rule("r2", "n1", "eth1", "egress"))
            .await
            .unwrap();
        store
            .create_rule(&sample_rule("r3", "n2", "eth0", "ingress"))
            .await
            .unwrap();

        store.delete_rules_for_node("n1").await.unwrap();
        assert!(store.list_rules_for_node("n1").await.unwrap().is_empty());
        assert_eq!(store.list_rules_for_node("n2").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_node_interfaces() {
        let store = InMemoryControllerStore::new();
        let interfaces = vec![
            InterfaceReport {
                name: "eth0".to_string(),
                addresses: vec![],
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                link_state: "up".to_string(),
                ifindex: 2,
            },
            InterfaceReport {
                name: "lo".to_string(),
                addresses: vec![],
                mac_address: String::new(),
                link_state: "unknown".to_string(),
                ifindex: 1,
            },
        ];

        store
            .upsert_node_interfaces("n1", &interfaces)
            .await
            .unwrap();
        let result = store.list_node_interfaces("n1").await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "eth0");
        assert_eq!(result[0].mac_address.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[tokio::test]
    async fn test_interface_tagging() {
        let store = InMemoryControllerStore::new();
        let interfaces = vec![InterfaceReport {
            name: "eth0".to_string(),
            addresses: vec![],
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            link_state: "up".to_string(),
            ifindex: 2,
        }];
        store
            .upsert_node_interfaces("n1", &interfaces)
            .await
            .unwrap();

        store.set_interface_tag("n1", "eth0", "WAN").await.unwrap();
        let result = store.list_node_interfaces("n1").await.unwrap();
        assert_eq!(result[0].tag.as_deref(), Some("WAN"));

        store.remove_interface_tag("n1", "eth0").await.unwrap();
        let result = store.list_node_interfaces("n1").await.unwrap();
        assert!(result[0].tag.is_none());
    }

    #[tokio::test]
    async fn test_audit_log_ordering() {
        let store = InMemoryControllerStore::new();
        for i in 0..5u32 {
            store
                .append_audit(NewAuditEntry {
                    operator: None,
                    action: format!("action-{}", i),
                    node_id: None,
                    detail: None,
                    tenant_id: None,
                })
                .await
                .unwrap();
        }
        let log = store.list_audit(None, 3, 0).await.unwrap();
        assert_eq!(log.len(), 3);
        assert!(log[0].action.contains("4"));
    }

    #[tokio::test]
    async fn test_audit_list_between_filters_and_caps() {
        let store = InMemoryControllerStore::new();
        for i in 0..5u32 {
            store
                .append_audit(NewAuditEntry {
                    operator: None,
                    action: format!("action-{}", i),
                    node_id: None,
                    detail: None,
                    tenant_id: Some("acme".to_string()),
                })
                .await
                .unwrap();
        }
        // A row in a different tenant must stay invisible to acme-scoped reads.
        store
            .append_audit(NewAuditEntry {
                operator: None,
                action: "other".to_string(),
                node_id: None,
                detail: None,
                tenant_id: Some("globex".to_string()),
            })
            .await
            .unwrap();

        let now = Utc::now().timestamp();

        // Wide-open window, tenant-scoped, capped: newest-first, 3 of 5 rows.
        let capped = store
            .list_audit_between(Some("acme"), None, None, 3)
            .await
            .unwrap();
        assert_eq!(capped.len(), 3);
        assert!(capped[0].action.contains("4"));

        // A window straddling "now" returns all acme rows and only acme rows.
        let in_window = store
            .list_audit_between(Some("acme"), Some(now - 60), Some(now + 60), 100)
            .await
            .unwrap();
        assert_eq!(in_window.len(), 5);
        assert!(in_window.iter().all(|e| e.tenant_id == "acme"));

        // A window entirely in the past matches nothing.
        let empty = store
            .list_audit_between(Some("acme"), Some(0), Some(now - 3600), 100)
            .await
            .unwrap();
        assert!(empty.is_empty());

        // Cross-tenant (None) sees every tenant's rows.
        let all = store
            .list_audit_between(None, None, None, 100)
            .await
            .unwrap();
        assert_eq!(all.len(), 6);
    }

    /// B3 resolution: explicit > derived from node > 'default'. Exercised
    /// against the in-memory store; the sqlite path uses the same precedence
    /// via a COALESCE in the INSERT.
    #[tokio::test]
    async fn test_audit_tenant_resolution_precedence() {
        let store = InMemoryControllerStore::new();

        // A node row anchored to tenant "acme".
        let mut node = sample_node("acme-node-1");
        node.tenant_id = "acme".to_string();
        store.upsert_node(&node).await.unwrap();

        // 1. Explicit slug wins over everything else.
        store
            .append_audit(NewAuditEntry {
                operator: None,
                action: "iam.role.granted".to_string(),
                node_id: Some("acme-node-1".to_string()),
                detail: None,
                tenant_id: Some("override-tenant".to_string()),
            })
            .await
            .unwrap();

        // 2. No explicit + node_id present → derived from the node.
        store
            .append_audit(NewAuditEntry {
                operator: None,
                action: "node.enrollment_approved".to_string(),
                node_id: Some("acme-node-1".to_string()),
                detail: None,
                tenant_id: None,
            })
            .await
            .unwrap();

        // 3. No explicit + unknown node_id → 'default' fallback.
        store
            .append_audit(NewAuditEntry {
                operator: None,
                action: "node.audit_after_decommission".to_string(),
                node_id: Some("ghost-node".to_string()),
                detail: None,
                tenant_id: None,
            })
            .await
            .unwrap();

        // 4. No explicit + no node_id → 'default' fallback.
        store
            .append_audit(NewAuditEntry {
                operator: None,
                action: "controller.startup".to_string(),
                node_id: None,
                detail: None,
                tenant_id: None,
            })
            .await
            .unwrap();

        let all = store.list_audit(None, 100, 0).await.unwrap();
        let tenant_for = |action: &str| {
            all.iter()
                .find(|e| e.action == action)
                .map(|e| e.tenant_id.as_str())
                .expect("audit entry for action present")
        };
        assert_eq!(tenant_for("iam.role.granted"), "override-tenant");
        assert_eq!(tenant_for("node.enrollment_approved"), "acme");
        assert_eq!(tenant_for("node.audit_after_decommission"), "default");
        assert_eq!(tenant_for("controller.startup"), "default");

        // The filter on list_audit honours the resolved tenant, not the
        // node's tenant (so an explicit-override row stays in the override
        // tenant's view even if the node belongs elsewhere).
        let actions_in = |slug: &str| -> Vec<String> {
            all.iter()
                .filter(|e| e.tenant_id == slug)
                .map(|e| e.action.clone())
                .collect()
        };
        let acme = actions_in("acme");
        assert!(acme.contains(&"node.enrollment_approved".to_string()));
        assert!(!acme.contains(&"iam.role.granted".to_string()));
        assert_eq!(actions_in("override-tenant"), vec!["iam.role.granted"]);
    }

    #[tokio::test]
    async fn test_replace_rules_for_node_noop() {
        let store = InMemoryControllerStore::new();
        store
            .create_rule(&sample_rule("r1", "n1", "eth0", "ingress"))
            .await
            .unwrap();
        let same = sample_rule("r1", "n1", "eth0", "ingress");
        let summary = store.replace_rules_for_node("n1", &[same]).await.unwrap();
        assert!(
            summary.is_noop(),
            "expected noop replace, got {:?}",
            summary
        );
        assert_eq!(summary.unchanged, 1);
    }

    #[tokio::test]
    async fn test_replace_rules_for_node_add_update_delete() {
        let store = InMemoryControllerStore::new();
        // Seed: r1 (will be updated), r2 (will be deleted), and a rule on
        // another node that must not be touched.
        store
            .create_rule(&sample_rule("r1", "n1", "eth0", "ingress"))
            .await
            .unwrap();
        store
            .create_rule(&sample_rule("r2", "n1", "eth1", "egress"))
            .await
            .unwrap();
        store
            .create_rule(&sample_rule("r9", "n2", "eth0", "ingress"))
            .await
            .unwrap();

        let mut updated_r1 = sample_rule("r1", "n1", "eth0", "ingress");
        updated_r1.dst_port = Some(8080); // content change
        let new_r3 = sample_rule("r3", "n1", "eth2", "ingress");

        let summary = store
            .replace_rules_for_node("n1", &[updated_r1, new_r3])
            .await
            .unwrap();
        assert_eq!(summary.added, 1, "r3 added");
        assert_eq!(summary.updated, 1, "r1 updated");
        assert_eq!(summary.deleted, 1, "r2 deleted");
        assert_eq!(summary.unchanged, 0);

        let after: std::collections::HashSet<String> = store
            .list_rules_for_node("n1")
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(after, ["r1", "r3"].iter().map(|s| s.to_string()).collect());

        // n2's rule survives.
        let n2 = store.list_rules_for_node("n2").await.unwrap();
        assert_eq!(n2.len(), 1);
        assert_eq!(n2[0].id, "r9");

        // The updated r1 actually has the new port.
        let r1 = store.get_rule("r1").await.unwrap().unwrap();
        assert_eq!(r1.dst_port, Some(8080));
    }

    #[tokio::test]
    async fn test_replace_rules_for_node_to_empty_deletes_all() {
        let store = InMemoryControllerStore::new();
        store
            .create_rule(&sample_rule("r1", "n1", "eth0", "ingress"))
            .await
            .unwrap();
        store
            .create_rule(&sample_rule("r2", "n1", "eth1", "egress"))
            .await
            .unwrap();
        let summary = store.replace_rules_for_node("n1", &[]).await.unwrap();
        assert_eq!(summary.deleted, 2);
        assert_eq!(summary.added, 0);
        assert_eq!(summary.updated, 0);
        assert!(store.list_rules_for_node("n1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_replace_rules_for_node_rejects_wrong_node() {
        let store = InMemoryControllerStore::new();
        let foreign = sample_rule("r1", "other", "eth0", "ingress");
        let err = store
            .replace_rules_for_node("n1", &[foreign])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("node_id"));
    }

    #[tokio::test]
    async fn test_get_node_by_enrollment_id() {
        let store = InMemoryControllerStore::new();
        let node = sample_node("n1");
        let eid = node.enrollment_id.clone().unwrap();
        store.upsert_node(&node).await.unwrap();

        let found = store
            .get_node_by_enrollment_id(&eid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, "n1");

        let missing = store.get_node_by_enrollment_id("no-such").await.unwrap();
        assert!(missing.is_none());
    }
}
