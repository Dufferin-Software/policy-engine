// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Delta computation between controller-desired state and agent-reported state.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use policy_controller_proto::controller::{DeltaConfigPush, RuleAdd, StateSnapshot};
use serde_json::{Map, Value};

use std::sync::Arc;

use crate::store::{ControllerStore, DiffSummary, NodeInterface, Rule};

/// Convert stored [`Rule`]s into proto [`RuleAdd`] messages.
pub fn rules_to_rule_adds(rules: &[Rule]) -> Vec<RuleAdd> {
    rules
        .iter()
        .map(|rule| {
            let add_rule_input = build_add_rule_json(rule);
            RuleAdd {
                rule_id: rule.id.clone(),
                interface_name: rule.interface_name.clone(),
                direction: rule.direction.to_uppercase(),
                params_json: add_rule_input.into_bytes(),
            }
        })
        .collect()
}

/// Compute the delta between desired rules (from the controller DB) and
/// the actual state reported by the agent in a [`StateSnapshot`].
///
/// Returns a [`DeltaConfigPush`] with:
/// - `rules_to_add`: rules in `desired` but missing from `actual`
/// - `rule_ids_to_delete`: rule IDs in `actual` but not in `desired`
pub fn compute_delta(desired: &[Rule], actual: &StateSnapshot) -> DeltaConfigPush {
    let desired_ids: HashSet<u64> = desired
        .iter()
        .filter_map(|r| r.id.parse::<u64>().ok())
        .collect();

    let actual_ids: HashSet<u64> = actual.rules.iter().map(|r| r.id).collect();

    // Rules to add: in desired but not in actual.
    let to_add: Vec<RuleAdd> = desired
        .iter()
        .filter(|r| {
            r.id.parse::<u64>()
                .map(|id| !actual_ids.contains(&id))
                .unwrap_or(true)
        })
        .map(|r| RuleAdd {
            rule_id: r.id.clone(),
            interface_name: r.interface_name.clone(),
            direction: r.direction.to_uppercase(),
            params_json: build_add_rule_json(r).into_bytes(),
        })
        .collect();

    // Rules to delete: in actual but not in desired.
    let to_delete: Vec<String> = actual_ids
        .iter()
        .filter(|id| !desired_ids.contains(id))
        .map(|id| id.to_string())
        .collect();

    DeltaConfigPush {
        rules_to_add: to_add,
        rule_ids_to_delete: to_delete,
        is_full_restore: false,
        per_interface_default_actions: std::collections::HashMap::new(),
        // Reconciliation deltas bypass the pending gate — see build_full_restore_push.
        generation_id: String::new(),
        confirm_deadline_ms: 0,
        stop_behavior: String::new(),
    }
}

/// Build a JSON string matching the policy-engine `AddRuleInput` format
/// from a controller [`Rule`].
fn build_add_rule_json(rule: &Rule) -> String {
    let mut obj = serde_json::Map::new();

    if let Ok(numeric_id) = rule.id.parse::<u64>() {
        obj.insert(
            "id".to_string(),
            serde_json::Value::Number(serde_json::Number::from(numeric_id)),
        );
    }

    obj.insert(
        "interface".to_string(),
        serde_json::Value::String(rule.interface_name.clone()),
    );
    obj.insert(
        "direction".to_string(),
        serde_json::Value::String(rule.direction.to_uppercase()),
    );

    if let Some(ref src) = rule.src_cidr {
        obj.insert("src".to_string(), serde_json::Value::String(src.clone()));
    }
    if let Some(ref dst) = rule.dst_cidr {
        obj.insert("dst".to_string(), serde_json::Value::String(dst.clone()));
    }

    obj.insert(
        "sport".to_string(),
        serde_json::Value::Number(serde_json::Number::from(rule.src_port.unwrap_or(0))),
    );
    obj.insert(
        "dport".to_string(),
        serde_json::Value::Number(serde_json::Number::from(rule.dst_port.unwrap_or(0))),
    );
    obj.insert(
        "protocol".to_string(),
        serde_json::Value::String(rule.protocol.clone()),
    );

    if let Some(ref sni) = rule.sni_pattern {
        obj.insert("sni".to_string(), serde_json::Value::String(sni.clone()));
    }
    if let Some(ref qv) = rule.quic_version {
        obj.insert(
            "quicVersion".to_string(),
            serde_json::Value::String(qv.clone()),
        );
    }
    if let Some(ref mac) = rule.src_mac {
        obj.insert("srcMac".to_string(), serde_json::Value::String(mac.clone()));
    }
    if let Some(ref mac) = rule.dst_mac {
        obj.insert("dstMac".to_string(), serde_json::Value::String(mac.clone()));
    }

    // Parse actions_json and normalise action names to UPPERCASE, which is
    // what the policy-engine's AddRuleInput (GqlPolicyAction) expects.
    if let Ok(serde_json::Value::Array(actions)) =
        serde_json::from_str::<serde_json::Value>(&rule.actions_json)
    {
        let normalised: Vec<serde_json::Value> = actions
            .into_iter()
            .map(|mut a| {
                let upper = a
                    .get("action")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_uppercase());
                if let Some(u) = upper {
                    a.as_object_mut()
                        .unwrap()
                        .insert("action".to_string(), serde_json::Value::String(u));
                }
                a
            })
            .collect();
        obj.insert("actions".to_string(), serde_json::Value::Array(normalised));
    }

    if let Some(ttl) = rule.expires_after_secs {
        obj.insert(
            "expiresAfterSecs".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ttl)),
        );
    }
    if let Some(ref sched) = rule.schedule_json {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(sched) {
            obj.insert("schedule".to_string(), v);
        }
    }

    serde_json::Value::Object(obj).to_string()
}

/// Optional string fields in the `AddRuleInput` JSON shape. Empty strings and
/// JSON `null` are treated as absent in the canonical form.
const OPTIONAL_STRING_KEYS: &[&str] = &["src", "dst", "sni", "quicVersion", "srcMac", "dstMac"];

/// Produce a canonical byte representation of an `AddRuleInput` JSON payload
/// for content-based comparison.
///
/// Normalization rules:
/// * The `id` field (rule identity) is removed; equality compares rule content.
/// * `direction` is uppercased; `actions[*].action` is uppercased.
/// * Optional string fields (`src`, `dst`, `sni`, `quicVersion`, `srcMac`,
///   `dstMac`) treat missing, `null`, and `""` as equivalent (all removed).
/// * `sport` / `dport`: missing or `null` becomes `0` (matches what the
///   forward codec emits for `None`).
/// * `actions` entries default `priority` to `0` and are sorted by
///   `(priority, action)` so list ordering is not significant.
/// * Object keys are emitted in sorted order (serde_json default with no
///   `preserve_order` feature).
pub fn canonicalize_add_rule_json(bytes: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
    let mut value: Value = serde_json::from_slice(bytes)?;
    canonicalize_value(&mut value);
    Ok(serde_json::to_vec(&value)?)
}

fn canonicalize_value(value: &mut Value) {
    let Value::Object(obj) = value else { return };

    obj.remove("id");

    if let Some(Value::String(s)) = obj.get_mut("direction") {
        *s = s.to_uppercase();
    }

    for key in OPTIONAL_STRING_KEYS {
        let drop = match obj.get(*key) {
            Some(Value::Null) => true,
            Some(Value::String(s)) if s.is_empty() => true,
            _ => false,
        };
        if drop {
            obj.remove(*key);
        }
    }

    for key in ["sport", "dport"] {
        match obj.get(key) {
            None | Some(Value::Null) => {
                obj.insert(key.to_string(), Value::Number(0u64.into()));
            }
            _ => {}
        }
    }

    if let Some(Value::Array(actions)) = obj.get_mut("actions") {
        for action in actions.iter_mut() {
            if let Value::Object(a) = action {
                if let Some(Value::String(s)) = a.get_mut("action") {
                    *s = s.to_uppercase();
                }
                a.entry("priority").or_insert(Value::Number(0u64.into()));
            }
        }
        actions.sort_by(|a, b| {
            let pa = a.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
            let pb = b.get("priority").and_then(|v| v.as_i64()).unwrap_or(0);
            let sa = a.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let sb = b.get("action").and_then(|v| v.as_str()).unwrap_or("");
            (pa, sa).cmp(&(pb, sb))
        });
    }
}

/// Parse an `AddRuleInput` JSON payload (as emitted by the agent's
/// `change_detector` or by [`build_add_rule_json`]) back into a controller
/// [`Rule`] row.
///
/// `node_id` / `tenant_id` / `created_at` are supplied by the caller because
/// they are not part of the `AddRuleInput` shape. The rule's numeric `id`,
/// `interface`, and `direction` MUST be present in the JSON.
pub fn rule_from_add_rule_json(
    node_id: &str,
    tenant_id: &str,
    params_json: &[u8],
    created_at: DateTime<Utc>,
) -> Result<Rule, RuleFromJsonError> {
    let value: Value = serde_json::from_slice(params_json)?;
    let Value::Object(obj) = value else {
        return Err(RuleFromJsonError::NotAnObject);
    };

    let id = obj
        .get("id")
        .and_then(|v| v.as_u64())
        .ok_or(RuleFromJsonError::MissingField("id"))?;

    let interface_name = required_string(&obj, "interface")?;
    let direction = required_string(&obj, "direction")?.to_lowercase();

    let src_cidr = optional_string(&obj, "src");
    let dst_cidr = optional_string(&obj, "dst");
    let sni_pattern = optional_string(&obj, "sni");
    let quic_version = optional_string(&obj, "quicVersion");
    let src_mac = optional_string(&obj, "srcMac");
    let dst_mac = optional_string(&obj, "dstMac");

    let src_port = port_field(&obj, "sport");
    let dst_port = port_field(&obj, "dport");

    let protocol = optional_string(&obj, "protocol").unwrap_or_else(|| "any".to_string());

    let actions_value = obj
        .get("actions")
        .cloned()
        .ok_or(RuleFromJsonError::MissingField("actions"))?;
    let actions_json = normalize_actions_for_db(actions_value)?;

    let expires_after_secs = obj
        .get("expiresAfterSecs")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok());

    let schedule_json = obj.get("schedule").and_then(|v| {
        if v.is_null() {
            None
        } else {
            serde_json::to_string(v).ok()
        }
    });

    Ok(Rule {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        node_id: node_id.to_string(),
        interface_name,
        direction,
        src_cidr,
        dst_cidr,
        src_port,
        dst_port,
        protocol,
        sni_pattern,
        quic_version,
        src_mac,
        dst_mac,
        actions_json,
        created_at,
        created_by: None,
        expires_after_secs,
        schedule_json,
    })
}

fn required_string(
    obj: &Map<String, Value>,
    key: &'static str,
) -> Result<String, RuleFromJsonError> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or(RuleFromJsonError::MissingField(key))
}

fn optional_string(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn port_field(obj: &Map<String, Value>, key: &str) -> Option<u32> {
    let n = obj.get(key).and_then(|v| v.as_u64())?;
    if n == 0 {
        None
    } else {
        u32::try_from(n).ok()
    }
}

fn normalize_actions_for_db(value: Value) -> Result<String, RuleFromJsonError> {
    let Value::Array(mut actions) = value else {
        return Err(RuleFromJsonError::InvalidActions);
    };
    for action in actions.iter_mut() {
        let Value::Object(a) = action else {
            return Err(RuleFromJsonError::InvalidActions);
        };
        if let Some(Value::String(s)) = a.get_mut("action") {
            *s = s.to_lowercase();
        }
    }
    serde_json::to_string(&Value::Array(actions)).map_err(RuleFromJsonError::Json)
}

/// Result of comparing the controller DB's desired rule set with the rules
/// the agent actually has loaded (per its [`StateSnapshot`]).
///
/// All vectors hold rule IDs (as strings) sorted ascending for determinism.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleDrift {
    /// Rule IDs present in the controller DB but missing from the agent.
    pub only_in_db: Vec<String>,
    /// Rule IDs present in the agent's snapshot but with no DB row.
    pub only_in_agent: Vec<String>,
    /// Rule IDs present on both sides whose canonicalized `AddRuleInput`
    /// payloads do not match.
    pub params_mismatch: Vec<String>,
}

impl RuleDrift {
    /// True when the DB and agent agree on every rule and its content.
    pub fn is_clean(&self) -> bool {
        self.only_in_db.is_empty()
            && self.only_in_agent.is_empty()
            && self.params_mismatch.is_empty()
    }
}

/// Drift between the controller DB's per-interface default actions and what
/// the agent currently has loaded. Keys are the snapshot's
/// `"interface:direction"` form (e.g. `"eth0:ingress"`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultActionDrift {
    /// `(key, db_value)` for entries present in the DB but missing from
    /// the snapshot's `per_interface_default_actions`.
    pub only_in_db: Vec<(String, String)>,
    /// `(key, agent_value)` for entries present in the snapshot but with
    /// no DB-side default action recorded.
    pub only_in_agent: Vec<(String, String)>,
    /// `(key, db_value, agent_value)` for entries present on both sides
    /// whose values differ.
    pub mismatch: Vec<(String, String, String)>,
}

impl DefaultActionDrift {
    pub fn is_clean(&self) -> bool {
        self.only_in_db.is_empty() && self.only_in_agent.is_empty() && self.mismatch.is_empty()
    }
}

/// Drift between the controller's desired stop behavior for a node and what
/// the agent reports. `None` on the DB side means the operator has not
/// configured one (the node uses its compiled-in default), which is
/// treated as compatible with any agent value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopBehaviorDrift {
    pub db: Option<String>,
    pub agent: String,
}

impl StopBehaviorDrift {
    /// True when both sides agree, or when the DB has no preference set.
    pub fn is_clean(&self) -> bool {
        match &self.db {
            None => true,
            Some(db) => db == &self.agent,
        }
    }
}

/// Compare the controller DB's desired rule set for a node against the
/// agent's [`StateSnapshot`]. Pure function — no I/O — so call sites can
/// decide what to do with the result (log, reconcile, alarm, etc.).
pub fn compute_drift(db_rules: &[Rule], snapshot: &StateSnapshot) -> RuleDrift {
    use std::collections::HashMap;

    let db_by_id: HashMap<u64, &Rule> = db_rules
        .iter()
        .filter_map(|r| r.id.parse::<u64>().ok().map(|id| (id, r)))
        .collect();
    let agent_by_id: HashMap<u64, &policy_controller_proto::controller::PersistedRule> =
        snapshot.rules.iter().map(|r| (r.id, r)).collect();

    let mut only_in_db = Vec::new();
    let mut only_in_agent = Vec::new();
    let mut params_mismatch = Vec::new();

    for (id, db_rule) in &db_by_id {
        match agent_by_id.get(id) {
            None => only_in_db.push(db_rule.id.clone()),
            Some(agent_rule) => {
                let db_canon =
                    canonicalize_add_rule_json(build_add_rule_json(db_rule).as_bytes()).ok();
                let agent_canon = canonicalize_add_rule_json(&agent_rule.params_json).ok();
                if db_canon.is_none() || agent_canon.is_none() || db_canon != agent_canon {
                    params_mismatch.push(db_rule.id.clone());
                }
            }
        }
    }
    for (id, _) in &agent_by_id {
        if !db_by_id.contains_key(id) {
            only_in_agent.push(id.to_string());
        }
    }

    only_in_db.sort();
    only_in_agent.sort();
    params_mismatch.sort();

    RuleDrift {
        only_in_db,
        only_in_agent,
        params_mismatch,
    }
}

/// Compare per-interface default actions recorded in the DB
/// (NodeInterface.{ingress,egress}_default_action) with the snapshot's
/// `per_interface_default_actions` map. Pure.
pub fn compute_default_action_drift(
    db_interfaces: &[NodeInterface],
    snapshot: &StateSnapshot,
) -> DefaultActionDrift {
    use std::collections::HashMap;

    let mut db_map: HashMap<String, String> = HashMap::new();
    for iface in db_interfaces {
        if let Some(a) = &iface.ingress_default_action {
            db_map.insert(format!("{}:ingress", iface.name), a.clone());
        }
        if let Some(a) = &iface.egress_default_action {
            db_map.insert(format!("{}:egress", iface.name), a.clone());
        }
    }

    let mut drift = DefaultActionDrift::default();
    for (k, db_v) in &db_map {
        match snapshot.per_interface_default_actions.get(k) {
            None => drift.only_in_db.push((k.clone(), db_v.clone())),
            Some(agent_v) if agent_v != db_v => {
                drift
                    .mismatch
                    .push((k.clone(), db_v.clone(), agent_v.clone()));
            }
            _ => {}
        }
    }
    for (k, agent_v) in &snapshot.per_interface_default_actions {
        if !db_map.contains_key(k) {
            drift.only_in_agent.push((k.clone(), agent_v.clone()));
        }
    }

    drift.only_in_db.sort();
    drift.only_in_agent.sort();
    drift.mismatch.sort();
    drift
}

/// Compare the DB's recorded stop behavior with the agent's reported one.
/// An empty `snapshot.stop_behavior` string ("not yet reported", per the
/// proto comment) is preserved verbatim so callers can distinguish
/// "agent silent" from a real disagreement.
pub fn compute_stop_behavior_drift(
    db_stop_behavior: Option<&str>,
    snapshot: &StateSnapshot,
) -> StopBehaviorDrift {
    StopBehaviorDrift {
        db: db_stop_behavior.map(|s| s.to_string()),
        agent: snapshot.stop_behavior.clone(),
    }
}

/// Outcome of [`apply_local_change`]: the rule-replace [`DiffSummary`] plus
/// counts of side-channel updates we applied (default actions overwritten on
/// the DB side, stop-behavior overwritten, snapshot rules we had to skip
/// because the JSON was unparseable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalChangeOutcome {
    pub rules: DiffSummary,
    pub default_actions_updated: usize,
    pub stop_behavior_updated: bool,
    pub skipped_rules: usize,
}

/// Errors produced by [`apply_local_change`].
#[derive(Debug, thiserror::Error)]
pub enum ApplyLocalChangeError {
    #[error("node {0} not found in store")]
    NodeNotFound(String),
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

/// Treat the agent's [`StateSnapshot`] as authoritative for the given node
/// and write it back into the controller DB.
///
/// Used by the management stream when an agent reports a `LocalChange` —
/// e.g. an operator changed the node's config out-of-band via `policy-client`.
/// The controller's prior view is discarded and replaced; the function does
/// not attempt to merge or to assert one side over the other.
///
/// Behavior:
/// * Rules: each [`PersistedRule`] is parsed via [`rule_from_add_rule_json`];
///   `created_at` is preserved for rules whose `id` already existed, otherwise
///   the supplied `now` timestamp is used. Snapshot rules whose `params_json`
///   fails to parse are logged and counted in
///   [`LocalChangeOutcome::skipped_rules`] but do not abort the rest of the
///   apply — a single bad row must not strand the whole sync.
///   The full rule set is then committed via
///   [`ControllerStore::replace_rules_for_node`] in one transaction.
/// * Per-interface default actions: every entry in
///   `snapshot.per_interface_default_actions` is written through
///   [`ControllerStore::update_interface_default_action`]. Keys not following
///   the `"iface:direction"` shape are skipped.
/// * Stop behavior: if `snapshot.stop_behavior` is non-empty and differs
///   from the node's recorded value, the node row is updated.
///
/// `created_by` is hard-coded to `"agent:local-change"` for any newly
/// inserted rule so the audit trail of `rules.created_by` distinguishes
/// operator-initiated rules from agent-sync inserts.
pub async fn apply_local_change(
    node_id: &str,
    snapshot: &StateSnapshot,
    store: &Arc<dyn ControllerStore>,
    now: DateTime<Utc>,
) -> Result<LocalChangeOutcome, ApplyLocalChangeError> {
    let node = store
        .get_node(node_id)
        .await?
        .ok_or_else(|| ApplyLocalChangeError::NodeNotFound(node_id.to_string()))?;

    let existing = store.list_rules_for_node(node_id).await?;
    let existing_created_at: std::collections::HashMap<String, DateTime<Utc>> = existing
        .iter()
        .map(|r| (r.id.clone(), r.created_at))
        .collect();

    let snapshot_ids: Vec<u64> = snapshot.rules.iter().map(|r| r.id).collect();
    let existing_ids: Vec<&str> = existing.iter().map(|r| r.id.as_str()).collect();
    log::info!(
        "apply_local_change[{node_id}]: snapshot_rules={} existing_rules={} \
         snapshot_ids={snapshot_ids:?} existing_ids={existing_ids:?}",
        snapshot.rules.len(),
        existing.len(),
    );

    let mut new_rules: Vec<Rule> = Vec::with_capacity(snapshot.rules.len());
    let mut skipped = 0usize;
    for persisted in &snapshot.rules {
        let id_str = persisted.id.to_string();
        let created_at = existing_created_at.get(&id_str).copied().unwrap_or(now);
        match rule_from_add_rule_json(node_id, &node.tenant_id, &persisted.params_json, created_at)
        {
            Ok(mut r) => {
                // Snapshot's PersistedRule.id is the authoritative identity;
                // the embedded JSON id should match but we trust the outer one.
                r.id = id_str;
                if !existing_created_at.contains_key(&r.id) {
                    r.created_by = Some("agent:local-change".to_string());
                }
                new_rules.push(r);
            }
            Err(e) => {
                log::warn!(
                    "apply_local_change: skipping rule {} from {} — unparseable params_json: {:#}",
                    persisted.id,
                    node_id,
                    e
                );
                skipped += 1;
            }
        }
    }

    let summary = store.replace_rules_for_node(node_id, &new_rules).await?;

    let mut default_actions_updated = 0usize;
    for (key, action) in &snapshot.per_interface_default_actions {
        let Some((iface, direction)) = key.split_once(':') else {
            log::warn!(
                "apply_local_change: ignoring malformed default-action key {:?} from {}",
                key,
                node_id
            );
            continue;
        };
        if let Err(e) = store
            .update_interface_default_action(node_id, iface, direction, action)
            .await
        {
            log::warn!(
                "apply_local_change: failed to set default action {}:{}={} on {}: {:#}",
                iface,
                direction,
                action,
                node_id,
                e
            );
            continue;
        }
        default_actions_updated += 1;
    }

    let mut stop_behavior_updated = false;
    if !snapshot.stop_behavior.is_empty()
        && node.stop_behavior.as_deref() != Some(snapshot.stop_behavior.as_str())
    {
        store
            .update_node_stop_behavior(node_id, Some(snapshot.stop_behavior.as_str()))
            .await?;
        stop_behavior_updated = true;
    }

    Ok(LocalChangeOutcome {
        rules: summary,
        default_actions_updated,
        stop_behavior_updated,
        skipped_rules: skipped,
    })
}

/// Errors produced by [`rule_from_add_rule_json`].
#[derive(Debug, thiserror::Error)]
pub enum RuleFromJsonError {
    #[error("AddRuleInput JSON is not an object")]
    NotAnObject,
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("`actions` is not an array of objects")]
    InvalidActions,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use policy_controller_proto::controller::PersistedRule;

    fn make_rule(id: u64) -> Rule {
        Rule {
            id: id.to_string(),
            tenant_id: "default".to_string(),
            node_id: "n1".to_string(),
            interface_name: "eth0".to_string(),
            direction: "ingress".to_string(),
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
            created_by: None,
            expires_after_secs: None,
            schedule_json: None,
        }
    }

    #[test]
    fn test_compute_delta_adds_missing() {
        let desired = vec![make_rule(100), make_rule(200)];
        let actual = StateSnapshot {
            rules: vec![PersistedRule {
                id: 999,
                params_json: vec![],
            }],
            attachments: vec![],
            default_actions: Default::default(),
            fib_forwarding_interfaces: Vec::new(),
            per_interface_default_actions: Default::default(),
            stop_behavior: String::new(),
        };

        let delta = compute_delta(&desired, &actual);
        assert_eq!(delta.rules_to_add.len(), 2);
        assert_eq!(delta.rule_ids_to_delete.len(), 1);
        assert_eq!(delta.rule_ids_to_delete[0], "999");
    }

    #[test]
    fn test_compute_delta_empty_actual() {
        let desired = vec![make_rule(100)];
        let actual = StateSnapshot {
            rules: vec![],
            attachments: vec![],
            default_actions: Default::default(),
            fib_forwarding_interfaces: Vec::new(),
            per_interface_default_actions: Default::default(),
            stop_behavior: String::new(),
        };

        let delta = compute_delta(&desired, &actual);
        assert_eq!(delta.rules_to_add.len(), 1);
        assert!(delta.rule_ids_to_delete.is_empty());
    }

    #[test]
    fn test_compute_delta_in_sync() {
        let desired = vec![make_rule(100)];
        let actual = StateSnapshot {
            rules: vec![PersistedRule {
                id: 100,
                params_json: vec![],
            }],
            attachments: vec![],
            default_actions: Default::default(),
            fib_forwarding_interfaces: Vec::new(),
            per_interface_default_actions: Default::default(),
            stop_behavior: String::new(),
        };

        let delta = compute_delta(&desired, &actual);
        assert!(delta.rules_to_add.is_empty());
        assert!(delta.rule_ids_to_delete.is_empty());
    }

    #[test]
    fn test_roundtrip_rule_via_add_rule_json() {
        let mut original = make_rule(100);
        original.dst_cidr = Some("192.168.1.0/24".to_string());
        original.sni_pattern = Some("example.com".to_string());
        original.expires_after_secs = Some(3600);

        let json = build_add_rule_json(&original);
        let parsed = rule_from_add_rule_json(
            &original.node_id,
            &original.tenant_id,
            json.as_bytes(),
            original.created_at,
        )
        .expect("parse");

        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.interface_name, original.interface_name);
        assert_eq!(parsed.direction, original.direction);
        assert_eq!(parsed.src_cidr, original.src_cidr);
        assert_eq!(parsed.dst_cidr, original.dst_cidr);
        assert_eq!(parsed.src_port, original.src_port);
        assert_eq!(parsed.dst_port, original.dst_port);
        assert_eq!(parsed.protocol, original.protocol);
        assert_eq!(parsed.sni_pattern, original.sni_pattern);
        assert_eq!(parsed.expires_after_secs, original.expires_after_secs);

        let parsed_actions: serde_json::Value = serde_json::from_str(&parsed.actions_json).unwrap();
        let original_actions: serde_json::Value =
            serde_json::from_str(&original.actions_json).unwrap();
        assert_eq!(parsed_actions, original_actions);
    }

    #[test]
    fn test_rule_from_add_rule_json_missing_id() {
        let err = rule_from_add_rule_json(
            "n1",
            "default",
            br#"{"interface":"eth0","direction":"INGRESS","actions":[]}"#,
            Utc::now(),
        )
        .unwrap_err();
        assert!(matches!(err, RuleFromJsonError::MissingField("id")));
    }

    #[test]
    fn test_rule_from_add_rule_json_malformed() {
        let err = rule_from_add_rule_json("n1", "default", b"not json", Utc::now()).unwrap_err();
        assert!(matches!(err, RuleFromJsonError::Json(_)));
    }

    #[test]
    fn test_canonicalize_drops_id_and_sorts_keys() {
        let a = br#"{"id":1,"protocol":"tcp","interface":"eth0","direction":"INGRESS","sport":0,"dport":0,"actions":[]}"#;
        let b =
            br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","actions":[],"id":999}"#;
        let ca = canonicalize_add_rule_json(a).unwrap();
        let cb = canonicalize_add_rule_json(b).unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn test_canonicalize_port_equivalence() {
        // missing, null, and 0 are all equivalent for port fields.
        let missing =
            br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","actions":[]}"#;
        let null = br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","sport":null,"dport":null,"actions":[]}"#;
        let zero = br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","sport":0,"dport":0,"actions":[]}"#;
        let c1 = canonicalize_add_rule_json(missing).unwrap();
        let c2 = canonicalize_add_rule_json(null).unwrap();
        let c3 = canonicalize_add_rule_json(zero).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn test_canonicalize_optional_string_equivalence() {
        // missing, null, and "" are all equivalent for optional string fields.
        let missing =
            br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","actions":[]}"#;
        let null = br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","sni":null,"src":null,"actions":[]}"#;
        let empty = br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","sni":"","src":"","actions":[]}"#;
        let c1 = canonicalize_add_rule_json(missing).unwrap();
        let c2 = canonicalize_add_rule_json(null).unwrap();
        let c3 = canonicalize_add_rule_json(empty).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c2, c3);
    }

    #[test]
    fn test_canonicalize_action_order_and_case() {
        let a = br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","actions":[{"action":"log","priority":5},{"action":"DROP","priority":0}]}"#;
        let b = br#"{"interface":"eth0","direction":"INGRESS","protocol":"tcp","actions":[{"action":"drop","priority":0},{"action":"LOG","priority":5}]}"#;
        let ca = canonicalize_add_rule_json(a).unwrap();
        let cb = canonicalize_add_rule_json(b).unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn test_canonicalize_matches_forward_codec() {
        // build_add_rule_json output canonicalizes to itself (minus `id`).
        let rule = make_rule(100);
        let forward = build_add_rule_json(&rule);
        let canon1 = canonicalize_add_rule_json(forward.as_bytes()).unwrap();
        let canon2 = canonicalize_add_rule_json(&canon1).unwrap();
        assert_eq!(canon1, canon2);
    }

    fn snapshot_with(rules: Vec<PersistedRule>) -> StateSnapshot {
        StateSnapshot {
            rules,
            attachments: vec![],
            default_actions: Default::default(),
            fib_forwarding_interfaces: Vec::new(),
            per_interface_default_actions: Default::default(),
            stop_behavior: String::new(),
        }
    }

    fn persisted_from(rule: &Rule) -> PersistedRule {
        PersistedRule {
            id: rule.id.parse().unwrap(),
            params_json: build_add_rule_json(rule).into_bytes(),
        }
    }

    #[test]
    fn test_compute_drift_identical() {
        let r = make_rule(100);
        let snap = snapshot_with(vec![persisted_from(&r)]);
        let drift = compute_drift(&[r], &snap);
        assert!(drift.is_clean(), "expected clean drift, got {:?}", drift);
    }

    #[test]
    fn test_compute_drift_only_in_db() {
        let r = make_rule(100);
        let snap = snapshot_with(vec![]);
        let drift = compute_drift(&[r], &snap);
        assert_eq!(drift.only_in_db, vec!["100".to_string()]);
        assert!(drift.only_in_agent.is_empty());
        assert!(drift.params_mismatch.is_empty());
    }

    #[test]
    fn test_compute_drift_only_in_agent() {
        let r = make_rule(100);
        let snap = snapshot_with(vec![persisted_from(&r)]);
        let drift = compute_drift(&[], &snap);
        assert_eq!(drift.only_in_agent, vec!["100".to_string()]);
        assert!(drift.only_in_db.is_empty());
        assert!(drift.params_mismatch.is_empty());
    }

    #[test]
    fn test_compute_drift_params_mismatch() {
        let r = make_rule(100);
        // Agent has same id but different port — content drift.
        let mut other = r.clone();
        other.dst_port = Some(443);
        let snap = snapshot_with(vec![persisted_from(&other)]);
        let drift = compute_drift(&[r], &snap);
        assert_eq!(drift.params_mismatch, vec!["100".to_string()]);
        assert!(drift.only_in_db.is_empty());
        assert!(drift.only_in_agent.is_empty());
    }

    #[test]
    fn test_compute_drift_action_order_is_not_a_mismatch() {
        let mut db_rule = make_rule(100);
        db_rule.actions_json =
            r#"[{"action":"drop","priority":0},{"action":"log","priority":5}]"#.to_string();
        // Agent has actions in reversed order; canonicalization sorts them.
        let mut agent_rule = db_rule.clone();
        agent_rule.actions_json =
            r#"[{"action":"log","priority":5},{"action":"drop","priority":0}]"#.to_string();
        let snap = snapshot_with(vec![persisted_from(&agent_rule)]);
        let drift = compute_drift(&[db_rule], &snap);
        assert!(drift.is_clean(), "ordering should not drift: {:?}", drift);
    }

    #[test]
    fn test_compute_default_action_drift_clean_and_dirty() {
        use std::collections::HashMap;
        let iface = NodeInterface {
            node_id: "n1".into(),
            name: "eth0".into(),
            ifindex: 2,
            mac_address: None,
            link_state: "up".into(),
            addresses_json: "[]".into(),
            tag: None,
            last_reported: Utc::now(),
            xdp_attached: true,
            tc_attached: false,
            fib_forwarding: false,
            ingress_default_action: Some("drop".into()),
            egress_default_action: Some("pass".into()),
        };
        let mut agent_map = HashMap::new();
        agent_map.insert("eth0:ingress".to_string(), "drop".to_string());
        agent_map.insert("eth0:egress".to_string(), "pass".to_string());
        let mut snap = snapshot_with(vec![]);
        snap.per_interface_default_actions = agent_map.clone();
        assert!(compute_default_action_drift(&[iface.clone()], &snap).is_clean());

        // Agent disagrees on egress + has an extra interface.
        let mut bad = agent_map;
        bad.insert("eth0:egress".to_string(), "drop".to_string());
        bad.insert("eth1:ingress".to_string(), "pass".to_string());
        let mut bad_snap = snapshot_with(vec![]);
        bad_snap.per_interface_default_actions = bad;
        let drift = compute_default_action_drift(&[iface], &bad_snap);
        assert_eq!(
            drift.mismatch,
            vec![(
                "eth0:egress".to_string(),
                "pass".to_string(),
                "drop".to_string()
            )]
        );
        assert_eq!(
            drift.only_in_agent,
            vec![("eth1:ingress".to_string(), "pass".to_string())]
        );
        assert!(drift.only_in_db.is_empty());
    }

    #[test]
    fn test_compute_stop_behavior_drift() {
        let mut snap = snapshot_with(vec![]);
        snap.stop_behavior = "clear-state".to_string();

        // DB has no opinion → always clean.
        assert!(compute_stop_behavior_drift(None, &snap).is_clean());

        // Match.
        assert!(compute_stop_behavior_drift(Some("clear-state"), &snap).is_clean());

        // Mismatch.
        let d = compute_stop_behavior_drift(Some("preserve-state"), &snap);
        assert!(!d.is_clean());
        assert_eq!(d.db.as_deref(), Some("preserve-state"));
        assert_eq!(d.agent, "clear-state");
    }

    // ── apply_local_change ───────────────────────────────────────────────

    use crate::store::{InMemoryControllerStore, NodeRecord, NodeStatus};
    use policy_controller_proto::controller::InterfaceReport;

    fn node_record(id: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_string(),
            label: None,
            public_key_der: vec![1, 2, 3],
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
            agent_version: None,
            hostname: None,
            os_pretty_name: None,
            kernel_version: None,
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
        }
    }

    async fn seed_node_and_iface(store: &Arc<dyn ControllerStore>, node_id: &str, iface: &str) {
        store.upsert_node(&node_record(node_id)).await.unwrap();
        store
            .upsert_node_interfaces(
                node_id,
                &[InterfaceReport {
                    name: iface.to_string(),
                    addresses: vec![],
                    mac_address: String::new(),
                    link_state: "up".to_string(),
                    ifindex: 2,
                }],
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_apply_local_change_round_trips_rules() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        seed_node_and_iface(&store, "n1", "eth0").await;
        // Pre-existing rule we want to keep created_at on.
        let original_created = Utc::now() - chrono::Duration::hours(2);
        let mut r1 = make_rule(100);
        r1.created_at = original_created;
        store.create_rule(&r1).await.unwrap();

        // Snapshot: same r1 (so unchanged) + a brand-new r2.
        let mut r2 = make_rule(200);
        r2.dst_port = Some(443);
        let snap = snapshot_with(vec![persisted_from(&r1), persisted_from(&r2)]);
        let now = Utc::now();
        let outcome = apply_local_change("n1", &snap, &store, now).await.unwrap();
        assert_eq!(outcome.rules.added, 1);
        assert_eq!(outcome.rules.updated, 0);
        assert_eq!(outcome.rules.deleted, 0);
        assert_eq!(outcome.rules.unchanged, 1);
        assert_eq!(outcome.skipped_rules, 0);
        assert!(!outcome.stop_behavior_updated);
        assert_eq!(outcome.default_actions_updated, 0);

        // r1's created_at preserved; r2 gets `now` + agent-local-change marker.
        let r1_db = store.get_rule("100").await.unwrap().unwrap();
        assert_eq!(r1_db.created_at, original_created);
        let r2_db = store.get_rule("200").await.unwrap().unwrap();
        assert_eq!(r2_db.created_at, now);
        assert_eq!(r2_db.created_by.as_deref(), Some("agent:local-change"));
    }

    #[tokio::test]
    async fn test_apply_local_change_deletes_missing_rules() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        seed_node_and_iface(&store, "n1", "eth0").await;
        store.create_rule(&make_rule(1)).await.unwrap();
        store.create_rule(&make_rule(2)).await.unwrap();
        // Snapshot has none — both should be deleted.
        let snap = snapshot_with(vec![]);
        let outcome = apply_local_change("n1", &snap, &store, Utc::now())
            .await
            .unwrap();
        assert_eq!(outcome.rules.deleted, 2);
        assert!(store.list_rules_for_node("n1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_apply_local_change_updates_default_actions_and_stop_behavior() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        seed_node_and_iface(&store, "n1", "eth0").await;

        let mut snap = snapshot_with(vec![]);
        snap.per_interface_default_actions
            .insert("eth0:ingress".to_string(), "drop".to_string());
        snap.per_interface_default_actions
            .insert("eth0:egress".to_string(), "pass".to_string());
        snap.stop_behavior = "clear-state".to_string();

        let outcome = apply_local_change("n1", &snap, &store, Utc::now())
            .await
            .unwrap();
        assert_eq!(outcome.default_actions_updated, 2);
        assert!(outcome.stop_behavior_updated);

        let ifaces = store.list_node_interfaces("n1").await.unwrap();
        assert_eq!(ifaces[0].ingress_default_action.as_deref(), Some("drop"));
        assert_eq!(ifaces[0].egress_default_action.as_deref(), Some("pass"));
        assert_eq!(
            store
                .get_node("n1")
                .await
                .unwrap()
                .unwrap()
                .stop_behavior
                .as_deref(),
            Some("clear-state")
        );
    }

    #[tokio::test]
    async fn test_apply_local_change_stop_behavior_noop_when_already_matches() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let mut node = node_record("n1");
        node.stop_behavior = Some("preserve-state".to_string());
        store.upsert_node(&node).await.unwrap();

        let mut snap = snapshot_with(vec![]);
        snap.stop_behavior = "preserve-state".to_string();
        let outcome = apply_local_change("n1", &snap, &store, Utc::now())
            .await
            .unwrap();
        assert!(!outcome.stop_behavior_updated);
    }

    #[tokio::test]
    async fn test_apply_local_change_skips_malformed_rule_but_applies_rest() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        seed_node_and_iface(&store, "n1", "eth0").await;
        let good = make_rule(100);
        let bad = PersistedRule {
            id: 999,
            params_json: b"not json".to_vec(),
        };
        let snap = snapshot_with(vec![persisted_from(&good), bad]);
        let outcome = apply_local_change("n1", &snap, &store, Utc::now())
            .await
            .unwrap();
        assert_eq!(outcome.skipped_rules, 1);
        assert_eq!(outcome.rules.added, 1);
        assert!(store.get_rule("100").await.unwrap().is_some());
        assert!(store.get_rule("999").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_apply_local_change_unknown_node_errors() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        let snap = snapshot_with(vec![]);
        let err = apply_local_change("ghost", &snap, &store, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(err, ApplyLocalChangeError::NodeNotFound(_)));
    }

    #[tokio::test]
    async fn test_apply_local_change_ignores_malformed_default_action_key() {
        let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
        seed_node_and_iface(&store, "n1", "eth0").await;
        let mut snap = snapshot_with(vec![]);
        // Missing the ":direction" half — must not blow up the whole apply.
        snap.per_interface_default_actions
            .insert("eth0_bogus".to_string(), "drop".to_string());
        snap.per_interface_default_actions
            .insert("eth0:ingress".to_string(), "drop".to_string());
        let outcome = apply_local_change("n1", &snap, &store, Utc::now())
            .await
            .unwrap();
        assert_eq!(outcome.default_actions_updated, 1);
    }

    #[test]
    fn test_rules_to_rule_adds() {
        let rules = vec![make_rule(100)];
        let adds = rules_to_rule_adds(&rules);
        assert_eq!(adds.len(), 1);
        assert_eq!(adds[0].rule_id, "100");
        assert_eq!(adds[0].direction, "INGRESS");
        assert_eq!(adds[0].interface_name, "eth0");

        let json: serde_json::Value = serde_json::from_slice(&adds[0].params_json).unwrap();
        assert_eq!(json["id"], 100);
        assert_eq!(json["interface"], "eth0");
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["dport"], 80);
        assert_eq!(json["actions"][0]["action"], "DROP");
    }
}
