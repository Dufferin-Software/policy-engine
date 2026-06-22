// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use policy_controller_proto::controller::DeltaConfigPush;

/// A single operation that undoes part of a previously-applied DeltaConfigPush.
///
/// Captured *before* the push is applied so the agent can revert locally if the
/// controller-side commit ack never arrives (or arrives with committed=false).
#[derive(Debug, Clone)]
pub enum InverseOp {
    /// Delete a rule the push added.
    DeleteRule {
        id: u64,
        interface: String,
        direction: String,
    },
    /// Re-add a rule the push deleted, from its prior JSON form.
    AddRuleJson(String),
    /// Restore a default action that the push changed. `action` may be empty
    /// (meaning "unknown prior value — skip").
    SetDefaultAction {
        interface: String,
        direction: String,
        action: String,
    },
    /// Restore the uRPF mode of an interface to its prior value
    /// ("off" / "loose" / "strict").
    SetUrpf { interface: String, mode: String },
    /// Re-attach a program the push detached (inverse of detach). `direction`
    /// is "ingress" or "egress"; `mode` is the XDP attach mode for ingress.
    Attach {
        interface: String,
        direction: String,
        mode: String,
    },
    /// Detach a program the push attached (inverse of attach). Only emitted when
    /// the program was not already attached before the push.
    Detach {
        interface: String,
        direction: String,
    },
    /// Restore the FIB-forwarding enable state of an interface.
    SetFibForwarding { interface: String, enabled: bool },
}

// ── Local policy-engine client abstraction (mockable) ────────────────────────

/// Async interface to the local policy-engine GraphQL server.
///
/// Abstracting over the actual client allows unit tests to inject a mock
/// without running a real policy-engine instance.
#[async_trait]
pub trait LocalPolicyClient: Send + Sync {
    /// Flush all rules scoped to a single interface+direction. `direction` is
    /// "INGRESS" or "EGRESS".
    async fn flush_rules(&self, interface: &str, direction: &str) -> Result<()>;
    /// Add a single rule from its JSON representation (serialised AddRuleInput).
    async fn add_rule_json(&self, rule_json: &str) -> Result<()>;
    /// Delete a single rule by its rule ID, scoped to a specific interface and direction.
    async fn delete_rule(&self, rule_id: u64, interface: &str, direction: &str) -> Result<()>;
    /// Set the default action for an interface+direction.
    async fn set_default_action(
        &self,
        interface: &str,
        direction: &str,
        action: &str,
    ) -> Result<()>;
    /// Attach XDP ingress program to an interface. Returns Ok(true) if already attached.
    async fn attach_ingress(&self, interface: &str, mode: &str) -> Result<()>;
    /// Attach TC egress program to an interface. Returns Ok(true) if already attached.
    async fn attach_tc(&self, interface: &str) -> Result<()>;
    /// Detach the XDP ingress program from an interface.
    async fn detach_ingress(&self, interface: &str) -> Result<()>;
    /// Detach the TC egress program from an interface.
    async fn detach_tc(&self, interface: &str) -> Result<()>;
    /// Enable or disable XDP FIB forwarding on an interface.
    async fn set_fib_forwarding(&self, interface: &str, enabled: bool) -> Result<()>;
    /// Query whether XDP FIB forwarding is enabled on an interface.
    async fn get_fib_forwarding(&self, interface: &str) -> Result<bool>;
    /// List currently attached interfaces as (interface_name, direction, mode) tuples.
    async fn list_attachments(&self) -> Result<Vec<(String, String, String)>>;
    /// List all rules in a direction as (rule_id, AddRuleInput JSON) pairs.
    ///
    /// Used by inverse-delta capture: the agent must know the prior form of any
    /// rule that is about to be deleted so it can re-add it on revert.
    async fn list_rules_json(&self, direction: &str) -> Result<Vec<(u64, String)>>;
    /// Configure stop behavior on the local engine ("clear-state" or "preserve-state").
    async fn configure_stop_behavior(&self, behavior: &str) -> Result<()>;
    /// Query the current stop behavior from the local engine.
    async fn get_stop_behavior(&self) -> Result<String>;
    /// Set the uRPF mode ("off" / "loose" / "strict") on an ingress interface.
    async fn set_urpf(&self, interface: &str, mode: &str) -> Result<()>;
    /// Query the current uRPF mode for an interface ("off" / "loose" / "strict").
    /// Used to capture the prior value so a change can be rolled back.
    async fn get_urpf(&self, interface: &str) -> Result<String>;
}

// ── Real implementation using policy-engine-dev (blocking → async) ────────────

/// Wraps the blocking `policy-engine-dev` using `tokio::task::spawn_blocking`.
pub struct SpawnBlockingLocalClient {
    server_url: String,
}

impl SpawnBlockingLocalClient {
    pub fn new(server_url: String) -> Self {
        Self { server_url }
    }

    fn make_client(&self) -> policy_engine_dev::PolicyClient {
        policy_engine_dev::PolicyClient::with_config(policy_engine_dev::ClientConfig {
            server_url: self.server_url.clone(),
            tls_ca_cert: None,
            danger_accept_invalid_certs: false,
        })
    }
}

#[async_trait]
impl LocalPolicyClient for SpawnBlockingLocalClient {
    async fn flush_rules(&self, interface: &str, direction: &str) -> Result<()> {
        let client = self.make_client();
        let dir: policy_engine_dev::GqlDirection = direction
            .parse()
            .with_context(|| format!("Invalid direction: {}", direction))?;
        let iface = interface.to_string();
        tokio::task::spawn_blocking(move || client.flush_rules(&iface, dir))
            .await
            .context("spawn_blocking panicked")??
            .success
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("flush_rules returned success=false"))
    }

    async fn add_rule_json(&self, rule_json: &str) -> Result<()> {
        let client = self.make_client();
        let input: policy_engine_dev::AddRuleInput =
            serde_json::from_str(rule_json).context("Failed to parse rule JSON")?;
        tokio::task::spawn_blocking(move || client.add_rule(input))
            .await
            .context("spawn_blocking panicked")??
            .success
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("add_rule returned success=false"))
    }

    async fn delete_rule(&self, rule_id: u64, interface: &str, direction: &str) -> Result<()> {
        let client = self.make_client();
        let dir: policy_engine_dev::GqlDirection = direction
            .parse()
            .with_context(|| format!("Invalid direction: {}", direction))?;
        let input = policy_engine_dev::DeleteRuleInput {
            interface: interface.to_string(),
            direction: dir,
            id: Some(rule_id.to_string()),
            src: None,
            dst: None,
            sport: None,
            dport: None,
            protocol: None,
        };
        tokio::task::spawn_blocking(move || client.delete_rule(input))
            .await
            .context("spawn_blocking panicked")??
            .success
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("delete_rule returned success=false"))
    }

    async fn set_default_action(
        &self,
        interface: &str,
        direction: &str,
        action: &str,
    ) -> Result<()> {
        let client = self.make_client();
        let iface = interface.to_string();
        let dir: policy_engine_dev::GqlDirection = direction
            .parse()
            .with_context(|| format!("Invalid direction: {}", direction))?;
        let act: policy_engine_dev::GqlPolicyAction = match action.to_lowercase().as_str() {
            "pass" => policy_engine_dev::GqlPolicyAction::Pass,
            "drop" => policy_engine_dev::GqlPolicyAction::Drop,
            other => anyhow::bail!("Invalid default action: {}", other),
        };
        tokio::task::spawn_blocking(move || client.set_default_action(act, dir, &iface))
            .await
            .context("spawn_blocking panicked")??
            .success
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("set_default_action returned success=false"))
    }

    async fn set_urpf(&self, interface: &str, mode: &str) -> Result<()> {
        let client = self.make_client();
        let iface = interface.to_string();
        let m = mode.to_string();
        let result = tokio::task::spawn_blocking(move || client.set_urpf(&iface, &m))
            .await
            .context("spawn_blocking panicked")??;
        if result.success {
            Ok(())
        } else {
            anyhow::bail!("set_urpf failed: {}", result.message)
        }
    }

    async fn get_urpf(&self, interface: &str) -> Result<String> {
        let client = self.make_client();
        let iface = interface.to_string();
        tokio::task::spawn_blocking(move || client.get_urpf(&iface))
            .await
            .context("spawn_blocking panicked")?
    }

    async fn attach_ingress(&self, interface: &str, mode: &str) -> Result<()> {
        let client = self.make_client();
        let iface = interface.to_string();
        let m = mode.to_string();
        let result = tokio::task::spawn_blocking(move || client.attach_ingress(&iface, &m))
            .await
            .context("spawn_blocking panicked")??;
        if result.success {
            Ok(())
        } else {
            anyhow::bail!("attach_ingress failed: {}", result.message)
        }
    }

    async fn attach_tc(&self, interface: &str) -> Result<()> {
        let client = self.make_client();
        let iface = interface.to_string();
        let result = tokio::task::spawn_blocking(move || client.attach_tc(&iface))
            .await
            .context("spawn_blocking panicked")??;
        if result.success {
            Ok(())
        } else {
            anyhow::bail!("attach_tc failed: {}", result.message)
        }
    }

    async fn detach_ingress(&self, interface: &str) -> Result<()> {
        let client = self.make_client();
        let iface = interface.to_string();
        let result = tokio::task::spawn_blocking(move || client.detach_ingress(&iface))
            .await
            .context("spawn_blocking panicked")??;
        if result.success {
            Ok(())
        } else {
            anyhow::bail!("detach_ingress failed: {}", result.message)
        }
    }

    async fn detach_tc(&self, interface: &str) -> Result<()> {
        let client = self.make_client();
        let iface = interface.to_string();
        let result = tokio::task::spawn_blocking(move || client.detach_tc(&iface))
            .await
            .context("spawn_blocking panicked")??;
        if result.success {
            Ok(())
        } else {
            anyhow::bail!("detach_tc failed: {}", result.message)
        }
    }

    async fn set_fib_forwarding(&self, interface: &str, enabled: bool) -> Result<()> {
        let client = self.make_client();
        let iface = interface.to_string();
        let result =
            tokio::task::spawn_blocking(move || client.set_fib_forwarding(&iface, enabled))
                .await
                .context("spawn_blocking panicked")??;
        if result.success {
            Ok(())
        } else {
            anyhow::bail!("set_fib_forwarding failed: {}", result.message)
        }
    }

    async fn get_fib_forwarding(&self, interface: &str) -> Result<bool> {
        let client = self.make_client();
        let iface = interface.to_string();
        tokio::task::spawn_blocking(move || client.get_fib_forwarding(&iface))
            .await
            .context("spawn_blocking panicked")?
    }

    async fn list_attachments(&self) -> Result<Vec<(String, String, String)>> {
        let client = self.make_client();
        let ifaces = tokio::task::spawn_blocking(move || client.list_interfaces())
            .await
            .context("spawn_blocking panicked")??;
        Ok(ifaces
            .into_iter()
            .map(|i| (i.interface, i.direction, i.mode))
            .collect())
    }

    async fn configure_stop_behavior(&self, behavior: &str) -> Result<()> {
        let client = self.make_client();
        let b = behavior.to_string();
        let result = tokio::task::spawn_blocking(move || client.configure_stop_behavior(&b))
            .await
            .context("spawn_blocking panicked")??;
        if result.success {
            Ok(())
        } else {
            anyhow::bail!("configure_stop_behavior failed: {}", result.message)
        }
    }

    async fn get_stop_behavior(&self) -> Result<String> {
        let client = self.make_client();
        tokio::task::spawn_blocking(move || client.get_stop_behavior())
            .await
            .context("spawn_blocking panicked")?
    }

    async fn list_rules_json(&self, direction: &str) -> Result<Vec<(u64, String)>> {
        let client = self.make_client();
        let dir: policy_engine_dev::GqlDirection = direction
            .parse()
            .with_context(|| format!("Invalid direction: {}", direction))?;
        let rules = tokio::task::spawn_blocking(move || client.list_rules(dir))
            .await
            .context("spawn_blocking panicked")??;
        let mut out = Vec::with_capacity(rules.len());
        for r in rules {
            let actions: Vec<policy_engine_dev::ActionInput> = r
                .actions
                .iter()
                .map(|a| policy_engine_dev::ActionInput {
                    action: a.action,
                    priority: a.priority,
                    param: a.param,
                })
                .collect();
            let input = policy_engine_dev::AddRuleInput {
                interface: r.interface.clone(),
                direction: dir,
                src: Some(r.src_prefix.clone()),
                dst: Some(r.dst_prefix.clone()),
                sport: r.sport,
                dport: r.dport,
                protocol: format!("{:?}", r.protocol).to_lowercase(),
                actions,
                id: Some(r.rule_id),
                sni: r.sni.clone(),
                quic_version: r.quic_version.clone(),
                src_mac: r.src_mac.clone(),
                dst_mac: r.dst_mac.clone(),
                expires_after_secs: None,
                schedule: None,
            };
            let json = serde_json::to_string(&input)
                .context("Failed to serialize rule as JSON for inverse capture")?;
            out.push((r.rule_id, json));
        }
        Ok(out)
    }
}

// ── ConfigApplier ─────────────────────────────────────────────────────────────

/// Applies a [`DeltaConfigPush`] from the controller to the local policy-engine.
///
/// Apply strategy:
/// - If `is_full_restore` is true: flush all rules first, then add all.
/// - Otherwise: delete rules by ID, then add new rules.
/// - Set default actions where specified.
pub struct ConfigApplier {
    client: Arc<dyn LocalPolicyClient>,
    /// Last-applied default actions, keyed by "interface:direction" (e.g. "eth0:INGRESS").
    /// Populated on every successful `set_default_action` call so we can emit
    /// an inverse op restoring the prior value.
    default_actions: Mutex<std::collections::HashMap<String, String>>,
}

impl ConfigApplier {
    pub fn new(client: Arc<dyn LocalPolicyClient>) -> Self {
        Self {
            client,
            default_actions: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Query the current uRPF mode for an interface ("off"/"loose"/"strict").
    pub async fn get_urpf(&self, interface: &str) -> Result<String> {
        self.client.get_urpf(interface).await
    }

    /// Set the uRPF mode ("off"/"loose"/"strict") on an interface.
    pub async fn set_urpf(&self, interface: &str, mode: &str) -> Result<()> {
        self.client.set_urpf(interface, mode).await
    }

    /// List currently attached programs as (interface, direction, mode) tuples.
    pub async fn list_attachments(&self) -> Result<Vec<(String, String, String)>> {
        self.client.list_attachments().await
    }

    /// Attach a program for the given direction ("ingress" / "egress").
    pub async fn attach(&self, interface: &str, direction: &str, mode: &str) -> Result<()> {
        if direction.eq_ignore_ascii_case("egress") {
            self.client.attach_tc(interface).await
        } else {
            self.client.attach_ingress(interface, mode).await
        }
    }

    /// Detach a program for the given direction ("ingress" / "egress").
    pub async fn detach(&self, interface: &str, direction: &str) -> Result<()> {
        if direction.eq_ignore_ascii_case("egress") {
            self.client.detach_tc(interface).await
        } else {
            self.client.detach_ingress(interface).await
        }
    }

    /// Query whether FIB forwarding is enabled on an interface.
    pub async fn get_fib_forwarding(&self, interface: &str) -> Result<bool> {
        self.client.get_fib_forwarding(interface).await
    }

    /// Enable or disable FIB forwarding on an interface.
    pub async fn set_fib_forwarding(&self, interface: &str, enabled: bool) -> Result<()> {
        self.client.set_fib_forwarding(interface, enabled).await
    }

    /// Capture the inverse of a push *before* applying it.
    ///
    /// Queries current rules (to snapshot JSON for any rule the push is about
    /// to delete) and reads the cached default actions. Never fails fatally:
    /// errors degrade to an empty inverse with a logged warning.
    pub async fn capture_inverse(&self, push: &DeltaConfigPush) -> Vec<InverseOp> {
        let mut ops = Vec::new();

        if push.is_full_restore {
            // A full-restore push is not reversibly captured — reverting by
            // re-flushing would be destructive and racy. The controller
            // avoids using full_restore for user-initiated changes.
            return ops;
        }

        // For each rule the push adds, the inverse is a delete by its ID.
        for add in &push.rules_to_add {
            if let Ok(id) = add.rule_id.parse::<u64>() {
                ops.push(InverseOp::DeleteRule {
                    id,
                    interface: add.interface_name.clone(),
                    direction: add.direction.to_uppercase(),
                });
            }
        }

        // For each rule the push deletes, capture the current JSON so we can
        // re-add on revert. Look in both directions (the push does not tell us).
        let delete_ids: std::collections::HashSet<u64> = push
            .rule_ids_to_delete
            .iter()
            .filter_map(|s| s.parse::<u64>().ok())
            .collect();
        if !delete_ids.is_empty() {
            for dir in ["INGRESS", "EGRESS"] {
                match self.client.list_rules_json(dir).await {
                    Ok(rules) => {
                        for (id, json) in rules {
                            if delete_ids.contains(&id) {
                                ops.push(InverseOp::AddRuleJson(json));
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "capture_inverse: failed to list {} rules for revert snapshot: {:#}",
                            dir,
                            e
                        );
                    }
                }
            }
        }

        // For default-action changes, emit an inverse using the cached prior value.
        let cache = self.default_actions.lock().unwrap();
        for key in push.per_interface_default_actions.keys() {
            if let Some(prior) = cache.get(key.as_str()) {
                // key is "iface:direction" (e.g. "eth0:INGRESS")
                if let Some((iface, dir)) = key.split_once(':') {
                    ops.push(InverseOp::SetDefaultAction {
                        interface: iface.to_string(),
                        direction: dir.to_string(),
                        action: prior.clone(),
                    });
                }
            }
        }

        ops
    }

    /// Apply a list of inverse operations in order. Logs per-op errors but
    /// does not abort — best-effort rollback.
    pub async fn apply_inverse(&self, ops: &[InverseOp]) {
        for op in ops {
            match op {
                InverseOp::DeleteRule {
                    id,
                    interface,
                    direction,
                } => {
                    if let Err(e) = self.client.delete_rule(*id, interface, direction).await {
                        log::warn!("apply_inverse: delete_rule({}) failed: {:#}", id, e);
                    }
                }
                InverseOp::AddRuleJson(json) => {
                    if let Err(e) = self.client.add_rule_json(json).await {
                        log::warn!("apply_inverse: add_rule_json failed: {:#}", e);
                    }
                }
                InverseOp::SetDefaultAction {
                    interface,
                    direction,
                    action,
                } => {
                    if action.is_empty() {
                        continue;
                    }
                    if let Err(e) = self
                        .client
                        .set_default_action(interface, direction, action)
                        .await
                    {
                        log::warn!(
                            "apply_inverse: set_default_action({}, {}, {}) failed: {:#}",
                            interface,
                            direction,
                            action,
                            e
                        );
                    } else {
                        let cache_key = format!("{}:{}", interface, direction);
                        self.default_actions
                            .lock()
                            .unwrap()
                            .insert(cache_key, action.clone());
                    }
                }
                InverseOp::SetUrpf { interface, mode } => {
                    if let Err(e) = self.client.set_urpf(interface, mode).await {
                        log::warn!(
                            "apply_inverse: set_urpf({}, {}) failed: {:#}",
                            interface,
                            mode,
                            e
                        );
                    }
                }
                InverseOp::Attach {
                    interface,
                    direction,
                    mode,
                } => {
                    let res = if direction.eq_ignore_ascii_case("egress") {
                        self.client.attach_tc(interface).await
                    } else {
                        self.client.attach_ingress(interface, mode).await
                    };
                    if let Err(e) = res {
                        log::warn!(
                            "apply_inverse: attach({}, {}) failed: {:#}",
                            interface,
                            direction,
                            e
                        );
                    }
                }
                InverseOp::Detach {
                    interface,
                    direction,
                } => {
                    let res = if direction.eq_ignore_ascii_case("egress") {
                        self.client.detach_tc(interface).await
                    } else {
                        self.client.detach_ingress(interface).await
                    };
                    if let Err(e) = res {
                        log::warn!(
                            "apply_inverse: detach({}, {}) failed: {:#}",
                            interface,
                            direction,
                            e
                        );
                    }
                }
                InverseOp::SetFibForwarding { interface, enabled } => {
                    if let Err(e) = self.client.set_fib_forwarding(interface, *enabled).await {
                        log::warn!(
                            "apply_inverse: set_fib_forwarding({}, {}) failed: {:#}",
                            interface,
                            enabled,
                            e
                        );
                    }
                }
            }
        }
    }

    /// Ensure BPF programs are attached for each (interface, direction) that has rules.
    /// Logs warnings on failure but does not abort — rule application may still succeed
    /// if the program is already attached by other means.
    async fn ensure_attachments(&self, rules: &[policy_controller_proto::controller::RuleAdd]) {
        use std::collections::HashSet;

        // Collect unique (interface, direction) pairs from the rules.
        let mut needed: HashSet<(String, String)> = HashSet::new();
        for rule in rules {
            let dir = rule.direction.to_uppercase();
            needed.insert((rule.interface_name.clone(), dir));
        }

        if needed.is_empty() {
            return;
        }

        // Query current attachments.
        let attached: HashSet<(String, String)> = match self.client.list_attachments().await {
            Ok(list) => list
                .into_iter()
                .map(|(iface, dir, _mode)| (iface, dir.to_uppercase()))
                .collect(),
            Err(e) => {
                log::warn!("Failed to list attachments for auto-attach: {:#}", e);
                HashSet::new()
            }
        };

        for (iface, dir) in needed {
            if attached.contains(&(iface.clone(), dir.clone())) {
                continue;
            }
            log::info!(
                "Auto-attaching {} {} (required by pushed rules)",
                iface,
                dir
            );
            let result = match dir.as_str() {
                "INGRESS" => self.client.attach_ingress(&iface, "auto").await,
                "EGRESS" => self.client.attach_tc(&iface).await,
                _ => {
                    log::warn!("Unknown direction for auto-attach: {}", dir);
                    continue;
                }
            };
            if let Err(e) = result {
                log::warn!("Auto-attach {} {} failed: {:#}", iface, dir, e);
            }
        }
    }

    /// Apply a [`DeltaConfigPush`], returning `(success, error_message)`.
    pub async fn apply(&self, push: &DeltaConfigPush) -> (bool, String) {
        match self.do_apply(push).await {
            Ok(()) => (true, String::new()),
            Err(e) => (false, format!("{:#}", e)),
        }
    }

    async fn do_apply(&self, push: &DeltaConfigPush) -> Result<()> {
        if push.is_full_restore {
            // Full restore: flush every (interface, direction) the engine
            // currently knows about, then re-add. Rules are interface-scoped,
            // so flushing has to be enumerated per attachment.
            let attachments = self
                .client
                .list_attachments()
                .await
                .context("Failed to list attachments for full-restore flush")?;
            for (iface, dir, _mode) in &attachments {
                self.client
                    .flush_rules(iface, dir)
                    .await
                    .with_context(|| format!("Failed to flush {} rules on {}", dir, iface))?;
            }
        } else {
            // Delta: delete rules that are no longer desired.
            // Resolve each rule_id to its (interface, direction) by scanning both directions,
            // since per-interface scoping means the engine needs both to delete.
            let mut id_map: std::collections::HashMap<u64, (String, String)> =
                std::collections::HashMap::new();
            for dir in ["INGRESS", "EGRESS"] {
                let rules = self.client.list_rules_json(dir).await.with_context(|| {
                    format!(
                        "Failed to list {} rules — cannot safely process deletes",
                        dir
                    )
                })?;
                for (id, json) in rules {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
                        let iface = parsed
                            .get("interface")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        id_map.insert(id, (iface, dir.to_string()));
                    }
                }
            }
            for rule_id_str in &push.rule_ids_to_delete {
                let rule_id = rule_id_str.parse::<u64>().map_err(|_| {
                    anyhow::anyhow!(
                        "Cannot delete rule '{}': not a valid numeric ID — \
                         controller DB may contain legacy UUID-format rules",
                        rule_id_str
                    )
                })?;
                let (iface, dir) = id_map.get(&rule_id).cloned().unwrap_or_default();
                if iface.is_empty() || dir.is_empty() {
                    // Rule is not present in the engine — treat as already deleted.
                    log::info!(
                        "do_apply: rule {} not found in engine; treating as already deleted",
                        rule_id
                    );
                    continue;
                }
                self.client
                    .delete_rule(rule_id, &iface, &dir)
                    .await
                    .with_context(|| format!("Failed to delete rule {}", rule_id))?;
            }
        }

        // Auto-attach BPF programs for interfaces that have rules.
        if !push.rules_to_add.is_empty() {
            self.ensure_attachments(&push.rules_to_add).await;
        }

        // Add new rules.
        for rule_add in &push.rules_to_add {
            let rule_json = std::str::from_utf8(&rule_add.params_json)
                .context("Rule params_json is not valid UTF-8")?;
            self.client
                .add_rule_json(rule_json)
                .await
                .with_context(|| {
                    format!(
                        "Failed to add rule {} on {} {}",
                        rule_add.rule_id, rule_add.interface_name, rule_add.direction
                    )
                })?;
        }

        // Set per-interface default actions.
        for (key, action) in &push.per_interface_default_actions {
            if action.is_empty() {
                continue;
            }
            // key is "interface:direction" (e.g. "eth0:INGRESS")
            let (iface, dir) = match key.split_once(':') {
                Some(parts) => parts,
                None => {
                    log::warn!("Skipping malformed default action key: {}", key);
                    continue;
                }
            };
            self.client
                .set_default_action(iface, dir, action)
                .await
                .with_context(|| format!("Failed to set default action for {}", key))?;
            self.default_actions
                .lock()
                .unwrap()
                .insert(key.clone(), action.clone());
        }

        // Apply stop behavior if specified.
        if !push.stop_behavior.is_empty() {
            if let Err(e) = self
                .client
                .configure_stop_behavior(&push.stop_behavior)
                .await
            {
                log::warn!(
                    "Failed to set stop_behavior to '{}': {:#}",
                    push.stop_behavior,
                    e
                );
            }
        }

        log::info!(
            "Config applied: full_restore={}, added={}, deleted={}, default_action_keys={}, stop_behavior={}",
            push.is_full_restore,
            push.rules_to_add.len(),
            push.rule_ids_to_delete.len(),
            push.per_interface_default_actions.len(),
            if push.stop_behavior.is_empty() { "unchanged" } else { &push.stop_behavior },
        );
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use policy_controller_proto::controller::RuleAdd;
    use std::sync::Mutex;

    /// Records calls for assertion.
    #[derive(Default)]
    struct RecordingClient {
        flushes: Mutex<Vec<(String, String)>>,
        attachments: Mutex<Vec<(String, String, String)>>,
        adds: Mutex<Vec<String>>,
        deletes: Mutex<Vec<u64>>,
        defaults: Mutex<Vec<(String, String)>>,
        attaches: Mutex<Vec<(String, String)>>,
        urpf_sets: Mutex<Vec<(String, String)>>,
        detaches: Mutex<Vec<(String, String)>>,
        fib_sets: Mutex<Vec<(String, bool)>>,
        /// Seeded rules returned by `list_rules_json`, keyed by direction.
        /// Each entry is (rule_id, JSON); the JSON must have an `interface` field
        /// so the delete path can resolve (interface, direction) for a given id.
        seeded_rules: Mutex<std::collections::HashMap<String, Vec<(u64, String)>>>,
        fail_add: bool,
    }

    impl RecordingClient {
        fn new_failing() -> Self {
            Self {
                fail_add: true,
                ..Default::default()
            }
        }
    }

    #[async_trait]
    impl LocalPolicyClient for RecordingClient {
        async fn flush_rules(&self, interface: &str, direction: &str) -> Result<()> {
            self.flushes
                .lock()
                .unwrap()
                .push((interface.to_string(), direction.to_string()));
            Ok(())
        }

        async fn add_rule_json(&self, rule_json: &str) -> Result<()> {
            if self.fail_add {
                anyhow::bail!("simulated add_rule failure");
            }
            self.adds.lock().unwrap().push(rule_json.to_string());
            Ok(())
        }

        async fn delete_rule(
            &self,
            rule_id: u64,
            _interface: &str,
            _direction: &str,
        ) -> Result<()> {
            self.deletes.lock().unwrap().push(rule_id);
            Ok(())
        }

        async fn set_default_action(
            &self,
            interface: &str,
            direction: &str,
            action: &str,
        ) -> Result<()> {
            self.defaults
                .lock()
                .unwrap()
                .push((format!("{}:{}", interface, direction), action.to_string()));
            Ok(())
        }

        async fn attach_ingress(&self, interface: &str, _mode: &str) -> Result<()> {
            self.attaches
                .lock()
                .unwrap()
                .push((interface.to_string(), "INGRESS".to_string()));
            Ok(())
        }

        async fn attach_tc(&self, interface: &str) -> Result<()> {
            self.attaches
                .lock()
                .unwrap()
                .push((interface.to_string(), "EGRESS".to_string()));
            Ok(())
        }

        async fn list_attachments(&self) -> Result<Vec<(String, String, String)>> {
            Ok(self.attachments.lock().unwrap().clone())
        }

        async fn list_rules_json(&self, direction: &str) -> Result<Vec<(u64, String)>> {
            Ok(self
                .seeded_rules
                .lock()
                .unwrap()
                .get(direction)
                .cloned()
                .unwrap_or_default())
        }

        async fn configure_stop_behavior(&self, _behavior: &str) -> Result<()> {
            Ok(())
        }

        async fn get_stop_behavior(&self) -> Result<String> {
            Ok("clear-state".to_string())
        }
        async fn set_urpf(&self, interface: &str, mode: &str) -> Result<()> {
            self.urpf_sets
                .lock()
                .unwrap()
                .push((interface.to_string(), mode.to_string()));
            Ok(())
        }
        async fn get_urpf(&self, _i: &str) -> Result<String> {
            Ok("off".to_string())
        }
        async fn detach_ingress(&self, interface: &str) -> Result<()> {
            self.detaches
                .lock()
                .unwrap()
                .push((interface.to_string(), "ingress".to_string()));
            Ok(())
        }
        async fn detach_tc(&self, interface: &str) -> Result<()> {
            self.detaches
                .lock()
                .unwrap()
                .push((interface.to_string(), "egress".to_string()));
            Ok(())
        }
        async fn set_fib_forwarding(&self, interface: &str, enabled: bool) -> Result<()> {
            self.fib_sets
                .lock()
                .unwrap()
                .push((interface.to_string(), enabled));
            Ok(())
        }
        async fn get_fib_forwarding(&self, _i: &str) -> Result<bool> {
            Ok(false)
        }
    }

    fn make_rule_add(rule_id: &str, json: &str) -> RuleAdd {
        RuleAdd {
            rule_id: rule_id.to_string(),
            interface_name: "eth0".to_string(),
            direction: "INGRESS".to_string(),
            params_json: json.as_bytes().to_vec(),
        }
    }

    fn delta_push(adds: Vec<RuleAdd>, deletes: Vec<String>, full_restore: bool) -> DeltaConfigPush {
        DeltaConfigPush {
            rules_to_add: adds,
            rule_ids_to_delete: deletes,
            is_full_restore: full_restore,
            per_interface_default_actions: std::collections::HashMap::new(),
            generation_id: String::new(),
            confirm_deadline_ms: 0,
            stop_behavior: String::new(),
        }
    }

    #[tokio::test]
    async fn test_empty_push() {
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let (ok, _) = applier.apply(&delta_push(vec![], vec![], false)).await;
        assert!(ok);
        assert!(client.flushes.lock().unwrap().is_empty());
        assert!(client.adds.lock().unwrap().is_empty());
        assert!(client.deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_full_restore_flushes_first() {
        let rule_json = r#"{"direction":"INGRESS","protocol":"tcp"}"#;
        let client = Arc::new(RecordingClient::default());
        // Seed two attachments so the per-interface flush has something to enumerate.
        client.attachments.lock().unwrap().extend([
            (
                "eth0".to_string(),
                "INGRESS".to_string(),
                "generic".to_string(),
            ),
            ("eth0".to_string(), "EGRESS".to_string(), String::new()),
        ]);
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let push = delta_push(vec![make_rule_add("r1", rule_json)], vec![], true);
        let (ok, _) = applier.apply(&push).await;
        assert!(ok);

        let flushes = client.flushes.lock().unwrap();
        assert_eq!(flushes.len(), 2);
        assert!(flushes.contains(&("eth0".to_string(), "INGRESS".to_string())));
        assert!(flushes.contains(&("eth0".to_string(), "EGRESS".to_string())));
        assert_eq!(client.adds.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_delta_deletes_and_adds() {
        let rule_json = r#"{"direction":"INGRESS","protocol":"tcp"}"#;
        let client = Arc::new(RecordingClient::default());
        // Seed rule 42 so the delete path can resolve its (interface, direction).
        client.seeded_rules.lock().unwrap().insert(
            "INGRESS".to_string(),
            vec![(42u64, r#"{"interface":"eth0"}"#.to_string())],
        );
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let push = delta_push(
            vec![make_rule_add("r2", rule_json)],
            vec!["42".to_string()],
            false,
        );
        let (ok, _) = applier.apply(&push).await;
        assert!(ok);

        assert!(client.flushes.lock().unwrap().is_empty()); // No flush on delta
        assert_eq!(*client.deletes.lock().unwrap(), vec![42u64]);
        assert_eq!(client.adds.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_default_actions_applied() {
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let mut push = delta_push(vec![], vec![], false);
        push.per_interface_default_actions
            .insert("eth0:INGRESS".to_string(), "drop".to_string());
        push.per_interface_default_actions
            .insert("eth0:EGRESS".to_string(), "pass".to_string());
        let (ok, _) = applier.apply(&push).await;
        assert!(ok);

        let defaults = client.defaults.lock().unwrap();
        assert!(defaults.contains(&("eth0:INGRESS".to_string(), "drop".to_string())));
        assert!(defaults.contains(&("eth0:EGRESS".to_string(), "pass".to_string())));
    }

    #[tokio::test]
    async fn test_apply_failure_returns_error_string() {
        let rule_json = r#"{"direction":"INGRESS","protocol":"any"}"#;
        let client = Arc::new(RecordingClient::new_failing());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let push = delta_push(vec![make_rule_add("r1", rule_json)], vec![], false);
        let (ok, msg) = applier.apply(&push).await;
        assert!(!ok);
        assert!(!msg.is_empty());
    }

    #[tokio::test]
    async fn test_auto_attach_on_rule_add() {
        let rule_json = r#"{"direction":"INGRESS","protocol":"tcp"}"#;
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let push = delta_push(vec![make_rule_add("r1", rule_json)], vec![], false);
        let (ok, _) = applier.apply(&push).await;
        assert!(ok);

        let attaches = client.attaches.lock().unwrap();
        assert!(
            attaches.contains(&("eth0".to_string(), "INGRESS".to_string())),
            "Should auto-attach ingress for the rule's interface"
        );
    }

    #[tokio::test]
    async fn test_auto_attach_egress() {
        let rule_json = r#"{"direction":"EGRESS","protocol":"tcp"}"#;
        let mut rule = make_rule_add("r1", rule_json);
        rule.direction = "EGRESS".to_string();
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let push = delta_push(vec![rule], vec![], false);
        let (ok, _) = applier.apply(&push).await;
        assert!(ok);

        let attaches = client.attaches.lock().unwrap();
        assert!(
            attaches.contains(&("eth0".to_string(), "EGRESS".to_string())),
            "Should auto-attach egress for the rule's interface"
        );
    }

    #[tokio::test]
    async fn test_delete_non_numeric_rule_id_fails() {
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        // UUID-format rule ID: should fail rather than silently skip.
        let push = delta_push(
            vec![],
            vec!["550e8400-e29b-41d4-a716-446655440000".to_string()],
            false,
        );
        let (ok, msg) = applier.apply(&push).await;
        assert!(!ok, "Non-numeric rule_id should cause apply to fail");
        assert!(
            msg.contains("not a valid numeric ID"),
            "Error message should mention invalid ID: {}",
            msg
        );
        // Nothing should have been deleted from the engine.
        assert!(client.deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_delete_rule_missing_from_engine_succeeds() {
        let client = Arc::new(RecordingClient::default());
        // No seeded rules — the engine reports empty list.
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let push = delta_push(vec![], vec!["99".to_string()], false);
        let (ok, _) = applier.apply(&push).await;
        // Rule not found in engine → treated as already deleted → success.
        assert!(ok);
        assert!(client.deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_full_restore_auto_attaches() {
        let rule_json = r#"{"direction":"INGRESS","protocol":"tcp"}"#;
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);
        let push = delta_push(vec![make_rule_add("r1", rule_json)], vec![], true);
        let (ok, _) = applier.apply(&push).await;
        assert!(ok);

        let attaches = client.attaches.lock().unwrap();
        assert!(!attaches.is_empty(), "Full restore should also auto-attach");
    }

    #[tokio::test]
    async fn test_apply_inverse_seturpf_restores_prior_mode() {
        // The uRPF watchdog rollback path: an InverseOp::SetUrpf must call
        // set_urpf with the prior mode so a connectivity-killing change reverts.
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);

        applier
            .apply_inverse(&[InverseOp::SetUrpf {
                interface: "eth0".to_string(),
                mode: "off".to_string(),
            }])
            .await;

        let sets = client.urpf_sets.lock().unwrap();
        assert_eq!(
            *sets,
            vec![("eth0".to_string(), "off".to_string())],
            "apply_inverse(SetUrpf) must restore the prior uRPF mode"
        );
    }

    #[tokio::test]
    async fn test_apply_inverse_detach_undoes_attach() {
        // Inverse of an attach is a detach of the same interface+direction.
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);

        applier
            .apply_inverse(&[InverseOp::Detach {
                interface: "eth0".to_string(),
                direction: "ingress".to_string(),
            }])
            .await;

        let detaches = client.detaches.lock().unwrap();
        assert_eq!(*detaches, vec![("eth0".to_string(), "ingress".to_string())]);
    }

    #[tokio::test]
    async fn test_apply_inverse_attach_undoes_detach() {
        // Inverse of a detach re-attaches with the prior mode.
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);

        applier
            .apply_inverse(&[InverseOp::Attach {
                interface: "eth0".to_string(),
                direction: "ingress".to_string(),
                mode: "native".to_string(),
            }])
            .await;

        // RecordingClient records ingress attaches as (interface, "INGRESS").
        let attaches = client.attaches.lock().unwrap();
        assert_eq!(*attaches, vec![("eth0".to_string(), "INGRESS".to_string())]);
    }

    #[tokio::test]
    async fn test_apply_inverse_setfib_restores_prior_state() {
        let client = Arc::new(RecordingClient::default());
        let applier = ConfigApplier::new(Arc::clone(&client) as Arc<dyn LocalPolicyClient>);

        applier
            .apply_inverse(&[InverseOp::SetFibForwarding {
                interface: "eth0".to_string(),
                enabled: false,
            }])
            .await;

        let fib = client.fib_sets.lock().unwrap();
        assert_eq!(*fib, vec![("eth0".to_string(), false)]);
    }
}
