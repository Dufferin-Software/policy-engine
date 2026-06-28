// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! GraphQL client for the policy engine

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::types::*;

/// Client configuration
#[derive(Clone)]
pub struct ClientConfig {
    pub server_url: String,
    /// Path to a PEM-encoded CA certificate to trust (for self-signed server certs)
    pub tls_ca_cert: Option<String>,
    /// Skip TLS certificate verification entirely. Use only in development.
    pub danger_accept_invalid_certs: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080/graphql".to_string(),
            tls_ca_cert: None,
            danger_accept_invalid_certs: false,
        }
    }
}

/// GraphQL client for the policy engine
pub struct PolicyClient {
    config: ClientConfig,
    client: reqwest::blocking::Client,
}

/// Generic GraphQL response structure
#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

impl PolicyClient {
    /// Create a new client with default configuration
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }

    /// Create a new client with custom configuration
    pub fn with_config(config: ClientConfig) -> Self {
        let mut builder = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30));

        if config.danger_accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(ref ca_path) = config.tls_ca_cert {
            let pem = std::fs::read(ca_path)
                .unwrap_or_else(|e| panic!("failed to read CA cert '{}': {}", ca_path, e));
            let cert = reqwest::Certificate::from_pem(&pem)
                .unwrap_or_else(|e| panic!("invalid CA cert '{}': {}", ca_path, e));
            builder = builder.add_root_certificate(cert);
        }

        let client = builder.build().expect("failed to build HTTP client");
        Self { config, client }
    }

    /// Execute a GraphQL query
    fn execute<T: for<'de> Deserialize<'de>>(
        &self,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<T> {
        let body = if let Some(vars) = variables {
            json!({
                "query": query,
                "variables": vars
            })
        } else {
            json!({
                "query": query
            })
        };

        let response = self
            .client
            .post(&self.config.server_url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send request to server")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Server returned error: {} {}",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("Unknown")
            ));
        }

        let gql_response: GraphQLResponse<T> = response
            .json()
            .context("Failed to parse GraphQL response")?;

        if let Some(errors) = gql_response.errors {
            let error_msgs: Vec<String> = errors.iter().map(|e| e.message.clone()).collect();
            return Err(anyhow!("GraphQL errors: {}", error_msgs.join(", ")));
        }

        gql_response
            .data
            .ok_or_else(|| anyhow!("No data in GraphQL response"))
    }

    /// Get server status
    pub fn status(&self) -> Result<ServerStatus> {
        #[derive(Deserialize)]
        struct Response {
            status: ServerStatus,
        }

        let query = r#"
            query {
                status {
                    running
                    version
                    uptimeSecs
                    programAttached
                    inspectMode
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.status)
    }

    /// List attached interfaces
    pub fn list_interfaces(&self) -> Result<Vec<InterfaceAttachment>> {
        #[derive(Deserialize)]
        struct Response {
            interfaces: Vec<InterfaceAttachment>,
        }

        let query = r#"
            query {
                interfaces {
                    interface
                    ifindex
                    mode
                    direction
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.interfaces)
    }

    /// Get global statistics for an interface
    pub fn get_stats(&self, interface: &str, direction: GqlDirection) -> Result<GlobalStatsOutput> {
        #[derive(Deserialize)]
        struct Response {
            stats: GlobalStatsOutput,
        }

        let query = r#"
            query GetStats($interface: String!, $direction: GqlDirection!) {
                stats(interface: $interface, direction: $direction) {
                    rxPackets rxBytes txPackets txBytes
                    policyMatches policyDrops policyPass policyRedirects
                    parseErrors tailCalls bumPackets nonIpUnicast
                    inspectRedirects
                    fragments
                    verdictPassPackets verdictPassBytes verdictDropPackets verdictDropBytes
                    fibForwardedPackets fibForwardedBytes fibFallbackPackets
                    urpfDropPackets urpfDropBytes
                }
            }
        "#;

        let variables = json!({
            "interface": interface,
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.stats)
    }

    /// Get ethertype statistics for an interface (non-IP traffic breakdown)
    pub fn get_ethertype_stats(
        &self,
        interface: &str,
        direction: GqlDirection,
    ) -> Result<Vec<EthertypeStatsOutput>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "ethertypeStats")]
            ethertype_stats: Vec<EthertypeStatsOutput>,
        }

        let query = r#"
            query GetEthertypeStats($interface: String!, $direction: GqlDirection!) {
                ethertypeStats(interface: $interface, direction: $direction) {
                    ethertype
                    name
                    packets
                }
            }
        "#;

        let variables = json!({
            "interface": interface,
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.ethertype_stats)
    }

    /// Get non-IP sender statistics for an interface (ingress only).
    /// Returns one entry per (source MAC, ethertype) pair, sorted by packet count desc.
    pub fn get_nonip_senders(&self, interface: &str) -> Result<Vec<NonIpSenderOutput>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "nonipSenders")]
            nonip_senders: Vec<NonIpSenderOutput>,
        }

        let query = r#"
            query GetNonIpSenders($interface: String!) {
                nonipSenders(interface: $interface) {
                    mac
                    ethertype
                    name
                    packets
                }
            }
        "#;

        let variables = json!({ "interface": interface });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.nonip_senders)
    }

    /// Get rule statistics
    pub fn get_rule_stats(
        &self,
        rule_id: u64,
        direction: GqlDirection,
    ) -> Result<Option<RuleStatsOutput>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "ruleStats")]
            rule_stats: Option<RuleStatsOutput>,
        }

        let query = r#"
            query GetRuleStats($ruleId: String!, $direction: GqlDirection!) {
                ruleStats(ruleId: $ruleId, direction: $direction) {
                    packets
                    bytes
                    lastSeenNs
                }
            }
        "#;

        let variables = json!({
            "ruleId": rule_id.to_string(),
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.rule_stats)
    }

    /// List all rules for a direction
    pub fn list_rules(&self, direction: GqlDirection) -> Result<Vec<LpmRuleOutput>> {
        #[derive(Deserialize)]
        struct Response {
            rules: Vec<serde_json::Value>,
        }

        let query = r#"
            query ListRules($direction: GqlDirection!) {
                rules(direction: $direction) {
                    ruleId
                    interface
                    srcPrefix
                    dstPrefix
                    sport
                    dport
                    protocol
                    actions {
                        action
                        priority
                        param
                    }
                    sni
                    quicVersion
                    srcMac
                    dstMac
                }
            }
        "#;

        let variables = json!({
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;

        // Map JSON values to `LpmRuleOutput`, tolerating `ruleId` as string or number.
        let mut rules_out: Vec<LpmRuleOutput> = Vec::new();
        for r in response.rules.into_iter() {
            // parse ruleId which may be string (ID) or number
            let rule_id = match r.get("ruleId") {
                Some(v) => {
                    if v.is_string() {
                        v.as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
                    } else {
                        v.as_u64().unwrap_or(0)
                    }
                }
                None => 0,
            };

            let src_prefix = r
                .get("srcPrefix")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0/0")
                .to_string();
            let dst_prefix = r
                .get("dstPrefix")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0/0")
                .to_string();
            let sport = r.get("sport").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let dport = r.get("dport").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let mut actions: Vec<RuleActionOutput> = Vec::new();
            if let Some(arr) = r.get("actions").and_then(|v| v.as_array()) {
                for a in arr.iter() {
                    let action_str = a.get("action").and_then(|x| x.as_str()).unwrap_or("PASS");
                    let priority_a = a.get("priority").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
                    let param_a = a.get("param").and_then(|x| x.as_i64()).unwrap_or(0);
                    let gql_action = match action_str {
                        "DROP" | "Drop" | "drop" => GqlPolicyAction::Drop,
                        "LOG" | "Log" | "log" => GqlPolicyAction::Log,
                        "TAIL_CALL" | "TAILCALL" | "TailCall" | "tailcall" => {
                            GqlPolicyAction::TailCall
                        }
                        "INSPECT" | "Inspect" | "inspect" => GqlPolicyAction::Inspect,
                        _ => GqlPolicyAction::Pass,
                    };
                    actions.push(RuleActionOutput {
                        action: gql_action,
                        priority: priority_a,
                        param: param_a,
                    });
                }
            }

            // Map protocol string to GqlProtocol
            let protocol = r
                .get("protocol")
                .and_then(|v| v.as_str())
                .map(|s| match s.to_lowercase().as_str() {
                    "tcp" => GqlProtocol::Tcp,
                    "udp" => GqlProtocol::Udp,
                    "icmp" => GqlProtocol::Icmp,
                    _ => GqlProtocol::Any,
                })
                .unwrap_or(GqlProtocol::Any);

            let sni = r.get("sni").and_then(|v| v.as_str()).map(|s| s.to_string());
            let quic_version = r
                .get("quicVersion")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let src_mac = r
                .get("srcMac")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let dst_mac = r
                .get("dstMac")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let interface = r
                .get("interface")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            rules_out.push(LpmRuleOutput {
                rule_id,
                interface,
                src_prefix,
                dst_prefix,
                sport,
                dport,
                protocol,
                actions,
                sni,
                quic_version,
                src_mac,
                dst_mac,
            });
        }

        Ok(rules_out)
    }

    /// Attach ingress program to an interface
    pub fn attach_ingress(&self, interface: &str, mode: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "attachIngress")]
            attach_ingress: OperationResult,
        }

        let query = r#"
            mutation AttachIngress($input: AttachIngressInput!) {
                attachIngress(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": interface,
                "mode": mode
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.attach_ingress)
    }

    /// Detach ingress program from an interface
    pub fn detach_ingress(&self, interface: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "detachIngress")]
            detach_ingress: OperationResult,
        }

        let query = r#"
            mutation DetachIngress($input: DetachIngressInput!) {
                detachIngress(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": interface
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.detach_ingress)
    }

    /// Attach egress program to an interface
    pub fn attach_tc(&self, interface: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "attachTc")]
            attach_tc: OperationResult,
        }

        let query = r#"
            mutation AttachTc($input: AttachTcInput!) {
                attachTc(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": interface
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.attach_tc)
    }

    /// Detach egress program from an interface
    pub fn detach_tc(&self, interface: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "detachTc")]
            detach_tc: OperationResult,
        }

        let query = r#"
            mutation DetachTc($input: DetachTcInput!) {
                detachTc(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": interface
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.detach_tc)
    }

    /// Detach all programs
    pub fn detach_all(&self) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "detachAll")]
            detach_all: OperationResult,
        }

        let query = r#"
            mutation {
                detachAll {
                    success
                    message
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.detach_all)
    }

    /// Enable or disable FIB forwarding for a single interface (XDP ingress only).
    pub fn set_fib_forwarding(&self, interface: &str, enabled: bool) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "setFibForwarding")]
            set_fib_forwarding: OperationResult,
        }

        let query = r#"
            mutation SetFibForwarding($input: SetFibForwardingInput!) {
                setFibForwarding(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": interface,
                "enabled": enabled,
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.set_fib_forwarding)
    }

    /// Query FIB forwarding status for all interfaces.
    /// Returns `(interface, enabled)` pairs — only interfaces that currently
    /// have an entry in the BPF map are returned.
    pub fn list_fib_forwarding(&self) -> Result<Vec<(String, bool)>> {
        #[derive(Deserialize)]
        struct Entry {
            interface: String,
            enabled: bool,
        }
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "fibForwarding")]
            fib_forwarding: Vec<Entry>,
        }

        let query = r#"
            query {
                fibForwarding { interface enabled }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response
            .fib_forwarding
            .into_iter()
            .map(|e| (e.interface, e.enabled))
            .collect())
    }

    /// Query FIB forwarding status for a single interface. Returns `false`
    /// when the interface has no entry in the BPF map.
    pub fn get_fib_forwarding(&self, interface: &str) -> Result<bool> {
        Ok(self
            .list_fib_forwarding()?
            .into_iter()
            .find(|(name, _)| name == interface)
            .map(|(_, enabled)| enabled)
            .unwrap_or(false))
    }

    /// Set the uRPF (unicast Reverse Path Forwarding) mode for a single ingress
    /// interface. `mode` is one of "OFF", "LOOSE", or "STRICT" (case-insensitive
    /// at the API). uRPF is ingress-only (XDP); setting it on a non-XDP
    /// interface returns an OperationResult with `success == false`.
    pub fn set_urpf(&self, interface: &str, mode: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "setUrpf")]
            set_urpf: OperationResult,
        }

        let query = r#"
            mutation SetUrpf($input: SetUrpfInput!) {
                setUrpf(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": interface,
                "mode": mode.to_uppercase(),
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.set_urpf)
    }

    /// Query uRPF mode for all interfaces with uRPF enabled.
    /// Returns `(interface, mode)` pairs where mode is "LOOSE" or "STRICT".
    pub fn list_urpf(&self) -> Result<Vec<(String, String)>> {
        #[derive(Deserialize)]
        struct Entry {
            interface: String,
            mode: String,
        }
        #[derive(Deserialize)]
        struct Response {
            urpf: Vec<Entry>,
        }

        let query = r#"
            query {
                urpf { interface mode }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response
            .urpf
            .into_iter()
            .map(|e| (e.interface, e.mode))
            .collect())
    }

    /// Query the uRPF mode for a single interface. Returns "OFF" when the
    /// interface has no uRPF entry.
    pub fn get_urpf(&self, interface: &str) -> Result<String> {
        Ok(self
            .list_urpf()?
            .into_iter()
            .find(|(name, _)| name == interface)
            .map(|(_, mode)| mode)
            .unwrap_or_else(|| "OFF".to_string()))
    }

    /// Add a policy rule
    pub fn add_rule(&self, input: AddRuleInput) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "addRule")]
            add_rule: OperationResult,
        }

        let query = r#"
            mutation AddRule($input: AddRuleInput!) {
                addRule(input: $input) {
                    success
                    message
                }
            }
        "#;

        // Convert actions to the GraphQL format
        let actions: Vec<serde_json::Value> = input
            .actions
            .iter()
            .map(|a| {
                json!({
                    "action": format!("{:?}", a.action).to_uppercase(),
                    "priority": a.priority,
                    "param": a.param
                })
            })
            .collect();

        let mut input_obj = json!({
            "interface": input.interface,
            "direction": input.direction,
            "src": input.src,
            "dst": input.dst,
            "sport": input.sport,
            "dport": input.dport,
            "protocol": input.protocol,
            "actions": actions,
            "id": input.id
        });

        if let Some(ref sni) = input.sni {
            input_obj
                .as_object_mut()
                .unwrap()
                .insert("sni".to_string(), json!(sni));
        }

        if let Some(ref qv) = input.quic_version {
            input_obj
                .as_object_mut()
                .unwrap()
                .insert("quicVersion".to_string(), json!(qv));
        }

        if let Some(ref mac) = input.src_mac {
            input_obj
                .as_object_mut()
                .unwrap()
                .insert("srcMac".to_string(), json!(mac));
        }

        if let Some(ref mac) = input.dst_mac {
            input_obj
                .as_object_mut()
                .unwrap()
                .insert("dstMac".to_string(), json!(mac));
        }

        if let Some(secs) = input.expires_after_secs {
            input_obj
                .as_object_mut()
                .unwrap()
                .insert("expiresAfterSecs".to_string(), json!(secs));
        }

        if let Some(ref sched) = input.schedule {
            let windows: Vec<serde_json::Value> = sched
                .windows
                .iter()
                .map(|w| {
                    json!({
                        "start": {
                            "dayOfWeek": w.start.day_of_week,
                            "hour": w.start.hour,
                            "minute": w.start.minute,
                        },
                        "end": {
                            "dayOfWeek": w.end.day_of_week,
                            "hour": w.end.hour,
                            "minute": w.end.minute,
                        },
                    })
                })
                .collect();
            input_obj.as_object_mut().unwrap().insert(
                "schedule".to_string(),
                json!({
                    "windows": windows,
                    "timezone": sched.timezone,
                }),
            );
        }

        let variables = json!({
            "input": input_obj
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.add_rule)
    }

    /// List rules with TTL or schedule constraints (managed rules)
    pub fn managed_rules(&self, direction: GqlDirection) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "managedRules")]
            managed_rules: Vec<serde_json::Value>,
        }

        let query = r#"
            query ManagedRules($direction: GqlDirection!) {
                managedRules(direction: $direction) {
                    ruleId
                    direction
                    interface
                    srcPrefix
                    dstPrefix
                    sport
                    dport
                    protocol
                    actions { action priority param }
                    sni
                    quicVersion
                    expiresAtMs
                    schedule {
                        timezone
                        windows {
                            start { dayOfWeek hour minute }
                            end   { dayOfWeek hour minute }
                        }
                    }
                    ruleState
                }
            }
        "#;

        let variables = json!({ "direction": direction });
        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.managed_rules)
    }

    /// Delete a policy rule
    pub fn delete_rule(&self, input: DeleteRuleInput) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "deleteRule")]
            delete_rule: OperationResult,
        }

        let query = r#"
            mutation DeleteRule($input: DeleteRuleInput!) {
                deleteRule(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": input.interface,
                "direction": input.direction,
                "id": input.id,
                "src": input.src,
                "dst": input.dst,
                "sport": input.sport,
                "dport": input.dport,
                "protocol": input.protocol
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.delete_rule)
    }

    /// Flush all rules scoped to a single interface+direction.
    pub fn flush_rules(&self, interface: &str, direction: GqlDirection) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "flushRules")]
            flush_rules: OperationResult,
        }

        let query = r#"
            mutation FlushRules($interface: String!, $direction: GqlDirection!) {
                flushRules(interface: $interface, direction: $direction) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "interface": interface,
            "direction": direction,
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.flush_rules)
    }

    /// Get the current default action for a specific interface+direction ("PASS" or "DROP")
    pub fn get_default_action(&self, interface: &str, direction: GqlDirection) -> Result<String> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "defaultAction")]
            default_action: String,
        }

        let query = r#"
            query GetDefaultAction($interface: String!, $direction: GqlDirection!) {
                defaultAction(interface: $interface, direction: $direction)
            }
        "#;

        let variables = json!({ "interface": interface, "direction": direction });
        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.default_action)
    }

    /// Set default action for a specific interface+direction
    pub fn set_default_action(
        &self,
        action: GqlPolicyAction,
        direction: GqlDirection,
        interface: &str,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "setDefaultAction")]
            set_default_action: OperationResult,
        }

        let query = r#"
            mutation SetDefaultAction($input: DefaultActionInput!) {
                setDefaultAction(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "interface": interface,
                "action": format!("{:?}", action).to_uppercase(),
                "direction": direction
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.set_default_action)
    }

    /// Register tail call program for a direction
    pub fn register_tail_call(
        &self,
        slot: u32,
        program: &str,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "registerTailCall")]
            register_tail_call: OperationResult,
        }

        let query = r#"
            mutation RegisterTailCall($input: TailCallInput!) {
                registerTailCall(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "slot": slot,
                "program": program,
                "direction": direction
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.register_tail_call)
    }

    /// Clear global statistics for an interface
    pub fn clear_global_stats(
        &self,
        interface: &str,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "clearGlobalStats")]
            clear_global_stats: OperationResult,
        }

        let query = r#"
            mutation ClearGlobalStats($interface: String!, $direction: GqlDirection!) {
                clearGlobalStats(interface: $interface, direction: $direction) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "interface": interface,
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.clear_global_stats)
    }

    /// Clear statistics for a specific rule
    pub fn clear_rule_stats(
        &self,
        rule_id: u64,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "clearRuleStats")]
            clear_rule_stats: OperationResult,
        }

        let query = r#"
            mutation ClearRuleStats($ruleId: String!, $direction: GqlDirection!) {
                clearRuleStats(ruleId: $ruleId, direction: $direction) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "ruleId": rule_id.to_string(),
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.clear_rule_stats)
    }

    /// Clear statistics for all rules
    pub fn clear_all_rule_stats(&self, direction: GqlDirection) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "clearAllRuleStats")]
            clear_all_rule_stats: OperationResult,
        }

        let query = r#"
            mutation ClearAllRuleStats($direction: GqlDirection!) {
                clearAllRuleStats(direction: $direction) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.clear_all_rule_stats)
    }

    /// Clear ethertype statistics for an interface
    pub fn clear_ethertype_stats(
        &self,
        interface: &str,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "clearEthertypeStats")]
            clear_ethertype_stats: OperationResult,
        }

        let query = r#"
            mutation ClearEthertypeStats($interface: String!, $direction: GqlDirection!) {
                clearEthertypeStats(interface: $interface, direction: $direction) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "interface": interface,
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.clear_ethertype_stats)
    }

    /// Clear all statistics for an interface (global + ethertype)
    pub fn clear_interface_stats(
        &self,
        interface: &str,
        direction: GqlDirection,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "clearInterfaceStats")]
            clear_interface_stats: OperationResult,
        }

        let query = r#"
            mutation ClearInterfaceStats($interface: String!, $direction: GqlDirection!) {
                clearInterfaceStats(interface: $interface, direction: $direction) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "interface": interface,
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.clear_interface_stats)
    }

    /// Clear all statistics
    pub fn clear_all_stats(&self) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "clearAllStats")]
            clear_all_stats: OperationResult,
        }

        let query = r#"
            mutation ClearAllStats {
                clearAllStats {
                    success
                    message
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.clear_all_stats)
    }

    /// Get inspect/IPS status (only succeeds against IPS/IDS servers)
    pub fn inspect_status(&self) -> Result<InspectStatusOutput> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "inspectStatus")]
            inspect_status: InspectStatusOutput,
        }

        let query = r#"
            query {
                inspectStatus {
                    mode
                    suricataRunning
                    mirrorInterface
                    mirrorIfindex
                    peerInterface
                    flowVerdictCount
                    suricataVersion
                    rulesetVersion
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.inspect_status)
    }

    /// Configure inspect mode (only succeeds against IPS/IDS servers)
    pub fn configure_inspect(&self, mode: GqlInspectMode) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "configureInspect")]
            configure_inspect: OperationResult,
        }

        let mode_str = match mode {
            GqlInspectMode::Disabled => "DISABLED",
            GqlInspectMode::Ips => "IPS",
            GqlInspectMode::Ids => "IDS",
        };

        let query = r#"
            mutation ConfigureInspect($input: ConfigureInspectInput!) {
                configureInspect(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "mode": mode_str
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.configure_inspect)
    }

    /// Disable inspect mode (only succeeds against IPS/IDS servers)
    pub fn disable_inspect(&self) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "disableInspect")]
            disable_inspect: OperationResult,
        }

        let query = r#"
            mutation {
                disableInspect {
                    success
                    message
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.disable_inspect)
    }

    /// Get flow verdict stats for a direction (only succeeds against IPS/IDS servers)
    pub fn flow_verdicts(&self, direction: GqlDirection) -> Result<FlowVerdictStatsOutput> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "flowVerdicts")]
            flow_verdicts: FlowVerdictStatsOutput,
        }

        let query = r#"
            query FlowVerdicts($direction: GqlDirection!) {
                flowVerdicts(direction: $direction) {
                    activeVerdicts
                }
            }
        "#;

        let variables = json!({
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.flow_verdicts)
    }

    /// List individual cached flow verdict entries for a direction.
    ///
    /// Entries come back soonest-expiring first, capped server-side at `limit`
    /// (default 1000 when `None`).
    pub fn flow_verdict_list(
        &self,
        direction: GqlDirection,
        limit: Option<i32>,
    ) -> Result<Vec<FlowVerdictEntry>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "flowVerdictList")]
            flow_verdict_list: Vec<FlowVerdictEntry>,
        }

        let query = r#"
            query FlowVerdictList($direction: GqlDirection!, $limit: Int) {
                flowVerdictList(direction: $direction, limit: $limit) {
                    srcIp
                    dstIp
                    srcPort
                    dstPort
                    protocol
                    action
                    expiresNs
                    expired
                    packets
                    bytes
                }
            }
        "#;

        let variables = json!({
            "direction": direction,
            "limit": limit,
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.flow_verdict_list)
    }

    /// Clear flow verdicts for a direction (only succeeds against IPS/IDS servers)
    pub fn clear_flow_verdicts(&self, direction: GqlDirection) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "clearFlowVerdicts")]
            clear_flow_verdicts: OperationResult,
        }

        let query = r#"
            mutation ClearFlowVerdicts($direction: GqlDirection!) {
                clearFlowVerdicts(direction: $direction) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "direction": direction
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.clear_flow_verdicts)
    }

    /// Deploy Suricata rules (only succeeds against IPS/IDS servers)
    pub fn deploy_suricata_rules(&self, rules: &str, filename: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "deploySuricataRules")]
            deploy_suricata_rules: OperationResult,
        }

        let query = r#"
            mutation DeploySuricataRules($input: DeploySuricataRulesInput!) {
                deploySuricataRules(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "rules": rules,
                "filename": filename
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.deploy_suricata_rules)
    }

    /// Reload Suricata rules (only succeeds against IPS/IDS servers)
    pub fn reload_suricata_rules(&self) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "reloadSuricataRules")]
            reload_suricata_rules: OperationResult,
        }

        let query = r#"
            mutation {
                reloadSuricataRules {
                    success
                    message
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.reload_suricata_rules)
    }

    /// Get Suricata service status (only succeeds against IPS/IDS servers)
    pub fn suricata_status(&self) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "suricataStatus")]
            suricata_status: OperationResult,
        }

        let query = r#"
            query {
                suricataStatus {
                    success
                    message
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.suricata_status)
    }

    /// Get the current stop behavior setting ("clear-state" or "preserve-state").
    pub fn get_stop_behavior(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct StopBehavior {
            behavior: String,
        }
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "stopBehavior")]
            stop_behavior: StopBehavior,
        }

        let query = r#"
            query {
                stopBehavior { behavior }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.stop_behavior.behavior)
    }

    /// Set the stop behavior ("clear-state" or "preserve-state").
    pub fn configure_stop_behavior(&self, behavior: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "configureStopBehavior")]
            configure_stop_behavior: OperationResult,
        }

        let query = r#"
            mutation ConfigureStopBehavior($input: ConfigureStopBehaviorInput!) {
                configureStopBehavior(input: $input) {
                    success
                    message
                }
            }
        "#;

        let variables = json!({
            "input": {
                "stopBehavior": behavior,
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.configure_stop_behavior)
    }

    /// Get server compile-time feature flags
    pub fn server_features(&self) -> Result<ServerFeaturesOutput> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "serverFeatures")]
            server_features: ServerFeaturesOutput,
        }

        let query = r#"
            query {
                serverFeatures {
                    suricata
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.server_features)
    }
}

impl Default for PolicyClient {
    fn default() -> Self {
        Self::new()
    }
}
