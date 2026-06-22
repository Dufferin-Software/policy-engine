// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::types::*;

/// Connection configuration for the controller client.
pub struct ClientConfig {
    /// Base URL of the controller HTTP API (e.g. `http://127.0.0.1:8443`).
    pub base_url: String,
    /// Optional bearer token. Required against any controller that has
    /// auth enabled (i.e. anything past the api_tokens migration).
    pub api_token: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8443".to_string(),
            api_token: None,
        }
    }
}

/// GraphQL client for the policy controller operator API.
pub struct ControllerClient {
    http: reqwest::blocking::Client,
    graphql_url: String,
    api_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

impl ControllerClient {
    /// Create a new client with default configuration.
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }

    /// Create a new client with custom configuration.
    pub fn with_config(config: ClientConfig) -> Self {
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        let graphql_url = format!("{}/graphql", config.base_url.trim_end_matches('/'));
        Self {
            http,
            graphql_url,
            api_token: config.api_token,
        }
    }

    fn execute<T: for<'de> Deserialize<'de>>(
        &self,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<T> {
        let body = match variables {
            Some(vars) => json!({ "query": query, "variables": vars }),
            None => json!({ "query": query }),
        };

        let mut req = self.http.post(&self.graphql_url).json(&body);
        if let Some(t) = &self.api_token {
            req = req.bearer_auth(t);
        }
        let response = req.send().context("Failed to connect to controller")?;

        let status = response.status();
        let text = response
            .text()
            .context("Failed to read controller response")?;

        let parsed: GraphQLResponse<T> = serde_json::from_str(&text)
            .with_context(|| format!("Non-JSON response (HTTP {}): {}", status, text))?;

        if let Some(errors) = parsed.errors {
            let msg = errors
                .into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow!("Controller error: {}", msg));
        }

        parsed.data.ok_or_else(|| anyhow!("No data in response"))
    }

    // ── Nodes ─────────────────────────────────────────────────────────────────

    /// List nodes, optionally filtered by status ("pending", "active", "decommissioned").
    pub fn list_nodes(&self, status: Option<String>) -> Result<Vec<Node>> {
        #[derive(Deserialize)]
        struct Response {
            nodes: Vec<Node>,
        }
        let q = r#"
            query ListNodes($status: String) {
                nodes(status: $status) {
                    id status label dmiUuid tpmBacked agentVersion lastSeen enrolledAt
                }
            }
        "#;
        let r: Response = self.execute(q, status.map(|s| json!({ "status": s })))?;
        Ok(r.nodes)
    }

    /// Get a single node by ID.
    pub fn get_node(&self, node_id: &str) -> Result<Option<Node>> {
        #[derive(Deserialize)]
        struct Response {
            node: Option<Node>,
        }
        let q = r#"
            query GetNode($id: ID!) {
                node(id: $id) {
                    id status label hostname dmiUuid tpmBacked agentVersion
                    osPrettyName kernelVersion dmiSysVendor dmiProductName
                    certExpiry lastSeen enrolledAt tenantId
                }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "id": node_id })))?;
        Ok(r.node)
    }

    /// List all pending enrollment requests.
    pub fn pending_enrollments(&self) -> Result<Vec<Node>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "pendingEnrollments")]
            pending_enrollments: Vec<Node>,
        }
        let q = r#"
            query {
                pendingEnrollments {
                    id status label dmiUuid tpmBacked agentVersion lastSeen enrolledAt
                }
            }
        "#;
        let r: Response = self.execute(q, None)?;
        Ok(r.pending_enrollments)
    }

    /// Approve a pending enrollment request.
    pub fn approve_enrollment(&self, node_id: &str, label: Option<String>) -> Result<Node> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "approveEnrollment")]
            approve_enrollment: Node,
        }
        let q = r#"
            mutation Approve($nodeId: ID!, $label: String) {
                approveEnrollment(nodeId: $nodeId, label: $label) { id status label }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id, "label": label })))?;
        Ok(r.approve_enrollment)
    }

    /// Reject a pending enrollment request.
    pub fn reject_enrollment(
        &self,
        node_id: &str,
        reason: Option<String>,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "rejectEnrollment")]
            reject_enrollment: OperationResult,
        }
        let q = r#"
            mutation Reject($nodeId: ID!, $reason: String) {
                rejectEnrollment(nodeId: $nodeId, reason: $reason) { success message }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id, "reason": reason })))?;
        Ok(r.reject_enrollment)
    }

    /// Decommission an active node (revokes cert, blocks reconnect).
    pub fn decommission_node(&self, node_id: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "decommissionNode")]
            decommission_node: OperationResult,
        }
        let q = r#"
            mutation Decommission($nodeId: ID!) {
                decommissionNode(nodeId: $nodeId) { success message }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id })))?;
        Ok(r.decommission_node)
    }

    /// Permanently remove a decommissioned node from the registry.
    pub fn remove_node(&self, node_id: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "removeNode")]
            remove_node: OperationResult,
        }
        let q = r#"
            mutation Remove($nodeId: ID!) {
                removeNode(nodeId: $nodeId) { success message }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id })))?;
        Ok(r.remove_node)
    }

    /// Set a human-readable label on a node.
    pub fn label_node(&self, node_id: &str, label: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "labelNode")]
            label_node: OperationResult,
        }
        let q = r#"
            mutation Label($nodeId: ID!, $label: String!) {
                labelNode(nodeId: $nodeId, label: $label) { success message }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id, "label": label })))?;
        Ok(r.label_node)
    }

    /// Push the current config to a specific node.
    pub fn push_config(&self, node_id: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "pushConfig")]
            push_config: OperationResult,
        }
        let q = r#"
            mutation Push($nodeId: ID!) {
                pushConfig(nodeId: $nodeId) { success message }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id })))?;
        Ok(r.push_config)
    }

    /// List the IDs of currently-connected nodes.
    pub fn online_nodes(&self) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "onlineNodes")]
            online_nodes: Vec<String>,
        }
        let q = "query { onlineNodes }";
        let r: Response = self.execute(q, None)?;
        Ok(r.online_nodes)
    }

    // ── Rules ─────────────────────────────────────────────────────────────────

    /// List rules for a node, optionally filtered by interface and direction.
    pub fn list_rules(
        &self,
        node_id: &str,
        interface: Option<String>,
        direction: Option<String>,
    ) -> Result<Vec<Rule>> {
        #[derive(Deserialize)]
        struct Response {
            rules: Vec<Rule>,
        }
        let q = r#"
            query ListRules($nodeId: ID!, $interfaceName: String, $direction: String) {
                rules(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) {
                    id nodeId interfaceName direction protocol
                    srcCidr dstCidr srcPort dstPort sniPattern quicVersion
                    srcMac dstMac actionsJson createdAt createdBy
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({
                "nodeId": node_id,
                "interfaceName": interface,
                "direction": direction,
            })),
        )?;
        Ok(r.rules)
    }

    /// Create a rule on a single node.
    pub fn create_rule(&self, input: CreateRuleInput) -> Result<Rule> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "createRule")]
            create_rule: Rule,
        }
        let q = r#"
            mutation CreateRule($input: CreateRuleInput!) {
                createRule(input: $input) {
                    id nodeId interfaceName direction protocol actionsJson createdAt
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({
                "input": {
                    "nodeId": input.node_id,
                    "interfaceName": input.interface,
                    "direction": input.direction,
                    "actionsJson": input.actions_json,
                    "srcCidr": input.src_cidr,
                    "dstCidr": input.dst_cidr,
                    "srcPort": input.src_port,
                    "dstPort": input.dst_port,
                    "protocol": input.protocol,
                    "sniPattern": input.sni_pattern,
                    "quicVersion": input.quic_version,
                    "srcMac": input.src_mac,
                    "dstMac": input.dst_mac,
                }
            })),
        )?;
        Ok(r.create_rule)
    }

    /// Create the same rule on multiple nodes simultaneously.
    pub fn create_rules_multi_node(&self, input: CreateRuleMultiNodeInput) -> Result<Vec<Rule>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "createRulesMultiNode")]
            create_rules_multi_node: Vec<Rule>,
        }
        let q = r#"
            mutation CreateRulesMultiNode($input: CreateRuleMultiNodeInput!) {
                createRulesMultiNode(input: $input) {
                    id nodeId interfaceName direction protocol actionsJson createdAt
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({
                "input": {
                    "nodeIds": input.node_ids,
                    "interfaceName": input.interface,
                    "direction": input.direction,
                    "actionsJson": input.actions_json,
                    "srcCidr": input.src_cidr,
                    "dstCidr": input.dst_cidr,
                    "srcPort": input.src_port,
                    "dstPort": input.dst_port,
                    "protocol": input.protocol,
                    "sniPattern": input.sni_pattern,
                    "quicVersion": input.quic_version,
                    "srcMac": input.src_mac,
                    "dstMac": input.dst_mac,
                }
            })),
        )?;
        Ok(r.create_rules_multi_node)
    }

    /// Delete a rule by ID.
    pub fn delete_rule(&self, rule_id: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "deleteRule")]
            delete_rule: OperationResult,
        }
        let q = r#"
            mutation DeleteRule($ruleId: ID!) {
                deleteRule(ruleId: $ruleId) { success message }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "ruleId": rule_id })))?;
        Ok(r.delete_rule)
    }

    // ── Interfaces ────────────────────────────────────────────────────────────

    /// List interfaces on a node.
    pub fn node_interfaces(&self, node_id: &str) -> Result<Vec<NodeInterface>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "nodeInterfaces")]
            node_interfaces: Vec<NodeInterface>,
        }
        let q = r#"
            query NodeInterfaces($nodeId: ID!) {
                nodeInterfaces(nodeId: $nodeId) {
                    nodeId name macAddress linkState tag
                    xdpAttached tcAttached fibForwarding
                    ingressDefaultAction egressDefaultAction lastReported
                }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id })))?;
        Ok(r.node_interfaces)
    }

    /// List all interfaces across all nodes.
    pub fn all_node_interfaces(&self) -> Result<Vec<NodeInterface>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "allNodeInterfaces")]
            all_node_interfaces: Vec<NodeInterface>,
        }
        let q = r#"
            query {
                allNodeInterfaces {
                    nodeId name macAddress linkState tag
                    xdpAttached tcAttached fibForwarding
                    ingressDefaultAction egressDefaultAction lastReported
                }
            }
        "#;
        let r: Response = self.execute(q, None)?;
        Ok(r.all_node_interfaces)
    }

    /// Tag an interface (e.g. WAN, LAN).
    pub fn tag_interface(&self, node_id: &str, name: &str, tag: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "tagInterface")]
            tag_interface: OperationResult,
        }
        let q = r#"
            mutation Tag($nodeId: ID!, $interfaceName: String!, $tag: String!) {
                tagInterface(nodeId: $nodeId, interfaceName: $interfaceName, tag: $tag) {
                    success message
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({ "nodeId": node_id, "interfaceName": name, "tag": tag })),
        )?;
        Ok(r.tag_interface)
    }

    /// Remove a tag from an interface.
    pub fn untag_interface(&self, node_id: &str, name: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "untagInterface")]
            untag_interface: OperationResult,
        }
        let q = r#"
            mutation Untag($nodeId: ID!, $interfaceName: String!) {
                untagInterface(nodeId: $nodeId, interfaceName: $interfaceName) {
                    success message
                }
            }
        "#;
        let r: Response =
            self.execute(q, Some(json!({ "nodeId": node_id, "interfaceName": name })))?;
        Ok(r.untag_interface)
    }

    /// Attach a BPF program to an interface.
    pub fn attach_program(
        &self,
        node_id: &str,
        name: &str,
        direction: &str,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "attachProgram")]
            attach_program: OperationResult,
        }
        let q = r#"
            mutation Attach($nodeId: ID!, $interfaceName: String!, $direction: String!) {
                attachProgram(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) {
                    success message
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({ "nodeId": node_id, "interfaceName": name, "direction": direction })),
        )?;
        Ok(r.attach_program)
    }

    /// Detach a BPF program from an interface.
    pub fn detach_program(
        &self,
        node_id: &str,
        name: &str,
        direction: &str,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "detachProgram")]
            detach_program: OperationResult,
        }
        let q = r#"
            mutation Detach($nodeId: ID!, $interfaceName: String!, $direction: String!) {
                detachProgram(nodeId: $nodeId, interfaceName: $interfaceName, direction: $direction) {
                    success message
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({ "nodeId": node_id, "interfaceName": name, "direction": direction })),
        )?;
        Ok(r.detach_program)
    }

    /// Enable or disable XDP FIB forwarding on an interface.
    pub fn set_fib_forwarding(
        &self,
        node_id: &str,
        name: &str,
        enabled: bool,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "setFibForwarding")]
            set_fib_forwarding: OperationResult,
        }
        let q = r#"
            mutation SetFib($nodeId: ID!, $interfaceName: String!, $enabled: Boolean!) {
                setFibForwarding(nodeId: $nodeId, interfaceName: $interfaceName, enabled: $enabled) {
                    success message
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({ "nodeId": node_id, "interfaceName": name, "enabled": enabled })),
        )?;
        Ok(r.set_fib_forwarding)
    }

    /// Set the uRPF mode on an ingress interface. `mode` is "off", "loose", or
    /// "strict". uRPF is ingress-only (XDP) and is never supported on egress.
    pub fn set_urpf(&self, node_id: &str, name: &str, mode: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "setUrpf")]
            set_urpf: OperationResult,
        }
        let q = r#"
            mutation SetUrpf($nodeId: ID!, $interfaceName: String!, $mode: String!) {
                setUrpf(nodeId: $nodeId, interfaceName: $interfaceName, mode: $mode) {
                    success message
                }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({ "nodeId": node_id, "interfaceName": name, "mode": mode })),
        )?;
        Ok(r.set_urpf)
    }

    /// Set the default action for unmatched packets on an interface+direction.
    pub fn set_interface_default_action(
        &self,
        node_id: &str,
        name: &str,
        direction: &str,
        action: &str,
    ) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "setInterfaceDefaultAction")]
            set_interface_default_action: OperationResult,
        }
        let q = r#"
            mutation SetDefault(
                $nodeId: ID!
                $interfaceName: String!
                $direction: String!
                $action: String!
            ) {
                setInterfaceDefaultAction(
                    nodeId: $nodeId
                    interfaceName: $interfaceName
                    direction: $direction
                    action: $action
                ) { success message }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({
                "nodeId": node_id,
                "interfaceName": name,
                "direction": direction,
                "action": action,
            })),
        )?;
        Ok(r.set_interface_default_action)
    }

    // ── Pending ───────────────────────────────────────────────────────────────

    /// List all in-flight config generations.
    pub fn pending_generations(&self) -> Result<Vec<PendingGeneration>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "pendingGenerations")]
            pending_generations: Vec<PendingGeneration>,
        }
        let q = r#"
            query {
                pendingGenerations {
                    generationId nodeId opKind issuedAt
                }
            }
        "#;
        let r: Response = self.execute(q, None)?;
        Ok(r.pending_generations)
    }

    /// Get the in-flight config generation for a specific node.
    pub fn pending_generation(&self, node_id: &str) -> Result<Option<PendingGeneration>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "pendingGeneration")]
            pending_generation: Option<PendingGeneration>,
        }
        let q = r#"
            query PendingGen($nodeId: ID!) {
                pendingGeneration(nodeId: $nodeId) {
                    generationId nodeId opKind issuedAt
                }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "nodeId": node_id })))?;
        Ok(r.pending_generation)
    }

    // ── Audit ─────────────────────────────────────────────────────────────────

    /// List audit log entries, newest first.
    pub fn audit_log(&self, limit: i32, offset: i32) -> Result<Vec<AuditEntry>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "auditLog")]
            audit_log: Vec<AuditEntry>,
        }
        let q = r#"
            query AuditLog($limit: Int, $offset: Int) {
                auditLog(limit: $limit, offset: $offset) {
                    id ts operator action nodeId detail
                }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "limit": limit, "offset": offset })))?;
        Ok(r.audit_log)
    }

    // ── CA ────────────────────────────────────────────────────────────────────

    /// Fetch the controller CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "caCertPem")]
            ca_cert_pem: String,
        }
        let q = "query { caCertPem }";
        let r: Response = self.execute(q, None)?;
        Ok(r.ca_cert_pem)
    }

    /// List all ZTP enrollment tokens.
    pub fn list_enrollment_tokens(&self) -> Result<Vec<EnrollmentTokenInfo>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "enrollmentTokens")]
            enrollment_tokens: Vec<EnrollmentTokenInfo>,
        }
        let q = r#"
            query {
                enrollmentTokens {
                    tokenId createdAt createdBy expiresAt usesRemaining
                    cidrScope fleetLabel revokedAt
                }
            }
        "#;
        let r: Response = self.execute(q, None)?;
        Ok(r.enrollment_tokens)
    }

    /// Mint a new ZTP bootstrap token.
    pub fn create_enrollment_token(
        &self,
        enrollment_url: &str,
        controller_url: &str,
        ttl_seconds: i64,
        max_uses: i64,
        cidr_scope: Option<&str>,
        fleet_label: Option<&str>,
    ) -> Result<IssuedEnrollmentToken> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "createEnrollmentToken")]
            create_enrollment_token: IssuedEnrollmentToken,
        }
        let q = r#"
            mutation Mint(
                $enrollmentUrl: String!,
                $controllerUrl: String!,
                $ttlSeconds: Int!,
                $maxUses: Int!,
                $cidrScope: String,
                $fleetLabel: String
            ) {
                createEnrollmentToken(
                    enrollmentUrl: $enrollmentUrl,
                    controllerUrl: $controllerUrl,
                    ttlSeconds: $ttlSeconds,
                    maxUses: $maxUses,
                    cidrScope: $cidrScope,
                    fleetLabel: $fleetLabel
                ) { tokenId bundle expiresAt usesRemaining }
            }
        "#;
        let r: Response = self.execute(
            q,
            Some(json!({
                "enrollmentUrl": enrollment_url,
                "controllerUrl": controller_url,
                "ttlSeconds": ttl_seconds,
                "maxUses": max_uses,
                "cidrScope": cidr_scope,
                "fleetLabel": fleet_label,
            })),
        )?;
        Ok(r.create_enrollment_token)
    }

    /// Revoke a previously-issued enrollment token.
    pub fn revoke_enrollment_token(&self, token_id: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "revokeEnrollmentToken")]
            revoke_enrollment_token: OperationResult,
        }
        let q = r#"
            mutation Revoke($tokenId: ID!) {
                revokeEnrollmentToken(tokenId: $tokenId) { success message }
            }
        "#;
        let r: Response = self.execute(q, Some(json!({ "tokenId": token_id })))?;
        Ok(r.revoke_enrollment_token)
    }
}

impl Default for ControllerClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_url_trailing_slash() {
        let c = ControllerClient::with_config(ClientConfig {
            base_url: "http://localhost:8443/".to_string(),
            api_token: None,
        });
        assert_eq!(c.graphql_url, "http://localhost:8443/graphql");
    }

    #[test]
    fn test_graphql_url_no_slash() {
        let c = ControllerClient::with_config(ClientConfig {
            base_url: "http://localhost:8443".to_string(),
            api_token: None,
        });
        assert_eq!(c.graphql_url, "http://localhost:8443/graphql");
    }
}
