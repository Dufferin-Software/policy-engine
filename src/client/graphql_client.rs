//! GraphQL client for the policy engine

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::shared_types::*;

/// Client configuration
#[derive(Clone)]
pub struct ClientConfig {
    pub server_url: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:8080/graphql".to_string(),
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
        Self {
            config,
            client: reqwest::blocking::Client::new(),
        }
    }

    /// Execute a GraphQL query
    fn execute<T: for<'de> Deserialize<'de>>(&self, query: &str, variables: Option<serde_json::Value>) -> Result<T> {
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
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.interfaces)
    }

    /// Get global statistics for an interface
    pub fn get_stats(&self, interface: &str) -> Result<GlobalStatsOutput> {
        #[derive(Deserialize)]
        struct Response {
            stats: GlobalStatsOutput,
        }

        let query = r#"
            query GetStats($interface: String!) {
                stats(interface: $interface) {
                    rxPackets
                    rxBytes
                    txPackets
                    txBytes
                    policyMatches
                    policyDrops
                    policyPass
                    policyRedirects
                    parseErrors
                    tailCalls
                    bumPackets
                    nonIpUnicast
                }
            }
        "#;

        let variables = json!({
            "interface": interface
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.stats)
    }

    /// Get ethertype statistics for an interface (non-IP traffic breakdown)
    pub fn get_ethertype_stats(&self, interface: &str) -> Result<Vec<EthertypeStatsOutput>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "ethertypeStats")]
            ethertype_stats: Vec<EthertypeStatsOutput>,
        }

        let query = r#"
            query GetEthertypeStats($interface: String!) {
                ethertypeStats(interface: $interface) {
                    ethertype
                    ethertypeHex
                    name
                    packets
                }
            }
        "#;

        let variables = json!({
            "interface": interface
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.ethertype_stats)
    }

    /// Get rule statistics
    pub fn get_rule_stats(&self, rule_id: u64) -> Result<Option<RuleStatsOutput>> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "ruleStats")]
            rule_stats: Option<RuleStatsOutput>,
        }

        let query = r#"
            query GetRuleStats($ruleId: Int!) {
                ruleStats(ruleId: $ruleId) {
                    ruleId
                    packets
                    bytes
                    lastSeenNs
                }
            }
        "#;

        let variables = json!({
            "ruleId": rule_id as i64
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.rule_stats)
    }

    /// List all rules
    pub fn list_rules(&self) -> Result<Vec<LpmRuleOutput>> {
        #[derive(Deserialize)]
        struct Response {
            rules: Vec<LpmRuleOutput>,
        }

        let query = r#"
            query {
                rules {
                    ruleId
                    srcPrefix
                    dstPrefix
                    sport
                    dport
                    protocol
                    priority
                    isIpv6
                    actions {
                        action
                        priority
                    }
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.rules)
    }

    /// Attach XDP program to an interface
    pub fn attach_xdp(&self, interface: &str, mode: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "attachXdp")]
            attach_xdp: OperationResult,
        }

        let query = r#"
            mutation AttachXdp($input: AttachXdpInput!) {
                attachXdp(input: $input) {
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
        Ok(response.attach_xdp)
    }

    /// Detach XDP program from an interface
    pub fn detach_xdp(&self, interface: &str) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "detachXdp")]
            detach_xdp: OperationResult,
        }

        let query = r#"
            mutation DetachXdp($input: DetachXdpInput!) {
                detachXdp(input: $input) {
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
        Ok(response.detach_xdp)
    }

    /// Detach all XDP programs
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
                    "priority": a.priority
                })
            })
            .collect();

        let variables = json!({
            "input": {
                "src": input.src,
                "dst": input.dst,
                "sport": input.sport,
                "dport": input.dport,
                "protocol": input.protocol,
                "actions": actions,
                "id": input.id,
                "priority": input.priority,
                "tailCallSlot": input.tail_call_slot
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.add_rule)
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

    /// Flush all rules
    pub fn flush_rules(&self) -> Result<OperationResult> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "flushRules")]
            flush_rules: OperationResult,
        }

        let query = r#"
            mutation {
                flushRules {
                    success
                    message
                }
            }
        "#;

        let response: Response = self.execute(query, None)?;
        Ok(response.flush_rules)
    }

    /// Set default action
    pub fn set_default_action(&self, action: GqlPolicyAction) -> Result<OperationResult> {
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
                "action": format!("{:?}", action).to_uppercase()
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.set_default_action)
    }

    /// Register tail call program
    pub fn register_tail_call(&self, slot: u32, program: &str) -> Result<OperationResult> {
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
                "program": program
            }
        });

        let response: Response = self.execute(query, Some(variables))?;
        Ok(response.register_tail_call)
    }
}

impl Default for PolicyClient {
    fn default() -> Self {
        Self::new()
    }
}
