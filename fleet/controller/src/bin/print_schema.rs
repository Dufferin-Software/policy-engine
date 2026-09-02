// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Dump the GraphQL SDL for the controller schema to stdout.
//!
//! Used by `npm run codegen` (via `web/schema.graphql`) to type-check the
//! frontend against the current Rust schema without needing a running
//! controller. Run with:
//!
//!   cargo run --bin policy-controller-print-schema > web/schema.graphql
//!
//! Builds a no-op `TenantScope` against an in-memory SQLite so the schema
//! can be assembled without I/O of its own.

use std::sync::Arc;

use policy_controller::{
    api_tokens::ApiTokenStore,
    event_pipeline::{alert_bus::AlertRuleBus, bootstrap_default_tenant},
    graphql::{build_schema, ServiceEndpoints},
    metrics_store::MetricsStore,
    node_registry::NodeRegistry,
    pending::PendingRegistry,
    rule_lifecycle_bus::RuleLifecycleBus,
    security::ca::{CertificateAuthority, IssuedCert},
    session::NodeSessionManager,
    store::{ControllerStore, InMemoryControllerStore},
};

struct NopCa;
impl CertificateAuthority for NopCa {
    fn ca_cert_pem(&self) -> String {
        String::new()
    }
    fn ca_fingerprint_sha256(&self) -> anyhow::Result<[u8; 32]> {
        Ok([0u8; 32])
    }
    fn issue_node_cert(&self, _: &str, _: u64) -> anyhow::Result<IssuedCert> {
        unreachable!("print-schema does not issue certs")
    }
    fn issue_node_cert_from_csr(&self, _: &str, _: &str, _: u64) -> anyhow::Result<IssuedCert> {
        unreachable!("print-schema does not issue certs")
    }
    fn issue_server_cert(&self, _: &[String], _: u64) -> anyhow::Result<IssuedCert> {
        unreachable!("print-schema does not issue certs")
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let store: Arc<dyn ControllerStore> = Arc::new(InMemoryControllerStore::new());
    let registry = Arc::new(NodeRegistry::new(Arc::clone(&store), Arc::new(NopCa)));
    let sessions = Arc::new(NodeSessionManager::new());
    let pending = Arc::new(PendingRegistry::new());
    let flow_queries = Arc::new(policy_controller::flow_query::FlowQueryRegistry::new());
    let metrics_store = Arc::new(MetricsStore::new());
    let rule_lifecycle = Arc::new(RuleLifecycleBus::new());
    let alert_rule_bus = Arc::new(AlertRuleBus::new());

    let pool = sqlx::sqlite::SqlitePool::connect("sqlite::memory:").await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    let scope = Arc::new(bootstrap_default_tenant(pool.clone()).await?);
    let api_token_store = Arc::new(ApiTokenStore::new(pool.clone()));
    let operator_store = Arc::new(policy_controller::operators::OperatorStore::new(
        pool.clone(),
    ));
    let rbac_store = Arc::new(policy_controller::rbac::RbacStore::new(pool));

    let schema = build_schema(
        registry,
        store,
        sessions,
        pending,
        flow_queries,
        metrics_store,
        rule_lifecycle,
        scope,
        Arc::new(policy_controller::event_pipeline::EventStore::new()),
        alert_rule_bus,
        api_token_store,
        operator_store,
        rbac_store,
        ServiceEndpoints {
            controller_url: String::new(),
            enrollment_url: String::new(),
        },
    );

    print!("{}", schema.sdl());
    Ok(())
}
