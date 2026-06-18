// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Background task that removes TTL-expired rules from the controller DB.
//!
//! The policy-engine on each agent expires TTL rules itself and forwards
//! `RuleLifecycleBatch` events to the controller (handled in `grpc/management.rs`),
//! which deletes them from the DB in real time.  This reaper is a safety net for
//! rules that aged out while the agent was offline or disconnected.

use std::{sync::Arc, time::Duration};

use chrono::Utc;

use crate::{
    rule_lifecycle_bus::{RuleLifecycleBus, RuleLifecycleEvent},
    store::ControllerStore,
};

/// Returns true if the rule's TTL has elapsed as of `now`.
pub fn is_ttl_expired(rule: &crate::store::Rule, now: chrono::DateTime<Utc>) -> bool {
    if let Some(ttl_secs) = rule.expires_after_secs {
        let expires_at = rule.created_at + chrono::Duration::seconds(ttl_secs as i64);
        now >= expires_at
    } else {
        false
    }
}

/// Single tick of the TTL reaper: scan all nodes for expired rules, delete
/// them from the DB, and emit lifecycle events.
///
/// No push to the agent is needed — the policy-engine expires the rule itself
/// and streams the lifecycle event back via `RuleLifecycleBatch`.
pub async fn tick(store: &Arc<dyn ControllerStore>, bus: &Arc<RuleLifecycleBus>) {
    let now = Utc::now();

    // None = cross-tenant: the reaper sweeps every tenant's expired rules
    // on each tick. See ControllerStore::list_nodes.
    let nodes = match store.list_nodes(None, None).await {
        Ok(n) => n,
        Err(e) => {
            log::warn!("TTL reaper: failed to list nodes: {:#}", e);
            return;
        }
    };

    for node in nodes {
        let rules = match store.list_rules_for_node(&node.id).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("TTL reaper: failed to list rules for {}: {:#}", node.id, e);
                continue;
            }
        };

        let expired: Vec<_> = rules
            .into_iter()
            .filter(|r| is_ttl_expired(r, now))
            .collect();

        if expired.is_empty() {
            continue;
        }

        let ts_ms = now.timestamp_millis() as u64;

        for rule in &expired {
            match store.delete_rule(&rule.id).await {
                Ok(()) => {
                    log::info!(
                        "TTL reaper: removed expired rule {} on node {} (iface={} dir={})",
                        rule.id,
                        node.id,
                        rule.interface_name,
                        rule.direction,
                    );
                    bus.publish(RuleLifecycleEvent {
                        event_type: "expired".to_string(),
                        rule_id: rule.id.clone(),
                        node_id: node.id.clone(),
                        interface_name: rule.interface_name.clone(),
                        direction: rule.direction.to_uppercase(),
                        timestamp_ms: ts_ms,
                        reason: Some("ttl_expired".to_string()),
                    });
                }
                Err(e) => {
                    log::warn!("TTL reaper: failed to delete rule {}: {:#}", rule.id, e);
                }
            }
        }
    }
}

/// Spawn a background loop that calls [`tick`] every 30 seconds.
pub async fn run(store: Arc<dyn ControllerStore>, bus: Arc<RuleLifecycleBus>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        tick(&store, &bus).await;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rule_lifecycle_bus::RuleLifecycleBus,
        store::{memory::InMemoryControllerStore, NodeRecord, NodeStatus, Rule},
    };
    use chrono::Utc;

    fn make_store() -> Arc<InMemoryControllerStore> {
        Arc::new(InMemoryControllerStore::new())
    }

    async fn insert_active_node(store: &InMemoryControllerStore, node_id: &str) {
        store
            .upsert_node(&NodeRecord {
                id: node_id.to_string(),
                tenant_id: "default".to_string(),
                label: None,
                public_key_der: vec![1],
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
                stop_behavior: None,
                metrics_interval_secs: None,
                capabilities: "{}".to_string(),
            })
            .await
            .unwrap();
    }

    fn make_rule(id: &str, node_id: &str, expires_after_secs: Option<u32>, age_secs: i64) -> Rule {
        Rule {
            id: id.to_string(),
            tenant_id: "default".to_string(),
            node_id: node_id.to_string(),
            interface_name: "eth0".to_string(),
            direction: "ingress".to_string(),
            src_cidr: None,
            dst_cidr: None,
            src_port: None,
            dst_port: None,
            protocol: "any".to_string(),
            sni_pattern: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            actions_json: r#"[{"action":"drop","priority":0}]"#.to_string(),
            created_at: Utc::now() - chrono::Duration::seconds(age_secs),
            created_by: None,
            expires_after_secs,
            schedule_json: None,
        }
    }

    #[test]
    fn test_is_ttl_expired_not_yet() {
        let rule = make_rule("1", "n1", Some(3600), 10); // created 10s ago, TTL 1h
        assert!(!is_ttl_expired(&rule, Utc::now()));
    }

    #[test]
    fn test_is_ttl_expired_past() {
        let rule = make_rule("1", "n1", Some(60), 120); // created 2m ago, TTL 1m
        assert!(is_ttl_expired(&rule, Utc::now()));
    }

    #[test]
    fn test_is_ttl_expired_no_ttl() {
        let rule = make_rule("1", "n1", None, 99999);
        assert!(!is_ttl_expired(&rule, Utc::now()));
    }

    #[tokio::test]
    async fn test_tick_removes_expired_rule() {
        let store = make_store();
        insert_active_node(&store, "node-1").await;
        let rule = make_rule("100", "node-1", Some(60), 120);
        store.create_rule(&rule).await.unwrap();

        let bus = Arc::new(RuleLifecycleBus::new());
        let mut rx = bus.subscribe();

        tick(&(Arc::clone(&store) as Arc<dyn ControllerStore>), &bus).await;

        assert!(
            store.get_rule("100").await.unwrap().is_none(),
            "Expired rule must be removed from DB"
        );
        let ev = rx.try_recv().expect("Lifecycle event must be emitted");
        assert_eq!(ev.event_type, "expired");
        assert_eq!(ev.rule_id, "100");
        assert_eq!(ev.node_id, "node-1");
        assert_eq!(ev.reason.as_deref(), Some("ttl_expired"));
    }

    #[tokio::test]
    async fn test_tick_preserves_live_rule() {
        let store = make_store();
        insert_active_node(&store, "node-1").await;
        let rule = make_rule("200", "node-1", Some(3600), 10); // not expired
        store.create_rule(&rule).await.unwrap();

        let bus = Arc::new(RuleLifecycleBus::new());

        tick(&(Arc::clone(&store) as Arc<dyn ControllerStore>), &bus).await;

        assert!(
            store.get_rule("200").await.unwrap().is_some(),
            "Non-expired rule must remain"
        );
    }
}
