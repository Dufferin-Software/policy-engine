// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Server module - BPF management, GraphQL schema, and HTTP server
//!
//! This module contains all server-side functionality:
//! - BPF program loading and management
//! - GraphQL schema and resolvers
//! - HTTP server setup
//! - Policy service with business logic
//! - Suricata IPS integration (veth mirroring, EVE consumption, flow verdicts)
//!   (only available with the `suricata` feature)

#[cfg(feature = "suricata")]
pub mod alert_stream;
pub mod audit_export;
pub mod audit_logger;
pub mod auth_middleware;
mod bpf_manager;
pub mod cpu_affinity;
#[cfg(feature = "suricata")]
pub mod eve_consumer;
pub mod event_stream;
pub mod flow_verdict_manager;
pub mod graphql;
mod http;
#[cfg(feature = "suricata")]
pub mod inspect_orchestrator;
pub mod ip_forwarding;
#[cfg(feature = "ipfix")]
pub mod ipfix_exporter;
pub mod metrics;
mod policy_service;
pub mod quic_initial;
pub mod rule_events;
pub mod rule_registry;
pub mod state_store;
#[cfg(feature = "suricata")]
pub mod suricata_coordinator;
#[cfg(feature = "suricata")]
pub mod suricata_runtime;
#[cfg(feature = "suricata")]
pub mod veth_manager;

pub use bpf_manager::BpfManager;
#[cfg(feature = "suricata")]
pub use eve_consumer::{AlertInfo, EveConsumer, SuricataAlert};
pub use flow_verdict_manager::FlowVerdictManager;
pub use http::{resolve_server_config, run_server, CliOverrides, ServerConfig};
pub use policy_service::{
    AddRuleParams, ClockSource, DeleteRuleParams, OperationResult, PolicyService,
    RuleScheduleParams, RuleStatsOutput, ServerStatus, WeeklyTimePointParams, WeeklyWindowParams,
};
pub use rule_events::{start_rule_event_broadcaster, RuleLifecycleEvent};
pub use rule_registry::{
    ManagedRule, RuleLifecycleKind, RuleRegistry, RuleSchedule, RuleState, WeeklyTimePoint,
    WeeklyWindow,
};
#[cfg(feature = "suricata")]
pub use suricata_coordinator::{SuricataCoordinator, SuricataStatus};
#[cfg(feature = "suricata")]
pub use veth_manager::VethManager;

#[cfg(test)]
mod tests;
