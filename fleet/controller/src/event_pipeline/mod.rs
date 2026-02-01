// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Event pipeline: persists policy match events shipped from agents over the
//! gRPC `EventBatch` channel.
//!
//! Wiring (see docs/event-pipeline.md "Architecture"):
//!
//!   gRPC ingest → event_bus (broadcast<TaggedEventBatch>)
//!                   ├── existing /ws/events live tail
//!                   └── persister task ──► events table
//!                                          ▲
//!                                          │
//!                                  retention task (DELETE … LIMIT)
//!
//! GraphQL `events` / `eventAggregate` and the REST projections read from
//! the same table via [`TenantScope`].

pub mod alert_bus;
pub mod alert_engine;
pub mod alert_metrics;
pub mod alert_store;
pub mod dispatcher;
pub mod grouper;
pub mod matcher;
pub mod metrics;
pub mod persister;
pub mod providers;
pub mod retention;
pub mod store;
pub mod tenant;
pub mod types;

pub use metrics::EventPipelineMetrics;
pub use persister::{spawn_persister, PersisterConfig};
pub use retention::spawn_retention;
pub use store::EventStore;
pub use tenant::{bootstrap_default_tenant, TenantScope, DEFAULT_TENANT_SLUG};
pub use types::{parse_policy_event, Action, Direction, PolicyEvent};
