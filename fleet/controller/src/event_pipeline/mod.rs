// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Event pipeline: buffers policy match events shipped from agents over the
//! gRPC `EventBatch` channel. Events are held in memory only — never
//! persisted to disk.
//!
//! Wiring (see docs/event-pipeline.md "Architecture"):
//!
//!   gRPC ingest → event_bus (broadcast<TaggedEventBatch>)
//!                   ├── existing /ws/events live tail
//!                   └── ingest task ──► in-memory ring buffer (EventStore)
//!                                        ▲
//!                                        │
//!                                retention task (age-out sweep)
//!
//! GraphQL `events` / `eventAggregate` and the REST projections read from
//! the same buffer, scoped by tenant id.

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
pub mod suricata_alert_persister;
pub mod tenant;
pub mod types;

pub use metrics::EventPipelineMetrics;
pub use persister::spawn_persister;
pub use retention::spawn_retention;
pub use store::EventStore;
pub use suricata_alert_persister::spawn_suricata_alert_persister;
pub use tenant::{bootstrap_default_tenant, TenantScope, DEFAULT_TENANT_SLUG};
pub use types::{parse_policy_event, Action, Direction, PolicyEvent};
