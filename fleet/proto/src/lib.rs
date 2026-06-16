// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

/// Protocol version exchanged in AgentHello.
/// Agents with a different major version are rejected by the controller.
pub const PROTOCOL_VERSION: u32 = 1;

/// Generated gRPC types and service stubs.
pub mod controller {
    tonic::include_proto!("controller.v1");
}

// Re-export the most commonly used types at crate root for convenience.
pub use controller::{
    agent_message, clear_stats, config_confirm, controller_message, AddressReport, AgentHello,
    AgentMessage, ClearStats, ConfigApplyResult, ConfigCommitAck, ConfigConfirm, ControllerMessage,
    DeltaConfigPush,
    Disconnect, EnrollmentRequest, EnrollmentResponse, EnrollmentStatus, EnrollmentStatusRequest,
    EnrollmentStatusResponse, EventBatch, Heartbeat, InterfaceReport, InterfaceUpdate,
    LocalChangeReport, MetricsUpdate, PersistedAttachment, PersistedRule, RuleAdd, StateQuery,
    StateRestoreRequest, StateSnapshot,
};

pub use controller::{
    enrollment_service_client::EnrollmentServiceClient,
    enrollment_service_server::{EnrollmentService, EnrollmentServiceServer},
    node_management_service_client::NodeManagementServiceClient,
    node_management_service_server::{NodeManagementService, NodeManagementServiceServer},
};
