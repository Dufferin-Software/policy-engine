// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

/// Protocol version exchanged in AgentHello.
/// Agents with a different major version are rejected by the controller.
pub const PROTOCOL_VERSION: u32 = 1;

/// Max gRPC message size for the management stream, both directions.
///
/// Tonic's default is 4 MiB, which SuricataRulesetPush can exceed: rule-file
/// content is capped at 4 MiB per file by the controller, so a push carrying
/// a few files needs headroom above the default. Both the controller server
/// and the agent client must apply this limit or oversized pushes fail with
/// an opaque transport error on one side only.
pub const MAX_MANAGEMENT_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Generated gRPC types and service stubs.
pub mod controller {
    tonic::include_proto!("controller.v1");
}

// Re-export the most commonly used types at crate root for convenience.
pub use controller::{
    agent_message, clear_stats, config_confirm, controller_message, AddressReport, AgentHello,
    AgentMessage, ClearStats, ConfigApplyResult, ConfigCommitAck, ConfigConfirm, ControllerMessage,
    DeltaConfigPush, Disconnect, EnrollmentRequest, EnrollmentResponse, EnrollmentStatus,
    EnrollmentStatusRequest, EnrollmentStatusResponse, EventBatch, Heartbeat, InterfaceReport,
    InterfaceUpdate, LocalChangeReport, MetricsUpdate, PersistedAttachment, PersistedRule, RuleAdd,
    SetMetricsInterval, StateQuery, StateRestoreRequest, StateSnapshot,
};

pub use controller::{
    enrollment_service_client::EnrollmentServiceClient,
    enrollment_service_server::{EnrollmentService, EnrollmentServiceServer},
    node_management_service_client::NodeManagementServiceClient,
    node_management_service_server::{NodeManagementService, NodeManagementServiceServer},
};

#[cfg(test)]
mod tests {
    use super::controller::*;
    use prost::Message;

    /// A peer built before a oneof variant existed decodes the unknown
    /// variant as `payload: None` (prost drops unrecognised fields). Both
    /// stream loops must therefore tolerate `None` payloads — this pins the
    /// decode behaviour the wire-compat design relies on. Simulated by
    /// hand-encoding a length-delimited message field with a tag no current
    /// variant uses.
    #[test]
    fn unknown_oneof_variant_decodes_as_none_payload() {
        let inner = SuricataAlertBatch {
            timestamp_ns: 1,
            node_id: "n".into(),
            alerts_json: vec![b"{}".to_vec()],
        }
        .encode_to_vec();
        let mut buf = Vec::new();
        // Field 1000, wire type 2 (length-delimited): unknown to AgentMessage.
        prost::encoding::encode_key(1000, prost::encoding::WireType::LengthDelimited, &mut buf);
        prost::encoding::encode_varint(inner.len() as u64, &mut buf);
        buf.extend_from_slice(&inner);

        let decoded = AgentMessage::decode(buf.as_slice()).expect("decode");
        assert!(decoded.payload.is_none());
    }

    #[test]
    fn suricata_messages_roundtrip() {
        let ctrl = ControllerMessage {
            payload: Some(controller_message::Payload::SuricataRulesetPush(
                SuricataRulesetPush {
                    files: vec![SuricataRuleFile {
                        filename: "fleet-base.rules".into(),
                        content: b"alert tcp any any -> any any (sid:1;)\n".to_vec(),
                        sha256: "ab".repeat(32),
                        rule_count: 1,
                    }],
                    desired_filenames: vec!["fleet-base.rules".into()],
                    generation_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                    confirm_deadline_ms: 30_000,
                },
            )),
        };
        let decoded = ControllerMessage::decode(ctrl.encode_to_vec().as_slice()).expect("decode");
        assert_eq!(decoded, ctrl);

        let snap = StateSnapshot {
            inspect_mode: 1,
            inspect_enabled_interfaces: vec!["eth0".into()],
            suricata_rule_files: vec![SuricataRuleFileDigest {
                filename: "fleet-base.rules".into(),
                sha256: "cd".repeat(32),
                rule_count: 1,
            }],
            ..Default::default()
        };
        let decoded = StateSnapshot::decode(snap.encode_to_vec().as_slice()).expect("decode");
        assert_eq!(decoded, snap);
    }
}
