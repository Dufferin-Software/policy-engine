// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use policy_controller_proto::{
    controller::{
        agent_message::Payload as AgentPayload, config_confirm::Outcome as ConfigConfirmOutcome,
        controller_message::Payload as CtrlPayload,
        node_management_service_server::NodeManagementService, AgentMessage, ConfigCommitAck,
        ConfigConfirm, ControllerMessage, DeltaConfigPush, Disconnect, RenewClientCertRequest,
        RenewClientCertResponse, StateQuery,
    },
    PROTOCOL_VERSION,
};

use crate::{
    event_bus::{EventBus, TaggedEventBatch},
    metrics_store::MetricsStore,
    node_registry::NodeRegistry,
    pending::{ConfirmOutcome, PendingRegistry},
    rule_lifecycle_bus::{RuleLifecycleBus, RuleLifecycleEvent},
    session::NodeSessionManager,
    store::{ControllerStore, NewAuditEntry, NodeStatus},
};

/// Build a full-restore `DeltaConfigPush` from a list of rules.
///
/// Each rule is already a complete `RuleAdd`.  The returned push has
/// `is_full_restore = true`, meaning the agent should flush all existing rules
/// before applying.
///
/// `per_interface_default_actions`: map from "interface:direction" to "pass"/"drop".
pub fn build_full_restore_push(
    rules: Vec<policy_controller_proto::controller::RuleAdd>,
    per_interface_default_actions: std::collections::HashMap<String, String>,
    stop_behavior: Option<String>,
) -> DeltaConfigPush {
    DeltaConfigPush {
        rules_to_add: rules,
        rule_ids_to_delete: Vec::new(),
        is_full_restore: true,
        per_interface_default_actions,
        // Reconciliation-on-reconnect pushes bypass the pending-generation gate:
        // they reflect already-committed DB state, not new user intent.
        generation_id: String::new(),
        confirm_deadline_ms: 0,
        stop_behavior: stop_behavior.unwrap_or_default(),
    }
}

// ── Service implementation ────────────────────────────────────────────────────

pub struct NodeManagementServiceImpl {
    sessions: Arc<NodeSessionManager>,
    store: Arc<dyn ControllerStore>,
    event_bus: Arc<EventBus>,
    metrics_store: Arc<MetricsStore>,
    pending: Arc<PendingRegistry>,
    rule_lifecycle_bus: Arc<RuleLifecycleBus>,
    /// Used by `renew_client_cert` to drive CSR-signing + old-serial
    /// revocation in a single registry-level operation that also publishes
    /// to the in-memory revocation watch.
    registry: Arc<NodeRegistry>,
}

impl NodeManagementServiceImpl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<NodeSessionManager>,
        store: Arc<dyn ControllerStore>,
        event_bus: Arc<EventBus>,
        metrics_store: Arc<MetricsStore>,
        pending: Arc<PendingRegistry>,
        rule_lifecycle_bus: Arc<RuleLifecycleBus>,
        registry: Arc<NodeRegistry>,
    ) -> Self {
        Self {
            sessions,
            store,
            event_bus,
            metrics_store,
            pending,
            rule_lifecycle_bus,
            registry,
        }
    }
}

#[tonic::async_trait]
impl NodeManagementService for NodeManagementServiceImpl {
    type AgentStreamStream = ReceiverStream<Result<ControllerMessage, Status>>;

    async fn agent_stream(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::AgentStreamStream>, Status> {
        let (tx, rx) = mpsc::channel::<Result<ControllerMessage, Status>>(64);
        let sessions = Arc::clone(&self.sessions);
        let store = Arc::clone(&self.store);
        let event_bus = Arc::clone(&self.event_bus);
        let metrics_store = Arc::clone(&self.metrics_store);
        let pending = Arc::clone(&self.pending);

        // Wrap the tonic Streaming in a boxed stream so the handler is testable
        // without a real gRPC connection.
        let inbound = Box::pin(request.into_inner().map(|r| r.map_err(|e| e.into())));
        tokio::spawn(handle_agent_stream(
            inbound,
            tx,
            sessions,
            store,
            event_bus,
            metrics_store,
            pending,
            Arc::clone(&self.rule_lifecycle_bus),
        ));

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn renew_client_cert(
        &self,
        request: Request<RenewClientCertRequest>,
    ) -> Result<Response<RenewClientCertResponse>, Status> {
        renew_client_cert_impl(&self.registry, request).await
    }
}

/// Free function so it can be unit-tested without spinning up a tonic server.
/// Pulls the authenticated `node_id` from the peer cert's CN, verifies the
/// CSR's subject CN matches, and delegates to [`NodeRegistry::renew_cert`].
async fn renew_client_cert_impl(
    registry: &Arc<NodeRegistry>,
    request: Request<RenewClientCertRequest>,
) -> Result<Response<RenewClientCertResponse>, Status> {
    use tonic::transport::server::TlsConnectInfo;

    // ── Step 1: pull peer cert from the TLS connection ────────────────────────
    // The mgmt port runs with `RevokingClientCertVerifier`, so by the time a
    // request reaches here the handshake-layer trust chain check has already
    // passed and the cert is not revoked. We trust the CN here for routing
    // because that authentication already happened.
    let tls_info = request
        .extensions()
        .get::<TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>()
        .ok_or_else(|| Status::unauthenticated("RenewClientCert requires an mTLS connection"))?;
    let peer_certs = tls_info
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("No peer certificate presented"))?;
    let leaf = peer_certs
        .first()
        .ok_or_else(|| Status::unauthenticated("Empty peer cert chain"))?;

    let peer_node_id = extract_cn(leaf.as_ref()).map_err(|e| {
        Status::unauthenticated(format!("Could not extract CN from peer cert: {e}"))
    })?;

    // ── Step 2: parse CSR (cheap) and check its CN matches the peer ───────────
    // The registry will re-parse the CSR to verify the signature when it
    // signs; we parse here only for the CN cross-check.
    let req = request.into_inner();
    let csr_pem = std::str::from_utf8(&req.csr_pem)
        .map_err(|_| Status::invalid_argument("csr_pem must be UTF-8"))?;
    let csr_cn = csr_subject_cn(csr_pem)
        .map_err(|e| Status::invalid_argument(format!("Could not parse CSR: {e}")))?;
    if csr_cn != peer_node_id {
        log::warn!("RenewClientCert rejected: CSR CN '{csr_cn}' != peer cert CN '{peer_node_id}'");
        return Err(Status::permission_denied(
            "CSR subject CN does not match authenticated node_id",
        ));
    }

    // ── Step 3: delegate to the registry ──────────────────────────────────────
    let renewed = registry
        .renew_cert(&peer_node_id, csr_pem)
        .await
        .map_err(|e| {
            // The registry returns a typed error for "node not Active" / "cert
            // revoked"; surface them as PermissionDenied so the agent doesn't
            // retry indefinitely against a decommissioned node.
            let s = format!("{e:#}");
            log::warn!("RenewClientCert failed for {peer_node_id}: {s}");
            if s.contains("not active") || s.contains("revoked") {
                Status::permission_denied(s)
            } else {
                Status::internal(s)
            }
        })?;

    Ok(Response::new(RenewClientCertResponse {
        cert_pem: renewed.cert_pem.into_bytes(),
        cert_serial: renewed.serial,
        not_after_unix: renewed.not_after_unix,
    }))
}

fn extract_cn(cert_der: &[u8]) -> Result<String, String> {
    use x509_parser::prelude::FromDer;
    let (_rest, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| format!("x509 parse: {e}"))?;
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));
    cn.ok_or_else(|| "no CN in subject".to_string())
}

fn csr_subject_cn(csr_pem: &str) -> Result<String, String> {
    use x509_parser::prelude::FromDer;
    let mut reader = csr_pem.as_bytes();
    let der = rustls_pemfile::csr(&mut reader)
        .map_err(|e| format!("PEM decode: {e}"))?
        .ok_or_else(|| "PEM contained no CSR".to_string())?;
    let (_rest, parsed) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&der)
            .map_err(|e| format!("CSR parse: {e}"))?;
    let cn = parsed
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));
    cn.ok_or_else(|| "no CN in CSR subject".to_string())
}

// ── Stream handler ────────────────────────────────────────────────────────────

/// Capacity of the buffered outbound channel that sits between the inbound
/// reader / session pushes and the tonic response channel. Larger than the
/// tonic channel so transient bursts are absorbed; if it fills, the agent has
/// genuinely stopped draining and the stream is torn down (see [`enqueue`]).
const OUTBOUND_BUFFER: usize = 256;

/// How long the teardown path waits for the writer task to flush a final queued
/// message (e.g. a `Disconnect`) before aborting it.
const WRITER_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Enqueue an outbound message on the buffered writer channel **without
/// blocking**. A full buffer means the agent has stopped draining the stream;
/// returning an error tears the connection down so the agent reconnects and
/// re-syncs, rather than parking the inbound reader on a back-pressured send —
/// which deadlocks the bidirectional stream (both ends blocked on `send`, so
/// neither reads and neither send window reopens).
fn enqueue(
    tx: &mpsc::Sender<Result<ControllerMessage, Status>>,
    msg: ControllerMessage,
) -> anyhow::Result<()> {
    use mpsc::error::TrySendError;
    match tx.try_send(Ok(msg)) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            anyhow::bail!("outbound buffer full — agent not draining; closing stream")
        }
        Err(TrySendError::Closed(_)) => anyhow::bail!("outbound channel closed"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_agent_stream(
    mut inbound: impl futures_util::Stream<Item = anyhow::Result<AgentMessage>> + Send + Unpin + 'static,
    tx: mpsc::Sender<Result<ControllerMessage, Status>>,
    sessions: Arc<NodeSessionManager>,
    store: Arc<dyn ControllerStore>,
    event_bus: Arc<EventBus>,
    metrics_store: Arc<MetricsStore>,
    pending: Arc<PendingRegistry>,
    rule_lifecycle_bus: Arc<RuleLifecycleBus>,
) {
    // Buffered outbound + dedicated writer task. The inbound reader and session
    // pushes enqueue onto `out_tx` (never blocking); the writer drains onto the
    // tonic response channel `tx`, absorbing HTTP/2 back-pressure off the read
    // path. `out_tx` is what gets registered with the session manager, so all
    // controller→agent traffic funnels through this one buffer.
    let (out_tx, mut out_rx) = mpsc::channel::<Result<ControllerMessage, Status>>(OUTBOUND_BUFFER);
    let mut writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    match drive_stream(
        &mut inbound,
        &out_tx,
        &sessions,
        &store,
        &event_bus,
        &metrics_store,
        &pending,
        &rule_lifecycle_bus,
    )
    .await
    {
        Ok(node_id) => {
            log::info!("Agent stream closed for node {}", node_id);
            sessions.unregister_if_sender(&node_id, &out_tx);
        }
        Err(e) => {
            log::warn!("Agent stream error: {:#}", e);
        }
    }

    // Let the writer flush any final queued message (e.g. a Disconnect emitted
    // just before bailing) before the response stream closes, bounded so a
    // wedged socket can't hang the task.
    drop(out_tx);
    if tokio::time::timeout(WRITER_FLUSH_TIMEOUT, &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_stream(
    inbound: &mut (impl futures_util::Stream<Item = anyhow::Result<AgentMessage>> + Send + Unpin),
    tx: &mpsc::Sender<Result<ControllerMessage, Status>>,
    sessions: &Arc<NodeSessionManager>,
    store: &Arc<dyn ControllerStore>,
    event_bus: &Arc<EventBus>,
    metrics_store: &Arc<MetricsStore>,
    pending: &Arc<PendingRegistry>,
    rule_lifecycle_bus: &Arc<RuleLifecycleBus>,
) -> anyhow::Result<String> {
    // ── Step 1: receive and validate AgentHello ───────────────────────────────
    let hello = match inbound.next().await {
        None => anyhow::bail!("Agent disconnected before sending hello"),
        Some(Err(e)) => return Err(e),
        Some(Ok(msg)) => match msg.payload {
            Some(AgentPayload::Hello(h)) => h,
            other => anyhow::bail!("Expected AgentHello, got {:?}", other),
        },
    };

    if hello.protocol_version != PROTOCOL_VERSION {
        let reason = format!(
            "Protocol version mismatch: agent={}, controller={}",
            hello.protocol_version, PROTOCOL_VERSION
        );
        log::warn!("{}", reason);
        // Best-effort: we bail immediately after, and the writer task flushes
        // this on teardown.
        let _ = tx.try_send(Ok(ControllerMessage {
            payload: Some(CtrlPayload::Disconnect(Disconnect {
                reason: reason.clone(),
            })),
        }));
        anyhow::bail!("{}", reason);
    }

    let node_id = hello.node_id.clone();
    let node_hostname: Option<String> = if hello.hostname.is_empty() {
        None
    } else {
        Some(hello.hostname.clone())
    };

    // ── Step 2: verify node is Active in the store ────────────────────────────
    let node = match store.get_node(&node_id).await? {
        Some(n) => n,
        None => {
            // Most common cause: controller DB was wiped (pre-1.0 schema
            // change) but the agent still has its identity + cert from
            // before. Tell the agent explicitly so its log isn't just
            // "channel closed" on the next send.
            let reason = format!(
                "Unknown node: {} — controller has no record of this identity; \
                 re-enroll required (delete identity.key and controller-client.*)",
                node_id
            );
            log::warn!("{}", reason);
            // Best-effort: we bail immediately after, and the writer task
            // flushes this on teardown.
            let _ = tx.try_send(Ok(ControllerMessage {
                payload: Some(CtrlPayload::Disconnect(Disconnect {
                    reason: reason.clone(),
                })),
            }));
            anyhow::bail!("{}", reason);
        }
    };

    if node.status != NodeStatus::Active {
        let reason = format!("Node {} is not active (status={})", node_id, node.status);
        // Best-effort: we bail immediately after, and the writer task flushes
        // this on teardown.
        let _ = tx.try_send(Ok(ControllerMessage {
            payload: Some(CtrlPayload::Disconnect(Disconnect {
                reason: reason.clone(),
            })),
        }));
        anyhow::bail!("{}", reason);
    }

    // Defense-in-depth on top of the status check above: if this node's issued
    // cert serial has been explicitly revoked, reject the connection even when
    // the row was somehow flipped back to Active. A future change should also
    // extract the serial from the *presented* peer cert at the TLS layer so a
    // stale cert cannot be used after re-enrollment.
    if let Some(ref serial) = node.cert_serial {
        if !serial.is_empty() && store.is_cert_revoked(serial).await.unwrap_or(false) {
            let reason = format!("Node {} cert is revoked", node_id);
            let _ = store
                .append_audit(NewAuditEntry {
                    operator: None,
                    action: "revoked_cert_reject".to_string(),
                    node_id: Some(node_id.clone()),
                    detail: Some(format!("serial={}", hex::encode(serial))),
                    tenant_id: None,
                })
                .await;
            // Best-effort: we bail immediately after, and the writer task
            // flushes this on teardown.
            let _ = tx.try_send(Ok(ControllerMessage {
                payload: Some(CtrlPayload::Disconnect(Disconnect {
                    reason: reason.clone(),
                })),
            }));
            anyhow::bail!("{}", reason);
        }
    }

    log::info!(
        "Node {} connected (agent_version={}, tpm={})",
        node_id,
        hello.agent_version,
        hello.tpm_backed
    );
    let now = chrono::Utc::now();
    let _ = store.update_node_last_seen(&node_id, now).await;
    let _ = store
        .update_node_agent_info(
            &node_id,
            hello.tpm_backed,
            if hello.agent_version.is_empty() {
                None
            } else {
                Some(&hello.agent_version)
            },
            if hello.hostname.is_empty() {
                None
            } else {
                Some(&hello.hostname)
            },
            if hello.os_pretty_name.is_empty() {
                None
            } else {
                Some(&hello.os_pretty_name)
            },
            if hello.kernel_version.is_empty() {
                None
            } else {
                Some(&hello.kernel_version)
            },
            if hello.dmi_sys_vendor.is_empty() {
                None
            } else {
                Some(&hello.dmi_sys_vendor)
            },
            if hello.dmi_product_name.is_empty() {
                None
            } else {
                Some(&hello.dmi_product_name)
            },
            if hello.dmi_uuid.is_empty() {
                None
            } else {
                Some(&hello.dmi_uuid)
            },
        )
        .await;

    // Capabilities: opaque JSON blob so adding fields to the proto doesn't
    // require a schema change. An agent that pre-dates step 6 won't set
    // `capabilities`, in which case we leave the column at its default
    // ("{}") rather than overwriting it.
    if let Some(caps) = hello.capabilities.as_ref() {
        match serde_json::to_string(&serde_json::json!({
            "features": caps.features,
            "engine_version": caps.engine_version,
            "sources": caps.sources,
        })) {
            Ok(blob) => {
                let _ = store.update_node_capabilities(&node_id, &blob).await;
            }
            Err(e) => {
                log::warn!("node {node_id}: failed to serialize capabilities, skipping: {e:#}")
            }
        }
    }

    // ── Step 3: store discovered interfaces ────────────────────────────────
    if !hello.interfaces.is_empty() {
        log::info!(
            "Node {} reported {} interfaces",
            node_id,
            hello.interfaces.len()
        );
        if let Err(e) = store
            .upsert_node_interfaces(&node_id, &hello.interfaces)
            .await
        {
            log::warn!("Failed to store interfaces for {}: {:#}", node_id, e);
        }
    }

    // ── Step 4: register session ─────────────────────────────────────────────
    // Interface rows are committed above before we mark the node online so any
    // caller gating on is_online() is guaranteed to find the interface rows.
    sessions.register(node_id.clone(), node.tenant_id.clone(), tx.clone());

    // ── Step 5: reconciliation — send full restore from stored rules ─────
    // TTL-expired rules are excluded so they are not pushed back to the agent;
    // the TTL reaper removes them from the DB on the next tick.
    match store.list_rules_for_node(&node_id).await {
        Ok(all_rules) => {
            let now = chrono::Utc::now();
            let rules: Vec<_> = all_rules
                .into_iter()
                .filter(|r| !crate::ttl_reaper::is_ttl_expired(r, now))
                .collect();
            if !rules.is_empty() {
                let rule_adds = crate::reconciliation::rules_to_rule_adds(&rules);
                let defaults = build_per_interface_defaults_map(&node_id, store).await;
                let push = build_full_restore_push(rule_adds, defaults, node.stop_behavior.clone());
                log::info!(
                    "Sending reconciliation DeltaConfigPush to node {} ({} rules)",
                    node_id,
                    push.rules_to_add.len()
                );
                enqueue(
                    tx,
                    ControllerMessage {
                        payload: Some(CtrlPayload::Config(push)),
                    },
                )?;
            } else {
                log::debug!(
                    "No stored rules for node {}, skipping reconciliation",
                    node_id
                );
            }
        }
        Err(e) => log::warn!("Failed to load rules for {}: {:#}", node_id, e),
    }

    // Re-apply the operator-configured metrics interval (if any) on connect, so
    // it survives agent restarts without the agent persisting it locally.
    if let Some(secs) = node.metrics_interval_secs {
        log::info!(
            "Sending SetMetricsInterval({}s) to node {} on connect",
            secs,
            node_id
        );
        enqueue(
            tx,
            ControllerMessage {
                payload: Some(CtrlPayload::SetMetricsInterval(
                    policy_controller_proto::controller::SetMetricsInterval {
                        interval_secs: secs,
                    },
                )),
            },
        )?;
    }

    // ── Step 6: message loop ──────────────────────────────────────────────────
    while let Some(item) = inbound.next().await {
        let msg = match item {
            Ok(m) => m,
            Err(e) => {
                log::warn!("Stream error from {}: {:#}", node_id, e);
                break;
            }
        };
        match msg.payload {
            Some(AgentPayload::Heartbeat(hb)) => {
                log::debug!("Heartbeat from {} (ts_ns={})", node_id, hb.timestamp_ns);
                let _ = store
                    .update_node_last_seen(&node_id, chrono::Utc::now())
                    .await;
            }
            Some(AgentPayload::State(snap)) => {
                log::debug!(
                    "StateSnapshot from {} ({} rules, {} attachments)",
                    node_id,
                    snap.rules.len(),
                    snap.attachments.len()
                );
                // Persist attachment state so the UI can display it.
                {
                    use policy_controller_proto::controller::BpfDirection;
                    let att: Vec<(String, String)> = snap
                        .attachments
                        .iter()
                        .map(|a| {
                            let dir = match BpfDirection::try_from(a.direction) {
                                Ok(BpfDirection::Ingress) => "ingress",
                                Ok(BpfDirection::Egress) => "egress",
                                _ => "unknown",
                            };
                            (a.interface_name.clone(), dir.to_string())
                        })
                        .collect();
                    if let Err(e) = store.update_interface_attachments(&node_id, &att).await {
                        log::warn!("Failed to update attachments for {}: {:#}", node_id, e);
                    }
                    if let Err(e) = store
                        .update_interface_fib_forwarding(&node_id, &snap.fib_forwarding_interfaces)
                        .await
                    {
                        log::warn!("Failed to update fib_forwarding for {}: {:#}", node_id, e);
                    }
                    let urpf_modes: Vec<(String, u32)> = snap
                        .urpf_interfaces
                        .iter()
                        .map(|(name, mode)| (name.clone(), *mode))
                        .collect();
                    if let Err(e) = store.update_interface_urpf(&node_id, &urpf_modes).await {
                        log::warn!("Failed to update urpf for {}: {:#}", node_id, e);
                    }
                }
                // Diff snapshot against desired state and send delta if needed.
                // Exclude TTL-expired rules from desired so they are not pushed back —
                // the TTL reaper will delete them from the DB on the next tick.
                match store.list_rules_for_node(&node_id).await {
                    Ok(all_rules) => {
                        let now = chrono::Utc::now();
                        let desired: Vec<_> = all_rules
                            .into_iter()
                            .filter(|r| !crate::ttl_reaper::is_ttl_expired(r, now))
                            .collect();
                        let delta = crate::reconciliation::compute_delta(&desired, &snap);
                        let has_changes =
                            !delta.rules_to_add.is_empty() || !delta.rule_ids_to_delete.is_empty();
                        if has_changes {
                            log::info!(
                                "Reconciliation delta for {}: +{} -{} rules",
                                node_id,
                                delta.rules_to_add.len(),
                                delta.rule_ids_to_delete.len()
                            );
                            enqueue(
                                tx,
                                ControllerMessage {
                                    payload: Some(CtrlPayload::Config(delta)),
                                },
                            )?;
                        }
                    }
                    Err(e) => log::warn!("Failed to load rules for diff: {:#}", e),
                }
            }
            Some(AgentPayload::ConfigResult(result)) => {
                let success = result.success;
                log::info!(
                    "Node {} config apply {}{}",
                    node_id,
                    if success { "OK" } else { "FAILED" },
                    if success {
                        String::new()
                    } else {
                        format!(" — {}", result.error_message)
                    }
                );
                let _ = store
                    .append_audit(NewAuditEntry {
                        operator: None,
                        action: if success {
                            "config_applied".to_string()
                        } else {
                            "config_apply_failed".to_string()
                        },
                        node_id: Some(node_id.clone()),
                        detail: if !success {
                            Some(format!("error={}", result.error_message))
                        } else {
                            None
                        },
                        tenant_id: None,
                    })
                    .await;
            }
            Some(AgentPayload::Metrics(update)) => {
                log::debug!(
                    "MetricsUpdate from {} ({} bytes)",
                    node_id,
                    update.prometheus_text.len()
                );
                metrics_store.update(
                    &node_id,
                    update.timestamp_ns,
                    update.prometheus_text,
                    node_hostname.clone(),
                );
            }
            Some(AgentPayload::Events(batch)) => {
                log::debug!(
                    "EventBatch from {} ({} events)",
                    node_id,
                    batch.events_json.len()
                );
                event_bus.publish(TaggedEventBatch {
                    node_id: node_id.clone(),
                    timestamp_ns: batch.timestamp_ns,
                    events_json: batch.events_json,
                });
            }
            Some(AgentPayload::RuleLifecycleEvents(batch)) => {
                log::debug!(
                    "RuleLifecycleBatch from {} ({} events)",
                    node_id,
                    batch.events_json.len()
                );
                handle_rule_lifecycle_batch(&node_id, batch.events_json, store, rule_lifecycle_bus)
                    .await;
            }
            Some(AgentPayload::InterfaceUpdate(update)) => {
                log::info!(
                    "InterfaceUpdate from {} ({} interfaces)",
                    node_id,
                    update.interfaces.len()
                );
                if let Err(e) = store
                    .upsert_node_interfaces(&node_id, &update.interfaces)
                    .await
                {
                    log::warn!("Failed to store interfaces for {}: {:#}", node_id, e);
                }
            }
            Some(AgentPayload::LocalChange(report)) => {
                log::warn!(
                    "Local config change detected on node {} (source={})",
                    node_id,
                    report.source
                );
                let detail = match report.current_state.as_ref() {
                    Some(snap) => {
                        match crate::reconciliation::apply_local_change(
                            &node_id,
                            snap,
                            store,
                            chrono::Utc::now(),
                        )
                        .await
                        {
                            Ok(outcome) => {
                                log::info!(
                                    "Synced local change from {}: added={} updated={} \
                                     deleted={} unchanged={} default_actions={} \
                                     stop_behavior={} skipped={}",
                                    node_id,
                                    outcome.rules.added,
                                    outcome.rules.updated,
                                    outcome.rules.deleted,
                                    outcome.rules.unchanged,
                                    outcome.default_actions_updated,
                                    outcome.stop_behavior_updated,
                                    outcome.skipped_rules,
                                );
                                format!(
                                    "source={} added={} updated={} deleted={} unchanged={} \
                                     default_actions={} stop_behavior={} skipped={}",
                                    report.source,
                                    outcome.rules.added,
                                    outcome.rules.updated,
                                    outcome.rules.deleted,
                                    outcome.rules.unchanged,
                                    outcome.default_actions_updated,
                                    outcome.stop_behavior_updated,
                                    outcome.skipped_rules,
                                )
                            }
                            Err(e) => {
                                log::warn!(
                                    "Failed to apply local change from {}: {:#}",
                                    node_id,
                                    e
                                );
                                format!("source={} apply_error={}", report.source, e)
                            }
                        }
                    }
                    None => format!("source={} no_snapshot", report.source),
                };
                let _ = store
                    .append_audit(NewAuditEntry {
                        operator: None,
                        action: "local_change_detected".to_string(),
                        node_id: Some(node_id.clone()),
                        detail: Some(detail),
                        tenant_id: None,
                    })
                    .await;
            }
            Some(AgentPayload::RestoreRequest(req)) => {
                log::info!(
                    "State restore requested by node {} (reason={})",
                    node_id,
                    req.reason
                );
                // Send full restore.
                match store.list_rules_for_node(&node_id).await {
                    Ok(rules) => {
                        let rule_adds = crate::reconciliation::rules_to_rule_adds(&rules);
                        let defaults = build_per_interface_defaults_map(&node_id, store).await;
                        let stop_behavior = store
                            .get_node(&node_id)
                            .await
                            .ok()
                            .flatten()
                            .and_then(|n| n.stop_behavior);
                        let push = build_full_restore_push(rule_adds, defaults, stop_behavior);
                        enqueue(
                            tx,
                            ControllerMessage {
                                payload: Some(CtrlPayload::Config(push)),
                            },
                        )?;
                    }
                    Err(e) => log::warn!("Failed to load rules for restore: {:#}", e),
                }
            }
            Some(AgentPayload::ConfigConfirm(confirm)) => {
                handle_config_confirm(&node_id, confirm, pending, store, tx).await?;
            }
            Some(AgentPayload::Hello(_)) => {
                log::warn!("Unexpected second AgentHello from {}", node_id);
            }
            None => {}
        }
    }

    Ok(node_id)
}

/// Process a batch of rule lifecycle events received from an agent.
///
/// For each `ttl_expired` event, the rule is deleted from the controller DB so it
/// is not pushed back on the next reconciliation. All events are broadcast on the
/// `RuleLifecycleBus` for streaming to UI subscribers.
async fn handle_rule_lifecycle_batch(
    node_id: &str,
    events_json: Vec<Vec<u8>>,
    store: &Arc<dyn ControllerStore>,
    bus: &Arc<RuleLifecycleBus>,
) {
    for raw in events_json {
        let text = match std::str::from_utf8(&raw) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let event: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "Failed to parse rule lifecycle event from {}: {:#}",
                    node_id,
                    e
                );
                continue;
            }
        };

        let event_type = event["event_type"].as_str().unwrap_or("").to_string();
        let rule_id = event["rule_id"]
            .as_u64()
            .map(|id| id.to_string())
            .or_else(|| event["rule_id"].as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let direction = event["direction"].as_str().unwrap_or("").to_string();
        let reason = event["reason"].as_str().map(|s| s.to_string());
        let timestamp_ms = event["timestamp_ms"].as_u64().unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        });

        if event_type == "expired" && !rule_id.is_empty() {
            match store.delete_rule(&rule_id).await {
                Ok(()) => log::info!(
                    "Deleted TTL-expired rule {} from DB (node={})",
                    rule_id,
                    node_id
                ),
                Err(e) => log::warn!("Failed to delete expired rule {} from DB: {:#}", rule_id, e),
            }
        }

        // Reconstruct the interface_name from the event if present; fall back to empty.
        let interface_name = event["interface"]
            .as_str()
            .or_else(|| event["interface_name"].as_str())
            .unwrap_or("")
            .to_string();

        bus.publish(RuleLifecycleEvent {
            event_type,
            rule_id,
            node_id: node_id.to_string(),
            interface_name,
            direction,
            timestamp_ms,
            reason,
        });
    }
}

/// Build the per-interface default actions map from stored interface records.
/// Returns a map from "interface:direction" to "pass"/"drop".
async fn build_per_interface_defaults_map(
    node_id: &str,
    store: &Arc<dyn ControllerStore>,
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    match store.list_node_interfaces(node_id).await {
        Ok(interfaces) => {
            for iface in interfaces {
                if let Some(ref action) = iface.ingress_default_action {
                    map.insert(format!("{}:ingress", iface.name), action.clone());
                }
                if let Some(ref action) = iface.egress_default_action {
                    map.insert(format!("{}:egress", iface.name), action.clone());
                }
            }
        }
        Err(e) => {
            log::warn!(
                "Failed to load interfaces for default action map ({}): {:#}",
                node_id,
                e
            );
        }
    }
    map
}

/// Drain a pending generation from the registry, commit (or not) to the store
/// based on the agent's outcome, and send back a `ConfigCommitAck` so the agent
/// can clear its local inverse-delta.
async fn handle_config_confirm(
    node_id: &str,
    confirm: ConfigConfirm,
    pending: &Arc<PendingRegistry>,
    store: &Arc<dyn ControllerStore>,
    tx: &mpsc::Sender<Result<ControllerMessage, Status>>,
) -> anyhow::Result<()> {
    let gen_id = confirm.generation_id.clone();
    let outcome = ConfigConfirmOutcome::try_from(confirm.outcome)
        .unwrap_or(ConfigConfirmOutcome::Unspecified);
    log::info!(
        "ConfigConfirm from {}: gen={} outcome={:?} err='{}'",
        node_id,
        gen_id,
        outcome,
        confirm.error_message
    );

    let Some(pending_gen) = pending.take(&gen_id) else {
        // The generation was already resolved (e.g. the Applied confirm landed
        // first and was committed) or is unknown (controller restart). A late
        // *Reverted* outcome here is a genuine divergence: the agent applied the
        // change then rolled it back via its watchdog, so the controller's
        // committed/stored state — and the UI — no longer matches the agent.
        // Don't silently drop it: record the divergence and ask the agent to
        // re-report so the stored interface columns (urpf_mode, attachments, …)
        // converge to reality instead of showing the reverted value as live.
        if outcome == ConfigConfirmOutcome::Reverted {
            log::warn!(
                "Reverted confirm for already-resolved generation {} from {} — state \
                 divergence; auditing and requesting a fresh snapshot",
                gen_id,
                node_id
            );
            let _ = store
                .append_audit(NewAuditEntry {
                    operator: None,
                    action: "config_reverted_after_resolve".to_string(),
                    node_id: Some(node_id.to_string()),
                    detail: Some(format!(
                        "generation={} err={}",
                        gen_id, confirm.error_message
                    )),
                    tenant_id: None,
                })
                .await;
            // Best-effort: a full buffer means the stream is tearing down anyway.
            let _ = enqueue(
                tx,
                ControllerMessage {
                    payload: Some(CtrlPayload::StateQuery(StateQuery {})),
                },
            );
        } else {
            log::warn!(
                "ConfigConfirm for unknown or already-resolved generation {} from {}",
                gen_id,
                node_id
            );
        }
        return Ok(());
    };

    match outcome {
        ConfigConfirmOutcome::Applied => {
            match pending_gen.op.commit(store).await {
                Ok(()) => {
                    // Tell the agent it may clear its inverse-delta. The local
                    // waiter is notified regardless of whether the ack made it
                    // onto the wire; a full buffer tears the stream down (via
                    // `?`) so the agent reconnects and re-syncs.
                    let ack = ControllerMessage {
                        payload: Some(CtrlPayload::CommitAck(ConfigCommitAck {
                            generation_id: gen_id.clone(),
                            committed: true,
                            reason: String::new(),
                        })),
                    };
                    let send_res = enqueue(tx, ack);
                    pending_gen.notify(ConfirmOutcome::Applied);
                    send_res?;
                }
                Err(e) => {
                    log::error!(
                        "Commit failed for generation {} on node {}: {:#}",
                        gen_id,
                        node_id,
                        e
                    );
                    let reason = format!("{:#}", e);
                    let ack = ControllerMessage {
                        payload: Some(CtrlPayload::CommitAck(ConfigCommitAck {
                            generation_id: gen_id.clone(),
                            committed: false,
                            reason: reason.clone(),
                        })),
                    };
                    let send_res = enqueue(tx, ack);
                    pending_gen.notify(ConfirmOutcome::CommitFailed(reason));
                    send_res?;
                }
            }
        }
        ConfigConfirmOutcome::Rejected => {
            pending_gen.notify(ConfirmOutcome::Rejected(confirm.error_message));
        }
        ConfigConfirmOutcome::Reverted => {
            pending_gen.notify(ConfirmOutcome::Reverted(confirm.error_message));
        }
        ConfigConfirmOutcome::Unspecified => {
            pending_gen.notify(ConfirmOutcome::Rejected(
                "agent sent unspecified outcome".to_string(),
            ));
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event_bus::EventBus,
        metrics_store::MetricsStore,
        store::{memory::InMemoryControllerStore, NodeRecord, Rule},
    };
    use chrono::Utc;
    use futures_util::stream;
    use policy_controller_proto::controller::{AgentHello, Heartbeat};

    fn make_store() -> Arc<InMemoryControllerStore> {
        Arc::new(InMemoryControllerStore::new())
    }

    /// `enqueue` must never block: on a full buffer it returns an error (so the
    /// caller tears the stream down) rather than awaiting capacity, which would
    /// park the inbound reader and deadlock the bidirectional stream.
    #[tokio::test]
    async fn enqueue_errs_on_full_buffer_instead_of_blocking() {
        let (tx, _rx) = mpsc::channel::<Result<ControllerMessage, Status>>(1);
        let msg = || ControllerMessage {
            payload: Some(CtrlPayload::Disconnect(Disconnect {
                reason: "x".to_string(),
            })),
        };
        // First fits the single slot; second has nowhere to go.
        assert!(enqueue(&tx, msg()).is_ok());
        let err = enqueue(&tx, msg()).unwrap_err().to_string();
        assert!(err.contains("buffer full"), "unexpected error: {err}");

        // A closed channel (reader gone) is also a non-blocking error.
        let (tx2, rx2) = mpsc::channel::<Result<ControllerMessage, Status>>(1);
        drop(rx2);
        assert!(enqueue(&tx2, msg()).is_err());
    }

    fn config_confirm(gen: &str, outcome: ConfigConfirmOutcome) -> ConfigConfirm {
        ConfigConfirm {
            generation_id: gen.to_string(),
            outcome: outcome as i32,
            error_message: "watchdog".to_string(),
        }
    }

    /// A late REVERTED confirm for a generation the controller already resolved
    /// (took) must not vanish: it signals the agent rolled back a change the
    /// controller may have committed. We record the divergence and pull a fresh
    /// snapshot so stored/UI state converges to the agent's reality.
    #[tokio::test]
    async fn reverted_confirm_for_resolved_gen_audits_and_requests_snapshot() {
        let store: Arc<dyn ControllerStore> = make_store();
        let pending = make_pending(); // empty → take() returns None
        let (tx, mut rx) = mpsc::channel::<Result<ControllerMessage, Status>>(8);

        handle_config_confirm(
            "node-1",
            config_confirm("gen-x", ConfigConfirmOutcome::Reverted),
            &pending,
            &store,
            &tx,
        )
        .await
        .unwrap();

        let audits = store.list_audit(None, 10, 0).await.unwrap();
        assert!(
            audits
                .iter()
                .any(|a| a.action == "config_reverted_after_resolve"),
            "expected divergence audit, got {:?}",
            audits.iter().map(|a| &a.action).collect::<Vec<_>>()
        );

        match rx.try_recv() {
            Ok(Ok(ControllerMessage {
                payload: Some(CtrlPayload::StateQuery(_)),
            })) => {}
            other => panic!("expected a StateQuery to be enqueued, got {other:?}"),
        }
    }

    /// A non-reverted confirm (e.g. a duplicate APPLIED) for an unknown
    /// generation is benign: no divergence audit, no snapshot request.
    #[tokio::test]
    async fn applied_confirm_for_unknown_gen_is_silent() {
        let store: Arc<dyn ControllerStore> = make_store();
        let pending = make_pending();
        let (tx, mut rx) = mpsc::channel::<Result<ControllerMessage, Status>>(8);

        handle_config_confirm(
            "node-1",
            config_confirm("gen-y", ConfigConfirmOutcome::Applied),
            &pending,
            &store,
            &tx,
        )
        .await
        .unwrap();

        assert!(store.list_audit(None, 10, 0).await.unwrap().is_empty());
        assert!(rx.try_recv().is_err(), "no message should be enqueued");
    }

    fn make_bus() -> Arc<EventBus> {
        Arc::new(EventBus::new())
    }

    fn make_metrics() -> Arc<MetricsStore> {
        Arc::new(MetricsStore::new())
    }

    fn make_pending() -> Arc<PendingRegistry> {
        Arc::new(PendingRegistry::new())
    }

    fn make_lifecycle_bus() -> Arc<RuleLifecycleBus> {
        Arc::new(RuleLifecycleBus::new())
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

    fn hello_msg(node_id: &str, version: u32) -> AgentMessage {
        AgentMessage {
            payload: Some(AgentPayload::Hello(AgentHello {
                node_id: node_id.to_string(),
                protocol_version: version,
                agent_version: "0.1.0".to_string(),
                dmi_uuid: String::new(),
                tpm_backed: false,
                interfaces: vec![],
                hostname: "test-host".to_string(),
                os_pretty_name: String::new(),
                kernel_version: String::new(),
                dmi_sys_vendor: String::new(),
                dmi_product_name: String::new(),
                capabilities: None,
            })),
        }
    }

    fn msgs_stream(
        msgs: Vec<AgentMessage>,
    ) -> impl futures_util::Stream<Item = anyhow::Result<AgentMessage>> + Send + Unpin {
        stream::iter(msgs.into_iter().map(Ok))
    }

    #[tokio::test]
    async fn test_valid_hello_registers_session() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        insert_active_node(&store, "node-1").await;

        let (tx, _rx) = mpsc::channel(8);
        drive_stream(
            &mut msgs_stream(vec![hello_msg("node-1", PROTOCOL_VERSION)]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await
        .unwrap();

        assert!(sessions.is_online("node-1"));
    }

    #[tokio::test]
    async fn test_wrong_protocol_version_disconnects() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        insert_active_node(&store, "node-1").await;

        let (tx, mut rx) = mpsc::channel(8);
        let result = drive_stream(
            &mut msgs_stream(vec![hello_msg("node-1", 99)]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await;

        assert!(result.is_err());
        let sent = rx.recv().await.unwrap().unwrap();
        assert!(matches!(sent.payload, Some(CtrlPayload::Disconnect(_))));
    }

    #[tokio::test]
    async fn test_unknown_node_errors() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());

        let (tx, _rx) = mpsc::channel(8);
        let result = drive_stream(
            &mut msgs_stream(vec![hello_msg("no-such-node", PROTOCOL_VERSION)]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reconciliation_sends_config_push() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        insert_active_node(&store, "node-1").await;

        // Create a rule for node-1
        let rule = Rule {
            id: "r1".to_string(),
            tenant_id: "default".to_string(),
            node_id: "node-1".to_string(),
            interface_name: "eth0".to_string(),
            direction: "ingress".to_string(),
            src_cidr: Some("10.0.0.0/8".to_string()),
            dst_cidr: None,
            src_port: None,
            dst_port: Some(80),
            protocol: "tcp".to_string(),
            sni_pattern: None,
            quic_version: None,
            src_mac: None,
            dst_mac: None,
            actions_json: r#"[{"action":"drop","priority":0}]"#.to_string(),
            created_at: Utc::now(),
            created_by: None,
            expires_after_secs: None,
            schedule_json: None,
        };
        store.create_rule(&rule).await.unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        drive_stream(
            &mut msgs_stream(vec![hello_msg("node-1", PROTOCOL_VERSION)]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await
        .unwrap();

        let mut found_push = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(&msg.unwrap().payload, Some(CtrlPayload::Config(p)) if p.is_full_restore && !p.rules_to_add.is_empty())
            {
                found_push = true;
            }
        }
        assert!(found_push, "DeltaConfigPush must be sent on reconnect");
    }

    #[tokio::test]
    async fn test_heartbeat_updates_last_seen() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        insert_active_node(&store, "node-1").await;

        let (tx, _rx) = mpsc::channel(8);
        drive_stream(
            &mut msgs_stream(vec![
                hello_msg("node-1", PROTOCOL_VERSION),
                AgentMessage {
                    payload: Some(AgentPayload::Heartbeat(Heartbeat { timestamp_ns: 99 })),
                },
            ]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await
        .unwrap();

        let node = store.get_node("node-1").await.unwrap().unwrap();
        assert!(node.last_seen.is_some());
    }

    #[tokio::test]
    async fn test_metrics_update_stored() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        let metrics = make_metrics();
        insert_active_node(&store, "node-1").await;

        let metrics_msg = AgentMessage {
            payload: Some(AgentPayload::Metrics(
                policy_controller_proto::controller::MetricsUpdate {
                    timestamp_ns: 1000,
                    prometheus_text: b"counter 42\n".to_vec(),
                },
            )),
        };

        let (tx, _rx) = mpsc::channel(8);
        drive_stream(
            &mut msgs_stream(vec![hello_msg("node-1", PROTOCOL_VERSION), metrics_msg]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &metrics,
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await
        .unwrap();

        let data = metrics.get("node-1").unwrap();
        assert_eq!(&data, b"counter 42\n");
    }

    #[tokio::test]
    async fn test_events_published_to_bus() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        let bus = make_bus();
        let mut rx = bus.subscribe();
        insert_active_node(&store, "node-1").await;

        let events_msg = AgentMessage {
            payload: Some(AgentPayload::Events(
                policy_controller_proto::controller::EventBatch {
                    timestamp_ns: 2000,
                    node_id: "node-1".to_string(),
                    events_json: vec![b"{}".to_vec(), b"{\"x\":1}".to_vec()],
                },
            )),
        };

        let (tx, _rx) = mpsc::channel(8);
        drive_stream(
            &mut msgs_stream(vec![hello_msg("node-1", PROTOCOL_VERSION), events_msg]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &bus,
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await
        .unwrap();

        let batch = rx.try_recv().expect("Should have received an EventBatch");
        assert_eq!(batch.node_id, "node-1");
        assert_eq!(batch.events_json.len(), 2);
    }

    #[tokio::test]
    async fn test_hello_persists_tpm_and_agent_version() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        insert_active_node(&store, "node-1").await;

        let hello = AgentMessage {
            payload: Some(AgentPayload::Hello(AgentHello {
                node_id: "node-1".to_string(),
                protocol_version: PROTOCOL_VERSION,
                agent_version: "0.2.0".to_string(),
                dmi_uuid: "12345678-90ab-cdef-1234-567890abcdef".to_string(),
                tpm_backed: true,
                interfaces: vec![],
                hostname: "node-1-host".to_string(),
                os_pretty_name: "Debian 13".to_string(),
                kernel_version: "6.12.0".to_string(),
                dmi_sys_vendor: "Dell Inc.".to_string(),
                dmi_product_name: "PowerEdge R340".to_string(),
                capabilities: None,
            })),
        };

        let (tx, _rx) = mpsc::channel(8);
        drive_stream(
            &mut msgs_stream(vec![hello]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await
        .unwrap();

        let node = store.get_node("node-1").await.unwrap().unwrap();
        assert!(
            node.tpm_backed,
            "tpm_backed should be persisted from AgentHello"
        );
        assert_eq!(
            node.agent_version.as_deref(),
            Some("0.2.0"),
            "agent_version should be persisted from AgentHello"
        );
        assert_eq!(
            node.dmi_sys_vendor.as_deref(),
            Some("Dell Inc."),
            "dmi_sys_vendor should be persisted from AgentHello"
        );
        assert_eq!(
            node.dmi_product_name.as_deref(),
            Some("PowerEdge R340"),
            "dmi_product_name should be persisted from AgentHello"
        );
        assert_eq!(
            node.dmi_uuid.as_deref(),
            Some("12345678-90ab-cdef-1234-567890abcdef"),
            "dmi_uuid should be persisted from AgentHello"
        );
    }

    fn msgs_stream_with_error(
        msgs: Vec<AgentMessage>,
    ) -> impl futures_util::Stream<Item = anyhow::Result<AgentMessage>> + Send + Unpin {
        let ok_items = msgs.into_iter().map(Ok::<_, anyhow::Error>);
        let err_item = std::iter::once(Err(anyhow::anyhow!("simulated connection drop")));
        stream::iter(ok_items.chain(err_item))
    }

    #[tokio::test]
    async fn test_stream_error_after_registration_unregisters_own_session() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        insert_active_node(&store, "node-1").await;

        let (tx, _rx) = mpsc::channel(8);
        // Stream: hello (registers session), then a simulated connection error.
        // drive_stream must return Ok(node_id) so handle_agent_stream can
        // call unregister_if_sender.
        let result = drive_stream(
            &mut msgs_stream_with_error(vec![hello_msg("node-1", PROTOCOL_VERSION)]),
            &tx,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await;

        assert!(
            result.is_ok(),
            "drive_stream must return Ok after stream error"
        );
        // After Ok, handle_agent_stream would call unregister_if_sender.
        // Simulate that here:
        sessions.unregister_if_sender("node-1", &tx);
        assert!(!sessions.is_online("node-1"), "Session must be removed");
    }

    #[tokio::test]
    async fn test_stream_error_does_not_evict_reconnected_session() {
        let store = make_store();
        let sessions = Arc::new(NodeSessionManager::new());
        insert_active_node(&store, "node-1").await;

        let (tx_old, _rx_old) = mpsc::channel(8);
        // Simulate old stream ending with an error → returns Ok(node_id)
        let result = drive_stream(
            &mut msgs_stream_with_error(vec![hello_msg("node-1", PROTOCOL_VERSION)]),
            &tx_old,
            &sessions,
            &(Arc::clone(&store) as Arc<dyn ControllerStore>),
            &make_bus(),
            &make_metrics(),
            &make_pending(),
            &make_lifecycle_bus(),
        )
        .await;
        assert!(result.is_ok());

        // Node reconnects before old stream teardown → new session registered
        let (tx_new, _rx_new) = mpsc::channel(8);
        sessions.register("node-1".to_string(), "default".to_string(), tx_new.clone());
        assert!(sessions.is_online("node-1"));

        // Old stream teardown must NOT evict the new session
        sessions.unregister_if_sender("node-1", &tx_old);
        assert!(
            sessions.is_online("node-1"),
            "Reconnected session must survive old stream teardown"
        );
    }

    #[test]
    fn test_build_full_restore_push_empty() {
        let mut defaults = std::collections::HashMap::new();
        defaults.insert("eth0:ingress".to_string(), "drop".to_string());
        let push = build_full_restore_push(vec![], defaults, None);
        assert!(push.is_full_restore);
        assert!(push.rules_to_add.is_empty());
        assert_eq!(
            push.per_interface_default_actions
                .get("eth0:ingress")
                .map(|s| s.as_str()),
            Some("drop")
        );
    }

    #[test]
    fn test_build_full_restore_push_with_rules() {
        let rule_add = policy_controller_proto::controller::RuleAdd {
            rule_id: "r1".to_string(),
            interface_name: "eth0".to_string(),
            direction: "INGRESS".to_string(),
            params_json: b"{}".to_vec(),
        };
        let push = build_full_restore_push(vec![rule_add], std::collections::HashMap::new(), None);
        assert_eq!(push.rules_to_add.len(), 1);
        assert!(push.is_full_restore);
    }
}
