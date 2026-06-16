// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{bail, Context, Result};
pub mod renewal;

use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::ReceiverStream;

use policy_controller_proto::controller::{
    agent_message::Payload as AgentPayload, controller_message::Payload as CtrlPayload,
    AddressReport, AgentHello, AgentMessage, Capabilities, ControllerMessage, Heartbeat,
    InterfaceReport, LocalChangeReport, PersistedAttachment, PersistedRule, StateSnapshot,
};
use policy_controller_proto::PROTOCOL_VERSION;

use crate::{
    change_detector::ChangeDetector,
    config_applier::ConfigApplier,
    identity::NodeIdentity,
    metrics_forwarder::base_url_from_graphql,
    network_info::{InterfaceInfo, NetworkInfo},
    pending_change::PendingChangeRegistry,
    system_info::SystemInfo,
};
use policy_controller_proto::controller::{
    config_confirm::Outcome as ConfirmOutcome, ConfigConfirm,
};

// ── Stream abstraction (mockable) ────────────────────────────────────────────

/// Abstract handle to an open bidirectional agent↔controller stream.
///
/// Abstracting over tonic enables unit tests to exercise the message loop
/// with in-memory channels instead of a real gRPC connection.
#[async_trait]
pub trait AgentStreamHandle: Send {
    async fn send(&mut self, msg: AgentMessage) -> Result<()>;
    /// Returns `None` when the stream is closed by the controller.
    async fn recv(&mut self) -> Result<Option<ControllerMessage>>;
}

// ── Real tonic implementation ────────────────────────────────────────────────

/// Tonic-backed stream handle.
pub struct TonicStreamHandle {
    tx: mpsc::Sender<AgentMessage>,
    rx: tonic::codec::Streaming<ControllerMessage>,
}

#[async_trait]
impl AgentStreamHandle for TonicStreamHandle {
    async fn send(&mut self, msg: AgentMessage) -> Result<()> {
        self.tx
            .send(msg)
            .await
            .context("Failed to send message to controller")
    }

    async fn recv(&mut self) -> Result<Option<ControllerMessage>> {
        self.rx
            .message()
            .await
            .context("Failed to receive message from controller")
    }
}

// ── Connection builder ────────────────────────────────────────────────────────

/// Establishes mTLS connections to the management service.
pub async fn connect(
    management_url: String,
    ca_cert_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<TonicStreamHandle> {
    let ca = tonic::transport::Certificate::from_pem(ca_cert_pem);
    let identity = tonic::transport::Identity::from_pem(client_cert_pem, client_key_pem);
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(identity);

    let channel = tonic::transport::Channel::from_shared(management_url)
        .context("Invalid management URL")?
        .tls_config(tls)
        .context("mTLS configuration error")?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .context("Failed to connect to management service")?;

    let (tx, rx_stream) = mpsc::channel::<AgentMessage>(64);
    let mut mgmt_client =
        policy_controller_proto::controller::node_management_service_client::NodeManagementServiceClient::new(channel);

    let response = mgmt_client
        .agent_stream(ReceiverStream::new(rx_stream))
        .await
        .context("Failed to open agent stream")?;

    Ok(TonicStreamHandle {
        tx,
        rx: response.into_inner(),
    })
}

// ── Stream message loop ───────────────────────────────────────────────────────

/// Heartbeat interval.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// How often the agent polls the local policy-engine for out-of-band config
/// changes (e.g., rules added via the policy-client CLI). Faster than the
/// heartbeat because operator-driven CLI edits need to appear in the
/// controller's view promptly.
const CHANGE_DETECT_INTERVAL: Duration = Duration::from_secs(5);

/// Convert local interface info to proto InterfaceReport, filtering out blocklisted names.
fn interfaces_to_proto(interfaces: &[InterfaceInfo], blocklist: &[String]) -> Vec<InterfaceReport> {
    interfaces
        .iter()
        .filter(|iface| !blocklist.iter().any(|b| b == &iface.name))
        .map(|iface| InterfaceReport {
            name: iface.name.clone(),
            mac_address: iface.mac_address.clone().unwrap_or_default(),
            link_state: iface.link_state.to_string(),
            ifindex: iface.ifindex,
            addresses: iface
                .addresses
                .iter()
                .map(|a| AddressReport {
                    address: a.address.clone(),
                    prefix_len: a.prefix_len,
                    family: a.family.to_string(),
                })
                .collect(),
        })
        .collect()
}

/// Drives the bidirectional management stream for one connection lifetime.
///
/// Sends `AgentHello` immediately on connect, then runs a heartbeat timer,
/// an inbound message handler, and optional metrics/event forwarders concurrently.
/// Returns when the stream is closed or a fatal error occurs.
///
/// # Arguments
/// * `stream` — an open bidirectional handle (real tonic or mock)
/// * `identity` — node identity, used to populate `AgentHello`
/// * `agent_version` — semver string, e.g. `"0.1.0"`
/// * `applier` — optional config applier; if `None` ConfigPush is acknowledged without applying
/// * `local_server_graphql_url` — if `Some`, spawn metrics + event forwarders against the
///   local policy-engine server derived from this GraphQL URL
#[allow(clippy::too_many_arguments)]
pub async fn run_stream_loop(
    mut stream: impl AgentStreamHandle,
    identity: &dyn NodeIdentity,
    agent_version: &str,
    applier: Option<Arc<ConfigApplier>>,
    local_server_graphql_url: Option<String>,
    net_info: Option<&dyn NetworkInfo>,
    sys_info: Option<&dyn SystemInfo>,
    interface_blocklist: &[String],
    metrics_interval: Duration,
    change_detector: Option<Arc<dyn ChangeDetector>>,
) -> Result<()> {
    // Outbound channel: forwarders push messages here; the loop drains it.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<AgentMessage>(256);

    // Tracks locally-applied but unacknowledged config generations. A watchdog
    // per entry reverts and emits ConfigConfirm{REVERTED} on timeout.
    let pending = Arc::new(PendingChangeRegistry::new());

    // Send AgentHello as the first message.
    let node_id = identity.node_id();
    let hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let interfaces = net_info
        .and_then(|ni| match ni.list_interfaces() {
            Ok(ifaces) => Some(interfaces_to_proto(&ifaces, interface_blocklist)),
            Err(e) => {
                log::warn!("Failed to discover interfaces: {:#}", e);
                None
            }
        })
        .unwrap_or_default();
    let (os_pretty_name, kernel_version, dmi_sys_vendor, dmi_product_name) = sys_info
        .and_then(|si| match si.get_os_info() {
            Ok(info) => Some((
                info.os_pretty_name,
                info.kernel_version,
                info.dmi_sys_vendor,
                info.dmi_product_name,
            )),
            Err(e) => {
                log::warn!("Failed to read OS info: {:#}", e);
                None
            }
        })
        .unwrap_or_default();
    let hello = AgentMessage {
        payload: Some(AgentPayload::Hello(AgentHello {
            node_id: node_id.clone(),
            protocol_version: PROTOCOL_VERSION,
            agent_version: agent_version.to_string(),
            dmi_uuid: identity.dmi_uuid().unwrap_or_default(),
            tpm_backed: identity.tpm_available(),
            interfaces,
            hostname,
            os_pretty_name,
            kernel_version,
            dmi_sys_vendor,
            dmi_product_name,
            capabilities: Some(Capabilities {
                // No optional features wired yet — placeholder for the
                // forwarders/inspectors we'll gate behind cargo features.
                features: vec![],
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                // The only event stream agents produce today. Add to this
                // list when ipfix/suricata/quic-inspect forwarders ship.
                sources: vec!["policy_events".to_string()],
            }),
        })),
    };
    stream
        .send(hello)
        .await
        .context("Failed to send AgentHello")?;
    log::info!("Sent AgentHello (protocol_version={})", PROTOCOL_VERSION);

    // Send an initial StateSnapshot so the controller's view of attachments
    // and rules is accurate from the moment the stream opens.
    if let Some(ref graphql_url) = local_server_graphql_url {
        let snapshot = fetch_state_snapshot(graphql_url).await;
        // Seed the change-detector baseline before sending so a poll that
        // races the send doesn't classify the initial state as a "local change".
        if let Some(ref det) = change_detector {
            det.update_baseline(&snapshot);
        }
        if let Err(send_err) = stream
            .send(AgentMessage {
                payload: Some(AgentPayload::State(snapshot)),
            })
            .await
        {
            // A failure here is almost always because the controller
            // closed the stream right after AgentHello (unknown node,
            // protocol mismatch, …). Peek for the Disconnect payload
            // so the agent log surfaces *why* instead of just
            // "channel closed".
            if let Ok(Some(msg)) = stream.recv().await {
                if let Some(CtrlPayload::Disconnect(d)) = msg.payload {
                    bail!("Disconnected by controller: {}", d.reason);
                }
            }
            return Err(send_err).context("Failed to send initial StateSnapshot");
        }
    }

    // Spawn forwarders if a local server URL is configured.
    let metrics_trigger = Arc::new(Notify::new());
    // Every task below holds a clone of this connection's `outbound_tx`. They are
    // bound to the connection: aborted when `run_stream_loop` returns (i.e. on
    // stream teardown) so a reconnect never leaves a stale generation running
    // with a now-closed channel. The change detector additionally shares a
    // baseline across generations, so an orphan there silently swallows
    // out-of-band edits — but all of them leak without this. See [`AbortOnDrop`].
    let mut _connection_tasks: Vec<AbortOnDrop> = Vec::new();
    if let Some(ref graphql_url) = local_server_graphql_url {
        let base = base_url_from_graphql(graphql_url);

        let metrics_tx = outbound_tx.clone();
        let trigger = Arc::clone(&metrics_trigger);
        _connection_tasks.push(AbortOnDrop(tokio::spawn(crate::metrics_forwarder::run(
            base.clone(),
            metrics_interval,
            trigger,
            metrics_tx,
        ))));

        let events_tx = outbound_tx.clone();
        _connection_tasks.push(AbortOnDrop(tokio::spawn(crate::event_forwarder::run(
            base.clone(),
            node_id.clone(),
            events_tx,
        ))));

        let lifecycle_tx = outbound_tx.clone();
        _connection_tasks.push(AbortOnDrop(tokio::spawn(
            crate::rule_lifecycle_forwarder::run(base, node_id, lifecycle_tx),
        )));

        if let Some(ref det) = change_detector {
            let det = Arc::clone(det);
            let url = graphql_url.clone();
            let tx = outbound_tx.clone();
            _connection_tasks.push(AbortOnDrop(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(CHANGE_DETECT_INTERVAL);
                ticker.tick().await; // consume the immediate first tick
                loop {
                    ticker.tick().await;
                    if let Err(e) = change_detector_tick(det.as_ref(), &url, &tx).await {
                        log::warn!("Change detector tick failed: {:#}", e);
                    }
                }
            })));
        }
    }

    let mut heartbeat_interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat_interval.tick().await; // consume the immediate first tick

    let result = run_event_loop(
        &mut stream,
        applier.as_ref(),
        local_server_graphql_url.as_deref(),
        &pending,
        &outbound_tx,
        &mut outbound_rx,
        &mut heartbeat_interval,
        &metrics_trigger,
        change_detector.as_ref(),
    )
    .await;

    // Revert any pending changes before returning. If the stream broke while
    // a gated mutation was in-flight (e.g. a blackhole rule that severed the
    // gRPC connection), the agent must undo that change before reconnecting.
    // Without this, a new mutation pushed on the next connection would have
    // its confirm swallowed by the still-active stale rule, causing another
    // abandonment.
    if let Some(ref a) = applier {
        pending.drain_and_revert(a).await;
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn run_event_loop<S: AgentStreamHandle>(
    stream: &mut S,
    applier: Option<&Arc<ConfigApplier>>,
    local_graphql_url: Option<&str>,
    pending: &Arc<PendingChangeRegistry>,
    outbound_tx: &mpsc::Sender<AgentMessage>,
    outbound_rx: &mut mpsc::Receiver<AgentMessage>,
    heartbeat_interval: &mut tokio::time::Interval,
    metrics_trigger: &Arc<Notify>,
    change_detector: Option<&Arc<dyn ChangeDetector>>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = heartbeat_interval.tick() => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                stream.send(AgentMessage {
                    payload: Some(AgentPayload::Heartbeat(Heartbeat {
                        timestamp_ns: ts,
                    })),
                })
                .await
                .context("Failed to send heartbeat")?;
                log::debug!("Sent heartbeat");
            }

            msg = stream.recv() => {
                match msg? {
                    None => {
                        log::info!("Controller closed the stream");
                        return Ok(());
                    }
                    Some(ctrl_msg) => {
                        handle_controller_message(
                            ctrl_msg,
                            stream,
                            applier,
                            local_graphql_url,
                            pending,
                            outbound_tx,
                            metrics_trigger,
                            change_detector,
                        )
                        .await?;
                    }
                }
            }

            Some(outbound_msg) = outbound_rx.recv() => {
                stream.send(outbound_msg).await.context("Failed to send forwarder message")?;
            }
        }
    }
}

async fn handle_controller_message(
    msg: ControllerMessage,
    stream: &mut impl AgentStreamHandle,
    applier: Option<&Arc<ConfigApplier>>,
    local_graphql_url: Option<&str>,
    pending: &Arc<PendingChangeRegistry>,
    outbound_tx: &mpsc::Sender<AgentMessage>,
    metrics_trigger: &Arc<Notify>,
    change_detector: Option<&Arc<dyn ChangeDetector>>,
) -> Result<()> {
    match msg.payload {
        Some(CtrlPayload::Config(push)) => {
            log::info!(
                "Received DeltaConfigPush (full_restore={}, adds={}, deletes={}, generation={})",
                push.is_full_restore,
                push.rules_to_add.len(),
                push.rule_ids_to_delete.len(),
                push.generation_id
            );

            let gated = !push.generation_id.is_empty();
            let generation_id = push.generation_id.clone();
            let deadline_ms = push.confirm_deadline_ms;

            if let Some(a) = applier {
                if gated {
                    // Gated push: capture inverse ops, apply inline, then confirm.
                    // These are typically small incremental diffs so should be fast.
                    let inverse_ops = a.capture_inverse(&push).await;
                    let (success, error_message) = a.apply(&push).await;
                    if success {
                        // Sync the change-detector baseline to post-apply state so
                        // the next poll doesn't echo this controller-pushed delta
                        // back as a "local change", causing a feedback loop.
                        refresh_baseline(change_detector, local_graphql_url).await;
                        pending.register(
                            generation_id.clone(),
                            inverse_ops,
                            deadline_ms,
                            Arc::clone(a),
                            outbound_tx.clone(),
                        );
                    }
                    let outcome = if success {
                        ConfirmOutcome::Applied
                    } else {
                        ConfirmOutcome::Rejected
                    };
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigResult(
                                policy_controller_proto::controller::ConfigApplyResult {
                                    success,
                                    error_message: error_message.clone(),
                                    ruleset_id: String::new(),
                                    ruleset_version: 0,
                                },
                            )),
                        })
                        .await
                        .context("Failed to send ConfigApplyResult")?;
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: outcome as i32,
                                error_message,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm")?;
                } else {
                    // Ungated full-restore (fire-and-forget from push_config): spawn in the
                    // background so the message loop can continue processing gated mutations
                    // without stalling behind potentially many HTTP calls to the local engine.
                    let applier_clone = Arc::clone(a);
                    let tx = outbound_tx.clone();
                    let detector_clone = change_detector.cloned();
                    let url_clone = local_graphql_url.map(|u| u.to_string());
                    tokio::spawn(async move {
                        let (ok, err) = applier_clone.apply(&push).await;
                        if ok {
                            refresh_baseline(detector_clone.as_ref(), url_clone.as_deref()).await;
                        }
                        let _ = tx
                            .send(AgentMessage {
                                payload: Some(AgentPayload::ConfigResult(
                                    policy_controller_proto::controller::ConfigApplyResult {
                                        success: ok,
                                        error_message: err,
                                        ruleset_id: String::new(),
                                        ruleset_version: 0,
                                    },
                                )),
                            })
                            .await;
                    });
                }
            } else {
                log::debug!("No ConfigApplier configured — acknowledging without applying");
                stream
                    .send(AgentMessage {
                        payload: Some(AgentPayload::ConfigResult(
                            policy_controller_proto::controller::ConfigApplyResult {
                                success: true,
                                error_message: String::new(),
                                ruleset_id: String::new(),
                                ruleset_version: 0,
                            },
                        )),
                    })
                    .await
                    .context("Failed to send ConfigApplyResult")?;
                if gated {
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Applied as i32,
                                error_message: String::new(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm")?;
                }
            }
        }
        Some(CtrlPayload::CommitAck(ack)) => {
            log::info!(
                "Received ConfigCommitAck (generation={}, committed={})",
                ack.generation_id,
                ack.committed
            );
            if ack.committed {
                pending.commit(&ack.generation_id);
            } else if let Some(a) = applier {
                let reason = if ack.reason.is_empty() {
                    "controller denied commit".to_string()
                } else {
                    format!("controller denied commit: {}", ack.reason)
                };
                let reverted = pending
                    .revert(&ack.generation_id, a, outbound_tx, &reason)
                    .await;
                if !reverted {
                    log::warn!(
                        "CommitAck{{committed=false}} for unknown generation {} — nothing to revert",
                        ack.generation_id
                    );
                }
            } else {
                log::warn!("CommitAck received but no ConfigApplier configured");
            }
        }
        Some(CtrlPayload::StateQuery(_)) => {
            log::info!("Received StateQuery — collecting current state snapshot");
            let snapshot = match local_graphql_url {
                Some(url) => fetch_state_snapshot(url).await,
                None => {
                    log::debug!("No local server URL configured — sending empty StateSnapshot");
                    StateSnapshot::default()
                }
            };
            stream
                .send(AgentMessage {
                    payload: Some(AgentPayload::State(snapshot)),
                })
                .await
                .context("Failed to send StateSnapshot")?;
        }
        Some(CtrlPayload::Disconnect(d)) => {
            log::info!("Controller requested disconnect: {}", d.reason);
            bail!("Disconnected by controller: {}", d.reason);
        }
        Some(CtrlPayload::Attach(attach)) => {
            let interface_name = attach.interface_name.clone();
            let generation_id = attach.generation_id.clone();
            let direction_str =
                match policy_controller_proto::controller::BpfDirection::try_from(attach.direction)
                {
                    Ok(policy_controller_proto::controller::BpfDirection::Ingress) => "ingress",
                    Ok(policy_controller_proto::controller::BpfDirection::Egress) => "egress",
                    _ => {
                        return Err(anyhow::anyhow!(
                            "Invalid direction value: {}",
                            attach.direction
                        ))
                    }
                };
            let mode_str = match policy_controller_proto::controller::BpfMode::try_from(attach.mode)
            {
                Ok(policy_controller_proto::controller::BpfMode::Auto) => "auto",
                Ok(policy_controller_proto::controller::BpfMode::Native) => "native",
                Ok(policy_controller_proto::controller::BpfMode::Generic) => "generic",
                Ok(policy_controller_proto::controller::BpfMode::Offload) => "offload",
                _ => return Err(anyhow::anyhow!("Invalid mode value: {}", attach.mode)),
            };
            log::info!(
                "Received AttachProgram (interface={}, direction={}, mode={}, generation={})",
                interface_name,
                direction_str,
                mode_str,
                generation_id,
            );
            if let Some(url) = local_graphql_url {
                let url_for_sb = url.to_string();
                let url_for_snapshot = url.to_string();
                let direction = direction_str.to_string();
                let mode = mode_str.to_string();
                let iface = interface_name.clone();
                let tx = outbound_tx.clone();
                // BPF first-load triggers the verifier + JIT and can take 10–25 s.
                // Spawn in the background so the message loop can continue receiving
                // other messages (including the next gated mutation) without blocking.
                tokio::spawn(async move {
                    let join_result = tokio::task::spawn_blocking(move || {
                        use policy_engine_dev::{ClientConfig, PolicyClient};
                        let client = PolicyClient::with_config(ClientConfig {
                            server_url: url_for_sb,
                            ..Default::default()
                        });
                        match direction.as_str() {
                            "ingress" => client.attach_ingress(&iface, &mode),
                            "egress" => client.attach_tc(&iface),
                            _ => Err(anyhow::anyhow!("Invalid direction: {}", direction)),
                        }
                    })
                    .await;

                    let (confirm_outcome, confirm_error) = match join_result {
                        Err(e) => {
                            log::error!("Attach spawn_blocking panicked: {:#}", e);
                            (
                                ConfirmOutcome::Rejected,
                                format!("spawn_blocking panicked: {:#}", e),
                            )
                        }
                        Ok(Ok(r)) if r.success => {
                            log::info!(
                                "Successfully attached program to {} {}",
                                direction_str,
                                interface_name
                            );
                            (ConfirmOutcome::Applied, String::new())
                        }
                        Ok(Ok(r)) => {
                            log::warn!("Failed to attach program: {}", r.message);
                            (ConfirmOutcome::Rejected, r.message.clone())
                        }
                        Ok(Err(e)) => {
                            log::error!("Error attaching program: {:#}", e);
                            (ConfirmOutcome::Rejected, format!("{:#}", e))
                        }
                    };

                    if !generation_id.is_empty() {
                        let _ = tx
                            .send(AgentMessage {
                                payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                    generation_id,
                                    outcome: confirm_outcome as i32,
                                    error_message: confirm_error,
                                })),
                            })
                            .await;
                    }

                    // Snapshot after attach so controller sees updated attachment state.
                    let snapshot = fetch_state_snapshot(&url_for_snapshot).await;
                    let _ = tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::State(snapshot)),
                        })
                        .await;
                });
            } else {
                log::warn!("No local GraphQL URL configured — cannot attach program");
                if !generation_id.is_empty() {
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local GraphQL URL configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for attach")?;
                }
            }
        }
        Some(CtrlPayload::SetFib(fib)) => {
            let generation_id = fib.generation_id.clone();
            log::info!(
                "Received SetFibForwarding (interface={}, enabled={}, generation={})",
                fib.interface_name,
                fib.enabled,
                generation_id,
            );
            if let Some(url) = local_graphql_url {
                let url = url.to_string();
                let url_for_push = url.clone();
                let enabled = fib.enabled;
                let interface = fib.interface_name.clone();
                let op_result = tokio::task::spawn_blocking(move || {
                    use policy_engine_dev::{ClientConfig, PolicyClient};
                    let client = PolicyClient::with_config(ClientConfig {
                        server_url: url,
                        ..Default::default()
                    });
                    client.set_fib_forwarding(&interface, enabled)
                })
                .await
                .context("spawn_blocking panicked")?;

                let (confirm_outcome, confirm_error) = match &op_result {
                    Ok(r) if r.success => {
                        log::info!(
                            "FIB forwarding {} on {}",
                            if fib.enabled { "enabled" } else { "disabled" },
                            fib.interface_name
                        );
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Ok(r) => {
                        log::warn!("Failed to set FIB forwarding: {}", r.message);
                        (ConfirmOutcome::Rejected, r.message.clone())
                    }
                    Err(e) => {
                        log::error!("Error setting FIB forwarding: {:#}", e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if !generation_id.is_empty() {
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: confirm_outcome as i32,
                                error_message: confirm_error,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_fib")?;
                }

                if matches!(op_result, Ok(ref r) if r.success) {
                    spawn_push_state_snapshot(url_for_push, outbound_tx.clone());
                }
            } else {
                log::warn!("No local GraphQL URL configured — cannot set FIB forwarding");
                if !generation_id.is_empty() {
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local GraphQL URL configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_fib")?;
                }
            }
        }
        Some(CtrlPayload::Detach(detach)) => {
            let interface_name = detach.interface_name.clone();
            let generation_id = detach.generation_id.clone();
            let direction_str =
                match policy_controller_proto::controller::BpfDirection::try_from(detach.direction)
                {
                    Ok(policy_controller_proto::controller::BpfDirection::Ingress) => "ingress",
                    Ok(policy_controller_proto::controller::BpfDirection::Egress) => "egress",
                    _ => {
                        return Err(anyhow::anyhow!(
                            "Invalid direction value: {}",
                            detach.direction
                        ))
                    }
                };
            log::info!(
                "Received DetachProgram (interface={}, direction={}, generation={})",
                interface_name,
                direction_str,
                generation_id,
            );
            if let Some(url) = local_graphql_url {
                let url_owned = url.to_string();
                let url = url_owned.clone();
                let direction = direction_str.to_string();
                let iface = interface_name.clone();
                let op_result = tokio::task::spawn_blocking(move || {
                    use policy_engine_dev::{ClientConfig, PolicyClient};
                    let client = PolicyClient::with_config(ClientConfig {
                        server_url: url_owned,
                        ..Default::default()
                    });
                    match direction.as_str() {
                        "ingress" => client.detach_ingress(&iface),
                        "egress" => client.detach_tc(&iface),
                        _ => Err(anyhow::anyhow!("Invalid direction: {}", direction)),
                    }
                })
                .await
                .context("spawn_blocking panicked")?;

                let (confirm_outcome, confirm_error) = match &op_result {
                    Ok(r) if r.success => {
                        log::info!(
                            "Successfully detached program from {} {}",
                            direction_str,
                            interface_name
                        );
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Ok(r) => {
                        log::warn!("Failed to detach program: {}", r.message);
                        (ConfirmOutcome::Rejected, r.message.clone())
                    }
                    Err(e) => {
                        log::error!("Error detaching program: {:#}", e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if !generation_id.is_empty() {
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: confirm_outcome as i32,
                                error_message: confirm_error,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for detach")?;
                }

                // Push a fresh snapshot non-blocking so the message loop can
                // continue receiving messages while the snapshot is fetched.
                spawn_push_state_snapshot(url, outbound_tx.clone());
            } else {
                log::warn!("No local GraphQL URL configured — cannot detach program");
                if !generation_id.is_empty() {
                    stream
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local GraphQL URL configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for detach")?;
                }
            }
        }
        Some(CtrlPayload::MetricsQuery(_)) => {
            log::debug!("Received MetricsQuery — waking metrics forwarder");
            metrics_trigger.notify_one();
        }
        Some(CtrlPayload::ClearStats(req)) => {
            use policy_controller_proto::controller::clear_stats::Scope;
            let scope = Scope::try_from(req.scope).unwrap_or(Scope::Unspecified);
            log::info!(
                "Received ClearStats (scope={:?}, interface='{}', rule_id='{}', direction='{}')",
                scope,
                req.interface_name,
                req.rule_id,
                req.direction,
            );
            // Fire-and-forget: stats live only in the engine's BPF maps, so there
            // is nothing to confirm or roll back. We log the outcome; the operator
            // observes the result by re-querying stats from the controller.
            if let Some(url) = local_graphql_url {
                let url = url.to_string();
                let req = req.clone();
                let outcome = tokio::task::spawn_blocking(move || {
                    use policy_engine_dev::{ClientConfig, PolicyClient};
                    let client = PolicyClient::with_config(ClientConfig {
                        server_url: url,
                        ..Default::default()
                    });
                    apply_clear_stats(&client, scope, &req)
                })
                .await
                .context("clear-stats spawn_blocking panicked")?;

                match outcome {
                    Ok(msg) => log::info!("ClearStats applied: {}", msg),
                    Err(e) => log::warn!("ClearStats failed: {:#}", e),
                }
            } else {
                log::warn!("No local GraphQL URL configured — cannot clear stats");
            }
        }
        None => {
            log::warn!("Received ControllerMessage with no payload");
        }
    }
    Ok(())
}

/// Apply a [`ClearStats`] request against the local policy-engine, returning a
/// human-readable summary on success.
///
/// `INTERFACE` and `ALL_INTERFACES` clear per-interface counters (global +
/// ethertype). Where the request leaves `direction` empty, both directions are
/// cleared. For `ALL_INTERFACES` the engine is asked which interfaces are
/// attached and each is cleared in its attached direction — the engine has no
/// single "all interfaces" call, only per-interface and clear-everything.
fn apply_clear_stats(
    client: &policy_engine_dev::PolicyClient,
    scope: policy_controller_proto::controller::clear_stats::Scope,
    req: &policy_controller_proto::controller::ClearStats,
) -> Result<String> {
    use policy_controller_proto::controller::clear_stats::Scope;
    use policy_engine_dev::GqlDirection;

    // Directions to act on: the one named, or both when unspecified.
    let dirs: Vec<GqlDirection> = match req.direction.as_str() {
        "" => vec![GqlDirection::Ingress, GqlDirection::Egress],
        other => vec![other
            .parse::<GqlDirection>()
            .map_err(|_| anyhow::anyhow!("invalid direction '{other}'"))?],
    };

    match scope {
        Scope::Interface => {
            if req.interface_name.is_empty() {
                bail!("INTERFACE scope requires interface_name");
            }
            for dir in &dirs {
                let op = client.clear_interface_stats(&req.interface_name, *dir)?;
                if !op.success {
                    bail!(op.message);
                }
            }
            Ok(format!("cleared interface stats for {}", req.interface_name))
        }
        Scope::AllInterfaces => {
            let attachments = client.list_interfaces()?;
            let mut cleared = 0usize;
            for att in &attachments {
                let dir: GqlDirection = att.direction.parse().unwrap_or(GqlDirection::Ingress);
                let op = client.clear_interface_stats(&att.interface, dir)?;
                if !op.success {
                    bail!(op.message);
                }
                cleared += 1;
            }
            Ok(format!("cleared interface stats for {cleared} attachment(s)"))
        }
        other => bail!("unsupported ClearStats scope: {other:?}"),
    }
}

/// Aborts the wrapped task when dropped, binding a per-connection background
/// task (forwarders + change detector) to the lifetime of [`run_stream_loop`].
///
/// Each such task holds a clone of its connection's `outbound_tx`. Without this
/// guard, a stream reconnect spawns a fresh generation while the previous one
/// keeps running with a now-closed channel — a steadily growing pile of orphans.
///
/// The change detector is the worst offender: it also shares one
/// `Arc<dyn ChangeDetector>` (and thus one baseline) across generations, so an
/// orphan can advance the shared baseline (consuming an out-of-band edit) while
/// failing to deliver the resulting `LocalChange` — the edit then never reaches
/// the controller.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawn a background task to fetch and forward a fresh StateSnapshot via
/// `outbound_tx`. Non-blocking: the caller's message loop continues immediately.
fn spawn_push_state_snapshot(graphql_url: String, outbound_tx: mpsc::Sender<AgentMessage>) {
    tokio::spawn(async move {
        let snapshot = fetch_state_snapshot(&graphql_url).await;
        let _ = outbound_tx
            .send(AgentMessage {
                payload: Some(AgentPayload::State(snapshot)),
            })
            .await;
    });
}

/// Fetch a fresh snapshot and update the change-detector baseline so the next
/// poll observes the post-apply state as the new baseline. No-op if either
/// arg is `None`.
async fn refresh_baseline(
    change_detector: Option<&Arc<dyn ChangeDetector>>,
    graphql_url: Option<&str>,
) {
    if let (Some(det), Some(url)) = (change_detector, graphql_url) {
        let snapshot = fetch_state_snapshot(url).await;
        det.update_baseline(&snapshot);
    }
}

/// Run one iteration of the change-detector poll. If a change is detected,
/// fetches a fresh snapshot, advances the baseline to it, and sends a
/// `LocalChange` message over `outbound_tx`. If no change is detected, the
/// baseline is still refreshed so per-rule param drift gets re-synced.
async fn change_detector_tick(
    detector: &dyn ChangeDetector,
    graphql_url: &str,
    outbound_tx: &mpsc::Sender<AgentMessage>,
) -> Result<bool> {
    // Single, fallible read of the local engine. The diff decision, the
    // reported payload, and the new baseline must all derive from *this one*
    // snapshot: splitting the read lets the detector report a rule as deleted
    // while the payload still lists it, so the deletion re-fires forever and
    // the controller never drops the rule.
    //
    // A fetch failure propagates here (and the caller skips the tick) rather
    // than being swallowed into an empty snapshot. A transiently-unreachable
    // engine must never be mistaken for "no rules" — that would diff as "every
    // rule deleted" and make the controller wipe the node's entire config.
    let snapshot = do_fetch_state_snapshot(graphql_url).await?;
    process_snapshot(detector, snapshot, outbound_tx).await
}

/// Diff `snapshot` against the detector baseline, advance the baseline to it,
/// and emit a `LocalChange` if anything changed. Split out from
/// [`change_detector_tick`] so the diff/emit logic is unit-testable without a
/// live engine — the tick itself owns the single fallible fetch.
async fn process_snapshot(
    detector: &dyn ChangeDetector,
    snapshot: StateSnapshot,
    outbound_tx: &mpsc::Sender<AgentMessage>,
) -> Result<bool> {
    let Some(changes) = detector.diff_against_baseline(&snapshot.rules) else {
        // No change detected: still re-sync the baseline so per-rule param
        // drift gets re-synced on the next tick.
        detector.update_baseline(&snapshot);
        return Ok(false);
    };

    let snapshot_ids: Vec<u64> = snapshot.rules.iter().map(|r| r.id).collect();
    let added_ids: Vec<u64> = changes.added_rules.iter().map(|r| r.id).collect();
    log::info!(
        "change_detector_tick: detector_added={added_ids:?} \
         detector_deleted={:?} snapshot_rules={} snapshot_ids={snapshot_ids:?}",
        changes.deleted_rule_ids,
        snapshot.rules.len(),
    );

    // Send first, advance the baseline only on a *successful* send. If the send
    // fails (e.g. a stale `outbound_tx` from a since-reconnected stream),
    // advancing the baseline anyway would silently consume the change and leave
    // the controller permanently out of sync — the original symptom of this bug.
    outbound_tx
        .send(AgentMessage {
            payload: Some(AgentPayload::LocalChange(LocalChangeReport {
                current_state: Some(snapshot.clone()),
                source: "detected".to_string(),
            })),
        })
        .await
        .context("Failed to send LocalChange")?;
    detector.update_baseline(&snapshot);
    Ok(true)
}

/// Query the local policy-engine and build a [`StateSnapshot`].
///
/// On any error (e.g. policy-engine not yet attached), logs a warning and
/// returns an empty snapshot so the controller can push the desired state.
async fn fetch_state_snapshot(graphql_url: &str) -> StateSnapshot {
    match do_fetch_state_snapshot(graphql_url).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "StateQuery: failed to read local policy-engine state: {:#}",
                e
            );
            StateSnapshot::default()
        }
    }
}

async fn do_fetch_state_snapshot(graphql_url: &str) -> Result<StateSnapshot> {
    use policy_engine_dev::{ClientConfig, GqlDirection, PolicyClient};

    let url = graphql_url.to_string();
    let (ingress_rules, egress_rules, interfaces, fib_entries, stop_behavior) =
        tokio::task::spawn_blocking(move || {
            let client = PolicyClient::with_config(ClientConfig {
                server_url: url,
                ..Default::default()
            });
            let ingress = client.list_rules(GqlDirection::Ingress)?;
            let egress = client.list_rules(GqlDirection::Egress)?;
            let ifaces = client.list_interfaces()?;
            let fib = client.list_fib_forwarding().unwrap_or_default();
            let sb = client.get_stop_behavior().unwrap_or_default();
            Ok::<_, anyhow::Error>((ingress, egress, ifaces, fib, sb))
        })
        .await
        .context("spawn_blocking panicked")??;

    let mut rules = Vec::new();
    for (dir, rule_list) in [
        (policy_engine_dev::GqlDirection::Ingress, ingress_rules),
        (policy_engine_dev::GqlDirection::Egress, egress_rules),
    ] {
        for r in rule_list {
            let actions: Vec<policy_engine_dev::ActionInput> = r
                .actions
                .iter()
                .map(|a| policy_engine_dev::ActionInput {
                    action: a.action,
                    priority: a.priority,
                    param: a.param,
                })
                .collect();

            let input = policy_engine_dev::AddRuleInput {
                interface: r.interface.clone(),
                direction: dir,
                src: Some(r.src_prefix.clone()),
                dst: Some(r.dst_prefix.clone()),
                sport: r.sport,
                dport: r.dport,
                protocol: format!("{:?}", r.protocol).to_lowercase(),
                actions,
                id: Some(r.rule_id),
                sni: r.sni.clone(),
                quic_version: r.quic_version.clone(),
                src_mac: r.src_mac.clone(),
                dst_mac: r.dst_mac.clone(),
                expires_after_secs: None,
                schedule: None,
            };

            let params_json =
                serde_json::to_vec(&input).context("Failed to serialize rule as JSON")?;
            rules.push(PersistedRule {
                id: r.rule_id,
                params_json,
            });
        }
    }

    let attachments = interfaces
        .iter()
        .map(|iface| {
            let direction = match iface.direction.to_lowercase().as_str() {
                "ingress" => policy_controller_proto::controller::BpfDirection::Ingress as i32,
                "egress" => policy_controller_proto::controller::BpfDirection::Egress as i32,
                _ => policy_controller_proto::controller::BpfDirection::Unspecified as i32,
            };
            let xdp_mode = match iface.mode.to_lowercase().as_str() {
                "auto" => policy_controller_proto::controller::BpfMode::Auto as i32,
                "native" => policy_controller_proto::controller::BpfMode::Native as i32,
                "generic" => policy_controller_proto::controller::BpfMode::Generic as i32,
                "offload" => policy_controller_proto::controller::BpfMode::Offload as i32,
                _ => policy_controller_proto::controller::BpfMode::Unspecified as i32,
            };
            PersistedAttachment {
                interface_name: iface.interface.clone(),
                direction,
                xdp_mode,
            }
        })
        .collect();

    let fib_forwarding_interfaces = fib_entries
        .into_iter()
        .filter_map(|(iface, enabled)| if enabled { Some(iface) } else { None })
        .collect();

    Ok(StateSnapshot {
        rules,
        attachments,
        default_actions: std::collections::HashMap::new(),
        fib_forwarding_interfaces,
        per_interface_default_actions: std::collections::HashMap::new(),
        stop_behavior,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MockNodeIdentity;
    use policy_controller_proto::controller::{DeltaConfigPush, StateQuery};
    use std::{collections::VecDeque, sync::Arc};
    use tokio::sync::Mutex;

    #[test]
    fn apply_clear_stats_rejects_invalid_direction() {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        use policy_engine_dev::{ClientConfig, PolicyClient};
        // URL is never dialed — validation bails before any HTTP call.
        let client = PolicyClient::with_config(ClientConfig {
            server_url: "http://127.0.0.1:0".to_string(),
            ..Default::default()
        });
        let req = ClearStats {
            scope: Scope::Interface as i32,
            interface_name: "eth0".to_string(),
            rule_id: String::new(),
            direction: "sideways".to_string(),
        };
        let err = apply_clear_stats(&client, Scope::Interface, &req).unwrap_err();
        assert!(err.to_string().contains("invalid direction"), "{err}");
    }

    #[test]
    fn apply_clear_stats_interface_requires_name() {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        use policy_engine_dev::{ClientConfig, PolicyClient};
        let client = PolicyClient::with_config(ClientConfig {
            server_url: "http://127.0.0.1:0".to_string(),
            ..Default::default()
        });
        let req = ClearStats {
            scope: Scope::Interface as i32,
            interface_name: String::new(),
            rule_id: String::new(),
            direction: "ingress".to_string(),
        };
        let err = apply_clear_stats(&client, Scope::Interface, &req).unwrap_err();
        assert!(err.to_string().contains("interface_name"), "{err}");
    }

    /// In-memory stream handle driven by pre-loaded messages from the controller.
    struct MockStreamHandle {
        sent: Arc<Mutex<Vec<AgentMessage>>>,
        inbound: VecDeque<ControllerMessage>,
    }

    impl MockStreamHandle {
        fn new(inbound: Vec<ControllerMessage>) -> (Self, Arc<Mutex<Vec<AgentMessage>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            let handle = Self {
                sent: Arc::clone(&sent),
                inbound: inbound.into(),
            };
            (handle, sent)
        }
    }

    #[async_trait]
    impl AgentStreamHandle for MockStreamHandle {
        async fn send(&mut self, msg: AgentMessage) -> Result<()> {
            self.sent.lock().await.push(msg);
            Ok(())
        }

        async fn recv(&mut self) -> Result<Option<ControllerMessage>> {
            Ok(self.inbound.pop_front())
        }
    }

    fn mock_identity() -> MockNodeIdentity {
        let mut id = MockNodeIdentity::new();
        id.expect_node_id().returning(|| "test-node-id".to_string());
        id.expect_dmi_uuid().returning(|| None);
        id.expect_tpm_available().returning(|| false);
        id
    }

    #[tokio::test]
    async fn test_hello_sent_first() {
        let (stream, sent) = MockStreamHandle::new(vec![]); // empty: stream closes immediately
        let id = mock_identity();
        let _ = run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            None,
            &[],
            Duration::from_secs(30),
            None,
        )
        .await;

        let messages = sent.lock().await;
        assert!(!messages.is_empty(), "At least AgentHello must be sent");
        match &messages[0].payload {
            Some(AgentPayload::Hello(h)) => {
                assert_eq!(h.node_id, "test-node-id");
                assert_eq!(h.protocol_version, PROTOCOL_VERSION);
                assert_eq!(h.agent_version, "0.1.0");
                assert!(!h.tpm_backed);
            }
            other => panic!("Expected Hello, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_config_push_acknowledged() {
        let push = ControllerMessage {
            payload: Some(CtrlPayload::Config(DeltaConfigPush {
                rules_to_add: vec![],
                rule_ids_to_delete: vec![],
                is_full_restore: false,
                per_interface_default_actions: std::collections::HashMap::new(),
                generation_id: String::new(),
                confirm_deadline_ms: 0,
                stop_behavior: String::new(),
            })),
        };
        // After the push, stream closes (None)
        let (stream, sent) = MockStreamHandle::new(vec![push]);
        let id = mock_identity();
        run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            None,
            &[],
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();

        let messages = sent.lock().await;
        // Find ConfigApplyResult
        let result = messages
            .iter()
            .find(|m| matches!(&m.payload, Some(AgentPayload::ConfigResult(_))));
        assert!(
            result.is_some(),
            "ConfigApplyResult must be sent after DeltaConfigPush"
        );
        if let Some(AgentPayload::ConfigResult(r)) = &result.unwrap().payload {
            assert!(r.success);
        }
    }

    #[tokio::test]
    async fn test_state_query_returns_snapshot() {
        let query = ControllerMessage {
            payload: Some(CtrlPayload::StateQuery(StateQuery {})),
        };
        let (stream, sent) = MockStreamHandle::new(vec![query]);
        let id = mock_identity();
        run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            None,
            &[],
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap();

        let messages = sent.lock().await;
        let snapshot = messages
            .iter()
            .find(|m| matches!(&m.payload, Some(AgentPayload::State(_))));
        assert!(
            snapshot.is_some(),
            "StateSnapshot must be sent after StateQuery"
        );
    }

    #[tokio::test]
    async fn test_disconnect_returns_error() {
        let disconnect = ControllerMessage {
            payload: Some(CtrlPayload::Disconnect(
                policy_controller_proto::controller::Disconnect {
                    reason: "maintenance".to_string(),
                },
            )),
        };
        let (stream, _) = MockStreamHandle::new(vec![disconnect]);
        let id = mock_identity();
        let result = run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            None,
            &[],
            Duration::from_secs(30),
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("maintenance"));
    }

    #[tokio::test]
    async fn test_hello_includes_dmi_and_os_info_from_sys_info_trait() {
        use crate::system_info::{MockSystemInfo, OsInfo};

        let (stream, sent) = MockStreamHandle::new(vec![]);
        let id = mock_identity();
        let mut sys = MockSystemInfo::new();
        sys.expect_get_os_info().returning(|| {
            Ok(OsInfo {
                os_pretty_name: "Debian GNU/Linux 13 (trixie)".to_string(),
                kernel_version: "6.12.74+deb13+1-amd64".to_string(),
                dmi_sys_vendor: "Dell Inc.".to_string(),
                dmi_product_name: "PowerEdge R340".to_string(),
            })
        });
        let _ = run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            Some(&sys),
            &[],
            Duration::from_secs(30),
            None,
        )
        .await;

        let messages = sent.lock().await;
        match &messages[0].payload {
            Some(AgentPayload::Hello(h)) => {
                assert_eq!(h.os_pretty_name, "Debian GNU/Linux 13 (trixie)");
                assert_eq!(h.kernel_version, "6.12.74+deb13+1-amd64");
                assert_eq!(h.dmi_sys_vendor, "Dell Inc.");
                assert_eq!(h.dmi_product_name, "PowerEdge R340");
            }
            other => panic!("Expected Hello, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hello_empty_dmi_when_sys_info_absent() {
        let (stream, sent) = MockStreamHandle::new(vec![]);
        let id = mock_identity();
        let _ = run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            None,
            &[],
            Duration::from_secs(30),
            None,
        )
        .await;

        let messages = sent.lock().await;
        match &messages[0].payload {
            Some(AgentPayload::Hello(h)) => {
                assert!(h.dmi_sys_vendor.is_empty());
                assert!(h.dmi_product_name.is_empty());
            }
            other => panic!("Expected Hello, got {:?}", other),
        }
    }

    // ── change detector wiring ────────────────────────────────────────────────

    use crate::change_detector::{LocalChanges, MockChangeDetector};

    #[tokio::test]
    async fn test_process_snapshot_sends_local_change_when_changes_detected() {
        let mut detector = MockChangeDetector::new();
        // The diff is computed against the *same* snapshot we feed in, so the
        // payload can never disagree with the detector's decision.
        detector
            .expect_diff_against_baseline()
            .times(1)
            .returning(|_| {
                Some(LocalChanges {
                    added_rules: vec![PersistedRule {
                        id: 42,
                        params_json: vec![],
                    }],
                    deleted_rule_ids: vec![],
                })
            });
        // Baseline must advance after the send so we don't re-emit on the next tick.
        detector.expect_update_baseline().times(1).returning(|_| ());

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(8);
        let snapshot = StateSnapshot::default();
        let sent = process_snapshot(&detector, snapshot, &tx).await.unwrap();
        assert!(sent);

        let msg = rx.try_recv().expect("LocalChange must be sent");
        match msg.payload {
            Some(AgentPayload::LocalChange(report)) => {
                assert_eq!(report.source, "detected");
                assert!(report.current_state.is_some());
            }
            other => panic!("Expected LocalChange, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_process_snapshot_silent_when_no_changes() {
        let mut detector = MockChangeDetector::new();
        detector
            .expect_diff_against_baseline()
            .times(1)
            .returning(|_| None);
        // Even on a no-change tick we re-sync baseline so per-rule param
        // drift doesn't accumulate.
        detector.expect_update_baseline().times(1).returning(|_| ());

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(8);
        let snapshot = StateSnapshot::default();
        let sent = process_snapshot(&detector, snapshot, &tx).await.unwrap();
        assert!(!sent);
        assert!(
            rx.try_recv().is_err(),
            "Nothing should be sent when no changes detected"
        );
    }

    #[tokio::test]
    async fn test_process_snapshot_keeps_baseline_when_send_fails() {
        // A stale `outbound_tx` (e.g. from a stream that reconnected under us)
        // makes the send fail. The baseline must NOT advance — otherwise the
        // change is silently consumed and the controller never learns about it,
        // which is exactly the write-back bug this guards against.
        let mut detector = MockChangeDetector::new();
        detector
            .expect_diff_against_baseline()
            .times(1)
            .returning(|_| {
                Some(LocalChanges {
                    added_rules: vec![],
                    deleted_rule_ids: vec![42],
                })
            });
        detector.expect_update_baseline().times(0);

        let (tx, rx) = mpsc::channel::<AgentMessage>(8);
        drop(rx); // close the channel so the send fails

        let snapshot = StateSnapshot::default();
        let result = process_snapshot(&detector, snapshot, &tx).await;
        assert!(
            result.is_err(),
            "send on a closed channel must surface an error"
        );
    }

    #[tokio::test]
    async fn test_refresh_baseline_invokes_update_baseline() {
        // The same helper is called both after a controller-pushed delta is
        // applied and after attach/detach/set-fib operations — anywhere the
        // local state has just changed under controller direction. Without
        // this, the next change-detector poll would echo the just-applied
        // mutation back as a "local change" and produce a feedback loop.
        let mut detector = MockChangeDetector::new();
        detector.expect_update_baseline().times(1).returning(|_| ());
        let detector: Arc<dyn ChangeDetector> = Arc::new(detector);

        // Empty URL → fetch_state_snapshot returns default. We only care that
        // update_baseline is invoked.
        refresh_baseline(Some(&detector), Some("")).await;
    }

    #[tokio::test]
    async fn test_refresh_baseline_noop_without_url() {
        // No graphql URL means we have nowhere to fetch from — must be a
        // no-op rather than calling update_baseline with stale data.
        let mut detector = MockChangeDetector::new();
        detector.expect_update_baseline().times(0);
        let detector: Arc<dyn ChangeDetector> = Arc::new(detector);
        refresh_baseline(Some(&detector), None).await;
    }
}
