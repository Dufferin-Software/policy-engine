// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{bail, Context, Result};
pub mod renewal;

use async_trait::async_trait;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::ReceiverStream;

use policy_controller_proto::controller::{
    agent_message::Payload as AgentPayload, controller_message::Payload as CtrlPayload,
    AddressReport, AgentHello, AgentMessage, Capabilities, ControllerMessage,
    FlowVerdictEntryProto, FlowVerdictSnapshot, Heartbeat, InterfaceReport, LocalChangeReport,
    PersistedAttachment, PersistedRule, StateSnapshot,
};
use policy_controller_proto::PROTOCOL_VERSION;

use crate::{
    change_detector::ChangeDetector,
    config_applier::{ConfigApplier, InverseOp},
    identity::NodeIdentity,
    metrics_forwarder::base_url_from_graphql,
    network_info::{InterfaceInfo, NetworkInfo},
    pending_change::watchdog_deadline_ms,
    pending_change::PendingChangeRegistry,
    system_info::SystemInfo,
};
use policy_controller_proto::controller::{
    config_confirm::Outcome as ConfirmOutcome, ConfigConfirm,
};

/// Mutual-exclusion handle shared between the controller-apply path and the
/// change-detector poll so the poll can never observe a half-applied push
/// (rule installed, baseline not yet refreshed) and report it as a local edit.
type ApplyLock = Arc<tokio::sync::Mutex<()>>;

// ── Stream abstraction (mockable) ────────────────────────────────────────────

/// Write half of an open bidirectional agent↔controller stream.
#[async_trait]
pub trait AgentStreamTx: Send + 'static {
    async fn send(&mut self, msg: AgentMessage) -> Result<()>;
}

/// Read half of an open bidirectional agent↔controller stream.
#[async_trait]
pub trait AgentStreamRx: Send {
    /// Returns `None` when the stream is closed by the controller.
    async fn recv(&mut self) -> Result<Option<ControllerMessage>>;
}

/// Abstract handle to an open bidirectional agent↔controller stream.
///
/// Abstracting over tonic enables unit tests to exercise the message loop
/// with in-memory channels instead of a real gRPC connection.
///
/// The handle splits into independent read/write halves so the connection's
/// reader is never parked behind a back-pressured send (and vice-versa). A
/// single task doing both `recv` and `send` deadlocks the bidirectional stream
/// under mutual back-pressure: while it is awaiting a send it stops reading, so
/// the peer's send window never reopens. The write half is therefore driven by a
/// dedicated task and the read half by the event loop.
pub trait AgentStreamHandle: Send {
    type Tx: AgentStreamTx;
    type Rx: AgentStreamRx;
    fn split(self) -> (Self::Tx, Self::Rx);
}

// ── Real tonic implementation ────────────────────────────────────────────────

/// Tonic-backed stream handle.
pub struct TonicStreamHandle {
    tx: mpsc::Sender<AgentMessage>,
    rx: tonic::codec::Streaming<ControllerMessage>,
}

/// Write half of [`TonicStreamHandle`]. `tx` already feeds an internal mpsc that
/// tonic's own task drains onto the socket, so `send` blocks only when the
/// HTTP/2 send window is exhausted — which is precisely why it must live off the
/// read path.
pub struct TonicStreamTx {
    tx: mpsc::Sender<AgentMessage>,
}

/// Read half of [`TonicStreamHandle`].
pub struct TonicStreamRx {
    rx: tonic::codec::Streaming<ControllerMessage>,
}

#[async_trait]
impl AgentStreamTx for TonicStreamTx {
    async fn send(&mut self, msg: AgentMessage) -> Result<()> {
        self.tx
            .send(msg)
            .await
            .context("Failed to send message to controller")
    }
}

#[async_trait]
impl AgentStreamRx for TonicStreamRx {
    async fn recv(&mut self) -> Result<Option<ControllerMessage>> {
        self.rx
            .message()
            .await
            .context("Failed to receive message from controller")
    }
}

impl AgentStreamHandle for TonicStreamHandle {
    type Tx = TonicStreamTx;
    type Rx = TonicStreamRx;
    fn split(self) -> (TonicStreamTx, TonicStreamRx) {
        (TonicStreamTx { tx: self.tx }, TonicStreamRx { rx: self.rx })
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
        policy_controller_proto::controller::node_management_service_client::NodeManagementServiceClient::new(channel)
            .max_decoding_message_size(policy_controller_proto::MAX_MANAGEMENT_MESSAGE_BYTES)
            .max_encoding_message_size(policy_controller_proto::MAX_MANAGEMENT_MESSAGE_BYTES);

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

/// How long the teardown path waits for the writer task to flush queued
/// outbound messages (e.g. revert confirms) before aborting it.
const WRITER_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

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
    stream: impl AgentStreamHandle,
    identity: &dyn NodeIdentity,
    agent_version: &str,
    applier: Option<Arc<ConfigApplier>>,
    local_server_graphql_url: Option<String>,
    net_info: Option<&dyn NetworkInfo>,
    sys_info: Option<&dyn SystemInfo>,
    interface_blocklist: &[String],
    metrics_interval: Arc<AtomicU64>,
    change_detector: Option<Arc<dyn ChangeDetector>>,
) -> Result<()> {
    // Split the stream so reads and writes run on independent tasks: a
    // back-pressured send must never park the reader (see `AgentStreamHandle`).
    let (mut writer, mut reader) = stream.split();

    // Outbound channel: forwarders and the event loop push messages here; a
    // dedicated writer task (spawned below) drains it onto the stream.
    let (outbound_tx, outbound_rx) = mpsc::channel::<AgentMessage>(256);

    // Tracks locally-applied but unacknowledged config generations. A watchdog
    // per entry reverts and emits ConfigConfirm{REVERTED} on timeout.
    let pending = Arc::new(PendingChangeRegistry::new());

    // Serialises the change-detector poll against controller-initiated config
    // applies. A gated/full-restore apply installs rules into the engine and
    // only *afterwards* refreshes the detector baseline; without this lock a
    // poll landing in that window classifies the controller's own rule as a
    // *local* edit and echoes it back as a spurious `LocalChange`. Held across
    // apply+refresh on the write side and across fetch+diff on the poll side.
    let apply_lock: ApplyLock = Arc::new(tokio::sync::Mutex::new(()));

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
    // Probed per connection (not cached across reconnects) so an engine that
    // was down or upgraded since the last stream still advertises correctly.
    let (features, sources) = probe_capabilities(local_server_graphql_url.as_deref()).await;
    // Kept for post-hello decisions (e.g. whether to spawn the alert forwarder).
    let suricata_capable = features.iter().any(|f| f == "suricata");
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
                features,
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                sources,
            }),
        })),
    };
    // Hello and the initial snapshot are sent directly on the writer half,
    // before the writer task is spawned, so they are guaranteed to reach the
    // wire ahead of any forwarder/heartbeat traffic queued on `outbound_tx`.
    writer
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
        if let Err(send_err) = writer
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
            if let Ok(Some(msg)) = reader.recv().await {
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

    // Dedicated writer task: the sole owner of the write half, draining
    // `outbound_rx` onto the stream. Keeping all sends here means the event
    // loop's reader is never parked behind a back-pressured send. Held as a bare
    // handle (not `AbortOnDrop`) so the teardown path below can drain queued
    // messages — e.g. the final REVERTED confirms from `drain_and_revert` —
    // before the connection closes, falling back to abort if it can't flush.
    let mut writer_task = tokio::spawn(async move {
        let mut outbound_rx = outbound_rx;
        while let Some(msg) = outbound_rx.recv().await {
            if let Err(e) = writer.send(msg).await {
                log::warn!("Outbound writer stopping: {:#}", e);
                break;
            }
        }
    });

    if let Some(ref graphql_url) = local_server_graphql_url {
        let base = base_url_from_graphql(graphql_url);

        let metrics_tx = outbound_tx.clone();
        let trigger = Arc::clone(&metrics_trigger);
        _connection_tasks.push(AbortOnDrop(tokio::spawn(crate::metrics_forwarder::run(
            base.clone(),
            Arc::clone(&metrics_interval),
            trigger,
            metrics_tx,
        ))));

        let events_tx = outbound_tx.clone();
        _connection_tasks.push(AbortOnDrop(tokio::spawn(crate::event_forwarder::run(
            base.clone(),
            node_id.clone(),
            events_tx,
        ))));

        // Suricata alert forwarder — only when the local engine advertised
        // the capability (a plain engine has no /ws/alerts endpoint).
        // Connection-scoped like every forwarder: must live in
        // _connection_tasks or it leaks across reconnects.
        if suricata_capable {
            let alerts_tx = outbound_tx.clone();
            _connection_tasks.push(AbortOnDrop(tokio::spawn(
                crate::suricata_alert_forwarder::run(base.clone(), node_id.clone(), alerts_tx),
            )));
        }

        let lifecycle_tx = outbound_tx.clone();
        _connection_tasks.push(AbortOnDrop(tokio::spawn(
            crate::rule_lifecycle_forwarder::run(base, node_id, lifecycle_tx),
        )));

        if let Some(ref det) = change_detector {
            let det = Arc::clone(det);
            let url = graphql_url.clone();
            let tx = outbound_tx.clone();
            let lock = Arc::clone(&apply_lock);
            _connection_tasks.push(AbortOnDrop(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(CHANGE_DETECT_INTERVAL);
                ticker.tick().await; // consume the immediate first tick
                loop {
                    ticker.tick().await;
                    if let Err(e) = change_detector_tick(det.as_ref(), &url, &tx, &lock).await {
                        log::warn!("Change detector tick failed: {:#}", e);
                    }
                }
            })));
        }
    }

    let mut heartbeat_interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat_interval.tick().await; // consume the immediate first tick

    let result = run_event_loop(
        &mut reader,
        applier.as_ref(),
        local_server_graphql_url.as_deref(),
        &pending,
        &outbound_tx,
        &mut heartbeat_interval,
        &metrics_trigger,
        &metrics_interval,
        change_detector.as_ref(),
        &apply_lock,
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

    // Graceful writer shutdown: stop the forwarders so they release their
    // outbound senders, drop our own, then let the writer drain whatever is
    // still queued (notably the revert confirms above) and exit when the
    // channel closes. Bounded so a wedged stream can't stall reconnect.
    drop(_connection_tasks);
    drop(outbound_tx);
    if tokio::time::timeout(WRITER_FLUSH_TIMEOUT, &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn run_event_loop<R: AgentStreamRx>(
    reader: &mut R,
    applier: Option<&Arc<ConfigApplier>>,
    local_graphql_url: Option<&str>,
    pending: &Arc<PendingChangeRegistry>,
    outbound_tx: &mpsc::Sender<AgentMessage>,
    heartbeat_interval: &mut tokio::time::Interval,
    metrics_trigger: &Arc<Notify>,
    metrics_interval: &Arc<AtomicU64>,
    change_detector: Option<&Arc<dyn ChangeDetector>>,
    apply_lock: &ApplyLock,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = heartbeat_interval.tick() => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;

                // Drop the heartbeat if the outbound queue is full or closed
                // rather than parking the reader on it — a missed heartbeat is
                // harmless and the next tick retries.
                if let Err(e) = outbound_tx.try_send(AgentMessage {
                    payload: Some(AgentPayload::Heartbeat(Heartbeat {
                        timestamp_ns: ts,
                    })),
                }) {
                    log::debug!("Skipped heartbeat (outbound unavailable): {e}");
                } else {
                    log::debug!("Sent heartbeat");
                }
            }

            msg = reader.recv() => {
                match msg? {
                    None => {
                        log::info!("Controller closed the stream");
                        return Ok(());
                    }
                    Some(ctrl_msg) => {
                        handle_controller_message(
                            ctrl_msg,
                            applier,
                            local_graphql_url,
                            pending,
                            outbound_tx,
                            metrics_trigger,
                            metrics_interval,
                            change_detector,
                            apply_lock,
                        )
                        .await?;
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_controller_message(
    msg: ControllerMessage,
    applier: Option<&Arc<ConfigApplier>>,
    local_graphql_url: Option<&str>,
    pending: &Arc<PendingChangeRegistry>,
    outbound_tx: &mpsc::Sender<AgentMessage>,
    metrics_trigger: &Arc<Notify>,
    metrics_interval: &Arc<AtomicU64>,
    change_detector: Option<&Arc<dyn ChangeDetector>>,
    apply_lock: &ApplyLock,
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
                    //
                    // Hold `apply_lock` across capture+apply+refresh so a
                    // concurrent change-detector poll cannot observe the engine
                    // after the rule is installed but before the baseline is
                    // refreshed — that window is what made the controller's own
                    // push echo back as a spurious local change.
                    let (success, error_message) = {
                        let _apply_guard = apply_lock.lock().await;
                        let inverse_ops = a.capture_inverse(&push).await;
                        let (success, error_message) = a.apply(&push).await;
                        if success {
                            // Sync the change-detector baseline to post-apply state
                            // so the next poll doesn't echo this controller-pushed
                            // delta back as a "local change".
                            refresh_baseline(change_detector, local_graphql_url).await;
                            pending.register(
                                generation_id.clone(),
                                inverse_ops,
                                watchdog_deadline_ms(deadline_ms),
                                Arc::clone(a),
                                outbound_tx.clone(),
                            );
                        }
                        (success, error_message)
                    };
                    let outcome = if success {
                        ConfirmOutcome::Applied
                    } else {
                        ConfirmOutcome::Rejected
                    };
                    outbound_tx
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
                    outbound_tx
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
                    let lock = Arc::clone(apply_lock);
                    tokio::spawn(async move {
                        let (ok, err) = {
                            // Same apply↔poll exclusion as the gated path: a
                            // full-restore rewrites the engine's rule set, so the
                            // detector must not read between apply and baseline
                            // refresh.
                            let _apply_guard = lock.lock().await;
                            let (ok, err) = applier_clone.apply(&push).await;
                            if ok {
                                refresh_baseline(detector_clone.as_ref(), url_clone.as_deref())
                                    .await;
                            }
                            (ok, err)
                        };
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
                outbound_tx
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
                    outbound_tx
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
            outbound_tx
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
            let gated = !generation_id.is_empty();
            let deadline_ms = attach.confirm_deadline_ms;

            if let Some(a) = applier {
                let a = Arc::clone(a);
                let pending = Arc::clone(pending);
                let tx = outbound_tx.clone();
                let url_for_snapshot = local_graphql_url.map(|u| u.to_string());
                let direction = direction_str.to_string();
                let mode = mode_str.to_string();
                let iface = interface_name.clone();
                // BPF first-load triggers the verifier + JIT and can take 10–25 s.
                // Spawn in the background so the message loop can continue receiving
                // other messages (including the next gated mutation) without blocking.
                tokio::spawn(async move {
                    // Capture prior attach state: if the program is already
                    // attached, the apply is a no-op and there is nothing to
                    // revert; otherwise the inverse is a detach.
                    let already_attached = a
                        .list_attachments()
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .any(|(i, d, _)| i == iface && d == direction);

                    let apply_res = a.attach(&iface, &direction, &mode).await;

                    let (outcome, error_message) = match &apply_res {
                        Ok(()) => {
                            log::info!("Successfully attached program to {} {}", direction, iface);
                            if gated {
                                let inverse = if already_attached {
                                    Vec::new()
                                } else {
                                    vec![InverseOp::Detach {
                                        interface: iface.clone(),
                                        direction: direction.clone(),
                                    }]
                                };
                                // Register before sending Applied so the controller's
                                // CommitAck (sent only in response to Applied) cannot
                                // race ahead of the watchdog arming.
                                pending.register(
                                    generation_id.clone(),
                                    inverse,
                                    watchdog_deadline_ms(deadline_ms),
                                    Arc::clone(&a),
                                    tx.clone(),
                                );
                            }
                            (ConfirmOutcome::Applied, String::new())
                        }
                        Err(e) => {
                            log::warn!("Failed to attach program: {:#}", e);
                            (ConfirmOutcome::Rejected, format!("{:#}", e))
                        }
                    };

                    if gated {
                        let _ = tx
                            .send(AgentMessage {
                                payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                    generation_id,
                                    outcome: outcome as i32,
                                    error_message,
                                })),
                            })
                            .await;
                    }

                    // Snapshot after attach so the controller sees updated
                    // attachment state.
                    if let Some(url) = url_for_snapshot {
                        let snapshot = fetch_state_snapshot(&url).await;
                        let _ = tx
                            .send(AgentMessage {
                                payload: Some(AgentPayload::State(snapshot)),
                            })
                            .await;
                    }
                });
            } else {
                log::warn!("No local applier configured — cannot attach program");
                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local applier configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for attach")?;
                }
            }
        }
        Some(CtrlPayload::SetFib(fib)) => {
            let generation_id = fib.generation_id.clone();
            let gated = !generation_id.is_empty();
            let deadline_ms = fib.confirm_deadline_ms;
            let enabled = fib.enabled;
            let interface = fib.interface_name.clone();
            log::info!(
                "Received SetFibForwarding (interface={}, enabled={}, generation={})",
                interface,
                enabled,
                generation_id,
            );

            if let Some(a) = applier {
                // Capture the prior enable state so the change can be rolled back
                // by the watchdog if the controller's CommitAck is not received
                // in time. Fall back to "false" if it can't be read.
                let prior = a.get_fib_forwarding(&interface).await.unwrap_or_else(|e| {
                    log::warn!(
                        "SetFib: could not read prior FIB state for {} ({:#}); \
                         will revert to disabled if needed",
                        interface,
                        e
                    );
                    false
                });

                let apply_res = a.set_fib_forwarding(&interface, enabled).await;
                let (outcome, error_message) = match &apply_res {
                    Ok(()) => {
                        log::info!(
                            "FIB forwarding {} on {}",
                            if enabled { "enabled" } else { "disabled" },
                            interface
                        );
                        if gated {
                            pending.register(
                                generation_id.clone(),
                                vec![InverseOp::SetFibForwarding {
                                    interface: interface.clone(),
                                    enabled: prior,
                                }],
                                watchdog_deadline_ms(deadline_ms),
                                Arc::clone(a),
                                outbound_tx.clone(),
                            );
                        }
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Err(e) => {
                        log::warn!("Failed to set FIB forwarding on {}: {:#}", interface, e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: outcome as i32,
                                error_message,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_fib")?;
                } else if apply_res.is_ok() {
                    if let Some(url) = local_graphql_url {
                        spawn_push_state_snapshot(url.to_string(), outbound_tx.clone());
                    }
                }
            } else {
                log::warn!("No local applier configured — cannot set FIB forwarding");
                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local applier configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_fib")?;
                }
            }
        }
        Some(CtrlPayload::SetUrpf(urpf)) => {
            let generation_id = urpf.generation_id.clone();
            let gated = !generation_id.is_empty();
            let deadline_ms = urpf.confirm_deadline_ms;
            let mode_str = match urpf.mode {
                1 => "LOOSE",
                2 => "STRICT",
                _ => "OFF",
            };
            let interface = urpf.interface_name.clone();
            log::info!(
                "Received SetUrpf (interface={}, mode={}, generation={})",
                interface,
                mode_str,
                generation_id,
            );

            if let Some(a) = applier {
                // Capture the prior mode *before* applying so the change can be
                // rolled back. uRPF filters ingress on this interface and can
                // sever the agent's own control channel, so a gated change arms
                // a watchdog that reverts to the prior mode if the controller's
                // CommitAck is not received within the deadline. If the prior
                // mode can't be read, fall back to "off" — reverting to off
                // always restores connectivity.
                let prior_mode = a.get_urpf(&interface).await.unwrap_or_else(|e| {
                    log::warn!(
                        "SetUrpf: could not read prior uRPF mode for {} ({:#}); \
                         will revert to off if needed",
                        interface,
                        e
                    );
                    "off".to_string()
                });

                let apply_res = a.set_urpf(&interface, mode_str).await;
                let (outcome, error_message) = match &apply_res {
                    Ok(()) => {
                        log::info!("uRPF {} on {}", mode_str, interface);
                        if gated {
                            pending.register(
                                generation_id.clone(),
                                vec![InverseOp::SetUrpf {
                                    interface: interface.clone(),
                                    mode: prior_mode,
                                }],
                                watchdog_deadline_ms(deadline_ms),
                                Arc::clone(a),
                                outbound_tx.clone(),
                            );
                        }
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Err(e) => {
                        log::warn!("Failed to set uRPF on {}: {:#}", interface, e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: outcome as i32,
                                error_message,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_urpf")?;
                } else if apply_res.is_ok() {
                    // Legacy (non-gated) push has no confirm handshake, so report
                    // the new state to the controller via a fresh snapshot.
                    if let Some(url) = local_graphql_url {
                        spawn_push_state_snapshot(url.to_string(), outbound_tx.clone());
                    }
                }
            } else {
                log::warn!("No local applier configured — cannot set uRPF");
                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local applier configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_urpf")?;
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
            let gated = !generation_id.is_empty();
            let deadline_ms = detach.confirm_deadline_ms;

            if let Some(a) = applier {
                // Capture the prior attach mode so the inverse can re-attach the
                // program if the change is not confirmed. If it wasn't attached,
                // detach is a no-op and the inverse is empty.
                let prior_mode = a
                    .list_attachments()
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .find(|(i, d, _)| i == &interface_name && d == direction_str)
                    .map(|(_, _, m)| m);

                let apply_res = a.detach(&interface_name, direction_str).await;
                let (outcome, error_message) = match &apply_res {
                    Ok(()) => {
                        log::info!(
                            "Successfully detached program from {} {}",
                            direction_str,
                            interface_name
                        );
                        if gated {
                            let inverse = match prior_mode {
                                Some(mode) => vec![InverseOp::Attach {
                                    interface: interface_name.clone(),
                                    direction: direction_str.to_string(),
                                    mode,
                                }],
                                None => Vec::new(),
                            };
                            pending.register(
                                generation_id.clone(),
                                inverse,
                                watchdog_deadline_ms(deadline_ms),
                                Arc::clone(a),
                                outbound_tx.clone(),
                            );
                        }
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Err(e) => {
                        log::warn!("Failed to detach program: {:#}", e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: outcome as i32,
                                error_message,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for detach")?;
                } else if apply_res.is_ok() {
                    if let Some(url) = local_graphql_url {
                        spawn_push_state_snapshot(url.to_string(), outbound_tx.clone());
                    }
                }
            } else {
                log::warn!("No local applier configured — cannot detach program");
                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local applier configured".to_string(),
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
        Some(CtrlPayload::SetMetricsInterval(req)) => {
            let secs =
                (req.interval_secs as u64).max(crate::metrics_forwarder::MIN_METRICS_INTERVAL_SECS);
            log::info!("Setting metrics scrape interval to {}s", secs);
            // Live-applied to the running forwarder (takes effect after at most
            // one current-interval sleep). Wake it so the new cadence — and a
            // fresh push — happen promptly rather than after the old interval.
            metrics_interval.store(secs, Ordering::Relaxed);
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
        Some(CtrlPayload::FlowVerdictQuery(query)) => {
            log::info!(
                "Received FlowVerdictQuery (request_id={}, direction={}, limit={})",
                query.request_id,
                query.direction,
                query.limit,
            );
            // Read-only query against the local engine's BPF verdict cache. We
            // always reply (even on failure) so the controller's waiter resolves
            // promptly rather than timing out.
            let started = std::time::Instant::now();
            let snapshot = match local_graphql_url {
                Some(url) => fetch_flow_verdicts(url, &query).await,
                None => FlowVerdictSnapshot {
                    request_id: query.request_id.clone(),
                    direction: query.direction.clone(),
                    ok: false,
                    error: "No local GraphQL URL configured".to_string(),
                    entries: Vec::new(),
                },
            };
            log::info!(
                "FlowVerdictQuery {} answered in {:?} (ok={}, entries={}{})",
                query.request_id,
                started.elapsed(),
                snapshot.ok,
                snapshot.entries.len(),
                if snapshot.ok {
                    String::new()
                } else {
                    format!(", error={}", snapshot.error)
                },
            );
            outbound_tx
                .send(AgentMessage {
                    payload: Some(AgentPayload::FlowVerdictSnapshot(snapshot)),
                })
                .await
                .context("Failed to send FlowVerdictSnapshot")?;
        }
        Some(CtrlPayload::SetInspectMode(req)) => {
            let generation_id = req.generation_id.clone();
            let gated = !generation_id.is_empty();
            let deadline_ms = req.confirm_deadline_ms;
            let mode = req.mode;
            log::info!(
                "Received SetInspectMode (mode={}, generation={})",
                mode,
                generation_id,
            );

            if let Some(a) = applier {
                // Capture the prior mode before applying so a missed CommitAck
                // reverts to it.  If it can't be read, fall back to disabled —
                // reverting to "no inspection" is always safe.
                let prior_mode = match a.get_inspect_status().await {
                    Ok(s) => s.mode,
                    Err(e) => {
                        log::warn!(
                            "SetInspectMode: could not read prior mode ({:#}); \
                             will revert to disabled if needed",
                            e
                        );
                        0
                    }
                };

                let apply_res = a.set_inspect_mode(mode).await;
                let (outcome, error_message) = match &apply_res {
                    Ok(()) => {
                        log::info!("Inspect mode set to {}", mode);
                        if gated {
                            pending.register(
                                generation_id.clone(),
                                vec![InverseOp::SetInspectMode { mode: prior_mode }],
                                watchdog_deadline_ms(deadline_ms),
                                Arc::clone(a),
                                outbound_tx.clone(),
                            );
                        }
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Err(e) => {
                        log::warn!("Failed to set inspect mode: {:#}", e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: outcome as i32,
                                error_message,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_inspect_mode")?;
                } else if apply_res.is_ok() {
                    if let Some(url) = local_graphql_url {
                        spawn_push_state_snapshot(url.to_string(), outbound_tx.clone());
                    }
                }
            } else {
                log::warn!("No local applier configured — cannot set inspect mode");
                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local applier configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_inspect_mode")?;
                }
            }
        }
        Some(CtrlPayload::SetInspectInterface(req)) => {
            let generation_id = req.generation_id.clone();
            let gated = !generation_id.is_empty();
            let deadline_ms = req.confirm_deadline_ms;
            let interface = req.interface_name.clone();
            let enabled = req.enabled;
            log::info!(
                "Received SetInspectInterface (interface={}, enabled={}, generation={})",
                interface,
                enabled,
                generation_id,
            );

            if let Some(a) = applier {
                let prior_enabled = match a.get_inspect_status().await {
                    Ok(s) => s.enabled_interfaces.iter().any(|i| i == &interface),
                    Err(e) => {
                        log::warn!(
                            "SetInspectInterface: could not read prior state for {} ({:#}); \
                             will revert to disabled if needed",
                            interface,
                            e
                        );
                        false
                    }
                };

                let apply_res = a.set_inspect_interface(&interface, enabled).await;
                let (outcome, error_message) = match &apply_res {
                    Ok(()) => {
                        log::info!(
                            "Inspection {} on {}",
                            if enabled { "enabled" } else { "disabled" },
                            interface
                        );
                        if gated {
                            pending.register(
                                generation_id.clone(),
                                vec![InverseOp::SetInspectInterface {
                                    interface: interface.clone(),
                                    enabled: prior_enabled,
                                }],
                                watchdog_deadline_ms(deadline_ms),
                                Arc::clone(a),
                                outbound_tx.clone(),
                            );
                        }
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Err(e) => {
                        log::warn!("Failed to set inspect interface {}: {:#}", interface, e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: outcome as i32,
                                error_message,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_inspect_interface")?;
                } else if apply_res.is_ok() {
                    if let Some(url) = local_graphql_url {
                        spawn_push_state_snapshot(url.to_string(), outbound_tx.clone());
                    }
                }
            } else {
                log::warn!("No local applier configured — cannot set inspect interface");
                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local applier configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for set_inspect_interface")?;
                }
            }
        }
        Some(CtrlPayload::SuricataRulesetPush(push)) => {
            let generation_id = push.generation_id.clone();
            let gated = !generation_id.is_empty();
            let deadline_ms = push.confirm_deadline_ms;
            log::info!(
                "Received SuricataRulesetPush ({} files, {} desired, generation={})",
                push.files.len(),
                push.desired_filenames.len(),
                generation_id,
            );

            if let Some(a) = applier {
                let apply_res = a.apply_suricata_ruleset_push(&push).await;
                let (outcome, error_message) = match &apply_res {
                    Ok(()) => {
                        // Non-reverting by design: register with no inverse
                        // ops so the confirm handshake still runs, but a
                        // watchdog timeout undoes nothing — the controller's
                        // snapshot-driven drift detection is the corrector.
                        if gated {
                            pending.register(
                                generation_id.clone(),
                                Vec::new(),
                                watchdog_deadline_ms(deadline_ms),
                                Arc::clone(a),
                                outbound_tx.clone(),
                            );
                        }
                        (ConfirmOutcome::Applied, String::new())
                    }
                    Err(e) => {
                        log::warn!("Failed to apply Suricata ruleset push: {:#}", e);
                        (ConfirmOutcome::Rejected, format!("{:#}", e))
                    }
                };

                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id: generation_id.clone(),
                                outcome: outcome as i32,
                                error_message,
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for suricata_ruleset_push")?;
                } else if apply_res.is_ok() {
                    if let Some(url) = local_graphql_url {
                        spawn_push_state_snapshot(url.to_string(), outbound_tx.clone());
                    }
                }
            } else {
                log::warn!("No local applier configured — cannot apply Suricata rulesets");
                if gated {
                    outbound_tx
                        .send(AgentMessage {
                            payload: Some(AgentPayload::ConfigConfirm(ConfigConfirm {
                                generation_id,
                                outcome: ConfirmOutcome::Rejected as i32,
                                error_message: "No local applier configured".to_string(),
                            })),
                        })
                        .await
                        .context("Failed to send ConfigConfirm for suricata_ruleset_push")?;
                }
            }
        }
        None => {
            log::warn!("Received ControllerMessage with no payload");
        }
    }
    Ok(())
}

/// Query the local policy-engine's flow verdict cache and build a
/// [`FlowVerdictSnapshot`] reply for the controller. Never returns an error —
/// failures are encoded in the snapshot's `ok`/`error` fields so the controller
/// always gets a correlated response.
async fn fetch_flow_verdicts(
    graphql_url: &str,
    query: &policy_controller_proto::controller::FlowVerdictQuery,
) -> FlowVerdictSnapshot {
    use policy_engine_dev::{ClientConfig, GqlDirection, PolicyClient};

    let request_id = query.request_id.clone();
    let direction = query.direction.clone();
    let limit = query.limit;
    let url = graphql_url.to_string();

    let dir: GqlDirection = match direction.to_lowercase().parse() {
        Ok(d) => d,
        Err(_) => {
            return FlowVerdictSnapshot {
                request_id,
                ok: false,
                error: format!("invalid direction '{}'", direction),
                direction,
                entries: Vec::new(),
            };
        }
    };
    // Treat 0 (or no limit) as the engine default by passing None.
    let limit_opt = if limit == 0 { None } else { Some(limit as i32) };

    let result = tokio::task::spawn_blocking(move || {
        let client = PolicyClient::with_config(ClientConfig {
            server_url: url,
            ..Default::default()
        });
        client.flow_verdict_list(dir, limit_opt)
    })
    .await;

    match result {
        Ok(Ok(entries)) => FlowVerdictSnapshot {
            request_id,
            direction,
            ok: true,
            error: String::new(),
            entries: entries
                .into_iter()
                .map(|e| FlowVerdictEntryProto {
                    src_ip: e.src_ip,
                    dst_ip: e.dst_ip,
                    src_port: e.src_port as u32,
                    dst_port: e.dst_port as u32,
                    protocol: e.protocol,
                    action: e.action,
                    expires_ns: e.expires_ns.parse().unwrap_or(0),
                    expired: e.expired,
                    packets: e.packets as u64,
                    bytes: e.bytes as u64,
                })
                .collect(),
        },
        Ok(Err(e)) => FlowVerdictSnapshot {
            request_id,
            direction,
            ok: false,
            error: format!("local engine query failed: {:#}", e),
            entries: Vec::new(),
        },
        Err(e) => FlowVerdictSnapshot {
            request_id,
            direction,
            ok: false,
            error: format!("flow-verdict query task panicked: {}", e),
            entries: Vec::new(),
        },
    }
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
            Ok(format!(
                "cleared interface stats for {}",
                req.interface_name
            ))
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
            Ok(format!(
                "cleared interface stats for {cleared} attachment(s)"
            ))
        }
        Scope::Rule => {
            let id: u64 = req
                .rule_id
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid rule_id '{}'", req.rule_id))?;
            for dir in &dirs {
                let op = client.clear_rule_stats(id, *dir)?;
                if !op.success {
                    bail!(op.message);
                }
            }
            Ok(format!("cleared rule stats for {}", req.rule_id))
        }
        Scope::AllRules => {
            // Rule stats are per-direction; clear both regardless of the request.
            for dir in [GqlDirection::Ingress, GqlDirection::Egress] {
                let op = client.clear_all_rule_stats(dir)?;
                if !op.success {
                    bail!(op.message);
                }
            }
            Ok("cleared all rule stats".to_string())
        }
        Scope::All => {
            let op = client.clear_all_stats()?;
            if !op.success {
                bail!(op.message);
            }
            Ok("cleared all stats".to_string())
        }
        Scope::Unspecified => bail!("ClearStats scope unspecified"),
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
    apply_lock: &ApplyLock,
) -> Result<bool> {
    // Exclude controller-initiated applies for the whole fetch+diff: an apply
    // installs rules and only then refreshes the baseline, so reading the engine
    // mid-apply would diff the controller's own push as a local edit. Holding the
    // lock until after `process_snapshot` advances the baseline closes that race.
    let _apply_guard = apply_lock.lock().await;

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
/// How many times [`probe_capabilities`] attempts to reach the local engine,
/// and the pause between attempts. The advertisement is sent once per stream
/// and only heals on reconnect, so losing the boot race against the engine's
/// GraphQL bind (`policy-engine.service` is `Type=simple` — systemd ordering
/// does not wait for the socket) would leave the node advertised as vanilla
/// indefinitely. Retrying for a few seconds covers that window without
/// stalling connection setup when the engine is genuinely down.
const CAPABILITY_PROBE_ATTEMPTS: u32 = 5;
const CAPABILITY_PROBE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Probe the local engine's compile-time features and derive the capability
/// advertisement for AgentHello: the `features` list gates which controller
/// message types are valid for this node, and `sources` feeds the
/// controller's alert-rule write-time validation.
///
/// The baseline (`policy_events`, no features) is returned when no local
/// engine URL is configured or the engine stays unreachable across all
/// attempts — a temporarily down engine must not be mistaken for one built
/// without a feature, and the probe reruns on every reconnect so the
/// advertisement heals itself.
async fn probe_capabilities(graphql_url: Option<&str>) -> (Vec<String>, Vec<String>) {
    probe_capabilities_with_retry(
        graphql_url,
        CAPABILITY_PROBE_ATTEMPTS,
        CAPABILITY_PROBE_RETRY_DELAY,
    )
    .await
}

async fn probe_capabilities_with_retry(
    graphql_url: Option<&str>,
    attempts: u32,
    retry_delay: std::time::Duration,
) -> (Vec<String>, Vec<String>) {
    let mut features = Vec::new();
    let mut sources = vec!["policy_events".to_string()];
    let Some(url) = graphql_url else {
        return (features, sources);
    };

    for attempt in 1..=attempts {
        let url = url.to_string();
        let probed = tokio::task::spawn_blocking(move || {
            use policy_engine_dev::{ClientConfig, PolicyClient};
            let client = PolicyClient::with_config(ClientConfig {
                server_url: url,
                ..Default::default()
            });
            client.server_features()
        })
        .await;

        match probed {
            Ok(Ok(f)) => {
                if f.suricata {
                    features.push("suricata".to_string());
                    sources.push("suricata_alerts".to_string());
                }
                return (features, sources);
            }
            Ok(Err(e)) if attempt < attempts => {
                log::info!(
                    "Capability probe attempt {attempt}/{attempts} failed, retrying in {}s: {e:#}",
                    retry_delay.as_secs_f32()
                );
                tokio::time::sleep(retry_delay).await;
            }
            Ok(Err(e)) => log::warn!(
                "Capability probe failed after {attempts} attempts; advertising baseline capabilities: {e:#}"
            ),
            Err(e) => {
                log::warn!("Capability probe task panicked: {:#}", e);
                break;
            }
        }
    }
    (features, sources)
}

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
    let (
        ingress_rules,
        egress_rules,
        interfaces,
        fib_entries,
        urpf_entries,
        stop_behavior,
        inspect_status,
    ) = tokio::task::spawn_blocking(move || {
        let client = PolicyClient::with_config(ClientConfig {
            server_url: url,
            ..Default::default()
        });
        let ingress = client.list_rules(GqlDirection::Ingress)?;
        let egress = client.list_rules(GqlDirection::Egress)?;
        let ifaces = client.list_interfaces()?;
        let fib = client.list_fib_forwarding().unwrap_or_default();
        let urpf = client.list_urpf().unwrap_or_default();
        let sb = client.get_stop_behavior().unwrap_or_default();
        // None on engines built without the suricata feature (the query
        // errors there) — reported as mode 0 / empty lists.
        let inspect = client.inspect_status().ok();
        Ok::<_, anyhow::Error>((ingress, egress, ifaces, fib, urpf, sb, inspect))
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

    let urpf_interfaces = urpf_entries
        .into_iter()
        .filter_map(|(iface, mode)| {
            let m = match mode.to_uppercase().as_str() {
                "LOOSE" => 1u32,
                "STRICT" => 2u32,
                _ => 0u32,
            };
            if m != 0 {
                Some((iface, m))
            } else {
                None
            }
        })
        .collect();

    let (inspect_mode, suricata_rule_files, inspect_enabled_interfaces) = match inspect_status {
        Some(s) => (
            match s.mode {
                policy_engine_dev::GqlInspectMode::Ips => 1,
                policy_engine_dev::GqlInspectMode::Ids => 2,
                policy_engine_dev::GqlInspectMode::Disabled => 0,
            },
            s.custom_rule_files
                .into_iter()
                .map(
                    |f| policy_controller_proto::controller::SuricataRuleFileDigest {
                        filename: f.filename,
                        sha256: f.sha256,
                        rule_count: f.rule_count.max(0) as u32,
                    },
                )
                .collect(),
            s.enabled_interfaces,
        ),
        None => (0, Vec::new(), Vec::new()),
    };

    Ok(StateSnapshot {
        rules,
        attachments,
        default_actions: std::collections::HashMap::new(),
        fib_forwarding_interfaces,
        per_interface_default_actions: std::collections::HashMap::new(),
        stop_behavior,
        urpf_interfaces,
        inspect_mode,
        suricata_rule_files,
        inspect_enabled_interfaces,
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

    #[test]
    fn apply_clear_stats_rule_requires_numeric_id() {
        use policy_controller_proto::controller::{clear_stats::Scope, ClearStats};
        use policy_engine_dev::{ClientConfig, PolicyClient};
        let client = PolicyClient::with_config(ClientConfig {
            server_url: "http://127.0.0.1:0".to_string(),
            ..Default::default()
        });
        let req = ClearStats {
            scope: Scope::Rule as i32,
            interface_name: String::new(),
            rule_id: "not-a-number".to_string(),
            direction: "ingress".to_string(),
        };
        let err = apply_clear_stats(&client, Scope::Rule, &req).unwrap_err();
        assert!(err.to_string().contains("invalid rule_id"), "{err}");
    }

    /// In-memory stream handle driven by pre-loaded messages from the controller.
    struct MockStreamHandle {
        sent: Arc<Mutex<Vec<AgentMessage>>>,
        inbound: VecDeque<ControllerMessage>,
    }

    /// Write half of [`MockStreamHandle`]; records every sent message.
    struct MockStreamTx {
        sent: Arc<Mutex<Vec<AgentMessage>>>,
    }

    /// Read half of [`MockStreamHandle`]; replays pre-loaded inbound messages.
    struct MockStreamRx {
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
    impl AgentStreamTx for MockStreamTx {
        async fn send(&mut self, msg: AgentMessage) -> Result<()> {
            self.sent.lock().await.push(msg);
            Ok(())
        }
    }

    #[async_trait]
    impl AgentStreamRx for MockStreamRx {
        async fn recv(&mut self) -> Result<Option<ControllerMessage>> {
            Ok(self.inbound.pop_front())
        }
    }

    impl AgentStreamHandle for MockStreamHandle {
        type Tx = MockStreamTx;
        type Rx = MockStreamRx;
        fn split(self) -> (MockStreamTx, MockStreamRx) {
            (
                MockStreamTx { sent: self.sent },
                MockStreamRx {
                    inbound: self.inbound,
                },
            )
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
            Arc::new(AtomicU64::new(30)),
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
    async fn test_set_metrics_interval_updates_shared_atomic() {
        use policy_controller_proto::controller::SetMetricsInterval;

        let msg = ControllerMessage {
            payload: Some(CtrlPayload::SetMetricsInterval(SetMetricsInterval {
                interval_secs: 7,
            })),
        };
        let (stream, _sent) = MockStreamHandle::new(vec![msg]);
        let id = mock_identity();
        let interval = Arc::new(AtomicU64::new(30));
        let _ = run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            None,
            &[],
            Arc::clone(&interval),
            None,
        )
        .await;
        assert_eq!(interval.load(Ordering::Relaxed), 7);
    }

    #[tokio::test]
    async fn test_set_metrics_interval_clamps_below_minimum() {
        use policy_controller_proto::controller::SetMetricsInterval;

        let msg = ControllerMessage {
            payload: Some(CtrlPayload::SetMetricsInterval(SetMetricsInterval {
                interval_secs: 0,
            })),
        };
        let (stream, _sent) = MockStreamHandle::new(vec![msg]);
        let id = mock_identity();
        let interval = Arc::new(AtomicU64::new(30));
        let _ = run_stream_loop(
            stream,
            &id,
            "0.1.0",
            None,
            None,
            None,
            None,
            &[],
            Arc::clone(&interval),
            None,
        )
        .await;
        assert_eq!(
            interval.load(Ordering::Relaxed),
            crate::metrics_forwarder::MIN_METRICS_INTERVAL_SECS
        );
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
            Arc::new(AtomicU64::new(30)),
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
            Arc::new(AtomicU64::new(30)),
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

    /// Stream handle whose write half stalls forever after the first send,
    /// modelling a back-pressured (full HTTP/2 window) connection.
    struct StallTxStreamHandle {
        inbound: VecDeque<ControllerMessage>,
    }
    struct StallTx {
        remaining_ok: usize,
    }
    struct StallRx {
        inbound: VecDeque<ControllerMessage>,
    }

    #[async_trait]
    impl AgentStreamTx for StallTx {
        async fn send(&mut self, _msg: AgentMessage) -> Result<()> {
            if self.remaining_ok > 0 {
                self.remaining_ok -= 1;
                return Ok(());
            }
            // Never completes — the connection's send window is wedged.
            std::future::pending::<()>().await;
            unreachable!()
        }
    }

    #[async_trait]
    impl AgentStreamRx for StallRx {
        async fn recv(&mut self) -> Result<Option<ControllerMessage>> {
            Ok(self.inbound.pop_front())
        }
    }

    impl AgentStreamHandle for StallTxStreamHandle {
        type Tx = StallTx;
        type Rx = StallRx;
        fn split(self) -> (StallTx, StallRx) {
            // Let only AgentHello through; every subsequent send blocks forever.
            (
                StallTx { remaining_ok: 1 },
                StallRx {
                    inbound: self.inbound,
                },
            )
        }
    }

    /// Regression guard for the bidirectional-stream deadlock: a wedged write
    /// half must not park the reader. The first inbound message (`StateQuery`)
    /// queues an outbound send the writer stalls on; if the reader were coupled
    /// to the writer it would never reach the second message and the metrics
    /// interval would stay at its initial value.
    #[tokio::test]
    async fn stalled_writer_does_not_block_reader() {
        use policy_controller_proto::controller::{SetMetricsInterval, StateQuery};
        let inbound = vec![
            ControllerMessage {
                payload: Some(CtrlPayload::StateQuery(StateQuery {})),
            },
            ControllerMessage {
                payload: Some(CtrlPayload::SetMetricsInterval(SetMetricsInterval {
                    interval_secs: 7,
                })),
            },
        ];
        let stream = StallTxStreamHandle {
            inbound: inbound.into(),
        };
        let id = mock_identity();
        let interval = Arc::new(AtomicU64::new(30));
        // The reader runs to completion in microseconds; teardown then waits on
        // the stalled writer (WRITER_FLUSH_TIMEOUT), so cap the whole call well
        // under that — we only care that the reader made progress.
        let _ = tokio::time::timeout(
            Duration::from_millis(500),
            run_stream_loop(
                stream,
                &id,
                "0.1.0",
                None,
                None,
                None,
                None,
                &[],
                Arc::clone(&interval),
                None,
            ),
        )
        .await;

        assert_eq!(
            interval.load(Ordering::Relaxed),
            7,
            "reader must process inbound past a message whose response the writer stalled on"
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
            Arc::new(AtomicU64::new(30)),
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
            Arc::new(AtomicU64::new(30)),
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
            Arc::new(AtomicU64::new(30)),
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

    #[tokio::test]
    async fn test_change_detector_tick_blocks_while_apply_lock_held() {
        // The poll must not even read the engine while a controller apply holds
        // the lock: that read-during-apply window is what made the controller's
        // own push echo back as a spurious local change. Holding the lock here
        // simulates an in-flight apply; the tick must stay pending until release.
        let apply_lock: ApplyLock = Arc::new(tokio::sync::Mutex::new(()));
        let guard = apply_lock.lock().await;

        // No expectations: the detector must not be touched while the tick is
        // blocked, and once unblocked the empty-URL fetch errors out before any
        // diff happens — so update_baseline/diff are never called either way.
        let detector = MockChangeDetector::new();
        let (tx, _rx) = mpsc::channel::<AgentMessage>(8);
        let lock = Arc::clone(&apply_lock);
        let handle = tokio::spawn(async move {
            // Empty URL → the fallible fetch errors immediately (no network).
            change_detector_tick(&detector, "", &tx, &lock).await
        });

        // While the lock is held the tick cannot complete.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "change_detector_tick must block while the apply lock is held"
        );

        // Releasing the lock lets the tick proceed (and fail on the bogus fetch).
        drop(guard);
        let result = handle.await.expect("tick task panicked");
        assert!(
            result.is_err(),
            "tick should surface the fetch error once unblocked"
        );
    }

    /// Serve exactly one canned GraphQL HTTP response on an ephemeral port.
    /// Reads until the request headers are complete, then replies and closes.
    fn one_shot_graphql_server(body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}/graphql")
    }

    #[tokio::test]
    async fn probe_capabilities_no_engine_url_advertises_baseline() {
        let (features, sources) = probe_capabilities(None).await;
        assert!(features.is_empty());
        assert_eq!(sources, vec!["policy_events".to_string()]);
    }

    #[tokio::test]
    async fn probe_capabilities_unreachable_engine_advertises_baseline() {
        // Nothing listens on port 1; the probe must exhaust its retries and
        // degrade to baseline capabilities rather than fail connection setup.
        let (features, sources) = probe_capabilities_with_retry(
            Some("http://127.0.0.1:1/graphql"),
            2,
            std::time::Duration::from_millis(10),
        )
        .await;
        assert!(features.is_empty());
        assert_eq!(sources, vec!["policy_events".to_string()]);
    }

    /// Refuse the first connection (accept + immediate close, no response),
    /// then serve one canned GraphQL response — the engine winning its
    /// GraphQL bind race between two probe attempts.
    fn flaky_then_graphql_server(body: &'static str) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
            }
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}/graphql")
    }

    #[tokio::test]
    async fn probe_capabilities_retries_until_engine_is_reachable() {
        let url = flaky_then_graphql_server(r#"{"data":{"serverFeatures":{"suricata":true}}}"#);
        let (features, sources) =
            probe_capabilities_with_retry(Some(&url), 3, std::time::Duration::from_millis(10))
                .await;
        assert_eq!(features, vec!["suricata".to_string()]);
        assert_eq!(
            sources,
            vec!["policy_events".to_string(), "suricata_alerts".to_string()]
        );
    }

    #[tokio::test]
    async fn probe_capabilities_suricata_engine_advertises_feature_and_source() {
        let url = one_shot_graphql_server(r#"{"data":{"serverFeatures":{"suricata":true}}}"#);
        let (features, sources) = probe_capabilities(Some(&url)).await;
        assert_eq!(features, vec!["suricata".to_string()]);
        assert_eq!(
            sources,
            vec!["policy_events".to_string(), "suricata_alerts".to_string()]
        );
    }

    #[tokio::test]
    async fn probe_capabilities_plain_engine_advertises_baseline() {
        let url = one_shot_graphql_server(r#"{"data":{"serverFeatures":{"suricata":false}}}"#);
        let (features, sources) = probe_capabilities(Some(&url)).await;
        assert!(features.is_empty());
        assert_eq!(sources, vec!["policy_events".to_string()]);
    }
}
