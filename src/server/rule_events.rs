// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Rule lifecycle event streaming over WebSocket.
//!
//! Broadcasts [`RuleLifecycleEvent`] messages to connected WebSocket clients
//! via the `/ws/rule-events` endpoint whenever a managed rule is added,
//! deleted, activated, deactivated, or expires.

use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use log::{info, warn};
use serde::Serialize;
use tokio::sync::{broadcast, watch};
use tokio::time::interval;

// ── Event type ───────────────────────────────────────────────────────────────

/// A JSON-serialisable notification for a rule state change.
#[derive(Serialize, Clone, Debug)]
pub struct RuleLifecycleEvent {
    /// `"activated"` | `"deactivated"` | `"deleted"` | `"expired"`
    pub event_type: String,
    pub rule_id: u64,
    /// `"INGRESS"` | `"EGRESS"`
    pub direction: String,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Human-readable reason, e.g. `"ttl_expired"` or `"schedule_window_start"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RuleLifecycleEvent {
    pub fn new(
        event_type: impl Into<String>,
        rule_id: u64,
        direction: impl Into<String>,
        reason: Option<String>,
    ) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            event_type: event_type.into(),
            rule_id,
            direction: direction.into(),
            timestamp_ms,
            reason,
        }
    }
}

// ── Broadcaster ──────────────────────────────────────────────────────────────

/// Create the broadcast channel used for rule lifecycle events.
///
/// The returned sender is cloned into [`PolicyService`] and into the actix
/// `web::Data` that the WebSocket handler receives.
pub fn start_rule_event_broadcaster() -> broadcast::Sender<RuleLifecycleEvent> {
    let (tx, _) = broadcast::channel::<RuleLifecycleEvent>(256);
    tx
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

/// WebSocket handler for `/ws/rule-events`.
///
/// Mirrors the architecture of [`event_stream::ws_events`]:
/// - Subscribes to the [`RuleLifecycleEvent`] broadcast channel.
/// - Sends heartbeat pings every 15 seconds.
/// - Sends a Close frame on server shutdown.
pub async fn ws_rule_events(
    req: HttpRequest,
    body: web::Payload,
    tx: web::Data<broadcast::Sender<RuleLifecycleEvent>>,
    shutdown: web::Data<Arc<watch::Sender<bool>>>,
) -> actix_web::Result<HttpResponse> {
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, body)?;

    let mut rx = tx.subscribe();
    let mut shutdown_rx = shutdown.subscribe();

    info!(
        "WebSocket client connected to /ws/rule-events (subscribers={})",
        tx.receiver_count()
    );

    actix_rt::spawn(async move {
        use futures_util::StreamExt as _;
        let mut stream_open = true;
        let mut heartbeat = interval(Duration::from_secs(15));
        heartbeat.tick().await; // consume immediate first tick

        loop {
            tokio::select! {
                incoming = msg_stream.next(), if stream_open => {
                    match incoming {
                        Some(Ok(actix_ws::Message::Ping(bytes))) => {
                            if session.pong(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(actix_ws::Message::Close(_))) => {
                            let _ = session.close(None).await;
                            break;
                        }
                        None => {
                            stream_open = false;
                        }
                        Some(_) => {}
                    }
                }
                _ = heartbeat.tick() => {
                    if session.ping(b"").await.is_err() {
                        break;
                    }
                }
                result = rx.recv() => {
                    match result {
                        Ok(ev) => {
                            match serde_json::to_string(&ev) {
                                Ok(text) => {
                                    if session.text(text).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to serialize rule lifecycle event: {}", e);
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WebSocket rule-events client lagged, skipped {} events", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let _ = session.close(None).await;
                            break;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    let _ = session.close(Some(actix_ws::CloseReason {
                        code: actix_ws::CloseCode::Away,
                        description: Some("server shutting down".into()),
                    }))
                    .await;
                    break;
                }
            }
        }
    });

    Ok(response)
}
