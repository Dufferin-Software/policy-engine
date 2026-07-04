// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! `/ws/alerts` — WebSocket stream of Suricata EVE alerts.
//!
//! Mirrors the `/ws/events` handler in `event_stream.rs`: one broadcast
//! subscription per client, drop-and-warn on lag, heartbeat pings, and a
//! Close frame on the server shutdown signal so graceful shutdown is not
//! held up by connected clients.
//!
//! The stream is fed by the [`EveConsumer`](super::eve_consumer::EveConsumer)
//! broadcast channel, which exists (in `AppState`) from process start.  While
//! inspection is disabled the stream simply idles — clients can stay
//! connected across enable/disable cycles.

use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use log::{info, warn};
use tokio::sync::{broadcast, watch};
use tokio::time::interval;

use super::graphql::AppState;

pub async fn ws_alerts(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<Arc<AppState>>,
    shutdown: web::Data<Arc<watch::Sender<bool>>>,
) -> actix_web::Result<HttpResponse> {
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, body)?;

    let mut rx = state.eve_consumer.lock().await.subscribe();
    // Each connection gets its own watch receiver so they track "seen" state
    // independently.  subscribe() always reflects the current sender value.
    let mut shutdown_rx = shutdown.subscribe();
    info!("WebSocket client connected to /ws/alerts");

    actix_rt::spawn(async move {
        use futures_util::StreamExt as _;
        // See ws_events: keep sending after the read stream ends; only a
        // Close frame or a write error terminates the connection.
        let mut stream_open = true;
        let mut heartbeat = interval(Duration::from_secs(15));
        heartbeat.tick().await; // consume the immediate first tick
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
                        Some(_) => {} // text/binary/continuation/pong — ignore
                    }
                }
                _ = heartbeat.tick() => {
                    if session.ping(b"").await.is_err() {
                        break;
                    }
                }
                result = rx.recv() => {
                    match result {
                        Ok(alert) => match serde_json::to_string(&alert) {
                            Ok(text) => {
                                if session.text(text).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => warn!("Failed to serialize alert: {}", e),
                        },
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("/ws/alerts client lagged, skipped {} alerts", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let _ = session.close(None).await;
                            break;
                        }
                    }
                }
                // Server shutdown: send Close so clients see a clean goodbye
                // and actix's shutdown_timeout is not held up.
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
