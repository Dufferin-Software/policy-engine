// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Forwards Suricata EVE alerts from the local engine's `/ws/alerts`
//! WebSocket to the controller as `SuricataAlertBatch` messages.
//!
//! Near-verbatim sibling of `event_forwarder` (same batching, reconnect and
//! shutdown semantics); only the source endpoint and the proto envelope
//! differ. Spawned per connection — it must live in `run_stream_loop`'s
//! `_connection_tasks` so a reconnect never leaks an orphan forwarder — and
//! only when the local engine advertised the `suricata` capability.

use futures_util::StreamExt;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use policy_controller_proto::controller::{
    agent_message::Payload as AgentPayload, AgentMessage, SuricataAlertBatch,
};

/// Flush a batch after at most this long, even if not full.
const BATCH_TIMEOUT: Duration = Duration::from_millis(200);
/// Maximum alerts per batch (avoids oversized gRPC messages).
const BATCH_MAX: usize = 100;
/// Delay before reconnecting after a WebSocket error.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Connects to the local policy-engine `/ws/alerts` WebSocket, batches EVE
/// alerts, and forwards them to the controller via the agent gRPC stream.
///
/// Reconnects automatically on disconnect or error. Exits when `tx` closes.
pub async fn run(base_url: String, node_id: String, tx: mpsc::Sender<AgentMessage>) {
    let ws_url = make_ws_url(&base_url);
    loop {
        if tx.is_closed() {
            break;
        }
        match run_once(&ws_url, &node_id, &tx).await {
            Ok(()) => log::debug!("AlertForwarder: WebSocket closed cleanly, reconnecting"),
            Err(e) => log::warn!("AlertForwarder: WebSocket error: {:#}, reconnecting", e),
        }
        tokio::select! {
            _ = tokio::time::sleep(RECONNECT_DELAY) => {}
            _ = tx.closed() => break,
        }
    }
}

async fn run_once(
    ws_url: &str,
    node_id: &str,
    tx: &mpsc::Sender<AgentMessage>,
) -> anyhow::Result<()> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url).await?;
    let (_, mut read) = ws_stream.split();

    let mut batch: Vec<Vec<u8>> = Vec::new();
    let mut batch_timer = tokio::time::interval(BATCH_TIMEOUT);
    batch_timer.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    None => return Ok(()), // server closed the connection
                    Some(Err(e)) => return Err(e.into()),
                    Some(Ok(Message::Text(text))) => {
                        batch.push(text.as_bytes().to_vec());
                        if batch.len() >= BATCH_MAX {
                            flush_batch(&mut batch, node_id, tx).await?;
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        batch.push(bytes.to_vec());
                        if batch.len() >= BATCH_MAX {
                            flush_batch(&mut batch, node_id, tx).await?;
                        }
                    }
                    Some(Ok(_)) => {} // Ping / Pong / Close frames — ignore
                }
            }
            _ = batch_timer.tick() => {
                if !batch.is_empty() {
                    flush_batch(&mut batch, node_id, tx).await?;
                }
            }
        }
    }
}

async fn flush_batch(
    batch: &mut Vec<Vec<u8>>,
    node_id: &str,
    tx: &mpsc::Sender<AgentMessage>,
) -> anyhow::Result<()> {
    let alerts = std::mem::take(batch);
    let count = alerts.len();
    let msg = AgentMessage {
        payload: Some(AgentPayload::SuricataAlerts(SuricataAlertBatch {
            timestamp_ns: current_ns(),
            node_id: node_id.to_string(),
            alerts_json: alerts,
        })),
    };
    tx.send(msg)
        .await
        .map_err(|_| anyhow::anyhow!("AlertForwarder: stream channel closed"))?;
    log::debug!("AlertForwarder: flushed {} alerts", count);
    Ok(())
}

fn current_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Convert an HTTP base URL to a WebSocket URL for the alerts endpoint.
pub fn make_ws_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{}/ws/alerts", rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{}/ws/alerts", rest)
    } else {
        format!("ws://{}/ws/alerts", base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_ws_url() {
        assert_eq!(
            make_ws_url("http://localhost:8080"),
            "ws://localhost:8080/ws/alerts"
        );
        assert_eq!(
            make_ws_url("https://localhost:8080/"),
            "wss://localhost:8080/ws/alerts"
        );
    }

    #[tokio::test]
    async fn test_run_exits_when_tx_closed() {
        let (tx, rx) = mpsc::channel::<AgentMessage>(8);
        drop(rx);
        tokio::time::timeout(
            Duration::from_secs(1),
            run("http://127.0.0.1:0".to_string(), "node-1".to_string(), tx),
        )
        .await
        .unwrap();
    }
}
