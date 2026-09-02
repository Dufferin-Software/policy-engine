// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use futures_util::StreamExt;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use policy_controller_proto::controller::{
    agent_message::Payload as AgentPayload, AgentMessage, EventBatch,
};

/// Flush a batch after at most this long, even if not full.
const BATCH_TIMEOUT: Duration = Duration::from_millis(200);
/// Maximum events per batch (avoids oversized gRPC messages).
const BATCH_MAX: usize = 100;
/// Delay before reconnecting after a WebSocket error.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Connects to the local policy-engine `/ws/events` WebSocket, batches BPF
/// events, and forwards them to the controller via the agent gRPC stream.
///
/// Reconnects automatically on disconnect or error.
/// Exits when `tx` is closed.
pub async fn run(base_url: String, node_id: String, tx: mpsc::Sender<AgentMessage>) {
    let ws_url = make_ws_url(&base_url);
    loop {
        if tx.is_closed() {
            break;
        }
        match run_once(&ws_url, &node_id, &tx).await {
            Ok(()) => log::debug!("EventForwarder: WebSocket closed cleanly, reconnecting"),
            Err(e) => log::warn!("EventForwarder: WebSocket error: {:#}, reconnecting", e),
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
    let events = std::mem::take(batch);
    let count = events.len();
    let msg = AgentMessage {
        payload: Some(AgentPayload::Events(EventBatch {
            timestamp_ns: current_ns(),
            node_id: node_id.to_string(),
            events_json: events,
        })),
    };
    tx.send(msg)
        .await
        .map_err(|_| anyhow::anyhow!("EventForwarder: stream channel closed"))?;
    log::debug!("EventForwarder: flushed {} events", count);
    Ok(())
}

fn current_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Convert an HTTP base URL to a WebSocket URL for the events endpoint.
pub fn make_ws_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{}/ws/events", rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{}/ws/events", rest)
    } else {
        format!("ws://{}/ws/events", base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_ws_url_http() {
        assert_eq!(
            make_ws_url("http://localhost:8080"),
            "ws://localhost:8080/ws/events"
        );
    }

    #[test]
    fn test_make_ws_url_https() {
        assert_eq!(
            make_ws_url("https://localhost:8080"),
            "wss://localhost:8080/ws/events"
        );
    }

    #[test]
    fn test_make_ws_url_trailing_slash() {
        assert_eq!(
            make_ws_url("http://localhost:8080/"),
            "ws://localhost:8080/ws/events"
        );
    }

    #[tokio::test]
    async fn test_run_exits_when_tx_closed() {
        // Closing the channel before calling run() should exit immediately.
        let (tx, rx) = mpsc::channel::<AgentMessage>(8);
        drop(rx);
        // run() with an unreachable URL should exit quickly once it sees tx is closed.
        // We can't actually connect, so it will get an error and then see tx is closed.
        tokio::time::timeout(
            Duration::from_secs(1),
            run(
                "http://127.0.0.1:0".to_string(), // unreachable
                "node-1".to_string(),
                tx,
            ),
        )
        .await
        .unwrap(); // should complete within timeout
    }
}
