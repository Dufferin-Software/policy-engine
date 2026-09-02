// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use futures_util::StreamExt;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use policy_controller_proto::controller::{
    agent_message::Payload as AgentPayload, AgentMessage, RuleLifecycleBatch,
};

/// Delay before reconnecting after a WebSocket error.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Connects to the local policy-engine `/ws/rule-events` WebSocket and forwards
/// rule lifecycle events to the controller via the agent gRPC stream.
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
            Ok(()) => log::debug!("RuleLifecycleForwarder: WebSocket closed cleanly, reconnecting"),
            Err(e) => log::warn!(
                "RuleLifecycleForwarder: WebSocket error: {:#}, reconnecting",
                e
            ),
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

    while let Some(msg) = read.next().await {
        match msg {
            Err(e) => return Err(e.into()),
            Ok(Message::Text(text)) => {
                forward_event(text.as_bytes().to_vec(), node_id, tx).await?;
            }
            Ok(Message::Binary(bytes)) => {
                forward_event(bytes.to_vec(), node_id, tx).await?;
            }
            Ok(_) => {} // Ping / Pong / Close frames — ignore
        }
    }
    Ok(())
}

async fn forward_event(
    event_json: Vec<u8>,
    node_id: &str,
    tx: &mpsc::Sender<AgentMessage>,
) -> anyhow::Result<()> {
    let msg = AgentMessage {
        payload: Some(AgentPayload::RuleLifecycleEvents(RuleLifecycleBatch {
            node_id: node_id.to_string(),
            events_json: vec![event_json],
        })),
    };
    tx.send(msg)
        .await
        .map_err(|_| anyhow::anyhow!("RuleLifecycleForwarder: stream channel closed"))?;
    Ok(())
}

/// Convert an HTTP base URL to a WebSocket URL for the rule-events endpoint.
pub fn make_ws_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{}/ws/rule-events", rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{}/ws/rule-events", rest)
    } else {
        format!("ws://{}/ws/rule-events", base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_ws_url_http() {
        assert_eq!(
            make_ws_url("http://localhost:8080"),
            "ws://localhost:8080/ws/rule-events"
        );
    }

    #[test]
    fn test_make_ws_url_https() {
        assert_eq!(
            make_ws_url("https://localhost:8080"),
            "wss://localhost:8080/ws/rule-events"
        );
    }

    #[test]
    fn test_make_ws_url_trailing_slash() {
        assert_eq!(
            make_ws_url("http://localhost:8080/"),
            "ws://localhost:8080/ws/rule-events"
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
