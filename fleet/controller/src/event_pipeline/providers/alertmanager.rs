// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Alertmanager v2 notifier.
//!
//! `receivers.config_json` schema:
//!
//! ```json
//! {
//!   "url": "http://alertmanager:9093",       // base URL; /api/v2/alerts is appended
//!   "extra_labels": { "env": "prod" }        // optional, merged into labels
//! }
//! ```
//!
//! POSTs a single-element array to `<url>/api/v2/alerts` in the Alertmanager
//! v2 JSON schema. `Resolve` notifications set `endsAt` to the fire time so
//! Alertmanager closes the alert immediately; otherwise `endsAt` is left
//! unset and Alertmanager applies its own resolve_timeout.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use super::super::alert_store::Receiver;
use super::{NotificationKindStr, NotificationPayload, Notifier};

const DEFAULT_TIMEOUT_S: u64 = 10;
const ALERTS_PATH: &str = "/api/v2/alerts";

#[derive(Debug, Deserialize)]
struct AlertmanagerConfig {
    url: String,
    #[serde(default)]
    extra_labels: HashMap<String, String>,
}

pub struct AlertmanagerNotifier {
    client: reqwest::Client,
}

impl Default for AlertmanagerNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertmanagerNotifier {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_S))
            .build()
            .expect("reqwest client builds with default opts");
        Self { client }
    }
}

#[async_trait]
impl Notifier for AlertmanagerNotifier {
    fn kind(&self) -> &'static str {
        "alertmanager"
    }

    async fn send(&self, receiver: &Receiver, payload: &NotificationPayload) -> Result<()> {
        let cfg: AlertmanagerConfig =
            serde_json::from_str(&receiver.config_json).with_context(|| {
                format!(
                    "receiver {} ({}): bad config_json",
                    receiver.id, receiver.name
                )
            })?;
        let target = format!("{}{}", cfg.url.trim_end_matches('/'), ALERTS_PATH);
        let body = build_body(payload, &cfg.extra_labels);
        let resp = self
            .client
            .post(&target)
            .json(&body)
            .send()
            .await
            .context("alertmanager POST failed")?;
        let status = resp.status();
        if !status.is_success() {
            let snippet: String = resp
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(256)
                .collect();
            return Err(anyhow!("alertmanager returned {status}: {snippet}"));
        }
        Ok(())
    }
}

fn build_body(
    payload: &NotificationPayload,
    extra_labels: &HashMap<String, String>,
) -> serde_json::Value {
    use serde_json::json;

    let mut labels = serde_json::Map::new();
    labels.insert("alertname".into(), json!(payload.rule_name));
    labels.insert("severity".into(), json!(payload.severity));
    labels.insert("rule_id".into(), json!(payload.rule_id.to_string()));
    labels.insert("group_key".into(), json!(payload.group_key));
    for (k, v) in extra_labels {
        labels.insert(k.clone(), json!(v));
    }

    let starts_at = payload.fired_at.to_rfc3339();
    let mut alert = serde_json::Map::new();
    alert.insert("labels".into(), serde_json::Value::Object(labels));
    alert.insert(
        "annotations".into(),
        json!({
            "summary": format!("{} (group={})", payload.rule_name, payload.group_key),
            "description": format!(
                "kind={:?} event_count={} sample_event_ids={:?}",
                payload.kind, payload.event_count, payload.sample_event_ids,
            ),
        }),
    );
    alert.insert("startsAt".into(), json!(starts_at));
    if matches!(payload.kind, NotificationKindStr::Resolve) {
        alert.insert("endsAt".into(), json!(starts_at));
    }

    json!([alert])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::grouper::NotificationKind;
    use chrono::TimeZone;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    fn payload(kind: NotificationKind) -> NotificationPayload {
        NotificationPayload {
            rule_id: 7,
            rule_name: "drops on n1".into(),
            severity: "critical".into(),
            group_key: "rule_id=7".into(),
            kind: kind.into(),
            fired_at: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            event_count: 5,
            sample_event_ids: vec![1, 2, 3],
        }
    }

    fn receiver(url: &str) -> Receiver {
        Receiver {
            id: 1,
            tenant_id: 1,
            name: "am".into(),
            kind: "alertmanager".into(),
            config_json: format!(r#"{{"url":"{}","extra_labels":{{"env":"test"}}}}"#, url),
        }
    }

    #[test]
    fn build_body_contains_required_fields_for_initial() {
        let body = build_body(&payload(NotificationKind::InitialFire), &HashMap::new());
        let alert = &body.as_array().unwrap()[0];
        let labels = &alert["labels"];
        assert_eq!(labels["alertname"], "drops on n1");
        assert_eq!(labels["severity"], "critical");
        assert_eq!(labels["rule_id"], "7");
        assert_eq!(labels["group_key"], "rule_id=7");
        assert!(alert["startsAt"].is_string());
        // Non-resolve: no endsAt — let Alertmanager apply its own timeout.
        assert!(alert.get("endsAt").is_none());
    }

    #[test]
    fn build_body_sets_ends_at_for_resolve() {
        let body = build_body(&payload(NotificationKind::Resolve), &HashMap::new());
        let alert = &body.as_array().unwrap()[0];
        assert_eq!(alert["endsAt"], alert["startsAt"]);
    }

    #[test]
    fn build_body_merges_extra_labels() {
        let mut extra = HashMap::new();
        extra.insert("env".into(), "prod".into());
        extra.insert("team".into(), "secops".into());
        let body = build_body(&payload(NotificationKind::InitialFire), &extra);
        let labels = &body.as_array().unwrap()[0]["labels"];
        assert_eq!(labels["env"], "prod");
        assert_eq!(labels["team"], "secops");
    }

    /// Spin a one-shot TCP listener that pretends to be Alertmanager, capture
    /// the request, and respond 200. Verifies the notifier hits the v2 path
    /// and sends a valid JSON body.
    #[tokio::test]
    async fn send_hits_alertmanager_v2_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            *captured_clone.lock().await = Some(String::from_utf8_lossy(&buf[..n]).into_owned());
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
            sock.write_all(resp).await.unwrap();
            sock.flush().await.unwrap();
        });

        let notifier = AlertmanagerNotifier::new();
        let rcv = receiver(&format!("http://127.0.0.1:{port}"));
        notifier
            .send(&rcv, &payload(NotificationKind::InitialFire))
            .await
            .unwrap();
        server.await.unwrap();

        let raw = captured.lock().await.clone().unwrap();
        assert!(
            raw.contains(&format!("POST {ALERTS_PATH}")),
            "did not POST {ALERTS_PATH}; raw=\n{raw}"
        );
        assert!(raw.contains("\"alertname\":\"drops on n1\""));
        assert!(raw.contains("\"env\":\"test\""));
    }

    #[tokio::test]
    async fn send_returns_err_on_non_2xx() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            let resp = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nfail";
            let _ = sock.write_all(resp).await;
        });

        let notifier = AlertmanagerNotifier::new();
        let rcv = receiver(&format!("http://127.0.0.1:{port}"));
        let err = notifier
            .send(&rcv, &payload(NotificationKind::InitialFire))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("503"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn send_rejects_bad_config_json() {
        let notifier = AlertmanagerNotifier::new();
        let mut rcv = receiver("http://unused");
        rcv.config_json = "not json".into();
        let err = notifier
            .send(&rcv, &payload(NotificationKind::InitialFire))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad config_json"));
    }
}
