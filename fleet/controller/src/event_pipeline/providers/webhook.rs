// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Generic webhook notifier.
//!
//! `receivers.config_json` schema:
//!
//! ```json
//! {
//!   "url": "https://hooks.example.com/abc",
//!   "method": "POST",            // optional, defaults to POST
//!   "headers": { "X-Token": "…" } // optional, sent as-is
//! }
//! ```
//!
//! Posts the [`NotificationPayload`] as the JSON body. 2xx ⇒ success, any
//! other status / network error ⇒ retryable failure.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

use super::super::alert_store::Receiver;
use super::{NotificationPayload, Notifier};

const DEFAULT_TIMEOUT_S: u64 = 10;

#[derive(Debug, Deserialize)]
struct WebhookConfig {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
}

fn default_method() -> String {
    "POST".into()
}

pub struct WebhookNotifier {
    client: reqwest::Client,
}

impl Default for WebhookNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookNotifier {
    pub fn new() -> Self {
        // Single shared client so connection pooling kicks in across
        // notifications. Timeout caps the worst-case dispatch latency —
        // the dispatcher's retry budget assumes calls return quickly.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_S))
            .build()
            .expect("reqwest client builds with default opts");
        Self { client }
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    fn kind(&self) -> &'static str {
        "webhook"
    }

    async fn send(&self, receiver: &Receiver, payload: &NotificationPayload) -> Result<()> {
        let cfg: WebhookConfig =
            serde_json::from_str(&receiver.config_json).with_context(|| {
                format!(
                    "receiver {} ({}): bad config_json",
                    receiver.id, receiver.name
                )
            })?;
        let method = cfg
            .method
            .parse::<reqwest::Method>()
            .map_err(|e| anyhow!("invalid HTTP method '{}': {e}", cfg.method))?;
        let mut req = self.client.request(method, &cfg.url).json(payload);
        for (k, v) in cfg.headers {
            req = req.header(k, v);
        }
        let resp = req.send().await.context("webhook POST failed")?;
        let status = resp.status();
        if !status.is_success() {
            // Read a small slice of the body for diagnostics; bounded so a
            // huge error page doesn't blow up the log.
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(256).collect();
            anyhow::bail!("webhook returned {status}: {snippet}");
        }
        Ok(())
    }
}
