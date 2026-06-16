// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, Notify};

use policy_controller_proto::controller::{
    agent_message::Payload as AgentPayload, AgentMessage, MetricsUpdate,
};

/// Default metrics scrape interval when none is configured.
/// Keep in sync with `config::default_metrics_interval_secs`.
pub const METRICS_INTERVAL: Duration = Duration::from_secs(5);

/// Floor for the scrape interval, so an operator (or a bad push) can't pin an
/// agent into a tight scrape loop that hammers the local engine and controller.
pub const MIN_METRICS_INTERVAL_SECS: u64 = 1;

/// Scrapes `/metrics` from the local policy-engine on a configurable interval and
/// forwards the raw Prometheus exposition text to the controller via the agent
/// gRPC stream.
///
/// The `trigger` notify can be signalled to request an immediate push ahead of
/// the normal interval (used by the `refreshNodeMetrics` GraphQL mutation).
///
/// `interval_secs` is read fresh each iteration so a controller-driven
/// `SetMetricsInterval` takes effect without restarting the forwarder (a change
/// applies after at most one current-interval sleep).
///
/// Runs until `tx` is closed (stream disconnected).
pub async fn run(
    base_url: String,
    interval_secs: Arc<AtomicU64>,
    trigger: Arc<Notify>,
    tx: mpsc::Sender<AgentMessage>,
) {
    let url = format!("{}/metrics", base_url.trim_end_matches('/'));
    let client = match reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            log::error!("MetricsForwarder: failed to build HTTP client: {}", e);
            return;
        }
    };

    loop {
        let secs = interval_secs
            .load(Ordering::Relaxed)
            .max(MIN_METRICS_INTERVAL_SECS);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
            _ = trigger.notified() => {
                log::debug!("MetricsForwarder: early wake-up via MetricsQuery");
            }
        }

        if tx.is_closed() {
            break;
        }

        match fetch_metrics(&client, &url).await {
            Ok(mut body) => {
                // Append the agent's own process-local metrics (renewal
                // counter/gauge, etc.) to the engine-scraped body. Both
                // sources are Prometheus exposition text so concatenation
                // is valid as long as metric names don't collide — and we
                // namespace agent metrics with `fleet_node_` to keep them
                // disjoint from engine metrics.
                let agent_metrics = crate::metrics::render();
                if !agent_metrics.is_empty() {
                    if !body.ends_with(b"\n") {
                        body.push(b'\n');
                    }
                    body.extend_from_slice(&agent_metrics);
                }
                let len = body.len();
                let msg = AgentMessage {
                    payload: Some(AgentPayload::Metrics(MetricsUpdate {
                        timestamp_ns: current_ns(),
                        prometheus_text: body,
                    })),
                };
                if tx.send(msg).await.is_err() {
                    break; // stream closed
                }
                log::debug!("MetricsForwarder: sent MetricsUpdate ({} bytes)", len);
            }
            Err(e) => {
                log::warn!("MetricsForwarder: failed to fetch metrics: {:#}", e);
            }
        }
    }
}

async fn fetch_metrics(client: &reqwest::Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let resp = client.get(url).send().await?;
    Ok(resp.bytes().await?.to_vec())
}

pub fn current_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Derive the base URL (no path) from a GraphQL URL.
/// `"http://127.0.0.1:8080/graphql"` → `"http://127.0.0.1:8080"`
pub fn base_url_from_graphql(graphql_url: &str) -> String {
    let trimmed = graphql_url.trim_end_matches('/');
    trimmed
        .strip_suffix("/graphql")
        .unwrap_or(trimmed)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_url_strips_graphql() {
        assert_eq!(
            base_url_from_graphql("http://127.0.0.1:8080/graphql"),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn test_base_url_no_path() {
        assert_eq!(
            base_url_from_graphql("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn test_base_url_trailing_slash() {
        assert_eq!(
            base_url_from_graphql("http://127.0.0.1:8080/graphql/"),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn test_current_ns_nonzero() {
        assert!(current_ns() > 0);
    }
}
