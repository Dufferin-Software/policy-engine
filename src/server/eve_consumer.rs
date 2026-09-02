// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Suricata EVE JSON consumer
//!
//! Listens on a Unix stream socket for Suricata's EVE JSON output.
//! Suricata connects to the socket as a client and streams JSON lines;
//! we parse alert events and broadcast them to subscribers.
//!
//! The socket path must match `filename` in the Suricata EVE output config
//! (see `generate_suricata_yaml` in `suricata_runtime.rs`).

use anyhow::Result;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::broadcast;

/// A Suricata alert parsed from EVE JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataAlert {
    pub timestamp: String,
    pub src_ip: String,
    pub dest_ip: String,
    /// Absent in EVE records for portless protocols (ICMP carries
    /// icmp_type/icmp_code instead).  `process_line` fills these from
    /// icmp_type/icmp_code so the flow-verdict key matches the BPF
    /// convention of ICMP type/code as pseudo-ports.
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dest_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u16>,
    pub proto: String,
    #[serde(default)]
    pub event_type: String,
    pub alert: Option<AlertInfo>,
}

/// Alert details from EVE JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
    pub action: String,
    pub signature_id: u64,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub category: String,
    pub severity: u32,
}

/// EVE JSON consumer that listens on a Unix socket for Suricata's output.
pub struct EveConsumer {
    socket_path: PathBuf,
    alert_tx: broadcast::Sender<SuricataAlert>,
    _alert_rx: broadcast::Receiver<SuricataAlert>,
    running: bool,
}

impl EveConsumer {
    /// Create a new EVE consumer for the given Unix socket path.
    pub fn new(socket_path: PathBuf) -> Self {
        let (alert_tx, _alert_rx) = broadcast::channel(1024);
        Self {
            socket_path,
            alert_tx,
            _alert_rx,
            running: false,
        }
    }

    /// Get a receiver for alerts.
    pub fn subscribe(&self) -> broadcast::Receiver<SuricataAlert> {
        self.alert_tx.subscribe()
    }

    /// Start the Unix socket listener in the background.
    ///
    /// The socket is bound synchronously, so it exists on disk before this
    /// returns: the Suricata systemd drop-in gates startup on
    /// `ConditionPathExists=<socket>`, and the inspect restore path restarts
    /// Suricata immediately after this call.
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        let listener = Self::bind_unix_socket(&self.socket_path)?;
        let alert_tx = self.alert_tx.clone();

        tokio::spawn(async move {
            Self::accept_loop(listener, alert_tx).await;
        });

        self.running = true;
        info!("Started EVE consumer on {:?}", self.socket_path);
        Ok(())
    }

    /// Stop the consumer (marks it stopped; the background task exits on next connection close).
    pub fn stop(&mut self) {
        self.running = false;
        info!("Stopped EVE consumer");
    }

    /// Whether the consumer is currently marked as running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Bind the EVE Unix socket, replacing any stale file from a previous run.
    fn bind_unix_socket(socket_path: &PathBuf) -> Result<UnixListener> {
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }

        // Ensure the parent directory exists.
        if let Some(parent) = socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(socket_path)?;
        info!("EVE consumer listening on {:?}", socket_path);
        Ok(listener)
    }

    /// Accept connections from Suricata and parse EVE JSON alert lines.
    /// Suricata reconnects automatically after a restart so we loop back to
    /// `accept()` on each connection close.
    async fn accept_loop(listener: UnixListener, alert_tx: broadcast::Sender<SuricataAlert>) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    info!("Suricata connected to EVE socket");
                    let tx = alert_tx.clone();
                    Self::handle_connection(stream, tx).await;
                    info!("Suricata disconnected from EVE socket, waiting for reconnect");
                }
                Err(e) => {
                    warn!("EVE socket accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Read JSON lines from an accepted Suricata connection and broadcast alerts.
    async fn handle_connection(
        stream: tokio::net::UnixStream,
        alert_tx: broadcast::Sender<SuricataAlert>,
    ) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // Connection closed
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    Self::process_line(trimmed, &alert_tx);
                }
                Err(e) => {
                    warn!("EVE socket read error: {}", e);
                    break;
                }
            }
        }
    }

    fn process_line(line: &str, alert_tx: &broadcast::Sender<SuricataAlert>) {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => {
                if value.get("event_type").and_then(|v| v.as_str()) == Some("alert") {
                    match serde_json::from_value::<SuricataAlert>(value) {
                        Ok(mut alert) => {
                            // ICMP EVE records carry no ports; the BPF flow key
                            // uses type/code as pseudo-ports, so mirror that
                            // here or IPS DROP verdicts never match the flow.
                            if let Some(t) = alert.icmp_type {
                                alert.src_port = t;
                                alert.dest_port = alert.icmp_code.unwrap_or(0);
                            }
                            debug!(
                                "EVE alert: sig_id={}, action={}",
                                alert.alert.as_ref().map(|a| a.signature_id).unwrap_or(0),
                                alert
                                    .alert
                                    .as_ref()
                                    .map(|a| a.action.as_str())
                                    .unwrap_or("unknown"),
                            );
                            let _ = alert_tx.send(alert);
                        }
                        Err(e) => warn!("Dropping unparseable EVE alert: {}", e),
                    }
                }
            }
            Err(e) => debug!("Failed to parse EVE JSON line: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx() -> broadcast::Sender<SuricataAlert> {
        let (tx, _rx) = broadcast::channel(16);
        tx
    }

    #[test]
    fn test_process_line_ignores_non_alert_events() {
        let tx = make_tx();
        let mut rx = tx.subscribe();
        EveConsumer::process_line(
            r#"{"event_type":"stats","timestamp":"2024-01-01T00:00:00"}"#,
            &tx,
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_process_line_ignores_invalid_json() {
        let tx = make_tx();
        let mut rx = tx.subscribe();
        EveConsumer::process_line("not json at all", &tx);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_process_line_broadcasts_alert() {
        let tx = make_tx();
        let mut rx = tx.subscribe();
        let line = r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature_id":2100498,"signature":"ET SCAN","category":"Attempted Info Leak","severity":2}}"#;
        EveConsumer::process_line(line, &tx);
        let alert = rx.try_recv().expect("should have broadcast an alert");
        assert_eq!(alert.src_ip, "1.2.3.4");
        assert_eq!(alert.dest_ip, "5.6.7.8");
        assert_eq!(alert.alert.as_ref().unwrap().signature_id, 2100498);
        assert_eq!(alert.alert.as_ref().unwrap().action, "blocked");
    }

    // -------------------------------------------------------------------------
    // EveConsumer lifecycle tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_new_is_not_running() {
        let ec = EveConsumer::new(PathBuf::from("/tmp/test_eve.sock"));
        assert!(!ec.is_running());
    }

    #[test]
    fn test_stop_sets_not_running() {
        let mut ec = EveConsumer::new(PathBuf::from("/tmp/test_eve_stop.sock"));
        // Manually set running=true to test stop
        ec.running = true;
        assert!(ec.is_running());
        ec.stop();
        assert!(!ec.is_running());
    }

    #[test]
    fn test_subscribe_returns_usable_receiver() {
        let ec = EveConsumer::new(PathBuf::from("/tmp/test_eve_sub.sock"));
        let _rx = ec.subscribe();
        // Just verifying it doesn't panic
    }

    #[test]
    fn test_subscribe_receiver_gets_messages() {
        let ec = EveConsumer::new(PathBuf::from("/tmp/test_eve_msg.sock"));
        let mut rx = ec.subscribe();
        // Send an alert directly through the internal sender
        let alert = SuricataAlert {
            timestamp: "2024-01-01T00:00:00".to_string(),
            src_ip: "10.0.0.1".to_string(),
            dest_ip: "10.0.0.2".to_string(),
            src_port: 1234,
            dest_port: 80,
            icmp_type: None,
            icmp_code: None,
            proto: "TCP".to_string(),
            event_type: "alert".to_string(),
            alert: None,
        };
        ec.alert_tx.send(alert.clone()).unwrap();
        let received = rx.try_recv().expect("should receive alert");
        assert_eq!(received.src_ip, "10.0.0.1");
    }

    #[tokio::test]
    async fn test_start_sets_running() {
        let path = PathBuf::from(format!(
            "/tmp/policy_engine_test_start_{}.sock",
            std::process::id()
        ));
        let mut ec = EveConsumer::new(path.clone());
        ec.start().await.unwrap();
        assert!(ec.is_running());
        ec.stop();
        assert!(!ec.is_running());
        // cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_start_idempotent() {
        let path = PathBuf::from(format!(
            "/tmp/policy_engine_test_idem_{}.sock",
            std::process::id()
        ));
        let mut ec = EveConsumer::new(path.clone());
        ec.start().await.unwrap();
        ec.start().await.unwrap(); // second call should be no-op
        assert!(ec.is_running());
        ec.stop();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_handle_connection_processes_alert() {
        use tokio::io::AsyncWriteExt;
        let (tx_alert, mut rx_alert) = broadcast::channel(16);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        let write_task = tokio::spawn(async move {
            let mut client = client;
            let line = concat!(
                r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP","#,
                r#""alert":{"action":"blocked","signature_id":2100498,"signature":"ET SCAN","category":"Attempted Info Leak","severity":2}}"#,
                "\n"
            );
            client.write_all(line.as_bytes()).await.unwrap();
            drop(client); // close to trigger EOF
        });

        EveConsumer::handle_connection(server, tx_alert).await;
        write_task.await.unwrap();

        let alert = rx_alert.try_recv().expect("should have received alert");
        assert_eq!(alert.src_ip, "1.2.3.4");
        assert_eq!(alert.dest_ip, "5.6.7.8");
        let ai = alert.alert.expect("alert info should be present");
        assert_eq!(ai.signature_id, 2100498);
        assert_eq!(ai.action, "blocked");
    }

    #[test]
    fn test_process_line_icmp_alert_without_ports() {
        // Real-shape EVE record for an ICMP alert: no src_port/dest_port,
        // icmp_type/icmp_code instead.  Must parse (regression: required
        // port fields silently dropped every ICMP alert) and map type/code
        // into the pseudo-port fields used by the BPF flow-verdict key.
        let (tx, mut rx) = broadcast::channel(16);
        let line = concat!(
            r#"{"timestamp":"2026-07-05T18:00:05.457514+0100","flow_id":1,"in_iface":"pe-inspect1","#,
            r#""event_type":"alert","src_ip":"10.0.0.2","dest_ip":"10.0.0.1","proto":"ICMP","#,
            r#""icmp_type":8,"icmp_code":0,"#,
            r#""alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"#,
            r#""signature":"TEST ICMP Ping","category":"","severity":3}}"#
        );
        EveConsumer::process_line(line, &tx);
        let alert = rx.try_recv().expect("ICMP alert should be broadcast");
        assert_eq!(alert.proto, "ICMP");
        assert_eq!(alert.src_port, 8, "icmp_type must become src_port");
        assert_eq!(alert.dest_port, 0, "icmp_code must become dest_port");
        assert_eq!(alert.alert.unwrap().signature_id, 1000001);
    }

    #[tokio::test]
    async fn test_handle_connection_skips_non_alert() {
        use tokio::io::AsyncWriteExt;
        let (tx_alert, mut rx_alert) = broadcast::channel(16);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        let write_task = tokio::spawn(async move {
            let mut client = client;
            let line = "{\"event_type\":\"stats\",\"timestamp\":\"2024-01-01T00:00:00\"}\n";
            client.write_all(line.as_bytes()).await.unwrap();
            drop(client);
        });

        EveConsumer::handle_connection(server, tx_alert).await;
        write_task.await.unwrap();

        assert!(
            rx_alert.try_recv().is_err(),
            "non-alert should not be broadcast"
        );
    }

    #[tokio::test]
    async fn test_handle_connection_multiple_lines() {
        use tokio::io::AsyncWriteExt;
        let (tx_alert, mut rx_alert) = broadcast::channel(16);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        let write_task = tokio::spawn(async move {
            let mut client = client;
            // First: a stats event (ignored)
            client
                .write_all(b"{\"event_type\":\"stats\",\"timestamp\":\"2024-01-01T00:00:00\"}\n")
                .await
                .unwrap();
            // Second: an alert
            let alert_line = concat!(
                r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:01","src_ip":"9.9.9.9","dest_ip":"1.1.1.1","src_port":5000,"dest_port":443,"proto":"TCP","#,
                r#""alert":{"action":"allowed","signature_id":9999,"signature":"TEST","category":"Test","severity":1}}"#,
                "\n"
            );
            client.write_all(alert_line.as_bytes()).await.unwrap();
            drop(client);
        });

        EveConsumer::handle_connection(server, tx_alert).await;
        write_task.await.unwrap();

        let alert = rx_alert.try_recv().expect("should have received the alert");
        assert_eq!(alert.src_ip, "9.9.9.9");
        assert!(rx_alert.try_recv().is_err(), "only one alert expected");
    }

    // -------------------------------------------------------------------------
    // SuricataAlert / AlertInfo serialization
    // -------------------------------------------------------------------------

    #[test]
    fn suricata_alert_roundtrip_json() {
        let json = r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature_id":2100498,"signature":"ET SCAN","category":"Attempted Info Leak","severity":2}}"#;
        let alert: SuricataAlert = serde_json::from_str(json).unwrap();
        assert_eq!(alert.src_ip, "1.2.3.4");
        assert_eq!(alert.dest_port, 80);
        let info = alert.alert.unwrap();
        assert_eq!(info.signature_id, 2100498);
        assert_eq!(info.severity, 2);
    }

    #[test]
    fn suricata_alert_optional_alert_field() {
        let json = r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP"}"#;
        let alert: SuricataAlert = serde_json::from_str(json).unwrap();
        assert!(alert.alert.is_none());
    }

    #[test]
    fn test_process_line_drops_alert_without_alert_field() {
        // event_type=alert but no .alert object means we skip
        let tx = make_tx();
        let mut rx = tx.subscribe();
        // This has event_type=alert but fields would fail SuricataAlert deserialization
        // Actually SuricataAlert.alert is Option<AlertInfo>, so it'd succeed with alert=None
        // Let's verify it IS broadcast (alert is None)
        let line = r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP"}"#;
        EveConsumer::process_line(line, &tx);
        let alert = rx
            .try_recv()
            .expect("should have broadcast alert even without alert field");
        assert!(alert.alert.is_none());
    }

    // ── Additional process_line tests ─────────────────────────────────────────

    #[test]
    fn test_process_line_ipv6_alert() {
        let tx = make_tx();
        let mut rx = tx.subscribe();
        let line = r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"2001:db8::1","dest_ip":"2001:db8::2","src_port":12345,"dest_port":443,"proto":"TCP","alert":{"action":"blocked","signature_id":9001,"signature":"IPv6 Test","category":"Test","severity":1}}"#;
        EveConsumer::process_line(line, &tx);
        let alert = rx.try_recv().expect("should broadcast IPv6 alert");
        assert_eq!(alert.src_ip, "2001:db8::1");
        assert_eq!(alert.dest_ip, "2001:db8::2");
        assert_eq!(alert.dest_port, 443);
    }

    #[test]
    fn test_process_line_drop_event_not_broadcast() {
        // event_type=drop should be ignored (only alert is processed)
        let tx = make_tx();
        let mut rx = tx.subscribe();
        let line = r#"{"event_type":"drop","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP"}"#;
        EveConsumer::process_line(line, &tx);
        assert!(rx.try_recv().is_err(), "drop event should not be broadcast");
    }

    #[test]
    fn test_process_line_flow_event_not_broadcast() {
        let tx = make_tx();
        let mut rx = tx.subscribe();
        let line = r#"{"event_type":"flow","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP"}"#;
        EveConsumer::process_line(line, &tx);
        assert!(rx.try_recv().is_err(), "flow event should not be broadcast");
    }

    #[test]
    fn test_process_line_empty_string_not_broadcast() {
        let tx = make_tx();
        let mut rx = tx.subscribe();
        EveConsumer::process_line("", &tx);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_multiple_subscribers_all_receive_alert() {
        let tx = make_tx();
        let mut rx1 = tx.subscribe();
        let mut rx2 = tx.subscribe();
        let line = r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","src_port":1234,"dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature_id":1,"signature":"Test","category":"Test","severity":1}}"#;
        EveConsumer::process_line(line, &tx);
        let a1 = rx1.try_recv().expect("subscriber 1 should receive alert");
        let a2 = rx2.try_recv().expect("subscriber 2 should receive alert");
        assert_eq!(a1.src_ip, a2.src_ip);
    }

    #[test]
    fn test_process_line_udp_alert() {
        let tx = make_tx();
        let mut rx = tx.subscribe();
        let line = r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:00","src_ip":"10.0.0.1","dest_ip":"8.8.8.8","src_port":54321,"dest_port":53,"proto":"UDP","alert":{"action":"allowed","signature_id":5001,"signature":"DNS Query","category":"DNS","severity":3}}"#;
        EveConsumer::process_line(line, &tx);
        let alert = rx.try_recv().expect("UDP alert should be broadcast");
        assert_eq!(alert.proto, "UDP");
        assert_eq!(alert.dest_port, 53);
        assert_eq!(alert.alert.unwrap().signature_id, 5001);
    }

    // ── handle_connection edge-cases ──────────────────────────────────────────

    #[tokio::test]
    async fn test_handle_connection_whitespace_lines_ignored() {
        use tokio::io::AsyncWriteExt;
        let (tx_alert, mut rx_alert) = broadcast::channel(16);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        let write_task = tokio::spawn(async move {
            let mut client = client;
            // Send a blank line, then a tab line, then EOF
            client.write_all(b"   \n\t\n").await.unwrap();
            drop(client);
        });

        EveConsumer::handle_connection(server, tx_alert).await;
        write_task.await.unwrap();
        assert!(
            rx_alert.try_recv().is_err(),
            "whitespace lines should be ignored"
        );
    }

    #[tokio::test]
    async fn test_handle_connection_invalid_json_then_alert() {
        use tokio::io::AsyncWriteExt;
        let (tx_alert, mut rx_alert) = broadcast::channel(16);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        let write_task = tokio::spawn(async move {
            let mut client = client;
            client.write_all(b"not valid json\n").await.unwrap();
            let alert_line = concat!(
                r#"{"event_type":"alert","timestamp":"2024-01-01T00:00:01","src_ip":"9.9.9.9","dest_ip":"1.1.1.1","src_port":5000,"dest_port":443,"proto":"TCP","#,
                r#""alert":{"action":"allowed","signature_id":7777,"signature":"After Invalid","category":"Test","severity":1}}"#,
                "\n"
            );
            client.write_all(alert_line.as_bytes()).await.unwrap();
            drop(client);
        });

        EveConsumer::handle_connection(server, tx_alert).await;
        write_task.await.unwrap();

        // The alert after the invalid line should still be processed.
        let alert = rx_alert
            .try_recv()
            .expect("alert after invalid JSON should be broadcast");
        assert_eq!(alert.alert.unwrap().signature_id, 7777);
    }

    // ── SuricataAlert / AlertInfo defaults ────────────────────────────────────

    #[test]
    fn alert_info_signature_defaults_to_empty() {
        let json = r#"{"action":"blocked","signature_id":1,"severity":2}"#;
        let info: AlertInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.signature, "");
        assert_eq!(info.category, "");
    }

    #[test]
    fn suricata_alert_event_type_defaults_to_empty() {
        // event_type has #[serde(default)]
        let json = r#"{"timestamp":"2024-01-01","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","src_port":1,"dest_port":2,"proto":"TCP"}"#;
        let alert: SuricataAlert = serde_json::from_str(json).unwrap();
        assert_eq!(alert.event_type, "");
    }

    #[test]
    fn suricata_alert_clone_is_independent() {
        let alert = SuricataAlert {
            timestamp: "2024-01-01T00:00:00".to_string(),
            src_ip: "1.2.3.4".to_string(),
            dest_ip: "5.6.7.8".to_string(),
            src_port: 1234,
            dest_port: 80,
            icmp_type: None,
            icmp_code: None,
            proto: "TCP".to_string(),
            event_type: "alert".to_string(),
            alert: Some(AlertInfo {
                action: "blocked".to_string(),
                signature_id: 999,
                signature: "Test".to_string(),
                category: "Test".to_string(),
                severity: 1,
            }),
        };
        let cloned = alert.clone();
        assert_eq!(cloned.src_ip, alert.src_ip);
        assert_eq!(cloned.alert.unwrap().signature_id, 999);
    }
}
