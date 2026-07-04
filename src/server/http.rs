// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! HTTP server for the GraphQL API

use std::sync::Arc;

use actix_cors::Cors;
use actix_files::Files;
use actix_web::{http::header, web, App, HttpResponse, HttpServer, Result as ActixResult};
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use log::info;
use rustls::ServerConfig as RustlsServerConfig;
use rustls_pemfile::{certs, private_key};
use tokio::sync::{broadcast, mpsc, watch};

use super::audit_logger::{AuditBackend, FileAuditLogger, NoopAuditLogger};
use super::auth_middleware::{auth_middleware, AllowAll, AuthProvider, BearerTokenAuth};
use super::bpf_manager::BpfManager;
#[cfg(feature = "suricata")]
use super::eve_consumer::EveConsumer;
use super::event_stream;
use super::flow_verdict_manager::FlowVerdictManager;
#[cfg(feature = "suricata")]
use super::flow_verdict_manager::{alert_to_flow_verdict_key, monotonic_now_ns};
use super::graphql::{build_schema, AppState, PeerAddr, PolicyEngineSchema};
use super::metrics::{self, MetricsFormatter, PrometheusFormatter};
use super::policy_service::{PolicyService, QueueCmd};
use super::rule_events;
use super::state_store::FileStateStore;
#[cfg(feature = "suricata")]
use super::suricata_coordinator::SuricataCoordinator;
#[cfg(feature = "suricata")]
use super::veth_manager::VethManager;
use crate::config::{AffinityPlan, ConfigProvider};
#[cfg(feature = "suricata")]
use crate::types::{Direction, FlowVerdict, InspectMode, PolicyAction};

/// GraphQL endpoint handler
async fn graphql_handler(
    schema: web::Data<PolicyEngineSchema>,
    http_req: actix_web::HttpRequest,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let peer_addr = PeerAddr(
        http_req
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    );
    schema
        .execute(req.into_inner().data(peer_addr))
        .await
        .into()
}

/// GraphQL Playground handler (for development/testing)
async fn graphql_playground() -> ActixResult<HttpResponse> {
    let source = playground_source(GraphQLPlaygroundConfig::new("/graphql"));
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(source))
}

/// Health check endpoint
async fn health_check() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

/// Schema SDL export endpoint
async fn schema_sdl(schema: web::Data<PolicyEngineSchema>) -> ActixResult<HttpResponse> {
    let sdl = schema.sdl();
    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(sdl))
}

/// Default path where the policy-engine-web package installs static assets
const DEFAULT_WEB_ROOT: &str = "/usr/share/policy-engine-web";

/// Server configuration
#[derive(Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub web_root: Option<String>,
    pub affinity: Arc<AffinityPlan>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            web_root: None,
            affinity: Arc::new(AffinityPlan::disabled()),
            tls_cert: None,
            tls_key: None,
        }
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> std::io::Result<RustlsServerConfig> {
    let cert_file = std::fs::File::open(cert_path).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("TLS cert '{}': {}", cert_path, e),
        )
    })?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse certs from '{}': {}", cert_path, e),
            )
        })?;
    if cert_chain.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("no certificates found in '{}'", cert_path),
        ));
    }

    let key_file = std::fs::File::open(key_path).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("TLS key '{}': {}", key_path, e),
        )
    })?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let private_key = private_key(&mut key_reader)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse key from '{}': {}", key_path, e),
            )
        })?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("no private key found in '{}'", key_path),
            )
        })?;

    RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid TLS cert/key pair: {}", e),
            )
        })
}

/// CLI argument overrides for server configuration.
///
/// All fields are `Option<T>` so that an absent CLI argument is distinguishable
/// from an explicit value, enabling correct config-file → CLI precedence.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub web_root: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

/// Build a [`ServerConfig`] by merging config-file values with CLI overrides.
///
/// Precedence (highest first):
/// 1. CLI argument (explicitly provided)
/// 2. `[server]` section of the config file
/// 3. Hardcoded default (`127.0.0.1:8080`, no TLS)
///
/// `affinity` is passed in pre-computed (from the same `Config` load) so this
/// function does not need to re-read the file for the affinity section.
pub fn resolve_server_config(
    provider: &dyn ConfigProvider,
    overrides: CliOverrides,
    affinity: Arc<AffinityPlan>,
) -> ServerConfig {
    let cfg = provider.load();
    let s = &cfg.server;
    ServerConfig {
        host: overrides
            .host
            .or_else(|| s.host.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        port: overrides.port.or(s.port).unwrap_or(8080),
        web_root: overrides.web_root,
        affinity,
        tls_cert: overrides.tls_cert.or_else(|| s.tls_cert.clone()),
        tls_key: overrides.tls_key.or_else(|| s.tls_key.clone()),
    }
}

/// Initialize the BPF manager and build the [`PolicyService`].
///
/// `BpfManager::new()` auto-detects whether the compiled BPF ELF has changed and
/// clears stale pins when needed; if pins are intact from a previous run it also
/// re-attaches the loaded skeletons so map reads (stats, rules) work immediately.
///
/// Persisted on-disk state is restored only when the kernel maps are *fresh*
/// (reboot, BPF version change, or first start). When pins were reused — a daemon
/// restart with the same BPF binary — the kernel already holds the correct state,
/// so no restore is performed.
fn init_policy_service(
    rule_event_tx: broadcast::Sender<rule_events::RuleLifecycleEvent>,
    timer_tx: mpsc::Sender<QueueCmd>,
) -> std::io::Result<PolicyService> {
    let manager = BpfManager::new().map_err(|e| std::io::Error::other(e.to_string()))?;
    let xdp_already_loaded = manager.xdp_loaded();
    let tc_already_loaded = manager.tc_loaded();
    let maps_are_fresh = !manager.pins_were_reused();

    let state_store = FileStateStore::new(crate::paths::STATE_FILE_PATH);

    let mut service = PolicyService::new_with_state(
        Box::new(manager),
        Box::new(state_store),
        xdp_already_loaded,
        tc_already_loaded,
    )
    .with_rule_event_sender(rule_event_tx)
    .with_timer_sender(timer_tx);

    if maps_are_fresh {
        if let Err(e) = service.restore_from_store() {
            log::warn!("Failed to restore state from store: {:#}", e);
        }
    }

    Ok(service)
}

/// Build the GraphQL auth provider from the environment.
///
/// Bearer-token authentication is enforced when `POLICY_ENGINE_API_TOKEN` is set;
/// otherwise every request is allowed through.
fn build_auth_provider() -> Arc<dyn AuthProvider> {
    match std::env::var("POLICY_ENGINE_API_TOKEN").ok() {
        Some(token) => {
            info!("Bearer token authentication enabled");
            Arc::new(BearerTokenAuth::new(token))
        }
        None => {
            info!("Bearer token authentication disabled (POLICY_ENGINE_API_TOKEN not set)");
            Arc::new(AllowAll)
        }
    }
}

/// Build the audit-log backend, falling back to a no-op logger (non-fatal) when
/// the audit log file cannot be opened.
fn build_audit_backend() -> Arc<dyn AuditBackend> {
    match FileAuditLogger::new("/var/log/policy-engine/audit.log") {
        Ok(al) => {
            info!("Audit log: /var/log/policy-engine/audit.log");
            Arc::new(al)
        }
        Err(e) => {
            log::warn!("Audit log disabled: {:#}", e);
            Arc::new(NoopAuditLogger)
        }
    }
}

/// Resolve the web-UI root directory: the explicit `--web-root` flag wins, then
/// the default install path if it exists on disk, otherwise the UI is disabled.
fn resolve_web_root(web_root: Option<String>) -> Option<String> {
    web_root.or_else(|| {
        let default = std::path::Path::new(DEFAULT_WEB_ROOT);
        default.is_dir().then(|| DEFAULT_WEB_ROOT.to_string())
    })
}

/// Start the inspect (Suricata) subsystem: launch the EVE consumer and spawn the
/// flow-verdict cleanup and IPS enforcement background loops.
#[cfg(feature = "suricata")]
async fn start_inspect_tasks(state: &Arc<AppState>) -> std::io::Result<()> {
    state
        .eve_consumer
        .lock()
        .await
        .start()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    spawn_ips_enforcement_loop(state.clone());
    Ok(())
}

/// Background loop: periodically evict expired flow verdicts from the BPF maps.
///
/// Not gated behind `suricata`: SNI/QUIC matching writes verdicts into the same
/// cache in every build, so the cache needs an evictor regardless of IPS. Plain
/// HASH maps don't auto-expire — without this loop, expired entries accumulate
/// until the map fills (`MAX_FLOW_VERDICTS`).
fn spawn_flow_verdict_cleanup_loop(state: Arc<AppState>) {
    let manager = FlowVerdictManager::new();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(manager.cleanup_interval());
        loop {
            interval.tick().await;
            let mut service = state.service.lock().await;
            let _ = manager.cleanup_expired(&mut service);
        }
    });
}

/// Background loop: turn Suricata EVE alerts into DROP flow verdicts.
///
/// A verdict is installed only in IPS mode; in IDS mode alerts are still received
/// and broadcast but never block traffic. When dropping, both directions of the
/// flow (server→client ingress and client→server egress) are blocked.
#[cfg(feature = "suricata")]
fn spawn_ips_enforcement_loop(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut rx = { state.eve_consumer.lock().await.subscribe() };
        let verdict_ttl_ns = std::time::Duration::from_secs(300).as_nanos() as u64;
        loop {
            match rx.recv().await {
                Ok(alert) => {
                    if alert.alert.is_some() {
                        if let Ok(key) = alert_to_flow_verdict_key(&alert) {
                            let mut service = state.service.lock().await;
                            let is_ips = service
                                .get_inspect_config(Direction::Ingress)
                                .map(|c| InspectMode::from(c.mode) == InspectMode::Ips)
                                .unwrap_or(false);
                            if is_ips {
                                let now_ns = monotonic_now_ns();
                                let verdict = FlowVerdict {
                                    action: PolicyAction::Drop as u32,
                                    _pad: 0,
                                    timestamp_ns: now_ns,
                                    expires_ns: now_ns + verdict_ttl_ns,
                                    packets: 0,
                                    bytes: 0,
                                    rule_id: 0,
                                };
                                // The verdict cache is scoped per-interface
                                // (flow_verdict_key.ifindex), but a Suricata alert
                                // carries no ifindex. Install the DROP on every
                                // attached interface for the matching direction so
                                // the flow is blocked wherever it ingresses/egresses.
                                // The interface set is tiny and stale entries are
                                // LRU-reclaimed, so the spray is cheap.
                                let interfaces = service.get_interfaces();
                                // Ingress key blocks the server→client direction;
                                // the reversed key blocks client→server on egress.
                                let mut egress_key = key;
                                egress_key.saddr.copy_from_slice(&key.daddr);
                                egress_key.daddr.copy_from_slice(&key.saddr);
                                egress_key.sport = key.dport;
                                egress_key.dport = key.sport;
                                for iface in &interfaces {
                                    let ifindex = iface.ifindex as u32;
                                    if iface.direction.eq_ignore_ascii_case("ingress") {
                                        let mut k = key;
                                        k.ifindex = ifindex;
                                        service
                                            .update_flow_verdict(&k, &verdict, Direction::Ingress)
                                            .ok();
                                    } else if iface.direction.eq_ignore_ascii_case("egress") {
                                        let mut k = egress_key;
                                        k.ifindex = ifindex;
                                        service
                                            .update_flow_verdict(&k, &verdict, Direction::Egress)
                                            .ok();
                                    }
                                }
                            }
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    log::warn!("IPS enforcement loop missed {} alerts", n);
                }
                Err(_) => break,
            }
        }
    });
}

/// Background loop: periodically export aged BPF flows to the configured IPFIX
/// collector, recreating the exporter/socket when the collector address changes.
#[cfg(feature = "ipfix")]
fn spawn_ipfix_export_loop(state: Arc<AppState>) {
    use super::ipfix_exporter::IpfixExporter;
    use std::sync::atomic::Ordering;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut exporter: Option<IpfixExporter> = None;
        let mut socket: Option<std::net::UdpSocket> = None;
        let mut last_collector: Option<std::net::SocketAddr> = None;
        loop {
            interval.tick().await;
            let config = {
                let service = state.service.lock().await;
                service.get_flow_export_config().clone()
            };
            if !config.enabled {
                exporter = None;
                socket = None;
                last_collector = None;
                continue;
            }
            let collector_addr: std::net::SocketAddr =
                match format!("{}:{}", config.collector_host, config.collector_port).parse() {
                    Ok(a) => a,
                    Err(e) => {
                        log::warn!("IPFIX: invalid collector address: {}", e);
                        continue;
                    }
                };
            // Recreate exporter/socket when collector address changes.
            if last_collector != Some(collector_addr) {
                match IpfixExporter::new(&config) {
                    Ok(exp) => {
                        exporter = Some(exp);
                        match std::net::UdpSocket::bind("0.0.0.0:0") {
                            Ok(s) => {
                                socket = Some(s);
                                last_collector = Some(collector_addr);
                            }
                            Err(e) => {
                                log::warn!("IPFIX: failed to bind UDP socket: {}", e);
                                exporter = None;
                                socket = None;
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("IPFIX: failed to create exporter: {}", e);
                        continue;
                    }
                }
            }
            if let (Some(exp), Some(sock)) = (exporter.as_mut(), socket.as_ref()) {
                let mut service = state.service.lock().await;
                let bpf = service.bpf_ops_mut();
                match exp.export_aged_flows(bpf, sock) {
                    Ok(n) => {
                        if n > 0 {
                            state.flows_exported_total.fetch_add(n, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        log::warn!("IPFIX: export error: {}", e);
                    }
                }
            }
        }
    });
}

/// Background loop: enforce rule TTL and schedule transitions via a [`DelayQueue`],
/// firing exactly when each rule's next transition is due. Commands to (re)insert
/// or remove timers arrive on `timer_rx` from the policy service.
fn spawn_rule_timer_loop(state: Arc<AppState>, timer_rx: mpsc::Receiver<QueueCmd>) {
    use futures_util::StreamExt;
    use std::collections::HashMap;
    use tokio_util::time::delay_queue;
    use tokio_util::time::DelayQueue;

    tokio::spawn(async move {
        let mut queue: DelayQueue<u64> = DelayQueue::new();
        let mut key_map: HashMap<u64, delay_queue::Key> = HashMap::new();
        let mut cmd_rx = timer_rx;

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(QueueCmd::Insert { rule_id, at }) => {
                            // Cancel any existing entry before re-inserting.
                            if let Some(old_key) = key_map.remove(&rule_id) {
                                queue.try_remove(&old_key);
                            }
                            let key = queue.insert_at(rule_id, at);
                            key_map.insert(rule_id, key);
                        }
                        Some(QueueCmd::Remove { rule_id }) => {
                            if let Some(key) = key_map.remove(&rule_id) {
                                queue.try_remove(&key);
                            }
                        }
                        // Channel closed (service shutdown) — exit cleanly.
                        None => break,
                    }
                }
                Some(expired) = queue.next() => {
                    let rule_id = *expired.get_ref();
                    key_map.remove(&rule_id);
                    let next = state.service.lock().await.handle_timer_expiry(rule_id);
                    if let Some(at) = next {
                        let key = queue.insert_at(rule_id, at);
                        key_map.insert(rule_id, key);
                    }
                }
            }
        }
    });
}

/// Spawn a task that watches for SIGTERM/SIGINT and broadcasts a shutdown signal.
///
/// WebSocket handlers subscribe to the returned channel and send a Close frame to
/// clients on shutdown, before actix forcibly drops connections at the
/// `shutdown_timeout` boundary.
fn spawn_shutdown_signal_task() -> Arc<watch::Sender<bool>> {
    let (shutdown_tx, _) = watch::channel(false);
    let shutdown_tx = Arc::new(shutdown_tx);

    let tx = Arc::clone(&shutdown_tx);
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        info!("Shutdown signal received; notifying WebSocket clients");
        let _ = tx.send(true);
    });

    shutdown_tx
}

/// Build the CORS configuration shared by every HTTP worker.
fn build_cors() -> Cors {
    Cors::default()
        .allow_any_origin()
        .allowed_methods(vec!["GET", "POST", "OPTIONS"])
        .allowed_headers(vec![
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
        ])
        .max_age(3600)
}

/// Build the static-file service for the web UI, with an SPA fallback that serves
/// `index.html` for any route not matching a file on disk.
fn spa_files_service(root: &str) -> Files {
    Files::new("/", root)
        .index_file("index.html")
        .default_handler(actix_web::dev::fn_service(
            |req: actix_web::dev::ServiceRequest| {
                let root = req
                    .app_data::<web::Data<String>>()
                    .map(|d| d.get_ref().clone())
                    .unwrap_or_default();
                let index_path = format!("{}/index.html", root);
                async move {
                    let res = actix_files::NamedFile::open_async(index_path)
                        .await?
                        .into_response(req.request());
                    Ok(req.into_response(res))
                }
            },
        ))
}

/// Log the startup banner with the resolved endpoint URLs.
fn log_startup_endpoints(config: &ServerConfig, web_root: Option<&str>) {
    let scheme = if config.tls_cert.is_some() {
        "https"
    } else {
        "http"
    };
    info!(
        "Starting GraphQL server at {}://{}:{}",
        scheme, config.host, config.port
    );
    info!(
        "GraphQL Playground available at {}://{}:{}/playground",
        scheme, config.host, config.port
    );
    info!(
        "Schema SDL available at {}://{}:{}/schema.graphql",
        scheme, config.host, config.port
    );
    if let Some(root) = web_root {
        info!("Serving web UI from {}", root);
    }
}

/// Start the GraphQL server.
///
/// High-level flow: build the policy service and shared state, spawn the
/// background tasks (inspect/IPFIX/rule-timer/event-stream/shutdown), wire up the
/// actix HTTP app, then bind (TLS or plaintext) and run until shutdown — finally
/// performing BPF cleanup once the server has stopped.
pub async fn run_server(config: ServerConfig) -> std::io::Result<()> {
    // --- Build the policy service and shared application state ---

    // Rule lifecycle broadcaster and timer channel are created up front so their
    // senders can be wired into the service before it is constructed.
    let rule_event_tx = rule_events::start_rule_event_broadcaster();
    let (timer_tx, timer_rx) = mpsc::channel::<QueueCmd>(1024);

    let service = init_policy_service(rule_event_tx.clone(), timer_tx)?;

    // Inspect infrastructure (suricata feature only).
    #[cfg(feature = "suricata")]
    let veth_manager = VethManager::new();
    #[cfg(feature = "suricata")]
    let suricata_coordinator = SuricataCoordinator::new();
    #[cfg(feature = "suricata")]
    let eve_consumer = EveConsumer::new(suricata_coordinator.eve_path().clone());

    let state = Arc::new(
        AppState::new(
            service,
            #[cfg(feature = "suricata")]
            veth_manager,
            #[cfg(feature = "suricata")]
            suricata_coordinator,
            #[cfg(feature = "suricata")]
            eve_consumer,
            config.affinity.clone(),
        )
        .with_audit_logger(build_audit_backend()),
    );

    let schema = build_schema(state.clone());

    // --- Spawn background tasks ---
    #[cfg(feature = "suricata")]
    start_inspect_tasks(&state).await?;
    // Re-apply persisted inspect state (mode + per-interface flags).  Runs
    // after init_policy_service has replayed attachments, so the per-interface
    // TC auto-attach sees the restored XDP interfaces.  Failures are logged,
    // never fatal.
    #[cfg(feature = "suricata")]
    super::inspect_orchestrator::restore_inspect_state(&state).await;
    #[cfg(feature = "ipfix")]
    spawn_ipfix_export_loop(state.clone());
    // Evict expired flow verdicts in every build — SNI/QUIC matching populates
    // the cache even without the IPS (suricata) feature.
    spawn_flow_verdict_cleanup_loop(state.clone());
    spawn_rule_timer_loop(state.clone(), timer_rx);

    // BPF event stream broadcaster (ring-buffer polling thread pinned to event_cpus).
    let event_tx = event_stream::start_event_stream(config.affinity.clone(), state.service.clone());

    // --- Wire up and run the HTTP server ---
    let web_root = resolve_web_root(config.web_root.clone());
    log_startup_endpoints(&config, web_root.as_deref());

    let auth_data: web::Data<Arc<dyn AuthProvider>> = web::Data::new(build_auth_provider());
    let formatter_data: web::Data<Arc<dyn MetricsFormatter>> =
        web::Data::new(Arc::new(PrometheusFormatter));
    let state_data = web::Data::new(state.clone());
    let shutdown_data: web::Data<Arc<watch::Sender<bool>>> =
        web::Data::new(spawn_shutdown_signal_task());

    // Allow in-flight HTTP requests to drain on shutdown, but don't wait
    // indefinitely for persistent connections (WebSocket, keep-alive). The
    // default is 30 s — which is exactly how long the WebSocket event stream
    // connection delays shutdown when a web-UI client is connected.
    const SHUTDOWN_TIMEOUT_SECS: u64 = 5;
    let actix_workers = config.affinity.actix_workers;

    let server = HttpServer::new(move || {
        let mut app = App::new()
            .wrap(build_cors())
            .wrap(actix_web::middleware::from_fn(auth_middleware))
            .app_data(web::Data::new(schema.clone()))
            .app_data(web::Data::new(event_tx.clone()))
            .app_data(web::Data::new(rule_event_tx.clone()))
            .app_data(auth_data.clone())
            .app_data(formatter_data.clone())
            .app_data(state_data.clone())
            .app_data(shutdown_data.clone())
            .route("/graphql", web::post().to(graphql_handler))
            .route("/graphql", web::get().to(graphql_playground))
            .route("/playground", web::get().to(graphql_playground))
            .route("/schema.graphql", web::get().to(schema_sdl))
            .route("/health", web::get().to(health_check))
            .route("/metrics", web::get().to(metrics::metrics_handler))
            .route("/ws/events", web::get().to(event_stream::ws_events))
            .route(
                "/ws/rule-events",
                web::get().to(rule_events::ws_rule_events),
            );

        // Suricata EVE alert stream — present whenever the feature is
        // compiled in; idles while inspection is disabled.
        #[cfg(feature = "suricata")]
        {
            app = app.route("/ws/alerts", web::get().to(super::alert_stream::ws_alerts));
        }

        // Serve the web UI (and its SPA fallback) when a root is configured.
        if let Some(ref root) = web_root {
            app = app
                .service(spa_files_service(root))
                .app_data(web::Data::new(root.clone()));
        }

        app
    })
    .workers(actix_workers)
    .shutdown_timeout(SHUTDOWN_TIMEOUT_SECS);

    // Bind with TLS or plaintext (per config) and run until shutdown. Binding
    // differs between TLS and plaintext, so it stays inline here rather than in a
    // helper (the un-bound HttpServer builder has an unnameable generic type).
    let server_result = match (config.tls_cert.as_deref(), config.tls_key.as_deref()) {
        (Some(cert), Some(key)) => {
            let tls_config = load_tls_config(cert, key)?;
            info!(
                "TLS enabled — HTTPS at https://{}:{}",
                config.host, config.port
            );
            server
                .bind_rustls_0_23((config.host.as_str(), config.port), tls_config)?
                .run()
                .await
        }
        (None, None) => {
            info!(
                "TLS disabled — HTTP at http://{}:{}",
                config.host, config.port
            );
            server
                .bind((config.host.as_str(), config.port))?
                .run()
                .await
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Both --tls-cert and --tls-key must be provided together (or neither)",
            ))
        }
    };

    // After actix has fully stopped accepting connections, perform BPF cleanup
    // according to the configured stop behavior.
    state.service.lock().await.perform_stop_cleanup();

    server_result
}

#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::config::{Config, MockConfigProvider, ServerFileConfig};

    fn no_affinity() -> Arc<AffinityPlan> {
        Arc::new(AffinityPlan::disabled())
    }

    fn no_overrides() -> CliOverrides {
        CliOverrides::default()
    }

    fn file_cfg(server: ServerFileConfig) -> Config {
        Config {
            server,
            ..Default::default()
        }
    }

    #[test]
    fn defaults_when_config_is_empty() {
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(Config::default);

        let s = resolve_server_config(&mock, no_overrides(), no_affinity());
        assert_eq!(s.host, "127.0.0.1");
        assert_eq!(s.port, 8080);
        assert!(s.tls_cert.is_none());
        assert!(s.tls_key.is_none());
    }

    #[test]
    fn file_port_used_when_no_cli_override() {
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(|| {
            file_cfg(ServerFileConfig {
                port: Some(9090),
                ..Default::default()
            })
        });

        let s = resolve_server_config(&mock, no_overrides(), no_affinity());
        assert_eq!(s.port, 9090);
    }

    #[test]
    fn cli_port_overrides_file_port() {
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(|| {
            file_cfg(ServerFileConfig {
                port: Some(9090),
                ..Default::default()
            })
        });

        let overrides = CliOverrides {
            port: Some(1234),
            ..Default::default()
        };
        let s = resolve_server_config(&mock, overrides, no_affinity());
        assert_eq!(s.port, 1234);
    }

    #[test]
    fn file_tls_used_when_no_cli_override() {
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(|| {
            file_cfg(ServerFileConfig {
                tls_cert: Some("/etc/certs/server.crt".to_string()),
                tls_key: Some("/etc/certs/server.key".to_string()),
                ..Default::default()
            })
        });

        let s = resolve_server_config(&mock, no_overrides(), no_affinity());
        assert_eq!(s.tls_cert.as_deref(), Some("/etc/certs/server.crt"));
        assert_eq!(s.tls_key.as_deref(), Some("/etc/certs/server.key"));
    }

    #[test]
    fn cli_tls_overrides_file_tls() {
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(|| {
            file_cfg(ServerFileConfig {
                tls_cert: Some("/file/cert.crt".to_string()),
                tls_key: Some("/file/key.key".to_string()),
                ..Default::default()
            })
        });

        let overrides = CliOverrides {
            tls_cert: Some("/cli/cert.crt".to_string()),
            tls_key: Some("/cli/key.key".to_string()),
            ..Default::default()
        };
        let s = resolve_server_config(&mock, overrides, no_affinity());
        assert_eq!(s.tls_cert.as_deref(), Some("/cli/cert.crt"));
        assert_eq!(s.tls_key.as_deref(), Some("/cli/key.key"));
    }

    #[test]
    fn file_host_used_when_no_cli_override() {
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(|| {
            file_cfg(ServerFileConfig {
                host: Some("0.0.0.0".to_string()),
                ..Default::default()
            })
        });

        let s = resolve_server_config(&mock, no_overrides(), no_affinity());
        assert_eq!(s.host, "0.0.0.0");
    }

    #[test]
    fn cli_host_overrides_file_host() {
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(|| {
            file_cfg(ServerFileConfig {
                host: Some("0.0.0.0".to_string()),
                ..Default::default()
            })
        });

        let overrides = CliOverrides {
            host: Some("10.0.0.1".to_string()),
            ..Default::default()
        };
        let s = resolve_server_config(&mock, overrides, no_affinity());
        assert_eq!(s.host, "10.0.0.1");
    }

    #[test]
    fn partial_tls_from_file_not_completed_by_defaults() {
        // Only cert in file, no key anywhere — both should stay as-is (None for key).
        let mut mock = MockConfigProvider::new();
        mock.expect_load().returning(|| {
            file_cfg(ServerFileConfig {
                tls_cert: Some("/etc/certs/server.crt".to_string()),
                ..Default::default()
            })
        });

        let s = resolve_server_config(&mock, no_overrides(), no_affinity());
        assert_eq!(s.tls_cert.as_deref(), Some("/etc/certs/server.crt"));
        assert!(s.tls_key.is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_default_host() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.host, "127.0.0.1");
    }

    #[test]
    fn server_config_default_port() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.port, 8080);
    }

    #[test]
    fn server_config_default_web_root_is_none() {
        let cfg = ServerConfig::default();
        assert!(cfg.web_root.is_none());
    }

    #[test]
    fn default_web_root_constant_value() {
        assert_eq!(DEFAULT_WEB_ROOT, "/usr/share/policy-engine-web");
    }

    #[actix_web::test]
    async fn health_check_returns_200() {
        use actix_web::{web, App};
        let app =
            actix_web::test::init_service(App::new().route("/health", web::get().to(health_check)))
                .await;
        let req = actix_web::test::TestRequest::get()
            .uri("/health")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn health_check_body_contains_ok() {
        use actix_web::{web, App};
        let app =
            actix_web::test::init_service(App::new().route("/health", web::get().to(health_check)))
                .await;
        let req = actix_web::test::TestRequest::get()
            .uri("/health")
            .to_request();
        let body: serde_json::Value = actix_web::test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok");
    }

    #[actix_web::test]
    async fn graphql_playground_returns_200_with_html() {
        use actix_web::{web, App};
        let app = actix_web::test::init_service(
            App::new().route("/playground", web::get().to(graphql_playground)),
        )
        .await;
        let req = actix_web::test::TestRequest::get()
            .uri("/playground")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/html"),
            "expected HTML content-type, got: {}",
            ct
        );
    }
}
