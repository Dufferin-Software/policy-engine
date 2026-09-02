// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use anyhow::{Context, Result};
use clap::Parser;
use policy_controller::{
    api_tokens::ApiTokenStore,
    auth::BearerAuthState,
    config::ControllerConfig,
    event_bus::EventBus,
    event_pipeline,
    event_pipeline::alert_bus::AlertRuleBus,
    graphql::{build_schema, ServiceEndpoints},
    grpc::{EnrollmentServiceImpl, NodeManagementServiceImpl},
    http::start_http_server,
    metrics_store::MetricsStore,
    node_registry::NodeRegistry,
    operators::OperatorStore,
    rule_lifecycle_bus::RuleLifecycleBus,
    security::{
        build_enrollment_server_config, build_management_server_config, ca::CertificateAuthority,
        ca::FileCertificateAuthority, server_cert::RenewalConfig, ReloadableServerCert,
        RevocationWatch, RevokedSerials,
    },
    session::NodeSessionManager,
    store::SqliteControllerStore,
    ttl_reaper,
};
use policy_controller_proto::controller::{
    enrollment_service_server::EnrollmentServiceServer,
    node_management_service_server::NodeManagementServiceServer,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
#[command(name = "policy-controller", about = "Policy Controller daemon")]
struct Cli {
    /// Path to TOML config file.
    #[arg(long, default_value = "/etc/policy-controller/config.toml")]
    config: PathBuf,

    /// Directory containing the built web UI (overrides config file).
    #[arg(long)]
    web_root: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    let cli = Cli::parse();

    let mut cfg = if cli.config.exists() {
        ControllerConfig::load(&cli.config)?
    } else {
        log::warn!(
            "Config file not found at {}, using defaults",
            cli.config.display()
        );
        ControllerConfig::default()
    };

    // CLI --web-root overrides config/default.
    if let Some(ref wr) = cli.web_root {
        cfg.web_root = Some(wr.clone());
    }

    // ── CA ─────────────────────────────────────────────────────────────────────
    let ca = FileCertificateAuthority::load_or_create(
        &cfg.ca_key_path(),
        &cfg.ca_cert_path(),
        &cfg.ca_common_name,
    )
    .context("Failed to initialise CA")?;
    let ca: Arc<dyn CertificateAuthority> = Arc::new(ca);
    log::info!("CA initialised");

    let ca_cert_pem = ca.ca_cert_pem();

    // ── Store ──────────────────────────────────────────────────────────────────
    let store = SqliteControllerStore::new(&cfg.db_path)
        .await
        .context("Failed to open SQLite store")?;
    // Borrow the underlying pool for the event pipeline before wrapping the
    // store in an `Arc<dyn ControllerStore>` (which erases the concrete type).
    let event_pool = store.pool();
    let store: Arc<dyn policy_controller::store::ControllerStore> = Arc::new(store);
    log::info!("SQLite store opened at {}", cfg.db_path.display());

    // ── Event pipeline scope + counters ────────────────────────────────────────
    let tenant_scope = Arc::new(
        event_pipeline::bootstrap_default_tenant(event_pool.clone())
            .await
            .context("Failed to bootstrap default tenant")?,
    );
    let event_metrics = Arc::new(event_pipeline::EventPipelineMetrics::new());

    // ── Revocation watch ───────────────────────────────────────────────────────
    // Seed the in-memory revoked-serial mirror from the store at boot. Past
    // decommissions live in `revoked_certs`; without this seed a controller
    // restart would silently re-trust every cert that was revoked before the
    // restart, until its next decommission re-published the serial.
    let initial_revoked = store
        .list_revoked_serials()
        .await
        .context("Failed to load revoked serials from store")?;
    log::info!(
        "Seeding revocation mirror with {} previously revoked serial(s)",
        initial_revoked.len()
    );
    let revocation = Arc::new(RevocationWatch::new(RevokedSerials::from_serials(
        initial_revoked,
    )));

    // ── Node registry ──────────────────────────────────────────────────────────
    let registry = Arc::new(
        NodeRegistry::new(Arc::clone(&store), Arc::clone(&ca))
            .with_revocation(Arc::clone(&revocation))
            .with_node_cert_ttl_secs(cfg.node_cert_ttl_secs),
    );

    // ── Session manager ────────────────────────────────────────────────────────
    let sessions = Arc::new(NodeSessionManager::new());

    // ── Visibility infrastructure ──────────────────────────────────────────────
    let event_bus = Arc::new(EventBus::new());
    let metrics_store = Arc::new(MetricsStore::new());
    let rule_lifecycle_bus = Arc::new(RuleLifecycleBus::new());
    let alert_rule_bus = Arc::new(AlertRuleBus::new());

    // ── Pending-generation registry (in-memory) ────────────────────────────────
    let pending = Arc::new(policy_controller::pending::PendingRegistry::new());
    // Correlates live flow-verdict-cache queries (GraphQL resolver ↔ gRPC stream).
    let flow_queries = Arc::new(policy_controller::flow_query::FlowQueryRegistry::new());
    {
        let reg = Arc::clone(&pending);
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            policy_controller::pending::run_watchdog(
                reg,
                store,
                std::time::Duration::from_millis(500),
            )
            .await;
        });
    }

    // ── TTL reaper — purge rules that expired while agent was offline ─────────
    {
        let store = Arc::clone(&store);
        let bus = Arc::clone(&rule_lifecycle_bus);
        tokio::spawn(async move {
            ttl_reaper::run(store, bus).await;
        });
    }

    // ── Event pipeline tasks ───────────────────────────────────────────────────
    // Policy events are held in a bounded in-memory buffer, never persisted.
    let events = Arc::new(event_pipeline::EventStore::new());
    let _persister_handle = event_pipeline::spawn_persister(
        Arc::clone(&event_bus),
        tenant_scope.tenant_id(),
        Arc::clone(&events),
        Arc::clone(&event_metrics),
    );
    let _retention_handle = event_pipeline::spawn_retention(
        (*tenant_scope).clone(),
        Arc::clone(&events),
        Arc::clone(&event_metrics),
    );
    // Suricata alert persister: EVE alerts from the dedicated bus channel →
    // suricata_alerts table (via the ControllerStore trait).
    let _suricata_alert_handle =
        event_pipeline::spawn_suricata_alert_persister(Arc::clone(&event_bus), Arc::clone(&store));

    // ── Alert pipeline (matcher → grouper → dispatcher) ───────────────────────
    let alert_metrics = Arc::new(event_pipeline::alert_metrics::AlertPipelineMetrics::new());
    let mut alert_notifiers: std::collections::HashMap<
        String,
        Arc<dyn event_pipeline::providers::Notifier>,
    > = std::collections::HashMap::new();
    alert_notifiers.insert(
        "webhook".into(),
        Arc::new(event_pipeline::providers::webhook::WebhookNotifier::new()),
    );
    alert_notifiers.insert(
        "alertmanager".into(),
        Arc::new(event_pipeline::providers::alertmanager::AlertmanagerNotifier::new()),
    );
    alert_notifiers.insert(
        "email".into(),
        Arc::new(event_pipeline::providers::email::EmailNotifier::new()),
    );
    let _alert_engine_handle = event_pipeline::alert_engine::spawn_alert_engine(
        Arc::clone(&event_bus),
        Arc::clone(&alert_rule_bus),
        Arc::clone(&tenant_scope),
        alert_notifiers,
        Arc::clone(&alert_metrics),
        event_pipeline::alert_engine::AlertEngineConfig::default(),
    );

    // ── GraphQL schema ─────────────────────────────────────────────────────────
    let service_endpoints = derive_service_endpoints(&cfg);
    let api_token_store = Arc::new(ApiTokenStore::new(event_pool.clone()));
    let operator_store = Arc::new(OperatorStore::new(event_pool.clone()));
    let rbac_store = Arc::new(policy_controller::rbac::RbacStore::new(event_pool.clone()));
    let schema = build_schema(
        Arc::clone(&registry),
        Arc::clone(&store),
        Arc::clone(&sessions),
        Arc::clone(&pending),
        Arc::clone(&flow_queries),
        Arc::clone(&metrics_store),
        Arc::clone(&rule_lifecycle_bus),
        Arc::clone(&tenant_scope),
        Arc::clone(&events),
        Arc::clone(&alert_rule_bus),
        Arc::clone(&api_token_store),
        Arc::clone(&operator_store),
        Arc::clone(&rbac_store),
        service_endpoints,
    );

    // ── HTTP operator API ──────────────────────────────────────────────────────
    let http_addr: SocketAddr = cfg.http_addr.parse().context("Invalid http_addr")?;
    let bearer_auth_state =
        BearerAuthState::new(Arc::clone(&api_token_store), Arc::clone(&rbac_store));
    let http_server = start_http_server(
        http_addr,
        schema,
        Arc::clone(&event_bus),
        Arc::clone(&metrics_store),
        Arc::clone(&rule_lifecycle_bus),
        Arc::clone(&store),
        Arc::clone(&sessions),
        Arc::clone(&tenant_scope),
        Arc::clone(&events),
        Arc::clone(&event_metrics),
        Arc::clone(&alert_metrics),
        bearer_auth_state,
        Arc::clone(&operator_store),
        Arc::clone(&api_token_store),
        Arc::clone(&rbac_store),
        cfg.web_root.clone(),
    )
    .context("Failed to bind HTTP")?;
    let http_handle = tokio::spawn(http_server);

    // ── gRPC enrollment service (TLS only, no client cert required) ────────────
    let enrollment_service = EnrollmentServiceImpl::new(Arc::clone(&registry));
    let enrollment_addr: SocketAddr = cfg
        .enrollment_addr
        .parse()
        .context("Invalid enrollment_addr")?;

    let server_cert_sans = cfg.server_cert_sans();
    log::info!("Server certificate SANs: {}", server_cert_sans.join(", "));
    let enrollment_server_cert = ca
        .issue_server_cert(&server_cert_sans, cfg.node_cert_ttl_secs)
        .context("Failed to issue enrollment server cert")?;
    // Append the CA cert to the chain the enrollment endpoint presents.
    // ZTP agents pin SHA-256 of the CA cert DER and walk the presented chain
    // looking for a match — including the CA here lets them find it without
    // any pre-distributed trust material.
    let enrollment_cert_holder = Arc::new(
        ReloadableServerCert::from_pem(
            &enrollment_server_cert.cert_pem,
            &enrollment_server_cert.key_pem,
            Some(&ca_cert_pem),
        )
        .context("Failed to build enrollment cert resolver")?,
    );
    let enrollment_tls_config = build_enrollment_server_config(enrollment_cert_holder.clone());
    let enrollment_acceptor = TlsAcceptor::from(enrollment_tls_config);
    let enrollment_listener = TcpListener::bind(enrollment_addr)
        .await
        .context("Failed to bind enrollment TCP listener")?;

    // Background server-cert renewal so a short `node_cert_ttl_secs` does
    // not kill the enrollment endpoint mid-uptime. Without this the cert
    // minted above expires after `ttl_secs` and the endpoint is dark
    // until controller restart.
    let _enrollment_renewal_handle = policy_controller::security::spawn_server_cert_renewal(
        enrollment_cert_holder.clone(),
        Arc::clone(&ca),
        RenewalConfig {
            sans: server_cert_sans.clone(),
            ttl_secs: cfg.node_cert_ttl_secs,
            extra_chain_pem: Some(ca_cert_pem.clone()),
            label: "enrollment",
        },
        enrollment_server_cert,
    );

    let enrollment_handle = tokio::spawn(async move {
        log::info!("gRPC enrollment service listening on {}", enrollment_addr);
        let incoming = async_stream::stream! {
            loop {
                let (tcp, peer) = match enrollment_listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        log::warn!("enrollment TCP accept failed: {e}");
                        continue;
                    }
                };
                let acceptor = enrollment_acceptor.clone();
                match acceptor.accept(tcp).await {
                    Ok(tls) => yield Ok::<_, std::io::Error>(tls),
                    Err(e) => {
                        log::debug!("enrollment TLS handshake from {peer} failed: {e}");
                    }
                }
            }
        };
        tonic::transport::Server::builder()
            .add_service(EnrollmentServiceServer::new(enrollment_service))
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC enrollment server failed");
    });

    // ── gRPC management service (mTLS — client cert required) ─────────────────
    //
    // Uses a hand-built rustls `ServerConfig` (not tonic's `ServerTlsConfig`)
    // so the `RevokingClientCertVerifier` can sit on the handshake path —
    // tonic 0.12 does not expose a hook for a custom `ClientCertVerifier`.
    // TCP accepts are wrapped with `tokio_rustls::TlsAcceptor` and the
    // resulting `TlsStream`s are handed to tonic via `serve_with_incoming`.
    // `TlsStream<TcpStream>` already implements
    // `tonic::transport::server::Connected` (via tonic's "tls" feature), so
    // handlers can still pull peer certs out of request extensions.
    let management_addr: SocketAddr = cfg
        .management_addr
        .parse()
        .context("Invalid management_addr")?;

    let mgmt_server_cert = ca
        .issue_server_cert(&server_cert_sans, cfg.node_cert_ttl_secs)
        .context("Failed to issue management server cert")?;
    let mgmt_cert_holder = Arc::new(
        ReloadableServerCert::from_pem(&mgmt_server_cert.cert_pem, &mgmt_server_cert.key_pem, None)
            .context("Failed to build management cert resolver")?,
    );
    let mgmt_server_config = build_management_server_config(
        &ca_cert_pem,
        mgmt_cert_holder.clone(),
        revocation.subscribe(),
    )
    .context("Failed to build management TLS config")?;
    let mgmt_acceptor = TlsAcceptor::from(mgmt_server_config);

    // Background server-cert renewal — symmetric with the enrollment
    // endpoint above. Agents that connect after the original cert's
    // expiry would otherwise be stuck with no way to even attempt a
    // client-cert renewal.
    let _mgmt_renewal_handle = policy_controller::security::spawn_server_cert_renewal(
        mgmt_cert_holder,
        Arc::clone(&ca),
        RenewalConfig {
            sans: server_cert_sans.clone(),
            ttl_secs: cfg.node_cert_ttl_secs,
            extra_chain_pem: None,
            label: "management",
        },
        mgmt_server_cert,
    );
    let mgmt_listener = TcpListener::bind(management_addr)
        .await
        .context("Failed to bind management TCP listener")?;

    let management_service = NodeManagementServiceImpl::new(
        Arc::clone(&sessions),
        Arc::clone(&store),
        Arc::clone(&event_bus),
        Arc::clone(&metrics_store),
        Arc::clone(&pending),
        Arc::clone(&rule_lifecycle_bus),
        Arc::clone(&flow_queries),
        Arc::clone(&registry),
    );

    let mgmt_handle = tokio::spawn(async move {
        log::info!(
            "gRPC management service (mTLS) listening on {}",
            management_addr
        );
        let incoming = async_stream::stream! {
            loop {
                let (tcp, peer) = match mgmt_listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        // Accept errors are generally transient (fd exhaustion,
                        // peer reset before accept); log and keep serving.
                        log::warn!("management TCP accept failed: {e}");
                        continue;
                    }
                };
                let acceptor = mgmt_acceptor.clone();
                match acceptor.accept(tcp).await {
                    Ok(tls) => yield Ok::<_, std::io::Error>(tls),
                    Err(e) => {
                        // Revoked-cert rejections surface here (the verifier
                        // emits a fatal alert before this future resolves).
                        // The verifier itself already logs the
                        // "Rejecting TLS handshake" line.
                        log::debug!("management TLS handshake from {peer} failed: {e}");
                    }
                }
            }
        };
        tonic::transport::Server::builder()
            .add_service(
                NodeManagementServiceServer::new(management_service)
                    .max_decoding_message_size(
                        policy_controller_proto::MAX_MANAGEMENT_MESSAGE_BYTES,
                    )
                    .max_encoding_message_size(
                        policy_controller_proto::MAX_MANAGEMENT_MESSAGE_BYTES,
                    ),
            )
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC management server failed");
    });

    // Fire the EventBus shutdown signal the moment a termination signal
    // arrives, in parallel with actix's own graceful drain. This lets the
    // long-lived /ws/events and /ws/rule-events tasks close their sessions
    // immediately instead of holding worker connections open until the HTTP
    // server's shutdown_timeout elapses.
    {
        let event_bus = Arc::clone(&event_bus);
        tokio::spawn(async move {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("Failed to install SIGTERM handler for WS shutdown: {e}");
                        return;
                    }
                };
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            log::info!("Termination signal received; closing WebSocket streams");
            event_bus.shutdown();
        });
    }

    log::info!("Policy controller started");

    tokio::select! {
        _ = enrollment_handle => log::error!("gRPC enrollment server exited unexpectedly"),
        _ = mgmt_handle => log::error!("gRPC management server exited unexpectedly"),
        _ = http_handle => log::error!("HTTP server exited unexpectedly"),
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutting down on SIGINT");
        }
    }

    Ok(())
}

/// Build the URLs the UI uses as defaults when minting an enrollment bundle.
/// Hostname comes from `server_san` (the cert SAN agents will verify against);
/// ports come from the bind-addresses so any operator override flows through.
/// Listen wildcards like `0.0.0.0:7777` collapse to `:7777` here — we only
/// care about the port.
fn derive_service_endpoints(cfg: &ControllerConfig) -> ServiceEndpoints {
    fn port_of(addr: &str) -> Option<&str> {
        addr.rsplit_once(':').map(|(_, port)| port)
    }
    let host = &cfg.server_san;
    let mgmt_port = port_of(&cfg.management_addr).unwrap_or("7777");
    let enroll_port = port_of(&cfg.enrollment_addr).unwrap_or("7776");
    ServiceEndpoints {
        controller_url: format!("https://{host}:{mgmt_port}"),
        enrollment_url: format!("https://{host}:{enroll_port}"),
    }
}
