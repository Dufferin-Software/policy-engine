// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{Context, Result};
use clap::Parser;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::time::sleep;

use policy_node_agent::{
    change_detector::{ChangeDetector, PollingChangeDetector},
    config::{AgentConfig, DEFAULT_CONFIG_PATH},
    config_applier::{ConfigApplier, SpawnBlockingLocalClient},
    controller_client,
    enrollment::{
        bundle::BootstrapBundle, EnrolledCredentials, EnrolledEndpoints, EnrollmentManager,
        TonicEnrollmentRpc,
    },
    identity::select_identity,
    network_info::system::SystemNetworkInfo,
    system_info::real::RealSystemInfo,
};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Initial reconnect delay; doubles on each failure up to `RECONNECT_DELAY_MAX`.
const RECONNECT_DELAY_INITIAL: Duration = Duration::from_secs(2);
/// Maximum delay between management stream reconnect attempts.
const RECONNECT_DELAY_MAX: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(
    name = "policy-node-agent",
    about = "Fleet management agent for policy-engine nodes"
)]
#[command(version)]
struct Cli {
    /// Path to the agent configuration file.
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Override the identity key path from config.
    #[arg(long)]
    identity_key: Option<PathBuf>,

    /// Path to a ZTP bootstrap bundle. Overrides config + the
    /// `POLICY_BOOTSTRAP_BUNDLE` environment variable.
    #[arg(long, env = "POLICY_BOOTSTRAP_BUNDLE")]
    bootstrap_bundle: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    let cli = Cli::parse();

    // ── Config ─────────────────────────────────────────────────────────────────
    let mut config = AgentConfig::load(&cli.config)?;
    if !config.controller_url.is_empty() {
        log::info!("Controller: {}", config.controller_url);
    }

    // ── Identity ────────────────────────────────────────────────────────────────
    let key_path = cli
        .identity_key
        .as_deref()
        .unwrap_or(&config.identity_key_path);

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create identity key directory: {}",
                parent.display()
            )
        })?;
    }

    let identity = select_identity(key_path)?;
    let identity: Arc<dyn policy_node_agent::identity::NodeIdentity> = Arc::from(identity);
    log::info!("Node ID:  {}", identity.node_id());
    if let Some(uuid) = identity.dmi_uuid() {
        log::info!("DMI UUID: {}", uuid);
    }

    // ── Enrollment ──────────────────────────────────────────────────────────────
    let creds = if EnrolledCredentials::exists(&config.client_key_path, &config.client_cert_path) {
        log::info!("Loading existing credentials from disk");
        let creds = EnrolledCredentials::load(
            &config.client_key_path,
            &config.client_cert_path,
            &config.ca_cert_path,
        )
        .with_context(|| {
            format!(
                "Failed to load credentials. To re-enroll, run:\n  \
                 sudo rm -f {} {} {}\n\
                 then drop a fresh ZTP bundle at {} and restart this service.",
                config.client_key_path.display(),
                config.client_cert_path.display(),
                config.ca_cert_path.display(),
                config.bootstrap_bundle_path.display(),
            )
        })?;

        // Recover the controller/enrollment URLs persisted at enrollment time.
        // The bootstrap bundle is consumed on first enroll, so the in-memory
        // config URLs from `AgentConfig::load` may be empty here.
        if config.endpoints_path.exists() {
            let endpoints = EnrolledEndpoints::load(&config.endpoints_path)?;
            if config.controller_url.is_empty() {
                config.controller_url = endpoints.controller_url.clone();
            }
            if config.enrollment_url.is_none() {
                config.enrollment_url = Some(endpoints.enrollment_url);
            }
            log::info!("Controller: {}", config.controller_url);
        } else if config.controller_url.is_empty() {
            anyhow::bail!(
                "No controller URL available: credentials exist but {} is missing \
                 and config.controller_url is empty. Re-enroll by removing the \
                 credentials and providing a fresh bootstrap bundle.",
                config.endpoints_path.display(),
            );
        }

        creds
    } else {
        log::info!("No credentials found, starting enrollment");

        let bundle_path = cli
            .bootstrap_bundle
            .clone()
            .unwrap_or_else(|| config.bootstrap_bundle_path.clone());

        let bundle = if bundle_path.exists() {
            let b = BootstrapBundle::read_from_file(&bundle_path)
                .context("Failed to load ZTP bootstrap bundle")?;
            log::info!(
                "ZTP bundle present at {} (token_id={})",
                bundle_path.display(),
                b.token_id
            );
            // Bundle URLs override config so a single distributed bundle suffices.
            config.controller_url = b.controller_url.clone();
            config.enrollment_url = Some(b.enrollment_url.clone());
            b
        } else {
            anyhow::bail!(
                "No bootstrap bundle on disk. Generate one with \
                 `policy-controller-client enroll-token create --bundle-only > bundle.b64` \
                 and place it at {} (mode 0600), then restart this service.",
                bundle_path.display()
            );
        };

        let enrollment_url = config.resolved_enrollment_url().to_string();
        log::info!("Enrollment URL: {}", enrollment_url);

        let fp = bundle
            .ca_fingerprint_bytes()
            .context("Bundle has malformed CA fingerprint")?;

        // Retry enrollment indefinitely — the controller may not be up yet.
        let creds = loop {
            let rpc = match TonicEnrollmentRpc::connect_pinned(enrollment_url.clone(), fp).await {
                Ok(rpc) => rpc,
                Err(e) => {
                    log::warn!(
                        "Failed to connect to enrollment service: {:#}. Retrying in {}s",
                        e,
                        RECONNECT_DELAY_MAX.as_secs()
                    );
                    tokio::select! {
                        _ = sleep(RECONNECT_DELAY_MAX) => continue,
                        _ = tokio::signal::ctrl_c() => {
                            log::info!("Shutting down");
                            return Ok(());
                        }
                    }
                }
            };

            let manager = EnrollmentManager::with_bundle(
                Arc::new(rpc),
                Arc::clone(&identity),
                AGENT_VERSION,
                &bundle,
            )?;
            match manager.enroll().await {
                Ok(creds) => break creds,
                Err(e) => {
                    log::warn!(
                        "Enrollment failed: {:#}. Retrying in {}s",
                        e,
                        RECONNECT_DELAY_MAX.as_secs()
                    );
                    tokio::select! {
                        _ = sleep(RECONNECT_DELAY_MAX) => continue,
                        _ = tokio::signal::ctrl_c() => {
                            log::info!("Shutting down");
                            return Ok(());
                        }
                    }
                }
            }
        };

        creds
            .save(
                &config.client_key_path,
                &config.client_cert_path,
                &config.ca_cert_path,
            )
            .context("Failed to save credentials")?;

        // Persist the URLs learned from the bundle so subsequent restarts can
        // recover them after the bundle is deleted below.
        EnrolledEndpoints {
            controller_url: config.controller_url.clone(),
            enrollment_url: config
                .enrollment_url
                .clone()
                .unwrap_or_else(|| config.controller_url.clone()),
        }
        .save(&config.endpoints_path)
        .context("Failed to save enrolled endpoints")?;

        // Consumed-secret hygiene: delete the bundle from disk so a stolen
        // image or operator screenshot of /etc cannot replay enrollment.
        if let Err(e) = std::fs::remove_file(&bundle_path) {
            log::warn!(
                "Could not remove consumed bundle at {}: {} \
                 (this is recoverable — the token is single/limited-use anyway)",
                bundle_path.display(),
                e
            );
        } else {
            log::info!(
                "Consumed bootstrap bundle removed from {}",
                bundle_path.display()
            );
        }

        log::info!("Credentials saved, node is now enrolled");
        creds
    };

    // ── Config applier ─────────────────────────────────────────────────────────
    let applier = Arc::new(ConfigApplier::new(Arc::new(SpawnBlockingLocalClient::new(
        config.local_server_url.clone(),
    ))));

    // ── Change detector ───────────────────────────────────────────────────────
    // Detects out-of-band edits (e.g. policy-client CLI) so the controller
    // can be kept in sync.
    let change_detector: Arc<dyn ChangeDetector> = Arc::new(PollingChangeDetector::new());

    // ── Network info ──────────────────────────────────────────────────────────
    let net_info = Arc::new(SystemNetworkInfo);

    // ── System info ──────────────────────────────────────────────────────────
    let sys_info = Arc::new(RealSystemInfo::new());

    // ── Cert renewal task ─────────────────────────────────────────────────────
    // Spawned once and runs for the lifetime of the agent process. The task
    // re-reads the cert/key paths on each tick rather than holding the
    // in-memory `creds`, so a successful renewal becomes visible to it on
    // the next iteration without needing to be plumbed through.
    let renewed_notify = Arc::new(tokio::sync::Notify::new());
    let _renewal_handle = policy_node_agent::controller_client::renewal::spawn(
        policy_node_agent::controller_client::renewal::RenewalConfig {
            management_url: config.controller_url.clone(),
            ca_cert_path: config.ca_cert_path.clone(),
            client_cert_path: config.client_cert_path.clone(),
            client_key_path: config.client_key_path.clone(),
            mtls_key_rotation_renewals: config.mtls_key_rotation_renewals,
            check_interval: std::time::Duration::from_secs(config.renewal_check_interval_secs),
            node_id: identity.node_id(),
            renewed_notify: Arc::clone(&renewed_notify),
            counter_path: config.renewal_counter_path.clone(),
        },
    );

    // ── Management stream (reconnect loop) ──────────────────────────────────────
    log::info!("Starting management stream loop");
    let mut reconnect_delay = RECONNECT_DELAY_INITIAL;
    // Mutable so we can re-load from disk after a successful renewal swaps
    // the cert (and possibly key) underneath us.
    let mut creds = creds;
    loop {
        let stream_fut = run_management_stream(
            &config.controller_url,
            &creds,
            Arc::clone(&identity),
            Arc::clone(&applier),
            config.local_server_url.clone(),
            Arc::clone(&net_info),
            Arc::clone(&sys_info),
            &config.interface_blocklist,
            std::time::Duration::from_secs(config.metrics_interval_secs),
            Arc::clone(&change_detector),
        );

        // Race the stream against the renewal-notify signal. When the
        // renewal task fires the notify, we drop the in-flight stream
        // future, re-load creds from disk, and reconnect with the new cert.
        // Without this the existing tonic channel happily keeps using the
        // *old* cert until it dies naturally — fine in prod, fatal on a
        // 60s-TTL test where the controller revokes the old serial as soon
        // as renewal completes.
        let outcome = tokio::select! {
            r = stream_fut => StreamOutcome::Finished(r),
            _ = renewed_notify.notified() => StreamOutcome::RenewedReconnect,
        };

        match outcome {
            StreamOutcome::Finished(Ok(())) => {
                log::info!(
                    "Management stream closed cleanly, reconnecting in {}s",
                    reconnect_delay.as_secs()
                );
                // Reset backoff on a clean close — the controller is reachable.
                reconnect_delay = RECONNECT_DELAY_INITIAL;
            }
            StreamOutcome::Finished(Err(e)) => {
                log::warn!(
                    "Management stream error: {:#}. Reconnecting in {}s",
                    e,
                    reconnect_delay.as_secs()
                );
            }
            StreamOutcome::RenewedReconnect => {
                log::info!("Cert renewed; reconnecting management stream with new credentials");
                // Skip the backoff sleep — this is a healthy reconnect, not
                // a failure recovery. Reload creds from disk so the new
                // cert (and key, on rotation) is used.
                reconnect_delay = RECONNECT_DELAY_INITIAL;
                match EnrolledCredentials::load(
                    &config.client_key_path,
                    &config.client_cert_path,
                    &config.ca_cert_path,
                ) {
                    Ok(c) => {
                        creds = c;
                        continue;
                    }
                    Err(e) => {
                        // Falling back to the old creds keeps the agent
                        // reachable; the next renewal tick will retry the
                        // file load.
                        log::error!(
                            "Failed to reload credentials after renewal — \
                             keeping previous creds in memory: {:#}",
                            e
                        );
                    }
                }
            }
        }

        // Check for Ctrl-C before waiting.
        tokio::select! {
            _ = sleep(reconnect_delay) => {}
            _ = tokio::signal::ctrl_c() => {
                log::info!("Shutting down");
                return Ok(());
            }
        }

        // Exponential backoff, capped at RECONNECT_DELAY_MAX.
        reconnect_delay = (reconnect_delay * 2).min(RECONNECT_DELAY_MAX);
    }
}

enum StreamOutcome {
    Finished(Result<()>),
    RenewedReconnect,
}

#[allow(clippy::too_many_arguments)]
async fn run_management_stream(
    management_url: &str,
    creds: &EnrolledCredentials,
    identity: Arc<dyn policy_node_agent::identity::NodeIdentity>,
    applier: Arc<ConfigApplier>,
    local_server_graphql_url: String,
    net_info: Arc<SystemNetworkInfo>,
    sys_info: Arc<RealSystemInfo>,
    interface_blocklist: &[String],
    metrics_interval: std::time::Duration,
    change_detector: Arc<dyn ChangeDetector>,
) -> Result<()> {
    let stream = controller_client::connect(
        management_url.to_string(),
        &creds.ca_cert_pem,
        &creds.cert_pem,
        &creds.key_pem,
    )
    .await
    .context("Failed to connect to management service")?;

    controller_client::run_stream_loop(
        stream,
        identity.as_ref(),
        AGENT_VERSION,
        Some(applier),
        Some(local_server_graphql_url),
        Some(net_info.as_ref()),
        Some(sys_info.as_ref()),
        interface_blocklist,
        metrics_interval,
        Some(change_detector),
    )
    .await
}
