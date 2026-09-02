// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Policy Engine Server binary
//!
//! GraphQL API server for managing policy rules.
//! Use the separate policy-client binary for CLI operations.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::Parser;

use policy_engine::config::{compute_affinity_plan, ConfigProvider, FileConfigProvider};
use policy_engine::server::cpu_affinity;
use policy_engine::server::{resolve_server_config, run_server, CliOverrides};

/// Policy Engine Server
#[derive(Parser)]
#[command(name = "policy-engine")]
#[command(
    author,
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("PE_BUILD_INFO"), ")"),
    about = "Policy Engine GraphQL Server"
)]
struct Args {
    /// Host address to bind to (overrides config file; default: 127.0.0.1)
    #[arg(short = 'H', long)]
    host: Option<String>,

    /// Port to listen on (overrides config file; default: 8080)
    #[arg(short, long)]
    port: Option<u16>,

    /// Path to web UI static assets (auto-detected from /usr/share/policy-engine-web if installed)
    #[arg(long)]
    web_root: Option<String>,

    /// Path to TLS certificate file (PEM format, may include full chain).
    /// Must be provided together with --tls-key to enable HTTPS.
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key file (PEM format, RSA/EC/PKCS8).
    /// Must be provided together with --tls-cert to enable HTTPS.
    #[arg(long)]
    tls_key: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_default_env()
        .format_timestamp(None)
        .init();

    // Install a process-default rustls CryptoProvider before any TLS is set up.
    // The dependency tree compiles rustls 0.23 with both the `aws-lc-rs` and
    // `ring` providers enabled (the `ring` feature is pulled in workspace-wide
    // via lettre in the controller), so rustls cannot auto-select one and
    // `ServerConfig::builder()` would panic at HTTPS bind time. Pick `ring`
    // explicitly, matching the fleet controller/agent binaries.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    let provider = FileConfigProvider::default();
    let cfg = provider.load();
    let total = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let affinity = Arc::new(compute_affinity_plan(&cfg.affinity, total));

    log::info!(
        "CPU affinity: control={:?} event={:?} dataplane={:?} actix_workers={} disabled={}",
        affinity.control_cpus,
        affinity.event_cpus,
        affinity.dataplane_cpus,
        affinity.actix_workers,
        affinity.disabled,
    );

    let cpus = affinity.control_cpus.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    let pin_disabled = affinity.disabled;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(affinity.control_cpus.len().max(1))
        .on_thread_start(move || {
            if !pin_disabled {
                let idx = counter.fetch_add(1, Ordering::Relaxed);
                cpu_affinity::pin_thread_by_index(&cpus, idx);
            }
        })
        .enable_all()
        .build()
        .map_err(|e| anyhow!("Failed to build Tokio runtime: {e}"))?;

    let overrides = CliOverrides {
        host: args.host,
        port: args.port,
        web_root: args.web_root,
        tls_cert: args.tls_cert,
        tls_key: args.tls_key,
    };
    let server_config = resolve_server_config(&provider, overrides, affinity);

    let tls_enabled = server_config.tls_cert.is_some();
    let scheme = if tls_enabled { "https" } else { "http" };

    println!("Starting Policy Engine GraphQL Server...");
    println!("Host: {}", server_config.host);
    println!("Port: {}", server_config.port);
    println!();
    println!(
        "GraphQL Playground: {}://{}:{}/playground",
        scheme, server_config.host, server_config.port
    );
    println!(
        "GraphQL Endpoint:   {}://{}:{}/graphql",
        scheme, server_config.host, server_config.port
    );
    println!(
        "Health Check:       {}://{}:{}/health",
        scheme, server_config.host, server_config.port
    );
    println!();

    runtime.block_on(async {
        run_server(server_config)
            .await
            .map_err(|e| anyhow!("Server error: {e}"))
    })
}
