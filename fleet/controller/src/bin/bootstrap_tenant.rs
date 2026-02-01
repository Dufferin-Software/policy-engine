// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Provision a new tenant on the controller.
//!
//! Usage:
//!
//!   policy-controller-bootstrap-tenant --slug acme --name "Acme Corp"
//!
//! Inserts a row in `tenants` (or reuses an existing slug) and seeds the
//! six built-in roles via [`rbac::bootstrap_tenant`]. Idempotent: re-runs
//! with the same slug are no-ops and exit 0.
//!
//! Prints the numeric tenant id to stdout on its own line so callers can
//! pipe it into `policy-controller-mint-token --tenant-id $(…)`. Stderr
//! carries the human-readable confirmation.
//!
//! Trust model matches `mint-token` / `add-operator`: opens the SQLite DB
//! directly. Filesystem access to the DB is already a full break.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use policy_controller::rbac;
use sqlx::sqlite::SqlitePool;

#[derive(Parser)]
#[command(
    name = "policy-controller-bootstrap-tenant",
    about = "Create a tenant and seed its built-in roles"
)]
struct Cli {
    /// Path to the controller SQLite database.
    #[arg(long, default_value = "/var/lib/policy-controller/controller.db")]
    db: PathBuf,

    /// Stable identifier used by tenant-aware code paths (nodes.tenant_id,
    /// rules.tenant_id, audit_log.tenant_id — all TEXT slugs).
    #[arg(long)]
    slug: String,

    /// Human-readable display name.
    #[arg(long)]
    name: String,

    /// Per-tenant event retention in seconds.
    #[arg(long, default_value_t = 604800)]
    retention_s: i64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    ensure_db_dir(&cli.db)?;
    let url = format!("sqlite://{}?mode=rwc", cli.db.display());
    let pool = SqlitePool::connect(&url)
        .await
        .with_context(|| format!("open DB at {}", cli.db.display()))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("run migrations")?;

    let now = now_s();

    // INSERT OR IGNORE then SELECT keeps the bin idempotent across reruns:
    // a duplicate slug is a no-op, not an error.
    sqlx::query(
        "INSERT OR IGNORE INTO tenants (slug, name, retention_s, created_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(&cli.slug)
    .bind(&cli.name)
    .bind(cli.retention_s)
    .bind(now)
    .execute(&pool)
    .await
    .context("insert tenant row")?;

    let tenant_id: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = ?")
        .bind(&cli.slug)
        .fetch_one(&pool)
        .await
        .context("resolve tenant id by slug")?;

    rbac::bootstrap_tenant(&pool, tenant_id, now)
        .await
        .context("seed built-in roles")?;

    println!("{}", tenant_id);
    eprintln!(
        "Tenant \"{}\" (slug={}) ready with id {} and the six built-in roles.",
        cli.name, cli.slug, tenant_id
    );
    Ok(())
}

/// Create the parent directory for `db` if needed. EEXIST is tolerated —
/// `/var/lib/policy-controller` is a `StateDirectory=` symlink the caller
/// can't traverse, so `create_dir_all` falls through to `mkdir(symlink)`
/// and gets EEXIST. (See `mint_token.rs` for the same dance.)
fn ensure_db_dir(db: &Path) -> Result<()> {
    let Some(parent) = db.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    match std::fs::create_dir_all(parent) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("create DB directory {}", parent.display())),
    }
}

fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
