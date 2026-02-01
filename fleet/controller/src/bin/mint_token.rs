// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Mint a bearer token for the controller's REST + GraphQL surface.
//!
//! Usage:
//!
//!   policy-controller-mint-token --name grafana-prod
//!   policy-controller-mint-token --name short-lived --expires-in 86400
//!
//! Opens the SQLite database directly. Trust model matches the existing
//! ZTP enrollment-token flow: anyone with filesystem access to the DB can
//! already read every event, so a tool that mints credentials from the same
//! path does not widen the boundary.
//!
//! The plaintext token is printed to **stdout** on its own line so it can be
//! captured via `$(policy-controller-mint-token --name grafana-prod)`.
//! Stderr carries the human-readable confirmation. The token cannot be
//! retrieved later — copy it now.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use policy_controller::{
    api_tokens::ApiTokenStore,
    rbac::{BuiltInRole, RbacStore},
};
use sqlx::sqlite::SqlitePool;

#[derive(Parser)]
#[command(
    name = "policy-controller-mint-token",
    about = "Mint a bearer token for the controller REST + GraphQL surface"
)]
struct Cli {
    /// Path to the controller SQLite database.
    #[arg(long, default_value = "/var/lib/policy-controller/controller.db")]
    db: PathBuf,

    /// Operator-facing label for the token (must be unique).
    #[arg(long)]
    name: String,

    /// Optional expiry, in seconds from now. If unset, the token does not
    /// expire and must be revoked explicitly.
    #[arg(long)]
    expires_in: Option<i64>,

    /// Built-in role to bind on the new token. Repeatable. Names match
    /// `rbac::BuiltInRole::as_str` — admin, operator, viewer,
    /// security-admin, auditor, service. Defaults to **no roles** — a
    /// freshly minted static token has zero permissions until the caller
    /// explicitly opts in. This is intentionally stricter than
    /// `add-operator` (which defaults to admin) because static tokens are
    /// higher blast-radius than human accounts.
    #[arg(long = "role")]
    roles: Vec<String>,

    /// Tenant id to look up the role names in. Defaults to 1 ('default').
    #[arg(long, default_value_t = 1)]
    tenant_id: i64,
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

    // Resolve role names up-front so a typo fails before we mint anything.
    let role_enums: Vec<BuiltInRole> = cli
        .roles
        .iter()
        .map(|n| parse_builtin(n))
        .collect::<Result<_>>()?;

    let expires_at = cli.expires_in.map(|secs| now_s() + secs);
    let store = ApiTokenStore::new(pool.clone());
    let (row, plaintext) = store
        .create(&cli.name, cli.tenant_id, expires_at, Some("mint-token-bin"))
        .await
        .context("mint token")?;

    let rbac = RbacStore::new(pool);
    let mut role_ids = Vec::with_capacity(role_enums.len());
    for role in &role_enums {
        let rid = rbac
            .builtin_role_id(cli.tenant_id, *role)
            .await
            .with_context(|| format!("look up role `{}`", role.as_str()))?;
        role_ids.push(rid);
    }
    if !role_ids.is_empty() {
        rbac.set_token_roles(row.id, &role_ids)
            .await
            .context("bind token roles")?;
    }

    println!("{}", plaintext);
    let role_summary = if role_enums.is_empty() {
        "no roles — token has zero permissions until granted via IAM".to_string()
    } else {
        format!(
            "roles [{}]",
            role_enums
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    eprintln!(
        "Token \"{}\" created (id={}) with {}. Copy it now — it cannot be retrieved later.",
        row.name, row.id, role_summary
    );
    if let Some(exp) = row.expires_at {
        eprintln!("Expires at unix timestamp {}.", exp);
    }
    Ok(())
}

fn parse_builtin(name: &str) -> Result<BuiltInRole> {
    for r in BuiltInRole::all() {
        if r.as_str() == name {
            return Ok(*r);
        }
    }
    anyhow::bail!(
        "unknown role `{name}` (expected one of: {})",
        BuiltInRole::all()
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Create the parent directory for `db` if needed. EEXIST is **not** an
/// error — `/var/lib/policy-controller` is a `StateDirectory=` symlink
/// into `/var/lib/private/`, which a non-root caller can't traverse, so
/// `create_dir_all` falls through to `mkdir(symlink)` and gets EEXIST.
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
