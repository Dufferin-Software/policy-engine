// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Create an operator account for controller-web login.
//!
//! Usage:
//!
//!   policy-controller-add-operator --username alice
//!     (prompts twice for the password on a TTY)
//!
//!   policy-controller-add-operator --username alice --password-file pw.txt
//!     (reads the password from the given file; first line, trailing newline stripped)
//!
//! Same trust model as `policy-controller-mint-token`: opens the SQLite DB
//! directly. Anyone with fs access to the DB can already read every event
//! and mint tokens, so adding an operator from the same path does not
//! widen the boundary.
//!
//! See `docs/login-flow.md` for the full operator-auth flow.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::Parser;
use policy_controller::{
    operators::OperatorStore,
    rbac::{BuiltInRole, RbacStore},
};
use sqlx::sqlite::SqlitePool;

#[derive(Parser)]
#[command(
    name = "policy-controller-add-operator",
    about = "Create a controller-web operator account (argon2id-hashed password)"
)]
struct Cli {
    /// Path to the controller SQLite database.
    #[arg(long, default_value = "/var/lib/policy-controller/controller.db")]
    db: PathBuf,

    /// Operator username (unique).
    #[arg(long)]
    username: String,

    /// Read password from a file instead of prompting. Useful for
    /// automation; the first line is taken, trailing newline stripped.
    /// Beware shell-history / file-mode leakage.
    #[arg(long)]
    password_file: Option<PathBuf>,

    /// Built-in role to grant the new operator. Repeatable. Names match
    /// `rbac::BuiltInRole::as_str` — admin, operator, viewer,
    /// security-admin, auditor, service. Defaults to `admin` so a fresh
    /// deploy has a working privileged account; pass `--role viewer`
    /// (or any other role, possibly multiple times) for less-privileged
    /// accounts.
    #[arg(long = "role", default_values_t = vec!["admin".to_string()])]
    roles: Vec<String>,

    /// Tenant id to attach the role grants in. Defaults to 1 ('default').
    #[arg(long, default_value_t = 1)]
    tenant_id: i64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    let password = match &cli.password_file {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read password file {}", path.display()))?;
            raw.lines().next().unwrap_or("").to_string()
        }
        None => {
            let first =
                rpassword::prompt_password("Password: ").context("read password from tty")?;
            let confirm =
                rpassword::prompt_password("Confirm: ").context("read password from tty")?;
            if first != confirm {
                anyhow::bail!("passwords did not match");
            }
            first
        }
    };

    ensure_db_dir(&cli.db)?;
    let url = format!("sqlite://{}?mode=rwc", cli.db.display());
    let pool = SqlitePool::connect(&url)
        .await
        .with_context(|| format!("open DB at {}", cli.db.display()))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("run migrations")?;

    let store = OperatorStore::new(pool.clone());
    let op = store
        .create(&cli.username, &password)
        .await
        .context("create operator")?;

    // Resolve role names to built-ins so we fail fast on typos before we
    // touch the DB again. Custom roles are intentionally not accepted
    // here — operator bootstrap is a CLI convenience; non-built-in
    // grants go through the IAM GraphQL surface.
    let role_enums: Vec<BuiltInRole> = cli
        .roles
        .iter()
        .map(|n| parse_builtin(n))
        .collect::<Result<_>>()?;

    let rbac = RbacStore::new(pool);
    let now = now_s();
    let mut granted = Vec::with_capacity(role_enums.len());
    for role in &role_enums {
        let role_id = rbac
            .builtin_role_id(cli.tenant_id, *role)
            .await
            .with_context(|| format!("look up role `{}`", role.as_str()))?;
        rbac.grant_role(op.id, role_id, None, now)
            .await
            .with_context(|| format!("grant role `{}`", role.as_str()))?;
        granted.push(role.as_str());
    }

    eprintln!(
        "Operator \"{}\" created (id={}) with roles [{}]. They can now log in at /login.",
        op.username,
        op.id,
        granted.join(", ")
    );
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

fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Create the parent directory for `db` if needed. EEXIST is **not** an
/// error — the systemd `StateDirectory=` setup installs
/// `/var/lib/policy-controller` as a symlink into `/var/lib/private/`,
/// which is mode 700 root. `create_dir_all` follows the symlink, can't
/// stat the target as a non-root caller, then calls `mkdir(symlink)`
/// and gets EEXIST. Depending on which internal step failed, std may
/// surface this with `ErrorKind::AlreadyExists`, `PermissionDenied`, or
/// `Uncategorized` — so we also match on raw errno 17. Treat that as
/// success and let `SqlitePool::connect` surface the real failure if
/// there is one.
fn ensure_db_dir(db: &Path) -> Result<()> {
    let Some(parent) = db.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    match std::fs::create_dir_all(parent) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists || e.raw_os_error() == Some(17) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("create DB directory {}", parent.display())),
    }
}
