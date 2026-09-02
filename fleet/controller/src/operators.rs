// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Operator accounts for controller-web.
//!
//! See `docs/login-flow.md` for the end-to-end flow. This module owns the
//! `operators` table: create, find-by-username, password verification, and
//! `last_login_at` bookkeeping. It does **not** mint session tokens — that
//! is the login endpoint's job (`api_tokens::ApiTokenStore::create_session`).
//!
//! Password hashing is argon2id with the `argon2` crate's default params.
//! The full PHC string is stored, so cost can be retuned without a
//! migration: future verifies still work against historical hashes, and
//! re-hashing on next successful login is the upgrade path.

use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params,
};
use sqlx::{Row, SqlitePool};

/// Default session lifetime when the login endpoint mints a session token.
/// 12 hours is long enough that a working day doesn't get interrupted and
/// short enough that an unattended browser doesn't stay logged in indefinitely.
/// Operators can revoke earlier via logout.
pub const SESSION_TTL_S: i64 = 12 * 3600;

#[derive(Debug, Clone)]
pub struct Operator {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    pub disabled_at: Option<i64>,
}

#[derive(Clone)]
pub struct OperatorStore {
    pool: SqlitePool,
}

impl OperatorStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a new operator. Returns the persisted row. Fails on duplicate
    /// username or empty inputs.
    pub async fn create(&self, username: &str, password: &str) -> Result<Operator> {
        let username = username.trim();
        if username.is_empty() {
            anyhow::bail!("username cannot be empty");
        }
        if password.len() < 8 {
            anyhow::bail!("password must be at least 8 characters");
        }

        let hash = hash_password(password)?;
        let created_at = now_s();

        let row = sqlx::query(
            r#"
            INSERT INTO operators (username, password_hash, created_at)
            VALUES (?, ?, ?)
            RETURNING id, username, created_at, last_login_at, disabled_at
            "#,
        )
        .bind(username)
        .bind(&hash)
        .bind(created_at)
        .fetch_one(&self.pool)
        .await
        .context("insert operator")?;

        row_to_operator(&row)
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<Operator>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, created_at, last_login_at, disabled_at
            FROM operators
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .context("find operator by username")?;

        row.as_ref().map(row_to_operator).transpose()
    }

    /// Authenticate `(username, password)`. Returns the operator on success,
    /// `Ok(None)` on any failure (unknown user, bad password, disabled
    /// account) — callers MUST treat all failures identically to avoid
    /// user-enumeration. DB errors propagate.
    pub async fn verify_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<Operator>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, created_at, last_login_at, disabled_at
            FROM operators
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .context("load operator for verify")?;

        let Some(row) = row else {
            // Still run a dummy verify to keep timing similar to the hit
            // path. Argon2id is ~50ms; skipping it leaks "user not found".
            let _ = Argon2::default().verify_password(
                password.as_bytes(),
                &PasswordHash::new(DUMMY_HASH).expect("dummy hash is well-formed"),
            );
            return Ok(None);
        };

        let stored: String = row.try_get("password_hash")?;
        let parsed = PasswordHash::new(&stored)
            .map_err(|e| anyhow::anyhow!("malformed stored hash for {username}: {e}"))?;
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        if !ok {
            return Ok(None);
        }

        let operator = row_to_operator(&row)?;
        if operator.disabled_at.is_some() {
            return Ok(None);
        }

        // Re-hash if the stored params are outdated (cost tuning path).
        // Non-fatal — a failure here never prevents a successful login.
        if hash_is_stale(&parsed) {
            if let Ok(new_hash) = hash_password(password) {
                let _ = sqlx::query(
                    "UPDATE operators SET password_hash = ? WHERE id = ?",
                )
                .bind(&new_hash)
                .bind(operator.id)
                .execute(&self.pool)
                .await;
            }
        }

        Ok(Some(operator))
    }

    /// List all operators, oldest first. Operators are global (no tenant
    /// column on the table) — tenant scoping comes from their role grants.
    pub async fn list(&self) -> Result<Vec<Operator>> {
        let rows = sqlx::query(
            r#"
            SELECT id, username, created_at, last_login_at, disabled_at
            FROM operators
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("list operators")?;
        rows.iter().map(row_to_operator).collect()
    }

    pub async fn find_by_id(&self, id: i64) -> Result<Option<Operator>> {
        let row = sqlx::query(
            r#"
            SELECT id, username, created_at, last_login_at, disabled_at
            FROM operators
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("find operator by id")?;
        row.as_ref().map(row_to_operator).transpose()
    }

    /// Disable an operator. Idempotent: a no-op if already disabled (keeps
    /// the original `disabled_at` so the audit trail stays meaningful).
    pub async fn disable(&self, id: i64, now: i64) -> Result<()> {
        sqlx::query("UPDATE operators SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("disable operator")?;
        Ok(())
    }

    /// Re-enable a previously disabled operator. Idempotent.
    pub async fn enable(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE operators SET disabled_at = NULL WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("enable operator")?;
        Ok(())
    }

    /// Replace the operator's password. Existing sessions stay valid until
    /// they expire on their own — callers that need immediate logout should
    /// revoke session tokens directly.
    pub async fn set_password(&self, id: i64, new_password: &str) -> Result<()> {
        if new_password.len() < 8 {
            anyhow::bail!("password must be at least 8 characters");
        }
        let hash = hash_password(new_password)?;
        sqlx::query("UPDATE operators SET password_hash = ? WHERE id = ?")
            .bind(&hash)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("set operator password")?;
        Ok(())
    }

    pub async fn touch_last_login(&self, id: i64, now: i64) -> Result<()> {
        sqlx::query("UPDATE operators SET last_login_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("touch operator last_login_at")?;
        Ok(())
    }
}

/// True when the stored PHC hash should be upgraded on the next successful
/// login — wrong algorithm or params that differ from the current defaults.
fn hash_is_stale(parsed: &PasswordHash<'_>) -> bool {
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return true;
    }
    let current = Params::default();
    // ParamsString::to_string() yields the comma-separated PHC params section
    // ("m=19456,t=2,p=1").  Parse the three fields we care about directly.
    let s = parsed.params.to_string();
    let get = |key: &str| -> Option<u32> {
        s.split(',').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == key { v.parse().ok() } else { None }
        })
    };
    match (get("m"), get("t"), get("p")) {
        (Some(m), Some(t), Some(p)) => {
            m != current.m_cost() || t != current.t_cost() || p != current.p_cost()
        }
        _ => true,
    }
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))
}

fn row_to_operator(row: &sqlx::sqlite::SqliteRow) -> Result<Operator> {
    Ok(Operator {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        created_at: row.try_get("created_at")?,
        last_login_at: row.try_get("last_login_at")?,
        disabled_at: row.try_get("disabled_at")?,
    })
}

fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Pre-computed argon2id hash of the empty string, used to keep the
/// "user not found" path running argon2 so it doesn't return faster than
/// the "user found, wrong password" path. Value is irrelevant — only the
/// time spent in `verify_password` matters.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$rj3iA9hxYsNvz5dXyKMaTQ";

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn create_then_verify_roundtrip() {
        let store = OperatorStore::new(pool().await);
        let op = store.create("alice", "correct horse").await.unwrap();
        assert_eq!(op.username, "alice");
        assert!(op.last_login_at.is_none());

        let found = store
            .verify_password("alice", "correct horse")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, op.id);
    }

    #[tokio::test]
    async fn wrong_password_rejected() {
        let store = OperatorStore::new(pool().await);
        store.create("alice", "correct horse").await.unwrap();
        assert!(store
            .verify_password("alice", "wrong")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn unknown_user_returns_none() {
        let store = OperatorStore::new(pool().await);
        assert!(store
            .verify_password("nobody", "anything")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn duplicate_username_rejected() {
        let store = OperatorStore::new(pool().await);
        store.create("alice", "correct horse").await.unwrap();
        assert!(store.create("alice", "different").await.is_err());
    }

    #[tokio::test]
    async fn short_password_rejected() {
        let store = OperatorStore::new(pool().await);
        assert!(store.create("alice", "short").await.is_err());
    }

    #[tokio::test]
    async fn empty_username_rejected() {
        let store = OperatorStore::new(pool().await);
        assert!(store.create("   ", "long-enough").await.is_err());
    }

    #[tokio::test]
    async fn touch_last_login_updates() {
        let store = OperatorStore::new(pool().await);
        let op = store.create("alice", "correct horse").await.unwrap();
        store.touch_last_login(op.id, 1234).await.unwrap();
        let again = store.find_by_username("alice").await.unwrap().unwrap();
        assert_eq!(again.last_login_at, Some(1234));
    }

    #[tokio::test]
    async fn disabled_account_cannot_log_in() {
        let store = OperatorStore::new(pool().await);
        let op = store.create("alice", "correct horse").await.unwrap();
        sqlx::query("UPDATE operators SET disabled_at = ? WHERE id = ?")
            .bind(now_s())
            .bind(op.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store
            .verify_password("alice", "correct horse")
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn dummy_hash_is_well_formed() {
        PasswordHash::new(DUMMY_HASH).expect("dummy hash must parse");
    }

    #[tokio::test]
    async fn stale_hash_upgraded_on_successful_verify() {
        let pool = pool().await;
        let store = OperatorStore::new(pool.clone());

        // Hash with deliberately cheap params so they differ from Argon2::default().
        let cheap = Argon2::new(
            Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(8 * 1024, 1, 1, None).unwrap(),
        );
        let salt = SaltString::generate(&mut OsRng);
        let cheap_hash = cheap.hash_password(b"mypassword", &salt).unwrap().to_string();

        sqlx::query(
            "INSERT INTO operators (username, password_hash, created_at) VALUES ('upgtest', ?, 0)",
        )
        .bind(&cheap_hash)
        .execute(&pool)
        .await
        .unwrap();

        let op = store
            .verify_password("upgtest", "mypassword")
            .await
            .unwrap()
            .unwrap();

        let new_hash: String =
            sqlx::query_scalar("SELECT password_hash FROM operators WHERE id = ?")
                .bind(op.id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_ne!(new_hash, cheap_hash, "stored hash must be upgraded after verify");

        // Upgraded hash must still accept the original password.
        assert!(
            store.verify_password("upgtest", "mypassword").await.unwrap().is_some(),
            "upgraded hash must still verify"
        );
    }

    #[test]
    fn hash_is_stale_detects_wrong_algorithm() {
        // argon2d is not our preferred algorithm.
        let hash_str = "$argon2d$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$rj3iA9hxYsNvz5dXyKMaTQ";
        let parsed = PasswordHash::new(hash_str).unwrap();
        assert!(hash_is_stale(&parsed));
    }

    #[test]
    fn hash_is_stale_detects_low_cost() {
        // m_cost=8192 is well below the argon2 default of 19456.
        let cheap = Argon2::new(
            Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(8 * 1024, 1, 1, None).unwrap(),
        );
        let salt = SaltString::generate(&mut OsRng);
        let h = cheap.hash_password(b"x", &salt).unwrap().to_string();
        let parsed = PasswordHash::new(&h).unwrap();
        assert!(hash_is_stale(&parsed));
    }

    #[test]
    fn hash_is_stale_accepts_current_defaults() {
        let salt = SaltString::generate(&mut OsRng);
        let h = Argon2::default().hash_password(b"x", &salt).unwrap().to_string();
        let parsed = PasswordHash::new(&h).unwrap();
        assert!(!hash_is_stale(&parsed));
    }
}
