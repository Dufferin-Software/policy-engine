// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Bearer tokens for the REST + GraphQL surface (Grafana et al).
//!
//! The plaintext is shown once at creation and never persisted; the DB only
//! holds `sha256(plaintext)`. Same hash-at-rest pattern as
//! `node_registry::tokens` (enrollment tokens).

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};

const TOKEN_PREFIX: &str = "dsw_";
const TOKEN_SECRET_BYTES: usize = 32;

/// Distinguishes long-lived static tokens (Grafana, scripts) from short-lived
/// session tokens minted by the login endpoint. Persisted as text in
/// `api_tokens.kind`; the schema CHECK constraint guards the column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Static,
    Session,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Static => "static",
            TokenKind::Session => "session",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "static" => Ok(TokenKind::Static),
            "session" => Ok(TokenKind::Session),
            other => anyhow::bail!("unknown token kind: {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub kind: TokenKind,
    pub created_at: i64,
    pub created_by: Option<String>,
    /// Numeric FK to the issuing operator. NULL for static tokens minted
    /// without an operator context (CLI bootstrap, automation). Drives the
    /// RBAC intersection rule — see `rbac::RbacStore::resolve`.
    pub operator_id: Option<i64>,
    /// Tenant the token operates within. Defaults to 1 ('default') for
    /// rows minted before multi-tenancy was wired in the UI.
    pub tenant_id: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Clone)]
pub struct ApiTokenStore {
    pool: SqlitePool,
}

impl ApiTokenStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Mint a static (long-lived) token. Returns the persisted row and the
    /// plaintext that must be shown to the operator exactly once.
    ///
    /// `tenant_id` binds the token to a single tenant. All subsequent
    /// requests carrying this bearer surface a `Principal` scoped to that
    /// tenant (see `auth.rs` and `RbacStore::resolve`).
    pub async fn create(
        &self,
        name: &str,
        tenant_id: i64,
        expires_at: Option<i64>,
        created_by: Option<&str>,
    ) -> Result<(ApiToken, String)> {
        self.create_kind(
            name,
            TokenKind::Static,
            tenant_id,
            expires_at,
            created_by,
            None,
        )
        .await
    }

    /// Mint a session token for the login endpoint. Always binds an
    /// `operator_id` so the RBAC intersection rule (token roles ∩ operator
    /// roles) applies on every request — disabling the operator drops the
    /// session to zero permissions on the next call.
    pub async fn create_session(
        &self,
        name: &str,
        tenant_id: i64,
        expires_at: i64,
        created_by: &str,
        operator_id: i64,
    ) -> Result<(ApiToken, String)> {
        self.create_kind(
            name,
            TokenKind::Session,
            tenant_id,
            Some(expires_at),
            Some(created_by),
            Some(operator_id),
        )
        .await
    }

    async fn create_kind(
        &self,
        name: &str,
        kind: TokenKind,
        tenant_id: i64,
        expires_at: Option<i64>,
        created_by: Option<&str>,
        operator_id: Option<i64>,
    ) -> Result<(ApiToken, String)> {
        if name.trim().is_empty() {
            anyhow::bail!("token name cannot be empty");
        }

        let (plaintext, hash) = mint();
        let created_at = now_s();

        let row = sqlx::query(
            r#"
            INSERT INTO api_tokens
                (name, token_hash, kind, created_at, created_by, operator_id, tenant_id, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id, name, kind, created_at, created_by, operator_id, tenant_id,
                     expires_at, revoked_at, last_used_at
            "#,
        )
        .bind(name)
        .bind(&hash[..])
        .bind(kind.as_str())
        .bind(created_at)
        .bind(created_by)
        .bind(operator_id)
        .bind(tenant_id)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .context("insert api_token")?;

        Ok((row_to_token(&row)?, plaintext))
    }

    /// List all tokens in `tenant_id`. Cross-tenant visibility is not
    /// supported on this surface — the GraphQL `apiTokens` resolver always
    /// passes the caller's `principal.tenant_id`. There is no admin
    /// "list every tenant's tokens" path; an admin needing that runs
    /// queries directly against the DB.
    pub async fn list(&self, tenant_id: i64) -> Result<Vec<ApiToken>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, kind, created_at, created_by, operator_id, tenant_id,
                   expires_at, revoked_at, last_used_at
            FROM api_tokens
            WHERE tenant_id = ?
            ORDER BY id ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .context("list api_tokens")?;

        rows.iter().map(row_to_token).collect()
    }

    /// Revoke a token only if it belongs to `tenant_id`. A mismatched
    /// tenant looks identical to "id not found" — we don't differentiate
    /// so a tenant A operator can't enumerate tenant B's token ids.
    pub async fn revoke(&self, id: i64, tenant_id: i64) -> Result<()> {
        let now = now_s();
        let res = sqlx::query(
            "UPDATE api_tokens SET revoked_at = ? \
             WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .context("revoke api_token")?;

        if res.rows_affected() == 0 {
            anyhow::bail!("token id {} not found or already revoked", id);
        }
        Ok(())
    }

    /// Hot path. Returns the row only when the token is known, not revoked,
    /// and not expired.
    pub async fn authenticate(&self, plaintext: &str) -> Result<Option<ApiToken>> {
        if !plaintext.starts_with(TOKEN_PREFIX) {
            return Ok(None);
        }
        let hash = Sha256::digest(plaintext.as_bytes()).to_vec();
        let now = now_s();

        let row = sqlx::query(
            r#"
            SELECT id, name, kind, created_at, created_by, operator_id, tenant_id,
                   expires_at, revoked_at, last_used_at
            FROM api_tokens
            WHERE token_hash = ?
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            "#,
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .context("authenticate api_token")?;

        row.as_ref().map(row_to_token).transpose()
    }

    /// Revoke the token whose plaintext matches. Used by `/api/v1/logout`,
    /// which has the caller's bearer in hand but not its row id.
    /// Returns `true` if a row was revoked, `false` if the token was already
    /// unknown / revoked / expired (logout should still succeed in those cases).
    pub async fn revoke_by_plaintext(&self, plaintext: &str) -> Result<bool> {
        if !plaintext.starts_with(TOKEN_PREFIX) {
            return Ok(false);
        }
        let hash = Sha256::digest(plaintext.as_bytes()).to_vec();
        let now = now_s();
        let res = sqlx::query(
            "UPDATE api_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(&hash)
        .execute(&self.pool)
        .await
        .context("revoke api_token by plaintext")?;
        Ok(res.rows_affected() > 0)
    }

    /// Bump `last_used_at`. The middleware throttles calls to this so we
    /// don't write on every request.
    pub async fn touch_last_used(&self, id: i64, now: i64) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("touch api_token last_used_at")?;
        Ok(())
    }
}

fn row_to_token(row: &sqlx::sqlite::SqliteRow) -> Result<ApiToken> {
    let kind_str: String = row.try_get("kind")?;
    Ok(ApiToken {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        kind: TokenKind::from_str(&kind_str)?,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
        operator_id: row.try_get("operator_id")?,
        tenant_id: row.try_get("tenant_id")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
        last_used_at: row.try_get("last_used_at")?,
    })
}

fn mint() -> (String, [u8; 32]) {
    let mut secret = [0u8; TOKEN_SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut secret);
    let plaintext = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(secret));
    let hash: [u8; 32] = Sha256::digest(plaintext.as_bytes()).into();
    (plaintext, hash)
}

fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    /// Create a second tenant row so tests can exercise cross-tenant
    /// isolation. The seed migration only inserts tenant 1.
    async fn seed_tenant(pool: &SqlitePool, slug: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "INSERT INTO tenants (slug, name, created_at) VALUES (?, ?, strftime('%s','now')) \
             RETURNING id",
        )
        .bind(slug)
        .bind(slug)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn create_then_authenticate_roundtrip() {
        let store = ApiTokenStore::new(pool().await);
        let (row, plaintext) = store.create("grafana", 1, None, None).await.unwrap();
        assert!(plaintext.starts_with(TOKEN_PREFIX));
        assert_eq!(row.name, "grafana");
        assert_eq!(row.tenant_id, 1);
        assert!(row.revoked_at.is_none());

        let got = store.authenticate(&plaintext).await.unwrap().unwrap();
        assert_eq!(got.id, row.id);
    }

    #[tokio::test]
    async fn unknown_token_returns_none() {
        let store = ApiTokenStore::new(pool().await);
        assert!(store.authenticate("dsw_garbage").await.unwrap().is_none());
        assert!(store.authenticate("not_our_token").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoked_token_is_rejected() {
        let store = ApiTokenStore::new(pool().await);
        let (row, plaintext) = store.create("grafana", 1, None, None).await.unwrap();
        store.revoke(row.id, 1).await.unwrap();
        assert!(store.authenticate(&plaintext).await.unwrap().is_none());
        assert!(store.revoke(row.id, 1).await.is_err());
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let store = ApiTokenStore::new(pool().await);
        let past = now_s() - 60;
        let (_row, plaintext) = store.create("grafana", 1, Some(past), None).await.unwrap();
        assert!(store.authenticate(&plaintext).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_name_is_rejected() {
        let store = ApiTokenStore::new(pool().await);
        store.create("grafana", 1, None, None).await.unwrap();
        assert!(store.create("grafana", 1, None, None).await.is_err());
    }

    #[tokio::test]
    async fn touch_last_used_updates_monotonically() {
        let store = ApiTokenStore::new(pool().await);
        let (row, _) = store.create("grafana", 1, None, None).await.unwrap();
        store.touch_last_used(row.id, 1000).await.unwrap();
        let listed = store.list(1).await.unwrap();
        assert_eq!(listed[0].last_used_at, Some(1000));
    }

    #[tokio::test]
    async fn list_filters_by_tenant() {
        let pool = pool().await;
        let other = seed_tenant(&pool, "acme").await;
        let store = ApiTokenStore::new(pool);

        store.create("default-token", 1, None, None).await.unwrap();
        store.create("acme-token", other, None, None).await.unwrap();

        let default = store.list(1).await.unwrap();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].name, "default-token");

        let acme = store.list(other).await.unwrap();
        assert_eq!(acme.len(), 1);
        assert_eq!(acme[0].name, "acme-token");
    }

    #[tokio::test]
    async fn revoke_rejects_other_tenant() {
        let pool = pool().await;
        let other = seed_tenant(&pool, "acme").await;
        let store = ApiTokenStore::new(pool);

        let (row, plaintext) = store.create("acme-token", other, None, None).await.unwrap();

        // Tenant 1 operator tries to revoke an acme-tenant token by id.
        assert!(
            store.revoke(row.id, 1).await.is_err(),
            "cross-tenant revoke must be rejected"
        );
        // The token is still live.
        assert!(store.authenticate(&plaintext).await.unwrap().is_some());

        // Same tenant revokes successfully.
        store.revoke(row.id, other).await.unwrap();
        assert!(store.authenticate(&plaintext).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mint_emits_distinct_tokens() {
        let (a, ha) = mint();
        let (b, hb) = mint();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
    }
}
