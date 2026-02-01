// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Multi-tenant scoping primitive.
//!
//! Per the design doc, every event-pipeline DB call MUST go through
//! [`TenantScope`] — raw `SqlitePool` access in handler code is forbidden.
//! The wrapper is structural; today it always resolves to the singleton
//! `default` tenant, but the type signature blocks accidental cross-tenant
//! leakage once auth grows real tenant resolution.

use anyhow::{Context, Result};
use sqlx::{sqlite::SqlitePool, Row};

pub const DEFAULT_TENANT_SLUG: &str = "default";

/// A `SqlitePool` plus the tenant ID every query against the new event
/// tables must be filtered by.
#[derive(Clone, Debug)]
pub struct TenantScope {
    pool: SqlitePool,
    tenant_id: i64,
    slug: String,
}

impl TenantScope {
    pub fn new(pool: SqlitePool, tenant_id: i64, slug: impl Into<String>) -> Self {
        Self {
            pool,
            tenant_id,
            slug: slug.into(),
        }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn tenant_id(&self) -> i64 {
        self.tenant_id
    }

    pub fn slug(&self) -> &str {
        &self.slug
    }

    /// Return a new scope pointing at the same pool but bound to the
    /// caller's tenant. Used by GraphQL resolvers to switch from the
    /// schema-level singleton scope (which is just a pool carrier) to a
    /// per-request scope derived from the request's [`Principal`]. No DB
    /// hit — the slug is already on the principal.
    pub fn for_principal(&self, principal: &crate::rbac::Principal) -> TenantScope {
        TenantScope {
            pool: self.pool.clone(),
            tenant_id: principal.tenant_id,
            slug: principal.tenant_slug.clone(),
        }
    }
}

/// Look up the singleton `default` tenant (inserted by migration 0002) and
/// return a scope wrapping it. Call once at startup.
pub async fn bootstrap_default_tenant(pool: SqlitePool) -> Result<TenantScope> {
    let row = sqlx::query("SELECT id FROM tenants WHERE slug = ?")
        .bind(DEFAULT_TENANT_SLUG)
        .fetch_optional(&pool)
        .await
        .context("Failed to query default tenant")?;

    let id: i64 = match row {
        Some(r) => r.try_get("id")?,
        None => {
            // Migration didn't seed (shouldn't happen) — create it.
            let now = chrono::Utc::now().timestamp();
            sqlx::query(
                "INSERT INTO tenants (slug, name, retention_s, created_at) \
                 VALUES (?, ?, 604800, ?)",
            )
            .bind(DEFAULT_TENANT_SLUG)
            .bind("Default Tenant")
            .bind(now)
            .execute(&pool)
            .await
            .context("Failed to insert default tenant")?;
            sqlx::query("SELECT id FROM tenants WHERE slug = ?")
                .bind(DEFAULT_TENANT_SLUG)
                .fetch_one(&pool)
                .await?
                .try_get("id")?
        }
    };

    Ok(TenantScope::new(pool, id, DEFAULT_TENANT_SLUG))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn bootstrap_returns_default_tenant() {
        let pool = fresh_pool().await;
        let scope = bootstrap_default_tenant(pool).await.unwrap();
        assert_eq!(scope.slug(), DEFAULT_TENANT_SLUG);
        assert!(scope.tenant_id() > 0);
    }

    #[tokio::test]
    async fn bootstrap_is_idempotent() {
        let pool = fresh_pool().await;
        let a = bootstrap_default_tenant(pool.clone()).await.unwrap();
        let b = bootstrap_default_tenant(pool).await.unwrap();
        assert_eq!(a.tenant_id(), b.tenant_id());
    }
}
