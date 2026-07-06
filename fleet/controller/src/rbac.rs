// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Role-based access control for the controller's REST + GraphQL surface.
//!
//! See `docs/rbac.md` for the design. In brief:
//!
//! * A [`Permission`] is a `resource:verb` pair. Verbs may contain hyphens
//!   (e.g. `event:read-payload`). The wildcard token is `*`.
//! * Six built-in roles are seeded per tenant in `migrations/0001_initial.sql`.
//!   Per-tenant seeding for tenants created at runtime goes through
//!   [`bootstrap_tenant`].
//! * A [`Principal`] is resolved once per request by the auth middleware
//!   and inserted into request extensions (and into the GraphQL request's
//!   per-execution data). Resolvers gate access with the [`Require`] guard.
//! * Effective permissions = (token's roles) ∩ (operator's roles, if any).
//!   The intersection means disabling an operator drops their active
//!   sessions to zero permissions without explicit revocation.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_graphql::{Context as GqlContext, Guard};
use sqlx::{Row, SqlitePool};

// ── Permission ──────────────────────────────────────────────────────────────

/// A `resource:verb` pair. Equality and hashing are case-sensitive on both
/// halves; callers normalise to lower-case at the boundary.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Permission {
    resource: String,
    verb: String,
}

impl Permission {
    /// Build a permission. Panics if the literal isn't valid `r:v`. Intended
    /// for `const`-style call sites inside guards; runtime input (from the
    /// DB) goes through [`Permission::parse`].
    pub fn new(s: &'static str) -> Self {
        Self::parse(s).expect("permission literal must be valid")
    }

    pub fn parse(s: &str) -> Result<Self> {
        let (r, v) = s
            .split_once(':')
            .with_context(|| format!("permission `{s}` missing ':' separator"))?;
        if r.is_empty() || v.is_empty() {
            anyhow::bail!("permission `{s}` has empty resource or verb");
        }
        Ok(Self {
            resource: r.to_string(),
            verb: v.to_string(),
        })
    }

    pub fn resource_str(&self) -> &str {
        &self.resource
    }

    pub fn verb_str(&self) -> &str {
        &self.verb
    }

    /// True when `self` (a grant from the DB) satisfies `required` (the
    /// guard literal). `*` matches in either position.
    pub fn satisfies(&self, required: &Permission) -> bool {
        let r_ok = self.resource == "*" || self.resource == required.resource;
        let v_ok = self.verb == "*" || self.verb == required.verb;
        r_ok && v_ok
    }
}

// ── Principal ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TokenScope {
    NodeId(String),
    NodeLabel(String),
}

/// Per-request identity + permissions. Built once by the auth middleware
/// and attached to (a) actix request extensions and (b) the GraphQL
/// request's per-execution data so resolvers can call `ctx.data::<Principal>()`.
#[derive(Debug, Clone)]
pub struct Principal {
    pub token_id: i64,
    pub operator_id: Option<i64>,
    pub tenant_id: i64,
    /// Stable text identifier for the tenant (e.g. `"default"`). Carried
    /// alongside the numeric id because legacy tables — `rules.tenant_id`,
    /// `audit_log.tenant_id`, `nodes.tenant_id` — store the slug instead of
    /// the FK. Populated by [`RbacStore::resolve`] from the `tenants` row.
    pub tenant_slug: String,
    /// Human-readable identity of the caller, for audit attribution.
    /// `operator:<username>` for a session token tied to an operator account,
    /// `token:<name>` for a static API token, or `token:<id>` as a last
    /// resort if the token row can't be named. Resolved once in
    /// [`RbacStore::resolve`]; never the bare literal `"operator"`.
    pub actor: String,
    permissions: HashSet<Permission>,
    pub scopes: Vec<TokenScope>,
}

impl Principal {
    /// Construct a wildcard-admin principal for unit tests. Only available
    /// when the crate is being compiled for `cargo test`, so production
    /// builds of `build_schema` cannot accidentally pick it up. Tests rely
    /// on this being attached at schema level by `build_schema` so that
    /// guarded resolvers don't reject all test executions.
    /// Build a Principal with the given pre-parsed permissions, for tests
    /// that need to exercise the guard with a non-wildcard set.
    #[cfg(test)]
    pub fn from_test_parts(permissions: HashSet<Permission>) -> Self {
        Self {
            token_id: 0,
            operator_id: None,
            tenant_id: 1,
            tenant_slug: "default".to_string(),
            actor: "token:test".to_string(),
            permissions,
            scopes: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn test_admin() -> Self {
        let mut perms = HashSet::new();
        perms.insert(Permission::new("*:*"));
        Self {
            token_id: 0,
            operator_id: None,
            tenant_id: 1,
            tenant_slug: "default".to_string(),
            actor: "operator:test-admin".to_string(),
            permissions: perms,
            scopes: Vec::new(),
        }
    }

    pub fn allows(&self, required: &Permission) -> bool {
        self.permissions.iter().any(|p| p.satisfies(required))
    }

    pub fn permissions(&self) -> &HashSet<Permission> {
        &self.permissions
    }

    /// Filter helper for resolvers that take a `node_id`: returns true when
    /// the principal has no scopes (unscoped) or when one of its scopes
    /// matches the supplied id or any of the supplied labels.
    pub fn allows_node(&self, node_id: &str, labels: &[&str]) -> bool {
        if self.scopes.is_empty() {
            return true;
        }
        self.scopes.iter().any(|s| match s {
            TokenScope::NodeId(id) => id == node_id,
            TokenScope::NodeLabel(l) => labels.iter().any(|x| x == l),
        })
    }
}

/// Display-friendly row from the `roles` table, used by IAM queries.
#[derive(Debug, Clone)]
pub struct RoleRow {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub built_in: bool,
}

// ── Store ───────────────────────────────────────────────────────────────────

/// Resolves a token id into a [`Principal`]. Owned by the auth middleware
/// (one instance, shared via `Arc`).
#[derive(Clone)]
pub struct RbacStore {
    pool: SqlitePool,
}

impl RbacStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Build the principal for an authenticated token. The caller has
    /// already validated the token (not revoked, not expired); this method
    /// only loads roles/permissions/scopes.
    pub async fn resolve(
        &self,
        token_id: i64,
        operator_id: Option<i64>,
        tenant_id: i64,
    ) -> Result<Principal> {
        // Token's own permissions: union over its role bindings.
        let token_perms = self.permissions_for_token(token_id).await?;

        // If a session token, intersect with the current operator's roles.
        // For static tokens (operator_id == None) the token's roles are the
        // sole source.
        let permissions = if let Some(op_id) = operator_id {
            // If the operator was disabled, drop permissions to empty.
            let disabled = sqlx::query_scalar::<_, Option<i64>>(
                "SELECT disabled_at FROM operators WHERE id = ?",
            )
            .bind(op_id)
            .fetch_optional(&self.pool)
            .await
            .context("load operator disabled_at")?;
            match disabled {
                Some(Some(_)) | None => HashSet::new(),
                Some(None) => {
                    let op_perms = self.permissions_for_operator(op_id).await?;
                    token_perms.intersection(&op_perms).cloned().collect()
                }
            }
        } else {
            token_perms
        };

        let scopes = self.scopes_for_token(token_id).await?;

        let tenant_slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = ?")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await
            .with_context(|| format!("load tenant slug for id {tenant_id}"))?;

        // Human-readable identity for audit attribution. Prefer the operator
        // account behind a session token; fall back to the static token's
        // name, then its id.
        let actor = if let Some(op_id) = operator_id {
            let username: Option<String> =
                sqlx::query_scalar("SELECT username FROM operators WHERE id = ?")
                    .bind(op_id)
                    .fetch_optional(&self.pool)
                    .await
                    .context("load operator username")?;
            match username {
                Some(name) => format!("operator:{name}"),
                None => format!("operator:{op_id}"),
            }
        } else {
            let token_name: Option<String> =
                sqlx::query_scalar("SELECT name FROM api_tokens WHERE id = ?")
                    .bind(token_id)
                    .fetch_optional(&self.pool)
                    .await
                    .context("load api token name")?;
            match token_name {
                Some(name) => format!("token:{name}"),
                None => format!("token:{token_id}"),
            }
        };

        Ok(Principal {
            token_id,
            operator_id,
            tenant_id,
            tenant_slug,
            actor,
            permissions,
            scopes,
        })
    }

    async fn permissions_for_token(&self, token_id: i64) -> Result<HashSet<Permission>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT rp.permission
            FROM api_token_roles tr
            JOIN role_permissions rp ON rp.role_id = tr.role_id
            WHERE tr.token_id = ?
            "#,
        )
        .bind(token_id)
        .fetch_all(&self.pool)
        .await
        .context("load token permissions")?;
        rows_to_perms(&rows)
    }

    async fn permissions_for_operator(&self, operator_id: i64) -> Result<HashSet<Permission>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT rp.permission
            FROM operator_roles oprl
            JOIN role_permissions rp ON rp.role_id = oprl.role_id
            WHERE oprl.operator_id = ?
            "#,
        )
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await
        .context("load operator permissions")?;
        rows_to_perms(&rows)
    }

    async fn scopes_for_token(&self, token_id: i64) -> Result<Vec<TokenScope>> {
        let rows =
            sqlx::query("SELECT scope_type, scope_value FROM api_token_scopes WHERE token_id = ?")
                .bind(token_id)
                .fetch_all(&self.pool)
                .await
                .context("load token scopes")?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let t: String = r.try_get("scope_type")?;
            let v: String = r.try_get("scope_value")?;
            out.push(match t.as_str() {
                "node_id" => TokenScope::NodeId(v),
                "node_label" => TokenScope::NodeLabel(v),
                other => anyhow::bail!("unknown scope_type `{other}`"),
            });
        }
        Ok(out)
    }

    /// Set the role set on a token. Used at mint time and by the IAM
    /// mutations. Replaces the prior set atomically.
    pub async fn set_token_roles(&self, token_id: i64, role_ids: &[i64]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM api_token_roles WHERE token_id = ?")
            .bind(token_id)
            .execute(&mut *tx)
            .await?;
        for rid in role_ids {
            sqlx::query("INSERT INTO api_token_roles (token_id, role_id) VALUES (?, ?)")
                .bind(token_id)
                .bind(rid)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Grant a role to an operator. Idempotent.
    pub async fn grant_role(
        &self,
        operator_id: i64,
        role_id: i64,
        granted_by: Option<i64>,
        now: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO operator_roles (operator_id, role_id, granted_at, granted_by)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(operator_id)
        .bind(role_id)
        .bind(now)
        .bind(granted_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Role ids currently bound to an operator. Used at login time to
    /// snapshot the operator's roles onto the new session token.
    pub async fn operator_role_ids(&self, operator_id: i64) -> Result<Vec<i64>> {
        let rows = sqlx::query_scalar::<_, i64>(
            "SELECT role_id FROM operator_roles WHERE operator_id = ?",
        )
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await
        .context("load operator role ids")?;
        Ok(rows)
    }

    /// Distinct tenant ids the operator currently holds role bindings in.
    /// The login endpoint uses this to pick the tenant for the freshly
    /// minted session token: exactly one → bind it, multiple → reject
    /// (tenant picker not yet implemented), zero → caller falls back to
    /// the default tenant (id 1).
    pub async fn operator_tenant_ids(&self, operator_id: i64) -> Result<Vec<i64>> {
        let rows = sqlx::query_scalar::<_, i64>(
            "SELECT DISTINCT r.tenant_id \
             FROM operator_roles oprl \
             JOIN roles r ON r.id = oprl.role_id \
             WHERE oprl.operator_id = ? \
             ORDER BY r.tenant_id ASC",
        )
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await
        .context("load operator tenant ids")?;
        Ok(rows)
    }

    /// All roles in a tenant. Used by IAM `roles` query so the UI can render
    /// a role-picker without leaking other tenants' custom roles.
    pub async fn list_roles(&self, tenant_id: i64) -> Result<Vec<RoleRow>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, description, built_in
            FROM roles
            WHERE tenant_id = ?
            ORDER BY built_in DESC, name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .context("list roles")?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let built_in: i64 = r.try_get("built_in")?;
            out.push(RoleRow {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                description: r.try_get("description")?,
                built_in: built_in != 0,
            });
        }
        Ok(out)
    }

    /// Permission strings attached to a role.
    pub async fn permissions_for_role(&self, role_id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT permission FROM role_permissions WHERE role_id = ? ORDER BY permission",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
        .context("load role permissions")?;
        Ok(rows)
    }

    /// Revoke a role grant. Idempotent — returns Ok even when the row
    /// already didn't exist.
    pub async fn revoke_role(&self, operator_id: i64, role_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM operator_roles WHERE operator_id = ? AND role_id = ?")
            .bind(operator_id)
            .bind(role_id)
            .execute(&self.pool)
            .await
            .context("revoke role")?;
        Ok(())
    }

    /// Replace a token's scope set. Used by the IAM mutation. `scopes` is
    /// `(scope_type, scope_value)` pairs.
    pub async fn set_token_scopes(&self, token_id: i64, scopes: &[(String, String)]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM api_token_scopes WHERE token_id = ?")
            .bind(token_id)
            .execute(&mut *tx)
            .await?;
        for (kind, value) in scopes {
            if kind != "node_id" && kind != "node_label" {
                anyhow::bail!("invalid scope type `{kind}` (expected node_id or node_label)");
            }
            sqlx::query(
                "INSERT INTO api_token_scopes (token_id, scope_type, scope_value) VALUES (?, ?, ?)",
            )
            .bind(token_id)
            .bind(kind)
            .bind(value)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Roles bound to an operator, with their display metadata.
    pub async fn roles_for_operator(&self, operator_id: i64) -> Result<Vec<RoleRow>> {
        let rows = sqlx::query(
            r#"
            SELECT r.id, r.name, r.description, r.built_in
            FROM operator_roles oprl
            JOIN roles r ON r.id = oprl.role_id
            WHERE oprl.operator_id = ?
            ORDER BY r.name
            "#,
        )
        .bind(operator_id)
        .fetch_all(&self.pool)
        .await
        .context("roles for operator")?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let built_in: i64 = r.try_get("built_in")?;
            out.push(RoleRow {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                description: r.try_get("description")?,
                built_in: built_in != 0,
            });
        }
        Ok(out)
    }

    /// Roles bound to a token.
    pub async fn roles_for_token(&self, token_id: i64) -> Result<Vec<RoleRow>> {
        let rows = sqlx::query(
            r#"
            SELECT r.id, r.name, r.description, r.built_in
            FROM api_token_roles tr
            JOIN roles r ON r.id = tr.role_id
            WHERE tr.token_id = ?
            ORDER BY r.name
            "#,
        )
        .bind(token_id)
        .fetch_all(&self.pool)
        .await
        .context("roles for token")?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let built_in: i64 = r.try_get("built_in")?;
            out.push(RoleRow {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                description: r.try_get("description")?,
                built_in: built_in != 0,
            });
        }
        Ok(out)
    }

    /// Scope pairs currently bound to a token.
    pub async fn token_scope_pairs(&self, token_id: i64) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT scope_type, scope_value FROM api_token_scopes WHERE token_id = ? ORDER BY scope_type, scope_value",
        )
        .bind(token_id)
        .fetch_all(&self.pool)
        .await
        .context("token scope pairs")?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push((r.try_get("scope_type")?, r.try_get("scope_value")?));
        }
        Ok(out)
    }

    /// Verify that every supplied role id belongs to `tenant_id`. Returns the
    /// id of the first offending role (not found, or owned by another tenant)
    /// as an error, so callers can surface it to clients.
    pub async fn validate_role_ids_for_tenant(
        &self,
        tenant_id: i64,
        role_ids: &[i64],
    ) -> Result<()> {
        for rid in role_ids {
            let found: Option<i64> =
                sqlx::query_scalar("SELECT id FROM roles WHERE id = ? AND tenant_id = ?")
                    .bind(rid)
                    .bind(tenant_id)
                    .fetch_optional(&self.pool)
                    .await
                    .context("validate role id")?;
            if found.is_none() {
                anyhow::bail!("role id {rid} does not exist in tenant {tenant_id}");
            }
        }
        Ok(())
    }

    /// Look up a built-in role's id within a tenant.
    pub async fn builtin_role_id(&self, tenant_id: i64, role: BuiltInRole) -> Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "SELECT id FROM roles WHERE tenant_id = ? AND name = ? AND built_in = 1",
        )
        .bind(tenant_id)
        .bind(role.as_str())
        .fetch_one(&self.pool)
        .await
        .with_context(|| {
            format!(
                "missing built-in role `{}` for tenant {}",
                role.as_str(),
                tenant_id
            )
        })?;
        Ok(id)
    }
}

fn rows_to_perms(rows: &[sqlx::sqlite::SqliteRow]) -> Result<HashSet<Permission>> {
    let mut out = HashSet::with_capacity(rows.len());
    for r in rows {
        let s: String = r.try_get("permission")?;
        out.insert(Permission::parse(&s)?);
    }
    Ok(out)
}

// ── Built-in roles ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltInRole {
    Admin,
    Operator,
    Viewer,
    SecurityAdmin,
    Auditor,
    Service,
}

impl BuiltInRole {
    pub fn as_str(self) -> &'static str {
        match self {
            BuiltInRole::Admin => "admin",
            BuiltInRole::Operator => "operator",
            BuiltInRole::Viewer => "viewer",
            BuiltInRole::SecurityAdmin => "security-admin",
            BuiltInRole::Auditor => "auditor",
            BuiltInRole::Service => "service",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            BuiltInRole::Admin => "Full access to everything in the tenant.",
            BuiltInRole::Operator => {
                "Day-to-day fleet operations: nodes, rules, alerts, enrollment."
            }
            BuiltInRole::Viewer => "Read-only access to everything except event payloads.",
            BuiltInRole::SecurityAdmin => "Operator plus IAM and token management.",
            BuiltInRole::Auditor => {
                "Read-only, including event payloads, for compliance investigations."
            }
            BuiltInRole::Service => {
                "Empty starter role for API tokens; grant additional roles explicitly."
            }
        }
    }

    /// Permission grants for this role. Mirrored in `0001_initial.sql` for
    /// the default tenant; [`bootstrap_tenant`] uses this list when seeding
    /// a new tenant at runtime.
    pub fn permissions(self) -> &'static [&'static str] {
        match self {
            BuiltInRole::Admin => &["*:*"],
            BuiltInRole::Operator => &[
                "node:read",
                "node:write",
                "node:delete",
                "rule:read",
                "rule:write",
                "rule:delete",
                "interface:read",
                "interface:write",
                "enrollment:read",
                "enrollment:write",
                "enrollment:delete",
                "alert:read",
                "alert:write",
                "alert:delete",
                "event:read",
                "event:delete",
                "audit:read",
                "token:read",
                "tenant:read",
            ],
            BuiltInRole::Viewer => &[
                "node:read",
                "rule:read",
                "interface:read",
                "enrollment:read",
                "alert:read",
                "event:read",
                "audit:read",
                "token:read",
                "tenant:read",
            ],
            BuiltInRole::SecurityAdmin => &[
                "node:read",
                "node:write",
                "node:delete",
                "rule:read",
                "rule:write",
                "rule:delete",
                "interface:read",
                "interface:write",
                "enrollment:read",
                "enrollment:write",
                "enrollment:delete",
                "alert:read",
                "alert:write",
                "alert:delete",
                "event:read",
                "event:delete",
                "audit:read",
                "token:read",
                "token:write",
                "token:delete",
                "iam:read",
                "iam:write",
                "iam:delete",
                "tenant:read",
            ],
            BuiltInRole::Auditor => &[
                "node:read",
                "rule:read",
                "interface:read",
                "enrollment:read",
                "alert:read",
                "event:read",
                "event:read-payload",
                "audit:read",
                "token:read",
                "iam:read",
                "tenant:read",
            ],
            BuiltInRole::Service => &[],
        }
    }

    pub fn all() -> &'static [BuiltInRole] {
        &[
            BuiltInRole::Admin,
            BuiltInRole::Operator,
            BuiltInRole::Viewer,
            BuiltInRole::SecurityAdmin,
            BuiltInRole::Auditor,
            BuiltInRole::Service,
        ]
    }
}

/// Seed the six built-in roles for `tenant_id`. Idempotent: re-runs after
/// the schema's initial seed (which targets tenant 1) are no-ops. Called
/// when a new tenant is provisioned at runtime.
pub async fn bootstrap_tenant(pool: &SqlitePool, tenant_id: i64, now: i64) -> Result<()> {
    let mut tx = pool.begin().await?;
    for role in BuiltInRole::all() {
        // Insert the role row.
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO roles (tenant_id, name, description, built_in, created_at)
            VALUES (?, ?, ?, 1, ?)
            "#,
        )
        .bind(tenant_id)
        .bind(role.as_str())
        .bind(role.description())
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // Look up the (possibly pre-existing) id.
        let id: i64 = sqlx::query_scalar(
            "SELECT id FROM roles WHERE tenant_id = ? AND name = ? AND built_in = 1",
        )
        .bind(tenant_id)
        .bind(role.as_str())
        .fetch_one(&mut *tx)
        .await?;

        for p in role.permissions() {
            sqlx::query(
                "INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?, ?)",
            )
            .bind(id)
            .bind(*p)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

// ── async-graphql Guard ─────────────────────────────────────────────────────

/// Guard that requires a specific permission on the request's [`Principal`].
///
/// Usage:
/// ```ignore
/// #[graphql(guard = "Require::new(\"rule:write\")")]
/// async fn create_rule(&self, ctx: &Context<'_>, ...) -> Result<Rule> { ... }
/// ```
pub struct Require(Permission);

impl Require {
    pub fn new(literal: &'static str) -> Self {
        Self(Permission::new(literal))
    }
}

impl Guard for Require {
    async fn check(&self, ctx: &GqlContext<'_>) -> async_graphql::Result<()> {
        let principal = ctx
            .data::<Arc<Principal>>()
            .map_err(|_| async_graphql::Error::new("unauthenticated"))?;
        if principal.allows(&self.0) {
            Ok(())
        } else {
            Err(async_graphql::Error::new(format!(
                "forbidden: requires {}:{}",
                self.0.resource, self.0.verb
            )))
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_parse_round_trip() {
        let p = Permission::parse("rule:write").unwrap();
        assert!(p.satisfies(&Permission::new("rule:write")));
        assert!(!p.satisfies(&Permission::new("rule:read")));
        assert!(!p.satisfies(&Permission::new("node:write")));
    }

    #[test]
    fn permission_wildcards() {
        let star = Permission::parse("*:*").unwrap();
        assert!(star.satisfies(&Permission::new("anything:goes")));

        let resource_wild = Permission::parse("*:read").unwrap();
        assert!(resource_wild.satisfies(&Permission::new("node:read")));
        assert!(!resource_wild.satisfies(&Permission::new("node:write")));

        let verb_wild = Permission::parse("rule:*").unwrap();
        assert!(verb_wild.satisfies(&Permission::new("rule:delete")));
        assert!(!verb_wild.satisfies(&Permission::new("node:delete")));
    }

    #[test]
    fn hyphenated_verbs_supported() {
        let p = Permission::parse("event:read-payload").unwrap();
        assert!(p.satisfies(&Permission::new("event:read-payload")));
        assert!(!p.satisfies(&Permission::new("event:read")));
    }

    #[test]
    fn malformed_rejected() {
        assert!(Permission::parse("no_colon").is_err());
        assert!(Permission::parse(":missing").is_err());
        assert!(Permission::parse("missing:").is_err());
    }

    async fn pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn builtin_roles_seeded_for_default_tenant() {
        let store = RbacStore::new(pool().await);
        for role in BuiltInRole::all() {
            let id = store.builtin_role_id(1, *role).await.unwrap();
            assert!(id > 0, "{}", role.as_str());
        }
    }

    #[tokio::test]
    async fn admin_role_has_wildcard() {
        let p = pool().await;
        let store = RbacStore::new(p.clone());

        // Mint a token and bind it to admin.
        let row_id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (name, token_hash, kind, created_at) \
             VALUES ('t', X'00', 'static', 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        let admin = store.builtin_role_id(1, BuiltInRole::Admin).await.unwrap();
        store.set_token_roles(row_id, &[admin]).await.unwrap();

        let principal = store.resolve(row_id, None, 1).await.unwrap();
        assert!(principal.allows(&Permission::new("rule:delete")));
        assert!(principal.allows(&Permission::new("iam:write")));
    }

    #[tokio::test]
    async fn viewer_cannot_read_event_payload() {
        let p = pool().await;
        let store = RbacStore::new(p.clone());
        let row_id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (name, token_hash, kind, created_at) \
             VALUES ('v', X'01', 'static', 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        let viewer = store.builtin_role_id(1, BuiltInRole::Viewer).await.unwrap();
        store.set_token_roles(row_id, &[viewer]).await.unwrap();

        let principal = store.resolve(row_id, None, 1).await.unwrap();
        assert!(principal.allows(&Permission::new("event:read")));
        assert!(!principal.allows(&Permission::new("event:read-payload")));
        assert!(!principal.allows(&Permission::new("rule:write")));
    }

    #[tokio::test]
    async fn auditor_can_read_payload() {
        let p = pool().await;
        let store = RbacStore::new(p.clone());
        let row_id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (name, token_hash, kind, created_at) \
             VALUES ('a', X'02', 'static', 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        let auditor = store
            .builtin_role_id(1, BuiltInRole::Auditor)
            .await
            .unwrap();
        store.set_token_roles(row_id, &[auditor]).await.unwrap();

        let principal = store.resolve(row_id, None, 1).await.unwrap();
        assert!(principal.allows(&Permission::new("event:read-payload")));
        assert!(!principal.allows(&Permission::new("rule:write")));
    }

    #[tokio::test]
    async fn session_token_intersects_with_operator_roles() {
        let p = pool().await;
        let store = RbacStore::new(p.clone());

        // Create operator (no roles yet).
        let op_id: i64 = sqlx::query_scalar(
            "INSERT INTO operators (username, password_hash, created_at) \
             VALUES ('alice', 'x', 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();

        // Session token bound to admin.
        let tok_id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (name, token_hash, kind, created_at, operator_id) \
             VALUES ('session:alice', X'03', 'session', 0, ?) RETURNING id",
        )
        .bind(op_id)
        .fetch_one(&p)
        .await
        .unwrap();
        let admin = store.builtin_role_id(1, BuiltInRole::Admin).await.unwrap();
        store.set_token_roles(tok_id, &[admin]).await.unwrap();

        // Operator has no roles → intersection is empty.
        let principal = store.resolve(tok_id, Some(op_id), 1).await.unwrap();
        assert!(!principal.allows(&Permission::new("rule:write")));

        // Grant admin to operator → intersection now equals admin's perms.
        store.grant_role(op_id, admin, None, 0).await.unwrap();
        let principal = store.resolve(tok_id, Some(op_id), 1).await.unwrap();
        assert!(principal.allows(&Permission::new("rule:write")));

        // Disable operator → intersection drops to empty.
        sqlx::query("UPDATE operators SET disabled_at = 1 WHERE id = ?")
            .bind(op_id)
            .execute(&p)
            .await
            .unwrap();
        let principal = store.resolve(tok_id, Some(op_id), 1).await.unwrap();
        assert!(!principal.allows(&Permission::new("rule:write")));
    }

    #[tokio::test]
    async fn actor_names_operator_and_static_token() {
        let p = pool().await;
        let store = RbacStore::new(p.clone());

        // Static token resolves to `token:<name>`.
        let static_id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (name, token_hash, kind, created_at) \
             VALUES ('grafana-prod', X'10', 'static', 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        let principal = store.resolve(static_id, None, 1).await.unwrap();
        assert_eq!(principal.actor, "token:grafana-prod");

        // Session token tied to an operator resolves to `operator:<username>`.
        let op_id: i64 = sqlx::query_scalar(
            "INSERT INTO operators (username, password_hash, created_at) \
             VALUES ('alice', 'x', 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        let session_id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (name, token_hash, kind, created_at, operator_id) \
             VALUES ('session:alice', X'11', 'session', 0, ?) RETURNING id",
        )
        .bind(op_id)
        .fetch_one(&p)
        .await
        .unwrap();
        let principal = store.resolve(session_id, Some(op_id), 1).await.unwrap();
        assert_eq!(principal.actor, "operator:alice");
    }

    #[tokio::test]
    async fn bootstrap_tenant_is_idempotent_and_seeds_new_tenant() {
        let p = pool().await;
        let store = RbacStore::new(p.clone());

        // Re-running against tenant 1 is a no-op (already seeded by SQL).
        bootstrap_tenant(&p, 1, 0).await.unwrap();

        // Create a second tenant and seed it.
        let new_tid: i64 = sqlx::query_scalar(
            "INSERT INTO tenants (slug, name, retention_s, created_at) \
             VALUES ('acme', 'Acme', 604800, 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        bootstrap_tenant(&p, new_tid, 0).await.unwrap();

        for role in BuiltInRole::all() {
            assert!(store.builtin_role_id(new_tid, *role).await.is_ok());
        }
    }

    #[tokio::test]
    async fn token_scopes_filter_nodes() {
        let p = pool().await;
        let store = RbacStore::new(p.clone());

        let tok_id: i64 = sqlx::query_scalar(
            "INSERT INTO api_tokens (name, token_hash, kind, created_at) \
             VALUES ('s', X'04', 'static', 0) RETURNING id",
        )
        .fetch_one(&p)
        .await
        .unwrap();
        let admin = store.builtin_role_id(1, BuiltInRole::Admin).await.unwrap();
        store.set_token_roles(tok_id, &[admin]).await.unwrap();

        sqlx::query(
            "INSERT INTO api_token_scopes (token_id, scope_type, scope_value) \
             VALUES (?, 'node_id', 'node-1'), (?, 'node_label', 'edge')",
        )
        .bind(tok_id)
        .bind(tok_id)
        .execute(&p)
        .await
        .unwrap();

        let principal = store.resolve(tok_id, None, 1).await.unwrap();
        assert!(principal.allows_node("node-1", &[]));
        assert!(principal.allows_node("node-9", &["edge"]));
        assert!(!principal.allows_node("node-9", &["dc"]));
    }
}
