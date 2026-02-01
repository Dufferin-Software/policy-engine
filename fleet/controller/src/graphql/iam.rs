// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! GraphQL IAM surface used by controller-web.
//!
//! Lets an authenticated operator inspect themselves (`me`), enumerate
//! operators/roles, and edit role/scope bindings on operators and tokens.
//! All resolvers here are guarded with `iam:read`, `iam:write`, or
//! `iam:delete`; the wiring lives in `graphql::schema`. The actual data
//! access goes through [`OperatorStore`] and [`RbacStore`] — this module
//! is GraphQL plumbing only.

use async_graphql::{Context, InputObject, Result, SimpleObject, ID};
use chrono::{DateTime, TimeZone, Utc};
use std::sync::Arc;

use crate::{
    graphql::api_tokens::ApiTokenOutput,
    operators::OperatorStore,
    rbac::{Principal, RbacStore, RoleRow},
};

// ── Output types ────────────────────────────────────────────────────────────

#[derive(SimpleObject, Clone)]
pub struct RoleOutput {
    pub id: ID,
    pub name: String,
    pub description: Option<String>,
    pub built_in: bool,
    pub permissions: Vec<String>,
}

#[derive(SimpleObject, Clone)]
pub struct OperatorOutput {
    pub id: ID,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub roles: Vec<RoleSummary>,
}

/// Lightweight role view used inside operator/token listings, without the
/// full permission set — saves a query per row.
#[derive(SimpleObject, Clone)]
pub struct RoleSummary {
    pub id: ID,
    pub name: String,
    pub built_in: bool,
}

#[derive(SimpleObject, Clone)]
pub struct TokenScopeOutput {
    /// `"node_id"` or `"node_label"`.
    pub scope_type: String,
    pub scope_value: String,
}

#[derive(InputObject, Clone)]
pub struct TokenScopeInput {
    pub scope_type: String,
    pub scope_value: String,
}

/// The authenticated caller's view of themselves. `operator` is None for
/// static (non-session) tokens.
#[derive(SimpleObject, Clone)]
pub struct MeOutput {
    pub token_id: ID,
    pub tenant_id: ID,
    pub operator: Option<OperatorOutput>,
    pub permissions: Vec<String>,
    pub scopes: Vec<TokenScopeOutput>,
}

fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().unwrap_or_else(Utc::now)
}

fn ts_opt(secs: Option<i64>) -> Option<DateTime<Utc>> {
    secs.and_then(|s| Utc.timestamp_opt(s, 0).single())
}

fn parse_id(id: &ID, label: &str) -> Result<i64> {
    id.0.parse::<i64>()
        .map_err(|e| async_graphql::Error::new(format!("Invalid {label} id: {e}")))
}

fn role_summary(r: &RoleRow) -> RoleSummary {
    RoleSummary {
        id: ID(r.id.to_string()),
        name: r.name.clone(),
        built_in: r.built_in,
    }
}

async fn build_operator_output(
    rbac: &RbacStore,
    op: crate::operators::Operator,
) -> Result<OperatorOutput> {
    let roles = rbac
        .roles_for_operator(op.id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    Ok(OperatorOutput {
        id: ID(op.id.to_string()),
        username: op.username,
        created_at: ts(op.created_at),
        last_login_at: ts_opt(op.last_login_at),
        disabled_at: ts_opt(op.disabled_at),
        roles: roles.iter().map(role_summary).collect(),
    })
}

fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Query resolvers ─────────────────────────────────────────────────────────

pub async fn resolve_me(ctx: &Context<'_>) -> Result<MeOutput> {
    let principal = ctx.data::<Arc<Principal>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let ops = ctx.data::<Arc<OperatorStore>>()?;

    let operator = if let Some(op_id) = principal.operator_id {
        let op = ops
            .find_by_id(op_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
            .ok_or_else(|| async_graphql::Error::new("operator vanished"))?;
        Some(build_operator_output(rbac, op).await?)
    } else {
        None
    };

    let scopes = rbac
        .token_scope_pairs(principal.token_id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .into_iter()
        .map(|(t, v)| TokenScopeOutput {
            scope_type: t,
            scope_value: v,
        })
        .collect();

    let mut perms: Vec<String> = principal
        .permissions()
        .iter()
        .map(|p| format!("{}:{}", p.resource_str(), p.verb_str()))
        .collect();
    perms.sort();

    Ok(MeOutput {
        token_id: ID(principal.token_id.to_string()),
        tenant_id: ID(principal.tenant_id.to_string()),
        operator,
        permissions: perms,
        scopes,
    })
}

pub async fn resolve_operators(ctx: &Context<'_>) -> Result<Vec<OperatorOutput>> {
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let rows = ops
        .list()
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    let mut out = Vec::with_capacity(rows.len());
    for op in rows {
        out.push(build_operator_output(rbac, op).await?);
    }
    Ok(out)
}

pub async fn resolve_operator(ctx: &Context<'_>, id: ID) -> Result<Option<OperatorOutput>> {
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let oid = parse_id(&id, "operator")?;
    let row = ops
        .find_by_id(oid)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    match row {
        Some(op) => Ok(Some(build_operator_output(rbac, op).await?)),
        None => Ok(None),
    }
}

pub async fn resolve_roles(ctx: &Context<'_>) -> Result<Vec<RoleOutput>> {
    let principal = ctx.data::<Arc<Principal>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let rows = rbac
        .list_roles(principal.tenant_id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let perms = rbac
            .permissions_for_role(r.id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
        out.push(RoleOutput {
            id: ID(r.id.to_string()),
            name: r.name,
            description: r.description,
            built_in: r.built_in,
            permissions: perms,
        });
    }
    Ok(out)
}

// ── Mutation resolvers ──────────────────────────────────────────────────────

pub async fn resolve_create_operator(
    ctx: &Context<'_>,
    username: String,
    password: String,
    role_ids: Vec<ID>,
) -> Result<OperatorOutput> {
    let principal = ctx.data::<Arc<Principal>>()?;
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;

    let parsed: Vec<i64> = role_ids
        .iter()
        .map(|r| parse_id(r, "role"))
        .collect::<Result<_>>()?;
    if !parsed.is_empty() {
        rbac.validate_role_ids_for_tenant(principal.tenant_id, &parsed)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    }

    let op = ops
        .create(&username, &password)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;

    let now = now_s();
    for rid in &parsed {
        rbac.grant_role(op.id, *rid, principal.operator_id, now)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    }

    build_operator_output(rbac, op).await
}

pub async fn resolve_disable_operator(ctx: &Context<'_>, id: ID) -> Result<OperatorOutput> {
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let oid = parse_id(&id, "operator")?;
    ops.disable(oid, now_s())
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    let op = ops
        .find_by_id(oid)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .ok_or_else(|| async_graphql::Error::new("operator not found"))?;
    build_operator_output(rbac, op).await
}

pub async fn resolve_enable_operator(ctx: &Context<'_>, id: ID) -> Result<OperatorOutput> {
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let oid = parse_id(&id, "operator")?;
    ops.enable(oid)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    let op = ops
        .find_by_id(oid)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .ok_or_else(|| async_graphql::Error::new("operator not found"))?;
    build_operator_output(rbac, op).await
}

pub async fn resolve_set_operator_password(
    ctx: &Context<'_>,
    id: ID,
    new_password: String,
) -> Result<bool> {
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let oid = parse_id(&id, "operator")?;
    ops.set_password(oid, &new_password)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    Ok(true)
}

pub async fn resolve_grant_role(
    ctx: &Context<'_>,
    operator_id: ID,
    role_id: ID,
) -> Result<OperatorOutput> {
    let principal = ctx.data::<Arc<Principal>>()?;
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;

    let oid = parse_id(&operator_id, "operator")?;
    let rid = parse_id(&role_id, "role")?;
    rbac.validate_role_ids_for_tenant(principal.tenant_id, &[rid])
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    rbac.grant_role(oid, rid, principal.operator_id, now_s())
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    let op = ops
        .find_by_id(oid)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .ok_or_else(|| async_graphql::Error::new("operator not found"))?;
    build_operator_output(rbac, op).await
}

pub async fn resolve_revoke_role(
    ctx: &Context<'_>,
    operator_id: ID,
    role_id: ID,
) -> Result<OperatorOutput> {
    let ops = ctx.data::<Arc<OperatorStore>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let oid = parse_id(&operator_id, "operator")?;
    let rid = parse_id(&role_id, "role")?;
    rbac.revoke_role(oid, rid)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    let op = ops
        .find_by_id(oid)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .ok_or_else(|| async_graphql::Error::new("operator not found"))?;
    build_operator_output(rbac, op).await
}

pub async fn resolve_set_token_roles(
    ctx: &Context<'_>,
    token_id: ID,
    role_ids: Vec<ID>,
) -> Result<ApiTokenOutput> {
    let principal = ctx.data::<Arc<Principal>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let token_store = ctx.data::<Arc<crate::api_tokens::ApiTokenStore>>()?;
    let tid = parse_id(&token_id, "token")?;

    let parsed: Vec<i64> = role_ids
        .iter()
        .map(|r| parse_id(r, "role"))
        .collect::<Result<_>>()?;
    if !parsed.is_empty() {
        rbac.validate_role_ids_for_tenant(principal.tenant_id, &parsed)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    }
    // The role-id validation above already rejects cross-tenant role ids,
    // but we still need to confirm the *target token* is in the caller's
    // tenant — otherwise an admin in tenant A could rebind tenant B's
    // token to a (validly tenant-A) role. Looking up via the tenant-scoped
    // list converts that into a plain "not found".
    let row = token_store
        .list(principal.tenant_id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .into_iter()
        .find(|t| t.id == tid)
        .ok_or_else(|| async_graphql::Error::new("token not found"))?;

    rbac.set_token_roles(tid, &parsed)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;

    // Re-fetch so the returned output reflects the just-applied changes
    // (today this is a no-op since none of the surfaced fields depend on
    // role bindings, but keeps the resolver honest if that ever changes).
    Ok(row.into())
}

pub async fn resolve_set_token_scopes(
    ctx: &Context<'_>,
    token_id: ID,
    scopes: Vec<TokenScopeInput>,
) -> Result<ApiTokenOutput> {
    let principal = ctx.data::<Arc<Principal>>()?;
    let rbac = ctx.data::<Arc<RbacStore>>()?;
    let token_store = ctx.data::<Arc<crate::api_tokens::ApiTokenStore>>()?;
    let tid = parse_id(&token_id, "token")?;

    // Tenant-gate the target token before applying scope changes (see
    // resolve_set_token_roles for the same pattern).
    let row = token_store
        .list(principal.tenant_id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .into_iter()
        .find(|t| t.id == tid)
        .ok_or_else(|| async_graphql::Error::new("token not found"))?;

    let pairs: Vec<(String, String)> = scopes
        .into_iter()
        .map(|s| (s.scope_type, s.scope_value))
        .collect();
    rbac.set_token_scopes(tid, &pairs)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;

    Ok(row.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api_tokens::ApiTokenStore,
        rbac::{BuiltInRole, Permission},
    };
    use async_graphql::{EmptySubscription, InputObject, Object, Request, Schema};
    use sqlx::sqlite::SqlitePool;
    use std::collections::HashSet;

    struct Q;
    #[Object]
    impl Q {
        async fn me(&self, ctx: &Context<'_>) -> Result<MeOutput> {
            resolve_me(ctx).await
        }
        async fn operators(&self, ctx: &Context<'_>) -> Result<Vec<OperatorOutput>> {
            resolve_operators(ctx).await
        }
        async fn operator(&self, ctx: &Context<'_>, id: ID) -> Result<Option<OperatorOutput>> {
            resolve_operator(ctx, id).await
        }
        async fn roles(&self, ctx: &Context<'_>) -> Result<Vec<RoleOutput>> {
            resolve_roles(ctx).await
        }
    }

    #[derive(InputObject)]
    struct ScopeIn {
        scope_type: String,
        scope_value: String,
    }
    impl From<ScopeIn> for TokenScopeInput {
        fn from(s: ScopeIn) -> Self {
            Self {
                scope_type: s.scope_type,
                scope_value: s.scope_value,
            }
        }
    }

    struct M;
    #[Object]
    impl M {
        async fn create_operator(
            &self,
            ctx: &Context<'_>,
            username: String,
            password: String,
            #[graphql(default_with = "Vec::new()")] role_ids: Vec<ID>,
        ) -> Result<OperatorOutput> {
            resolve_create_operator(ctx, username, password, role_ids).await
        }
        async fn disable_operator(&self, ctx: &Context<'_>, id: ID) -> Result<OperatorOutput> {
            resolve_disable_operator(ctx, id).await
        }
        async fn enable_operator(&self, ctx: &Context<'_>, id: ID) -> Result<OperatorOutput> {
            resolve_enable_operator(ctx, id).await
        }
        async fn grant_role(
            &self,
            ctx: &Context<'_>,
            operator_id: ID,
            role_id: ID,
        ) -> Result<OperatorOutput> {
            resolve_grant_role(ctx, operator_id, role_id).await
        }
        async fn revoke_role(
            &self,
            ctx: &Context<'_>,
            operator_id: ID,
            role_id: ID,
        ) -> Result<OperatorOutput> {
            resolve_revoke_role(ctx, operator_id, role_id).await
        }
        async fn set_token_roles(
            &self,
            ctx: &Context<'_>,
            token_id: ID,
            role_ids: Vec<ID>,
        ) -> Result<ApiTokenOutput> {
            resolve_set_token_roles(ctx, token_id, role_ids).await
        }
    }

    async fn harness() -> (Schema<Q, M, EmptySubscription>, SqlitePool) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let ops = Arc::new(OperatorStore::new(pool.clone()));
        let rbac = Arc::new(RbacStore::new(pool.clone()));
        let tokens = Arc::new(ApiTokenStore::new(pool.clone()));
        let principal = Arc::new(Principal::test_admin());
        let schema = Schema::build(Q, M, EmptySubscription)
            .data(ops)
            .data(rbac)
            .data(tokens)
            .data(principal)
            .finish();
        (schema, pool)
    }

    fn ok(resp: async_graphql::Response) -> serde_json::Value {
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        serde_json::to_value(&resp.data).unwrap()
    }

    #[tokio::test]
    async fn roles_query_lists_builtins_with_permissions() {
        let (schema, _) = harness().await;
        let resp = schema
            .execute("{ roles { name builtIn permissions } }")
            .await;
        let data = ok(resp);
        let names: Vec<&str> = data["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        for r in BuiltInRole::all() {
            assert!(names.contains(&r.as_str()), "missing role {}", r.as_str());
        }
        let admin = data["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "admin")
            .unwrap();
        assert!(admin["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "*:*"));
    }

    #[tokio::test]
    async fn create_operator_with_role_grants_it() {
        let (schema, pool) = harness().await;
        let rbac = RbacStore::new(pool);
        let viewer_id = rbac.builtin_role_id(1, BuiltInRole::Viewer).await.unwrap();

        let resp = schema
            .execute(format!(
                r#"mutation {{ createOperator(username: "alice", password: "longenoughpw", roleIds: ["{viewer_id}"]) {{
                    id username roles {{ name }}
                }} }}"#
            ))
            .await;
        let data = ok(resp);
        assert_eq!(data["createOperator"]["username"], "alice");
        let role_names: Vec<&str> = data["createOperator"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert_eq!(role_names, vec!["viewer"]);
    }

    #[tokio::test]
    async fn disable_then_enable_round_trip() {
        let (schema, _) = harness().await;
        let resp = schema
            .execute(
                r#"mutation { createOperator(username: "bob", password: "longenoughpw") { id } }"#,
            )
            .await;
        let id = ok(resp)["createOperator"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let resp = schema
            .execute(format!(
                r#"mutation {{ disableOperator(id: "{id}") {{ disabledAt }} }}"#
            ))
            .await;
        assert!(!ok(resp)["disableOperator"]["disabledAt"].is_null());

        let resp = schema
            .execute(format!(
                r#"mutation {{ enableOperator(id: "{id}") {{ disabledAt }} }}"#
            ))
            .await;
        assert!(ok(resp)["enableOperator"]["disabledAt"].is_null());
    }

    #[tokio::test]
    async fn grant_then_revoke_role() {
        let (schema, pool) = harness().await;
        let rbac = RbacStore::new(pool);
        let viewer = rbac.builtin_role_id(1, BuiltInRole::Viewer).await.unwrap();

        let resp = schema
            .execute(
                r#"mutation { createOperator(username: "carol", password: "longenoughpw") { id } }"#,
            )
            .await;
        let id = ok(resp)["createOperator"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let resp = schema
            .execute(format!(
                r#"mutation {{ grantRole(operatorId: "{id}", roleId: "{viewer}") {{ roles {{ name }} }} }}"#
            ))
            .await;
        let names: Vec<String> = ok(resp)["grantRole"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["viewer"]);

        let resp = schema
            .execute(format!(
                r#"mutation {{ revokeRole(operatorId: "{id}", roleId: "{viewer}") {{ roles {{ name }} }} }}"#
            ))
            .await;
        assert!(ok(resp)["revokeRole"]["roles"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn set_token_roles_round_trip() {
        let (schema, pool) = harness().await;
        let rbac = RbacStore::new(pool.clone());
        let store = ApiTokenStore::new(pool);
        let (tok, _pt) = store.create("grafana", 1, None, None).await.unwrap();
        let viewer = rbac.builtin_role_id(1, BuiltInRole::Viewer).await.unwrap();

        let resp = schema
            .execute(format!(
                r#"mutation {{ setTokenRoles(tokenId: "{}", roleIds: ["{viewer}"]) {{ id }} }}"#,
                tok.id
            ))
            .await;
        ok(resp);

        let principal = rbac.resolve(tok.id, None, 1).await.unwrap();
        assert!(principal.allows(&Permission::new("node:read")));
        assert!(!principal.allows(&Permission::new("rule:write")));
    }

    #[tokio::test]
    async fn me_returns_principal_view() {
        // Build a non-admin principal so we exercise the permission listing
        // path, then query `me` and confirm it round-trips.
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let ops = Arc::new(OperatorStore::new(pool.clone()));
        let rbac = Arc::new(RbacStore::new(pool.clone()));
        let tokens = Arc::new(ApiTokenStore::new(pool.clone()));

        let mut perms = HashSet::new();
        perms.insert(Permission::new("iam:read"));
        perms.insert(Permission::new("node:read"));
        let principal = Arc::new(Principal::from_test_parts(perms));

        let schema = Schema::build(Q, M, EmptySubscription)
            .data(ops)
            .data(rbac)
            .data(tokens)
            .data(principal)
            .finish();

        let resp = schema
            .execute(Request::new(
                "{ me { tokenId tenantId operator { id } permissions } }",
            ))
            .await;
        let data = ok(resp);
        assert_eq!(data["me"]["tenantId"], "1");
        assert!(data["me"]["operator"].is_null());
        let perms: Vec<&str> = data["me"]["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert!(perms.contains(&"iam:read"));
        assert!(perms.contains(&"node:read"));
    }
}
