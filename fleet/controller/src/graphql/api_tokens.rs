// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! GraphQL surface for API bearer tokens.
//!
//! Lets controller-web mint and revoke the `dsw_…` tokens that protect
//! `/graphql`, `/playground`, REST, and the WS endpoints. The plaintext is
//! returned exactly once on creation (mirrors the `policy-controller-mint-token`
//! bin); after that only the ID can be used to address the token.
//!
//! With operator login in place (see `docs/login-flow.md`), controller-web
//! reaches these mutations as the authenticated operator's session — the
//! `createApiToken` flow is the normal way to mint long-lived service
//! tokens for Grafana and friends. Session tokens themselves come from
//! `/api/v1/login`, not from this surface.

use async_graphql::{Context, Result, SimpleObject, ID};
use chrono::{DateTime, TimeZone, Utc};
use std::sync::Arc;

use crate::api_tokens::{ApiToken, ApiTokenStore};
use crate::rbac::{Principal, RbacStore};

#[derive(SimpleObject, Clone)]
pub struct ApiTokenOutput {
    pub id: ID,
    pub name: String,
    /// "static" or "session". UI uses this to filter session noise.
    pub kind: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<ApiToken> for ApiTokenOutput {
    fn from(t: ApiToken) -> Self {
        Self {
            id: ID(t.id.to_string()),
            name: t.name,
            kind: t.kind.as_str().to_string(),
            created_at: ts(t.created_at),
            created_by: t.created_by,
            expires_at: t.expires_at.and_then(ts_opt),
            revoked_at: t.revoked_at.and_then(ts_opt),
            last_used_at: t.last_used_at.and_then(ts_opt),
        }
    }
}

/// Returned only by `createApiToken`. `plaintext` is the `dsw_…` secret the
/// operator must capture — it is never persisted and cannot be retrieved
/// afterwards.
#[derive(SimpleObject, Clone)]
pub struct ApiTokenWithSecret {
    pub token: ApiTokenOutput,
    pub plaintext: String,
}

fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().unwrap_or_else(Utc::now)
}

fn ts_opt(secs: i64) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(secs, 0).single()
}

fn parse_id(id: &ID) -> Result<i64> {
    id.0.parse::<i64>()
        .map_err(|e| async_graphql::Error::new(format!("Invalid id: {e}")))
}

// ── Resolvers ────────────────────────────────────────────────────────────────

pub async fn resolve_api_tokens(ctx: &Context<'_>) -> Result<Vec<ApiTokenOutput>> {
    let store = ctx.data::<Arc<ApiTokenStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    Ok(store
        .list(principal.tenant_id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .into_iter()
        .map(ApiTokenOutput::from)
        .collect())
}

pub async fn resolve_create_api_token(
    ctx: &Context<'_>,
    name: String,
    expires_at: Option<DateTime<Utc>>,
    role_ids: Vec<ID>,
) -> Result<ApiTokenWithSecret> {
    let store = ctx.data::<Arc<ApiTokenStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;

    // Parse + validate role ids against the caller's tenant before minting,
    // so a bad input doesn't leave an unbound token behind.
    let parsed_role_ids: Vec<i64> = role_ids
        .iter()
        .map(|r| {
            r.0.parse::<i64>()
                .map_err(|e| async_graphql::Error::new(format!("Invalid role id: {e}")))
        })
        .collect::<Result<_>>()?;

    if !parsed_role_ids.is_empty() {
        let rbac = ctx.data::<Arc<RbacStore>>()?;
        rbac.validate_role_ids_for_tenant(principal.tenant_id, &parsed_role_ids)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    }

    let expires = expires_at.map(|t| t.timestamp());
    let (row, plaintext) = store
        .create(&name, principal.tenant_id, expires, Some("operator"))
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;

    if !parsed_role_ids.is_empty() {
        let rbac = ctx.data::<Arc<RbacStore>>()?;
        rbac.set_token_roles(row.id, &parsed_role_ids)
            .await
            .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    }

    Ok(ApiTokenWithSecret {
        token: row.into(),
        plaintext,
    })
}

pub async fn resolve_revoke_api_token(ctx: &Context<'_>, id: ID) -> Result<ApiTokenOutput> {
    let store = ctx.data::<Arc<ApiTokenStore>>()?;
    let principal = ctx.data::<Arc<Principal>>()?;
    let tid = parse_id(&id)?;
    store
        .revoke(tid, principal.tenant_id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?;
    let row = store
        .list(principal.tenant_id)
        .await
        .map_err(|e| async_graphql::Error::new(format!("{e:#}")))?
        .into_iter()
        .find(|t| t.id == tid)
        .ok_or_else(|| async_graphql::Error::new("token disappeared after revoke"))?;
    Ok(row.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::{EmptySubscription, Object, Schema};
    use sqlx::sqlite::SqlitePool;

    struct Q;
    #[Object]
    impl Q {
        async fn api_tokens(&self, ctx: &Context<'_>) -> Result<Vec<ApiTokenOutput>> {
            resolve_api_tokens(ctx).await
        }
    }

    struct M;
    #[Object]
    impl M {
        async fn create_api_token(
            &self,
            ctx: &Context<'_>,
            name: String,
            expires_at: Option<DateTime<Utc>>,
            #[graphql(default_with = "Vec::new()")] role_ids: Vec<ID>,
        ) -> Result<ApiTokenWithSecret> {
            resolve_create_api_token(ctx, name, expires_at, role_ids).await
        }
        async fn revoke_api_token(&self, ctx: &Context<'_>, id: ID) -> Result<ApiTokenOutput> {
            resolve_revoke_api_token(ctx, id).await
        }
    }

    async fn schema_with_data() -> Schema<Q, M, EmptySubscription> {
        let (schema, _pool) = schema_with_pool().await;
        schema
    }

    async fn schema_with_pool() -> (Schema<Q, M, EmptySubscription>, SqlitePool) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let store = Arc::new(ApiTokenStore::new(pool.clone()));
        let rbac = Arc::new(RbacStore::new(pool.clone()));
        let principal = Arc::new(Principal::test_admin());
        let schema = Schema::build(Q, M, EmptySubscription)
            .data(store)
            .data(rbac)
            .data(principal)
            .finish();
        (schema, pool)
    }

    fn ok_data(resp: async_graphql::Response) -> serde_json::Value {
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        serde_json::to_value(&resp.data).unwrap()
    }

    #[tokio::test]
    async fn create_list_revoke_round_trip() {
        let schema = schema_with_data().await;

        let resp = schema
            .execute(
                r#"mutation { createApiToken(name: "grafana") {
                    token { id name revokedAt }
                    plaintext
                } }"#,
            )
            .await;
        let data = ok_data(resp);
        let plaintext = data["createApiToken"]["plaintext"].as_str().unwrap();
        assert!(plaintext.starts_with("dsw_"));
        let id = data["createApiToken"]["token"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(data["createApiToken"]["token"]["name"], "grafana");
        assert!(data["createApiToken"]["token"]["revokedAt"].is_null());

        let resp = schema.execute("{ apiTokens { id name revokedAt } }").await;
        let data = ok_data(resp);
        let list = data["apiTokens"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], id);

        let resp = schema
            .execute(format!(
                r#"mutation {{ revokeApiToken(id: "{id}") {{ id revokedAt }} }}"#
            ))
            .await;
        let data = ok_data(resp);
        assert!(!data["revokeApiToken"]["revokedAt"].is_null());
    }

    #[tokio::test]
    async fn duplicate_name_is_rejected() {
        let schema = schema_with_data().await;
        let resp = schema
            .execute(r#"mutation { createApiToken(name: "grafana") { plaintext } }"#)
            .await;
        ok_data(resp);

        let resp = schema
            .execute(r#"mutation { createApiToken(name: "grafana") { plaintext } }"#)
            .await;
        assert!(!resp.errors.is_empty(), "duplicate should error");
    }

    #[tokio::test]
    async fn plaintext_only_returned_on_creation() {
        let schema = schema_with_data().await;
        let resp = schema
            .execute(r#"mutation { createApiToken(name: "grafana") { plaintext } }"#)
            .await;
        ok_data(resp);

        // No way to ask for plaintext via the list query — the ApiTokenOutput
        // type doesn't expose it. Asking for it should be a schema error.
        let resp = schema.execute("{ apiTokens { id name plaintext } }").await;
        assert!(!resp.errors.is_empty(), "plaintext must not be queryable");
    }

    #[tokio::test]
    async fn create_with_role_ids_binds_token_to_roles() {
        use crate::rbac::{BuiltInRole, Permission};
        let (schema, pool) = schema_with_pool().await;
        let rbac = RbacStore::new(pool.clone());
        let viewer_id = rbac.builtin_role_id(1, BuiltInRole::Viewer).await.unwrap();

        let resp = schema
            .execute(format!(
                r#"mutation {{ createApiToken(name: "grafana", roleIds: ["{viewer_id}"]) {{
                    token {{ id }}
                }} }}"#
            ))
            .await;
        let data = ok_data(resp);
        let tok_id: i64 = data["createApiToken"]["token"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let principal = rbac.resolve(tok_id, None, 1).await.unwrap();
        assert!(principal.allows(&Permission::new("node:read")));
        assert!(!principal.allows(&Permission::new("rule:write")));
    }

    #[tokio::test]
    async fn create_with_no_role_ids_has_zero_permissions() {
        let (schema, pool) = schema_with_pool().await;
        let resp = schema
            .execute(r#"mutation { createApiToken(name: "bare") { token { id } } }"#)
            .await;
        let data = ok_data(resp);
        let tok_id: i64 = data["createApiToken"]["token"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let rbac = RbacStore::new(pool);
        let principal = rbac.resolve(tok_id, None, 1).await.unwrap();
        assert!(principal.permissions().is_empty());
    }

    #[tokio::test]
    async fn create_rejects_unknown_role_id() {
        let schema = schema_with_data().await;
        let resp = schema
            .execute(
                r#"mutation { createApiToken(name: "x", roleIds: ["999999"]) { token { id } } }"#,
            )
            .await;
        assert!(!resp.errors.is_empty(), "unknown role id must error");
    }
}
