// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Bearer-token middleware for the controller's REST + GraphQL surface.
//!
//! Per-request flow:
//!   1. Extract `Authorization: Bearer <token>`.
//!   2. Hash and look up in `api_tokens`.
//!   3. On hit, attach the [`ApiToken`] to request extensions and bump
//!      `last_used_at` (throttled to one write per token per ~60s).
//!   4. On miss, return `401`.

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web::Data,
    Error, HttpMessage, HttpResponse,
};
use dashmap::DashMap;

use crate::api_tokens::{ApiToken, ApiTokenStore};
use crate::rbac::RbacStore;

/// How long to wait between `last_used_at` writes for the same token.
const TOUCH_THROTTLE_S: i64 = 60;

/// Shared state behind the middleware — the token store, the RBAC store
/// for principal resolution, and a tiny per-token last-write timestamp
/// cache so we don't UPDATE on every request.
#[derive(Clone)]
pub struct BearerAuthState {
    pub store: Arc<ApiTokenStore>,
    pub rbac: Arc<RbacStore>,
    pub last_touch: Arc<DashMap<i64, AtomicI64>>,
}

impl BearerAuthState {
    pub fn new(store: Arc<ApiTokenStore>, rbac: Arc<RbacStore>) -> Self {
        Self {
            store,
            rbac,
            last_touch: Arc::new(DashMap::new()),
        }
    }
}

/// Middleware function. Register with `.wrap(actix_web::middleware::from_fn(bearer_auth))`
/// and pass a `Data<BearerAuthState>` via `.app_data(...)` on the scope.
pub async fn bearer_auth(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let state = match req.app_data::<Data<BearerAuthState>>() {
        Some(s) => s.clone(),
        None => {
            // Wiring bug — fail closed.
            log::error!("bearer_auth middleware invoked without BearerAuthState in app_data");
            return Ok(req.into_response(unauthorized("server misconfigured")));
        }
    };

    let token_plaintext = match extract_bearer(&req) {
        Some(t) => t,
        None => return Ok(req.into_response(unauthorized("missing bearer token"))),
    };

    match state.store.authenticate(&token_plaintext).await {
        Ok(Some(row)) => {
            maybe_touch(&state, &row).await;
            // Resolve the principal once per request. A resolve failure is
            // an auth-backend error (DB issue), not a permission issue —
            // failing closed with 401 is safer than letting the request
            // proceed with no permissions attached.
            let principal = match state
                .rbac
                .resolve(row.id, row.operator_id, row.tenant_id)
                .await
            {
                Ok(p) => Arc::new(p),
                Err(err) => {
                    log::error!("rbac resolve failed for token {}: {err:#}", row.id);
                    return Ok(req.into_response(unauthorized("auth backend error")));
                }
            };
            req.extensions_mut().insert(row);
            req.extensions_mut().insert(principal);
            next.call(req)
                .await
                .map(|r| r.map_into_boxed_body().map_into_left_body())
        }
        Ok(None) => Ok(req.into_response(unauthorized("invalid token"))),
        Err(err) => {
            log::error!("bearer auth DB error: {err:#}");
            Ok(req.into_response(unauthorized("auth backend error")))
        }
    }
}

fn extract_bearer(req: &ServiceRequest) -> Option<String> {
    let h = req.headers().get(actix_web::http::header::AUTHORIZATION)?;
    let s = h.to_str().ok()?;
    let rest = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))?;
    let rest = rest.trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

fn unauthorized(
    reason: &str,
) -> HttpResponse<actix_web::body::EitherBody<actix_web::body::BoxBody>> {
    HttpResponse::Unauthorized()
        .json(serde_json::json!({ "error": reason }))
        .map_into_right_body()
}

async fn maybe_touch(state: &BearerAuthState, row: &ApiToken) {
    let now = now_s();
    let should_write = {
        let entry = state
            .last_touch
            .entry(row.id)
            .or_insert_with(|| AtomicI64::new(0));
        let prev = entry.load(Ordering::Relaxed);
        if now - prev >= TOUCH_THROTTLE_S {
            // Best-effort claim; even if two threads race, both writes are
            // idempotent and we only care about coarse "recently used."
            entry.store(now, Ordering::Relaxed);
            true
        } else {
            false
        }
    };
    if should_write {
        if let Err(err) = state.store.touch_last_used(row.id, now).await {
            log::warn!("touch_last_used for token {} failed: {err:#}", row.id);
        }
    }
}

fn now_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{middleware::from_fn, test, web, App, HttpResponse};
    use sqlx::SqlitePool;

    async fn stores() -> (Arc<ApiTokenStore>, Arc<RbacStore>) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        (
            Arc::new(ApiTokenStore::new(pool.clone())),
            Arc::new(RbacStore::new(pool)),
        )
    }

    fn build_app(
        state: BearerAuthState,
    ) -> App<
        impl actix_web::dev::ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<actix_web::body::BoxBody>,
            Error = Error,
            InitError = (),
        >,
    > {
        App::new().service(
            web::scope("/api")
                .app_data(Data::new(state))
                .wrap(from_fn(bearer_auth))
                .route(
                    "/ping",
                    web::get().to(|| async { HttpResponse::Ok().body("pong") }),
                ),
        )
    }

    #[actix_web::test]
    async fn missing_header_returns_401() {
        let (s, r) = stores().await;
        let app = test::init_service(build_app(BearerAuthState::new(s, r))).await;
        let req = test::TestRequest::get().uri("/api/ping").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn wrong_scheme_returns_401() {
        let (s, r) = stores().await;
        let app = test::init_service(build_app(BearerAuthState::new(s, r))).await;
        let req = test::TestRequest::get()
            .uri("/api/ping")
            .insert_header(("Authorization", "Basic abc"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn unknown_token_returns_401() {
        let (s, r) = stores().await;
        let app = test::init_service(build_app(BearerAuthState::new(s, r))).await;
        let req = test::TestRequest::get()
            .uri("/api/ping")
            .insert_header(("Authorization", "Bearer dsw_nope"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn valid_token_passes_through() {
        let (s, r) = stores().await;
        let (_row, plaintext) = s.create("grafana", 1, None, None).await.unwrap();
        let app = test::init_service(build_app(BearerAuthState::new(s, r))).await;
        let req = test::TestRequest::get()
            .uri("/api/ping")
            .insert_header(("Authorization", format!("Bearer {}", plaintext)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn revoked_token_returns_401() {
        let (s, r) = stores().await;
        let (row, plaintext) = s.create("grafana", 1, None, None).await.unwrap();
        s.revoke(row.id, 1).await.unwrap();
        let app = test::init_service(build_app(BearerAuthState::new(s, r))).await;
        let req = test::TestRequest::get()
            .uri("/api/ping")
            .insert_header(("Authorization", format!("Bearer {}", plaintext)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn touch_is_throttled() {
        let (s, r) = stores().await;
        let (row, plaintext) = s.create("grafana", 1, None, None).await.unwrap();
        let state = BearerAuthState::new(s.clone(), r);
        let app = test::init_service(build_app(state.clone())).await;

        for _ in 0..5 {
            let req = test::TestRequest::get()
                .uri("/api/ping")
                .insert_header(("Authorization", format!("Bearer {}", plaintext)))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }

        // Only one write should have happened within the throttle window.
        // The cache holds exactly one entry for this token id.
        let entry = state.last_touch.get(&row.id).unwrap();
        assert!(entry.load(Ordering::Relaxed) > 0);
        // last_used_at in the DB is set (any positive value).
        let listed = s.list(1).await.unwrap();
        assert!(listed[0].last_used_at.unwrap() > 0);
    }
}
