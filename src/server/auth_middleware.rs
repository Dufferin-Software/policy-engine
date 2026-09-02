// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Request authentication middleware for actix-web.
//!
//! The [`AuthProvider`] trait abstracts the authentication decision so that
//! different schemes (Bearer token, JWT, mTLS, API key, …) can be plugged in
//! without changing the middleware itself.
//!
//! Provided implementations:
//! - [`BearerTokenAuth`] — validates a static `Authorization: Bearer <token>` header.
//! - [`AllowAll`] — permits every request; used when auth is disabled and in tests.

use std::sync::Arc;

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web, Error, HttpResponse,
};

// ---------------------------------------------------------------------------
// AuthProvider trait
// ---------------------------------------------------------------------------

/// Trait for authentication backends.
///
/// The middleware calls [`is_authorized`](AuthProvider::is_authorized) with the
/// raw value of the `Authorization` header (if present). Implementors return
/// `true` to allow the request or `false` to reject it with HTTP 401.
pub trait AuthProvider: Send + Sync {
    /// Return `true` if the request carrying `auth_header` should be allowed.
    ///
    /// `auth_header` is the raw value of the HTTP `Authorization` header, or
    /// `None` if the header was absent or could not be decoded as UTF-8.
    fn is_authorized(&self, auth_header: Option<&str>) -> bool;
}

// ---------------------------------------------------------------------------
// BearerTokenAuth
// ---------------------------------------------------------------------------

/// Validates a static `Authorization: Bearer <token>` header.
pub struct BearerTokenAuth {
    expected: String,
}

impl BearerTokenAuth {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            expected: token.into(),
        }
    }
}

impl AuthProvider for BearerTokenAuth {
    fn is_authorized(&self, auth_header: Option<&str>) -> bool {
        auth_header
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|t| t == self.expected)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// AllowAll
// ---------------------------------------------------------------------------

/// Permits every request unconditionally.
///
/// Used when `POLICY_ENGINE_API_TOKEN` is not set and in unit tests that do
/// not need to exercise authentication.
pub struct AllowAll;

impl AuthProvider for AllowAll {
    fn is_authorized(&self, _auth_header: Option<&str>) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Middleware function
// ---------------------------------------------------------------------------

/// actix-web middleware that delegates auth decisions to an [`AuthProvider`].
///
/// The provider is read from `web::Data<Arc<dyn AuthProvider>>` registered on
/// the application.  The `/health` path is always bypassed.
pub async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    // Health check is always public regardless of auth configuration.
    if req.path() == "/health" {
        return next.call(req).await.map(|r| r.map_into_boxed_body());
    }

    let provider = req.app_data::<web::Data<Arc<dyn AuthProvider>>>().cloned();

    let auth_header = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let authorized = provider
        .as_ref()
        .map(|p| p.is_authorized(auth_header))
        .unwrap_or(true); // no provider registered → allow (open dev mode)

    if authorized {
        next.call(req).await.map(|r| r.map_into_boxed_body())
    } else {
        let response = HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "unauthorized",
            "message": "Missing or invalid Bearer token"
        }));
        Ok(req.into_response(response).map_into_boxed_body())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use actix_web::middleware::from_fn;
    use actix_web::{test as actix_test, web, App, HttpResponse};

    use super::*;

    async fn ok_handler() -> HttpResponse {
        HttpResponse::Ok().body("ok")
    }

    fn app_with_provider(provider: Arc<dyn AuthProvider>) -> web::Data<Arc<dyn AuthProvider>> {
        web::Data::new(provider)
    }

    // --- AllowAll ---

    #[actix_web::test]
    async fn allow_all_permits_any_request() {
        let app = actix_test::init_service(
            App::new()
                .app_data(app_with_provider(Arc::new(AllowAll)))
                .wrap(from_fn(auth_middleware))
                .route("/graphql", web::post().to(ok_handler)),
        )
        .await;
        let req = actix_test::TestRequest::post().uri("/graphql").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn no_provider_registered_allows_all() {
        // Simulates dev mode where no Data<Arc<dyn AuthProvider>> is set.
        let app = actix_test::init_service(
            App::new()
                .wrap(from_fn(auth_middleware))
                .route("/graphql", web::post().to(ok_handler)),
        )
        .await;
        let req = actix_test::TestRequest::post().uri("/graphql").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    // --- Health bypass ---

    #[actix_web::test]
    async fn health_is_always_public_with_bearer_auth() {
        let app = actix_test::init_service(
            App::new()
                .app_data(app_with_provider(Arc::new(BearerTokenAuth::new("secret"))))
                .wrap(from_fn(auth_middleware))
                .route("/health", web::get().to(ok_handler)),
        )
        .await;
        let req = actix_test::TestRequest::get().uri("/health").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    // --- BearerTokenAuth ---

    #[actix_web::test]
    async fn valid_bearer_token_allows_request() {
        let app = actix_test::init_service(
            App::new()
                .app_data(app_with_provider(Arc::new(BearerTokenAuth::new(
                    "secret123",
                ))))
                .wrap(from_fn(auth_middleware))
                .route("/metrics", web::get().to(ok_handler)),
        )
        .await;
        let req = actix_test::TestRequest::get()
            .uri("/metrics")
            .insert_header(("Authorization", "Bearer secret123"))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn missing_token_returns_401() {
        let app = actix_test::init_service(
            App::new()
                .app_data(app_with_provider(Arc::new(BearerTokenAuth::new(
                    "secret123",
                ))))
                .wrap(from_fn(auth_middleware))
                .route("/metrics", web::get().to(ok_handler)),
        )
        .await;
        let req = actix_test::TestRequest::get().uri("/metrics").to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn wrong_token_returns_401() {
        let app = actix_test::init_service(
            App::new()
                .app_data(app_with_provider(Arc::new(BearerTokenAuth::new(
                    "secret123",
                ))))
                .wrap(from_fn(auth_middleware))
                .route("/metrics", web::get().to(ok_handler)),
        )
        .await;
        let req = actix_test::TestRequest::get()
            .uri("/metrics")
            .insert_header(("Authorization", "Bearer wrong"))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    // --- BearerTokenAuth unit tests (no HTTP layer) ---

    #[test]
    fn bearer_auth_accepts_correct_token() {
        let auth = BearerTokenAuth::new("mytoken");
        assert!(auth.is_authorized(Some("Bearer mytoken")));
    }

    #[test]
    fn bearer_auth_rejects_wrong_token() {
        let auth = BearerTokenAuth::new("mytoken");
        assert!(!auth.is_authorized(Some("Bearer wrong")));
    }

    #[test]
    fn bearer_auth_rejects_missing_header() {
        let auth = BearerTokenAuth::new("mytoken");
        assert!(!auth.is_authorized(None));
    }

    #[test]
    fn bearer_auth_rejects_malformed_header() {
        let auth = BearerTokenAuth::new("mytoken");
        assert!(!auth.is_authorized(Some("Basic dXNlcjpwYXNz")));
    }
}
