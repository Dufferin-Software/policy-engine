//! HTTP server for the GraphQL API

use std::sync::Arc;

use actix_web::{web, App, HttpResponse, HttpServer, Result as ActixResult};
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};
use log::info;

use super::bpf_manager::BpfManager;
use super::graphql::{build_schema, AppState, PolicyEngineSchema};

/// GraphQL endpoint handler
async fn graphql_handler(schema: web::Data<PolicyEngineSchema>, req: GraphQLRequest) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

/// GraphQL Playground handler (for development/testing)
async fn graphql_playground() -> ActixResult<HttpResponse> {
    let source = playground_source(GraphQLPlaygroundConfig::new("/graphql"));
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(source))
}

/// Health check endpoint
async fn health_check() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

/// Server configuration
#[derive(Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}

/// Start the GraphQL server
pub async fn run_server(config: ServerConfig) -> std::io::Result<()> {
    // Check for root privileges (required for BPF operations)
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Error: This program requires root privileges to load BPF programs");
        std::process::exit(1);
    }

    // Initialize the BPF manager
    let manager = BpfManager::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Create shared state
    let state = Arc::new(AppState::new(manager));

    // Build GraphQL schema
    let schema = build_schema(state);

    info!(
        "Starting GraphQL server at http://{}:{}",
        config.host, config.port
    );
    info!(
        "GraphQL Playground available at http://{}:{}/playground",
        config.host, config.port
    );

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(schema.clone()))
            .route("/graphql", web::post().to(graphql_handler))
            .route("/graphql", web::get().to(graphql_handler))
            .route("/playground", web::get().to(graphql_playground))
            .route("/health", web::get().to(health_check))
    })
    .bind((config.host.as_str(), config.port))?
    .run()
    .await
}
