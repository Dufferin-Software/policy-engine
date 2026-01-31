//! Policy Engine Server binary
//!
//! GraphQL API server for managing XDP policy rules.
//! Use the separate policy-client binary for CLI operations.

use anyhow::Result;
use clap::Parser;

use policy_engine::server::{run_server, ServerConfig};

/// XDP Policy Engine Server
#[derive(Parser)]
#[command(name = "policy-engine")]
#[command(author, version, about = "XDP Policy Engine GraphQL Server")]
struct Args {
    /// Host address to bind to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Starting Policy Engine GraphQL Server...");
    println!("Host: {}", args.host);
    println!("Port: {}", args.port);
    println!();
    println!("GraphQL Playground: http://{}:{}/playground", args.host, args.port);
    println!("GraphQL Endpoint:   http://{}:{}/graphql", args.host, args.port);
    println!("Health Check:       http://{}:{}/health", args.host, args.port);
    println!();

    let config = ServerConfig {
        host: args.host,
        port: args.port,
    };
    
    run_server(config).await.map_err(|e| anyhow::anyhow!("Server error: {}", e))
}
