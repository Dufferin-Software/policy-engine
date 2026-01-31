//! Server module - BPF management, GraphQL schema, and HTTP server
//!
//! This module contains all server-side functionality:
//! - BPF program loading and management
//! - GraphQL schema and resolvers
//! - HTTP server setup

mod bpf_manager;
pub mod graphql;
mod http;

pub use bpf_manager::BpfManager;
pub use http::{run_server, ServerConfig};
