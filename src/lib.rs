//! Library module for policy engine
//!
//! The library is organized into logical submodules:
//! - `server` - Server-only code (BPF management, GraphQL schema, HTTP server)
//! - `client` - Client-only code (GraphQL HTTP client)  
//! - `types` - Shared BPF and core types
//! - `shared_types` - Shared GraphQL types for client/server serialization
//! - `output` - Output formatting utilities

// Shared types and utilities (used by both client and server)
pub mod types;
pub mod shared_types;
pub mod output;

// Server module (only use in server binary)
// Contains BpfManager, GraphQL schema, and HTTP server
pub mod server;

// Client module (only use in client binary)
// Contains GraphQL HTTP client
pub mod client;

// Re-exports for convenience
pub use types::*;
pub use shared_types::*;

