// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Library module for policy engine
//!
//! The library is organized into logical submodules:
//! - `server` - Server-only code (BPF management, GraphQL schema, HTTP server)
//! - `types` - Shared BPF and core types
//! - `output` - Output formatting utilities
//! - `traits` - Trait definitions for testability (BpfOperations, NetworkOperations)

// Shared types and utilities (used by both client and server)
pub mod config;
pub mod output;
pub mod paths;
pub mod traits;
pub mod types;

// Server module (only use in server binary)
// Contains BpfManager, GraphQL schema, and HTTP server
pub mod server;

// Shared types used by both server logic and BPF manager
pub mod shared_types {
    pub use crate::server::graphql::InterfaceAttachment;
}

// Re-exports for convenience
pub use paths::*;
pub use traits::*;
pub use types::*;
