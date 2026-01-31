//! Client module for the policy engine
//!
//! This module provides the GraphQL client for communicating with
//! the policy engine server.

mod graphql_client;

pub use graphql_client::{PolicyClient, ClientConfig};
