// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Policy Engine Client Library
//!
//! A standalone GraphQL client for communicating with the policy engine server.
//! This crate can be used to build applications that interact with the
//! policy engine API.

pub mod graphql_client;
pub mod output;
pub mod types;

pub use graphql_client::{ClientConfig, PolicyClient};
pub use types::*;
