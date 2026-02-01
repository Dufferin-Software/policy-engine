// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Policy Controller Client Library
//!
//! A standalone GraphQL client for communicating with the policy controller.
//! This crate can be used to build applications that interact with the
//! policy controller API.

pub mod client;
pub mod types;

pub use client::{ClientConfig, ControllerClient};
pub use types::*;
