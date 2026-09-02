// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! GraphQL schema and types for the server

mod schema;
mod types;

#[cfg(test)]
mod tests;

pub use schema::*;
pub use types::*;
