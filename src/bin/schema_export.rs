// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Print the GraphQL schema SDL to stdout.
//!
//! Run with:
//!   cargo run --bin schema_export > web/schema.graphql

fn main() {
    print!("{}", policy_engine::server::graphql::build_schema_sdl());
}
