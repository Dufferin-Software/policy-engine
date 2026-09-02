// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

mod flow_verdict_cache_tests;
mod quic_initial_inspect_tests;

#[cfg(feature = "suricata")]
mod suricata_coordinator_tests;
#[cfg(feature = "suricata")]
mod suricata_runtime_tests;
#[cfg(feature = "suricata")]
mod veth_manager_tests;
