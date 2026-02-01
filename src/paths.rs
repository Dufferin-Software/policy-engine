// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

/// BPF pinning directory
pub const BPF_PIN_PATH: &str = "/sys/fs/bpf/policy_engine";

/// Path for the persistent state file (rules, attachments, default actions).
/// Survives reboots; restored when BPF maps are fresh on startup.
pub const STATE_FILE_PATH: &str = "/var/lib/policy-engine/state.json";
