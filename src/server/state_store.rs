// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Persistent state storage for policy-engine.
//!
//! Abstracts storage behind a `StateStore` trait so the production file-based
//! implementation can be swapped for an in-memory mock in tests, or replaced
//! with a different backend (e.g. Postgres) in future without touching service
//! logic.
//!
//! ## Why a whole-file write instead of per-record updates?
//!
//! Rule sets are small (tens to low hundreds of entries).  Writing the entire
//! JSON state on every mutation is fast, keeps the file human-readable and
//! diff-friendly, and eliminates partial-write corruption with a simple
//! write-to-temp + `rename()` atomic swap.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::server::policy_service::AddRuleParams;
use crate::types::{Direction, PolicyAction, StopBehavior, XdpMode};

// ── Persisted data types ─────────────────────────────────────────────────────

/// A rule as stored on disk.  The `id` field ensures the same rule ID is
/// reproduced on restore so rule-stats references remain valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedRule {
    pub id: u64,
    /// Full rule parameters, serialised as-is via serde.
    /// Unknown fields from newer versions are silently ignored on load
    /// (`#[serde(default)]` on `AddRuleParams` fields handles missing ones).
    pub params: AddRuleParams,
}

/// An interface attachment as stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedAttachment {
    pub interface: String,
    pub direction: Direction,
    /// XDP mode for ingress attachments; `None` for TC egress.
    pub mode: Option<XdpMode>,
}

/// A persisted per-interface default action entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedDefaultAction {
    pub interface: String,
    pub direction: Direction,
    pub action: PolicyAction,
}

/// The complete persisted state written as a single JSON document.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedState {
    /// Schema version — increment if the structure changes in a breaking way.
    pub version: u32,
    pub rules: Vec<PersistedRule>,
    pub attachments: Vec<PersistedAttachment>,
    /// Per-interface default actions.  Absent entry → BPF default (PASS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub iface_default_actions: Vec<PersistedDefaultAction>,
    /// What to do with BPF programs and maps when the daemon stops.
    #[serde(default)]
    pub stop_behavior: StopBehavior,
    /// Suricata inspect mode: "ips" / "ids"; `None` = disabled.
    ///
    /// Deliberately NOT feature-gated: a state.json written by an -ips build
    /// must survive a serde round-trip on a plain build unchanged.  Only the
    /// restore *action* is gated behind the suricata feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspect_mode: Option<String>,
    /// Interfaces with per-interface Suricata inspection enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inspect_interfaces: Vec<String>,
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Storage abstraction for persisting policy-engine state across reboots.
///
/// All methods are synchronous; the rule set is small enough that blocking
/// file I/O is acceptable.
pub trait StateStore: Send + Sync {
    // ── Rules ────────────────────────────────────────────────────────────────

    fn save_rule(&self, id: u64, params: &AddRuleParams) -> Result<()>;
    fn delete_rule(&self, id: u64) -> Result<()>;
    /// Remove all persisted rules for `direction` (called on `flush_rules`).
    fn clear_rules(&self, direction: Direction) -> Result<()>;
    fn load_rules(&self) -> Result<Vec<PersistedRule>>;

    // ── Attachments ──────────────────────────────────────────────────────────

    fn save_attachment(
        &self,
        iface: &str,
        direction: Direction,
        mode: Option<XdpMode>,
    ) -> Result<()>;
    fn delete_attachment(&self, iface: &str, direction: Direction) -> Result<()>;
    fn load_attachments(&self) -> Result<Vec<PersistedAttachment>>;

    // ── Default actions ──────────────────────────────────────────────────────

    fn save_default_action(
        &self,
        iface: &str,
        direction: Direction,
        action: PolicyAction,
    ) -> Result<()>;
    fn delete_default_action(&self, iface: &str, direction: Direction) -> Result<()>;
    fn load_default_actions(&self) -> Result<Vec<PersistedDefaultAction>>;

    // ── Stop behaviour ───────────────────────────────────────────────────────

    fn save_stop_behavior(&self, behavior: StopBehavior) -> Result<()>;
    fn load_stop_behavior(&self) -> Result<StopBehavior>;

    // ── Inspect (Suricata) state ─────────────────────────────────────────────
    // Not feature-gated: plain builds must preserve inspect state written by
    // an -ips build (they just never act on it).

    /// Persist the node-global inspect mode ("ips"/"ids"; `None` = disabled).
    fn save_inspect_mode(&self, mode: Option<String>) -> Result<()>;
    /// Persist the enabled/disabled state of one inspect interface.
    fn save_inspect_interface(&self, iface: &str, enabled: bool) -> Result<()>;
    /// Load the persisted inspect state as (mode, enabled interfaces).
    fn load_inspect_state(&self) -> Result<(Option<String>, Vec<String>)>;
}

// ── InMemoryStateStore (tests) ────────────────────────────────────────────────

/// Non-persistent, in-memory implementation used in unit tests.
#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    state: Mutex<PersistedState>,
}

impl InMemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for InMemoryStateStore {
    fn save_rule(&self, id: u64, params: &AddRuleParams) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        // Upsert by id
        s.rules.retain(|r| r.id != id);
        s.rules.push(PersistedRule {
            id,
            params: params.clone(),
        });
        Ok(())
    }

    fn delete_rule(&self, id: u64) -> Result<()> {
        self.state.lock().unwrap().rules.retain(|r| r.id != id);
        Ok(())
    }

    fn clear_rules(&self, direction: Direction) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .rules
            .retain(|r| r.params.direction != direction);
        Ok(())
    }

    fn load_rules(&self) -> Result<Vec<PersistedRule>> {
        Ok(self.state.lock().unwrap().rules.clone())
    }

    fn save_attachment(
        &self,
        iface: &str,
        direction: Direction,
        mode: Option<XdpMode>,
    ) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.attachments
            .retain(|a| !(a.interface == iface && a.direction == direction));
        s.attachments.push(PersistedAttachment {
            interface: iface.to_string(),
            direction,
            mode,
        });
        Ok(())
    }

    fn delete_attachment(&self, iface: &str, direction: Direction) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .attachments
            .retain(|a| !(a.interface == iface && a.direction == direction));
        Ok(())
    }

    fn load_attachments(&self) -> Result<Vec<PersistedAttachment>> {
        Ok(self.state.lock().unwrap().attachments.clone())
    }

    fn save_default_action(
        &self,
        iface: &str,
        direction: Direction,
        action: PolicyAction,
    ) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.iface_default_actions
            .retain(|d| !(d.interface == iface && d.direction == direction));
        s.iface_default_actions.push(PersistedDefaultAction {
            interface: iface.to_string(),
            direction,
            action,
        });
        Ok(())
    }

    fn delete_default_action(&self, iface: &str, direction: Direction) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .iface_default_actions
            .retain(|d| !(d.interface == iface && d.direction == direction));
        Ok(())
    }

    fn load_default_actions(&self) -> Result<Vec<PersistedDefaultAction>> {
        Ok(self.state.lock().unwrap().iface_default_actions.clone())
    }

    fn save_stop_behavior(&self, behavior: StopBehavior) -> Result<()> {
        self.state.lock().unwrap().stop_behavior = behavior;
        Ok(())
    }

    fn load_stop_behavior(&self) -> Result<StopBehavior> {
        Ok(self.state.lock().unwrap().stop_behavior)
    }

    fn save_inspect_mode(&self, mode: Option<String>) -> Result<()> {
        self.state.lock().unwrap().inspect_mode = mode;
        Ok(())
    }

    fn save_inspect_interface(&self, iface: &str, enabled: bool) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.inspect_interfaces.retain(|i| i != iface);
        if enabled {
            s.inspect_interfaces.push(iface.to_string());
        }
        Ok(())
    }

    fn load_inspect_state(&self) -> Result<(Option<String>, Vec<String>)> {
        let s = self.state.lock().unwrap();
        Ok((s.inspect_mode.clone(), s.inspect_interfaces.clone()))
    }
}

// ── FileStateStore (production) ───────────────────────────────────────────────

/// File-backed implementation.  Maintains an in-memory mirror of the JSON
/// state and atomically overwrites the file on every mutation.
///
/// Atomic write: serialise to `<path>.tmp`, then `rename()` — POSIX guarantees
/// rename is atomic within the same filesystem, so a crash mid-write leaves
/// the old file intact.
pub struct FileStateStore {
    path: PathBuf,
    state: Mutex<PersistedState>,
}

impl FileStateStore {
    /// Open (or create) the state file at `path`.
    ///
    /// If the file exists it is loaded; if it is missing or unparseable a
    /// fresh empty state is used and a warning is logged.
    pub fn new(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let state = Self::load_from_disk(&path).unwrap_or_else(|e| {
            warn!(
                "state_store: failed to load {}: {:#} — starting fresh",
                path.display(),
                e
            );
            PersistedState::default()
        });
        Self {
            path,
            state: Mutex::new(state),
        }
    }

    fn load_from_disk(path: &Path) -> Result<PersistedState> {
        let data =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))
    }

    fn persist(&self, state: &PersistedState) -> Result<()> {
        let json = serde_json::to_string_pretty(state).context("serialising state")?;

        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &json)
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &self.path).with_context(|| {
            format!("renaming {} -> {}", tmp_path.display(), self.path.display())
        })?;

        Ok(())
    }
}

impl StateStore for FileStateStore {
    fn save_rule(&self, id: u64, params: &AddRuleParams) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.rules.retain(|r| r.id != id);
        s.rules.push(PersistedRule {
            id,
            params: params.clone(),
        });
        self.persist(&s)
    }

    fn delete_rule(&self, id: u64) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.rules.retain(|r| r.id != id);
        self.persist(&s)
    }

    fn clear_rules(&self, direction: Direction) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.rules.retain(|r| r.params.direction != direction);
        self.persist(&s)
    }

    fn load_rules(&self) -> Result<Vec<PersistedRule>> {
        Ok(self.state.lock().unwrap().rules.clone())
    }

    fn save_attachment(
        &self,
        iface: &str,
        direction: Direction,
        mode: Option<XdpMode>,
    ) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.attachments
            .retain(|a| !(a.interface == iface && a.direction == direction));
        s.attachments.push(PersistedAttachment {
            interface: iface.to_string(),
            direction,
            mode,
        });
        self.persist(&s)
    }

    fn delete_attachment(&self, iface: &str, direction: Direction) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.attachments
            .retain(|a| !(a.interface == iface && a.direction == direction));
        self.persist(&s)
    }

    fn load_attachments(&self) -> Result<Vec<PersistedAttachment>> {
        Ok(self.state.lock().unwrap().attachments.clone())
    }

    fn save_default_action(
        &self,
        iface: &str,
        direction: Direction,
        action: PolicyAction,
    ) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.iface_default_actions
            .retain(|d| !(d.interface == iface && d.direction == direction));
        s.iface_default_actions.push(PersistedDefaultAction {
            interface: iface.to_string(),
            direction,
            action,
        });
        self.persist(&s)
    }

    fn delete_default_action(&self, iface: &str, direction: Direction) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.iface_default_actions
            .retain(|d| !(d.interface == iface && d.direction == direction));
        self.persist(&s)
    }

    fn load_default_actions(&self) -> Result<Vec<PersistedDefaultAction>> {
        Ok(self.state.lock().unwrap().iface_default_actions.clone())
    }

    fn save_stop_behavior(&self, behavior: StopBehavior) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.stop_behavior = behavior;
        self.persist(&s)
    }

    fn load_stop_behavior(&self) -> Result<StopBehavior> {
        Ok(self.state.lock().unwrap().stop_behavior)
    }

    fn save_inspect_mode(&self, mode: Option<String>) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.inspect_mode = mode;
        self.persist(&s)
    }

    fn save_inspect_interface(&self, iface: &str, enabled: bool) -> Result<()> {
        let mut s = self.state.lock().unwrap();
        s.inspect_interfaces.retain(|i| i != iface);
        if enabled {
            s.inspect_interfaces.push(iface.to_string());
        }
        self.persist(&s)
    }

    fn load_inspect_state(&self) -> Result<(Option<String>, Vec<String>)> {
        let s = self.state.lock().unwrap();
        Ok((s.inspect_mode.clone(), s.inspect_interfaces.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state.json written before the inspect fields existed must load with
    /// inspect disabled — and one written by an -ips build must round-trip
    /// through (de)serialisation unchanged even though the fields are unknown
    /// to older readers of this struct.
    #[test]
    fn persisted_state_backcompat_without_inspect_fields() {
        let json = r#"{"version":1,"rules":[],"attachments":[]}"#;
        let s: PersistedState = serde_json::from_str(json).unwrap();
        assert!(s.inspect_mode.is_none());
        assert!(s.inspect_interfaces.is_empty());
    }

    #[test]
    fn persisted_state_inspect_fields_roundtrip() {
        let mut s = PersistedState {
            version: 1,
            ..Default::default()
        };
        s.inspect_mode = Some("ids".to_string());
        s.inspect_interfaces = vec!["eth0".to_string(), "eth1".to_string()];
        let json = serde_json::to_string(&s).unwrap();
        let back: PersistedState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.inspect_mode.as_deref(), Some("ids"));
        assert_eq!(back.inspect_interfaces, s.inspect_interfaces);
    }

    /// Simulated daemon restart: a fresh FileStateStore over the same path
    /// must see the inspect state exactly as the previous instance left it.
    #[test]
    fn file_store_inspect_state_survives_reopen() {
        let mut path = std::env::temp_dir();
        path.push(format!("pe_state_store_test_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        {
            let store = FileStateStore::new(&path);
            store.save_inspect_mode(Some("ips".to_string())).unwrap();
            store.save_inspect_interface("eth0", true).unwrap();
            store.save_inspect_interface("eth1", true).unwrap();
            store.save_inspect_interface("eth0", false).unwrap();
        }

        let store = FileStateStore::new(&path);
        let (mode, interfaces) = store.load_inspect_state().unwrap();
        assert_eq!(mode.as_deref(), Some("ips"));
        assert_eq!(interfaces, vec!["eth1".to_string()]);

        // Clearing the mode persists too.
        store.save_inspect_mode(None).unwrap();
        let store = FileStateStore::new(&path);
        let (mode, interfaces) = store.load_inspect_state().unwrap();
        assert!(mode.is_none());
        assert_eq!(interfaces, vec!["eth1".to_string()]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn in_memory_store_inspect_state_roundtrip() {
        let store = InMemoryStateStore::new();
        store.save_inspect_mode(Some("ids".to_string())).unwrap();
        store.save_inspect_interface("eth2", true).unwrap();
        assert_eq!(
            store.load_inspect_state().unwrap(),
            (Some("ids".to_string()), vec!["eth2".to_string()])
        );
        store.save_inspect_interface("eth2", false).unwrap();
        assert_eq!(
            store.load_inspect_state().unwrap(),
            (Some("ids".to_string()), Vec::new())
        );
    }
}
