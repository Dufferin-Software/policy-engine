// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Suricata service coordinator
//!
//! Orchestrates the Suricata service lifecycle: generating AF-XDP config,
//! writing the systemd drop-in, starting/stopping the service, deploying
//! detection rules, and reloading them without a full restart.

use anyhow::{Context, Result};
use log::info;
use std::path::PathBuf;
use std::sync::Arc;

use super::suricata_runtime::{DefaultSuricataRuntime, SuricataRuntime};

const DEFAULT_RULES_DIR: &str = "/etc/suricata/rules/policy-engine";
const DEFAULT_EVE_PATH: &str = "/run/policy-engine/eve.sock";
const DEFAULT_CMD_SOCKET: &str = "/var/run/suricata-command.socket";

/// Metadata for one custom `.rules` file: parsed rule lines plus the raw-byte
/// SHA-256 digest used for fleet drift detection.
#[derive(Debug, Clone)]
pub struct RuleFileMeta {
    pub filename: String,
    /// Non-empty, non-comment rule lines.
    pub rules: Vec<String>,
    /// Hex SHA-256 over the raw file bytes.
    pub sha256: String,
}

/// Status of the Suricata service.
#[derive(Debug, Clone)]
pub struct SuricataStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub version: Option<String>,
}

/// Coordinates with an independently-managed Suricata service.
///
/// `SuricataRuntime` is injected so the coordinator can be unit-tested without
/// touching the real filesystem or calling systemctl.
pub struct SuricataCoordinator {
    runtime: Arc<dyn SuricataRuntime>,
    rules_dir: PathBuf,
    eve_path: PathBuf,
    cmd_socket: PathBuf,
}

impl SuricataCoordinator {
    /// Production constructor — uses `DefaultSuricataRuntime` and standard paths.
    pub fn new() -> Self {
        Self {
            runtime: Arc::new(DefaultSuricataRuntime::new()),
            rules_dir: PathBuf::from(DEFAULT_RULES_DIR),
            eve_path: PathBuf::from(DEFAULT_EVE_PATH),
            cmd_socket: PathBuf::from(DEFAULT_CMD_SOCKET),
        }
    }

    /// Inject a custom runtime (used by unit tests).
    pub fn new_with_runtime(
        runtime: Arc<dyn SuricataRuntime>,
        rules_dir: PathBuf,
        eve_path: PathBuf,
        cmd_socket: PathBuf,
    ) -> Self {
        Self {
            runtime,
            rules_dir,
            eve_path,
            cmd_socket,
        }
    }

    /// Check whether Suricata is currently running.
    pub fn is_running(&self) -> bool {
        self.runtime.is_running()
    }

    /// Return a `SuricataStatus` snapshot.
    pub fn get_status(&self) -> SuricataStatus {
        let running = self.runtime.is_running();
        SuricataStatus {
            running,
            pid: if running {
                self.runtime.get_pid()
            } else {
                None
            },
            version: self.runtime.get_version(),
        }
    }

    /// Write the AF-XDP Suricata YAML config, environment file, and systemd
    /// drop-in for the given veth-peer interface, then restart the service.
    ///
    /// Call this after the veth pair has been created so that `iface` exists.
    pub fn apply_config(&self, iface: &str) -> Result<()> {
        // Pre-create the rules directory so Suricata doesn't log a warning
        // about an unresolvable glob when no rules have been deployed yet.
        let _ = std::fs::create_dir_all(&self.rules_dir);

        self.runtime.write_systemd_env(iface)?;
        // Best-effort restart — Suricata may not be installed.
        if let Err(e) = self.runtime.restart_service() {
            log::warn!("Suricata restart after config write failed: {}", e);
        }
        Ok(())
    }

    /// Remove the generated config and systemd files, then stop the service.
    ///
    /// Must stop, not restart: without the policy-engine drop-in a restart
    /// launches the stock distro unit with the default suricata.yaml
    /// (af-packet on eth0), which crash-loops on hosts without that
    /// interface. Suricata must only run while inspect mode is enabled.
    pub fn remove_config(&self) -> Result<()> {
        self.runtime.remove_systemd_env()?;
        if let Err(e) = self.runtime.stop() {
            log::warn!("Suricata stop after config removal failed: {}", e);
        }
        Ok(())
    }

    /// These two are kept for backward compat with tests that call them directly.
    pub fn write_systemd_env(&self, iface: &str) -> Result<()> {
        self.runtime.write_systemd_env(iface)?;
        self.runtime.restart_service()
    }

    pub fn remove_systemd_env(&self) -> Result<()> {
        self.runtime.remove_systemd_env()?;
        self.runtime.stop()
    }

    /// Start the Suricata systemd service.
    pub fn start(&self) -> Result<()> {
        self.runtime.start()
    }

    /// Stop the Suricata systemd service.
    pub fn stop(&self) -> Result<()> {
        self.runtime.stop()
    }

    /// Enable and start the daily suricata-update timer.
    pub fn enable_update_timer(&self) -> Result<()> {
        self.runtime.enable_update_timer()
    }

    /// Disable and stop the daily suricata-update timer.
    pub fn disable_update_timer(&self) -> Result<()> {
        self.runtime.disable_update_timer()
    }

    /// Write detection rules to the policy-engine rules directory.
    pub fn write_rules(&self, filename: &str, rules: &str) -> Result<()> {
        std::fs::create_dir_all(&self.rules_dir)
            .context("Failed to create Suricata rules directory")?;
        let rule_path = self.rules_dir.join(filename);
        std::fs::write(&rule_path, rules)
            .with_context(|| format!("Failed to write rules to {:?}", rule_path))?;
        info!("Wrote Suricata rules to {:?}", rule_path);
        Ok(())
    }

    /// Signal Suricata to reload its rules without a full restart.
    /// Tries the Unix command socket first, falls back to SIGUSR2.
    pub fn reload_rules(&self) -> Result<()> {
        self.runtime.reload_rules(&self.cmd_socket)
    }

    /// Path to the EVE JSON log (read by `EveConsumer`).
    pub fn eve_path(&self) -> &PathBuf {
        &self.eve_path
    }

    /// Path to the EVE Unix stream socket (listened by `EveConsumer`).
    pub fn eve_socket_path(&self) -> &PathBuf {
        &self.eve_path
    }

    /// Path to the rules directory.
    pub fn rules_dir(&self) -> &PathBuf {
        &self.rules_dir
    }

    /// Return the Suricata binary version string, if available.
    pub fn suricata_version(&self) -> Option<String> {
        self.runtime.get_version()
    }

    /// Return the suricata-update ruleset version/timestamp, if available.
    pub fn ruleset_version(&self) -> Option<String> {
        self.runtime.get_ruleset_version()
    }

    /// List custom `.rules` files deployed to the policy-engine rules directory.
    /// Returns `(filename, rules)` where `rules` is the non-empty, non-comment lines.
    pub fn list_custom_rules(&self) -> Vec<(String, Vec<String>)> {
        self.list_custom_rules_meta()
            .into_iter()
            .map(|m| (m.filename, m.rules))
            .collect()
    }

    /// Like [`list_custom_rules`](Self::list_custom_rules) but also returns
    /// each file's hex SHA-256 digest, computed over the *raw file bytes*
    /// exactly as written by [`write_rules`](Self::write_rules).  This is the
    /// drift-detection contract with the fleet controller: the controller
    /// hashes the bytes it pushes and compares against these digests, so no
    /// canonicalisation may ever be applied on either side.
    pub fn list_custom_rules_meta(&self) -> Vec<RuleFileMeta> {
        let Ok(entries) = std::fs::read_dir(&self.rules_dir) else {
            return vec![];
        };
        let mut files = Vec::new();
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("rules") {
                let name = entry.file_name().to_string_lossy().to_string();
                let Ok(bytes) = std::fs::read(entry.path()) else {
                    continue;
                };
                let sha256 = {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    format!("{:x}", hasher.finalize())
                };
                let rules: Vec<String> = String::from_utf8_lossy(&bytes)
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                    .map(|l| l.to_string())
                    .collect();
                files.push(RuleFileMeta {
                    filename: name,
                    rules,
                    sha256,
                });
            }
        }
        files.sort_by_key(|f| f.filename.clone());
        files
    }

    /// Append a single rule line to `filename` in the rules directory.
    pub fn add_rule(&self, filename: &str, rule: &str) -> Result<()> {
        let trimmed = rule.trim();
        anyhow::ensure!(
            !trimmed.is_empty() && !trimmed.starts_with('#'),
            "Rule must be a non-empty, non-comment Suricata rule"
        );
        std::fs::create_dir_all(&self.rules_dir)
            .context("Failed to create Suricata rules directory")?;
        let path = self.rules_dir.join(filename);
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open {:?}", path))?;
        writeln!(f, "{}", trimmed).with_context(|| format!("Failed to write to {:?}", path))?;
        info!("Added rule to {:?}", path);
        Ok(())
    }

    /// Remove rule lines whose `sid:N;` matches one of the given SIDs.
    pub fn delete_rules_by_sid(&self, filename: &str, sids: &[u32]) -> Result<usize> {
        let path = self.rules_dir.join(filename);
        let content =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {:?}", path))?;
        let before: Vec<&str> = content.lines().collect();
        let after: Vec<&str> = before
            .iter()
            .copied()
            .filter(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return true;
                }
                if let Some(sid) = parse_sid(line) {
                    return !sids.contains(&sid);
                }
                true
            })
            .collect();
        let removed = before.len() - after.len();
        std::fs::write(&path, after.join("\n") + "\n")
            .with_context(|| format!("Failed to write {:?}", path))?;
        info!("Removed {} rule(s) from {:?}", removed, path);
        Ok(removed)
    }

    /// Delete an entire `.rules` file from the rules directory.
    pub fn delete_rule_file(&self, filename: &str) -> Result<()> {
        let path = self.rules_dir.join(filename);
        std::fs::remove_file(&path).with_context(|| format!("Failed to remove {:?}", path))?;
        info!("Deleted rule file {:?}", path);
        Ok(())
    }

    /// Delete all `.rules` files from the policy-engine rules directory.
    pub fn delete_all_custom_rules(&self) -> Result<usize> {
        let Ok(entries) = std::fs::read_dir(&self.rules_dir) else {
            return Ok(0);
        };
        let mut count = 0;
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("rules")
                && std::fs::remove_file(entry.path()).is_ok()
            {
                count += 1;
            }
        }
        info!("Deleted {} custom rule file(s)", count);
        Ok(count)
    }
}

impl Default for SuricataCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_sid(rule: &str) -> Option<u32> {
    // Walk top-level rule keywords (separated by `;`) and look for one whose
    // key is exactly `sid`. This avoids matching `sid:N` substrings that appear
    // inside quoted `content:"..."` values, and also rejects keys like `ssid:`
    // that happen to end in `sid:`.
    //
    // Suricata rules escape `;` inside content with `|3b|`, so a top-level
    // `;`-split is safe for well-formed rules.
    for part in rule.split(';') {
        let trimmed = part.trim_start();
        let Some(rest) = trimmed.strip_prefix("sid:") else {
            continue;
        };
        let digits: &str = rest
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("");
        if let Ok(n) = digits.parse::<u32>() {
            return Some(n);
        }
    }
    None
}
