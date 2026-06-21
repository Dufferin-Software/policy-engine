// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Controller daemon configuration.
///
/// Loaded from a TOML file (default `/etc/policy-controller/config.toml`).
/// CA key and cert are stored in `data_dir` (default `/var/lib/policy-controller`).
#[derive(Debug, Deserialize)]
pub struct ControllerConfig {
    /// Directory for CA key, cert, and controller server cert.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// SQLite database file path.
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    /// HTTP operator API bind address.
    #[serde(default = "default_http_addr")]
    pub http_addr: String,

    /// gRPC enrollment service bind address (TLS, no client cert).
    #[serde(default = "default_enrollment_addr")]
    pub enrollment_addr: String,

    /// gRPC management service bind address (mTLS, client cert required).
    #[serde(default = "default_management_addr")]
    pub management_addr: String,

    /// CA common name (used on first-run CA generation).
    #[serde(default = "default_ca_cn")]
    pub ca_common_name: String,

    /// DNS SAN for the controller's gRPC server certificate.
    #[serde(default = "default_server_san")]
    pub server_san: String,

    /// Node certificate TTL in seconds.
    ///
    /// Default is 90 days. Values shorter than a day are intended for
    /// integration tests of cert renewal — a startup WARN is emitted in that
    /// case, and values below `MIN_NODE_CERT_TTL_SECS` are rejected outright
    /// to avoid an enroll/renew failure storm.
    #[serde(default = "default_node_cert_ttl_secs")]
    pub node_cert_ttl_secs: u64,

    /// Directory containing the built controller web UI (served at `/`).
    /// Set to `None` or omit to disable static file serving (API-only mode).
    #[serde(default = "default_web_root")]
    pub web_root: Option<PathBuf>,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            db_path: default_db_path(),
            http_addr: default_http_addr(),
            enrollment_addr: default_enrollment_addr(),
            management_addr: default_management_addr(),
            ca_common_name: default_ca_cn(),
            server_san: default_server_san(),
            node_cert_ttl_secs: default_node_cert_ttl_secs(),
            web_root: default_web_root(),
        }
    }
}

/// Minimum permitted `node_cert_ttl_secs`. Anything shorter would put the
/// agent renewal task into a tight failure loop and almost certainly indicates
/// a config error rather than an intentional test setting.
pub const MIN_NODE_CERT_TTL_SECS: u64 = 10;

impl ControllerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;
        let cfg: Self = toml::from_str(&text).context("Failed to parse controller config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate cross-field invariants that `serde` can't enforce alone.
    /// Called from `load` and from any test helper that bypasses `load`.
    pub fn validate(&self) -> Result<()> {
        if self.node_cert_ttl_secs < MIN_NODE_CERT_TTL_SECS {
            anyhow::bail!(
                "node_cert_ttl_secs={} is below the minimum of {}s — \
                 a TTL this short would cause continuous renewal failures",
                self.node_cert_ttl_secs,
                MIN_NODE_CERT_TTL_SECS
            );
        }
        if self.node_cert_ttl_secs < 86_400 {
            log::warn!(
                "node_cert_ttl_secs={} is shorter than a day — \
                 only intended for integration tests of cert renewal",
                self.node_cert_ttl_secs
            );
        }
        Ok(())
    }

    pub fn ca_key_path(&self) -> PathBuf {
        self.data_dir.join("ca.key")
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.data_dir.join("ca.crt")
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/policy-controller")
}

fn default_db_path() -> PathBuf {
    PathBuf::from("/var/lib/policy-controller/controller.db")
}

fn default_http_addr() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_enrollment_addr() -> String {
    "0.0.0.0:7776".to_string()
}

fn default_management_addr() -> String {
    "0.0.0.0:7777".to_string()
}

fn default_ca_cn() -> String {
    "Policy Controller CA".to_string()
}

fn default_server_san() -> String {
    "controller.local".to_string()
}

fn default_node_cert_ttl_secs() -> u64 {
    90 * 86_400
}

fn default_web_root() -> Option<PathBuf> {
    // Installed package path.
    let installed = PathBuf::from("/usr/share/policy-controller/web");
    if installed.join("index.html").is_file() {
        return Some(installed);
    }

    // Development: look for web/dist relative to the executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            for candidate in [
                parent.join("../../policy-controller/web/dist"),
                parent.join("../policy-controller/web/dist"),
            ] {
                if let Ok(canon) = candidate.canonicalize() {
                    if canon.join("index.html").is_file() {
                        return Some(canon);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = ControllerConfig::default();
        assert_eq!(cfg.http_addr, "0.0.0.0:8443");
        assert_eq!(cfg.node_cert_ttl_secs, 90 * 86_400);
        assert_eq!(cfg.enrollment_addr, "0.0.0.0:7776");
        assert_eq!(cfg.management_addr, "0.0.0.0:7777");
    }

    #[test]
    fn test_validate_rejects_ttl_below_minimum() {
        let cfg = ControllerConfig {
            node_cert_ttl_secs: MIN_NODE_CERT_TTL_SECS - 1,
            ..Default::default()
        };
        assert!(
            cfg.validate().is_err(),
            "ttl below MIN_NODE_CERT_TTL_SECS must be rejected"
        );
    }

    #[test]
    fn test_validate_accepts_short_but_above_minimum() {
        let cfg = ControllerConfig {
            node_cert_ttl_secs: 60,
            ..Default::default()
        };
        cfg.validate()
            .expect("60s TTL is allowed (test mode), only WARN-logged");
    }

    #[test]
    fn test_ca_paths() {
        let cfg = ControllerConfig::default();
        assert_eq!(
            cfg.ca_key_path(),
            PathBuf::from("/var/lib/policy-controller/ca.key")
        );
        assert_eq!(
            cfg.ca_cert_path(),
            PathBuf::from("/var/lib/policy-controller/ca.crt")
        );
    }
}
