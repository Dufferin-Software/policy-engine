// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/policy-node-agent/config.toml";
pub const DEFAULT_IDENTITY_KEY_PATH: &str = "/var/lib/policy-node-agent/identity.key";
pub const DEFAULT_CLIENT_CERT_PATH: &str = "/var/lib/policy-node-agent/controller-client.crt";
pub const DEFAULT_CLIENT_KEY_PATH: &str = "/var/lib/policy-node-agent/controller-client.key";
// CA cert is *runtime state* owned by the agent (persisted from enrollment),
// not operator config — it lives in StateDirectory (/var/lib/...) which the
// systemd unit makes writable. /etc/ is read-only under `ProtectSystem=strict`.
pub const DEFAULT_CA_CERT_PATH: &str = "/var/lib/policy-node-agent/controller-ca.crt";
pub const DEFAULT_ENDPOINTS_PATH: &str = "/var/lib/policy-node-agent/endpoints.json";
pub const DEFAULT_RENEWAL_COUNTER_PATH: &str = "/var/lib/policy-node-agent/renewal-counter";
pub const DEFAULT_BOOTSTRAP_BUNDLE_PATH: &str = "/etc/policy-node-agent/bootstrap.bundle";
pub const DEFAULT_LOCAL_SERVER_URL: &str = "http://127.0.0.1:8080/graphql";

/// Agent configuration loaded from `/etc/policy-node-agent/config.toml`.
#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    /// URL of the policy-controller management gRPC endpoint (mTLS, port 7777 by default).
    ///
    /// Used for the ongoing bidirectional management stream after enrollment.
    /// Example: `https://controller.example.com:7777`
    ///
    /// Optional when ZTP is in use: the bootstrap bundle carries these URLs and
    /// overrides the config values when present.
    #[serde(default)]
    pub controller_url: String,

    /// URL of the policy-controller enrollment gRPC endpoint (TLS only, port 7776 by default).
    ///
    /// Used to obtain the initial mTLS client certificate before joining the management stream.
    /// If omitted, `controller_url` is used (only correct when both services share the same port).
    /// Example: `https://controller.example.com:7776`
    #[serde(default)]
    pub enrollment_url: Option<String>,

    /// Path to a ZTP bootstrap bundle. When present and not yet enrolled, the
    /// agent uses the bundle's CA fingerprint + token to enrol unattended.
    /// The file is deleted on first successful enrollment.
    #[serde(default = "default_bootstrap_bundle_path")]
    pub bootstrap_bundle_path: PathBuf,

    /// Path to the persisted controller/enrollment URLs learned from the
    /// bootstrap bundle. Lives alongside the mTLS credentials so that the
    /// agent can recover the endpoints after the single-use bundle is gone.
    #[serde(default = "default_endpoints_path")]
    pub endpoints_path: PathBuf,

    /// Path to the controller CA certificate (PEM).
    /// Used to verify the controller's TLS server certificate.
    #[serde(default = "default_ca_cert_path")]
    pub ca_cert_path: PathBuf,

    /// Path to the node identity key (PKCS#8 PEM, mode 0600).
    /// Generated automatically on first run if absent.
    #[serde(default = "default_identity_key_path")]
    pub identity_key_path: PathBuf,

    /// Path where the issued mTLS client certificate is stored after enrollment.
    #[serde(default = "default_client_cert_path")]
    pub client_cert_path: PathBuf,

    /// Path where the issued mTLS client private key is stored after enrollment.
    #[serde(default = "default_client_key_path")]
    pub client_key_path: PathBuf,

    /// URL of the local policy-engine GraphQL server.
    #[serde(default = "default_local_server_url")]
    pub local_server_url: String,

    /// Interface names to exclude from discovery reports sent to the controller.
    /// Defaults to `["lo"]`.
    #[serde(default = "default_interface_blocklist")]
    pub interface_blocklist: Vec<String>,

    /// How often (in seconds) the agent scrapes and forwards Prometheus metrics to the controller.
    /// Defaults to 5 so controller-side stats refresh promptly; raise it for large fleets where
    /// the extra metrics traffic and controller parse load matter more than refresh latency.
    #[serde(default = "default_metrics_interval_secs")]
    pub metrics_interval_secs: u64,

    /// How many *cert* renewals occur between *key* rotations. The mTLS key
    /// is reused for N cert renewals, then rotated on the (N+1)th. Default 4
    /// — with a 90-day cert TTL that means a fresh key roughly every 240
    /// days (60d renew interval × 4). Set to 1 to rotate the key every
    /// renewal. The persisted counter lives at
    /// `<state_dir>/renewal-counter`.
    #[serde(default = "default_mtls_key_rotation_renewals")]
    pub mtls_key_rotation_renewals: u32,

    /// How often the renewal task wakes to check whether the cert is due for
    /// renewal. Default 3600s — fine for prod 90-day certs (renewal window is
    /// 30 days wide). Integration tests minting ~60s certs lower this to ~5s.
    #[serde(default = "default_renewal_check_interval_secs")]
    pub renewal_check_interval_secs: u64,

    /// Path to the persisted "renewals since last key rotation" counter
    /// used to decide when to rotate the mTLS *key* (vs. only the cert).
    /// Persisting across restarts so a crash loop cannot rotate the key on
    /// every restart.
    #[serde(default = "default_renewal_counter_path")]
    pub renewal_counter_path: PathBuf,
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read agent config: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse agent config: {}", path.display()))
    }

    /// Return the URL to use for the enrollment gRPC service.
    ///
    /// Falls back to `controller_url` if `enrollment_url` is not set.
    pub fn resolved_enrollment_url(&self) -> &str {
        self.enrollment_url
            .as_deref()
            .unwrap_or(&self.controller_url)
    }
}

fn default_ca_cert_path() -> PathBuf {
    PathBuf::from(DEFAULT_CA_CERT_PATH)
}
fn default_bootstrap_bundle_path() -> PathBuf {
    PathBuf::from(DEFAULT_BOOTSTRAP_BUNDLE_PATH)
}
fn default_endpoints_path() -> PathBuf {
    PathBuf::from(DEFAULT_ENDPOINTS_PATH)
}
fn default_identity_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_IDENTITY_KEY_PATH)
}
fn default_client_cert_path() -> PathBuf {
    PathBuf::from(DEFAULT_CLIENT_CERT_PATH)
}
fn default_client_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_CLIENT_KEY_PATH)
}
fn default_local_server_url() -> String {
    DEFAULT_LOCAL_SERVER_URL.to_string()
}
fn default_interface_blocklist() -> Vec<String> {
    vec!["lo".to_string()]
}
fn default_metrics_interval_secs() -> u64 {
    5
}
fn default_mtls_key_rotation_renewals() -> u32 {
    4
}
fn default_renewal_check_interval_secs() -> u64 {
    3600
}
fn default_renewal_counter_path() -> PathBuf {
    PathBuf::from(DEFAULT_RENEWAL_COUNTER_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_minimal_config() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"controller_url = "https://ctrl.example.com:7777""#).unwrap();

        let cfg = AgentConfig::load(f.path()).unwrap();
        assert_eq!(cfg.controller_url, "https://ctrl.example.com:7777");
        assert_eq!(
            cfg.ca_cert_path,
            PathBuf::from("/var/lib/policy-node-agent/controller-ca.crt")
        );
        assert_eq!(
            cfg.identity_key_path,
            PathBuf::from("/var/lib/policy-node-agent/identity.key")
        );
        assert_eq!(
            cfg.client_cert_path,
            PathBuf::from("/var/lib/policy-node-agent/controller-client.crt")
        );
        assert_eq!(cfg.local_server_url, DEFAULT_LOCAL_SERVER_URL);
        assert_eq!(cfg.interface_blocklist, vec!["lo".to_string()]);
        // enrollment_url not set → falls back to controller_url
        assert!(cfg.enrollment_url.is_none());
        assert_eq!(
            cfg.resolved_enrollment_url(),
            "https://ctrl.example.com:7777"
        );
    }

    #[test]
    fn test_enrollment_url_overrides_controller_url() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
controller_url = "https://10.0.0.1:7777"
enrollment_url = "https://10.0.0.1:7776"
"#
        )
        .unwrap();
        let cfg = AgentConfig::load(f.path()).unwrap();
        assert_eq!(cfg.resolved_enrollment_url(), "https://10.0.0.1:7776");
    }

    #[test]
    fn test_load_full_config() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
controller_url    = "https://10.0.0.1:7777"
enrollment_url    = "https://10.0.0.1:7776"
ca_cert_path      = "/custom/ca.crt"
identity_key_path = "/custom/identity.key"
client_cert_path  = "/custom/client.crt"
local_server_url  = "http://127.0.0.1:9090/graphql"
"#
        )
        .unwrap();

        let cfg = AgentConfig::load(f.path()).unwrap();
        assert_eq!(cfg.ca_cert_path, PathBuf::from("/custom/ca.crt"));
        assert_eq!(cfg.identity_key_path, PathBuf::from("/custom/identity.key"));
        assert_eq!(cfg.local_server_url, "http://127.0.0.1:9090/graphql");
        assert_eq!(cfg.resolved_enrollment_url(), "https://10.0.0.1:7776");
    }

    #[test]
    fn test_missing_controller_url_is_allowed() {
        // controller_url and enrollment_url are now optional in the config;
        // ZTP deployments populate them from the bootstrap bundle at runtime.
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"ca_cert_path = "/etc/something""#).unwrap();
        let cfg = AgentConfig::load(f.path()).unwrap();
        assert!(cfg.controller_url.is_empty());
        assert!(cfg.enrollment_url.is_none());
    }

    #[test]
    fn test_missing_file_fails() {
        assert!(AgentConfig::load(Path::new("/nonexistent/config.toml")).is_err());
    }
}
