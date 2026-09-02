// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! CPU affinity, server, and TLS configuration.
//!
//! Loads `/etc/policy-engine/config.toml` (if present) and provides an
//! `AffinityPlan` for CPU pinning and a `ServerFileConfig` for the listen
//! address, port, and TLS certificate paths.
//!
//! The `ConfigProvider` trait abstracts file I/O so that the startup
//! resolution logic can be unit-tested with a mock.

#[cfg(test)]
use mockall::automock;

/// Path to the optional TOML configuration file.
pub const CONFIG_PATH: &str = "/etc/policy-engine/config.toml";

/// Top-level configuration (TOML root table).
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub affinity: AffinityConfig,
    #[serde(default)]
    pub server: ServerFileConfig,
}

/// Server listen and TLS settings read from the config file.
///
/// All fields are optional so that a partial or missing `[server]` section
/// simply uses the hardcoded defaults rather than failing to parse.
///
/// ```toml
/// [server]
/// host     = "0.0.0.0"
/// port     = 8443
/// tls_cert = "/etc/policy-engine/server.crt"
/// tls_key  = "/etc/policy-engine/server.key"
/// ```
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct ServerFileConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

/// Trait that abstracts loading `Config` from a source.
///
/// The production implementation (`FileConfigProvider`) reads from disk.
/// In unit tests a `MockConfigProvider` can return any desired `Config`
/// without touching the filesystem.
#[cfg_attr(test, automock)]
pub trait ConfigProvider: Send + Sync {
    fn load(&self) -> Config;
}

/// Reads `Config` from `CONFIG_PATH` (or a custom path for testing).
pub struct FileConfigProvider {
    pub path: String,
}

impl Default for FileConfigProvider {
    fn default() -> Self {
        Self {
            path: CONFIG_PATH.to_string(),
        }
    }
}

impl ConfigProvider for FileConfigProvider {
    fn load(&self) -> Config {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
                log::warn!("Failed to parse {}: {e} — using defaults", self.path);
                Config::default()
            }),
            Err(_) => Config::default(),
        }
    }
}

/// User-supplied affinity overrides (all optional).
#[derive(Debug, Clone, serde::Deserialize, Default)]
pub struct AffinityConfig {
    /// Number of actix-web worker threads.  Defaults to `control_cpus.len()`.
    pub actix_workers: Option<usize>,
    /// CPUs for Tokio workers and actix-web threads (control-plane).
    pub control_cpus: Option<Vec<usize>>,
    /// CPUs for the BPF ring-buffer polling thread and EVE consumer.
    pub event_cpus: Option<Vec<usize>>,
    /// CPUs that NIC IRQs and RPS should be steered toward (dataplane).
    pub dataplane_cpus: Option<Vec<usize>>,
    /// Disable all CPU pinning (e.g. inside containers without CPU isolation).
    pub disabled: Option<bool>,
}

/// Resolved affinity plan used at runtime.
#[derive(Debug, Clone)]
pub struct AffinityPlan {
    pub control_cpus: Vec<usize>,
    pub event_cpus: Vec<usize>,
    pub dataplane_cpus: Vec<usize>,
    pub actix_workers: usize,
    pub disabled: bool,
}

impl AffinityPlan {
    /// A no-op plan: pinning disabled, single actix worker, all lists point at CPU 0.
    pub fn disabled() -> Self {
        Self {
            control_cpus: vec![0],
            event_cpus: vec![0],
            dataplane_cpus: vec![0],
            actix_workers: 1,
            disabled: true,
        }
    }
}

/// Compute an `AffinityPlan` from optional user config and the total CPU count.
///
/// Auto-default layout:
///
/// | Total CPUs | control | event | dataplane |
/// |------------|---------|-------|-----------|
/// | 1          | [0]     | [0]   | [0]       |
/// | 2          | [0]     | [0]   | [1]       |
/// | 3          | [0]     | [1]   | [2]       |
/// | ≥4         | [0]     | [1]   | [2..N-1]  |
///
/// Any field set in `cfg` overrides the corresponding auto value.
pub fn compute_affinity_plan(cfg: &AffinityConfig, total: usize) -> AffinityPlan {
    if cfg.disabled == Some(true) {
        return AffinityPlan::disabled();
    }

    let total = total.max(1);

    let (auto_control, auto_event, auto_dataplane): (Vec<usize>, Vec<usize>, Vec<usize>) =
        match total {
            1 => (vec![0], vec![0], vec![0]),
            2 => (vec![0], vec![0], vec![1]),
            3 => (vec![0], vec![1], vec![2]),
            _ => (vec![0], vec![1], (2..total).collect()),
        };

    let control_cpus = cfg.control_cpus.clone().unwrap_or(auto_control);
    let event_cpus = cfg.event_cpus.clone().unwrap_or(auto_event);
    let dataplane_cpus = cfg.dataplane_cpus.clone().unwrap_or(auto_dataplane);

    let actix_workers = cfg
        .actix_workers
        .unwrap_or_else(|| control_cpus.len().max(1));

    AffinityPlan {
        control_cpus,
        event_cpus,
        dataplane_cpus,
        actix_workers,
        disabled: false,
    }
}

/// Convenience wrapper: load configuration from `CONFIG_PATH`.
///
/// Falls back to `Config::default()` on any I/O or parse error.
/// Prefer constructing a `FileConfigProvider` directly when you need to
/// test or customise the config path.
pub fn load_config() -> Config {
    FileConfigProvider::default().load()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(total: usize) -> AffinityPlan {
        compute_affinity_plan(&AffinityConfig::default(), total)
    }

    #[test]
    fn test_1_cpu() {
        let p = plan(1);
        assert_eq!(p.control_cpus, vec![0]);
        assert_eq!(p.event_cpus, vec![0]);
        assert_eq!(p.dataplane_cpus, vec![0]);
        assert_eq!(p.actix_workers, 1);
        assert!(!p.disabled);
    }

    #[test]
    fn test_2_cpu() {
        let p = plan(2);
        assert_eq!(p.control_cpus, vec![0]);
        assert_eq!(p.event_cpus, vec![0]);
        assert_eq!(p.dataplane_cpus, vec![1]);
        assert_eq!(p.actix_workers, 1);
    }

    #[test]
    fn test_3_cpu() {
        let p = plan(3);
        assert_eq!(p.control_cpus, vec![0]);
        assert_eq!(p.event_cpus, vec![1]);
        assert_eq!(p.dataplane_cpus, vec![2]);
    }

    #[test]
    fn test_4_cpu() {
        let p = plan(4);
        assert_eq!(p.control_cpus, vec![0]);
        assert_eq!(p.event_cpus, vec![1]);
        assert_eq!(p.dataplane_cpus, vec![2, 3]);
    }

    #[test]
    fn test_8_cpu() {
        let p = plan(8);
        assert_eq!(p.dataplane_cpus, vec![2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_override_control_cpus() {
        let cfg = AffinityConfig {
            control_cpus: Some(vec![0, 1]),
            ..Default::default()
        };
        let p = compute_affinity_plan(&cfg, 8);
        assert_eq!(p.control_cpus, vec![0, 1]);
        assert_eq!(p.actix_workers, 2); // defaults to control_cpus.len()
        assert_eq!(p.event_cpus, vec![1]); // auto
        assert_eq!(p.dataplane_cpus, vec![2, 3, 4, 5, 6, 7]); // auto
    }

    #[test]
    fn test_override_actix_workers() {
        let cfg = AffinityConfig {
            actix_workers: Some(4),
            ..Default::default()
        };
        let p = compute_affinity_plan(&cfg, 8);
        assert_eq!(p.actix_workers, 4);
    }

    #[test]
    fn test_disabled() {
        let cfg = AffinityConfig {
            disabled: Some(true),
            ..Default::default()
        };
        let p = compute_affinity_plan(&cfg, 16);
        assert!(p.disabled);
        assert_eq!(p.actix_workers, 1);
    }

    #[test]
    fn test_disabled_plan() {
        let p = AffinityPlan::disabled();
        assert!(p.disabled);
        assert_eq!(p.actix_workers, 1);
    }
}
