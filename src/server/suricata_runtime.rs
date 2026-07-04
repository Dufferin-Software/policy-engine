// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! Suricata runtime abstraction
//!
//! Defines the `SuricataRuntime` trait for all Suricata system interactions
//! and provides `DefaultSuricataRuntime` for production use.  Tests inject a
//! `MockSuricataRuntime` to avoid touching the real filesystem or systemd.

use anyhow::{Context, Result};
use log::info;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(test)]
use mockall::automock;

/// All interactions with the Suricata service and its config files.
#[cfg_attr(test, automock)]
pub trait SuricataRuntime: Send + Sync {
    /// Return true if the suricata systemd service is currently active.
    fn is_running(&self) -> bool;

    /// `systemctl start suricata`
    fn start(&self) -> Result<()>;

    /// `systemctl stop suricata`
    fn stop(&self) -> Result<()>;

    /// Write the AF-packet YAML config, environment file, and systemd drop-in for
    /// the given veth-peer interface (e.g. `"pe-inspect1"`).
    fn write_systemd_env(&self, iface: &str) -> Result<()>;

    /// Remove the generated environment file and systemd drop-in.
    fn remove_systemd_env(&self) -> Result<()>;

    /// `systemctl restart suricata`
    fn restart_service(&self) -> Result<()>;

    /// Return the MainPID of the suricata systemd service, or None if not running / parse fails.
    fn get_pid(&self) -> Option<u32>;

    /// Return the first line of `suricata --build-info`, trimmed.
    fn get_version(&self) -> Option<String>;

    /// Read the suricata-update ruleset version from the rules file header.
    fn get_ruleset_version(&self) -> Option<String>;

    /// Signal Suricata to reload rules — tries suricatasc first, falls back to SIGUSR2.
    fn reload_rules(&self, cmd_socket: &std::path::Path) -> Result<()>;

    /// `systemctl enable --now policy-engine-suricata-update.timer`
    fn enable_update_timer(&self) -> Result<()>;

    /// `systemctl disable --now policy-engine-suricata-update.timer`
    fn disable_update_timer(&self) -> Result<()>;
}

/// Production implementation that writes to `/` and calls `systemctl`.
pub struct DefaultSuricataRuntime {
    /// Filesystem root — `/` in production, a tmpdir in tests.
    root: PathBuf,
}

impl DefaultSuricataRuntime {
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    /// Construct with an alternate root (used in unit tests to avoid touching
    /// the real filesystem).
    pub fn new_with_root(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("etc/suricata/policy-engine.yaml")
    }

    fn env_path(&self) -> PathBuf {
        // Lives under /etc/suricata (not /etc/default) so the unprivileged
        // policy-engine user can create and remove it — the -ips postinst
        // grants group write on /etc/suricata only.
        self.root.join("etc/suricata/suricata-policy-engine.env")
    }

    fn dropin_path(&self) -> PathBuf {
        self.root
            .join("etc/systemd/system/suricata.service.d/policy-engine.conf")
    }

    /// Reload systemd unit definitions so a freshly written or removed
    /// drop-in takes effect on the next start/restart.  Best-effort: a
    /// failure here should not mask the outcome of the start itself.
    fn daemon_reload() {
        match Command::new("systemctl").arg("daemon-reload").output() {
            Ok(o) if !o.status.success() => log::warn!(
                "systemctl daemon-reload failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => log::warn!("Failed to run systemctl daemon-reload: {}", e),
            _ => {}
        }
    }
}

impl Default for DefaultSuricataRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SuricataRuntime for DefaultSuricataRuntime {
    fn is_running(&self) -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", "suricata"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn start(&self) -> Result<()> {
        Self::daemon_reload();
        let out = Command::new("systemctl")
            .args(["start", "suricata"])
            .output()
            .context("Failed to run systemctl start suricata")?;
        if !out.status.success() {
            anyhow::bail!(
                "systemctl start suricata failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        Self::daemon_reload();
        let out = Command::new("systemctl")
            .args(["stop", "suricata"])
            .output()
            .context("Failed to run systemctl stop suricata")?;
        if !out.status.success() {
            anyhow::bail!(
                "systemctl stop suricata failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(())
    }

    fn write_systemd_env(&self, iface: &str) -> Result<()> {
        let config_path = self.config_path();
        std::fs::create_dir_all(config_path.parent().unwrap())
            .context("Failed to create suricata config dir")?;
        std::fs::write(&config_path, generate_suricata_yaml(iface))
            .context("Failed to write policy-engine.yaml")?;
        info!("Wrote Suricata config to {:?}", config_path);

        let env_path = self.env_path();
        std::fs::create_dir_all(env_path.parent().unwrap()).context("Failed to create env dir")?;
        let env_content = format!(
            "# Policy-engine managed Suricata options — do not edit manually\n\
             SURICATA_OPTS=-c {config} --af-packet={iface} -D --pidfile /var/run/suricata.pid\n",
            config = config_path.display(),
            iface = iface,
        );
        std::fs::write(&env_path, &env_content).context("Failed to write suricata env file")?;

        let dropin_path = self.dropin_path();
        std::fs::create_dir_all(dropin_path.parent().unwrap())
            .context("Failed to create systemd drop-in dir")?;
        // Detect the suricata binary path — Debian puts it in /usr/bin, RHEL in /usr/sbin.
        let suricata_bin = ["/usr/bin/suricata", "/usr/sbin/suricata"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .copied()
            .unwrap_or("/usr/bin/suricata");
        let dropin = format!(
            "[Unit]\n\
             Description=Suricata (policy-engine IPS drop-in)\n\
             After=policy-engine.service network.target\n\
             Wants=policy-engine.service\n\
             \n\
             [Service]\n\
             EnvironmentFile=-{env}\n\
             ExecStart=\n\
             ExecStart={suricata_bin} $SURICATA_OPTS\n\
             Restart=on-failure\n\
             RestartSec=5\n",
            env = env_path.display(),
            suricata_bin = suricata_bin,
        );
        std::fs::write(&dropin_path, &dropin).context("Failed to write systemd drop-in")?;
        info!("Wrote Suricata systemd drop-in to {:?}", dropin_path);
        Ok(())
    }

    fn remove_systemd_env(&self) -> Result<()> {
        let env_path = self.env_path();
        if env_path.exists() {
            std::fs::remove_file(&env_path).context("Failed to remove env file")?;
        }
        let dropin_path = self.dropin_path();
        if dropin_path.exists() {
            std::fs::remove_file(&dropin_path).context("Failed to remove systemd drop-in")?;
        }
        Ok(())
    }

    fn restart_service(&self) -> Result<()> {
        Self::daemon_reload();
        let out = Command::new("systemctl")
            .args(["restart", "suricata"])
            .output()
            .context("Failed to run systemctl restart suricata")?;
        if !out.status.success() {
            anyhow::bail!(
                "systemctl restart suricata failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(())
    }

    fn get_pid(&self) -> Option<u32> {
        Command::new("systemctl")
            .args(["show", "suricata", "--property=MainPID", "--value"])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .filter(|&pid| pid > 0)
    }

    fn get_version(&self) -> Option<String> {
        Command::new("suricata")
            .arg("--build-info")
            .output()
            .ok()
            .and_then(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.lines().next().map(|l| l.trim().to_string())
            })
    }

    fn get_ruleset_version(&self) -> Option<String> {
        let path = self.root.join("var/lib/suricata/rules/suricata.rules");
        if !path.exists() {
            return None;
        }
        std::fs::read_to_string(&path).ok().and_then(|content| {
            content
                .lines()
                .take(10)
                .find(|l| l.contains("version") || l.contains("date") || l.contains("updated"))
                .map(|l| l.trim_start_matches('#').trim().to_string())
        })
    }

    fn reload_rules(&self, cmd_socket: &std::path::Path) -> Result<()> {
        if cmd_socket.exists() {
            log::debug!("Attempting Suricata reload via command socket");
            let output = Command::new("suricatasc")
                .args([
                    "-c",
                    "reload-rules",
                    cmd_socket
                        .to_str()
                        .unwrap_or("/var/run/suricata-command.socket"),
                ])
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    info!("Suricata rules reloaded via command socket");
                    return Ok(());
                }
                Ok(o) => {
                    log::debug!(
                        "Command socket reload failed: {}",
                        String::from_utf8_lossy(&o.stderr)
                    );
                }
                Err(e) => {
                    log::debug!("Command socket not available: {}", e);
                }
            }
        }

        if self.is_running() {
            // Signal via systemd rather than kill(2): the daemon runs as the
            // unprivileged policy-engine user, which may not signal the
            // root-owned Suricata process directly.  systemctl kill goes
            // through polkit, where the -ips package grants access.
            info!("Sending SIGUSR2 to Suricata via systemctl kill");
            let out = Command::new("systemctl")
                .args(["kill", "--signal=SIGUSR2", "--kill-who=main", "suricata"])
                .output()
                .context("Failed to run systemctl kill suricata")?;
            if !out.status.success() {
                anyhow::bail!(
                    "systemctl kill -s SIGUSR2 suricata failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            return Ok(());
        }

        info!("Suricata is not running; rules on disk will be loaded on next start");
        Ok(())
    }

    fn enable_update_timer(&self) -> Result<()> {
        let out = Command::new("systemctl")
            .args(["enable", "--now", "policy-engine-suricata-update.timer"])
            .output()
            .context("Failed to run systemctl enable policy-engine-suricata-update.timer")?;
        if !out.status.success() {
            anyhow::bail!(
                "systemctl enable timer failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        info!("Suricata update timer enabled");
        Ok(())
    }

    fn disable_update_timer(&self) -> Result<()> {
        let out = Command::new("systemctl")
            .args(["disable", "--now", "policy-engine-suricata-update.timer"])
            .output()
            .context("Failed to run systemctl disable policy-engine-suricata-update.timer")?;
        if !out.status.success() {
            anyhow::bail!(
                "systemctl disable timer failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        info!("Suricata update timer disabled");
        Ok(())
    }
}

/// Generate a minimal Suricata YAML configuration for AF-packet capture on
/// the given veth-peer interface.  The file is auto-generated — users should
/// not edit it manually; changes should be made via the policy-engine API.
fn generate_suricata_yaml(iface: &str) -> String {
    format!(
        "%YAML 1.1\n\
         ---\n\
         # Auto-generated by policy-engine — do not edit manually.\n\
         # Suricata monitors pe-inspect1 (veth peer) via AF-packet.\n\
         # XDP marks INSPECT-matched flows in flows_to_inspect; TC ingress clones\n\
         # each packet to pe-inspect0 via bpf_clone_redirect; Suricata receives the\n\
         # full TCP stream here.  Alerts trigger DROP verdicts in flow_verdict_cache.\n\
         \n\
         # Standard Suricata variables required by ET Open rules\n\
         vars:\n\
         \x20 address-groups:\n\
         \x20   HOME_NET: \"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,127.0.0.0/8,::1]\"\n\
         \x20   EXTERNAL_NET: \"!$HOME_NET\"\n\
         \x20   HTTP_SERVERS: \"$HOME_NET\"\n\
         \x20   SMTP_SERVERS: \"$HOME_NET\"\n\
         \x20   SQL_SERVERS: \"$HOME_NET\"\n\
         \x20   DNS_SERVERS: \"$HOME_NET\"\n\
         \x20   TELNET_SERVERS: \"$HOME_NET\"\n\
         \x20   AIM_SERVERS: \"$EXTERNAL_NET\"\n\
         \x20   DC_SERVERS: \"$HOME_NET\"\n\
         \x20   DNP3_SERVER: \"$HOME_NET\"\n\
         \x20   DNP3_CLIENT: \"$HOME_NET\"\n\
         \x20   MODBUS_CLIENT: \"$HOME_NET\"\n\
         \x20   MODBUS_SERVER: \"$HOME_NET\"\n\
         \x20   ENIP_CLIENT: \"$HOME_NET\"\n\
         \x20   ENIP_SERVER: \"$HOME_NET\"\n\
         \x20 port-groups:\n\
         \x20   HTTP_PORTS: \"80\"\n\
         \x20   SHELLCODE_PORTS: \"!80\"\n\
         \x20   ORACLE_PORTS: 1521\n\
         \x20   SSH_PORTS: 22\n\
         \x20   DNP3_PORTS: 20000\n\
         \x20   MODBUS_CLIENT_PORTS: 502\n\
         \x20   FILE_DATA_PORTS: \"[$HTTP_PORTS,110,143]\"\n\
         \x20   FTP_PORTS: 21\n\
         \x20   VXLAN_PORTS: 4789\n\
         \x20   TEREDO_PORTS: 3544\n\
         \n\
         # Unix command socket — allows suricatasc and reload-rules without restart\n\
         unix-command:\n\
         \x20 enabled: yes\n\
         \x20 filename: /var/run/suricata-command.socket\n\
         \n\
         # AF-packet capture — Suricata sees all packets that XDP_PASS allows.\n\
         af-packet:\n\
         \x20 - interface: {iface}\n\
         \x20   threads: 1\n\
         \x20   cluster-id: 99\n\
         \x20   cluster-type: cluster_flow\n\
         \x20   defrag: yes\n\
         \n\
         default-rule-path: /var/lib/suricata/rules\n\
         rule-files:\n\
         \x20 - /etc/suricata/rules/policy-engine/*.rules\n\
         \x20 - suricata.rules\n\
         \n\
         # EVE JSON output — streamed to policy-engine via Unix socket\n\
         outputs:\n\
         \x20 - eve-log:\n\
         \x20     enabled: yes\n\
         \x20     filetype: unix_stream\n\
         \x20     filename: /run/policy-engine/eve.sock\n\
         \x20     types:\n\
         \x20       - alert:\n\
         \x20           payload: yes\n\
         \x20           payload-printable: yes\n\
         \x20           packet: no\n\
         \x20       - drop\n\
         \x20       - stats:\n\
         \x20           totals: yes\n\
         \x20           threads: no\n\
         \x20 - fast:\n\
         \x20     enabled: yes\n\
         \x20     filename: /var/log/suricata/fast.log\n\
         \x20     append: yes\n\
         \n\
         detect:\n\
         \x20 profile: medium\n\
         \x20 custom-values:\n\
         \x20   toclient-groups: 3\n\
         \x20   toserver-groups: 25\n\
         \n\
         app-layer:\n\
         \x20 protocols:\n\
         \x20   tls:\n\
         \x20     enabled: yes\n\
         \x20   http:\n\
         \x20     enabled: yes\n\
         \x20   dns:\n\
         \x20     enabled: yes\n\
         \x20   ssh:\n\
         \x20     enabled: yes\n\
         \n\
         logging:\n\
         \x20 default-log-level: notice\n\
         \x20 outputs:\n\
         \x20   - console:\n\
         \x20       enabled: no\n\
         \x20   - syslog:\n\
         \x20       enabled: yes\n\
         \x20       facility: local5\n\
         \x20       format: \"[%i] <%d> -- \"\n\
         ",
        iface = iface
    )
}
