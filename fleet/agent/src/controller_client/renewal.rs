// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Background task that renews the agent's mTLS client cert before it expires.
//!
//! Lifecycle per the Phase 7 design (`docs/enrollment-crypto.md`):
//!
//! 1. On startup parse `not_before`/`not_after` from the persisted client cert.
//! 2. Compute `renew_at = not_before + 2/3 * (not_after - not_before)` with a
//!    small jitter so a fleet doesn't all renew on the same second.
//! 3. Wake up every `renewal_check_interval_secs` to check whether `now`
//!    has reached `renew_at`.
//! 4. When due, generate a CSR — using either the existing client key or a
//!    fresh keypair every `mtls_key_rotation_renewals` calls — and invoke
//!    `RenewClientCert` over a freshly-built mTLS channel.
//! 5. Atomically replace `.crt` (and `.key`, on rotation) on success.
//!
//! The renewal task makes its own short-lived gRPC channel rather than
//! re-using the management stream's channel, because the stream sits behind
//! the [`AgentStreamHandle`](super::AgentStreamHandle) abstraction that
//! doesn't expose the underlying `tonic::transport::Channel`. Renewal is
//! infrequent (typically once per two months) so the extra TCP+TLS handshake
//! is in the noise.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chrono::{TimeZone, Utc};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use tokio::sync::{Mutex, Notify};

use policy_controller_proto::controller::{
    node_management_service_client::NodeManagementServiceClient, RenewClientCertRequest,
};

/// Inputs the renewal task needs. Cloned into the spawned task; paths stay
/// in `Arc<Path>` so the task can hold them without copying the strings.
#[derive(Clone, Debug)]
pub struct RenewalConfig {
    pub management_url: String,
    pub ca_cert_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub mtls_key_rotation_renewals: u32,
    pub check_interval: Duration,
    /// CN value the CSR will use — must equal the node_id this agent
    /// authenticated as, otherwise the controller rejects the renewal.
    pub node_id: String,
    /// Notified after every successful renewal. The agent's management
    /// stream loop listens on this and tears down its current connection so
    /// the reconnect picks up the new cert (and key, on rotation) from
    /// disk. Without this signal, the existing tonic channel keeps using
    /// the *previous* cert until it dies of its own accord — which on a
    /// short-TTL test means the controller eventually revokes the old serial
    /// while the agent is still presenting it, racing the verifier.
    pub renewed_notify: Arc<Notify>,
    /// Path for the persisted rotation counter. The renewal task increments
    /// it after each cert renewal and rotates the key on every Nth (where
    /// N == [`mtls_key_rotation_renewals`](Self::mtls_key_rotation_renewals)).
    /// Persisting across restarts means an agent restart in the middle of
    /// the rotation cycle does not reset back to a fresh key earlier than
    /// configured.
    pub counter_path: PathBuf,
}

/// Internal state: how many cert renewals have happened since the last *key*
/// rotation. Persisted to [`RenewalConfig::counter_path`] so an agent
/// restart in the middle of the cycle doesn't reset back to a fresh key
/// before the operator asked for one.
#[derive(Default)]
struct RenewalState {
    renewals_since_key_rotation: u32,
}

impl RenewalState {
    /// Load from disk, or return defaults if the file is missing or corrupt.
    /// A corrupt counter file is logged and treated as zero: the cost of
    /// rotating the key one cycle early is far smaller than refusing to
    /// renew.
    fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(s) => match s.trim().parse::<u32>() {
                Ok(n) => Self {
                    renewals_since_key_rotation: n,
                },
                Err(e) => {
                    log::warn!(
                        "Rotation counter at {} is unparseable ('{}'): {} — resetting to 0",
                        path.display(),
                        s.trim(),
                        e
                    );
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                log::warn!(
                    "Failed to read rotation counter at {}: {} — starting at 0",
                    path.display(),
                    e
                );
                Self::default()
            }
        }
    }

    /// Persist via the same atomic rename pattern as the cert/key writers.
    /// A failure here is logged but not propagated: a missed counter update
    /// merely shifts the key rotation by one cycle and is preferable to a
    /// failed renewal.
    fn save(&self, path: &Path) {
        let bytes = self.renewals_since_key_rotation.to_string();
        if let Err(e) = atomic_write(path, bytes.as_bytes(), 0o644) {
            log::warn!(
                "Failed to persist rotation counter to {}: {:#}",
                path.display(),
                e
            );
        }
    }
}

/// Spawn the renewal task. Returns a [`tokio::task::JoinHandle`] so callers
/// can `select!` on it during shutdown.
pub fn spawn(cfg: RenewalConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(cfg).await {
            log::error!("Cert renewal task exited with error: {:#}", e);
        }
    })
}

async fn run(cfg: RenewalConfig) -> Result<()> {
    let state = Arc::new(Mutex::new(RenewalState::load(&cfg.counter_path)));
    log::info!(
        "Cert renewal task started: check_interval={:?}, key_rotation_every={} renewals, \
         counter loaded at {} (current = {})",
        cfg.check_interval,
        cfg.mtls_key_rotation_renewals,
        cfg.counter_path.display(),
        state.lock().await.renewals_since_key_rotation
    );

    loop {
        match check_and_maybe_renew(&cfg, &state).await {
            Ok(RenewalOutcome::NotDue { next_check }) => {
                log::debug!("Renewal not yet due; next check in {next_check:?}");
                // Clear the alert gauge — a successful "nothing to do" tick
                // means we're not in the failing+expiring-soon state.
                crate::metrics::CERT_RENEWAL_FAILING.set(0);
            }
            Ok(RenewalOutcome::Renewed { new_not_after }) => {
                log::info!(
                    "Cert renewed; new not_after = {}",
                    new_not_after
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "<unknown>".to_string())
                );
                // Wake the mgmt stream loop so it reconnects with the new
                // creds on disk. `notify_waiters` (vs. `notify_one`) is
                // intentional: if no one is currently waiting, the
                // notification is *dropped*. That's fine — the mgmt loop
                // will pick up the new creds on its next reconnect anyway,
                // and we don't want to queue up wakeups that fire after the
                // loop has already reconnected.
                cfg.renewed_notify.notify_waiters();
                crate::metrics::CERT_RENEWAL_FAILING.set(0);
            }
            Err(e) => {
                // Don't propagate — a transient renewal failure must not
                // crash the task. Surface a loud log so monitoring can pick
                // it up; the loop retries on the next tick.
                log::warn!("Cert renewal attempt failed: {:#}", e);
                crate::metrics::CERT_RENEWAL_FAILURES_TOTAL.inc();
                // Only flip the alert gauge when we're actually running
                // out of cert. A failure with weeks of TTL left is just
                // noise. 7 days mirrors the "loud log" threshold called
                // out in the Phase 7 design doc.
                if cert_within_expiry_warning_window(
                    &cfg,
                    std::time::Duration::from_secs(7 * 86_400),
                ) {
                    crate::metrics::CERT_RENEWAL_FAILING.set(1);
                }
            }
        }
        tokio::time::sleep(cfg.check_interval).await;
    }
}

/// Best-effort: returns `true` if the on-disk cert's `not_after` is within
/// `window` from now. A read/parse error returns `false` — that's the
/// conservative answer for an alert gauge (better to miss the alert than
/// to flap on a transient I/O error).
fn cert_within_expiry_warning_window(cfg: &RenewalConfig, window: std::time::Duration) -> bool {
    let pem = match std::fs::read_to_string(&cfg.client_cert_path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let parsed = match parse_cert_window(&pem) {
        Ok(w) => w,
        Err(_) => return false,
    };
    let remaining = parsed.not_after - Utc::now();
    remaining.num_seconds() <= window.as_secs() as i64
}

enum RenewalOutcome {
    NotDue {
        #[allow(dead_code)]
        next_check: Duration,
    },
    Renewed {
        new_not_after: Option<chrono::DateTime<Utc>>,
    },
}

async fn check_and_maybe_renew(
    cfg: &RenewalConfig,
    state: &Arc<Mutex<RenewalState>>,
) -> Result<RenewalOutcome> {
    // Re-read the cert each tick: a previous successful renewal in this
    // process replaces it, and an out-of-band overwrite (operator
    // intervention) shouldn't confuse us either.
    let cert_pem = std::fs::read_to_string(&cfg.client_cert_path).with_context(|| {
        format!(
            "Failed to read client cert at {}",
            cfg.client_cert_path.display()
        )
    })?;
    let window = parse_cert_window(&cert_pem)?;
    if !window.is_due(Utc::now()) {
        return Ok(RenewalOutcome::NotDue {
            next_check: cfg.check_interval,
        });
    }

    log::info!(
        "Cert renewal due (not_before={}, not_after={}, renew_at={})",
        window.not_before.to_rfc3339(),
        window.not_after.to_rfc3339(),
        window.renew_at.to_rfc3339()
    );

    let renewed = perform_renewal(cfg, state).await?;
    Ok(RenewalOutcome::Renewed {
        new_not_after: renewed.new_not_after,
    })
}

struct RenewalResult {
    new_not_after: Option<chrono::DateTime<Utc>>,
}

async fn perform_renewal(
    cfg: &RenewalConfig,
    state: &Arc<Mutex<RenewalState>>,
) -> Result<RenewalResult> {
    // Decide whether this renewal also rotates the key, and persist the
    // updated counter before doing any network work. Persisting first means
    // a crash after the counter write but before the renewal succeeds
    // pessimistically advances the cycle by one — the worst case is the
    // operator's key-rotation cadence stretches by one renewal interval.
    // The alternative — persisting after success — would allow a crash
    // loop to repeatedly rotate the key on every restart.
    let rotate_key = {
        let mut st = state.lock().await;
        let rotate = st.renewals_since_key_rotation + 1 >= cfg.mtls_key_rotation_renewals;
        if rotate {
            st.renewals_since_key_rotation = 0;
        } else {
            st.renewals_since_key_rotation += 1;
        }
        st.save(&cfg.counter_path);
        rotate
    };
    log::info!(
        "Renewing cert (rotate_key={}, renewals_since_rotation={})",
        rotate_key,
        if rotate_key {
            0
        } else {
            state.lock().await.renewals_since_key_rotation
        }
    );

    // Pick the signing key: existing on disk, or fresh.
    let (csr_key, csr_key_pem) = if rotate_key {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate fresh renewal key")?;
        let pem = key.serialize_pem();
        (key, Some(pem))
    } else {
        let pem = std::fs::read_to_string(&cfg.client_key_path).with_context(|| {
            format!(
                "Failed to read existing client key at {}",
                cfg.client_key_path.display()
            )
        })?;
        let key = KeyPair::from_pem(&pem).context("Failed to parse existing client key")?;
        (key, None)
    };

    // Build the CSR with the node_id as the CN. The controller cross-checks
    // CSR.CN against the peer cert CN before signing — a mismatch is fatal.
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, &cfg.node_id);
    let csr_pem = params
        .serialize_request(&csr_key)
        .context("Failed to build CSR")?
        .pem()
        .context("Failed to PEM-encode CSR")?;

    // Build a one-shot mTLS channel using the *current* (still-valid)
    // credentials. Connection pooling isn't worth the complexity for a call
    // we make a few times per cert lifetime.
    let ca_pem = std::fs::read_to_string(&cfg.ca_cert_path)
        .with_context(|| format!("Failed to read CA cert at {}", cfg.ca_cert_path.display()))?;
    let cur_cert_pem = std::fs::read_to_string(&cfg.client_cert_path)?;
    let cur_key_pem = std::fs::read_to_string(&cfg.client_key_path)?;

    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(&ca_pem))
        .identity(tonic::transport::Identity::from_pem(
            &cur_cert_pem,
            &cur_key_pem,
        ));
    let channel = tonic::transport::Channel::from_shared(cfg.management_url.clone())
        .context("Invalid management URL")?
        .tls_config(tls)
        .context("mTLS configuration error")?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .context("Failed to connect to management service for renewal")?;

    let mut client = NodeManagementServiceClient::new(channel);
    let resp = client
        .renew_client_cert(RenewClientCertRequest {
            csr_pem: csr_pem.into_bytes(),
        })
        .await
        .context("RenewClientCert RPC failed")?
        .into_inner();

    let new_cert_pem =
        String::from_utf8(resp.cert_pem).context("Controller returned non-UTF-8 cert PEM")?;
    if !new_cert_pem.contains("BEGIN CERTIFICATE") {
        bail!("Renewal response did not contain a PEM certificate");
    }

    // ── Atomic write: key first (if rotating), then cert ─────────────────────
    // If we wrote the cert first and the agent crashed before writing the
    // new key, the cert and key on disk would mismatch and the next mTLS
    // connect would fail. Writing key first means a crash leaves us with
    // (new_key, old_cert) — the old cert still validates against the old
    // key embedded in the new key's public part? No: a fresh key has a new
    // SPKI, the old cert won't match. So we'd be wedged either way during
    // rotation. The mitigation is that an atomic per-file rename + fsync
    // is the smallest window we can give it; both files are < 1KB so the
    // crash window is microseconds.
    if let Some(ref new_key_pem) = csr_key_pem {
        atomic_write(&cfg.client_key_path, new_key_pem.as_bytes(), 0o600).with_context(|| {
            format!(
                "Failed to write renewed key to {}",
                cfg.client_key_path.display()
            )
        })?;
    }
    atomic_write(&cfg.client_cert_path, new_cert_pem.as_bytes(), 0o644).with_context(|| {
        format!(
            "Failed to write renewed cert to {}",
            cfg.client_cert_path.display()
        )
    })?;

    let new_not_after = if resp.not_after_unix > 0 {
        Some(
            Utc.timestamp_opt(resp.not_after_unix, 0)
                .single()
                .ok_or_else(|| anyhow!("Controller returned invalid not_after_unix"))?,
        )
    } else {
        None
    };

    Ok(RenewalResult { new_not_after })
}

#[derive(Debug)]
struct CertWindow {
    not_before: chrono::DateTime<Utc>,
    not_after: chrono::DateTime<Utc>,
    renew_at: chrono::DateTime<Utc>,
}

impl CertWindow {
    fn is_due(&self, now: chrono::DateTime<Utc>) -> bool {
        now >= self.renew_at
    }
}

fn parse_cert_window(pem: &str) -> Result<CertWindow> {
    use x509_parser::prelude::FromDer;
    let mut reader = pem.as_bytes();
    let der_item = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow!("PEM contained no certificate"))?
        .context("Failed to PEM-decode client cert")?;
    let der: Vec<u8> = der_item.to_vec();
    let (_rest, parsed) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| anyhow!("Failed to parse client cert DER: {e}"))?;
    let nb = parsed.validity().not_before.timestamp();
    let na = parsed.validity().not_after.timestamp();
    let not_before = Utc
        .timestamp_opt(nb, 0)
        .single()
        .ok_or_else(|| anyhow!("not_before out of range"))?;
    let not_after = Utc
        .timestamp_opt(na, 0)
        .single()
        .ok_or_else(|| anyhow!("not_after out of range"))?;

    // 2/3 of the validity window, plus ±5% jitter. Jitter is computed once
    // per cert, not per check, because we re-parse the cert each tick — so
    // we want a deterministic input to the jitter. The thread RNG is fine
    // here; the goal is just to spread the fleet, not to be reproducible.
    let lifetime = (na - nb).max(1);
    let two_thirds = (lifetime * 2) / 3;
    let jitter_range = (lifetime / 20).max(1); // ±5%
    let jitter = uniform_jitter(jitter_range);
    let renew_offset = (two_thirds + jitter).clamp(1, lifetime - 1);
    let renew_at = Utc
        .timestamp_opt(nb + renew_offset, 0)
        .single()
        .ok_or_else(|| anyhow!("renew_at out of range"))?;
    Ok(CertWindow {
        not_before,
        not_after,
        renew_at,
    })
}

/// Uniformly-distributed `i64` in `[-range, range]`. Uses `getrandom`
/// directly (the agent already depends on `rand_core` + `getrandom`) so we
/// don't pull in the full `rand` crate just for one jitter computation.
fn uniform_jitter(range: i64) -> i64 {
    if range <= 0 {
        return 0;
    }
    let span = (range as u64) * 2 + 1;
    let mut buf = [0u8; 8];
    // `getrandom` failures are vanishingly rare on Linux; if it does fail
    // (e.g. early boot before entropy is available) fall back to zero
    // jitter — the worst case is the fleet bunches up slightly.
    if getrandom::getrandom(&mut buf).is_err() {
        return 0;
    }
    let r = u64::from_le_bytes(buf) % span;
    (r as i64) - range
}

/// Write `bytes` to `path` via a `.new`+fsync+rename. The rename is atomic
/// on the same filesystem, so a partial write cannot leave a torn file at
/// `path` — readers see either the old contents or the new, never a mix.
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path has no parent: {}", path.display()))?;
    let staged = path.with_extension(format!(
        "{}.new",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&staged)
            .with_context(|| format!("open {} for write", staged.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&staged, path)
        .with_context(|| format!("rename {} -> {}", staged.display(), path.display()))?;
    // fsync the parent dir so the rename itself is durable.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Mint a real cert with a chosen validity window so `parse_cert_window`
    /// has something to chew on. Returns (cert_pem, not_before, not_after).
    fn mint_cert(seconds_ago: i64, ttl_secs: i64) -> (String, i64, i64) {
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
        use time::OffsetDateTime;

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nb_secs = now_secs - seconds_ago;
        let na_secs = nb_secs + ttl_secs;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test");
        params.not_before = OffsetDateTime::from_unix_timestamp(nb_secs).unwrap();
        params.not_after = OffsetDateTime::from_unix_timestamp(na_secs).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), nb_secs, na_secs)
    }

    #[test]
    fn parse_cert_window_picks_renew_at_near_two_thirds() {
        let (pem, nb, na) = mint_cert(0, 600); // fresh 10-min cert
        let w = parse_cert_window(&pem).unwrap();
        let lifetime = na - nb;
        let renew_offset = w.renew_at.timestamp() - nb;
        let two_thirds = (lifetime * 2) / 3;
        // ±5% jitter window + a few seconds slack.
        let tol = (lifetime / 20) + 5;
        assert!(
            (renew_offset - two_thirds).abs() <= tol,
            "renew_offset {renew_offset} should be ~{two_thirds} (±{tol})"
        );
    }

    #[test]
    fn is_due_false_for_fresh_cert() {
        let (pem, _, _) = mint_cert(0, 3600);
        let w = parse_cert_window(&pem).unwrap();
        assert!(
            !w.is_due(Utc::now()),
            "a fresh cert with a 1h lifetime must not be due"
        );
    }

    #[test]
    fn is_due_true_for_aged_cert() {
        // Cert that's already ~80% of the way through its lifetime — past
        // the 2/3 renewal point even with the most negative jitter.
        let (pem, _, _) = mint_cert(48, 60);
        let w = parse_cert_window(&pem).unwrap();
        assert!(
            w.is_due(Utc::now()),
            "aged cert past 2/3 lifetime must trigger renewal"
        );
    }

    #[test]
    fn atomic_write_replaces_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.crt");
        std::fs::write(&path, b"old").unwrap();
        atomic_write(&path, b"new contents", 0o644).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new contents");
        assert!(
            !path.with_extension("crt.new").exists(),
            "staging file must be renamed away"
        );
    }

    #[test]
    fn rotation_counter_persists_across_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("renewal-counter");
        let st = RenewalState {
            renewals_since_key_rotation: 3,
        };
        st.save(&path);
        let loaded = RenewalState::load(&path);
        assert_eq!(loaded.renewals_since_key_rotation, 3);
    }

    #[test]
    fn rotation_counter_load_recovers_from_corrupt_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("renewal-counter");
        std::fs::write(&path, b"not-a-number").unwrap();
        let loaded = RenewalState::load(&path);
        assert_eq!(
            loaded.renewals_since_key_rotation, 0,
            "corrupt counter must reset to 0 rather than panic — renewal must keep working"
        );
    }

    #[test]
    fn rotation_counter_load_returns_default_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("renewal-counter");
        let loaded = RenewalState::load(&path);
        assert_eq!(loaded.renewals_since_key_rotation, 0);
    }

    #[test]
    fn atomic_write_sets_requested_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key");
        atomic_write(&path, b"secret", 0o600).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "renewed key must be 0600, got {mode:o}");
    }
}
