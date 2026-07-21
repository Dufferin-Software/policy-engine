// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! In-process renewal for the controller's own TLS server certificates.
//!
//! Without this, the enrollment + management endpoints present a server
//! certificate that was minted once at startup with TTL `node_cert_ttl_secs`.
//! When operators (or integration tests) set `node_cert_ttl_secs` smaller
//! than controller uptime — e.g. 60s in the rotation suite — the server cert
//! expires and the entire mTLS control plane goes dark: every connect fails
//! at peer-cert verification, including agents trying to renew their own
//! client cert. There is no out-of-band path to recover.
//!
//! [`ReloadableServerCert`] is a [`ResolvesServerCert`] backed by a swappable
//! `CertifiedKey`. The background task spawned by [`spawn_renewal`] watches
//! the current cert's validity window and asks the CA for a fresh one when
//! the cert reaches 2/3 of its lifetime — mirroring the agent's policy.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::security::ca::{CertificateAuthority, IssuedCert};

/// Holds the active [`CertifiedKey`] and serves it to rustls on each
/// handshake. `replace` swaps the key atomically; in-flight handshakes that
/// already cloned the old `Arc<CertifiedKey>` complete with the old cert,
/// which is exactly what we want.
#[derive(Debug)]
pub struct ReloadableServerCert {
    inner: RwLock<Arc<CertifiedKey>>,
}

impl ReloadableServerCert {
    /// Build from PEM. `extra_chain_pem` is appended to the leaf cert and is
    /// used by the enrollment endpoint to include the CA cert in the
    /// presented chain — ZTP agents walk the chain looking for the
    /// pre-pinned CA fingerprint, so the CA must be visible there.
    pub fn from_pem(cert_pem: &str, key_pem: &str, extra_chain_pem: Option<&str>) -> Result<Self> {
        let key = build_certified_key(cert_pem, key_pem, extra_chain_pem)?;
        Ok(Self {
            inner: RwLock::new(Arc::new(key)),
        })
    }

    pub fn replace(
        &self,
        cert_pem: &str,
        key_pem: &str,
        extra_chain_pem: Option<&str>,
    ) -> Result<()> {
        let new = build_certified_key(cert_pem, key_pem, extra_chain_pem)?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| anyhow!("ReloadableServerCert lock poisoned"))?;
        *guard = Arc::new(new);
        Ok(())
    }
}

impl ResolvesServerCert for ReloadableServerCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // A poisoned lock here would mean a previous writer panicked while
        // installing a new key — there is no graceful response, just stop
        // serving handshakes (rustls will surface this as a TLS error).
        self.inner.read().ok().map(|g| Arc::clone(&g))
    }
}

fn build_certified_key(
    cert_pem: &str,
    key_pem: &str,
    extra_chain_pem: Option<&str>,
) -> Result<CertifiedKey> {
    let mut chain: Vec<CertificateDer<'static>> = {
        let mut reader = cert_pem.as_bytes();
        rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to parse server cert PEM")?
    };
    if chain.is_empty() {
        return Err(anyhow!("Server cert PEM contained no certificates"));
    }
    if let Some(extra) = extra_chain_pem {
        let mut reader = extra.as_bytes();
        for cert in rustls_pemfile::certs(&mut reader) {
            chain.push(cert.context("Failed to parse chain-extension cert PEM")?);
        }
    }

    let key_der = {
        let mut reader = key_pem.as_bytes();
        rustls_pemfile::private_key(&mut reader)
            .context("Failed to parse server key PEM")?
            .ok_or_else(|| anyhow!("Server key PEM contained no private key"))?
    };

    let signing_key = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| anyhow!("no rustls CryptoProvider installed"))?
        .key_provider
        .load_private_key(key_der)
        .context("Failed to load server key into rustls")?;

    Ok(CertifiedKey::new(chain, signing_key))
}

/// Configuration for the server-cert renewal task. One per renewable
/// endpoint (enrollment, management).
pub struct RenewalConfig {
    /// SANs to embed in the renewed cert (first entry is also the CN). Must
    /// cover every name/IP agents connect with, otherwise the handshake fails
    /// verification. See
    /// [`crate::security::ca::CertificateAuthority::issue_server_cert`].
    pub sans: Vec<String>,
    /// TTL applied to each renewed cert.
    pub ttl_secs: u64,
    /// If `Some`, the CA cert PEM is appended to the renewed chain. Use
    /// this for the enrollment endpoint where ZTP agents walk the chain
    /// to find the pinned CA. Leave `None` for the mTLS management
    /// endpoint where agents already have the CA as a trust anchor.
    pub extra_chain_pem: Option<String>,
    /// Tag for log lines so operators can tell enrollment renewals from
    /// management renewals.
    pub label: &'static str,
}

/// Spawn a task that re-issues the server cert ahead of its expiry and
/// swaps it into `cert_holder`. Mirrors the agent's 2/3-of-lifetime
/// renewal policy from `policy-engine/fleet/agent/src/controller_client/renewal.rs`.
pub fn spawn_renewal(
    cert_holder: Arc<ReloadableServerCert>,
    ca: Arc<dyn CertificateAuthority>,
    cfg: RenewalConfig,
    initial: IssuedCert,
) -> tokio::task::JoinHandle<()> {
    // Derive the check interval from TTL so a 60s test cert is checked
    // every few seconds and a 90-day prod cert isn't checked more than
    // hourly. The lower bound matches the agent's 5s tick; the upper
    // bound (1h) is well inside the 2/3 renewal window for any prod TTL
    // we'd realistically configure.
    let check_interval = Duration::from_secs(cfg.ttl_secs.div_ceil(12).clamp(5, 3600));

    tokio::spawn(async move {
        log::info!(
            "Server cert renewal task started ({}): ttl={}s, check_interval={:?}",
            cfg.label,
            cfg.ttl_secs,
            check_interval,
        );

        // Start tracking from the initial cert so we don't immediately
        // re-issue on first tick.
        let mut current_pem = initial.cert_pem;

        loop {
            tokio::time::sleep(check_interval).await;

            let due = match parse_renew_at(&current_pem) {
                Ok((_nb, _na, renew_at)) => Utc::now() >= renew_at,
                Err(e) => {
                    log::warn!(
                        "Server cert renewal ({}): failed to parse current cert, \
                         forcing renewal: {:#}",
                        cfg.label,
                        e
                    );
                    true
                }
            };
            if !due {
                continue;
            }

            match ca.issue_server_cert(&cfg.sans, cfg.ttl_secs) {
                Ok(new_cert) => match cert_holder.replace(
                    &new_cert.cert_pem,
                    &new_cert.key_pem,
                    cfg.extra_chain_pem.as_deref(),
                ) {
                    Ok(()) => {
                        log::info!("Server cert renewed ({}); new cert installed", cfg.label);
                        current_pem = new_cert.cert_pem;
                    }
                    Err(e) => {
                        // Don't update current_pem: next tick will retry.
                        log::error!(
                            "Server cert renewal ({}): failed to install new cert: {:#}",
                            cfg.label,
                            e
                        );
                    }
                },
                Err(e) => {
                    log::error!(
                        "Server cert renewal ({}): CA issuance failed: {:#}",
                        cfg.label,
                        e
                    );
                }
            }
        }
    })
}

/// Returns `(not_before, not_after, renew_at)` for the first cert in `pem`.
fn parse_renew_at(
    pem: &str,
) -> Result<(
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
)> {
    use x509_parser::prelude::FromDer;
    let mut reader = pem.as_bytes();
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow!("PEM contained no certificate"))?
        .context("Failed to PEM-decode server cert")?;
    let der_bytes: Vec<u8> = der.to_vec();
    let (_rest, parsed) = x509_parser::certificate::X509Certificate::from_der(&der_bytes)
        .map_err(|e| anyhow!("Failed to parse server cert DER: {e}"))?;
    let nb = Utc
        .timestamp_opt(parsed.validity().not_before.timestamp(), 0)
        .single()
        .ok_or_else(|| anyhow!("not_before out of range"))?;
    let na = Utc
        .timestamp_opt(parsed.validity().not_after.timestamp(), 0)
        .single()
        .ok_or_else(|| anyhow!("not_after out of range"))?;
    let lifetime = (na - nb).num_seconds().max(1);
    let two_thirds = (lifetime * 2) / 3;
    let renew_at = Utc
        .timestamp_opt(nb.timestamp() + two_thirds, 0)
        .single()
        .ok_or_else(|| anyhow!("renew_at out of range"))?;
    Ok((nb, na, renew_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ca::FileCertificateAuthority;
    use std::sync::Once;
    use tempfile::TempDir;

    fn install_provider_once() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn test_ca() -> (TempDir, Arc<dyn CertificateAuthority>) {
        let dir = TempDir::new().unwrap();
        let ca = FileCertificateAuthority::load_or_create(
            &dir.path().join("ca.key"),
            &dir.path().join("ca.crt"),
            "Test CA",
        )
        .unwrap();
        (dir, Arc::new(ca))
    }

    #[test]
    fn from_pem_builds_resolver_with_initial_cert() {
        install_provider_once();
        let (_dir, ca) = test_ca();
        let cert = ca
            .issue_server_cert(&["controller.local".to_string()], 3600)
            .unwrap();
        let holder = ReloadableServerCert::from_pem(&cert.cert_pem, &cert.key_pem, None).unwrap();
        // The resolver returns *something* — we can't synthesize a ClientHello
        // easily, so go straight to the inner key.
        let key = holder.inner.read().unwrap().clone();
        assert_eq!(key.cert.len(), 1, "no extra chain → single leaf");
    }

    #[test]
    fn from_pem_appends_extra_chain() {
        install_provider_once();
        let (_dir, ca) = test_ca();
        let cert = ca
            .issue_server_cert(&["controller.local".to_string()], 3600)
            .unwrap();
        let ca_pem = ca.ca_cert_pem();
        let holder =
            ReloadableServerCert::from_pem(&cert.cert_pem, &cert.key_pem, Some(&ca_pem)).unwrap();
        let key = holder.inner.read().unwrap().clone();
        assert_eq!(key.cert.len(), 2, "leaf + CA in chain");
    }

    #[test]
    fn replace_swaps_cert_chain() {
        install_provider_once();
        let (_dir, ca) = test_ca();
        let first = ca
            .issue_server_cert(&["controller.local".to_string()], 3600)
            .unwrap();
        let holder = ReloadableServerCert::from_pem(&first.cert_pem, &first.key_pem, None).unwrap();
        let first_der = holder.inner.read().unwrap().cert[0].clone();

        let second = ca
            .issue_server_cert(&["controller.local".to_string()], 3600)
            .unwrap();
        holder
            .replace(&second.cert_pem, &second.key_pem, None)
            .unwrap();
        let second_der = holder.inner.read().unwrap().cert[0].clone();

        assert_ne!(
            first_der.as_ref(),
            second_der.as_ref(),
            "replace must install a different cert"
        );
    }

    #[test]
    fn parse_renew_at_is_near_two_thirds() {
        install_provider_once();
        let (_dir, ca) = test_ca();
        let cert = ca
            .issue_server_cert(&["controller.local".to_string()], 600)
            .unwrap();
        let (nb, na, renew_at) = parse_renew_at(&cert.cert_pem).unwrap();
        let lifetime = (na - nb).num_seconds();
        let offset = (renew_at - nb).num_seconds();
        let two_thirds = (lifetime * 2) / 3;
        // Server cert path has no jitter — should land exactly on 2/3
        // modulo the second-level rounding of rcgen's not_before.
        assert!(
            (offset - two_thirds).abs() <= 2,
            "renew_at offset {offset}s vs 2/3 {two_thirds}s"
        );
    }
}
