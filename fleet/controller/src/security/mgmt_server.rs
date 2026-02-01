// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! TLS server config for the management mTLS port.
//!
//! Built by hand rather than via `tonic::transport::ServerTlsConfig` because we
//! need to install the [`RevokingClientCertVerifier`] (Phase 7 of
//! `docs/enrollment-crypto.md`), which rejects revoked client certs at the
//! handshake layer. Tonic 0.12's `ServerTlsConfig` does not expose a hook for
//! a custom `ClientCertVerifier`.
//!
//! The resulting `Arc<rustls::ServerConfig>` is consumed by
//! `tokio_rustls::TlsAcceptor` in `bin/controller.rs`, and the accepted
//! `TlsStream<TcpStream>`s are handed to tonic via `serve_with_incoming` —
//! `TlsStream` already implements `tonic::transport::server::Connected` via
//! tonic's "tls" feature, so request handlers can still see peer certs.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use tokio::sync::watch;

use crate::security::revocation::{RevokedSerials, RevokingClientCertVerifier};

/// ALPN identifier for HTTP/2 — required so gRPC clients (which negotiate
/// `h2`) succeed the handshake against this server.
const ALPN_H2: &[u8] = b"h2";

/// Build the rustls `ServerConfig` for the management gRPC port.
///
/// * `ca_cert_pem` — trust anchor used to verify client certs.
/// * `cert_resolver` — supplies the server identity per handshake. Wrap a
///   [`crate::security::server_cert::ReloadableServerCert`] in `Arc` so the
///   background renewal task can swap the cert without rebuilding this
///   `ServerConfig` (or restarting the listener).
/// * `revoked_rx` — receiver from the [`RevocationWatch`] so the verifier
///   sees the latest revoked-serial snapshot on every handshake.
pub fn build_management_server_config(
    ca_cert_pem: &str,
    cert_resolver: Arc<dyn ResolvesServerCert>,
    revoked_rx: watch::Receiver<RevokedSerials>,
) -> Result<Arc<ServerConfig>> {
    // ── Trust anchors for client-cert verification ────────────────────────────
    let mut roots = RootCertStore::empty();
    let mut reader = ca_cert_pem.as_bytes();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.context("Failed to parse CA cert PEM for client verifier")?;
        roots
            .add(cert)
            .context("Failed to add CA cert to client-verifier trust store")?;
        added += 1;
    }
    if added == 0 {
        return Err(anyhow!(
            "CA PEM contained no certificates — refusing to start management server \
             with an empty client-cert trust store"
        ));
    }

    let inner_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("Failed to build inner WebPkiClientVerifier")?;
    let verifier = Arc::new(RevokingClientCertVerifier::new(inner_verifier, revoked_rx));

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(cert_resolver);

    config.alpn_protocols.push(ALPN_H2.into());
    Ok(Arc::new(config))
}

/// Build the rustls `ServerConfig` for the enrollment port (TLS, no client
/// cert required). Same cert-resolver shape as the management server so the
/// background renewal task can keep both endpoints' certs fresh.
pub fn build_enrollment_server_config(
    cert_resolver: Arc<dyn ResolvesServerCert>,
) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    config.alpn_protocols.push(ALPN_H2.into());
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ca::{CertificateAuthority, FileCertificateAuthority};
    use crate::security::revocation::RevocationWatch;
    use crate::security::server_cert::ReloadableServerCert;
    use tempfile::TempDir;

    fn make_resolver(server: &crate::security::ca::IssuedCert) -> Arc<dyn ResolvesServerCert> {
        Arc::new(ReloadableServerCert::from_pem(&server.cert_pem, &server.key_pem, None).unwrap())
    }

    fn install_provider_once() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn build_succeeds_with_real_ca_issued_server_cert() {
        install_provider_once();
        let dir = TempDir::new().unwrap();
        let ca = FileCertificateAuthority::load_or_create(
            &dir.path().join("ca.key"),
            &dir.path().join("ca.crt"),
            "Test CA",
        )
        .unwrap();
        let server = ca.issue_server_cert("policy-controller", 3600).unwrap();
        let watch = RevocationWatch::new(RevokedSerials::default());

        let cfg = build_management_server_config(
            &ca.ca_cert_pem(),
            make_resolver(&server),
            watch.subscribe(),
        )
        .expect("config must build with CA-issued cert");
        assert!(
            cfg.alpn_protocols.iter().any(|p| p == b"h2"),
            "ALPN must include h2 so gRPC clients can connect"
        );
    }

    #[test]
    fn build_rejects_empty_ca_pem() {
        install_provider_once();
        let dir = TempDir::new().unwrap();
        let ca = FileCertificateAuthority::load_or_create(
            &dir.path().join("ca.key"),
            &dir.path().join("ca.crt"),
            "Test CA",
        )
        .unwrap();
        let server = ca.issue_server_cert("policy-controller", 3600).unwrap();
        let watch = RevocationWatch::new(RevokedSerials::default());

        let err = build_management_server_config("", make_resolver(&server), watch.subscribe())
            .expect_err("empty CA PEM must be rejected — silently starting with an empty trust store would let any client connect");
        assert!(format!("{err:#}").contains("no certificates"));
    }
}
