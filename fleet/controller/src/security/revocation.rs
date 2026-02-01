// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

//! TLS-handshake-layer certificate revocation.
//!
//! Phase 7 of `docs/enrollment-crypto.md`: a custom rustls [`ClientCertVerifier`]
//! that delegates trust-chain validation to [`WebPkiClientVerifier`] and then
//! rejects the handshake if the presented leaf cert's serial appears in an
//! in-memory mirror of the `revoked_certs` table.
//!
//! The mirror is seeded once at controller boot from the store and kept current
//! via a [`tokio::sync::watch`] channel — `revoke_cert` pushes the new serial,
//! the verifier reads the latest snapshot on each handshake. No polling.

use std::collections::HashSet;
use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use tokio::sync::watch;

/// An immutable snapshot of the revoked-serial set, cheap to clone (Arc).
#[derive(Debug, Clone, Default)]
pub struct RevokedSerials {
    inner: Arc<HashSet<Vec<u8>>>,
}

impl RevokedSerials {
    pub fn from_serials<I: IntoIterator<Item = Vec<u8>>>(iter: I) -> Self {
        Self {
            inner: Arc::new(iter.into_iter().collect()),
        }
    }

    pub fn contains(&self, serial: &[u8]) -> bool {
        self.inner.contains(serial)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Owner side of the revocation watch channel.
///
/// `NodeRegistry::decommission_node` calls [`Self::insert`] after the store
/// write commits, which atomically swaps in a new snapshot. The verifier holds
/// a [`watch::Receiver`] and reads `borrow()` at handshake time. There is a
/// narrow window between the store write and the snapshot swap; the existing
/// application-layer check in `grpc/management.rs` covers that window.
#[derive(Debug)]
pub struct RevocationWatch {
    tx: watch::Sender<RevokedSerials>,
}

impl RevocationWatch {
    pub fn new(initial: RevokedSerials) -> Self {
        let (tx, _rx) = watch::channel(initial);
        Self { tx }
    }

    pub fn subscribe(&self) -> watch::Receiver<RevokedSerials> {
        self.tx.subscribe()
    }

    /// Add a serial to the revoked set. Cheap when the serial is already
    /// present — does not allocate a new HashSet in that case.
    pub fn insert(&self, serial: Vec<u8>) {
        self.tx.send_if_modified(|snap| {
            if snap.inner.contains(&serial) {
                return false;
            }
            let mut new = HashSet::clone(&snap.inner);
            new.insert(serial);
            snap.inner = Arc::new(new);
            true
        });
    }

    /// Test-only: snapshot the current set.
    #[cfg(test)]
    pub fn snapshot(&self) -> RevokedSerials {
        self.tx.borrow().clone()
    }
}

/// Wraps any [`ClientCertVerifier`] (typically [`rustls::server::WebPkiClientVerifier`])
/// with a revocation check that runs after — and only after — successful
/// trust-chain validation.
#[derive(Debug)]
pub struct RevokingClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    revoked: watch::Receiver<RevokedSerials>,
}

impl RevokingClientCertVerifier {
    pub fn new(
        inner: Arc<dyn ClientCertVerifier>,
        revoked: watch::Receiver<RevokedSerials>,
    ) -> Self {
        Self { inner, revoked }
    }
}

impl ClientCertVerifier for RevokingClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Chain validation first. If this fails the cert was never trusted in
        // the first place and no revocation check is needed.
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;

        let serial = extract_serial(end_entity.as_ref())
            .map_err(|e| Error::General(format!("Failed to extract client cert serial: {e}")))?;

        if self.revoked.borrow().contains(&serial) {
            log::warn!(
                "Rejecting TLS handshake — client cert serial {} is revoked",
                hex::encode(&serial)
            );
            return Err(Error::General("client certificate has been revoked".into()));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Extract a certificate's serial number (big-endian, unsigned, no leading
/// zero) from its DER encoding.
///
/// `rcgen` issues serials via [`SerialNumber::from_slice`] with the high bit
/// cleared, so x509-parser's `raw` bytes match exactly what
/// `IssuedCert::serial` recorded — no normalization needed.
pub fn extract_serial(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_parser::prelude::FromDer;
    let (_rest, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| format!("x509 parse: {e}"))?;
    Ok(parsed.tbs_certificate.raw_serial().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::ca::{CertificateAuthority, FileCertificateAuthority};
    use rustls::server::WebPkiClientVerifier;
    use rustls::RootCertStore;
    use tempfile::TempDir;

    fn make_ca(dir: &TempDir) -> FileCertificateAuthority {
        FileCertificateAuthority::load_or_create(
            &dir.path().join("ca.key"),
            &dir.path().join("ca.crt"),
            "Test CA",
        )
        .unwrap()
    }

    fn install_provider_once() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn build_verifier(
        ca_pem: &str,
        rx: watch::Receiver<RevokedSerials>,
    ) -> RevokingClientCertVerifier {
        install_provider_once();
        let mut roots = RootCertStore::empty();
        let mut reader = ca_pem.as_bytes();
        for cert in rustls_pemfile::certs(&mut reader) {
            roots.add(cert.unwrap()).unwrap();
        }
        let inner = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        RevokingClientCertVerifier::new(inner, rx)
    }

    fn cert_der_from_pem(pem: &str) -> Vec<u8> {
        let mut reader = pem.as_bytes();
        let der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
        der.to_vec()
    }

    #[test]
    fn extract_serial_matches_rcgen_serial() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let issued = ca.issue_node_cert("node-1", 30 * 86_400).unwrap();
        let der = cert_der_from_pem(&issued.cert_pem);
        let extracted = extract_serial(&der).unwrap();
        assert_eq!(
            extracted, issued.serial,
            "serial extracted from leaf DER must match what rcgen issued"
        );
    }

    #[test]
    fn fresh_cert_passes_verification() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let issued = ca.issue_node_cert("node-ok", 30 * 86_400).unwrap();
        let watch = RevocationWatch::new(RevokedSerials::default());
        let verifier = build_verifier(&ca.ca_cert_pem(), watch.subscribe());

        let der = CertificateDer::from(cert_der_from_pem(&issued.cert_pem));
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        verifier
            .verify_client_cert(&der, &[], now)
            .expect("non-revoked cert must verify");
    }

    #[test]
    fn revoked_cert_is_rejected() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let issued = ca.issue_node_cert("node-bad", 30 * 86_400).unwrap();
        let watch = RevocationWatch::new(RevokedSerials::default());
        let verifier = build_verifier(&ca.ca_cert_pem(), watch.subscribe());

        // Cert verifies before revocation.
        let der = CertificateDer::from(cert_der_from_pem(&issued.cert_pem));
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        verifier.verify_client_cert(&der, &[], now).unwrap();

        // After revocation: same handshake input now fails.
        watch.insert(issued.serial.clone());
        let err = verifier
            .verify_client_cert(&der, &[], now)
            .expect_err("revoked cert must be rejected");
        let s = format!("{err}");
        assert!(
            s.contains("revoked"),
            "error should mention revocation, got: {s}"
        );
    }

    #[test]
    fn insert_is_idempotent_and_visible_to_existing_subscriber() {
        let watch = RevocationWatch::new(RevokedSerials::default());
        let rx = watch.subscribe();
        watch.insert(vec![1, 2, 3]);
        watch.insert(vec![1, 2, 3]); // duplicate — must not break
        watch.insert(vec![4, 5, 6]);

        let snap = rx.borrow();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains(&[1, 2, 3]));
        assert!(snap.contains(&[4, 5, 6]));
    }

    #[test]
    fn unrelated_ca_chain_fails_before_revocation_check() {
        // A cert signed by a different CA must be rejected at chain validation,
        // not at the revocation step. This protects the invariant that
        // `verify_client_cert` does not even read the revoked-set unless the
        // cert is otherwise trusted.
        let dir_trusted = TempDir::new().unwrap();
        let dir_other = TempDir::new().unwrap();
        let trusted_ca = make_ca(&dir_trusted);
        let other_ca = make_ca(&dir_other);
        let issued = other_ca.issue_node_cert("attacker", 30 * 86_400).unwrap();

        let watch = RevocationWatch::new(RevokedSerials::default());
        let verifier = build_verifier(&trusted_ca.ca_cert_pem(), watch.subscribe());

        let der = CertificateDer::from(cert_der_from_pem(&issued.cert_pem));
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        verifier
            .verify_client_cert(&der, &[], now)
            .expect_err("foreign-CA cert must fail chain validation");
    }
}
