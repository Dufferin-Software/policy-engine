// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! ZTP bootstrap bundle: parser and fingerprint-pinning TLS verifier.
//!
//! The controller mints a bundle (`policy-controller-client enroll-token create`)
//! containing the controller URL, the SHA-256 of its CA cert DER, and a
//! short-lived enrollment token. Operators drop the base64 blob into
//! `/etc/policy-node-agent/bootstrap.bundle` on each host they want to enrol.
//!
//! On first boot the agent reads the bundle, opens a TLS connection to the
//! enrollment endpoint using [`FingerprintPinningVerifier`] (no pre-distributed
//! CA cert required), includes the token in the EnrollmentRequest, and the
//! controller auto-approves and returns the per-node mTLS credentials in the
//! same response. The bundle is then deleted from disk.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// Bundle as embedded by the controller. Must stay byte-compatible with the
/// `BootstrapBundle` type in `policy-controller::node_registry::tokens`.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapBundle {
    pub v: u32,
    pub enrollment_url: String,
    pub controller_url: String,
    pub ca_fp_sha256: String,
    pub token_id: String,
    pub token_b64: String,
    pub expires_at: i64,
}

impl BootstrapBundle {
    /// Read and parse a bundle file written by the operator.
    pub fn read_from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read bootstrap bundle: {}", path.display()))?;
        Self::decode(&raw)
            .with_context(|| format!("Failed to parse bootstrap bundle: {}", path.display()))
    }

    /// Decode a base64url-no-pad bundle.
    pub fn decode(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        let bytes = URL_SAFE_NO_PAD
            .decode(trimmed)
            .context("Bootstrap bundle is not valid base64url-no-pad")?;
        let bundle: BootstrapBundle =
            serde_json::from_slice(&bytes).context("Bootstrap bundle JSON is malformed")?;
        if bundle.v != 1 {
            anyhow::bail!(
                "Unsupported bootstrap bundle version: {} (expected 1)",
                bundle.v
            );
        }
        Ok(bundle)
    }

    pub fn token_bytes(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.token_b64)
            .context("Bundle token is not valid base64url-no-pad")
    }

    pub fn ca_fingerprint_bytes(&self) -> Result<[u8; 32]> {
        let bytes =
            hex::decode(&self.ca_fp_sha256).context("Bundle ca_fp_sha256 is not valid hex")?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("Bundle ca_fp_sha256 must be 32 bytes, got {}", v.len())
        })
    }
}

// ── rustls verifier ───────────────────────────────────────────────────────────

/// rustls [`ServerCertVerifier`] that pins the controller CA by SHA-256
/// fingerprint instead of validating against a trust store.
///
/// The presented chain is accepted if any certificate in it has a DER whose
/// SHA-256 matches the expected fingerprint. This handles two server-cert
/// shapes the controller may present:
///   1. Server cert directly signed by the CA — the CA cert itself appears in
///      the chain as the issuer / second element.
///   2. Self-signed server cert that happens to be the CA — the leaf matches.
///
/// We deliberately do not perform path validation or hostname verification on
/// the bootstrap leg: the fingerprint is the trust anchor, distributed
/// out-of-band by the operator. After enrollment, the agent learns the real CA
/// cert and uses the regular tonic/rustls path for the management mTLS leg.
#[derive(Debug)]
pub struct FingerprintPinningVerifier {
    expected: [u8; 32],
    provider: rustls::crypto::CryptoProvider,
}

impl FingerprintPinningVerifier {
    pub fn new(expected_sha256: [u8; 32]) -> Self {
        Self {
            expected: expected_sha256,
            provider: rustls::crypto::ring::default_provider(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        for cert in std::iter::once(end_entity).chain(intermediates.iter()) {
            let digest: [u8; 32] = Sha256::digest(cert.as_ref()).into();
            if digest.ct_eq(&self.expected) {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        Err(rustls::Error::General(format!(
            "Controller CA fingerprint mismatch: expected {}, got chain of {} cert(s) — \
             this can mean the bootstrap bundle is stale or a MITM is in progress",
            hex::encode(self.expected),
            1 + intermediates.len()
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a rustls ClientConfig that pins the controller CA by fingerprint.
pub fn fingerprint_pinning_client_config(expected_sha256: [u8; 32]) -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintPinningVerifier::new(
            expected_sha256,
        )))
        .with_no_client_auth()
}

// ── Constant-time fingerprint comparison ──────────────────────────────────────

trait CtEq {
    fn ct_eq(&self, other: &Self) -> bool;
}

impl CtEq for [u8; 32] {
    fn ct_eq(&self, other: &Self) -> bool {
        let mut diff: u8 = 0;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn test_bundle_decode_rejects_garbage() {
        assert!(BootstrapBundle::decode("not-a-bundle!!!").is_err());
    }

    #[test]
    fn test_bundle_decode_minimal() {
        // Build a v1 bundle JSON and encode it as the controller would.
        let json = serde_json::json!({
            "v": 1,
            "enrollment_url": "https://e:1",
            "controller_url": "https://c:2",
            "ca_fp_sha256": "00".repeat(32),
            "token_id": "abc",
            "token_b64": URL_SAFE_NO_PAD.encode([1u8, 2, 3]),
            "expires_at": 0i64,
        });
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        let bundle = BootstrapBundle::decode(&encoded).unwrap();
        assert_eq!(bundle.enrollment_url, "https://e:1");
        assert_eq!(bundle.token_bytes().unwrap(), vec![1, 2, 3]);
        assert_eq!(bundle.ca_fingerprint_bytes().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_bundle_rejects_future_version() {
        let json = serde_json::json!({
            "v": 999,
            "enrollment_url": "https://e:1",
            "controller_url": "https://c:2",
            "ca_fp_sha256": "00".repeat(32),
            "token_id": "abc",
            "token_b64": "",
            "expires_at": 0i64,
        });
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert!(BootstrapBundle::decode(&encoded).is_err());
    }

    /// Verify the verifier accepts a chain where the trusted-fingerprint cert
    /// appears either as the leaf or as an intermediate.
    #[test]
    fn test_verifier_accepts_matching_cert() {
        install_provider();
        let cert_der = b"PRETEND-CERT-DER-BYTES".to_vec();
        let expected: [u8; 32] = Sha256::digest(&cert_der).into();

        let v = FingerprintPinningVerifier::new(expected);
        let leaf = CertificateDer::from(cert_der);
        let name = ServerName::try_from("ignored.example").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));
        assert!(v.verify_server_cert(&leaf, &[], &name, &[], now).is_ok());
    }

    #[test]
    fn test_verifier_accepts_intermediate_match() {
        install_provider();
        let leaf_der = b"LEAF".to_vec();
        let ca_der = b"CA".to_vec();
        let expected: [u8; 32] = Sha256::digest(&ca_der).into();

        let v = FingerprintPinningVerifier::new(expected);
        let leaf = CertificateDer::from(leaf_der);
        let intermediates = vec![CertificateDer::from(ca_der)];
        let name = ServerName::try_from("ignored.example").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));
        assert!(v
            .verify_server_cert(&leaf, &intermediates, &name, &[], now)
            .is_ok());
    }

    #[test]
    fn test_verifier_rejects_mismatch() {
        install_provider();
        let v = FingerprintPinningVerifier::new([0xAA; 32]);
        let leaf = CertificateDer::from(b"OTHER".to_vec());
        let name = ServerName::try_from("ignored.example").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));
        assert!(v.verify_server_cert(&leaf, &[], &name, &[], now).is_err());
    }
}
