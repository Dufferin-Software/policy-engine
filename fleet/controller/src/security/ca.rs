// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

use anyhow::{Context, Result};
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use std::net::IpAddr;
use std::path::Path;
use time::OffsetDateTime;

#[cfg(test)]
use mockall::automock;

/// Issued certificate and key material.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// PEM-encoded signed certificate.
    pub cert_pem: String,
    /// PEM-encoded private key (PKCS#8).
    /// Set for node client certs (controller generates the key and sends it to the agent).
    /// Empty for server certs (caller already has the key).
    pub key_pem: String,
    /// Big-endian DER-encoded certificate serial number. Persisted alongside the
    /// node record so that revocation (`store::revoke_cert`) can later target this
    /// specific issuance and reject reconnects whose presented cert serial matches.
    pub serial: Vec<u8>,
}

/// Manages the controller's Certificate Authority.
///
/// Issued node certs embed the `node_id` as the Common Name so the controller
/// can identify the node from its TLS client certificate without a separate lookup.
///
/// Note: the controller generates both key and cert for each node (rather than
/// using agent-submitted CSRs). This separates the identity key (hardware-bound,
/// used only for enrollment proof-of-possession) from the mTLS key (software,
/// controller-issued, rotatable). Phase 3 can optionally support CSR-based
/// issuance to allow TPM-bound mTLS keys.
#[cfg_attr(test, automock)]
pub trait CertificateAuthority: Send + Sync {
    /// Returns the CA certificate in PEM format.
    /// Distributed to agents as the trust anchor for verifying the controller.
    fn ca_cert_pem(&self) -> String;

    /// SHA-256 over the DER encoding of the CA certificate.
    ///
    /// Embedded in ZTP bootstrap bundles so agents can pin the controller's CA
    /// during the first TLS handshake without a pre-distributed cert file.
    fn ca_fingerprint_sha256(&self) -> Result<[u8; 32]>;

    /// Issue a new mTLS client certificate and key for the given node.
    /// The `node_id` is embedded as the certificate Common Name.
    ///
    /// `ttl_secs` is the validity window in seconds. Seconds rather than days
    /// because cert-rotation integration tests need to mint certs that expire
    /// in roughly a minute; the prod default still corresponds to 90 days.
    fn issue_node_cert(&self, node_id: &str, ttl_secs: u64) -> Result<IssuedCert>;

    /// Issue an mTLS client certificate from an agent-supplied CSR.
    ///
    /// Used by [`RenewClientCert`] so the renewed private key never leaves the
    /// node. The CSR's signature is verified (rcgen does this internally in
    /// `from_pem`); on success a fresh certificate is minted with `node_id` as
    /// the CN and the standard client-cert profile (P-256, `DigitalSignature`,
    /// `ClientAuth`, `ExplicitNoCa`). The CSR's own subject and extensions
    /// are **not** trusted — caller is responsible for any CN cross-checks
    /// against the authenticated peer.
    ///
    /// `key_pem` in the returned [`IssuedCert`] is empty: only the controller
    /// signature is returned, the agent already holds the matching key.
    fn issue_node_cert_from_csr(
        &self,
        node_id: &str,
        csr_pem: &str,
        ttl_secs: u64,
    ) -> Result<IssuedCert>;

    /// Issue a TLS server certificate covering the given SAN entries.
    ///
    /// Each entry is parsed as an `iPAddress` SAN when it parses as an
    /// `IpAddr`, otherwise as a `dNSName` SAN; the first entry is also used as
    /// the certificate Common Name. Agents validate the address they connect
    /// with against these SANs, so every name **and IP** an agent might use to
    /// reach the controller must be listed — a cert with only a DNS SAN makes
    /// mTLS by IP fail hostname verification. Errors if `sans` is empty.
    fn issue_server_cert(&self, sans: &[String], ttl_secs: u64) -> Result<IssuedCert>;
}

/// [`CertificateAuthority`] backed by key files on disk.
///
/// Generates an ECDSA P-384 CA on first run and saves it to disk.
/// On subsequent startups, loads the key from disk and reconstructs
/// the in-memory signing context. The stored CA cert PEM is returned
/// to agents as the trust anchor.
pub struct FileCertificateAuthority {
    /// In-memory CA certificate used as the issuer when signing node certs.
    /// Reconstructed from the key on each startup; same key → same signatures.
    ca_cert: rcgen::Certificate,
    /// CA key pair used for signing.
    ca_key: KeyPair,
    /// Original CA cert PEM loaded from disk — this is what agents trust.
    ca_cert_pem: String,
}

impl FileCertificateAuthority {
    /// Load an existing CA key+cert pair or generate a new one.
    ///
    /// # Arguments
    /// * `ca_key_path`  — PKCS#8 PEM private key (written with mode 0600)
    /// * `ca_cert_path` — PEM certificate
    /// * `common_name`  — CN for the CA certificate (e.g. "Policy Controller CA")
    pub fn load_or_create(
        ca_key_path: &Path,
        ca_cert_path: &Path,
        common_name: &str,
    ) -> Result<Self> {
        if ca_key_path.exists() && ca_cert_path.exists() {
            // Load existing CA
            let ca_key_pem = std::fs::read_to_string(ca_key_path)
                .with_context(|| format!("Failed to read CA key: {}", ca_key_path.display()))?;
            let ca_cert_pem = std::fs::read_to_string(ca_cert_path)
                .with_context(|| format!("Failed to read CA cert: {}", ca_cert_path.display()))?;

            let ca_key = KeyPair::from_pem(&ca_key_pem).context("Failed to parse CA key")?;
            // Reconstruct the Certificate signing object from the key.
            // The reconstructed cert uses the same key so issued certs validate
            // against the stored CA cert.
            let ca_cert = build_ca_params(common_name)?.self_signed(&ca_key)?;

            log::info!("Loaded CA from {}", ca_cert_path.display());
            Ok(Self {
                ca_cert,
                ca_key,
                ca_cert_pem,
            })
        } else {
            // Generate new CA
            let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
                .context("Failed to generate CA key")?;
            let ca_cert = build_ca_params(common_name)?.self_signed(&ca_key)?;
            let ca_cert_pem = ca_cert.pem();

            save_ca_files(&ca_key, &ca_cert_pem, ca_key_path, ca_cert_path)?;
            log::info!("Generated new CA at {}", ca_cert_path.display());

            Ok(Self {
                ca_cert,
                ca_key,
                ca_cert_pem,
            })
        }
    }
}

impl CertificateAuthority for FileCertificateAuthority {
    fn ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }

    fn ca_fingerprint_sha256(&self) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        // Hash the DER (not the PEM text) so the fingerprint is stable
        // regardless of PEM whitespace or line-endings.
        let mut reader = self.ca_cert_pem.as_bytes();
        let der = rustls_pemfile::certs(&mut reader)
            .next()
            .ok_or_else(|| anyhow::anyhow!("CA cert PEM contains no certificate"))?
            .context("Failed to parse CA cert PEM")?;
        Ok(Sha256::digest(&der).into())
    }

    fn issue_node_cert(&self, node_id: &str, ttl_secs: u64) -> Result<IssuedCert> {
        // Generate a fresh key pair for the node's mTLS credential
        let node_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate node key")?;

        let serial_bytes = random_serial();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, node_id);
        params.is_ca = IsCa::ExplicitNoCa;
        // Pin `not_before` to issuance time. `CertificateParams::default()`
        // leaves it at rcgen's 1975 sentinel, which makes
        // `renew_at = nb + 2/3*(na-nb)` compute a date decades in the past on
        // the agent side — the renewal task then fires on every tick instead
        // of at 2/3 of the configured TTL.
        params.not_before = now_offset();
        params.not_after = offset_after_secs(ttl_secs);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));

        let cert = params
            .signed_by(&node_key, &self.ca_cert, &self.ca_key)
            .context("Failed to sign node certificate")?;

        Ok(IssuedCert {
            cert_pem: cert.pem(),
            key_pem: node_key.serialize_pem(),
            serial: serial_bytes,
        })
    }

    fn issue_node_cert_from_csr(
        &self,
        node_id: &str,
        csr_pem: &str,
        ttl_secs: u64,
    ) -> Result<IssuedCert> {
        // rcgen's `from_pem` parses the PKCS#10 request AND verifies its
        // signature using the embedded public key — a malformed CSR or one
        // whose signature doesn't match the public key is rejected here.
        let parsed = CertificateSigningRequestParams::from_pem(csr_pem)
            .context("Failed to parse or verify CSR signature")?;

        // Build a fresh certificate profile from scratch. The CSR's own
        // extensions (KU/EKU/SAN/etc.) are intentionally discarded — they're
        // agent-controlled and could otherwise be used to widen the issued
        // cert's privileges (e.g. add ServerAuth). Only the CSR's public key
        // is carried forward.
        let serial_bytes = random_serial();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, node_id);
        params.is_ca = IsCa::ExplicitNoCa;
        // Pin `not_before` to issuance time. `CertificateParams::default()`
        // leaves it at rcgen's 1975 sentinel, which makes
        // `renew_at = nb + 2/3*(na-nb)` compute a date decades in the past on
        // the agent side — the renewal task then fires on every tick instead
        // of at 2/3 of the configured TTL.
        params.not_before = now_offset();
        params.not_after = offset_after_secs(ttl_secs);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));

        let to_sign = CertificateSigningRequestParams {
            params,
            public_key: parsed.public_key,
        };
        let cert = to_sign
            .signed_by(&self.ca_cert, &self.ca_key)
            .context("Failed to sign renewal certificate from CSR")?;

        Ok(IssuedCert {
            cert_pem: cert.pem(),
            // Agent already holds the matching key — the controller never sees
            // it. See the trait doc.
            key_pem: String::new(),
            serial: serial_bytes,
        })
    }

    fn issue_server_cert(&self, sans: &[String], ttl_secs: u64) -> Result<IssuedCert> {
        let primary = sans
            .first()
            .ok_or_else(|| anyhow::anyhow!("issue_server_cert requires at least one SAN entry"))?;

        let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .context("Failed to generate server key")?;

        let serial_bytes = random_serial();
        // Build the SAN list explicitly so IP-address entries become
        // `iPAddress` GeneralNames rather than being encoded as `dNSName`.
        // WebPKI matches an IP the agent connects with only against an
        // `iPAddress` SAN; a `dNSName` holding "192.0.2.1" would not satisfy
        // it. `rcgen::CertificateParams::new` does this IP/DNS split itself,
        // but we spell it out so the behaviour is obvious and testable.
        let alt_names = sans
            .iter()
            .map(|s| san_type(s))
            .collect::<Result<Vec<_>>>()?;
        let mut params = CertificateParams::default();
        params.subject_alt_names = alt_names;
        params
            .distinguished_name
            .push(DnType::CommonName, primary.as_str());
        params.is_ca = IsCa::ExplicitNoCa;
        // Pin `not_before` to issuance time. `CertificateParams::default()`
        // leaves it at rcgen's 1975 sentinel, which makes
        // `renew_at = nb + 2/3*(na-nb)` compute a date decades in the past on
        // the agent side — the renewal task then fires on every tick instead
        // of at 2/3 of the configured TTL.
        params.not_before = now_offset();
        params.not_after = offset_after_secs(ttl_secs);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));

        let cert = params
            .signed_by(&server_key, &self.ca_cert, &self.ca_key)
            .context("Failed to sign server certificate")?;

        Ok(IssuedCert {
            cert_pem: cert.pem(),
            key_pem: server_key.serialize_pem(),
            serial: serial_bytes,
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Classify a SAN string: a value that parses as an `IpAddr` becomes an
/// `iPAddress` SAN, everything else a `dNSName`. DNS names are IA5 (ASCII)
/// only — a non-ASCII name is rejected rather than silently mangled.
fn san_type(s: &str) -> Result<SanType> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        Ok(SanType::IpAddress(ip))
    } else {
        let dns = Ia5String::try_from(s.to_string())
            .with_context(|| format!("SAN {s:?} is not a valid IP or DNS name"))?;
        Ok(SanType::DnsName(dns))
    }
}

fn build_ca_params(common_name: &str) -> Result<CertificateParams> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_after = OffsetDateTime::from_unix_timestamp(2_051_222_400) // 2035-01-01
        .context("Failed to build CA validity")?;
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

/// Generate a 16-byte random serial. The high bit is cleared so that the
/// DER-encoded INTEGER stays positive without rcgen needing to prepend a
/// leading zero byte (which would make the on-disk serial differ from what
/// we persisted).
fn random_serial() -> Vec<u8> {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf[0] &= 0x7f;
    if buf[0] == 0 {
        buf[0] = 1;
    }
    buf.to_vec()
}

/// Current wall-clock time as an `OffsetDateTime`, falling back to the UNIX
/// epoch if the system clock is somehow before 1970 (which would only happen
/// on a misconfigured VM). The fallback is harmless — the cert just gets a
/// slightly-too-early `not_before` and rcgen accepts it.
fn now_offset() -> OffsetDateTime {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn offset_after_secs(secs_from_now: u64) -> OffsetDateTime {
    // `time::OffsetDateTime::from_unix_timestamp` rejects values past year 9999.
    // If we naively `unwrap_or(UNIX_EPOCH)` on failure, an out-of-range input
    // silently produces a 1970-01-01 `not_after` — i.e. an instantly-expired
    // certificate is issued with no error. Clamp to the max representable
    // timestamp instead.
    const MAX_UNIX_TS: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(secs_from_now);
    let clamped = i64::try_from(secs).unwrap_or(MAX_UNIX_TS).min(MAX_UNIX_TS);
    OffsetDateTime::from_unix_timestamp(clamped)
        .unwrap_or_else(|_| OffsetDateTime::from_unix_timestamp(MAX_UNIX_TS).unwrap())
}

fn save_ca_files(key: &KeyPair, cert_pem: &str, key_path: &Path, cert_path: &Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let key_pem = key.serialize_pem();
    let mut key_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key_path)
        .with_context(|| format!("Failed to create CA key file: {}", key_path.display()))?;
    key_file
        .write_all(key_pem.as_bytes())
        .context("Failed to write CA key")?;

    std::fs::write(cert_path, cert_pem)
        .with_context(|| format!("Failed to write CA cert: {}", cert_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_ca(dir: &TempDir) -> FileCertificateAuthority {
        FileCertificateAuthority::load_or_create(
            &dir.path().join("ca.key"),
            &dir.path().join("ca.crt"),
            "Test Policy Controller CA",
        )
        .unwrap()
    }

    #[test]
    fn test_generates_ca_on_first_run() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let pem = ca.ca_cert_pem();
        assert!(!pem.is_empty());
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(dir.path().join("ca.key").exists());
        assert!(dir.path().join("ca.crt").exists());
    }

    #[test]
    fn test_ca_key_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        make_ca(&dir);
        let mode = std::fs::metadata(dir.path().join("ca.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "CA key must have mode 0600, got {:o}", mode);
    }

    #[test]
    fn test_ca_cert_pem_stable_across_loads() {
        let dir = TempDir::new().unwrap();
        let ca1 = make_ca(&dir);
        let pem1 = ca1.ca_cert_pem();

        let ca2 = make_ca(&dir);
        assert_eq!(
            ca2.ca_cert_pem(),
            pem1,
            "CA cert PEM must be stable across loads"
        );
    }

    #[test]
    fn test_ca_fingerprint_stable_across_loads() {
        let dir = TempDir::new().unwrap();
        let fp1 = make_ca(&dir).ca_fingerprint_sha256().unwrap();
        let fp2 = make_ca(&dir).ca_fingerprint_sha256().unwrap();
        assert_eq!(fp1, fp2, "Fingerprint must be stable across reloads");
        assert_eq!(fp1.len(), 32);
    }

    #[test]
    fn test_ca_fingerprint_differs_across_cas() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let fp1 = make_ca(&dir1).ca_fingerprint_sha256().unwrap();
        let fp2 = make_ca(&dir2).ca_fingerprint_sha256().unwrap();
        assert_ne!(fp1, fp2, "Two distinct CAs must have distinct fingerprints");
    }

    #[test]
    fn test_issue_node_cert_produces_valid_pem() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let issued = ca.issue_node_cert("node-abc123", 90 * 86_400).unwrap();
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_issue_server_cert_produces_valid_pem() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let issued = ca
            .issue_server_cert(&["controller.example.com".to_string()], 365 * 86_400)
            .unwrap();
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_issue_server_cert_rejects_empty_sans() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let err = ca
            .issue_server_cert(&[], 3600)
            .expect_err("a server cert with no SANs is useless and must be rejected");
        assert!(format!("{err:#}").contains("at least one SAN"));
    }

    /// The whole point of the multi-SAN change: a cert issued for a mix of DNS
    /// names and IP addresses must encode the IPs as `iPAddress` GeneralNames
    /// (not `dNSName`), otherwise agents connecting to the controller by IP
    /// fail WebPKI hostname verification.
    #[test]
    fn test_issue_server_cert_encodes_ip_and_dns_sans() {
        use x509_parser::extensions::GeneralName;
        use x509_parser::prelude::FromDer;
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let issued = ca
            .issue_server_cert(
                &[
                    "policy-controller".to_string(),
                    "192.168.1.235".to_string(),
                    "fd00::1".to_string(),
                ],
                3600,
            )
            .unwrap();

        let mut reader = issued.cert_pem.as_bytes();
        let der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
        let (_rest, parsed) = x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
        let san = parsed
            .subject_alternative_name()
            .unwrap()
            .expect("cert must carry a SAN extension");

        let mut dns = Vec::new();
        let mut ips = Vec::new();
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(n) => dns.push(n.to_string()),
                GeneralName::IPAddress(bytes) => ips.push(bytes.len()),
                _ => {}
            }
        }
        assert_eq!(dns, vec!["policy-controller".to_string()], "DNS SANs");
        // One 4-byte (v4) and one 16-byte (v6) iPAddress SAN.
        ips.sort_unstable();
        assert_eq!(
            ips,
            vec![4, 16],
            "IPv4 + IPv6 iPAddress SANs must be present"
        );
    }

    /// Build a real CSR from a fresh P-256 keypair so we can drive
    /// `issue_node_cert_from_csr` against a CSR that actually verifies.
    fn make_csr_pem(cn: &str) -> (rcgen::KeyPair, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        (key, csr_pem)
    }

    #[test]
    fn test_issue_node_cert_from_csr_signs_with_csr_public_key() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let (_key, csr_pem) = make_csr_pem("node-xyz");

        let issued = ca
            .issue_node_cert_from_csr("node-xyz", &csr_pem, 60)
            .expect("CSR-signed issuance must succeed");

        // The agent already holds the private key — controller must not echo
        // it back. A non-empty `key_pem` would mean the controller fabricated
        // a key, defeating the point of the CSR flow.
        assert!(
            issued.key_pem.is_empty(),
            "CSR-signed renewal must not return a private key"
        );
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!issued.serial.is_empty(), "serial must be populated");
    }

    #[test]
    fn test_issue_node_cert_from_csr_rejects_malformed_csr() {
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);

        let err = ca
            .issue_node_cert_from_csr("node-xyz", "not a csr", 60)
            .expect_err("malformed CSR must be rejected");
        assert!(format!("{err:#}").contains("CSR"));
    }

    // Regression: `offset_after_secs` (and its predecessor `offset_after_days`)
    // previously fell back to `OffsetDateTime::UNIX_EPOCH` whenever the input
    // was large enough that `from_unix_timestamp` rejected the computed
    // seconds — silently producing a `not_after` of 1970-01-01 (an
    // instantly-expired cert).
    #[test]
    fn test_offset_after_secs_does_not_fall_back_to_epoch_on_overflow() {
        let result = offset_after_secs(u64::MAX);
        assert!(
            result.unix_timestamp() > OffsetDateTime::UNIX_EPOCH.unix_timestamp(),
            "offset_after_secs(u64::MAX) returned epoch (or earlier): {}",
            result
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            result.unix_timestamp() > now,
            "offset_after_secs(u64::MAX) must be in the future, got {} vs now {}",
            result.unix_timestamp(),
            now
        );
    }

    #[test]
    fn test_offset_after_secs_handles_normal_values() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let result = offset_after_secs(90 * 86_400);
        let delta = result.unix_timestamp() - now;
        // Expect ~90 days, allow a few seconds slack for timing.
        assert!(
            (delta - 90 * 86_400).abs() < 5,
            "offset_after_secs(90d) should be ~90d in the future, got delta={}s",
            delta
        );
    }

    #[test]
    fn test_offset_after_secs_handles_small_values() {
        // The cert-rotation suite mints ~60s certs; the helper must produce a
        // not_after that's actually 60s out, not silently rounded to today.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let result = offset_after_secs(60);
        let delta = result.unix_timestamp() - now;
        assert!(
            (delta - 60).abs() < 5,
            "offset_after_secs(60) should be ~60s in the future, got delta={}s",
            delta
        );
    }

    /// Regression: rcgen's `CertificateParams::default()` leaves `not_before`
    /// at a 1975 sentinel. If we don't override it the agent's
    /// `parse_cert_window` computes `renew_at = nb + 2/3*(na-nb)` ~35 years
    /// in the past, and the renewal task fires on every tick. Assert that
    /// every issued cert pins `not_before` to "now-ish" (within a minute of
    /// issuance).
    #[test]
    fn test_issued_certs_have_recent_not_before() {
        use x509_parser::prelude::FromDer;
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        for (label, pem) in [
            (
                "node cert",
                ca.issue_node_cert("n1", 3600).unwrap().cert_pem,
            ),
            (
                "server cert",
                ca.issue_server_cert(&["controller".to_string()], 3600)
                    .unwrap()
                    .cert_pem,
            ),
            ("CSR-signed", {
                let (_k, csr) = make_csr_pem("n1");
                ca.issue_node_cert_from_csr("n1", &csr, 3600)
                    .unwrap()
                    .cert_pem
            }),
        ] {
            let mut reader = pem.as_bytes();
            let der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
            let (_rest, parsed) =
                x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
            let nb = parsed.validity().not_before.timestamp();
            let delta = (now - nb).abs();
            assert!(
                delta < 60,
                "{label}: not_before must be within 60s of now (got delta={delta}s) — \
                 a 1975 sentinel here would make the agent renewal task thrash"
            );
        }
    }

    #[test]
    fn test_issue_node_cert_with_extreme_ttl_does_not_silently_fail() {
        // Previously, a very large ttl caused `offset_after_*` to fall back to
        // `UNIX_EPOCH`, so `signed_by` would issue a cert with `not_after =
        // 1970-01-01` — already expired — without returning an error.
        // Issuance should succeed AND the call should not panic or error.
        let dir = TempDir::new().unwrap();
        let ca = make_ca(&dir);
        let issued = ca
            .issue_node_cert("node-overflow", u64::MAX)
            .expect("issue_node_cert should still succeed with extreme ttl_secs");
        assert!(!issued.cert_pem.is_empty(), "cert PEM must not be empty");
    }
}
