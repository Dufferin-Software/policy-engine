// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Zero-touch provisioning: enrollment token issuance and bundle codec.
//!
//! The operator mints a token via the GraphQL API or the
//! `policy-controller-client enroll-token create` CLI. The controller returns
//! a base64-encoded "bootstrap bundle" carrying the controller URL, the CA
//! fingerprint, and the token. The bundle is dropped onto target hosts and
//! the agent uses it to complete an unattended enrollment.
//!
//! Token security:
//! - The random 32-byte secret is shown to the operator exactly once at
//!   creation time. Only its SHA-256 is persisted (`enrollment_tokens.token_hash`).
//! - Tokens are scoped (TTL, max-uses, optional CIDR/fleet label) and revocable.
//! - Once consumed, the receiving agent has its own per-node mTLS cert; the
//!   token is no longer needed.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::store::EnrollmentTokenRecord;

/// Length of the random token secret in bytes.
pub const TOKEN_SECRET_BYTES: usize = 32;

/// What the operator sees when minting a token. The base64 `bundle` is
/// dropped onto target hosts; the raw token secret is never returned to disk
/// or exposed again after this moment.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub token_id: String,
    pub bundle: String,
    pub expires_at: DateTime<Utc>,
    pub uses_remaining: i64,
}

/// On-the-wire bundle format. Versioned for future extension (e.g. signed
/// bundles with operator pubkey, fleet-specific overrides, etc.).
///
/// Encoded as JSON, then base64url-no-pad (compact, copy-pasteable, no
/// trailing `=` to confuse shell tools).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapBundle {
    /// Bundle schema version. Currently 1.
    pub v: u32,
    /// gRPC URL of the enrollment endpoint (TLS, no client cert).
    pub enrollment_url: String,
    /// gRPC URL of the management endpoint (mTLS, used after enrollment).
    pub controller_url: String,
    /// SHA-256 over the DER of the controller's CA cert, hex-encoded.
    pub ca_fp_sha256: String,
    /// UUID for token lookup.
    pub token_id: String,
    /// Raw token secret, base64url-encoded (no padding).
    pub token_b64: String,
    /// Unix seconds, for early agent-side expiry checks (controller is authoritative).
    pub expires_at: i64,
}

impl BootstrapBundle {
    /// Encode the bundle to its compact base64url-no-pad transport form.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context("Failed to serialise bootstrap bundle")?;
        Ok(URL_SAFE_NO_PAD.encode(json))
    }

    /// Decode a base64url-no-pad bundle.
    pub fn decode(s: &str) -> Result<Self> {
        // Tolerate surrounding whitespace and a stray trailing newline from
        // `command > bundle.b64` etc.
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

    /// Decode the raw token secret from `token_b64`.
    pub fn token_bytes(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.token_b64)
            .context("Token in bootstrap bundle is not valid base64url-no-pad")
    }

    /// Decode the CA fingerprint as 32 raw bytes.
    pub fn ca_fingerprint_bytes(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.ca_fp_sha256)
            .context("ca_fp_sha256 in bootstrap bundle is not valid hex")?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("Expected 32-byte fingerprint, got {}", v.len()))
    }
}

/// Build a fresh token + bundle pair.
///
/// Returns:
/// - the `EnrollmentTokenRecord` to persist (contains only the hash, never the secret).
/// - the [`IssuedToken`] to show the operator (contains the bundle to distribute).
///
/// The raw token secret exists only inside the returned bundle string; after
/// this function returns, the controller cannot reconstruct it.
#[allow(clippy::too_many_arguments)]
pub fn mint_token(
    enrollment_url: String,
    controller_url: String,
    ca_fingerprint_sha256: &[u8; 32],
    ttl: chrono::Duration,
    max_uses: i64,
    cidr_scope: Option<String>,
    fleet_label: Option<String>,
    created_by: Option<String>,
    tenant_id: String,
) -> Result<(EnrollmentTokenRecord, IssuedToken)> {
    anyhow::ensure!(max_uses > 0, "max_uses must be positive");
    anyhow::ensure!(ttl > chrono::Duration::zero(), "ttl must be positive");

    let token_id = Uuid::new_v4().to_string();
    let mut secret = vec![0u8; TOKEN_SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut secret);

    let token_hash = Sha256::digest(&secret).to_vec();
    let now = Utc::now();
    let expires_at = now + ttl;

    let bundle = BootstrapBundle {
        v: 1,
        enrollment_url,
        controller_url,
        ca_fp_sha256: hex::encode(ca_fingerprint_sha256),
        token_id: token_id.clone(),
        token_b64: URL_SAFE_NO_PAD.encode(&secret),
        expires_at: expires_at.timestamp(),
    };

    let record = EnrollmentTokenRecord {
        token_id: token_id.clone(),
        token_hash,
        created_at: now,
        created_by,
        expires_at,
        uses_remaining: max_uses,
        cidr_scope,
        fleet_label,
        revoked_at: None,
        tenant_id,
    };

    let issued = IssuedToken {
        token_id,
        bundle: bundle.encode()?,
        expires_at,
        uses_remaining: max_uses,
    };

    Ok((record, issued))
}

/// Hash a token secret for comparison against the stored hash.
pub fn hash_token_secret(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_fp() -> [u8; 32] {
        let mut fp = [0u8; 32];
        for (i, b) in fp.iter_mut().enumerate() {
            *b = i as u8;
        }
        fp
    }

    #[test]
    fn test_mint_token_returns_consistent_hash() {
        let (record, issued) = mint_token(
            "https://enroll.example.com:7776".to_string(),
            "https://controller.example.com:7777".to_string(),
            &fake_fp(),
            chrono::Duration::hours(1),
            50,
            None,
            None,
            Some("alice".to_string()),
            "default".to_string(),
        )
        .unwrap();

        let bundle = BootstrapBundle::decode(&issued.bundle).unwrap();
        assert_eq!(bundle.token_id, record.token_id);

        let secret = bundle.token_bytes().unwrap();
        let recomputed = hash_token_secret(&secret).to_vec();
        assert_eq!(
            recomputed, record.token_hash,
            "Hashing the bundle secret must yield the stored hash"
        );
        assert_eq!(record.uses_remaining, 50);
        assert_eq!(record.created_by.as_deref(), Some("alice"));
    }

    #[test]
    fn test_bundle_roundtrip() {
        let (_, issued) = mint_token(
            "https://e.example:7776".to_string(),
            "https://c.example:7777".to_string(),
            &fake_fp(),
            chrono::Duration::hours(1),
            1,
            Some("10.0.0.0/8".to_string()),
            Some("edge".to_string()),
            None,
            "default".to_string(),
        )
        .unwrap();

        let bundle = BootstrapBundle::decode(&issued.bundle).unwrap();
        assert_eq!(bundle.v, 1);
        assert_eq!(bundle.enrollment_url, "https://e.example:7776");
        assert_eq!(bundle.controller_url, "https://c.example:7777");
        assert_eq!(bundle.ca_fingerprint_bytes().unwrap(), fake_fp());
        assert_eq!(bundle.token_bytes().unwrap().len(), TOKEN_SECRET_BYTES);
    }

    #[test]
    fn test_bundle_decode_tolerates_whitespace() {
        let (_, issued) = mint_token(
            "https://e:1".to_string(),
            "https://c:2".to_string(),
            &fake_fp(),
            chrono::Duration::hours(1),
            1,
            None,
            None,
            None,
            "default".to_string(),
        )
        .unwrap();
        let padded = format!("\n  {}\n", issued.bundle);
        let _ = BootstrapBundle::decode(&padded).unwrap();
    }

    #[test]
    fn test_bundle_decode_rejects_garbage() {
        assert!(BootstrapBundle::decode("not a bundle!!!").is_err());
    }

    #[test]
    fn test_mint_token_validates_args() {
        assert!(mint_token(
            "u".to_string(),
            "u".to_string(),
            &fake_fp(),
            chrono::Duration::hours(1),
            0,
            None,
            None,
            None,
            "default".to_string(),
        )
        .is_err());
        assert!(mint_token(
            "u".to_string(),
            "u".to_string(),
            &fake_fp(),
            chrono::Duration::zero(),
            1,
            None,
            None,
            None,
            "default".to_string(),
        )
        .is_err());
    }
}
