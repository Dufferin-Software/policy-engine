// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::Result;
use std::path::Path;

#[cfg(test)]
use mockall::automock;

mod file;
mod tpm;

pub use file::FileNodeIdentity;
pub use tpm::{tpm_device_present, TpmNodeIdentity};

/// Stable cryptographic identity for a policy-engine node.
///
/// The node ID is `hex(SHA-256(SubjectPublicKeyInfo DER))` — derived entirely
/// from the public key, so it is stable across hostname changes, IP changes,
/// and reboots. Hostnames are never used as identity.
///
/// Two backends are provided:
/// - [`FileNodeIdentity`]: ECDSA P-256 key stored as PKCS#8 PEM at mode 0600.
///   Chosen when no TPM is present or when the TPM cannot be initialised.
/// - [`TpmNodeIdentity`]: private key generated inside the TPM and never
///   exposed in software. Chosen automatically when a TPM 2.0 device is
///   present and accessible. Requires `libtss2-dev` at build time (Phase 7).
///
/// All methods return owned values (rather than borrows) so that the trait is
/// compatible with `mockall::automock` and can be freely used across async
/// task boundaries without lifetime concerns.
#[cfg_attr(test, automock)]
pub trait NodeIdentity: Send + Sync {
    /// Returns the hex-encoded node ID: `hex(SHA-256(public_key_der()))`.
    fn node_id(&self) -> String;

    /// Returns the DER-encoded SubjectPublicKeyInfo (SPKI) public key bytes.
    fn public_key_der(&self) -> Vec<u8>;

    /// Signs `data` using the node's private key.
    ///
    /// Returns the compact IEEE P1363 ECDSA-SHA256 signature (64 bytes: r‖s).
    /// The implementation hashes `data` with SHA-256 before signing.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Returns the DMI system UUID if readable from sysfs, for display only.
    /// Never used as identity — use [`node_id`] instead.
    fn dmi_uuid(&self) -> Option<String>;

    /// Returns `true` if the private key is stored inside a hardware TPM.
    fn tpm_available(&self) -> bool;
}

/// Select the best available identity backend at runtime.
///
/// 1. If a TPM 2.0 device node exists (`/dev/tpmrm0` or `/dev/tpm0`), attempt
///    `TpmNodeIdentity::load_or_create()`. On success, the TPM-backed identity
///    is used and `tpm_available()` returns `true`.
/// 2. If the TPM is present but cannot be initialised (library not built, key
///    creation failure, etc.), log a warning and fall through.
/// 3. Fall back to `FileNodeIdentity` using `file_key_path`.
///
/// The TPM check is purely runtime — no feature flags are involved.
pub fn select_identity(file_key_path: &Path) -> Result<Box<dyn NodeIdentity>> {
    if tpm_device_present() {
        log::info!("TPM 2.0 device detected, attempting TPM-backed identity");
        match TpmNodeIdentity::load_or_create() {
            Ok(id) => {
                log::info!("Using TPM-backed node identity");
                return Ok(Box::new(id));
            }
            Err(e) => {
                log::warn!(
                    "TPM present but could not initialise, falling back to file identity: {:#}",
                    e
                );
            }
        }
    }

    log::info!(
        "Using file-backed node identity at {}",
        file_key_path.display()
    );
    Ok(Box::new(FileNodeIdentity::load_or_create(file_key_path)?))
}

/// Read the DMI system UUID from sysfs (`/sys/class/dmi/id/product_uuid`).
/// Returns `None` on non-Linux systems or if the file is unreadable.
pub fn read_dmi_uuid() -> Option<String> {
    std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Derive a node ID from raw public key DER bytes.
/// `node_id = hex(SHA-256(public_key_der))`
pub fn derive_node_id(public_key_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(public_key_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_select_identity_falls_back_to_file() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("identity.key");

        // select_identity must always succeed (TPM may or may not be available)
        let id = select_identity(&key_path).unwrap();
        assert!(!id.node_id().is_empty());
        // If no TPM, key file should be written
        if !tpm_device_present() {
            assert!(key_path.exists(), "File identity key should be created");
        }
    }

    #[test]
    fn test_tpm_detection_is_bool() {
        // Should never panic, result depends on hardware
        let _ = tpm_device_present();
    }
}
