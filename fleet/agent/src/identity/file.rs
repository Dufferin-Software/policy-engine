// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{Context, Result};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use rand_core::OsRng;
use std::path::Path;

use super::{derive_node_id, read_dmi_uuid, NodeIdentity};

/// Node identity backed by an ECDSA P-256 key stored as PKCS#8 PEM file.
///
/// On first boot the key is generated using the OS CSPRNG and written to
/// `key_path` with mode `0600`. On subsequent boots the same key is loaded,
/// preserving the stable NodeID across reboots and upgrades.
pub struct FileNodeIdentity {
    node_id: String,
    public_key_der: Vec<u8>,
    signing_key: SigningKey,
    dmi_uuid: Option<String>,
}

impl FileNodeIdentity {
    /// Load an existing PKCS#8 PEM key or generate a fresh one.
    ///
    /// # Errors
    /// Returns an error if the key file exists but cannot be read or parsed,
    /// or if a new key cannot be written (e.g. permission denied).
    pub fn load_or_create(key_path: &Path) -> Result<Self> {
        let signing_key = if key_path.exists() {
            load_key(key_path)?
        } else {
            let key = SigningKey::random(&mut OsRng);
            save_key(&key, key_path)?;
            log::info!(
                "Generated new ECDSA P-256 identity key at {}",
                key_path.display()
            );
            key
        };

        // Use the full SubjectPublicKeyInfo (SPKI) DER bytes as the input to
        // the node ID hash, not just the raw EC point, to ensure format stability.
        let spki_der = p256::pkcs8::EncodePublicKey::to_public_key_der(signing_key.verifying_key())
            .context("Failed to encode public key as SubjectPublicKeyInfo DER")?
            .into_vec();

        let node_id = derive_node_id(&spki_der);
        let dmi_uuid = read_dmi_uuid();

        log::info!("Node ID: {}", node_id);
        if let Some(ref uuid) = dmi_uuid {
            log::debug!("DMI UUID: {}", uuid);
        }

        Ok(Self {
            node_id,
            public_key_der: spki_der,
            signing_key,
            dmi_uuid,
        })
    }
}

impl NodeIdentity for FileNodeIdentity {
    fn node_id(&self) -> String {
        self.node_id.clone()
    }

    fn public_key_der(&self) -> Vec<u8> {
        self.public_key_der.clone()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Signer<Signature> hashes data with SHA-256 before signing.
        let sig: Signature = self.signing_key.sign(data);
        Ok(sig.to_bytes().to_vec())
    }

    fn dmi_uuid(&self) -> Option<String> {
        self.dmi_uuid.clone()
    }

    fn tpm_available(&self) -> bool {
        false
    }
}

fn load_key(key_path: &Path) -> Result<SigningKey> {
    let pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read identity key: {}", key_path.display()))?;
    SigningKey::from_pkcs8_pem(&pem)
        .with_context(|| format!("Failed to parse PKCS#8 PEM key: {}", key_path.display()))
}

fn save_key(key: &SigningKey, key_path: &Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .context("Failed to encode identity key as PKCS#8 PEM")?;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key_path)
        .with_context(|| format!("Failed to create identity key file: {}", key_path.display()))?;

    file.write_all(pem.as_bytes())
        .with_context(|| format!("Failed to write identity key: {}", key_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_identity(dir: &TempDir) -> FileNodeIdentity {
        FileNodeIdentity::load_or_create(&dir.path().join("identity.key")).unwrap()
    }

    #[test]
    fn test_creates_new_key_on_first_boot() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("identity.key");

        assert!(!key_path.exists());
        let identity = FileNodeIdentity::load_or_create(&key_path).unwrap();
        assert!(key_path.exists());

        // Node ID is 64 lowercase hex chars (SHA-256 output)
        let nid = identity.node_id();
        assert_eq!(nid.len(), 64);
        assert!(nid.chars().all(|c| c.is_ascii_hexdigit()));

        // Public key DER is non-empty
        assert!(!identity.public_key_der().is_empty());

        // Not TPM-backed
        assert!(!identity.tpm_available());
    }

    #[test]
    fn test_key_persists_across_loads() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("identity.key");

        let id1 = FileNodeIdentity::load_or_create(&key_path).unwrap();
        let node_id1 = id1.node_id().to_string();
        let pub_key1 = id1.public_key_der().to_vec();

        // Second load must produce exactly the same key material
        let id2 = FileNodeIdentity::load_or_create(&key_path).unwrap();
        assert_eq!(id2.node_id(), node_id1, "NodeID changed across loads");
        assert_eq!(
            id2.public_key_der(),
            pub_key1,
            "Public key DER changed across loads"
        );
    }

    #[test]
    fn test_sign_returns_64_byte_compact_signature() {
        let dir = TempDir::new().unwrap();
        let identity = make_identity(&dir);

        let sig = identity.sign(b"test message").unwrap();
        // ECDSA P-256 compact (r‖s) signature is always exactly 64 bytes
        assert_eq!(sig.len(), 64, "Expected 64-byte compact signature");
    }

    #[test]
    fn test_different_data_produces_different_signatures() {
        let dir = TempDir::new().unwrap();
        let identity = make_identity(&dir);

        let sig1 = identity.sign(b"data A").unwrap();
        let sig2 = identity.sign(b"data B").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_independent_keys_produce_different_node_ids() {
        let dir = TempDir::new().unwrap();
        let id1 = FileNodeIdentity::load_or_create(&dir.path().join("k1.key")).unwrap();
        let id2 = FileNodeIdentity::load_or_create(&dir.path().join("k2.key")).unwrap();
        assert_ne!(id1.node_id(), id2.node_id());
    }

    #[test]
    fn test_node_id_is_sha256_of_spki_der() {
        let dir = TempDir::new().unwrap();
        let identity = make_identity(&dir);

        let expected = derive_node_id(&identity.public_key_der());
        assert_eq!(identity.node_id(), expected);
    }

    #[test]
    fn test_key_file_has_restricted_permissions() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("identity.key");
        FileNodeIdentity::load_or_create(&key_path).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&key_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Key file must have mode 0600, got {:o}", mode);
    }
}
