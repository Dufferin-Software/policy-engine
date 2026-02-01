// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use anyhow::{bail, Context, Result};
use p256::pkcs8::EncodePublicKey;

use super::{derive_node_id, read_dmi_uuid, NodeIdentity};

const TPM_RESOURCE_MANAGER: &str = "/dev/tpmrm0";
const TPM_DIRECT: &str = "/dev/tpm0";

// Owner hierarchy persistent handle range: 0x81000000–0x817FFFFF
const IDENTITY_PERSISTENT_HANDLE: u32 = 0x81000001;

/// Returns `true` if a TPM 2.0 device node is present on this machine.
pub fn tpm_device_present() -> bool {
    std::path::Path::new(TPM_RESOURCE_MANAGER).exists() || std::path::Path::new(TPM_DIRECT).exists()
}

/// TPM 2.0 backed node identity.
///
/// The private key is generated inside the TPM and never exposed in software.
/// Node ID stability is ensured by using a persistent NV handle in the TPM.
///
/// A two-level key hierarchy is used: a restricted storage primary key under
/// the Owner hierarchy acts as the parent for the unrestricted ECDSA P-256
/// signing key. The signing key is persisted at handle 0x81000001 so that the
/// same node ID is used across reboots and agent restarts.
pub struct TpmNodeIdentity {
    node_id: String,
    public_key_der: Vec<u8>,
    dmi_uuid: Option<String>,
}

impl TpmNodeIdentity {
    /// Attempt to initialise a TPM-backed identity using the resource manager.
    ///
    /// Loads the existing persistent signing key from the TPM, or creates and
    /// persists a new ECDSA P-256 key if none exists. Returns an error if the
    /// TPM is not accessible.
    pub fn load_or_create() -> Result<Self> {
        if !tpm_device_present() {
            bail!(
                "No TPM 2.0 device found at {} or {}",
                TPM_RESOURCE_MANAGER,
                TPM_DIRECT
            );
        }

        let public_key_der =
            tpm_load_or_create_key().context("Failed to initialize TPM identity key")?;
        let node_id = derive_node_id(&public_key_der);
        let dmi_uuid = read_dmi_uuid();

        log::info!("TPM-backed node identity initialized, node_id={}", node_id);

        Ok(Self {
            node_id,
            public_key_der,
            dmi_uuid,
        })
    }
}

impl NodeIdentity for TpmNodeIdentity {
    fn node_id(&self) -> String {
        self.node_id.clone()
    }

    fn public_key_der(&self) -> Vec<u8> {
        self.public_key_der.clone()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        tpm_sign(data)
    }

    fn dmi_uuid(&self) -> Option<String> {
        self.dmi_uuid.clone()
    }

    fn tpm_available(&self) -> bool {
        true
    }
}

// ── TPM operations ────────────────────────────────────────────────────────────

fn tcti_path() -> String {
    if std::path::Path::new(TPM_RESOURCE_MANAGER).exists() {
        format!("device:{}", TPM_RESOURCE_MANAGER)
    } else {
        format!("device:{}", TPM_DIRECT)
    }
}

fn open_context() -> Result<tss_esapi::Context> {
    use std::str::FromStr;
    use tss_esapi::TctiNameConf;

    let tcti = TctiNameConf::from_str(&tcti_path()).context("Invalid TCTI path")?;
    tss_esapi::Context::new(tcti).context("Failed to connect to TPM")
}

/// Load the persistent signing key, or create a new one if it does not exist.
/// Returns the SPKI DER-encoded public key.
fn tpm_load_or_create_key() -> Result<Vec<u8>> {
    use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};

    let mut ctx = open_context()?;

    let persistent_handle = PersistentTpmHandle::new(IDENTITY_PERSISTENT_HANDLE)
        .context("Invalid persistent handle")?;

    // Try to find an existing key at the persistent handle.
    let key_handle: KeyHandle =
        match ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle)) {
            Ok(obj) => {
                log::info!(
                    "Loaded existing TPM identity key from persistent handle 0x{:08x}",
                    IDENTITY_PERSISTENT_HANDLE
                );
                KeyHandle::from(obj)
            }
            Err(_) => {
                log::info!(
                    "No TPM identity key found at 0x{:08x}, creating new key",
                    IDENTITY_PERSISTENT_HANDLE
                );
                create_and_persist_signing_key(&mut ctx, persistent_handle)?
            }
        };

    // Read and return the public key.
    let (public, _, _) = ctx
        .read_public(key_handle)
        .context("Failed to read TPM public key")?;
    ecc_public_to_spki_der(&public).context("Failed to convert TPM public key to SPKI DER")
}

/// Create an ECDSA P-256 signing key, persist it, and return its handle.
fn create_and_persist_signing_key(
    ctx: &mut tss_esapi::Context,
    persistent_handle: tss_esapi::handles::PersistentTpmHandle,
) -> Result<tss_esapi::handles::KeyHandle> {
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        handles::KeyHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            dynamic_handles::Persistent,
            ecc::EccCurve,
            resource_handles::{Hierarchy, Provision},
            session_handles::AuthSession,
        },
        structures::{
            EccPoint, EccScheme, HashScheme, PublicBuilder, PublicEccParametersBuilder,
            SymmetricDefinitionObject,
        },
    };

    // Build storage primary key template (restricted ECC decrypt key).
    let primary_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .context("Failed to build primary key attributes")?;

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(primary_attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .context("Failed to build primary ECC parameters")?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("Failed to build primary key template")?;

    // Owner hierarchy auth requires at least a password session, even when
    // the hierarchy auth value is empty. Without it the TPM returns BAD_VALUE
    // (TSS2 ESAPI layer 0x7000B) on CreatePrimary.
    let primary_result = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .context("Failed to create TPM storage primary key")?;

    // Build unrestricted ECDSA P-256 signing key template.
    let signing_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .context("Failed to build signing key attributes")?;

    let signing_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(signing_attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()
            .context("Failed to build signing key ECC parameters")?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("Failed to build signing key template")?;

    // Create and Load authorize against the parent key (the storage primary),
    // so they also need a session. Use the password session — the primary was
    // created with an empty auth value.
    let key_result = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(
                primary_result.key_handle,
                signing_pub,
                None,
                None,
                None,
                None,
            )
        })
        .context("Failed to create TPM signing key")?;

    let transient_handle = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(
                primary_result.key_handle,
                key_result.out_private,
                key_result.out_public,
            )
        })
        .context("Failed to load signing key into TPM")?;

    // Persist the key at the designated handle (requires Owner auth session).
    let persistent = Persistent::Persistent(persistent_handle);
    ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.evict_control(Provision::Owner, transient_handle.into(), persistent)
    })
    .context("Failed to persist TPM signing key")?;

    // Reload the persistent handle as a KeyHandle.
    let persistent_obj = ctx
        .tr_from_tpm_public(tss_esapi::handles::TpmHandle::Persistent(persistent_handle))
        .context("Failed to load persisted signing key")?;

    Ok(KeyHandle::from(persistent_obj))
}

/// Sign `data` with the persistent TPM signing key. Returns 64-byte P1363 r‖s.
fn tpm_sign(data: &[u8]) -> Result<Vec<u8>> {
    use tss_esapi::{
        handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
        interface_types::{
            algorithm::HashingAlgorithm, resource_handles::Hierarchy, session_handles::AuthSession,
        },
        structures::{HashScheme, MaxBuffer, Signature, SignatureScheme},
    };

    let mut ctx = open_context()?;

    let persistent_handle = PersistentTpmHandle::new(IDENTITY_PERSISTENT_HANDLE)
        .context("Invalid persistent handle")?;

    let key_obj = ctx
        .tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
        .context("Failed to load signing key from TPM")?;
    let key_handle = KeyHandle::from(key_obj);

    // Hash the data via the TPM to obtain a valid HashcheckTicket.
    let buf = MaxBuffer::try_from(data.to_vec()).context("Data too large for TPM hash")?;
    let (digest, validation) = ctx
        .hash(buf, HashingAlgorithm::Sha256, Hierarchy::Null)
        .context("TPM hash failed")?;

    // Sign requires a session.
    let signature = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.sign(
                key_handle,
                digest,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                validation,
            )
        })
        .context("TPM signing failed")?;

    // Extract r‖s in IEEE P1363 format (32 bytes each, zero-padded).
    match signature {
        Signature::EcDsa(ecc_sig) => {
            let r = ecc_sig.signature_r().value();
            let s = ecc_sig.signature_s().value();

            let mut result = vec![0u8; 64];
            let r_start = 32usize.saturating_sub(r.len());
            let s_start = 32usize.saturating_sub(s.len());
            result[r_start..32].copy_from_slice(&r[r.len().saturating_sub(32)..]);
            result[32 + s_start..].copy_from_slice(&s[s.len().saturating_sub(32)..]);
            Ok(result)
        }
        _ => bail!("Unexpected signature type from TPM (expected EcDsa)"),
    }
}

/// Convert a TPM ECC P-256 public key to SPKI DER bytes.
fn ecc_public_to_spki_der(public: &tss_esapi::structures::Public) -> Result<Vec<u8>> {
    use tss_esapi::structures::Public;

    match public {
        Public::Ecc { unique, .. } => {
            let x_raw = unique.x().value();
            let y_raw = unique.y().value();

            // P-256 coordinates must be 32 bytes; zero-pad on the left if shorter.
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            let xlen = x_raw.len().min(32);
            let ylen = y_raw.len().min(32);
            x[32 - xlen..].copy_from_slice(&x_raw[x_raw.len() - xlen..]);
            y[32 - ylen..].copy_from_slice(&y_raw[y_raw.len() - ylen..]);

            // Build uncompressed SEC1 encoding: 0x04 || x || y
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);

            let pub_key = p256::PublicKey::from_sec1_bytes(&sec1)
                .map_err(|e| anyhow::anyhow!("Invalid P-256 point received from TPM: {}", e))?;

            Ok(pub_key
                .to_public_key_der()
                .context("Failed to encode public key as SPKI DER")?
                .into_vec())
        }
        _ => bail!("Expected ECC public key from TPM"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_create_errors_without_tpm() {
        // On a machine without a TPM device, load_or_create must fail gracefully.
        if tpm_device_present() {
            // Skip: a real TPM is available so the call may succeed or fail
            // depending on state; the integration tests cover that path.
            return;
        }
        let result = TpmNodeIdentity::load_or_create();
        assert!(
            result.is_err(),
            "Should return an error when no TPM device present"
        );
    }

    #[test]
    fn test_tpm_detection_is_bool() {
        let _ = tpm_device_present();
    }
}
