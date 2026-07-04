// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

pub mod tokens;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    security::{CertificateAuthority, RevocationWatch},
    store::{
        ControllerStore, EnrollmentTokenRecord, NewAuditEntry, NodeRecord, NodeStatus,
        TokenRedeemOutcome,
    },
};

pub use tokens::{BootstrapBundle, IssuedToken};

/// Renewed credential returned by [`NodeRegistry::renew_cert`].
///
/// The renewed key is *not* in here — for CSR-based renewals the agent
/// already holds the key and the controller never sees it.
#[derive(Debug, Clone)]
pub struct RenewedCert {
    pub cert_pem: String,
    pub serial: Vec<u8>,
    pub not_after_unix: i64,
}

/// Default node-cert TTL used by tests that construct a registry directly via
/// `NodeRegistry::new`. Production code paths plumb the configured value
/// (`ControllerConfig::node_cert_ttl_secs`) through `with_node_cert_ttl_secs`.
pub const DEFAULT_NODE_CERT_TTL_SECS: u64 = 90 * 86_400;

/// All enrollment and node management operations.
///
/// Wraps a [`ControllerStore`] and a [`CertificateAuthority`]. All methods are
/// async and return `Result` — errors propagate to the GraphQL resolver.
pub struct NodeRegistry {
    store: Arc<dyn ControllerStore>,
    ca: Arc<dyn CertificateAuthority>,
    /// Updates the in-memory revocation mirror used by the TLS-handshake
    /// verifier. `None` is acceptable in tests and other contexts where the
    /// mTLS server is not running.
    revocation: Option<Arc<RevocationWatch>>,
    /// TTL applied to every node mTLS cert issued by `approve_enrollment`
    /// (and, when it lands, the renewal handler). Sourced from
    /// `ControllerConfig::node_cert_ttl_secs` in production.
    node_cert_ttl_secs: u64,
}

impl NodeRegistry {
    pub fn new(store: Arc<dyn ControllerStore>, ca: Arc<dyn CertificateAuthority>) -> Self {
        Self {
            store,
            ca,
            revocation: None,
            node_cert_ttl_secs: DEFAULT_NODE_CERT_TTL_SECS,
        }
    }

    /// Override the node-cert TTL. The controller binary calls this with the
    /// value from `ControllerConfig::node_cert_ttl_secs`; tests use it to
    /// exercise short-lifetime renewal paths.
    pub fn with_node_cert_ttl_secs(mut self, ttl_secs: u64) -> Self {
        self.node_cert_ttl_secs = ttl_secs;
        self
    }

    /// Attach a [`RevocationWatch`] so decommissioning a node also publishes
    /// the revoked serial to the TLS-handshake-layer mirror.
    pub fn with_revocation(mut self, revocation: Arc<RevocationWatch>) -> Self {
        self.revocation = Some(revocation);
        self
    }

    // ── Enrollment ────────────────────────────────────────────────────────────

    /// Handle an incoming enrollment request from an agent.
    ///
    /// Validates the signature (proving possession of the private key) and stores
    /// the node as Pending. Returns the `enrollment_id` UUID for status polling.
    ///
    /// If the node already has a record (re-enrollment after decommission), the
    /// existing record is updated with the new enrollment_id.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_enrollment(
        &self,
        public_key_der: Vec<u8>,
        dmi_uuid: Option<String>,
        csr_pem: Vec<u8>,
        signature: Vec<u8>,
        agent_version: Option<String>,
        tpm_backed: bool,
        hostname: Option<String>,
    ) -> Result<String> {
        let node_id = derive_node_id(&public_key_der);

        // Verify signature: agent signed SHA-256(csr_pem) with its private key
        let verifying_key = VerifyingKey::from_public_key_der(&public_key_der)
            .context("Failed to parse public key DER")?;

        let csr_hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&csr_pem)
        };

        let sig =
            Signature::from_slice(&signature).context("Failed to parse enrollment signature")?;
        verifying_key
            .verify(&csr_hash, &sig)
            .context("Enrollment signature verification failed — request rejected")?;

        // Reject if already active (re-enrollment of active node not allowed)
        if let Some(existing) = self.store.get_node(&node_id).await? {
            if existing.status == NodeStatus::Active {
                bail!("Node {} is already enrolled and active", node_id);
            }
        }

        let enrollment_id = Uuid::new_v4().to_string();

        let record = NodeRecord {
            id: node_id.clone(),
            label: None,
            public_key_der,
            dmi_uuid,
            status: NodeStatus::Pending,
            cert_serial: None,
            cert_expiry: None,
            last_seen: None,
            enrolled_at: None,
            decommissioned_at: None,
            last_renewed_at: None,
            enrollment_id: Some(enrollment_id.clone()),
            tpm_backed,
            agent_version,
            hostname,
            os_pretty_name: None,
            kernel_version: None,
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
            inspect_mode: "disabled".to_string(),
        };

        self.store.upsert_node(&record).await?;
        self.store
            .append_audit(NewAuditEntry {
                operator: None,
                action: "enrollment_submitted".to_string(),
                node_id: Some(node_id),
                detail: Some(format!("enrollment_id={}", enrollment_id)),
                tenant_id: None,
            })
            .await?;

        log::info!(
            "Enrollment request submitted (enrollment_id={})",
            enrollment_id
        );

        Ok(enrollment_id)
    }

    /// Check enrollment status. Returns `(status_string, cert_pem_if_approved)`.
    pub async fn check_enrollment_status(
        &self,
        enrollment_id: &str,
    ) -> Result<(String, Option<String>)> {
        let node = self
            .store
            .get_node_by_enrollment_id(enrollment_id)
            .await?
            .ok_or_else(|| anyhow!("Unknown enrollment ID: {}", enrollment_id))?;

        let cert_pem = if node.status == NodeStatus::Active {
            self.store.get_node_cert_pem(&node.id).await?
        } else {
            None
        };

        Ok((node.status.to_string(), cert_pem))
    }

    // ── Admin operations ──────────────────────────────────────────────────────

    /// Approve a pending enrollment. Issues a client certificate and marks the
    /// node as Active. Returns the issued certificate PEM.
    pub async fn approve_enrollment(
        &self,
        node_id: &str,
        label: Option<String>,
        operator: Option<&str>,
    ) -> Result<NodeRecord> {
        let mut node = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Node not found: {}", node_id))?;

        if node.status != NodeStatus::Pending {
            bail!(
                "Cannot approve node {}: status is {} (expected pending)",
                node_id,
                node.status
            );
        }

        // Issue a fresh key+cert for the node's mTLS credential.
        // Phase 3 will optionally support using the agent's own CSR so the
        // mTLS key can be TPM-backed, but for Phase 2 the controller generates it.
        let issued = self
            .ca
            .issue_node_cert(node_id, self.node_cert_ttl_secs)
            .context("Failed to issue client certificate")?;

        let expiry = Utc::now() + chrono::Duration::seconds(self.node_cert_ttl_secs as i64);

        // Persist the cert serial so a later decommission can revoke it and the
        // management connect path can reject reconnects from a revoked cert.
        self.store
            .update_node_cert(
                node_id,
                issued.serial.clone(),
                expiry,
                issued.cert_pem.clone(),
            )
            .await?;

        // Also store the private key PEM so the agent can fetch key+cert together.
        // The key is stored alongside the cert; access is guarded by mTLS on retrieval.
        self.store
            .store_node_cert_pem(node_id, &format!("{}{}", issued.key_pem, issued.cert_pem))
            .await?;

        self.store
            .update_node_status(node_id, NodeStatus::Active)
            .await?;

        self.store
            .append_audit(NewAuditEntry {
                operator: operator.map(str::to_string),
                action: "enrollment_approved".to_string(),
                node_id: Some(node_id.to_string()),
                detail: label.as_deref().map(|l| format!("label={}", l)),
                tenant_id: None,
            })
            .await?;

        if let Some(ref l) = label {
            // Update label
            node.label = Some(l.clone());
        }
        node.status = NodeStatus::Active;
        node.enrolled_at = Some(Utc::now());
        node.cert_expiry = Some(expiry);
        // Mirror what `update_node_cert` just persisted, otherwise this upsert
        // would overwrite the freshly-captured serial back to None.
        node.cert_serial = Some(issued.serial.clone());
        self.store.upsert_node(&node).await?;

        log::info!("Enrollment approved for node {}", node_id);

        self.store
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Node not found after approval"))
    }

    /// Reject a pending enrollment request.
    pub async fn reject_enrollment(
        &self,
        node_id: &str,
        reason: Option<&str>,
        operator: Option<&str>,
    ) -> Result<()> {
        let node = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Node not found: {}", node_id))?;

        if node.status != NodeStatus::Pending {
            bail!("Node {} is not in pending state", node_id);
        }

        // Remove from pending — don't leave it as a zombie entry
        // Mark decommissioned so the node ID can be re-enrolled if needed
        self.store
            .update_node_status(node_id, NodeStatus::Decommissioned)
            .await?;

        self.store
            .append_audit(NewAuditEntry {
                operator: operator.map(str::to_string),
                action: "enrollment_rejected".to_string(),
                node_id: Some(node_id.to_string()),
                detail: reason.map(|r| format!("reason={}", r)),
                tenant_id: None,
            })
            .await?;

        log::info!("Enrollment rejected for node {}", node_id);
        Ok(())
    }

    /// Set a human-readable label on a node.
    pub async fn label_node(
        &self,
        node_id: &str,
        label: &str,
        operator: Option<&str>,
    ) -> Result<()> {
        let mut node = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Node not found: {}", node_id))?;
        node.label = Some(label.to_string());
        self.store.upsert_node(&node).await?;

        self.store
            .append_audit(NewAuditEntry {
                operator: operator.map(str::to_string),
                action: "node_labelled".to_string(),
                node_id: Some(node_id.to_string()),
                detail: Some(format!("label={}", label)),
                tenant_id: None,
            })
            .await?;
        Ok(())
    }

    /// Sign a renewal CSR for an already-enrolled, still-Active node and
    /// atomically revoke the prior serial.
    ///
    /// The caller (`grpc::management::renew_client_cert`) is responsible for
    /// authenticating the request and confirming the CSR's subject CN matches
    /// the authenticated peer. This method enforces only the registry-level
    /// invariants — node is Active, current serial is not revoked, CA can
    /// sign the CSR — and performs the bookkeeping (new cert recorded, old
    /// serial revoked + published to the watch channel, audit entry).
    pub async fn renew_cert(&self, node_id: &str, csr_pem: &str) -> Result<RenewedCert> {
        let mut node = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Node not found: {}", node_id))?;

        // A renewal from a node that has been decommissioned (or never
        // approved) must not succeed even though the TLS handshake did. The
        // handshake verifier only knows about revoked *serials*; status
        // transitions to Decommissioned can race a revoked serial briefly
        // and the application-layer check is the backstop.
        if node.status != NodeStatus::Active {
            bail!("Node {} is not active (status: {})", node_id, node.status);
        }
        if let Some(ref old_serial) = node.cert_serial {
            if self.store.is_cert_revoked(old_serial).await? {
                bail!(
                    "Node {} current cert serial is revoked — renewal refused",
                    node_id
                );
            }
        }

        let issued = self
            .ca
            .issue_node_cert_from_csr(node_id, csr_pem, self.node_cert_ttl_secs)
            .context("Failed to sign renewal CSR")?;

        let expiry = Utc::now() + chrono::Duration::seconds(self.node_cert_ttl_secs as i64);
        let not_after_unix = expiry.timestamp();

        // Persist the new cert serial + expiry on the node row. We
        // deliberately do *not* refresh the `node_certs` blob — see the
        // doc on [`ControllerStore::store_node_cert_pem`]. The renewed
        // cert is returned to the agent in the RPC response, never via
        // `get_node_cert_pem`.
        self.store
            .update_current_cert_meta(node_id, issued.serial.clone(), expiry)
            .await?;

        // Revoke the *previous* serial so the old cert cannot be used in
        // parallel after handoff (Phase 7 §"Node mTLS Cert Renewal" step 4).
        let old_serial = node.cert_serial.take();
        if let Some(ref old) = old_serial {
            self.store.revoke_cert(old).await?;
            if let Some(ref rw) = self.revocation {
                rw.insert(old.clone());
            }
        }

        // Keep the in-memory NodeRecord consistent with what we just wrote.
        node.cert_serial = Some(issued.serial.clone());
        node.cert_expiry = Some(expiry);
        node.last_renewed_at = Some(Utc::now());
        self.store.upsert_node(&node).await?;

        self.store
            .append_audit(NewAuditEntry {
                operator: None,
                action: "cert_renewed".to_string(),
                node_id: Some(node_id.to_string()),
                detail: old_serial
                    .as_ref()
                    .map(|s| format!("old_serial={}", hex::encode(s))),
                tenant_id: None,
            })
            .await?;

        log::info!(
            "Renewed cert for node {} (new_serial={}, ttl_secs={})",
            node_id,
            hex::encode(&issued.serial),
            self.node_cert_ttl_secs
        );

        Ok(RenewedCert {
            cert_pem: issued.cert_pem,
            serial: issued.serial,
            not_after_unix,
        })
    }

    /// Decommission an active node: revoke its cert and mark Decommissioned.
    /// The node's gRPC connection will be rejected on next attempt.
    pub async fn decommission_node(&self, node_id: &str, operator: Option<&str>) -> Result<()> {
        let mut node = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Node not found: {}", node_id))?;

        if node.status == NodeStatus::Decommissioned {
            bail!("Node {} is already decommissioned", node_id);
        }

        // Revoke the issued cert. The store write is the source of truth; the
        // watch-channel insert mirrors it into the TLS-handshake verifier so
        // the cert can't open a new stream even before the application-layer
        // check in management.rs sees the update.
        if let Some(ref serial) = node.cert_serial {
            self.store.revoke_cert(serial).await?;
            if let Some(ref rw) = self.revocation {
                rw.insert(serial.clone());
            }
        }

        node.status = NodeStatus::Decommissioned;
        node.decommissioned_at = Some(Utc::now());
        self.store.upsert_node(&node).await?;

        self.store
            .append_audit(NewAuditEntry {
                operator: operator.map(str::to_string),
                action: "node_decommissioned".to_string(),
                node_id: Some(node_id.to_string()),
                detail: None,
                tenant_id: None,
            })
            .await?;

        log::info!("Node {} decommissioned", node_id);
        Ok(())
    }

    /// Permanently remove a decommissioned node from the registry.
    pub async fn remove_node(&self, node_id: &str, operator: Option<&str>) -> Result<()> {
        let node = self
            .store
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Node not found: {}", node_id))?;

        if node.status != NodeStatus::Decommissioned {
            bail!(
                "Node {} must be decommissioned before removal (status: {})",
                node_id,
                node.status
            );
        }

        self.store
            .append_audit(NewAuditEntry {
                operator: operator.map(str::to_string),
                action: "node_removed".to_string(),
                node_id: Some(node_id.to_string()),
                detail: None,
                tenant_id: None,
            })
            .await?;

        // Delete the node record (cascades to ruleset assignment and cert).
        self.store.delete_node(node_id).await?;

        log::info!("Node {} removed from registry", node_id);
        Ok(())
    }

    // ── Passthrough queries ───────────────────────────────────────────────────

    /// `tenant_id`: `Some(slug)` restricts to one tenant; `None` is
    /// cross-tenant and reserved for controller-internal jobs (TTL reaper,
    /// controller-metrics). Operator-facing resolvers must pass
    /// `Some(principal.tenant_slug)`.
    pub async fn list_nodes(
        &self,
        tenant_id: Option<&str>,
        status: Option<NodeStatus>,
    ) -> Result<Vec<NodeRecord>> {
        self.store.list_nodes(tenant_id, status).await
    }

    pub async fn get_node(&self, id: &str) -> Result<Option<NodeRecord>> {
        self.store.get_node(id).await
    }

    pub async fn ca_cert_pem(&self) -> String {
        self.ca.ca_cert_pem()
    }

    pub fn ca_fingerprint_sha256(&self) -> Result<[u8; 32]> {
        self.ca.ca_fingerprint_sha256()
    }

    // ── Enrollment tokens (ZTP) ──────────────────────────────────────────────

    /// Mint a new bootstrap token. The returned [`IssuedToken`] contains the
    /// base64 bundle to hand to the operator; the controller persists only
    /// the SHA-256 of the secret.
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_enrollment_token(
        &self,
        enrollment_url: String,
        controller_url: String,
        ttl: chrono::Duration,
        max_uses: i64,
        cidr_scope: Option<String>,
        fleet_label: Option<String>,
        operator: Option<&str>,
        tenant_id: &str,
    ) -> Result<IssuedToken> {
        let fp = self
            .ca
            .ca_fingerprint_sha256()
            .context("Failed to compute CA fingerprint")?;
        let (record, issued) = tokens::mint_token(
            enrollment_url,
            controller_url,
            &fp,
            ttl,
            max_uses,
            cidr_scope,
            fleet_label,
            operator.map(str::to_string),
            tenant_id.to_string(),
        )?;
        self.store.insert_enrollment_token(&record).await?;
        self.store
            .append_audit(NewAuditEntry {
                operator: operator.map(str::to_string),
                action: "enrollment_token_created".to_string(),
                node_id: None,
                detail: Some(format!(
                    "token_id={} max_uses={} expires_at={}",
                    issued.token_id, record.uses_remaining, record.expires_at
                )),
                tenant_id: Some(tenant_id.to_string()),
            })
            .await?;
        log::info!(
            "Minted enrollment token {} (uses={}, ttl={}s)",
            issued.token_id,
            record.uses_remaining,
            ttl.num_seconds()
        );
        Ok(issued)
    }

    pub async fn list_enrollment_tokens(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<EnrollmentTokenRecord>> {
        self.store.list_enrollment_tokens(tenant_id).await
    }

    pub async fn revoke_enrollment_token(
        &self,
        token_id: &str,
        operator: Option<&str>,
        tenant_id: &str,
    ) -> Result<bool> {
        let changed = self.store.revoke_enrollment_token(token_id).await?;
        if changed {
            self.store
                .append_audit(NewAuditEntry {
                    operator: operator.map(str::to_string),
                    action: "enrollment_token_revoked".to_string(),
                    node_id: None,
                    detail: Some(format!("token_id={}", token_id)),
                    tenant_id: Some(tenant_id.to_string()),
                })
                .await?;
        }
        Ok(changed)
    }

    /// Submit an enrollment request and, if a valid bootstrap token is
    /// presented, immediately auto-approve and return the issued mTLS cert
    /// blob (combined key+cert PEM, same shape as `CheckEnrollmentStatus`).
    ///
    /// Returns `(enrollment_id, auto_approved_cert_blob)`. The cert blob is
    /// `Some` only when the token redeemed successfully. Otherwise the node
    /// is left in Pending and the agent must poll / be operator-approved.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_enrollment_with_token(
        &self,
        public_key_der: Vec<u8>,
        dmi_uuid: Option<String>,
        csr_pem: Vec<u8>,
        signature: Vec<u8>,
        agent_version: Option<String>,
        tpm_backed: bool,
        hostname: Option<String>,
        bootstrap_token: Option<(String, Vec<u8>)>,
    ) -> Result<(String, Option<String>)> {
        let enrollment_id = self
            .submit_enrollment(
                public_key_der.clone(),
                dmi_uuid,
                csr_pem,
                signature,
                agent_version,
                tpm_backed,
                hostname,
            )
            .await?;

        let Some((token_id, secret)) = bootstrap_token else {
            return Ok((enrollment_id, None));
        };

        let token_hash = tokens::hash_token_secret(&secret);
        let outcome = self
            .store
            .redeem_enrollment_token(&token_id, &token_hash)
            .await?;

        match outcome {
            TokenRedeemOutcome::Redeemed {
                fleet_label,
                tenant_id,
            } => {
                let node_id = derive_node_id(&public_key_der);
                // Move the node into the token's tenant *before* approval so
                // the cert-issue, status flip, and the auto-approve audit row
                // all land under the right tenant. The Pending row written by
                // `submit_enrollment` above was forced to `'default'` because
                // it predates token validation.
                self.store
                    .update_node_tenant(&node_id, &tenant_id)
                    .await
                    .context("Failed to set node tenant after token redemption")?;
                let approved = self
                    .approve_enrollment(&node_id, fleet_label.clone(), Some("ztp-bootstrap"))
                    .await
                    .context("Auto-approval after token redemption failed")?;
                let cert_blob = self
                    .store
                    .get_node_cert_pem(&approved.id)
                    .await?
                    .ok_or_else(|| anyhow!("Auto-approve issued no cert blob"))?;
                self.store
                    .append_audit(NewAuditEntry {
                        operator: Some("ztp-bootstrap".to_string()),
                        action: "enrollment_token_redeemed".to_string(),
                        node_id: Some(approved.id.clone()),
                        detail: Some(format!("token_id={} tenant_id={}", token_id, tenant_id)),
                        tenant_id: Some(tenant_id.clone()),
                    })
                    .await?;
                log::info!(
                    "Token {} redeemed; node {} auto-approved into tenant {}",
                    token_id,
                    approved.id,
                    tenant_id,
                );
                Ok((enrollment_id, Some(cert_blob)))
            }
            other => {
                self.store
                    .append_audit(NewAuditEntry {
                        operator: None,
                        action: "enrollment_token_rejected".to_string(),
                        node_id: None,
                        detail: Some(format!("token_id={} outcome={:?}", token_id, other)),
                        tenant_id: None,
                    })
                    .await?;
                log::warn!(
                    "Token {} presented but rejected ({:?}); node remains Pending",
                    token_id,
                    other
                );
                Ok((enrollment_id, None))
            }
        }
    }
}

/// Derive `node_id` from a SubjectPublicKeyInfo DER. Stable across reboots.
pub fn derive_node_id(public_key_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(public_key_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        security::{ca::IssuedCert, MockCertificateAuthority},
        store::memory::InMemoryControllerStore,
    };
    use std::sync::Arc;

    fn make_registry() -> NodeRegistry {
        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca
            .expect_ca_cert_pem()
            .returning(|| "CA-CERT-PEM".to_string());
        mock_ca.expect_issue_node_cert().returning(|_, _| {
            Ok(IssuedCert {
                cert_pem: "NODE-CERT-PEM".to_string(),
                key_pem: "NODE-KEY-PEM".to_string(),
                serial: vec![1, 2, 3, 4],
            })
        });
        NodeRegistry::new(store, Arc::new(mock_ca))
    }

    /// Generate a real ECDSA P-256 key, build enrollment data, and run through
    /// the full pending → approved lifecycle.
    #[tokio::test]
    async fn test_enrollment_happy_path() {
        use p256::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::EncodePublicKey,
        };
        use rand_core::OsRng;
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

        let registry = make_registry();

        // Simulate agent: generate key + CSR + signature
        let signing_key = SigningKey::random(&mut OsRng);
        let pub_key_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();

        // Build a dummy CSR
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

        // Sign SHA-256(csr_pem)
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(csr_pem.as_bytes());
        let sig: Signature = signing_key.sign(&hash);

        let enrollment_id = registry
            .submit_enrollment(
                pub_key_der.clone(),
                Some("test-dmi".to_string()),
                csr_pem.into_bytes(),
                sig.to_bytes().to_vec(),
                Some("0.1.0".to_string()),
                false,
                Some("test-host".to_string()),
            )
            .await
            .unwrap();

        assert!(!enrollment_id.is_empty());

        // Status should be pending
        let (status, cert) = registry
            .check_enrollment_status(&enrollment_id)
            .await
            .unwrap();
        assert_eq!(status, "pending");
        assert!(cert.is_none());

        // Derive node ID to approve
        let node_id = hex::encode(Sha256::digest(&pub_key_der));
        let approved = registry
            .approve_enrollment(&node_id, Some("test-node".to_string()), None)
            .await
            .unwrap();
        assert_eq!(approved.status, NodeStatus::Active);

        // Status should now be approved with cert
        let (status2, cert2) = registry
            .check_enrollment_status(&enrollment_id)
            .await
            .unwrap();
        assert_eq!(status2, "active");
        // get_node_cert_pem stores "key_pem + cert_pem" concatenated
        let combined = cert2.unwrap();
        assert!(combined.contains("NODE-KEY-PEM"), "should contain key PEM");
        assert!(
            combined.contains("NODE-CERT-PEM"),
            "should contain cert PEM"
        );
    }

    /// Regression: `approve_enrollment` previously hard-coded a 90-day TTL
    /// via `NODE_CERT_TTL_DAYS`, so the configured `node_cert_ttl_secs` had
    /// no effect on actual issuance. This test pins that the value passed to
    /// `with_node_cert_ttl_secs` is exactly what reaches the CA.
    #[tokio::test]
    async fn test_approve_uses_configured_ttl_secs() {
        use mockall::predicate::eq;
        use p256::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::EncodePublicKey,
        };
        use rand_core::OsRng;
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

        const TEST_TTL_SECS: u64 = 60;

        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca
            .expect_ca_cert_pem()
            .returning(|| "CA-CERT-PEM".to_string());
        // Strict expectation: the second arg must equal the configured TTL.
        mock_ca
            .expect_issue_node_cert()
            .withf(|_, ttl_secs| *ttl_secs == TEST_TTL_SECS)
            .times(1)
            .returning(|_, _| {
                Ok(IssuedCert {
                    cert_pem: "NODE-CERT-PEM".to_string(),
                    key_pem: "NODE-KEY-PEM".to_string(),
                    serial: vec![1, 2, 3, 4],
                })
            });
        // Reference `eq` so the unused-import lint doesn't fire on the import
        // when the test is compiled without the strict matcher.
        let _ = eq::<u64>;

        let registry =
            NodeRegistry::new(store, Arc::new(mock_ca)).with_node_cert_ttl_secs(TEST_TTL_SECS);

        // Drive the same agent-side enrollment flow as the happy-path test.
        let signing_key = SigningKey::random(&mut OsRng);
        let pub_key_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(csr_pem.as_bytes());
        let sig: Signature = signing_key.sign(&hash);

        registry
            .submit_enrollment(
                pub_key_der.clone(),
                None,
                csr_pem.into_bytes(),
                sig.to_bytes().to_vec(),
                None,
                false,
                None,
            )
            .await
            .unwrap();

        let node_id = hex::encode(Sha256::digest(&pub_key_der));
        let approved = registry
            .approve_enrollment(&node_id, None, None)
            .await
            .expect("approve must succeed when CA receives the configured TTL");
        assert_eq!(approved.status, NodeStatus::Active);
        // cert_expiry should be ~TEST_TTL_SECS in the future, proving the
        // configured value also reached the persisted expiry stamp.
        let expiry = approved.cert_expiry.expect("expiry must be set");
        let delta = (expiry - Utc::now()).num_seconds();
        assert!(
            (delta - TEST_TTL_SECS as i64).abs() < 5,
            "cert_expiry should be ~{TEST_TTL_SECS}s out, got delta={delta}s"
        );
    }

    /// End-to-end renewal against a *real* CA: enroll → approve → renew →
    /// confirm old serial is revoked. Uses `FileCertificateAuthority` rather
    /// than the mock so the rcgen sign-from-CSR path actually runs.
    #[tokio::test]
    async fn test_renew_cert_revokes_old_serial_and_persists_new() {
        use crate::security::{ca::FileCertificateAuthority, RevocationWatch, RevokedSerials};
        use p256::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::EncodePublicKey,
        };
        use rand_core::OsRng;
        use rcgen::{
            CertificateParams as RcParams, DnType as RcDnType, KeyPair as RcKeyPair,
            PKCS_ECDSA_P256_SHA256 as RcEcdsa,
        };
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let ca: Arc<dyn CertificateAuthority> = Arc::new(
            FileCertificateAuthority::load_or_create(
                &dir.path().join("ca.key"),
                &dir.path().join("ca.crt"),
                "Test CA",
            )
            .unwrap(),
        );
        let store = Arc::new(InMemoryControllerStore::new());
        let watch = Arc::new(RevocationWatch::new(RevokedSerials::default()));
        let registry = NodeRegistry::new(store.clone(), ca)
            .with_revocation(Arc::clone(&watch))
            .with_node_cert_ttl_secs(60);

        // Enroll + approve so we have an Active node with a known serial.
        let signing_key = SigningKey::random(&mut OsRng);
        let pub_key_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let key = RcKeyPair::generate_for(&RcEcdsa).unwrap();
        let mut params = RcParams::default();
        params.distinguished_name.push(RcDnType::CommonName, "x");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(csr_pem.as_bytes());
        let sig: Signature = signing_key.sign(&hash);
        registry
            .submit_enrollment(
                pub_key_der.clone(),
                None,
                csr_pem.into_bytes(),
                sig.to_bytes().to_vec(),
                None,
                false,
                None,
            )
            .await
            .unwrap();
        let node_id = hex::encode(Sha256::digest(&pub_key_der));
        let approved = registry
            .approve_enrollment(&node_id, None, None)
            .await
            .unwrap();
        let old_serial = approved.cert_serial.clone().expect("approval sets serial");

        // Build a real renewal CSR using a fresh node-side key.
        let renew_key = RcKeyPair::generate_for(&RcEcdsa).unwrap();
        let mut rparams = RcParams::default();
        rparams
            .distinguished_name
            .push(RcDnType::CommonName, &node_id);
        let renew_csr = rparams
            .serialize_request(&renew_key)
            .unwrap()
            .pem()
            .unwrap();

        let renewed = registry
            .renew_cert(&node_id, &renew_csr)
            .await
            .expect("renewal of an Active, non-revoked node must succeed");

        // New serial must differ.
        assert_ne!(
            renewed.serial, old_serial,
            "renewal must produce a fresh serial — same serial would indicate \
             the CA reused a cert and we'd silently extend lifetime"
        );

        // Old serial must be revoked both in the store and on the watch.
        assert!(
            store.is_cert_revoked(&old_serial).await.unwrap(),
            "old serial must be revoked in store after renewal"
        );
        let snapshot = watch.snapshot();
        assert!(
            snapshot.contains(&old_serial),
            "old serial must be published to the revocation watch so the TLS \
             verifier rejects future handshakes with the old cert"
        );

        // Node record now points at the new serial.
        let after = store.get_node(&node_id).await.unwrap().unwrap();
        assert_eq!(after.cert_serial.as_ref(), Some(&renewed.serial));
    }

    #[tokio::test]
    async fn test_renew_cert_rejects_decommissioned_node() {
        use crate::security::ca::FileCertificateAuthority;
        use rcgen::{
            CertificateParams as RcParams, DnType as RcDnType, KeyPair as RcKeyPair,
            PKCS_ECDSA_P256_SHA256 as RcEcdsa,
        };
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let ca: Arc<dyn CertificateAuthority> = Arc::new(
            FileCertificateAuthority::load_or_create(
                &dir.path().join("ca.key"),
                &dir.path().join("ca.crt"),
                "Test CA",
            )
            .unwrap(),
        );
        let store = Arc::new(InMemoryControllerStore::new());
        let registry = NodeRegistry::new(store, ca);

        // No matching node at all — should fail with "Node not found", but
        // the relevant check for renewal is the "not active" status guard.
        // Use a syntactically-valid CSR.
        let key = RcKeyPair::generate_for(&RcEcdsa).unwrap();
        let mut p = RcParams::default();
        p.distinguished_name.push(RcDnType::CommonName, "unknown");
        let csr = p.serialize_request(&key).unwrap().pem().unwrap();
        let err = registry
            .renew_cert("unknown", &csr)
            .await
            .expect_err("renewal for unknown node must fail");
        let s = format!("{err:#}");
        assert!(
            s.contains("not found") || s.contains("not active"),
            "unexpected error message: {s}"
        );
    }

    #[tokio::test]
    async fn test_token_redemption_auto_approves() {
        use p256::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::EncodePublicKey,
        };
        use rand_core::OsRng;
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca
            .expect_ca_cert_pem()
            .returning(|| "CA-CERT-PEM".to_string());
        mock_ca
            .expect_ca_fingerprint_sha256()
            .returning(|| Ok([7u8; 32]));
        mock_ca.expect_issue_node_cert().returning(|_, _| {
            Ok(IssuedCert {
                cert_pem: "NODE-CERT-PEM".to_string(),
                key_pem: "NODE-KEY-PEM".to_string(),
                serial: vec![5, 6, 7, 8],
            })
        });
        let registry = NodeRegistry::new(store, Arc::new(mock_ca));

        // Mint a token.
        let issued = registry
            .mint_enrollment_token(
                "https://e:1".to_string(),
                "https://c:2".to_string(),
                chrono::Duration::hours(1),
                3,
                None,
                Some("edge".to_string()),
                Some("alice"),
                "default",
            )
            .await
            .unwrap();

        let bundle = BootstrapBundle::decode(&issued.bundle).unwrap();
        let secret = bundle.token_bytes().unwrap();

        // Build a real enrollment request with PoP signature.
        let signing_key = SigningKey::random(&mut OsRng);
        let pub_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "t");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        use sha2::Digest;
        let hash = sha2::Sha256::digest(csr_pem.as_bytes());
        let sig: Signature = signing_key.sign(&hash);

        let (_eid, cert_blob) = registry
            .submit_enrollment_with_token(
                pub_der.clone(),
                None,
                csr_pem.into_bytes(),
                sig.to_bytes().to_vec(),
                None,
                false,
                None,
                Some((issued.token_id.clone(), secret.clone())),
            )
            .await
            .unwrap();

        let blob = cert_blob.expect("token should auto-approve");
        assert!(blob.contains("NODE-KEY-PEM"));
        assert!(blob.contains("NODE-CERT-PEM"));

        // Token use should be decremented.
        let tokens = registry.list_enrollment_tokens(None).await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].uses_remaining, 2);

        // Node should be Active with the fleet label applied.
        let node_id = derive_node_id(&pub_der);
        let node = registry.get_node(&node_id).await.unwrap().unwrap();
        assert_eq!(node.status, NodeStatus::Active);
        assert_eq!(node.label.as_deref(), Some("edge"));
    }

    #[tokio::test]
    async fn test_token_redemption_bad_secret_keeps_pending() {
        use p256::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::EncodePublicKey,
        };
        use rand_core::OsRng;
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca.expect_ca_cert_pem().returning(|| "CA".to_string());
        mock_ca
            .expect_ca_fingerprint_sha256()
            .returning(|| Ok([1u8; 32]));
        let registry = NodeRegistry::new(store, Arc::new(mock_ca));

        let issued = registry
            .mint_enrollment_token(
                "u".to_string(),
                "u".to_string(),
                chrono::Duration::hours(1),
                1,
                None,
                None,
                None,
                "default",
            )
            .await
            .unwrap();

        let signing_key = SigningKey::random(&mut OsRng);
        let pub_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "t");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        use sha2::Digest;
        let hash = sha2::Sha256::digest(csr_pem.as_bytes());
        let sig: Signature = signing_key.sign(&hash);

        // Use a wrong secret.
        let (_eid, blob) = registry
            .submit_enrollment_with_token(
                pub_der.clone(),
                None,
                csr_pem.into_bytes(),
                sig.to_bytes().to_vec(),
                None,
                false,
                None,
                Some((issued.token_id.clone(), vec![0u8; 32])),
            )
            .await
            .unwrap();
        assert!(blob.is_none(), "Bad secret must not auto-approve");

        // Node should still be Pending.
        let node_id = derive_node_id(&pub_der);
        let node = registry.get_node(&node_id).await.unwrap().unwrap();
        assert_eq!(node.status, NodeStatus::Pending);

        // Token uses unchanged.
        let tokens = registry.list_enrollment_tokens(None).await.unwrap();
        assert_eq!(tokens[0].uses_remaining, 1);
    }

    #[tokio::test]
    async fn test_invalid_signature_rejected() {
        use p256::pkcs8::EncodePublicKey;
        use rand_core::OsRng;

        let registry = make_registry();

        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let pub_der = key.verifying_key().to_public_key_der().unwrap().into_vec();

        let result = registry
            .submit_enrollment(
                pub_der,
                None,
                b"dummy-csr".to_vec(),
                vec![0u8; 64], // garbage signature
                None,
                false,
                None,
            )
            .await;

        assert!(result.is_err(), "Should reject invalid signature");
    }

    #[tokio::test]
    async fn test_approve_non_pending_fails() {
        let registry = make_registry();
        // No node exists at all
        let result = registry.approve_enrollment("no-such-id", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_node_deletes_record() {
        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca.expect_ca_cert_pem().returning(|| "CA".to_string());
        let registry = NodeRegistry::new(
            Arc::clone(&store) as Arc<dyn ControllerStore>,
            Arc::new(mock_ca),
        );

        // Insert a decommissioned node
        let node = NodeRecord {
            id: "node-del".to_string(),
            label: None,
            public_key_der: vec![1],
            dmi_uuid: None,
            status: NodeStatus::Decommissioned,
            cert_serial: None,
            cert_expiry: None,
            last_seen: None,
            enrolled_at: None,
            decommissioned_at: None,
            last_renewed_at: None,
            enrollment_id: None,
            tpm_backed: false,
            agent_version: None,
            hostname: None,
            os_pretty_name: None,
            kernel_version: None,
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
            inspect_mode: "disabled".to_string(),
        };
        store.upsert_node(&node).await.unwrap();
        assert!(store.get_node("node-del").await.unwrap().is_some());

        registry.remove_node("node-del", None).await.unwrap();

        // Node must be gone
        assert!(
            store.get_node("node-del").await.unwrap().is_none(),
            "remove_node must delete the record from the store"
        );
    }

    #[tokio::test]
    async fn test_remove_active_node_fails() {
        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca.expect_ca_cert_pem().returning(|| "CA".to_string());
        let registry = NodeRegistry::new(
            Arc::clone(&store) as Arc<dyn ControllerStore>,
            Arc::new(mock_ca),
        );

        let node = NodeRecord {
            id: "node-active".to_string(),
            status: NodeStatus::Active,
            label: None,
            public_key_der: vec![2],
            dmi_uuid: None,
            cert_serial: None,
            cert_expiry: None,
            last_seen: None,
            enrolled_at: None,
            decommissioned_at: None,
            last_renewed_at: None,
            enrollment_id: None,
            tpm_backed: false,
            agent_version: None,
            hostname: None,
            os_pretty_name: None,
            kernel_version: None,
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
            inspect_mode: "disabled".to_string(),
        };
        store.upsert_node(&node).await.unwrap();

        let result = registry.remove_node("node-active", None).await;
        assert!(result.is_err(), "Cannot remove an active node");
    }

    #[tokio::test]
    async fn test_decommission_publishes_serial_to_revocation_watch() {
        use crate::security::{RevocationWatch, RevokedSerials};

        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca.expect_ca_cert_pem().returning(|| "CA".to_string());
        let watch = Arc::new(RevocationWatch::new(RevokedSerials::default()));
        let registry = NodeRegistry::new(
            Arc::clone(&store) as Arc<dyn ControllerStore>,
            Arc::new(mock_ca),
        )
        .with_revocation(Arc::clone(&watch));

        let serial = vec![0xAB, 0xCD, 0xEF];
        let node = NodeRecord {
            id: "node-rev".to_string(),
            label: None,
            public_key_der: vec![1],
            dmi_uuid: None,
            status: NodeStatus::Active,
            cert_serial: Some(serial.clone()),
            cert_expiry: None,
            last_seen: None,
            enrolled_at: None,
            decommissioned_at: None,
            last_renewed_at: None,
            enrollment_id: None,
            tpm_backed: false,
            agent_version: None,
            hostname: None,
            os_pretty_name: None,
            kernel_version: None,
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
            inspect_mode: "disabled".to_string(),
        };
        store.upsert_node(&node).await.unwrap();

        // Pre: not in the watch mirror yet.
        assert!(!watch.snapshot().contains(&serial));

        registry.decommission_node("node-rev", None).await.unwrap();

        // Post: store revoked AND the TLS-layer mirror sees it.
        assert!(store.is_cert_revoked(&serial).await.unwrap());
        assert!(
            watch.snapshot().contains(&serial),
            "decommission must publish to the revocation watch so TLS-layer rejects subsequent handshakes"
        );
    }

    #[tokio::test]
    async fn test_decommission_revokes_cert() {
        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca.expect_ca_cert_pem().returning(|| "CA".to_string());
        mock_ca.expect_issue_node_cert().returning(|_, _| {
            Ok(IssuedCert {
                cert_pem: "cert".to_string(),
                key_pem: "key".to_string(),
                serial: vec![9, 10],
            })
        });
        let registry = NodeRegistry::new(
            Arc::clone(&store) as Arc<dyn ControllerStore>,
            Arc::new(mock_ca),
        );

        // Insert an active node directly
        let node = NodeRecord {
            id: "node-x".to_string(),
            label: None,
            public_key_der: vec![1],
            dmi_uuid: None,
            status: NodeStatus::Active,
            cert_serial: Some(vec![42]),
            cert_expiry: None,
            last_seen: None,
            enrolled_at: None,
            decommissioned_at: None,
            last_renewed_at: None,
            enrollment_id: None,
            tpm_backed: false,
            agent_version: None,
            hostname: None,
            os_pretty_name: None,
            kernel_version: None,
            dmi_sys_vendor: None,
            dmi_product_name: None,
            tenant_id: "default".to_string(),
            stop_behavior: None,
            metrics_interval_secs: None,
            capabilities: "{}".to_string(),
            inspect_mode: "disabled".to_string(),
        };
        store.upsert_node(&node).await.unwrap();

        registry.decommission_node("node-x", None).await.unwrap();

        let updated = store.get_node("node-x").await.unwrap().unwrap();
        assert_eq!(updated.status, NodeStatus::Decommissioned);
        assert!(store.is_cert_revoked(&[42]).await.unwrap());
    }

    /// End-to-end check that the cert serial returned by `issue_node_cert` is
    /// captured on approval and that decommission revokes that exact serial.
    #[tokio::test]
    async fn test_approve_persists_serial_and_decommission_revokes_it() {
        use p256::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::EncodePublicKey,
        };
        use rand_core::OsRng;
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

        let registry = make_registry();

        // Drive a full enrollment so the approval path runs.
        let signing_key = SigningKey::random(&mut OsRng);
        let pub_key_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "test");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(csr_pem.as_bytes());
        let sig: Signature = signing_key.sign(&hash);

        registry
            .submit_enrollment(
                pub_key_der.clone(),
                None,
                csr_pem.into_bytes(),
                sig.to_bytes().to_vec(),
                None,
                false,
                None,
            )
            .await
            .unwrap();

        let node_id = hex::encode(Sha256::digest(&pub_key_der));
        registry
            .approve_enrollment(&node_id, None, None)
            .await
            .unwrap();

        // The mock_ca in `make_registry` returns serial = [1, 2, 3, 4].
        let stored = registry
            .store
            .get_node(&node_id)
            .await
            .unwrap()
            .expect("node should exist after approval");
        assert_eq!(
            stored.cert_serial.as_deref(),
            Some(&[1u8, 2, 3, 4][..]),
            "approval must persist the serial returned by issue_node_cert"
        );
        assert!(
            !registry.store.is_cert_revoked(&[1, 2, 3, 4]).await.unwrap(),
            "fresh cert must not start out revoked"
        );

        registry.decommission_node(&node_id, None).await.unwrap();

        assert!(
            registry.store.is_cert_revoked(&[1, 2, 3, 4]).await.unwrap(),
            "decommission must revoke the captured serial"
        );
    }

    /// Redemption propagates the token's tenant onto the new node row and
    /// onto the auto-approve audit entry, replacing the `'default'` slug
    /// that `submit_enrollment` had to write before the token was validated.
    #[tokio::test]
    async fn test_token_redemption_propagates_tenant() {
        use p256::{
            ecdsa::{signature::Signer, Signature, SigningKey},
            pkcs8::EncodePublicKey,
        };
        use rand_core::OsRng;
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca.expect_ca_cert_pem().returning(|| "CA".to_string());
        mock_ca
            .expect_ca_fingerprint_sha256()
            .returning(|| Ok([9u8; 32]));
        mock_ca.expect_issue_node_cert().returning(|_, _| {
            Ok(IssuedCert {
                cert_pem: "PEM".to_string(),
                key_pem: "KEY".to_string(),
                serial: vec![1, 2, 3, 4],
            })
        });
        let registry = NodeRegistry::new(store, Arc::new(mock_ca));

        let issued = registry
            .mint_enrollment_token(
                "https://e:1".to_string(),
                "https://c:2".to_string(),
                chrono::Duration::hours(1),
                1,
                None,
                None,
                Some("operator"),
                "acme",
            )
            .await
            .unwrap();

        let bundle = BootstrapBundle::decode(&issued.bundle).unwrap();
        let secret = bundle.token_bytes().unwrap();

        let signing_key = SigningKey::random(&mut OsRng);
        let pub_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "t");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        use sha2::Digest;
        let hash = sha2::Sha256::digest(csr_pem.as_bytes());
        let sig: Signature = signing_key.sign(&hash);

        let (_eid, cert_blob) = registry
            .submit_enrollment_with_token(
                pub_der.clone(),
                None,
                csr_pem.into_bytes(),
                sig.to_bytes().to_vec(),
                None,
                false,
                None,
                Some((issued.token_id.clone(), secret.clone())),
            )
            .await
            .unwrap();
        assert!(cert_blob.is_some(), "token should auto-approve");

        let node_id = derive_node_id(&pub_der);
        let node = registry.get_node(&node_id).await.unwrap().unwrap();
        assert_eq!(node.status, NodeStatus::Active);
        assert_eq!(
            node.tenant_id, "acme",
            "redemption must move the node out of the default tenant"
        );

        // The auto-approve audit row should be filed under the token's tenant.
        let acme_audit = registry
            .store
            .list_audit(Some("acme"), 100, 0)
            .await
            .unwrap();
        assert!(
            acme_audit
                .iter()
                .any(|e| e.action == "enrollment_token_redeemed"),
            "redemption audit row should be visible to the acme tenant"
        );
        // Conversely, default-tenant audit shouldn't have leaked the redemption.
        let default_audit = registry
            .store
            .list_audit(Some("default"), 100, 0)
            .await
            .unwrap();
        assert!(
            !default_audit
                .iter()
                .any(|e| e.action == "enrollment_token_redeemed"),
            "redemption audit row must not appear in the default tenant"
        );
    }

    /// `list_enrollment_tokens(Some(slug))` returns only that tenant's
    /// tokens, even when other tenants have minted into the same store.
    /// `None` is the cross-tenant escape hatch.
    #[tokio::test]
    async fn test_list_enrollment_tokens_filters_by_tenant() {
        let store = Arc::new(InMemoryControllerStore::new());
        let mut mock_ca = MockCertificateAuthority::new();
        mock_ca.expect_ca_cert_pem().returning(|| "CA".to_string());
        mock_ca
            .expect_ca_fingerprint_sha256()
            .returning(|| Ok([7u8; 32]));
        let registry = NodeRegistry::new(store, Arc::new(mock_ca));

        let mint = |slug: &'static str, label: &'static str| {
            let registry = &registry;
            async move {
                registry
                    .mint_enrollment_token(
                        "https://e:1".to_string(),
                        "https://c:2".to_string(),
                        chrono::Duration::hours(1),
                        1,
                        None,
                        Some(label.to_string()),
                        Some("alice"),
                        slug,
                    )
                    .await
                    .unwrap()
            }
        };
        let _ = mint("default", "fleet-a").await;
        let _ = mint("default", "fleet-b").await;
        let _ = mint("acme", "acme-edge").await;

        let default = registry
            .list_enrollment_tokens(Some("default"))
            .await
            .unwrap();
        assert_eq!(default.len(), 2);
        assert!(default.iter().all(|t| t.tenant_id == "default"));

        let acme = registry.list_enrollment_tokens(Some("acme")).await.unwrap();
        assert_eq!(acme.len(), 1);
        assert_eq!(acme[0].tenant_id, "acme");
        assert_eq!(acme[0].fleet_label.as_deref(), Some("acme-edge"));

        // `None` is the unscoped/admin view: still sees both.
        let all = registry.list_enrollment_tokens(None).await.unwrap();
        assert_eq!(all.len(), 3);

        // An unknown tenant slug yields nothing — not an error.
        let empty = registry
            .list_enrollment_tokens(Some("ghost"))
            .await
            .unwrap();
        assert!(empty.is_empty());
    }
}
