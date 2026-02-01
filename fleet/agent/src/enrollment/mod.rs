// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

pub mod bundle;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::time::sleep;

use policy_controller_proto::controller::{
    BootstrapToken, EnrollmentRequest, EnrollmentResponse, EnrollmentStatus,
    EnrollmentStatusRequest, EnrollmentStatusResponse,
};

use crate::identity::NodeIdentity;

pub use bundle::{fingerprint_pinning_client_config, BootstrapBundle, FingerprintPinningVerifier};

// ── RPC abstraction (mockable) ────────────────────────────────────────────────

/// Async RPC interface for the enrollment service.
///
/// Abstracting over tonic allows unit tests to inject mock implementations
/// without running a real gRPC server.
#[async_trait]
pub trait EnrollmentRpc: Send + Sync {
    async fn request_enrollment(&self, req: EnrollmentRequest) -> Result<EnrollmentResponse>;
    async fn check_status(&self, req: EnrollmentStatusRequest) -> Result<EnrollmentStatusResponse>;
}

// ── Real tonic implementation ────────────────────────────────────────────────

/// Connects to the controller enrollment gRPC endpoint using TLS (no client cert).
///
/// Used for post-enrollment re-connects (rare; agents normally connect to
/// the management endpoint, not enrollment). The CA cert was persisted from
/// the initial ZTP response.
pub struct TonicEnrollmentRpc {
    client: tokio::sync::Mutex<
        policy_controller_proto::controller::enrollment_service_client::EnrollmentServiceClient<
            tonic::transport::Channel,
        >,
    >,
}

impl TonicEnrollmentRpc {
    /// Connect to the enrollment endpoint at `url`.
    /// `ca_cert_pem` is the PEM of the controller's CA used to verify the server cert.
    pub async fn connect(url: String, ca_cert_pem: &str) -> Result<Self> {
        let ca = tonic::transport::Certificate::from_pem(ca_cert_pem);
        let tls = tonic::transport::ClientTlsConfig::new().ca_certificate(ca);

        let channel = tonic::transport::Channel::from_shared(url)
            .context("Invalid enrollment URL")?
            .tls_config(tls)
            .context("TLS configuration error")?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .connect()
            .await
            .context("Failed to connect to enrollment service")?;

        Ok(Self {
            client: tokio::sync::Mutex::new(
                policy_controller_proto::controller::enrollment_service_client::EnrollmentServiceClient::new(channel),
            ),
        })
    }

    /// Connect to the enrollment endpoint using fingerprint pinning. This is
    /// the only enrollment-time path; after enrollment the agent has the real
    /// CA cert and uses [`connect`] for any further enrollment-service calls.
    ///
    /// `url` is the operator-supplied https://host:port URL. Our connector
    /// drives TLS itself (with the fingerprint-pin verifier), so we hand
    /// tonic an `http://` Endpoint to suppress its built-in TLS path — the
    /// scheme only affects tonic's bookkeeping; the real TCP+TLS dial uses
    /// the host/port parsed from the original `url`.
    pub async fn connect_pinned(url: String, expected_sha256: [u8; 32]) -> Result<Self> {
        let connector = PinnedTlsConnector::new(&url, expected_sha256)?;
        // Replace the https:// scheme with http:// so tonic does not try to
        // initialise its own TLS layer on top of our already-TLS-wrapped stream.
        let tonic_url = url.replacen("https://", "http://", 1);
        let endpoint = tonic::transport::Endpoint::from_shared(tonic_url)
            .context("Invalid enrollment URL")?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));

        let channel = endpoint
            .connect_with_connector(connector)
            .await
            .context("Failed to connect to enrollment service (pinned)")?;

        Ok(Self {
            client: tokio::sync::Mutex::new(
                policy_controller_proto::controller::enrollment_service_client::EnrollmentServiceClient::new(channel),
            ),
        })
    }
}

/// tower::Service<Uri> that opens TCP + TLS using fingerprint pinning.
/// Returned future yields a hyper-1-compatible IO type via `hyper_util::rt::TokioIo`.
#[derive(Clone)]
struct PinnedTlsConnector {
    server_name: rustls::pki_types::ServerName<'static>,
    addr: String, // host:port for TCP connect
    config: Arc<rustls::ClientConfig>,
}

impl PinnedTlsConnector {
    fn new(url: &str, expected_sha256: [u8; 32]) -> Result<Self> {
        let uri: http::Uri = url.parse().context("Invalid enrollment URL")?;
        let host = uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("Enrollment URL missing host"))?;
        let port = uri.port_u16().unwrap_or(443);
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .context("Enrollment URL host is not a valid TLS server name")?;
        Ok(Self {
            server_name,
            addr: format!("{}:{}", host, port),
            config: Arc::new(fingerprint_pinning_client_config(expected_sha256)),
        })
    }
}

impl tower_service::Service<http::Uri> for PinnedTlsConnector {
    type Response = hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Self::Response>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: http::Uri) -> Self::Future {
        let addr = self.addr.clone();
        let server_name = self.server_name.clone();
        let config = self.config.clone();
        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect(&addr).await?;
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(server_name, tcp)
                .await?;
            Ok(hyper_util::rt::TokioIo::new(tls))
        })
    }
}

#[async_trait]
impl EnrollmentRpc for TonicEnrollmentRpc {
    async fn request_enrollment(&self, req: EnrollmentRequest) -> Result<EnrollmentResponse> {
        let resp = self
            .client
            .lock()
            .await
            .request_enrollment(tonic::Request::new(req))
            .await
            .context("request_enrollment RPC failed")?;
        Ok(resp.into_inner())
    }

    async fn check_status(&self, req: EnrollmentStatusRequest) -> Result<EnrollmentStatusResponse> {
        let resp = self
            .client
            .lock()
            .await
            .check_enrollment_status(tonic::Request::new(req))
            .await
            .context("check_enrollment_status RPC failed")?;
        Ok(resp.into_inner())
    }
}

/// Internal result of `submit()`.
struct SubmitOutcome {
    enrollment_id: String,
    ca_cert_pem: String,
    /// `Some` when the controller auto-approved via a bootstrap token.
    auto_approved: Option<EnrolledCredentials>,
}

// ── Enrollment outcome ────────────────────────────────────────────────────────

/// Credentials returned after successful enrollment.
#[derive(Debug, Clone)]
pub struct EnrolledCredentials {
    /// PEM-encoded mTLS client private key (controller-generated).
    pub key_pem: String,
    /// PEM-encoded mTLS client certificate (controller-issued).
    pub cert_pem: String,
    /// PEM-encoded controller CA certificate.
    pub ca_cert_pem: String,
}

impl EnrolledCredentials {
    /// Persist credentials to disk.
    ///
    /// - `key_path`: written with mode 0600
    /// - `cert_path`: written normally
    /// - `ca_cert_path`: written normally; lives under StateDirectory
    ///
    /// Parent directories are created if missing — credentials must land
    /// atomically as a triple, and a missing CA cert later puts the agent
    /// into an unrecoverable state.
    pub fn save(&self, key_path: &Path, cert_path: &Path, ca_cert_path: &Path) -> Result<()> {
        for p in [key_path, cert_path, ca_cert_path] {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "Failed to create credential directory: {}",
                        parent.display()
                    )
                })?;
            }
        }
        write_pem_file(key_path, &self.key_pem, 0o600).context("Failed to write client key")?;
        std::fs::write(cert_path, &self.cert_pem).context("Failed to write client cert")?;
        std::fs::write(ca_cert_path, &self.ca_cert_pem).context("Failed to write CA cert")?;
        Ok(())
    }

    /// Load previously-saved credentials from disk.
    pub fn load(key_path: &Path, cert_path: &Path, ca_cert_path: &Path) -> Result<Self> {
        let key_pem = std::fs::read_to_string(key_path).context("Failed to read client key")?;
        let cert_pem = std::fs::read_to_string(cert_path).context("Failed to read client cert")?;
        let ca_cert_pem =
            std::fs::read_to_string(ca_cert_path).context("Failed to read CA cert")?;
        Ok(Self {
            key_pem,
            cert_pem,
            ca_cert_pem,
        })
    }

    /// Return `true` if credentials appear to be present on disk.
    pub fn exists(key_path: &Path, cert_path: &Path) -> bool {
        key_path.exists() && cert_path.exists()
    }
}

/// Controller endpoint URLs learned during ZTP enrollment.
///
/// Persisted alongside the mTLS credentials so that subsequent agent restarts
/// can recover them after the single-use bootstrap bundle has been consumed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledEndpoints {
    pub controller_url: String,
    pub enrollment_url: String,
}

impl EnrolledEndpoints {
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create endpoints directory: {}", parent.display())
            })?;
        }
        let body = serde_json::to_vec_pretty(self).context("Failed to serialise endpoints")?;
        std::fs::write(path, body)
            .with_context(|| format!("Failed to write endpoints file: {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let body = std::fs::read(path)
            .with_context(|| format!("Failed to read endpoints file: {}", path.display()))?;
        serde_json::from_slice(&body)
            .with_context(|| format!("Failed to parse endpoints file: {}", path.display()))
    }
}

/// Split a combined key+cert PEM blob (as returned by the controller) into
/// separate key and cert PEM strings.
pub fn split_key_cert(combined: &str) -> Result<(String, String)> {
    // The controller stores "key_pem + cert_pem" concatenated.
    // Key PEM ends with "-----END PRIVATE KEY-----\n",
    // cert starts with "-----BEGIN CERTIFICATE-----".
    const CERT_MARKER: &str = "-----BEGIN CERTIFICATE-----";
    match combined.find(CERT_MARKER) {
        Some(pos) => {
            let key_pem = combined[..pos].to_string();
            let cert_pem = combined[pos..].to_string();
            if key_pem.is_empty() {
                bail!("Key PEM is empty in combined credential blob");
            }
            Ok((key_pem, cert_pem))
        }
        None => bail!("No certificate marker found in combined credential blob"),
    }
}

// ── Enrollment manager ────────────────────────────────────────────────────────

/// Fast poll interval used for the first minute after submission, so the
/// agent discovers operator approval within a couple of seconds.
const FAST_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Slow poll interval used after the fast-poll window, to keep controller
/// RPC load low while a request sits pending for a long time.
const SLOW_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Number of fast-poll attempts before backing off to `SLOW_POLL_INTERVAL`.
/// 30 × 2s = 60s of rapid polling right after submission.
const FAST_POLL_ATTEMPTS: u32 = 30;

/// Orchestrates the enrollment lifecycle:
/// 1. Build a CSR + proof-of-possession signature using the node identity.
/// 2. Call `RequestEnrollment` and receive an `enrollment_id`.
/// 3. Poll `CheckEnrollmentStatus` until approved (or rejected).
/// 4. Split the combined key+cert blob into separate [`EnrolledCredentials`].
///
/// When a [`BootstrapBundle`] is supplied, the manager includes the bundle's
/// token in the request. A valid token causes the controller to auto-approve
/// and return the credentials in the same response, so the poll step is
/// skipped entirely.
pub struct EnrollmentManager {
    rpc: Arc<dyn EnrollmentRpc>,
    identity: Arc<dyn NodeIdentity>,
    agent_version: String,
    bootstrap: Option<BundleContext>,
}

struct BundleContext {
    token_id: String,
    token: Vec<u8>,
}

impl EnrollmentManager {
    pub fn new(
        rpc: Arc<dyn EnrollmentRpc>,
        identity: Arc<dyn NodeIdentity>,
        agent_version: &str,
    ) -> Self {
        Self {
            rpc,
            identity,
            agent_version: agent_version.to_string(),
            bootstrap: None,
        }
    }

    /// Construct an [`EnrollmentManager`] that presents a ZTP bootstrap token.
    pub fn with_bundle(
        rpc: Arc<dyn EnrollmentRpc>,
        identity: Arc<dyn NodeIdentity>,
        agent_version: &str,
        bundle: &BootstrapBundle,
    ) -> Result<Self> {
        let token = bundle.token_bytes()?;
        Ok(Self {
            rpc,
            identity,
            agent_version: agent_version.to_string(),
            bootstrap: Some(BundleContext {
                token_id: bundle.token_id.clone(),
                token,
            }),
        })
    }

    /// Run the full enrollment flow, blocking until approved or failed.
    pub async fn enroll(&self) -> Result<EnrolledCredentials> {
        let SubmitOutcome {
            enrollment_id,
            ca_cert_pem,
            auto_approved,
        } = self.submit().await?;
        if let Some(creds) = auto_approved {
            log::info!("Enrollment auto-approved via bootstrap token");
            return Ok(creds);
        }
        log::info!(
            "Enrollment submitted (enrollment_id={}), waiting for operator approval…",
            enrollment_id
        );
        self.poll_approval(&enrollment_id, &ca_cert_pem).await
    }

    /// Submit the enrollment request.
    async fn submit(&self) -> Result<SubmitOutcome> {
        let public_key_der = self.identity.public_key_der();
        let dmi_uuid = self.identity.dmi_uuid().unwrap_or_default();

        // Build a CSR using a fresh ephemeral key.
        // The controller currently generates its own key+cert (Phase 2), so
        // the CSR key is not used for issuance, but including a valid CSR
        // ensures the protocol is ready for Phase 3 CSR-based issuance.
        let csr_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("Failed to generate CSR key")?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, self.identity.node_id());
        let csr = params
            .serialize_request(&csr_key)
            .context("Failed to build CSR")?;
        let csr_pem = csr.pem().context("Failed to encode CSR as PEM")?;

        // Sign SHA-256(csr_pem) with the node identity key to prove possession.
        let csr_hash = Sha256::digest(csr_pem.as_bytes());
        let signature = self
            .identity
            .sign(&csr_hash)
            .context("Failed to sign enrollment CSR")?;

        let hostname = gethostname::gethostname().to_string_lossy().into_owned();

        let bootstrap_token = self.bootstrap.as_ref().map(|b| BootstrapToken {
            token_id: b.token_id.clone(),
            token: b.token.clone(),
        });

        let resp = self
            .rpc
            .request_enrollment(EnrollmentRequest {
                public_key_der,
                dmi_uuid,
                csr_pem: csr_pem.into_bytes(),
                signature,
                agent_version: self.agent_version.clone(),
                hostname,
                tpm_backed: self.identity.tpm_available(),
                bootstrap_token,
            })
            .await
            .context("Enrollment request failed")?;

        let ca_cert_pem =
            String::from_utf8(resp.ca_cert_pem).context("CA cert PEM is not valid UTF-8")?;

        // If the controller auto-approved (token-bearing flow), credentials
        // ride back in the same response — no poll needed.
        let auto_approved = if resp.status == EnrollmentStatus::Approved as i32
            && !resp.client_cert_pem.is_empty()
        {
            let combined = String::from_utf8(resp.client_cert_pem)
                .context("Auto-approve credential blob is not valid UTF-8")?;
            let (key_pem, cert_pem) =
                split_key_cert(&combined).context("Failed to parse auto-approve credentials")?;
            Some(EnrolledCredentials {
                key_pem,
                cert_pem,
                ca_cert_pem: ca_cert_pem.clone(),
            })
        } else {
            None
        };

        Ok(SubmitOutcome {
            enrollment_id: resp.enrollment_id,
            ca_cert_pem,
            auto_approved,
        })
    }

    /// Poll for approval, returning credentials once the request is approved.
    async fn poll_approval(
        &self,
        enrollment_id: &str,
        ca_cert_pem: &str,
    ) -> Result<EnrolledCredentials> {
        let node_id = self.identity.node_id();

        let mut attempt: u32 = 0;
        loop {
            if attempt > 0 {
                let interval = if attempt < FAST_POLL_ATTEMPTS {
                    FAST_POLL_INTERVAL
                } else {
                    SLOW_POLL_INTERVAL
                };
                sleep(interval).await;
            }
            attempt = attempt.saturating_add(1);

            let resp = self
                .rpc
                .check_status(EnrollmentStatusRequest {
                    enrollment_id: enrollment_id.to_string(),
                    node_id: node_id.clone(),
                })
                .await
                .context("Status poll failed")?;

            let status = EnrollmentStatus::try_from(resp.status).unwrap_or_else(|_| {
                log::warn!(
                    "Unrecognised enrollment status value {} from controller, treating as Pending",
                    resp.status
                );
                EnrollmentStatus::Unspecified
            });

            match status {
                EnrollmentStatus::Approved => {
                    log::info!("Enrollment approved");
                    let combined = String::from_utf8(resp.client_cert_pem)
                        .context("Credential blob is not valid UTF-8")?;
                    let (key_pem, cert_pem) =
                        split_key_cert(&combined).context("Failed to parse credentials")?;
                    return Ok(EnrolledCredentials {
                        key_pem,
                        cert_pem,
                        ca_cert_pem: ca_cert_pem.to_string(),
                    });
                }
                EnrollmentStatus::Rejected => {
                    let reason = if resp.reject_reason.is_empty() {
                        "no reason given".to_string()
                    } else {
                        resp.reject_reason
                    };
                    bail!("Enrollment rejected by controller: {}", reason);
                }
                EnrollmentStatus::Pending | EnrollmentStatus::Unspecified => {
                    log::info!(
                        "Enrollment still pending, waiting for operator approval (attempt {})",
                        attempt
                    );
                }
            }
        }
    }
}

// ── File helpers ──────────────────────────────────────────────────────────────

#[cfg(unix)]
fn write_pem_file(path: &Path, content: &str, mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("Failed to open {}", path.display()))?;
    f.write_all(content.as_bytes())
        .context("Failed to write PEM file")
}

#[cfg(not(unix))]
fn write_pem_file(path: &Path, content: &str, _mode: u32) -> Result<()> {
    std::fs::write(path, content).context("Failed to write PEM file")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MockNodeIdentity;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use rand_core::OsRng;

    // Helper: build a mock identity backed by a real P-256 key so signing works.
    fn real_identity() -> (Arc<MockNodeIdentity>, SigningKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let pub_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();
        let node_id = crate::identity::derive_node_id(&pub_der);

        let mut mock = MockNodeIdentity::new();
        let pub_der2 = pub_der.clone();
        mock.expect_public_key_der()
            .returning(move || pub_der2.clone());
        let nid = node_id.clone();
        mock.expect_node_id().returning(move || nid.clone());
        mock.expect_dmi_uuid().returning(|| None);
        mock.expect_tpm_available().returning(|| false);
        let sk = signing_key.clone();
        mock.expect_sign().returning(move |data| {
            let sig: p256::ecdsa::Signature = sk.sign(data);
            Ok(sig.to_bytes().to_vec())
        });

        (Arc::new(mock), signing_key)
    }

    // Mock RPC that immediately approves.
    struct MockApproveRpc {
        ca_pem: String,
    }

    #[async_trait]
    impl EnrollmentRpc for MockApproveRpc {
        async fn request_enrollment(&self, _req: EnrollmentRequest) -> Result<EnrollmentResponse> {
            Ok(EnrollmentResponse {
                enrollment_id: "test-enroll-id".to_string(),
                status: EnrollmentStatus::Pending as i32,
                ca_cert_pem: self.ca_pem.as_bytes().to_vec(),
                client_cert_pem: vec![],
            })
        }

        async fn check_status(
            &self,
            _req: EnrollmentStatusRequest,
        ) -> Result<EnrollmentStatusResponse> {
            // Return combined key+cert PEM
            let combined = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n\
                            -----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";
            Ok(EnrollmentStatusResponse {
                status: EnrollmentStatus::Approved as i32,
                client_cert_pem: combined.as_bytes().to_vec(),
                reject_reason: String::new(),
            })
        }
    }

    // Mock RPC that rejects.
    struct MockRejectRpc;

    #[async_trait]
    impl EnrollmentRpc for MockRejectRpc {
        async fn request_enrollment(&self, _req: EnrollmentRequest) -> Result<EnrollmentResponse> {
            Ok(EnrollmentResponse {
                enrollment_id: "rej-id".to_string(),
                status: EnrollmentStatus::Pending as i32,
                ca_cert_pem: b"CA".to_vec(),
                client_cert_pem: vec![],
            })
        }

        async fn check_status(
            &self,
            _req: EnrollmentStatusRequest,
        ) -> Result<EnrollmentStatusResponse> {
            Ok(EnrollmentStatusResponse {
                status: EnrollmentStatus::Rejected as i32,
                client_cert_pem: vec![],
                reject_reason: "test rejection".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn test_enrollment_happy_path() {
        let (identity, _) = real_identity();
        let rpc = Arc::new(MockApproveRpc {
            ca_pem: "CA-CERT-PEM".to_string(),
        });
        let manager = EnrollmentManager::new(rpc, identity, "0.1.0");
        let creds = manager.enroll().await.unwrap();

        assert!(creds.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(creds.cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(creds.ca_cert_pem, "CA-CERT-PEM");
    }

    /// Mock RPC that auto-approves and returns creds in the same response.
    struct MockAutoApproveRpc;

    #[async_trait]
    impl EnrollmentRpc for MockAutoApproveRpc {
        async fn request_enrollment(&self, req: EnrollmentRequest) -> Result<EnrollmentResponse> {
            // The fixture below assumes the agent sent the token.
            assert!(req.bootstrap_token.is_some(), "Agent must include token");
            let combined = "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n\
                            -----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n";
            Ok(EnrollmentResponse {
                enrollment_id: "auto-id".to_string(),
                status: EnrollmentStatus::Approved as i32,
                ca_cert_pem: b"CA-PEM".to_vec(),
                client_cert_pem: combined.as_bytes().to_vec(),
            })
        }

        async fn check_status(
            &self,
            _req: EnrollmentStatusRequest,
        ) -> Result<EnrollmentStatusResponse> {
            panic!("check_status must not be called when auto-approved");
        }
    }

    #[tokio::test]
    async fn test_enrollment_auto_approve_with_bundle() {
        use base64::Engine as _;
        let (identity, _) = real_identity();
        // Build a minimal bundle (only the token bytes matter to the manager).
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let json = serde_json::json!({
            "v": 1,
            "enrollment_url": "https://x:1",
            "controller_url": "https://x:2",
            "ca_fp_sha256": "00".repeat(32),
            "token_id": "tok-1",
            "token_b64": b64.encode([9u8; 32]),
            "expires_at": 0i64,
        });
        let encoded = b64.encode(serde_json::to_vec(&json).unwrap());
        let bundle = bundle::BootstrapBundle::decode(&encoded).unwrap();

        let manager = EnrollmentManager::with_bundle(
            Arc::new(MockAutoApproveRpc),
            identity,
            "0.1.0",
            &bundle,
        )
        .unwrap();
        let creds = manager.enroll().await.unwrap();
        assert!(creds.key_pem.contains("PRIVATE KEY"));
        assert!(creds.cert_pem.contains("CERTIFICATE"));
        assert_eq!(creds.ca_cert_pem, "CA-PEM");
    }

    #[tokio::test]
    async fn test_enrollment_rejection_returns_error() {
        let (identity, _) = real_identity();
        let rpc = Arc::new(MockRejectRpc);
        let manager = EnrollmentManager::new(rpc, identity, "0.1.0");
        let result = manager.enroll().await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("test rejection"),
            "Error should include rejection reason"
        );
    }

    #[test]
    fn test_split_key_cert_valid() {
        let combined = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n\
                        -----BEGIN CERTIFICATE-----\nDEF\n-----END CERTIFICATE-----\n";
        let (key, cert) = split_key_cert(combined).unwrap();
        assert!(key.contains("PRIVATE KEY"));
        assert!(cert.contains("CERTIFICATE"));
        assert!(!key.contains("CERTIFICATE"));
        assert!(!cert.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_split_key_cert_missing_cert_marker() {
        let result =
            split_key_cert("-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_credentials_save_and_load() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("client.key");
        let cert_path = dir.path().join("client.crt");
        let ca_path = dir.path().join("ca.crt");

        let creds = EnrolledCredentials {
            key_pem: "KEY".to_string(),
            cert_pem: "CERT".to_string(),
            ca_cert_pem: "CA".to_string(),
        };
        creds.save(&key_path, &cert_path, &ca_path).unwrap();

        let loaded = EnrolledCredentials::load(&key_path, &cert_path, &ca_path).unwrap();
        assert_eq!(loaded.key_pem, "KEY");
        assert_eq!(loaded.cert_pem, "CERT");
        assert_eq!(loaded.ca_cert_pem, "CA");
    }

    #[test]
    fn test_credentials_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("client.key");
        let cert_path = dir.path().join("client.crt");

        assert!(!EnrolledCredentials::exists(&key_path, &cert_path));

        std::fs::write(&key_path, "KEY").unwrap();
        std::fs::write(&cert_path, "CERT").unwrap();

        assert!(EnrolledCredentials::exists(&key_path, &cert_path));
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("client.key");
        let creds = EnrolledCredentials {
            key_pem: "KEY".to_string(),
            cert_pem: "CERT".to_string(),
            ca_cert_pem: "CA".to_string(),
        };
        creds
            .save(
                &key_path,
                &dir.path().join("c.crt"),
                &dir.path().join("ca.crt"),
            )
            .unwrap();
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Client key must have mode 0600, got {:o}",
            mode
        );
    }
}
