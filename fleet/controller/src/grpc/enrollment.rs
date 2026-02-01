// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

use std::sync::Arc;
use tonic::{Request, Response, Status};

use policy_controller_proto::controller::{
    enrollment_service_server::EnrollmentService, EnrollmentRequest, EnrollmentResponse,
    EnrollmentStatus, EnrollmentStatusRequest, EnrollmentStatusResponse,
};

use crate::node_registry::NodeRegistry;

pub struct EnrollmentServiceImpl {
    registry: Arc<NodeRegistry>,
}

impl EnrollmentServiceImpl {
    pub fn new(registry: Arc<NodeRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl EnrollmentService for EnrollmentServiceImpl {
    async fn request_enrollment(
        &self,
        request: Request<EnrollmentRequest>,
    ) -> Result<Response<EnrollmentResponse>, Status> {
        let req = request.into_inner();

        let tpm_backed = req.tpm_backed;
        let bootstrap_token = req.bootstrap_token.map(|t| (t.token_id, t.token));

        match self
            .registry
            .submit_enrollment_with_token(
                req.public_key_der,
                if req.dmi_uuid.is_empty() {
                    None
                } else {
                    Some(req.dmi_uuid)
                },
                req.csr_pem,
                req.signature,
                if req.agent_version.is_empty() {
                    None
                } else {
                    Some(req.agent_version)
                },
                tpm_backed,
                if req.hostname.is_empty() {
                    None
                } else {
                    Some(req.hostname)
                },
                bootstrap_token,
            )
            .await
        {
            Ok((enrollment_id, auto_approved_cert)) => {
                let ca_cert = self.registry.ca_cert_pem().await.into_bytes();
                let (status, client_cert_pem) = match auto_approved_cert {
                    Some(blob) => (EnrollmentStatus::Approved as i32, blob.into_bytes()),
                    None => (EnrollmentStatus::Pending as i32, vec![]),
                };
                Ok(Response::new(EnrollmentResponse {
                    enrollment_id,
                    status,
                    ca_cert_pem: ca_cert,
                    client_cert_pem,
                }))
            }
            Err(e) => {
                log::warn!("Enrollment request rejected: {:#}", e);
                Err(Status::invalid_argument(format!("{:#}", e)))
            }
        }
    }

    async fn check_enrollment_status(
        &self,
        request: Request<EnrollmentStatusRequest>,
    ) -> Result<Response<EnrollmentStatusResponse>, Status> {
        let req = request.into_inner();

        match self
            .registry
            .check_enrollment_status(&req.enrollment_id)
            .await
        {
            Ok((status_str, cert_pem)) => {
                let status = match status_str.as_str() {
                    "pending" => EnrollmentStatus::Pending,
                    "active" => EnrollmentStatus::Approved,
                    "decommissioned" => EnrollmentStatus::Rejected,
                    _ => EnrollmentStatus::Unspecified,
                };
                Ok(Response::new(EnrollmentStatusResponse {
                    status: status as i32,
                    client_cert_pem: cert_pem.map(|s| s.into_bytes()).unwrap_or_default(),
                    reject_reason: String::new(),
                }))
            }
            Err(e) => Err(Status::not_found(format!("{:#}", e))),
        }
    }
}
