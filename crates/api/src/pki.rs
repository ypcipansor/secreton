//! PKI Secrets Engine API endpoints

use axum::{
    Router,
    extract::{Extension},
    http::StatusCode,
    response::Json,
    routing::{post, get},
};
use secreton_secrets_pki::CertificateRequest;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, error};

use crate::ApiResponse;
use crate::services::pki::PkiPersistentService;

/// API state for PKI engine
#[derive(Clone)]
pub struct PkiApiState {
    pub service: Option<Arc<PkiPersistentService>>,
}

impl Default for PkiApiState {
    fn default() -> Self {
        Self {
            service: None,
        }
    }
}

/// Request to generate a certificate
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateCertRequest {
    pub common_name: String,
    pub ttl: Option<u64>,
    pub key_type: Option<String>,
    pub key_bits: Option<u64>,
    pub organization: Option<String>,
}

/// Request to generate Root CA
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateRootCaRequest {
    pub common_name: String,
    pub organization: String,
}

/// Response for certificate generation
#[derive(Debug, Serialize, Deserialize)]
pub struct CertResponse {
    pub certificate: String,
    pub private_key: String,
    pub serial_number: String,
    pub expiration: i64,
}

/// Create the PKI router with all endpoints
pub fn create_pki_router() -> Router<()> {
    Router::new()
        .route("/issue", post(issue_certificate))
        .route("/root/generate", post(generate_root_ca))
        .route("/ca/pem", get(get_ca_pem))
}

/// Generate a certificate
#[axum::debug_handler]
pub async fn issue_certificate(
    Extension(state): Extension<crate::ApiState>,
    Extension(user): Extension<secreton_auth::User>,
    Json(request): Json<GenerateCertRequest>,
) -> Result<Json<ApiResponse<CertResponse>>, StatusCode> {
    // Authorization check: Only admin/root should be able to issue certificates
    let is_authorized = user.roles.iter().any(|r| r == "admin" || r == "root") || user.is_superuser;

    if !is_authorized {
        error!("Unauthorized attempt to issue certificate by user: {}", user.username);
        return Err(StatusCode::FORBIDDEN);
    }

    let service = state.pki.service.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    // Map request
    let cert_req = CertificateRequest {
        common_name: request.common_name,
        alt_names: vec![],
        ip_addresses: vec![],
        email_addresses: vec![],
        organization: request.organization,
        organizational_unit: None,
        country: None,
        state: None,
        locality: None,
        key_usages: vec![],
        extended_key_usages: vec![],
        ttl: request.ttl.map(|t| t as i64),
    };

    match service.issue_certificate(cert_req).await {
        Ok(res) => {
            info!("Certificate issued: {}", res.serial_number);
            Ok(Json(ApiResponse::success(CertResponse {
                certificate: res.certificate,
                private_key: res.private_key,
                serial_number: res.serial_number,
                expiration: res.expiration.timestamp(),
            })))
        }
        Err(e) => {
            error!("Failed to issue certificate: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Generate Root CA
#[axum::debug_handler]
pub async fn generate_root_ca(
    Extension(state): Extension<crate::ApiState>,
    Extension(user): Extension<secreton_auth::User>,
    Json(request): Json<GenerateRootCaRequest>,
) -> Result<Json<ApiResponse<CertResponse>>, StatusCode> {
    // Authorization check: Only admin/root should be able to generate Root CA
    let is_authorized = user.roles.iter().any(|r| r == "admin" || r == "root") || user.is_superuser;

    if !is_authorized {
        error!("Unauthorized attempt to generate Root CA by user: {}", user.username);
        return Err(StatusCode::FORBIDDEN);
    }

    let service = state.pki.service.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    match service.generate_root_ca(&request.common_name, &request.organization).await {
        Ok((cert, _key)) => {
            Ok(Json(ApiResponse::success(CertResponse {
                certificate: cert,
                private_key: String::new(), // Do not return private key in API response for security
                serial_number: "ROOT".to_string(),
                expiration: Utc::now().timestamp() + (3650 * 86400),
            })))
        },
        Err(e) => {
            error!("Failed to generate Root CA: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get CA PEM
#[axum::debug_handler]
pub async fn get_ca_pem(
    Extension(state): Extension<crate::ApiState>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let service = state.pki.service.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    match service.get_ca_pem().await {
        Ok(Some(pem)) => Ok(Json(ApiResponse::success(pem))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get CA PEM: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
