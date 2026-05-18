//! PKI Secret Engine Handlers

use axum::{
    Router,
    extract::{Json, State},
    response::Json as AxumJson,
    routing::{get, post},
};
use serde::Deserialize;

use crate::extractors::AuthenticatedUser;
use crate::handlers::AppState;
use crate::services::pki::PkiServiceError;
use crate::{ApiResponse, ApiResult};
use secreton_secrets_pki::{CertificateRequest, CertificateResponse};
use zeroize::Zeroize;

/// Map a [`PkiServiceError`] to the appropriate [`crate::ApiError`] variant
/// so that the HTTP response carries the correct status code.
fn map_pki_err(err: PkiServiceError) -> crate::ApiError {
    match err {
        PkiServiceError::NotFound(msg) => crate::ApiError::NotFound(msg),
        PkiServiceError::Conflict(msg) => {
            // SecretonError::Conflict maps to 409 CONFLICT in IntoResponse
            crate::ApiError(secreton_errors::SecretonError::Conflict { message: msg })
        }
        PkiServiceError::BadRequest(msg) => crate::ApiError::BadRequest(msg),
        PkiServiceError::Internal(msg) => crate::ApiError::Internal(msg),
    }
}

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/ca/pem", get(get_ca_pem))
        .route("/root/generate", post(generate_root_ca))
        .route("/issue", post(issue_certificate))
}

#[derive(Debug, Deserialize)]
pub struct GenerateRootCaRequest {
    pub common_name: String,
    pub organization: String,
}

async fn get_ca_pem(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> ApiResult<AxumJson<ApiResponse<String>>> {
    let pem = state.pki.get_ca_pem().await.map_err(map_pki_err)?;

    match pem {
        Some(p) => Ok(AxumJson(ApiResponse::success(p))),
        None => Err(crate::ApiError::NotFound(
            "Root CA not configured".to_string(),
        )),
    }
}

async fn generate_root_ca(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(payload): Json<GenerateRootCaRequest>,
) -> ApiResult<AxumJson<ApiResponse<CertificateResponse>>> {
    // Only admin/root users may generate a Root CA
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to generate Root CA".to_string(),
        ));
    }

    let mut response = state
        .pki
        .generate_root_ca(&payload.common_name, &payload.organization)
        .await
        .map_err(map_pki_err)?;

    // Do not return private key in API response for security.
    // Zeroize the old value before replacing it so the CA key does not
    // linger in freed memory.
    response.private_key.zeroize();

    Ok(AxumJson(ApiResponse::success(response)))
}

async fn issue_certificate(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(payload): Json<CertificateRequest>,
) -> ApiResult<AxumJson<ApiResponse<CertificateResponse>>> {
    // Only admin/root users may issue certificates
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to issue certificates".to_string(),
        ));
    }

    let response = state
        .pki
        .issue_certificate(payload)
        .await
        .map_err(map_pki_err)?;

    Ok(AxumJson(ApiResponse::success(response)))
}
