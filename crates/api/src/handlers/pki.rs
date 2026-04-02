//! PKI Secret Engine Handlers

use axum::{
    Router,
    extract::{Json, State},
    response::Json as AxumJson,
    routing::{get, post},
};
use serde::Deserialize;

use crate::handlers::AppState;
use crate::{ApiResponse, ApiResult};
use secreton_secrets_pki::{CertificateRequest, CertificateResponse};

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
) -> ApiResult<AxumJson<ApiResponse<String>>> {
    let pem = state.pki.get_ca_pem().await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    match pem {
        Some(p) => Ok(AxumJson(ApiResponse::success(p))),
        None => Err(crate::ApiError::NotFound("Root CA not configured".to_string())),
    }
}

async fn generate_root_ca(
    State(state): State<AppState>,
    Json(payload): Json<GenerateRootCaRequest>,
) -> ApiResult<AxumJson<ApiResponse<CertificateResponse>>> {
    let (cert, key) = state.pki.generate_root_ca(&payload.common_name, &payload.organization).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    let now = chrono::Utc::now();
    let expiration = now + chrono::Duration::days(3650);
    Ok(AxumJson(ApiResponse::success(CertificateResponse {
        certificate: cert.clone(),
        private_key: key,
        serial_number: "ROOT".to_string(),
        issuing_ca: cert,
        ca_chain: vec![],
        expiration,
        revocation_time: None,
    })))
}

async fn issue_certificate(
    State(state): State<AppState>,
    Json(payload): Json<CertificateRequest>,
) -> ApiResult<AxumJson<ApiResponse<CertificateResponse>>> {
    let response = state.pki.issue_certificate(payload).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(AxumJson(ApiResponse::success(response)))
}
