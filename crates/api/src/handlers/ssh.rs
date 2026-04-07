//! SSH Secret Engine Handlers

use axum::{
    Router,
    extract::{Json, State},
    response::Json as AxumJson,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::extractors::AuthenticatedUser;
use crate::handlers::AppState;
use crate::services::ssh::SshServiceError;
use crate::{ApiResponse, ApiResult};

/// Map a [`SshServiceError`] to the appropriate [`crate::ApiError`] variant
fn map_ssh_err(err: SshServiceError) -> crate::ApiError {
    match err {
        SshServiceError::NotFound(msg) => crate::ApiError::NotFound(msg),
        SshServiceError::Conflict(msg) => {
            crate::ApiError(secreton_errors::SecretonError::Conflict { message: msg })
        }
        SshServiceError::BadRequest(msg) => crate::ApiError::BadRequest(msg),
        SshServiceError::Internal(msg) => crate::ApiError::Internal(msg),
    }
}

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/config/ca", get(get_ca_public_key).post(generate_ca))
        .route("/sign", post(sign_key))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaResponse {
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignKeyRequest {
    pub public_key: String,
    pub valid_principals: Option<Vec<String>>,
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedKeyResponse {
    pub signed_key: String,
}

async fn get_ca_public_key(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> ApiResult<AxumJson<ApiResponse<CaResponse>>> {
    let pub_key = state.ssh.get_ca_public_key().await
        .map_err(map_ssh_err)?;

    match pub_key {
        Some(pk) => Ok(AxumJson(ApiResponse::success(CaResponse { public_key: pk }))),
        None => Err(crate::ApiError::NotFound("SSH CA not configured".to_string())),
    }
}

async fn generate_ca(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<AxumJson<ApiResponse<CaResponse>>> {
    // Only admin/root users may generate a CA
    if !user.is_admin() {
        return Err(crate::ApiError::Authorization(
            "Admin privileges required to generate SSH CA".to_string(),
        ));
    }

    let pub_key = state.ssh.generate_ca().await
        .map_err(map_ssh_err)?;

    Ok(AxumJson(ApiResponse::success(CaResponse { public_key: pub_key })))
}

async fn sign_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(payload): Json<SignKeyRequest>,
) -> ApiResult<AxumJson<ApiResponse<SignedKeyResponse>>> {
    // Enforce the max lease TTL (30 days) to prevent arbitrarily long-lived
    // certificates and potential u64 overflow in the engine's timestamp math.
    let min_ttl: u64 = 1; // Prevent immediately-expired certificates
    let max_ttl: u64 = 86400 * 30; // 30 days — must match SshConfig::max_lease_ttl
    let ttl = payload.ttl.unwrap_or(3600).clamp(min_ttl, max_ttl);

    // Security: Only allow users to sign for their own username by default.
    // If specific principals are requested, verify they are allowed.
    // For now, we enforce that users can ONLY sign for their own username
    // unless they have administrative privileges.
    let principals = match payload.valid_principals {
        Some(p) if !p.is_empty() => {
            if !user.is_admin() {
                // Non-admin users can only request their own username
                if p.len() != 1 || p[0] != user.username {
                    return Err(crate::ApiError::Authorization(
                        "Non-admin users can only sign keys for their own username".to_string(),
                    ));
                }
            }
            p
        }
        _ => vec![user.username.clone()],
    };

    let signed_key = state
        .ssh
        .sign_key(&payload.public_key, principals, ttl)
        .await
        .map_err(map_ssh_err)?;

    Ok(AxumJson(ApiResponse::success(SignedKeyResponse {
        signed_key,
    })))
}
