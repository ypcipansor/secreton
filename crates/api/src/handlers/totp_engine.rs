//! TOTP Secret Engine Handlers

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;

use crate::extractors::AuthenticatedUser;
use crate::handlers::{AppState, validate_name};
use crate::services::totp_engine::TotpServiceError;
use crate::{ApiResponse, ApiResult};

/// Map a [`TotpServiceError`] to the appropriate [`crate::ApiError`] variant
/// so that the HTTP response carries the correct status code.
fn map_totp_err(err: TotpServiceError) -> crate::ApiError {
    match err {
        TotpServiceError::NotFound(msg) => crate::ApiError::NotFound(msg),
        TotpServiceError::BadRequest(msg) => crate::ApiError::BadRequest(msg),
        TotpServiceError::Internal(msg) => crate::ApiError::Internal(msg),
    }
}

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/keys", get(list_keys))
        .route("/keys/{name}", post(create_key).delete(delete_key))
        .route("/code/{name}", get(generate_code))
}

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub secret: String,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

// Manual Debug impl to prevent accidental logging of the TOTP secret.
impl std::fmt::Debug for CreateKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateKeyRequest")
            .field("secret", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .finish()
    }
}

async fn list_keys(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let keys = state.totp_engine.list_keys(&user.id).await
        .map_err(map_totp_err)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "keys": keys
    }))))
}

async fn create_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(payload): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    validate_name(&name)?;

    state.totp_engine.create_key(
        &user.id,
        &name,
        &payload.secret,
        payload.issuer,
        payload.account_name,
    ).await
        .map_err(map_totp_err)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": format!("Key '{}' created", name)
    }))))
}

async fn generate_code(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    validate_name(&name)?;

    let code = state.totp_engine.generate_code(&user.id, &name).await
        .map_err(map_totp_err)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "code": code
    }))))
}

async fn delete_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    validate_name(&name)?;

    state.totp_engine.delete_key(&user.id, &name).await
        .map_err(map_totp_err)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": format!("Key '{}' deleted", name)
    }))))
}
