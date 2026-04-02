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
use crate::handlers::AppState;
use crate::{ApiResponse, ApiResult};

/// Validate that a user-supplied name is safe for use in storage paths.
fn validate_name(name: &str) -> Result<(), crate::ApiError> {
    if name.is_empty() {
        return Err(crate::ApiError::BadRequest("Name must not be empty".to_string()));
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(crate::ApiError::BadRequest(
            "Name must not contain '/', '\\', or '..'".to_string(),
        ));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(crate::ApiError::BadRequest(
            "Name must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/keys", get(list_keys))
        .route("/keys/{name}", post(create_key).delete(delete_key))
        .route("/code/{name}", get(generate_code))
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub secret: String,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

async fn list_keys(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let keys = state.totp_engine.list_keys(&user.id).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

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
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

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
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

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
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": format!("Key '{}' deleted", name)
    }))))
}
