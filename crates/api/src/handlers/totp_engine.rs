//! TOTP Secret Engine Handlers

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::Value;

use crate::handlers::AppState;
use crate::{ApiResponse, ApiResult};

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
) -> ApiResult<Json<ApiResponse<Value>>> {
    // Use a nil user_id for now; in production this should come from auth context
    let keys = state.totp_engine.list_keys("00000000-0000-0000-0000-000000000000").await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "keys": keys
    }))))
}

async fn create_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let user_id = "00000000-0000-0000-0000-000000000000";
    state.totp_engine.create_key(
        user_id,
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
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let user_id = "00000000-0000-0000-0000-000000000000";
    let code = state.totp_engine.generate_code(user_id, &name).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "code": code
    }))))
}

async fn delete_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<Value>>> {
    let user_id = "00000000-0000-0000-0000-000000000000";
    state.totp_engine.delete_key(user_id, &name).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": format!("Key '{}' deleted", name)
    }))))
}
