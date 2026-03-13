use crate::handlers::AppState;
use crate::services::seal::{InitResponse, UnsealResponse};
use crate::{ApiResponse, ApiResult};
use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/init", post(initialize))
        .route("/unseal", post(unseal))
        .route("/seal-status", get(get_seal_status))
        .route("/seal", post(seal))
        .route("/health", get(health_check))
}

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub shares: u8,
    pub threshold: u8,
    pub root_username: Option<String>,
    // root_password removed as root has no password login
}

#[derive(Debug, Deserialize)]
pub struct UnsealRequest {
    pub key: String,
}

/// Initialize the vault
async fn initialize(
    State(state): State<AppState>,
    Json(payload): Json<InitRequest>,
) -> ApiResult<Json<ApiResponse<InitResponse>>> {
    let root_username = payload.root_username.as_deref().unwrap_or("root");

    let result = state
        .seal
        .init(
            payload.shares,
            payload.threshold,
            root_username,
            &state.auth,
            &state.mfa,
        )
        .await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(result)))
}

/// Unseal the vault
async fn unseal(
    State(state): State<AppState>,
    Json(payload): Json<UnsealRequest>,
) -> ApiResult<Json<ApiResponse<UnsealResponse>>> {
    let result = state
        .seal
        .unseal(&payload.key)
        .await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(result)))
}

/// Get seal status
async fn get_seal_status(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<UnsealResponse>>> {
    let result = state
        .seal
        .get_status()
        .await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(result)))
}

/// Seal the vault
async fn seal(State(state): State<AppState>) -> ApiResult<StatusCode> {
    state.seal.seal().await;
    Ok(StatusCode::NO_CONTENT)
}

/// System health check (that works even when sealed)
async fn health_check(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    let sealed = state.seal.is_sealed().await;
    let initialized = state.seal.is_initialized().await;

    let status = if !initialized {
        "uninitialized"
    } else if sealed {
        "sealed"
    } else {
        "active"
    };

    let data = serde_json::json!({
        "status": status,
        "initialized": initialized,
        "sealed": sealed,
        "server_time_utc": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION"),
    });

    Ok(Json(ApiResponse::success(data)))
}
