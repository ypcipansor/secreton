use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use crate::handlers::AppState;
use crate::{ApiResponse, ApiResult, ApiError};
pub use secreton_common::dto::lifecycle::{SecretLifecycle, LifecycleStatistics};

// NOTE: These routes are not yet mounted in `handlers::mod::create_router`.
// Before wiring them up, each handler MUST gain a per-request authentication
// extractor (the global auth middleware covers transport-level auth, but
// `extend_secret_ttl` in particular requires verifying that the caller has
// write access to the target secret path).  See CONTRIBUTING.md "Secure
// Coding Checklist".

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/stats", get(get_lifecycle_stats))
        .route("/status/{*path}", get(get_secret_lifecycle_status))
        .route("/extend/{*path}", post(extend_secret_ttl))
}

/// Get system-wide lifecycle statistics
async fn get_lifecycle_stats(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<LifecycleStatistics>>> {
    let stats = state.lifecycle.get_statistics().await;
    Ok(Json(ApiResponse::success(stats)))
}

/// Get lifecycle status for a specific secret
async fn get_secret_lifecycle_status(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<SecretLifecycle>>> {
    let lifecycle = state.lifecycle.get_lifecycle(&path).await
        .ok_or_else(|| ApiError::NotFound(format!("Lifecycle for secret {}", path)))?;

    Ok(Json(ApiResponse::success(lifecycle)))
}

#[derive(Debug, Deserialize)]
pub struct ExtendTtlRequest {
    pub additional_days: u32,
}

/// Extend the TTL of a secret
async fn extend_secret_ttl(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Json(payload): Json<ExtendTtlRequest>,
) -> ApiResult<Json<ApiResponse<SecretLifecycle>>> {
    let lifecycle = state.lifecycle.extend_ttl(&path, payload.additional_days).await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(lifecycle)))
}
