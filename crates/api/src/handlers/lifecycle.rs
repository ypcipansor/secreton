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

// SECURITY: All handlers below intentionally reject every request with
// Unauthorized until per-request authentication and per-secret authorization
// checks are added (see CONTRIBUTING.md "Secure Coding Checklist").  This
// prevents the routes from becoming an unauthenticated attack surface if
// `create_routes` is mounted before the auth wiring is finished.

/// Get system-wide lifecycle statistics
async fn get_lifecycle_stats(
    State(_state): State<AppState>,
) -> ApiResult<Json<ApiResponse<LifecycleStatistics>>> {
    Err(ApiError::Unauthorized(
        "Lifecycle endpoints require authentication wiring before use".to_string(),
    ))
}

/// Get lifecycle status for a specific secret
async fn get_secret_lifecycle_status(
    State(_state): State<AppState>,
    Path(_path): Path<String>,
) -> ApiResult<Json<ApiResponse<SecretLifecycle>>> {
    Err(ApiError::Unauthorized(
        "Lifecycle endpoints require authentication wiring before use".to_string(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ExtendTtlRequest {
    pub additional_days: u32,
}

/// Extend the TTL of a secret
///
/// NOTE: Once authentication is wired, this handler MUST also persist the
/// new expiration on the storage-level `SecretEntry.expires_at` (matching
/// what `put_secret` does), not just the in-memory lifecycle manager.
/// Otherwise the lifecycle sweep and `get_secret` responses will continue
/// to use the original `expires_at`.
async fn extend_secret_ttl(
    State(_state): State<AppState>,
    Path(_path): Path<String>,
    Json(_payload): Json<ExtendTtlRequest>,
) -> ApiResult<Json<ApiResponse<SecretLifecycle>>> {
    Err(ApiError::Unauthorized(
        "Lifecycle endpoints require authentication wiring before use".to_string(),
    ))
}
