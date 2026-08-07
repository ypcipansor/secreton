use crate::error::ApiResult;
use crate::handlers::AppState;
use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
};
use secreton_domain::ApiResponse;
use secreton_domain::SecretonError;
use secreton_engines::Services;
use secreton_engines::services::seal::{InitResponse, UnsealResponse};
use serde::Deserialize;

/// Routes that must answer while the barrier is sealed.
///
/// Mounted outside the seal gate. Without this the unseal endpoint would be refused for
/// being sealed, which is unrecoverable without a restart.
pub fn unsealed_routes() -> Router<AppState> {
    Router::new()
        .route("/init", post(initialize))
        .route("/unseal", post(unseal))
        .route("/seal-status", get(get_seal_status))
        .route("/health", get(health_check))
}

/// Routes that need an unsealed, authenticated system.
pub fn routes() -> Router<AppState> {
    Router::new().route("/seal", post(seal))
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
    State(state): State<Services>,
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
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Internal {
                message: e.to_string(),
            })
        })?;
    Ok(Json(ApiResponse::success(result)))
}

/// Unseal the vault
async fn unseal(
    State(state): State<Services>,
    Json(payload): Json<UnsealRequest>,
) -> ApiResult<Json<ApiResponse<UnsealResponse>>> {
    let result = state.seal.unseal(&payload.key).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;
    Ok(Json(ApiResponse::success(result)))
}

/// Get seal status
async fn get_seal_status(
    State(state): State<Services>,
) -> ApiResult<Json<ApiResponse<UnsealResponse>>> {
    let result = state.seal.get_status().await.map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;
    Ok(Json(ApiResponse::success(result)))
}

/// Seal the vault
async fn seal(State(state): State<Services>) -> ApiResult<StatusCode> {
    state.seal.seal().await;
    Ok(StatusCode::NO_CONTENT)
}

/// System health check (that works even when sealed)
async fn health_check(
    State(state): State<Services>,
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
