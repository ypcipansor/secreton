use axum::{
    extract::{Path, State},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use crate::handlers::AppState;
use crate::{ApiResponse, ApiResult, ApiError};
use secreton_integrations::integrations::aws_secrets_manager::SyncOperation;

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/aws/sync-to/{*path}", post(sync_to_aws))
        .route("/aws/sync-from/{*path}", post(sync_from_aws))
}

#[derive(Debug, Deserialize)]
pub struct SyncToAwsRequest {
    pub aws_secret_name: String,
}

/// Sync a secret from Secreton to AWS Secrets Manager
///
/// NOTE: This handler is not yet wired into the router. Before mounting it,
/// it MUST be updated to enforce authentication/authorization (the surrounding
/// router applies global auth middleware, but per-handler permission checks
/// against the target secret are still required).
async fn sync_to_aws(
    State(_state): State<AppState>,
    Path(path): Path<String>,
    Json(payload): Json<SyncToAwsRequest>,
) -> ApiResult<Json<ApiResponse<SyncOperation>>> {
    tracing::info!("Syncing secret {} to AWS as {}", path, payload.aws_secret_name);

    // TODO: verify the caller owns/has-write access to `path`, then fetch the
    // secret data and call into the AWS Secrets Manager integration.  The
    // previous gating used `config.auth.mfa.sms.is_none()` as a proxy for
    // "enterprise features enabled" which is semantically incorrect (MFA SMS
    // configuration is unrelated to AWS integration).  Until proper config
    // plumbing exists, this endpoint is unconditionally unimplemented.
    Err(ApiError::Internal(
        "AWS Secrets Manager integration is not yet implemented".to_string(),
    ))
}

/// Sync a secret from AWS Secrets Manager to Secreton
///
/// NOTE: Not yet wired into the router. See `sync_to_aws` for the
/// authentication/authorization requirements that must be added before
/// mounting these routes.
async fn sync_from_aws(
    State(_state): State<AppState>,
    Path(_path): Path<String>,
) -> ApiResult<Json<ApiResponse<SyncOperation>>> {
    Err(ApiError::Internal("Not implemented".to_string()))
}
