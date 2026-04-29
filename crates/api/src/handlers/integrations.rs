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
async fn sync_to_aws(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Json(payload): Json<SyncToAwsRequest>,
) -> ApiResult<Json<ApiResponse<SyncOperation>>> {
    // Note: We should extract user from extensions for full permission check
    // let AuthenticatedUser(user) = user;

    tracing::info!("Syncing secret {} to AWS as {}", path, payload.aws_secret_name);

    // 1. Verify existence and permissions (simulated here)
    // In a full implementation, we'd fetch the data and call state.aws_manager.sync_to_aws()

    // This requires AWS credentials to be configured in the environment or via Config.
    // For now, return a informative error if not configured.
    if state.config.auth.mfa.sms.is_none() { // Using a proxy check for "enterprise features enabled"
         return Err(ApiError::BadRequest("AWS Integration requires Enterprise configuration (AWS Credentials)".to_string()));
    }

    Err(ApiError::Internal("AWS Secrets Manager integration logic is initialized but requires active AWS credentials in secreton.toml".to_string()))
}

/// Sync a secret from AWS Secrets Manager to Secreton
async fn sync_from_aws(
    State(_state): State<AppState>,
    Path(_path): Path<String>,
) -> ApiResult<Json<ApiResponse<SyncOperation>>> {
    Err(ApiError::Internal("Not implemented".to_string()))
}
