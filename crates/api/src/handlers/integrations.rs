use crate::extractors::AuthenticatedUser;
use crate::handlers::AppState;
use crate::services::integrations::IntegrationConfig;
use crate::{ApiError, ApiResponse, ApiResult};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, get, post, put},
};
use secreton_integrations::integrations::aws_secrets_manager::SyncOperation;
use serde::Deserialize;

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_integrations).post(create_integration))
        .route(
            "/{id}",
            get(get_integration)
                .put(update_integration)
                .delete(delete_integration),
        )
        .route("/aws/sync-to/{config_id}/{*path}", post(sync_to_aws))
        .route("/aws/sync-from/{config_id}/{*path}", post(sync_from_aws))
}

async fn list_integrations(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Vec<IntegrationConfig>>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError::Authorization(
            "Only admins can access integrations".to_string(),
        ));
    }
    let configs = state
        .integrations
        .list_integrations()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(configs)))
}

async fn get_integration(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
) -> ApiResult<Json<ApiResponse<IntegrationConfig>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError::Authorization(
            "Only admins can access integrations".to_string(),
        ));
    }
    let config = state
        .integrations
        .get_integration(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("Integration {} not found", id)))?;
    Ok(Json(ApiResponse::success(config)))
}

async fn create_integration(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(config): Json<IntegrationConfig>,
) -> ApiResult<Json<ApiResponse<()>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError::Authorization(
            "Only admins can manage integrations".to_string(),
        ));
    }
    state
        .integrations
        .save_integration(config)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(())))
}

async fn update_integration(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
    Json(mut config): Json<IntegrationConfig>,
) -> ApiResult<Json<ApiResponse<()>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError::Authorization(
            "Only admins can manage integrations".to_string(),
        ));
    }
    config.id = id;
    state
        .integrations
        .save_integration(config)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(())))
}

async fn delete_integration(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(ApiError::Authorization(
            "Only admins can manage integrations".to_string(),
        ));
    }
    state
        .integrations
        .delete_integration(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(())))
}

#[derive(Debug, Deserialize)]
pub struct SyncToAwsRequest {
    pub aws_secret_name: String,
}

async fn sync_to_aws(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path((config_id, path)): Path<(String, String)>,
    Json(payload): Json<SyncToAwsRequest>,
) -> ApiResult<Json<ApiResponse<SyncOperation>>> {
    let secret = state.secreton.get_secret(&path, &user, None).await?;
    let manager = state
        .integrations
        .get_aws_manager(&config_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let data = serde_json::to_vec(&secret.data).map_err(|e| ApiError::Internal(e.to_string()))?;
    let op = manager
        .sync_to_aws(&path, &payload.aws_secret_name, &data)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(ApiResponse::success(op)))
}

async fn sync_from_aws(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path((config_id, path)): Path<(String, String)>,
) -> ApiResult<Json<ApiResponse<SyncOperation>>> {
    let manager = state
        .integrations
        .get_aws_manager(&config_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let aws_secret_name = path.split('/').last().unwrap_or(&path);
    let (data, op) = manager
        .sync_from_aws(aws_secret_name)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let secret_data: std::collections::HashMap<String, String> = serde_json::from_slice(&data)
        .map_err(|_| ApiError::BadRequest("AWS secret is not a valid JSON object".to_string()))?;
    state
        .secreton
        .put_secret(&path, secret_data, None, &user, None)
        .await?;
    Ok(Json(ApiResponse::success(op)))
}
