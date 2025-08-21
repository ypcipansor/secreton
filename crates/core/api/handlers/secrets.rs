//! Secret management handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use crate::{
    api::{error::ApiError, AppState},
    auth::Claims,
    secrets::models::{Secret, SecretVersion},
};

/// Request to create or update a secret
#[derive(Debug, Deserialize, Validate)]
pub struct CreateOrUpdateSecretRequest {
    /// The secret value
    #[validate(required)]
    pub value: Option<serde_json::Value>,
    
    /// Optional description
    pub description: Option<String>,
    
    /// Optional metadata
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Request to list secrets
#[derive(Debug, Deserialize)]
pub struct ListSecretsQuery {
    /// Maximum number of results to return
    pub limit: Option<usize>,
    
    /// Pagination token
    pub next_token: Option<String>,
}

/// Response for listing secrets
#[derive(Debug, Serialize)]
pub struct ListSecretsResponse {
    /// List of secret paths
    pub secrets: Vec<SecretListItem>,
    
    /// Pagination token for the next page
    pub next_token: Option<String>,
}

/// Secret list item
#[derive(Debug, Serialize)]
pub struct SecretListItem {
    /// Secret path
    pub path: String,
    
    /// Secret description
    pub description: Option<String>,
    
    /// When the secret was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
    
    /// Version count
    pub version_count: usize,
}

/// Get a secret
pub async fn get_secret(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(
        &claims.sub,
        "secrets",
        &format!("secrets:read:{}", path),
    )? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    let secret = state.secrets_service.get_secret(&path).await?;
    Ok(Json(secret))
}

/// List secrets
pub async fn list_secrets(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    query: axum::extract::Query<ListSecretsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(&claims.sub, "secrets", "secrets:list")? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    let secrets = state
        .secrets_service
        .list_secrets(query.limit, query.next_token.as_deref())
        .await?;

    let items = secrets
        .items
        .into_iter()
        .map(|s| SecretListItem {
            path: s.path,
            description: s.description,
            updated_at: s.updated_at,
            version_count: s.version_count,
        })
        .collect();

    Ok(Json(ListSecretsResponse {
        secrets: items,
        next_token: secrets.next_token,
    }))
}

/// Create a secret
pub async fn create_secret(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Json(payload): Json<CreateOrUpdateSecretRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(
        &claims.sub,
        "secrets",
        &format!("secrets:create:{}", path),
    )? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    let value = payload.value.ok_or_else(|| {
        ApiError::bad_request("Value is required")
    })?;

    let secret = state
        .secrets_service
        .create_secret(
            &path,
            value,
            payload.description,
            payload.metadata.unwrap_or_default(),
            &claims.sub,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(secret)))
}

/// Update a secret
pub async fn update_secret(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Json(payload): Json<CreateOrUpdateSecretRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(
        &claims.sub,
        "secrets",
        &format!("secrets:update:{}", path),
    )? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    let value = payload.value.ok_or_else(|| {
        ApiError::bad_request("Value is required")
    })?;

    let secret = state
        .secrets_service
        .update_secret(
            &path,
            value,
            payload.description,
            payload.metadata,
            &claims.sub,
        )
        .await?;

    Ok(Json(secret))
}

/// Delete a secret
pub async fn delete_secret(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(
        &claims.sub,
        "secrets",
        &format!("secrets:delete:{}", path),
    )? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    state.secrets_service.delete_secret(&path).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List secret versions
pub async fn list_secret_versions(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(
        &claims.sub,
        "secrets",
        &format!("secrets:read:{}", path),
    )? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    let versions = state.secrets_service.list_secret_versions(&path).await?;
    Ok(Json(versions))
}

/// Get a specific secret version
pub async fn get_secret_version(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((path, version)): Path<(String, Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(
        &claims.sub,
        "secrets",
        &format!("secrets:read:{}", path),
    )? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    let version = state
        .secrets_service
        .get_secret_version(&path, &version)
        .await?;
    Ok(Json(version))
}

/// Rollback to a previous secret version
pub async fn rollback_secret_version(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((path, version)): Path<(String, Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    // Check permissions
    if !state.policy_engine.is_allowed(
        &claims.sub,
        "secrets",
        &format!("secrets:update:{}", path),
    )? {
        return Err(ApiError::forbidden("Insufficient permissions"));
    }

    let secret = state
        .secrets_service
        .rollback_secret_version(&path, &version, &claims.sub)
        .await?;

    Ok(Json(secret))
}
