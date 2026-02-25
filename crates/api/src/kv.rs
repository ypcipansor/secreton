//! KV Secrets Engine API endpoints

#![allow(clippy::collapsible_if)]

use anyhow::Result;
use axum::{
    Router,
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
};
use secreton_core::storage::secret::SecretStorage;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::ApiState;

// Simple in-memory implementation of SecretStorage for KV operations
#[derive(Debug, Clone)]
pub struct InMemorySecretStorage {
    secrets: Arc<RwLock<HashMap<String, (Value, u32)>>>,
}

impl Default for InMemorySecretStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySecretStorage {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl SecretStorage for InMemorySecretStorage {
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> {
        let mut secrets = self.secrets.write().await;
        let version = secrets.get(path).map(|(_, v)| v + 1).unwrap_or(1);
        secrets.insert(path.to_string(), (data.clone(), version));
        Ok(version)
    }

    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>> {
        let secrets = self.secrets.read().await;
        Ok(secrets.get(path).cloned())
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        let secrets = self.secrets.read().await;
        let prefix = if path.ends_with('/') {
            path
        } else {
            &format!("{}/", path)
        };
        let keys: Vec<String> = secrets
            .keys()
            .filter(|k| k.starts_with(prefix))
            .map(|k| {
                k[prefix.len()..]
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        Ok(keys)
    }

    async fn delete_secret(&self, path: &str) -> Result<()> {
        let mut secrets = self.secrets.write().await;
        secrets.remove(path);
        Ok(())
    }

    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()> {
        let mut secrets = self.secrets.write().await;
        if let Some((_, current_version)) = secrets.get(path) {
            if *current_version == version {
                secrets.remove(path);
            }
        }
        Ok(())
    }
}

/// API state for KV engine
#[derive(Clone)]
pub struct KVApiState {
    pub storage: std::sync::Arc<dyn SecretStorage>,
}

impl Default for KVApiState {
    fn default() -> Self {
        Self {
            storage: std::sync::Arc::new(InMemorySecretStorage::new()),
        }
    }
}

/// Request to create/update a secret
#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ListSecretsQuery {
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DestroySecretQuery {
    pub version: u32,
}

/// Response for secret creation
#[derive(Debug, Serialize)]
pub struct CreateSecretResponse {
    pub version: u32,
    pub created_time: String,
}

/// Response for secret retrieval
#[derive(Debug, Serialize)]
pub struct GetSecretResponse {
    pub data: serde_json::Value,
    pub version: u32,
}

/// Response for listing secrets
#[derive(Debug, Serialize)]
pub struct ListSecretsResponse {
    pub keys: Vec<String>,
}

/// Response for metadata
#[derive(Debug, Serialize)]
pub struct MetadataResponse {
    pub version: u32,
}

/// Response for delete operations
#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub success: bool,
    pub message: String,
}

/// Create the KV router with all endpoints
pub fn create_kv_router() -> Router<()> {
    Router::new()
        .route("/secrets", get(list_secrets))
        .route("/secret/data/*path", post(put_secret))
        .route("/secret/data/*path", get(get_secret))
        .route("/secret/data/*path", delete(delete_secret))
        .route("/secret/metadata/*path", get(get_metadata))
        .route("/secret/destroy/*path", delete(destroy_secret))
}

/// List all secret paths
#[axum::debug_handler]
pub async fn list_secrets(
    Query(query): Query<ListSecretsQuery>,
    Extension(state): Extension<ApiState>,
) -> Result<Json<ListSecretsResponse>, StatusCode> {
    let path = query.path.unwrap_or_default();
    match state.kv.storage.list_secrets(&path).await {
        Ok(keys) => {
            info!("Listed {} secret paths in '{}'", keys.len(), path);
            Ok(Json(ListSecretsResponse { keys }))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Create or update a secret
#[axum::debug_handler]
pub async fn put_secret(
    Extension(state): Extension<ApiState>,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>, StatusCode> {
    let path = path.trim_start_matches('/').to_string();
    match state
        .kv
        .storage
        .store_secret_versioned(&path, &request.data)
        .await
    {
        Ok(version) => {
            info!("Created secret at path '{}' version {}", path, version);
            Ok(Json(CreateSecretResponse {
                version,
                created_time: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(e) => {
            warn!("Failed to create secret at path '{}': {:?}", path, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get a secret
#[axum::debug_handler]
pub async fn get_secret(
    Extension(state): Extension<ApiState>,
    Path(path): Path<String>,
) -> Result<Json<GetSecretResponse>, StatusCode> {
    let path = path.trim_start_matches('/').to_string();
    match state.kv.storage.get_latest_secret(&path).await {
        Ok(Some((data, version))) => {
            info!("Retrieved secret at path '{}'", path);
            Ok(Json(GetSecretResponse { data, version }))
        }
        Ok(None) => {
            warn!("Secret not found at path '{}'", path);
            Err(StatusCode::NOT_FOUND)
        }
        Err(_) => {
            warn!("Error retrieving secret at path '{}'", path);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Delete a secret (soft delete)
#[axum::debug_handler]
pub async fn delete_secret(
    Extension(state): Extension<ApiState>,
    Path(path): Path<String>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let path = path.trim_start_matches('/').to_string();
    match state.kv.storage.delete_secret(&path).await {
        Ok(_) => {
            info!("Deleted secret at path '{}'", path);
            Ok(Json(DeleteResponse {
                success: true,
                message: format!("Secret '{}' deleted", path),
            }))
        }
        Err(_) => {
            warn!("Failed to delete secret at path '{}'", path);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Get secret metadata
#[axum::debug_handler]
pub async fn get_metadata(
    Extension(state): Extension<ApiState>,
    Path(path): Path<String>,
) -> Result<Json<MetadataResponse>, StatusCode> {
    let path = path.trim_start_matches('/').to_string();
    match state.kv.storage.get_latest_secret(&path).await {
        Ok(Some((_, version))) => {
            info!("Retrieved metadata for path '{}'", path);
            Ok(Json(MetadataResponse { version }))
        }
        Ok(None) => {
            warn!("Secret metadata not found at path '{}'", path);
            Err(StatusCode::NOT_FOUND)
        }
        Err(_) => {
            warn!("Secret metadata not found at path '{}'", path);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Permanently destroy a secret version
#[axum::debug_handler]
pub async fn destroy_secret(
    Query(query): Query<DestroySecretQuery>,
    Extension(state): Extension<ApiState>,
    Path(path): Path<String>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let path = path.trim_start_matches('/').to_string();
    match state.kv.storage.delete_secret_version(&path, query.version).await {
        Ok(_) => {
            info!(
                "Permanently destroyed secret '{}' version {}",
                path, query.version
            );
            Ok(Json(DeleteResponse {
                success: true,
                message: format!(
                    "Secret '{}' version {} permanently destroyed",
                    path, query.version
                ),
            }))
        }
        Err(_) => {
            warn!("Failed to destroy secret '{}' version {}", path, query.version);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
