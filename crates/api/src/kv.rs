//! KV Secrets Engine API endpoints

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use brankas_crypto::{KVEngine, SecretMetadata};

/// API state for KV engine
#[derive(Clone)]
pub struct KVApiState {
    pub engine: std::sync::Arc<KVEngine>,
}

/// Request to create/update a secret
#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub data: HashMap<String, String>,
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
    pub data: HashMap<String, String>,
    pub metadata: SecretMetadata,
}

/// Response for listing secrets
#[derive(Debug, Serialize)]
pub struct ListSecretsResponse {
    pub keys: Vec<String>,
}

/// Response for metadata
#[derive(Debug, Serialize)]
pub struct MetadataResponse {
    pub versions: HashMap<u32, SecretMetadata>,
}

/// Response for delete operations
#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub success: bool,
    pub message: String,
}

/// Create the KV router with all endpoints
pub fn create_kv_router(state: KVApiState) -> Router {
    Router::new()
        .route("/secrets", get(list_secrets))
        .route("/secret/data/:path", post(put_secret))
        .route("/secret/data/:path", get(get_secret))
        .route("/secret/data/:path", delete(delete_secret))
        .route("/secret/metadata/:path", get(get_metadata))
        .route("/secret/destroy/:path/:version", delete(destroy_secret))
        .with_state(state)
}

/// List all secret paths
#[axum::debug_handler]
pub async fn list_secrets(
    State(state): State<KVApiState>,
) -> Result<Json<ListSecretsResponse>, StatusCode> {
    let keys = state.engine.list_secrets().await;
    
    info!("Listed {} secret paths", keys.len());
    
    Ok(Json(ListSecretsResponse { keys }))
}

/// Create or update a secret
#[axum::debug_handler]
pub async fn put_secret(
    State(state): State<KVApiState>,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>, StatusCode> {
    match state.engine.put_secret(&path, request.data).await {
        Ok(version) => {
            info!("Created secret at path '{}' version {}", path, version);
            Ok(Json(CreateSecretResponse {
                version,
                created_time: chrono::Utc::now().to_rfc3339(),
            }))
        },
        Err(e) => {
            warn!("Failed to create secret at path '{}': {:?}", path, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get a secret
#[axum::debug_handler]
pub async fn get_secret(
    State(state): State<KVApiState>,
    Path(path): Path<String>,
) -> Result<Json<GetSecretResponse>, StatusCode> {
    match state.engine.get_secret(&path, None).await {
        Ok(secret_data) => {
            info!("Retrieved secret from path '{}'", path);
            Ok(Json(GetSecretResponse {
                data: secret_data.data,
                metadata: secret_data.metadata,
            }))
        },
        Err(_) => {
            warn!("Secret not found at path '{}'", path);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Delete a secret (soft delete)
#[axum::debug_handler]
pub async fn delete_secret(
    State(state): State<KVApiState>,
    Path(path): Path<String>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    match state.engine.delete_secret(&path, None).await {
        Ok(_) => {
            info!("Deleted secret at path '{}'", path);
            Ok(Json(DeleteResponse {
                success: true,
                message: format!("Secret '{}' deleted", path),
            }))
        },
        Err(_) => {
            warn!("Failed to delete secret at path '{}'", path);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Get secret metadata
#[axum::debug_handler]
pub async fn get_metadata(
    State(state): State<KVApiState>,
    Path(path): Path<String>,
) -> Result<Json<MetadataResponse>, StatusCode> {
    match state.engine.get_metadata(&path).await {
        Ok(versions) => {
            info!("Retrieved metadata for path '{}'", path);
            Ok(Json(MetadataResponse { versions }))
        },
        Err(_) => {
            warn!("Secret metadata not found at path '{}'", path);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Permanently destroy a secret version
#[axum::debug_handler]
pub async fn destroy_secret(
    State(state): State<KVApiState>,
    Path((path, version)): Path<(String, u32)>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    match state.engine.destroy_secret(&path, version).await {
        Ok(_) => {
            info!("Permanently destroyed secret '{}' version {}", path, version);
            Ok(Json(DeleteResponse {
                success: true,
                message: format!("Secret '{}' version {} permanently destroyed", path, version),
            }))
        },
        Err(_) => {
            warn!("Failed to destroy secret '{}' version {}", path, version);
            Err(StatusCode::NOT_FOUND)
        }
    }
}
