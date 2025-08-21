use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use brankas_crypto::transit_simple::{TransitEngine, KeyType};

#[derive(Clone)]
pub struct TransitApiState {
    pub engine: Arc<TransitEngine>,
}

#[derive(Serialize)]
pub struct ListKeysResponse {
    pub keys: Vec<String>,
}

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: Option<String>,
}

#[derive(Serialize)]
pub struct CreateKeyResponse {
    pub success: bool,
    pub message: String,
}

pub fn create_transit_router() -> Router<TransitApiState> {
    Router::new()
        .route("/keys", get(list_keys))
        .route("/keys/:key_name", post(create_key))
}

pub async fn list_keys(
    State(state): State<TransitApiState>,
) -> Result<Json<ListKeysResponse>, StatusCode> {
    let keys = state.engine.list_keys().await;
    Ok(Json(ListKeysResponse { keys }))
}

pub async fn create_key(
    Path(key_name): Path<String>,
    State(state): State<TransitApiState>,
    Json(_request): Json<CreateKeyRequest>,
) -> Result<Json<CreateKeyResponse>, StatusCode> {
    match state.engine.create_key(key_name.clone(), KeyType::Aes256Gcm, None).await {
        Ok(_) => {
            info!("Created key: {}", key_name);
            Ok(Json(CreateKeyResponse {
                success: true,
                message: format!("Key '{}' created", key_name),
            }))
        },
        Err(e) => {
            warn!("Failed to create key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}