//! TOTP Secrets Engine API endpoints

use axum::{
    Router,
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
};
use secreton_secrets::{SecretEngine, TotpEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::ApiResponse;

/// API state for TOTP engine
#[derive(Clone)]
pub struct TotpApiState {
    pub engine: Arc<RwLock<TotpEngine>>,
}

impl Default for TotpApiState {
    fn default() -> Self {
        let mut engine = TotpEngine::new();
        // Manually enable it for now as init isn't called via standard flow here
        engine.enable();
        Self {
            engine: Arc::new(RwLock::new(engine)),
        }
    }
}

/// Request to create a TOTP key
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub key: String, // Base32 encoded secret
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub period: Option<u64>,
    pub digits: Option<u32>,
}

/// Response for code generation
#[derive(Debug, Serialize, Deserialize)]
pub struct CodeResponse {
    pub code: String,
}

/// Response for list keys
#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<String>,
}

/// Create the TOTP router with all endpoints
pub fn create_totp_router() -> Router<()> {
    Router::new()
        .route("/keys", get(list_keys))
        .route("/keys/{name}", post(create_key).delete(delete_key))
        .route("/code/{name}", get(generate_code))
}

/// Create a new TOTP key
#[axum::debug_handler]
pub async fn create_key(
    Extension(state): Extension<crate::ApiState>,
    Path(name): Path<String>,
    Json(request): Json<CreateKeyRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut engine = state.totp.engine.write().await;

    let mut data = HashMap::new();
    data.insert("key".to_string(), Value::String(request.key));
    if let Some(issuer) = request.issuer {
        data.insert("issuer".to_string(), Value::String(issuer));
    }
    if let Some(account_name) = request.account_name {
        data.insert("account_name".to_string(), Value::String(account_name));
    }
    if let Some(period) = request.period {
        data.insert(
            "period".to_string(),
            Value::Number(serde_json::Number::from(period)),
        );
    }
    if let Some(digits) = request.digits {
        data.insert(
            "digits".to_string(),
            Value::Number(serde_json::Number::from(digits)),
        );
    }

    match engine.write(&format!("keys/{}", name), data).await {
        Ok(_) => {
            info!("TOTP Key created: {}", name);
            Ok(Json(ApiResponse::success(format!(
                "Key '{}' created",
                name
            ))))
        }
        Err(e) => {
            error!("Failed to create key {}: {:?}", name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Generate a code
#[axum::debug_handler]
pub async fn generate_code(
    Extension(state): Extension<crate::ApiState>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<CodeResponse>>, StatusCode> {
    let engine = state.totp.engine.read().await;

    match engine.read(&format!("code/{}", name)).await {
        Ok(Some(secret)) => {
            let code = secret
                .data
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Json(ApiResponse::success(CodeResponse { code })))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to generate code for {}: {:?}", name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// List keys
#[axum::debug_handler]
pub async fn list_keys(
    Extension(state): Extension<crate::ApiState>,
) -> Result<Json<ApiResponse<ListKeysResponse>>, StatusCode> {
    let engine = state.totp.engine.read().await;

    match engine.list("keys").await {
        Ok(keys) => Ok(Json(ApiResponse::success(ListKeysResponse { keys }))),
        Err(e) => {
            error!("Failed to list keys: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Delete a key
#[axum::debug_handler]
pub async fn delete_key(
    Extension(state): Extension<crate::ApiState>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let mut engine = state.totp.engine.write().await;

    match engine.delete(&format!("keys/{}", name)).await {
        Ok(_) => {
            info!("TOTP Key deleted: {}", name);
            Ok(Json(ApiResponse::success(format!(
                "Key '{}' deleted",
                name
            ))))
        }
        Err(e) => {
            error!("Failed to delete key {}: {:?}", name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
