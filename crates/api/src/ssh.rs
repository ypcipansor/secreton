//! SSH Secrets Engine API endpoints

use axum::{
    Router,
    extract::Extension,
    http::StatusCode,
    response::Json,
    routing::post,
};
use secreton_secrets::{SecretEngine, SshConfig, SshEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::ApiResponse;

/// API state for SSH engine
#[derive(Clone)]
pub struct SshApiState {
    pub engine: Arc<RwLock<SshEngine>>,
}

impl Default for SshApiState {
    fn default() -> Self {
        let config = SshConfig {
            default_lease_ttl: 3600,
            max_lease_ttl: 86400,
            allowed_users: vec![],
            allowed_extensions: vec![],
            ca_private_key: None,
            ca_public_key: None,
        };
        let mut engine = SshEngine::new(config);
        // Manually enable it for now as init isn't called via standard flow here
        engine.enable();
        Self {
            engine: Arc::new(RwLock::new(engine)),
        }
    }
}

/// Request to sign a public key
#[derive(Debug, Serialize, Deserialize)]
pub struct SignKeyRequest {
    pub public_key: String,
    pub valid_principals: Option<Vec<String>>,
    pub ttl: Option<u64>,
}

/// Response for signed key
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedKeyResponse {
    pub signed_key: String,
}

/// Response for CA info
#[derive(Debug, Serialize, Deserialize)]
pub struct CaResponse {
    pub public_key: String,
}

/// Create the SSH router with all endpoints
pub fn create_ssh_router() -> Router<()> {
    Router::new()
        .route("/sign", post(sign_key))
        .route("/config/ca", post(generate_ca).get(get_ca))
}

/// Sign a public key
#[axum::debug_handler]
pub async fn sign_key(
    Extension(state): Extension<crate::ApiState>,
    Json(request): Json<SignKeyRequest>,
) -> Result<Json<ApiResponse<SignedKeyResponse>>, StatusCode> {
    let mut engine = state.ssh.engine.write().await;

    let mut data = HashMap::new();
    data.insert("public_key".to_string(), Value::String(request.public_key));

    if let Some(principals) = request.valid_principals {
        let principals_json =
            serde_json::to_value(principals).map_err(|_| StatusCode::BAD_REQUEST)?;
        data.insert("valid_principals".to_string(), principals_json);
    }

    if let Some(ttl) = request.ttl {
        data.insert(
            "ttl".to_string(),
            Value::Number(serde_json::Number::from(ttl)),
        );
    }

    match engine.write("sign", data).await {
        Ok(secret) => {
            info!("SSH Key signed");
            let signed_key = secret
                .data
                .get("signed_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Ok(Json(ApiResponse::success(SignedKeyResponse { signed_key })))
        }
        Err(e) => {
            error!("Failed to sign key: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Generate CA
#[axum::debug_handler]
pub async fn generate_ca(
    Extension(state): Extension<crate::ApiState>,
) -> Result<Json<ApiResponse<CaResponse>>, StatusCode> {
    let mut engine = state.ssh.engine.write().await;
    let data = HashMap::new();

    match engine.write("config/ca", data).await {
        Ok(secret) => {
            info!("SSH CA generated");
            let pub_key = secret
                .data
                .get("public_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Ok(Json(ApiResponse::success(CaResponse {
                public_key: pub_key,
            })))
        }
        Err(e) => {
            error!("Failed to generate CA: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get CA Public Key
#[axum::debug_handler]
pub async fn get_ca(
    Extension(state): Extension<crate::ApiState>,
) -> Result<Json<ApiResponse<CaResponse>>, StatusCode> {
    let engine = state.ssh.engine.read().await;

    match engine.read("config/ca").await {
        Ok(Some(secret)) => {
            let pub_key = secret
                .data
                .get("public_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Json(ApiResponse::success(CaResponse {
                public_key: pub_key,
            })))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get CA: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
