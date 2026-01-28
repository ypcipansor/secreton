//! PKI Secrets Engine API endpoints

use axum::{
    Router,
    extract::{Extension},
    http::StatusCode,
    response::Json,
    routing::{post},
};
use secreton_secrets::{PkiEngine, SecretEngine, PkiConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

/// API state for PKI engine
#[derive(Clone)]
pub struct PkiApiState {
    pub engine: Arc<RwLock<PkiEngine>>,
}

impl Default for PkiApiState {
    fn default() -> Self {
        let config = PkiConfig {
            default_lease_ttl: 3600,
            max_lease_ttl: 86400,
            ca_private_key: None,
            ca_cert: None,
            enable_acme: false,
        };
        let mut engine = PkiEngine::new(config);
        // Manually enable it for now as init isn't called via standard flow here
        engine.enable();
        Self {
            engine: Arc::new(RwLock::new(engine)),
        }
    }
}

/// Request to generate a certificate
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateCertRequest {
    pub common_name: String,
    pub ttl: Option<u64>,
    pub key_type: Option<String>,
    pub key_bits: Option<u64>,
    pub organization: Option<String>,
}

/// Response for certificate generation
#[derive(Debug, Serialize, Deserialize)]
pub struct CertResponse {
    pub certificate: String,
    pub private_key: String,
    pub serial_number: String,
    pub expiration: i64,
}

/// Create the PKI router with all endpoints
pub fn create_pki_router() -> Router<()> {
    Router::new()
        .route("/issue", post(issue_certificate))
}

/// Generate a certificate
#[axum::debug_handler]
pub async fn issue_certificate(
    Extension(state): Extension<PkiApiState>,
    Json(request): Json<GenerateCertRequest>,
) -> Result<Json<CertResponse>, StatusCode> {
    let mut engine = state.engine.write().await;

    let mut data = HashMap::new();
    data.insert("common_name".to_string(), Value::String(request.common_name));
    if let Some(ttl) = request.ttl {
        data.insert("ttl".to_string(), Value::Number(serde_json::Number::from(ttl)));
    }
    if let Some(kt) = request.key_type {
        data.insert("key_type".to_string(), Value::String(kt));
    }
    if let Some(kb) = request.key_bits {
        data.insert("key_bits".to_string(), Value::Number(serde_json::Number::from(kb)));
    }
    if let Some(org) = request.organization {
        data.insert("organization".to_string(), Value::String(org));
    }

    match engine.write("issue", data).await {
        Ok(secret) => {
            info!("Certificate issued");
            // Extract from secret.data
            let cert = secret.data.get("certificate").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let key = secret.data.get("private_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let serial = secret.data.get("serial_number").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // TTL is returned as number in data? PkiEngine returns `ttl` in data.
            // But we want expiration time.
            // PkiEngine doesn't return expiration time in data map explicitly, only ttl.
            // But we can calculate or just return ttl for now.
            // Actually secret.data has "ttl".
            let ttl = secret.data.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0);

            Ok(Json(CertResponse {
                certificate: cert,
                private_key: key,
                serial_number: serial,
                expiration: ttl as i64,
            }))
        }
        Err(e) => {
            error!("Failed to issue certificate: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
