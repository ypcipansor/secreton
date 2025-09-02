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

// TODO: Replace with actual transit engine implementation
// use brankas_crypto::transit_simple::{KeyType, TransitEngine};

// Placeholder types until brankas_crypto is available
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Aes256Gcm96,
    ChaCha20Poly1305,
    Ed25519,
    Ecdsa256,
    // RSA key types removed for security - replaced with Ed25519
    // Rsa2048, // Deprecated - use Ed25519 instead
    // Rsa4096, // Deprecated - use Ed25519 instead
}

#[derive(Debug, Clone)]
pub struct TransitEngine {
    // Placeholder implementation
}

impl Default for TransitEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TransitEngine {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn list_keys(&self) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        // Placeholder implementation
        Ok(vec![])
    }

    pub async fn create_key(
        &self,
        _name: &str,
        _key_type: KeyType,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Placeholder implementation
        Ok(())
    }

    pub async fn encrypt(
        &self,
        _key_name: &str,
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Placeholder implementation
        Ok(vec![])
    }

    pub async fn decrypt(
        &self,
        _key_name: &str,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Placeholder implementation
        Ok(vec![])
    }
}

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

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,       // base64 encoded
    pub context: Option<String>, // base64 encoded
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub context: Option<String>, // base64 encoded
}

#[derive(Serialize)]
pub struct DecryptResponse {
    pub plaintext: String, // base64 encoded
}

pub fn create_transit_router() -> Router<TransitApiState> {
    Router::new()
        .route("/keys", get(list_keys))
        .route("/keys/:key_name", post(create_key))
        .route("/encrypt/:key_name", post(encrypt_data))
        .route("/decrypt/:key_name", post(decrypt_data))
}

pub async fn list_keys(
    State(state): State<TransitApiState>,
) -> Result<Json<ListKeysResponse>, StatusCode> {
    let keys = match state.engine.list_keys().await {
        Ok(keys) => keys,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    Ok(Json(ListKeysResponse { keys }))
}

pub async fn create_key(
    Path(key_name): Path<String>,
    State(state): State<TransitApiState>,
    Json(_request): Json<CreateKeyRequest>,
) -> Result<Json<CreateKeyResponse>, StatusCode> {
    match state
        .engine
        .create_key(&key_name, KeyType::Aes256Gcm96)
        .await
    {
        Ok(_) => {
            info!("Created key: {}", key_name);
            Ok(Json(CreateKeyResponse {
                success: true,
                message: format!("Key '{}' created", key_name),
            }))
        }
        Err(e) => {
            warn!("Failed to create key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[axum::debug_handler]
pub async fn encrypt_data(
    State(state): State<TransitApiState>,
    Path(key_name): Path<String>,
    Json(request): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, StatusCode> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    // Decode base64 plaintext
    let plaintext_bytes = match BASE64.decode(&request.plaintext) {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Decode context if provided
    let _context = if let Some(ctx) = request.context {
        match BASE64.decode(&ctx) {
            Ok(bytes) => Some(bytes),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    match state.engine.encrypt(&key_name, &plaintext_bytes).await {
        Ok(ciphertext) => {
            info!("Encrypted data with key: {}", key_name);
            let ciphertext_string = BASE64.encode(&ciphertext);
            Ok(Json(EncryptResponse {
                ciphertext: ciphertext_string,
            }))
        }
        Err(e) => {
            warn!("Failed to encrypt with key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[axum::debug_handler]
pub async fn decrypt_data(
    State(state): State<TransitApiState>,
    Path(key_name): Path<String>,
    Json(request): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, StatusCode> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    // Decode context if provided
    let _context = if let Some(ctx) = request.context {
        match BASE64.decode(&ctx) {
            Ok(bytes) => Some(bytes),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    match state
        .engine
        .decrypt(
            &key_name,
            &BASE64.decode(&request.ciphertext).unwrap_or_default(),
        )
        .await
    {
        Ok(plaintext_bytes) => {
            info!("Decrypted data with key: {}", key_name);
            let plaintext_b64 = BASE64.encode(&plaintext_bytes);
            Ok(Json(DecryptResponse {
                plaintext: plaintext_b64,
            }))
        }
        Err(e) => {
            warn!("Failed to decrypt with key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
