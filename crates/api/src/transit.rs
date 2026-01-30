use axum::{
    Router,
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

// Import the actual transit engine from the main crypto crate
use secreton_crypto::transit::{KeyType, TransitEngine, keys::KeyOptions};

// Import ApiState from the parent module
use crate::{ApiState, ApiResponse};

#[derive(Clone)]
pub struct TransitApiState {
    pub engine: Arc<TransitEngine>,
}

impl Default for TransitApiState {
    fn default() -> Self {
        Self {
            engine: Arc::new(TransitEngine::new()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateKeyResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,       // base64 encoded
    pub context: Option<String>, // base64 encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub context: Option<String>, // base64 encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String, // base64 encoded
}

pub fn create_transit_router() -> Router<()> {
    Router::new()
        .route("/keys", get(list_keys))
        .route("/keys/{key_name}", post(create_key))
        .route("/encrypt/{key_name}", post(encrypt_data))
        .route("/decrypt/{key_name}", post(decrypt_data))
}

pub async fn list_keys(Extension(state): Extension<ApiState>) -> Json<ApiResponse<ListKeysResponse>> {
    let keys = state.transit.engine.list_keys().await;
    Json(ApiResponse::success(ListKeysResponse { keys }))
}

pub async fn create_key(
    Path(key_name): Path<String>,
    Extension(state): Extension<ApiState>,
    Json(request): Json<CreateKeyRequest>,
) -> Result<Json<ApiResponse<CreateKeyResponse>>, StatusCode> {
    // Parse key type from string to KeyType enum
    let key_type = match request.key_type.as_deref().unwrap_or("aes256-gcm") {
        "aes256-gcm" => KeyType::Aes256Gcm,
        "chacha20-poly1305" => KeyType::ChaCha20Poly1305,
        "xchacha20-poly1305" => KeyType::XChaCha20Poly1305,
        "ed25519" => KeyType::Ed25519,
        "ecdsa-p256" => KeyType::EcdsaP256,
        "ecdsa-secp256k1" => KeyType::EcdsaSecp256k1,
        "x25519" => KeyType::X25519,
        _ => {
            warn!("Invalid key type requested: {:?}", request.key_type);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let options = KeyOptions::default();

    match state
        .transit
        .engine
        .create_key(key_name.clone(), key_type, Some(options))
        .await
    {
        Ok(_) => {
            info!("Created key: {}", key_name);
            Ok(Json(ApiResponse::success(CreateKeyResponse {
                success: true,
                message: format!("Key '{}' created", key_name),
            })))
        }
        Err(e) => {
            warn!("Failed to create key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[axum::debug_handler]
pub async fn encrypt_data(
    Extension(state): Extension<ApiState>,
    Path(key_name): Path<String>,
    Json(request): Json<EncryptRequest>,
) -> Result<Json<ApiResponse<EncryptResponse>>, StatusCode> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Decode base64 plaintext
    let plaintext_bytes = match BASE64.decode(&request.plaintext) {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Decode context if provided
    let context = if let Some(ctx) = request.context {
        match BASE64.decode(&ctx) {
            Ok(bytes) => Some(bytes),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    match state
        .transit
        .engine
        .encrypt(&key_name, &plaintext_bytes, context.as_deref(), None)
        .await
    {
        Ok(ciphertext) => {
            info!("Encrypted data with key: {}", key_name);
            Ok(Json(ApiResponse::success(EncryptResponse { ciphertext })))
        }
        Err(e) => {
            warn!("Failed to encrypt with key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[axum::debug_handler]
pub async fn decrypt_data(
    Extension(state): Extension<ApiState>,
    Path(key_name): Path<String>,
    Json(request): Json<DecryptRequest>,
) -> Result<Json<ApiResponse<DecryptResponse>>, StatusCode> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Decode context if provided
    let context = if let Some(ctx) = request.context {
        match BASE64.decode(&ctx) {
            Ok(bytes) => Some(bytes),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    match state
        .transit
        .engine
        .decrypt(&key_name, &request.ciphertext, context.as_deref())
        .await
    {
        Ok(plaintext_bytes) => {
            info!("Decrypted data with key: {}", key_name);
            Ok(Json(ApiResponse::success(DecryptResponse {
                plaintext: BASE64.encode(&plaintext_bytes),
            })))
        }
        Err(e) => {
            warn!("Failed to decrypt with key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
