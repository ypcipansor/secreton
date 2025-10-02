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

// Import the actual transit engine from the main crypto crate
use secreton_crypto::transit::{KeyType, TransitEngine, algorithms::HashAlgorithm, keys::{KeyOptions, KeyUsage}};

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
) -> Json<ListKeysResponse> {
    let keys = state.engine.list_keys().await;
    Json(ListKeysResponse { keys })
}

pub async fn create_key(
    Path(key_name): Path<String>,
    State(state): State<TransitApiState>,
    Json(request): Json<CreateKeyRequest>,
) -> Result<Json<CreateKeyResponse>, StatusCode> {
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

    match state.engine.create_key(key_name.clone(), key_type, Some(options)).await {
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
    let context = if let Some(ctx) = request.context {
        match BASE64.decode(&ctx) {
            Ok(bytes) => Some(bytes),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    match state.engine.encrypt(&key_name, &plaintext_bytes, context.as_deref(), None).await {
        Ok(ciphertext) => {
            info!("Encrypted data with key: {}", key_name);
            Ok(Json(EncryptResponse {
                ciphertext,
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
    let context = if let Some(ctx) = request.context {
        match BASE64.decode(&ctx) {
            Ok(bytes) => Some(bytes),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    match state.engine.decrypt(&key_name, &request.ciphertext, context.as_deref()).await {
        Ok(plaintext_bytes) => {
            info!("Decrypted data with key: {}", key_name);
            Ok(Json(DecryptResponse {
                plaintext: BASE64.encode(&plaintext_bytes),
            }))
        }
        Err(e) => {
            warn!("Failed to decrypt with key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
