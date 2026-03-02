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
use secreton_crypto::transit::{
    KeyType, KeyUsage, SignatureAlgorithm, TransitEngine,
    keys::{KeyInfo, KeyOptions},
};

// Import ApiState from the parent module
use crate::{ApiResponse, ApiState};

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

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub input: String, // base64 encoded
    pub algorithm: Option<String>,
    pub key_version: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: String,
    pub algorithm: Option<String>,
    pub key_version: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub input: String, // base64 encoded
    pub signature: String,
    pub algorithm: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

pub fn create_transit_router() -> Router<()> {
    Router::new()
        .route("/keys", get(list_keys))
        .route("/keys/{key_name}", post(create_key).get(get_key_info))
        .route("/encrypt/{key_name}", post(encrypt_data))
        .route("/decrypt/{key_name}", post(decrypt_data))
        .route("/sign/{key_name}", post(sign_data))
        .route("/verify/{key_name}", post(verify_data))
}

pub async fn list_keys(
    Extension(state): Extension<ApiState>,
) -> Json<ApiResponse<ListKeysResponse>> {
    let keys = state.transit.engine.list_keys().await;
    Json(ApiResponse::success(ListKeysResponse { keys }))
}

pub async fn get_key_info(
    Path(key_name): Path<String>,
    Extension(state): Extension<ApiState>,
) -> Result<Json<ApiResponse<KeyInfo>>, StatusCode> {
    match state.transit.engine.get_key_info(&key_name).await {
        Ok(info) => Ok(Json(ApiResponse::success(info))),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
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

    let options = match key_type {
        KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1 => KeyOptions {
            usage: vec![KeyUsage::Sign, KeyUsage::Verify],
            ..KeyOptions::default()
        },
        _ => KeyOptions::default(),
    };

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

#[axum::debug_handler]
pub async fn sign_data(
    Extension(state): Extension<ApiState>,
    Path(key_name): Path<String>,
    Json(request): Json<SignRequest>,
) -> Result<Json<ApiResponse<SignResponse>>, StatusCode> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Decode base64 input
    let input_bytes = match BASE64.decode(&request.input) {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let algorithm = match request.algorithm.as_deref() {
        Some("ed25519") => Some(SignatureAlgorithm::Ed25519),
        Some("ecdsa-p256") => Some(SignatureAlgorithm::EcdsaP256),
        Some("ecdsa-secp256k1") => Some(SignatureAlgorithm::EcdsaSecp256k1),
        Some(_) => return Err(StatusCode::BAD_REQUEST),
        None => None,
    };

    // If algorithm is not specified, try to infer it from key type for the response
    let response_algorithm = if request.algorithm.is_none() {
        if let Ok(key_info) = state.transit.engine.get_key_info(&key_name).await {
            match key_info.key_type {
                KeyType::Ed25519 => Some("ed25519".to_string()),
                KeyType::EcdsaP256 => Some("ecdsa-p256".to_string()),
                KeyType::EcdsaSecp256k1 => Some("ecdsa-secp256k1".to_string()),
                _ => None,
            }
        } else {
            None
        }
    } else {
        request.algorithm.clone()
    };

    match state
        .transit
        .engine
        .sign(&key_name, &input_bytes, algorithm, request.key_version)
        .await
    {
        Ok(signature) => {
            info!("Signed data with key: {}", key_name);
            Ok(Json(ApiResponse::success(SignResponse {
                signature,
                algorithm: response_algorithm,
                key_version: request.key_version,
            })))
        }
        Err(e) => {
            warn!("Failed to sign with key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[axum::debug_handler]
pub async fn verify_data(
    Extension(state): Extension<ApiState>,
    Path(key_name): Path<String>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<ApiResponse<VerifyResponse>>, StatusCode> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    // Decode base64 input
    let input_bytes = match BASE64.decode(&request.input) {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let algorithm = match request.algorithm.as_deref() {
        Some("ed25519") => Some(SignatureAlgorithm::Ed25519),
        Some("ecdsa-p256") => Some(SignatureAlgorithm::EcdsaP256),
        Some("ecdsa-secp256k1") => Some(SignatureAlgorithm::EcdsaSecp256k1),
        Some(_) => return Err(StatusCode::BAD_REQUEST),
        None => None,
    };

    match state
        .transit
        .engine
        .verify(&key_name, &input_bytes, &request.signature, algorithm)
        .await
    {
        Ok(valid) => {
            tracing::debug!("Verified data with key: {}, valid: {}", key_name, valid);
            Ok(Json(ApiResponse::success(VerifyResponse { valid })))
        }
        Err(e) => {
            warn!("Failed to verify with key {}: {:?}", key_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secreton_crypto::transit::{KeyType, SignatureAlgorithm, TransitEngine, keys::KeyOptions};

    #[tokio::test]
    async fn test_transit_engine_integration() {
        let engine = TransitEngine::new();
        let key_name = "test-sign-key".to_string();

        // 1. Create Key
        engine
            .create_key(
                key_name.clone(),
                KeyType::Ed25519,
                Some(KeyOptions {
                    usage: vec![KeyUsage::Sign, KeyUsage::Verify],
                    ..KeyOptions::default()
                }),
            )
            .await
            .expect("Failed to create key");

        // 2. Sign Data
        let data = b"Hello World";
        let signature = engine
            .sign(&key_name, data, Some(SignatureAlgorithm::Ed25519), None)
            .await
            .expect("Failed to sign data");

        // 3. Verify Data
        let valid = engine
            .verify(
                &key_name,
                data,
                &signature,
                Some(SignatureAlgorithm::Ed25519),
            )
            .await
            .expect("Failed to verify signature");

        assert!(valid, "Signature should be valid");

        // 4. Verify Invalid Data
        let invalid_data = b"Hello World Modified";
        let valid = engine
            .verify(
                &key_name,
                invalid_data,
                &signature,
                Some(SignatureAlgorithm::Ed25519),
            )
            .await
            .expect("Failed to verify signature");

        assert!(!valid, "Signature should be invalid for modified data");
    }
}
