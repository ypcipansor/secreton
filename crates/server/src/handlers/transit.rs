//! Transit Engine handlers.
//!
//! Provides endpoints for encryption-as-a-service operations,
//! including key management and cryptographic operations.

use secreton_domain::SecretonError;

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::extractors::AuthenticatedUser;
use crate::router::AppState;
use crate::handlers::validate_name;
use secreton_engines::Services;
use secreton_engines::services::audit::SecurityEventType;
use secreton_domain::{ApiResponse};
use crate::error::{ApiResult};
use secreton_crypto::CryptoError;
use secreton_crypto::transit::{HashAlgorithm, KeyOptions, KeyType, SignatureAlgorithm};
use tracing::{info, warn};

/// Create transit engine routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Key management
        .route("/keys", get(list_keys))
        .route("/keys/{name}", get(get_key))
        .route("/keys/{name}", post(create_key))
        .route("/keys/{name}/rotate", post(rotate_key))
        .route("/keys/{name}", delete(delete_key))
        // Cryptographic operations
        .route("/encrypt/{name}", post(encrypt))
        .route("/decrypt/{name}", post(decrypt))
        .route("/sign/{name}", post(sign))
        .route("/verify/{name}", post(verify))
        .route("/hash", post(hash))
        .route("/random", post(random))
}

// Models matching Transit Engine structures

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: Option<KeyType>,
    /// Whether key can be exported
    #[serde(default)]
    pub exportable: Option<bool>,
    /// Key usage constraints (if omitted, defaults are inferred from key type)
    pub usage: Option<Vec<secreton_crypto::transit::KeyUsage>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,       // Base64 encoded
    pub context: Option<String>, // Base64 encoded
    pub key_version: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub context: Option<String>, // Base64 encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String, // Base64 encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub input: String, // Base64 encoded
    pub algorithm: Option<SignatureAlgorithm>,
    pub key_version: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub input: String, // Base64 encoded
    pub signature: String,
    pub algorithm: Option<SignatureAlgorithm>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HashRequest {
    pub input: String, // Base64 encoded
    #[serde(default = "default_hash_algorithm")]
    pub algorithm: HashAlgorithm,
}

fn default_hash_algorithm() -> HashAlgorithm {
    HashAlgorithm::Sha256
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HashResponse {
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RandomRequest {
    pub bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RandomResponse {
    pub data: String, // Base64 encoded
}

/// Map `CryptoError` variants to the appropriate `ApiError` so that the HTTP
/// response carries the correct status code.
fn map_crypto_err(e: CryptoError) -> crate::error::ApiError {
    match &e {
        CryptoError::KeyNotFound(_) | CryptoError::KeyVersionNotFound(_) => {
            crate::error::ApiError(SecretonError::NotFound { resource: e.to_string() })
        }
        CryptoError::KeyAlreadyExists(_) => crate::error::ApiError(SecretonError::Conflict { message: e.to_string() }),
        CryptoError::InvalidInput(_)
        | CryptoError::InvalidUsage(_)
        | CryptoError::InvalidParameter(_)
        | CryptoError::InvalidKey(_)
        | CryptoError::InvalidKeyLength { .. }
        | CryptoError::InvalidNonceLength
        | CryptoError::InvalidAlgorithm(_)
        | CryptoError::InvalidCiphertext(_)
        | CryptoError::InvalidSignature(_)
        | CryptoError::ValidationError(_)
        | CryptoError::EncryptionFailed(_)
        | CryptoError::DecryptionFailed(_)
        | CryptoError::SigningFailed(_)
        | CryptoError::VerificationFailed(_) => crate::error::ApiError(SecretonError::Validation { message: e.to_string() }),
        CryptoError::PermissionDenied(_) => crate::error::ApiError(SecretonError::Authorization { message: e.to_string() }),
        CryptoError::RateLimitExceeded(_) | CryptoError::ConcurrencyLimitExceeded => {
            crate::error::ApiError(SecretonError::RateLimitExceeded { message: e.to_string() })
        }
        _ => crate::error::ApiError(SecretonError::Internal { message: e.to_string() }),
    }
}

/// List all transit keys
pub async fn list_keys(
    State(state): State<Services>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<HashMap<String, Vec<String>>>>> {
    let keys = state.transit.list_keys().await;
    let mut response = HashMap::new();
    response.insert("keys".to_string(), keys);
    Ok(Json(ApiResponse::success(response)))
}

/// Get transit key information
pub async fn get_key(
    State(state): State<Services>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<secreton_crypto::transit::KeyInfo>>> {
    validate_name(&name)?;
    let info = state
        .transit
        .get_key_info(&name)
        .await
        .map_err(map_crypto_err)?;
    Ok(Json(ApiResponse::success(info)))
}

/// Create a new transit key
pub async fn create_key(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    // Only admin/root users may create transit keys
    if !user.is_admin() {
        return Err(crate::error::ApiError(SecretonError::Authorization { message: 
            "Admin privileges required to create transit keys".to_string(),
         }));
    }

    validate_name(&name)?;
    let key_type = request.key_type.unwrap_or(KeyType::Aes256Gcm);

    // Build KeyOptions from the explicit optional fields.
    // When usage is omitted, infer sensible defaults from the key type.
    let usage = match request.usage {
        Some(u) => u,
        None => match &key_type {
            KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1 => {
                vec![
                    secreton_crypto::transit::KeyUsage::Sign,
                    secreton_crypto::transit::KeyUsage::Verify,
                ]
            }
            _ => KeyOptions::default().usage,
        },
    };

    let options = KeyOptions {
        exportable: request.exportable.unwrap_or(false),
        usage,
        ..KeyOptions::default()
    };

    state
        .transit
        .create_key(name.clone(), key_type.clone(), Some(options))
        .await
        .map_err(|e| {
            warn!("Failed to create key {}: {:?}", name, e);
            map_crypto_err(e)
        })?;
    info!("Created transit key: {}", name);

    state
        .audit
        .log_event(SecurityEventType::KeyGeneration {
            key_type: format!("{:?}", key_type),
            key_id: name,
            algorithm: format!("{:?}", key_type),
            user: user.username,
        })
        .await;

    Ok(Json(ApiResponse::success(())))
}

/// Rotate a transit key
pub async fn rotate_key(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<u32>>> {
    // Only admin/root users may rotate transit keys
    if !user.is_admin() {
        return Err(crate::error::ApiError(SecretonError::Authorization { message: 
            "Admin privileges required to rotate transit keys".to_string(),
         }));
    }

    validate_name(&name)?;
    let new_version = state.transit.rotate_key(&name).await.map_err(|e| {
        warn!("Failed to rotate key {}: {:?}", name, e);
        map_crypto_err(e)
    })?;
    info!("Rotated transit key: {} to version {}", name, new_version);

    state
        .audit
        .log_event(SecurityEventType::KeyRotation {
            old_key_id: name.clone(),
            new_key_id: name,
            algorithm: format!("v{}", new_version),
            user: user.username,
        })
        .await;

    Ok(Json(ApiResponse::success(new_version)))
}

/// Delete a transit key
pub async fn delete_key(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    // Only admin/root users may delete transit keys
    if !user.is_admin() {
        return Err(crate::error::ApiError(SecretonError::Authorization { message: 
            "Admin privileges required to delete transit keys".to_string(),
         }));
    }

    validate_name(&name)?;
    state.transit.delete_key(&name).await.map_err(|e| {
        warn!("Failed to delete key {}: {:?}", name, e);
        map_crypto_err(e)
    })?;
    info!("Deleted transit key: {}", name);

    state
        .audit
        .log_event(SecurityEventType::KeyDeletion {
            key_id: name,
            user: user.username,
        })
        .await;

    Ok(Json(ApiResponse::success(())))
}

/// Encrypt data
pub async fn encrypt(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<EncryptRequest>,
) -> ApiResult<Json<ApiResponse<EncryptResponse>>> {
    validate_name(&name)?;
    let plaintext = BASE64_STANDARD
        .decode(&request.plaintext)
        .map_err(|e| crate::error::ApiError(SecretonError::Validation { message: format!("Invalid base64 plaintext: {}", e) }))?;

    let data_size = plaintext.len() as u64;

    let context = request
        .context
        .map(|c| BASE64_STANDARD.decode(&c))
        .transpose()
        .map_err(|e| crate::error::ApiError(SecretonError::Validation { message: format!("Invalid base64 context: {}", e) }))?;

    let ciphertext = state
        .transit
        .encrypt(&name, &plaintext, context.as_deref(), request.key_version)
        .await
        .map_err(|e| {
            warn!("Failed to encrypt with key {}: {:?}", name, e);
            map_crypto_err(e)
        })?;

    state
        .audit
        .log_event(SecurityEventType::EncryptionOperation {
            key_id: name,
            user: user.username,
            data_size,
        })
        .await;

    Ok(Json(ApiResponse::success(EncryptResponse { ciphertext })))
}

/// Decrypt data
pub async fn decrypt(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<DecryptRequest>,
) -> ApiResult<Json<ApiResponse<DecryptResponse>>> {
    validate_name(&name)?;
    let context = request
        .context
        .map(|c| BASE64_STANDARD.decode(&c))
        .transpose()
        .map_err(|e| crate::error::ApiError(SecretonError::Validation { message: format!("Invalid base64 context: {}", e) }))?;

    let plaintext = state
        .transit
        .decrypt(&name, &request.ciphertext, context.as_deref())
        .await
        .map_err(|e| {
            warn!("Failed to decrypt with key {}: {:?}", name, e);
            map_crypto_err(e)
        })?;

    state
        .audit
        .log_event(SecurityEventType::DecryptionOperation {
            key_id: name,
            user: user.username,
            data_size: request.ciphertext.len() as u64,
        })
        .await;

    Ok(Json(ApiResponse::success(DecryptResponse {
        plaintext: BASE64_STANDARD.encode(plaintext),
    })))
}

/// Sign data
pub async fn sign(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<SignRequest>,
) -> ApiResult<Json<ApiResponse<SignResponse>>> {
    validate_name(&name)?;
    let input = BASE64_STANDARD
        .decode(&request.input)
        .map_err(|e| crate::error::ApiError(SecretonError::Validation { message: format!("Invalid base64 input: {}", e) }))?;

    let data_size = input.len() as u64;

    let signature = state
        .transit
        .sign(&name, &input, request.algorithm, request.key_version)
        .await
        .map_err(|e| {
            warn!("Failed to sign with key {}: {:?}", name, e);
            map_crypto_err(e)
        })?;

    state
        .audit
        .log_event(SecurityEventType::SigningOperation {
            key_id: name,
            user: user.username,
            data_size,
        })
        .await;

    Ok(Json(ApiResponse::success(SignResponse { signature })))
}

/// Verify signature
pub async fn verify(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<ApiResponse<VerifyResponse>>> {
    validate_name(&name)?;
    let input = BASE64_STANDARD
        .decode(&request.input)
        .map_err(|e| crate::error::ApiError(SecretonError::Validation { message: format!("Invalid base64 input: {}", e) }))?;

    let data_size = input.len() as u64;

    let valid = state
        .transit
        .verify(&name, &input, &request.signature, request.algorithm)
        .await
        .map_err(|e| {
            warn!("Failed to verify with key {}: {:?}", name, e);
            map_crypto_err(e)
        })?;

    state
        .audit
        .log_event(SecurityEventType::VerificationOperation {
            key_id: name,
            user: user.username,
            data_size,
            valid,
        })
        .await;

    Ok(Json(ApiResponse::success(VerifyResponse { valid })))
}

/// Hash data
pub async fn hash(
    State(state): State<Services>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Json(request): Json<HashRequest>,
) -> ApiResult<Json<ApiResponse<HashResponse>>> {
    let input = BASE64_STANDARD
        .decode(&request.input)
        .map_err(|e| crate::error::ApiError(SecretonError::Validation { message: format!("Invalid base64 input: {}", e) }))?;

    let hash = state
        .transit
        .hash(&input, request.algorithm)
        .await
        .map_err(map_crypto_err)?;

    Ok(Json(ApiResponse::success(HashResponse { hash })))
}

/// Generate random bytes
pub async fn random(
    State(state): State<Services>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Json(request): Json<RandomRequest>,
) -> ApiResult<Json<ApiResponse<RandomResponse>>> {
    let data = state
        .transit
        .random(request.bytes)
        .await
        .map_err(map_crypto_err)?;

    Ok(Json(ApiResponse::success(RandomResponse {
        data: BASE64_STANDARD.encode(data),
    })))
}

