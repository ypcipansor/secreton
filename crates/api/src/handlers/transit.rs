//! Transit Engine handlers.
//!
//! Provides endpoints for encryption-as-a-service operations,
//! including key management and cryptographic operations.

use axum::{
    Router,
    extract::{Path, State},
    response::Json,
    routing::{delete, get, post},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::handlers::AppState;
use crate::{ApiResponse, ApiResult};
use secreton_crypto::transit::{HashAlgorithm, KeyOptions, KeyType, SignatureAlgorithm};

/// Create transit engine routes
pub fn create_routes() -> Router<AppState> {
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
    #[serde(flatten)]
    pub options: Option<KeyOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String, // Base64 encoded
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
    pub algorithm: HashAlgorithm,
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

/// List all transit keys
pub async fn list_keys(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<HashMap<String, Vec<String>>>>> {
    let keys = state.transit.list_keys().await;
    let mut response = HashMap::new();
    response.insert("keys".to_string(), keys);
    Ok(Json(ApiResponse::success(response)))
}

/// Get transit key information
pub async fn get_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<secreton_crypto::transit::KeyInfo>>> {
    let info = state.transit.get_key_info(&name).await
        .map_err(|e| crate::ApiError::NotFound(format!("Key not found: {}", e)))?;
    Ok(Json(ApiResponse::success(info)))
}

/// Create a new transit key
pub async fn create_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(request): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<()>>> {
    let key_type = request.key_type.unwrap_or(KeyType::Aes256Gcm);
    state.transit.create_key(name, key_type, request.options).await
        .map_err(|e| crate::ApiError::BadRequest(e.to_string()))?;
    Ok(Json(ApiResponse::success(())))
}

/// Rotate a transit key
pub async fn rotate_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<u32>>> {
    let new_version = state.transit.rotate_key(&name).await
        .map_err(|e| crate::ApiError::NotFound(e.to_string()))?;
    Ok(Json(ApiResponse::success(new_version)))
}

/// Delete a transit key
pub async fn delete_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<()>>> {
    state.transit.delete_key(&name).await
        .map_err(|e| crate::ApiError::NotFound(e.to_string()))?;
    Ok(Json(ApiResponse::success(())))
}

/// Encrypt data
pub async fn encrypt(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(request): Json<EncryptRequest>,
) -> ApiResult<Json<ApiResponse<EncryptResponse>>> {
    let plaintext = BASE64_STANDARD.decode(&request.plaintext)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 plaintext: {}", e)))?;

    let context = request.context.map(|c| BASE64_STANDARD.decode(&c))
        .transpose()
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 context: {}", e)))?;

    let ciphertext = state.transit.encrypt(&name, &plaintext, context.as_deref(), request.key_version).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(EncryptResponse { ciphertext })))
}

/// Decrypt data
pub async fn decrypt(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(request): Json<DecryptRequest>,
) -> ApiResult<Json<ApiResponse<DecryptResponse>>> {
    let context = request.context.map(|c| BASE64_STANDARD.decode(&c))
        .transpose()
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 context: {}", e)))?;

    let plaintext = state.transit.decrypt(&name, &request.ciphertext, context.as_deref()).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(DecryptResponse {
        plaintext: BASE64_STANDARD.encode(plaintext)
    })))
}

/// Sign data
pub async fn sign(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(request): Json<SignRequest>,
) -> ApiResult<Json<ApiResponse<SignResponse>>> {
    let input = BASE64_STANDARD.decode(&request.input)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 input: {}", e)))?;

    let signature = state.transit.sign(&name, &input, request.algorithm, request.key_version).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(SignResponse { signature })))
}

/// Verify signature
pub async fn verify(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<ApiResponse<VerifyResponse>>> {
    let input = BASE64_STANDARD.decode(&request.input)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 input: {}", e)))?;

    let valid = state.transit.verify(&name, &input, &request.signature, request.algorithm).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(VerifyResponse { valid })))
}

/// Hash data
pub async fn hash(
    State(state): State<AppState>,
    Json(request): Json<HashRequest>,
) -> ApiResult<Json<ApiResponse<HashResponse>>> {
    let input = BASE64_STANDARD.decode(&request.input)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 input: {}", e)))?;

    let hash = state.transit.hash(&input, request.algorithm).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(HashResponse { hash })))
}

/// Generate random bytes
pub async fn random(
    State(state): State<AppState>,
    Json(request): Json<RandomRequest>,
) -> ApiResult<Json<ApiResponse<RandomResponse>>> {
    let data = state.transit.random(request.bytes).await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(RandomResponse {
        data: BASE64_STANDARD.encode(data)
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiConfig;
    use crate::services::ApiServiceContainer;
    use axum_test::TestServer;
    use std::sync::Arc;

    async fn server_with_routes() -> (TestServer, String) {
        // Set root key for crypto service auto-unseal
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }

        let mut config = ApiConfig::default();
        config.auth.jwt.secret = Some("test_secret".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();

        let services = Arc::new(
            ApiServiceContainer::new(&config)
                .await
                .expect("Failed to create services"),
        );

        // Generate mock token
        let user = secreton_auth::User {
            id: uuid::Uuid::new_v4().to_string(),
            username: "mock_user".to_string(),
            email: Some("mock@example.com".to_string()),
            display_name: Some("Mock User".to_string()),
            full_name: Some("Mock User".to_string()),
            roles: vec!["admin".to_string()],
            permissions: vec![],
            policies: vec!["default".to_string()],
            metadata: std::collections::HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            mfa_enabled: false,
            mfa_secret: None,
            password_hash: "".to_string(),
            disabled: false,
            enabled: true,
            is_active: true,
            is_superuser: true,
        };
        let token = services
            .auth
            .generate_token(&user)
            .await
            .expect("Failed to generate token");

        let app = create_routes().with_state(services.into());
        let server = TestServer::new(app.into_make_service())
            .expect("failed to start test server");
        (server, token)
    }

    #[tokio::test]
    async fn test_transit_lifecycle() {
        let (server, token) = server_with_routes().await;
        let key_name = "test-key";

        // 1. Create Key
        let create_req = CreateKeyRequest {
            key_type: Some(KeyType::Aes256Gcm),
            options: None,
        };
        let response = server
            .post(&format!("/keys/{}", key_name))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&create_req)
            .await;
        response.assert_status_ok();

        // 2. Encrypt
        let plaintext = "Hello Transit";
        let encrypt_req = EncryptRequest {
            plaintext: BASE64_STANDARD.encode(plaintext),
            context: None,
            key_version: None,
        };
        let response = server
            .post(&format!("/encrypt/{}", key_name))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&encrypt_req)
            .await;
        response.assert_status_ok();
        let encrypt_res: ApiResponse<EncryptResponse> = response.json();
        let ciphertext = encrypt_res.data.unwrap().ciphertext;

        // 3. Decrypt
        let decrypt_req = DecryptRequest {
            ciphertext,
            context: None,
        };
        let response = server
            .post(&format!("/decrypt/{}", key_name))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&decrypt_req)
            .await;
        response.assert_status_ok();
        let decrypt_res: ApiResponse<DecryptResponse> = response.json();
        let decrypted_b64 = decrypt_res.data.unwrap().plaintext;
        let decrypted = String::from_utf8(BASE64_STANDARD.decode(decrypted_b64).unwrap()).unwrap();
        assert_eq!(plaintext, decrypted);

        // 4. List Keys
        let response = server
            .get("/keys")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        response.assert_status_ok();
        let list_res: ApiResponse<HashMap<String, Vec<String>>> = response.json();
        assert!(list_res.data.unwrap()["keys"].contains(&key_name.to_string()));

        // 5. Delete Key
        let response = server
            .delete(&format!("/keys/{}", key_name))
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        response.assert_status_ok();
    }
}
