//! Vault operations handlers.
//! 
//! Provides endpoints for secret management, key operations,
//! policy management, and vault administration.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, post, put},
    Router,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    handlers::AppState,
    ApiResponse, ApiResult,
};
use brankas_core::audit::SecurityEventType;
use brankas_core::audit::{AuditFilters, ExportFormat};
use secreton_errors::SecretonError;

/// Create vault operation routes
pub fn create_routes() -> Router<AppState> {
    Router::new()
        // Secret operations
        .route("/secrets/:path", get(get_secret))
        .route("/secrets/:path", post(create_secret))
        .route("/secrets/:path", put(update_secret))
        .route("/secrets/:path", delete(delete_secret))
        .route("/secrets", get(list_secrets))
        
        // Key operations
        .route("/keys", get(list_keys))
        .route("/keys", post(create_key))
        .route("/keys/:key_id", get(get_key))
        .route("/keys/:key_id", put(update_key))
        .route("/keys/:key_id", delete(delete_key))
        .route("/keys/:key_id/rotate", post(rotate_key))
        .route("/keys/:key_id/versions", get(list_key_versions))
        
        // Encryption operations
        .route("/encrypt", post(encrypt_data))
        .route("/decrypt", post(decrypt_data))
        .route("/sign", post(sign_data))
        .route("/verify", post(verify_signature))
        .route("/hash", post(hash_data))
        
        // Policy operations
        .route("/policies", get(list_policies))
        .route("/policies/:name", get(get_policy))
        .route("/policies/:name", post(create_policy))
        .route("/policies/:name", put(update_policy))
        .route("/policies/:name", delete(delete_policy))
        
        // Audit operations
        .route("/audit", get(get_audit_logs))
        .route("/audit/export", get(export_audit_logs))
        
        // Backup operations
        .route("/backup", post(create_backup))
        .route("/backup", get(list_backups))
        .route("/backup/:backup_id", get(get_backup))
        .route("/backup/:backup_id/restore", post(restore_backup))
        .route("/backup/:backup_id", delete(delete_backup))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn get_audit_logs(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<ApiResponse<Vec<brankas_core::audit::AuditEntry>>>> {
    let mut builder = AuditFilters::builder();
    if let Some(user_id) = query.user_id.clone() {
        builder = builder.user_id(user_id);
    }
    if let Some(action) = query.action.clone() {
        builder = builder.action(action);
    }
    if let Some(limit) = query.limit {
        builder = builder.paginate(limit, query.offset.unwrap_or(0));
    }
    let filters = builder.build();

    let entries = state
        .audit
        .get_entries(filters)
        .await
        .map_err(|e| SecretonError::internal_error(e.to_string()))?;

    Ok(Json(ApiResponse::success(entries)))
}

#[derive(Debug, Deserialize)]
pub struct AuditExportQuery {
    pub format: Option<String>,
    pub user_id: Option<String>,
    pub action: Option<String>,
}

pub async fn export_audit_logs(
    State(state): State<AppState>,
    Query(query): Query<AuditExportQuery>,
) -> ApiResult<Json<ApiResponse<String>>> {
    let mut builder = AuditFilters::builder();
    if let Some(user_id) = query.user_id.clone() {
        builder = builder.user_id(user_id);
    }
    if let Some(action) = query.action.clone() {
        builder = builder.action(action);
    }
    let filters = builder.build();

    let format = match query
        .format
        .as_deref()
        .unwrap_or("JSON")
        .to_ascii_uppercase()
        .as_str()
    {
        "CSV" => ExportFormat::CSV,
        "XML" => ExportFormat::XML,
        "SIEM" => ExportFormat::SIEM,
        "CEF" => ExportFormat::CEF,
        "LEEF" => ExportFormat::LEEF,
        _ => ExportFormat::JSON,
    };

    let bytes = state
        .audit
        .export_data(format, filters)
        .await
        .map_err(|e| SecretonError::internal_error(e.to_string()))?;

    let data = String::from_utf8_lossy(&bytes).to_string();
    Ok(Json(ApiResponse::success(data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiConfig;
    use crate::services::ServiceContainer;
    use axum_test::TestServer;
    use std::sync::Arc;

    async fn server_with_routes() -> TestServer {
        let config = ApiConfig::default();
        let services = Arc::new(
            ServiceContainer::new(&config)
                .await
                .expect("Failed to create services"),
        );

        let app = create_routes().with_state(services);
        TestServer::new(app).expect("failed to start test server")
    }

    #[tokio::test]
    async fn test_get_secret_returns_placeholder_data() {
        let server = server_with_routes().await;
        let response = server.get("/secrets/app/config").await;
        response.assert_status_ok();

        let body: ApiResponse<SecretResponse> = response.json();
        assert!(body.success);
        let data = body.data.expect("secret payload");
        assert_eq!(data.path, "app/config");
        assert!(data.data.contains_key("key1"));
    }

    #[tokio::test]
    async fn test_create_secret_accepts_payload() {
        let server = server_with_routes().await;
        let payload = serde_json::json!({
            "data": {"username": "admin"},
            "metadata": {
                "description": "Admin credentials",
                "tags": ["auth"],
                "owner": "security",
                "classification": "secret"
            },
            "ttl": 90
        });

        let response = server
            .post("/secrets/app/admin")
            .json(&payload)
            .await;
        response.assert_status_ok();

        let body: ApiResponse<SecretResponse> = response.json();
        assert!(body.success);
        let secret = body.data.expect("secret response");
        assert_eq!(secret.path, "app/admin");
        assert!(secret.expires_at.is_some());
    }

    #[tokio::test]
    async fn test_create_key_returns_public_key() {
        let server = server_with_routes().await;
        let request = serde_json::json!({
            "name": "signing-key",
            "key_type": "Ed25519",
            "algorithm": "Ed25519",
            "usage": ["sign", "verify"],
            "exportable": true
        });

        let response = server.post("/keys").json(&request).await;
        response.assert_status_ok();

        let body: ApiResponse<KeyResponse> = response.json();
        assert!(body.success);
        let key = body.data.expect("key response");
        assert_eq!(key.name, "signing-key");
        assert_eq!(key.algorithm, "Ed25519");
        assert!(key.public_key.is_some());
    }
}

/// Query parameters for listing operations
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort: Option<String>,
    pub filter: Option<String>,
}

/// Secret request/response models
#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub data: HashMap<String, String>,
    pub metadata: Option<SecretMetadata>,
    pub ttl: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub classification: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub path: String,
    pub data: HashMap<String, String>,
    pub metadata: SecretMetadata,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct SecretListItem {
    pub path: String,
    pub metadata: SecretMetadata,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Key request/response models
#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub key_type: String,
    pub algorithm: String,
    pub size: Option<u32>,
    pub usage: Vec<String>,
    pub metadata: Option<KeyMetadata>,
    pub exportable: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub algorithm: String,
    pub size: u32,
    pub usage: Vec<String>,
    pub metadata: KeyMetadata,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
    pub public_key: Option<String>,
}

/// Cryptographic operation models
#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub key_id: String,
    pub plaintext: String,
    pub context: Option<HashMap<String, String>>,
    pub algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
    pub key_version: u32,
    pub algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub key_id: String,
    pub ciphertext: String,
    pub context: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    pub plaintext: String,
    pub key_version: u32,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub key_id: String,
    pub data: String,
    pub algorithm: Option<String>,
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub signature: String,
    pub key_version: u32,
    pub algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub key_id: String,
    pub data: String,
    pub signature: String,
    pub algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub key_version: u32,
}

#[derive(Debug, Deserialize)]
pub struct HashRequest {
    pub data: String,
    pub algorithm: String,
}

#[derive(Debug, Serialize)]
pub struct HashResponse {
    pub hash: String,
    pub algorithm: String,
}

/// Policy models
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub metadata: Option<PolicyMetadata>,
}

// Use canonical PolicyRule from core
pub use secreton_core::models::PolicyRule;

// API-specific extension if capabilities needed
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiPolicyRule {
    pub path: String,
    pub capabilities: Vec<String>,
    pub conditions: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub owner: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub metadata: PolicyMetadata,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Secret operations
pub async fn get_secret(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // RBAC check (placeholder user)
    if let Ok(false) = state.storage.check_policy("unknown", &path, "read").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement secret retrieval
    let secret = SecretResponse {
        path: path.clone(),
        data: {
            let mut data = HashMap::new();
            data.insert("key1".to_string(), "value1".to_string());
            data.insert("key2".to_string(), "value2".to_string());
            data
        },
        metadata: SecretMetadata {
            description: Some("Example secret".to_string()),
            tags: vec!["example".to_string()],
            owner: Some("user".to_string()),
            classification: Some("confidential".to_string()),
        },
        version: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: None,
    };

    Ok(Json(ApiResponse::success(secret)))
}

pub async fn create_secret(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // RBAC check (placeholder user)
    if let Ok(false) = state.storage.check_policy("unknown", &path, "create").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement secret creation
    let secret = SecretResponse {
        path: path.clone(),
        data: request.data,
        metadata: request.metadata.unwrap_or_default(),
        version: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        expires_at: request.ttl.map(|ttl| chrono::Utc::now() + chrono::Duration::seconds(ttl as i64)),
    };

    // Audit: SecretCreation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SecretCreation {
                secret_path: path.clone(),
                user: "unknown".to_string(),
            },
            None,
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(secret)))
}

pub async fn update_secret(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // RBAC check (placeholder user)
    if let Ok(false) = state.storage.check_policy("unknown", &path, "update").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement secret update
    let secret = SecretResponse {
        path: path.clone(),
        data: request.data,
        metadata: request.metadata.unwrap_or_default(),
        version: 2,
        created_at: chrono::Utc::now() - chrono::Duration::hours(1),
        updated_at: chrono::Utc::now(),
        expires_at: request.ttl.map(|ttl| chrono::Utc::now() + chrono::Duration::seconds(ttl as i64)),
    };

    // Audit: SecretVersionChange
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SecretVersionChange {
                secret_path: path.clone(),
                old_version: 1,
                new_version: 2,
                user: "unknown".to_string(),
            },
            None,
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(secret)))
}

pub async fn delete_secret(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // RBAC check (placeholder user)
    if let Ok(false) = state.storage.check_policy("unknown", &path, "delete").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement secret deletion
    let data = serde_json::json!({
        "message": "Secret deleted successfully",
        "path": path
    });

    // Audit: SecretDeletion
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SecretDeletion {
                secret_path: path.clone(),
                user: "unknown".to_string(),
            },
            None,
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(data)))
}

pub async fn list_secrets(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<SecretListItem>>>> {
    // RBAC check could be resource-specific; allow listing with generic check
    if let Ok(false) = state.storage.check_policy("unknown", "secrets:list", "read").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement secret listing
    let secrets = vec![
        SecretListItem {
            path: "app/database".to_string(),
            metadata: SecretMetadata {
                description: Some("Database credentials".to_string()),
                tags: vec!["database".to_string()],
                owner: Some("admin".to_string()),
                classification: Some("sensitive".to_string()),
            },
            version: 3,
            created_at: chrono::Utc::now() - chrono::Duration::days(7),
            updated_at: chrono::Utc::now() - chrono::Duration::hours(2),
        },
    ];

    Ok(Json(ApiResponse::success(secrets)))
}

/// Key operations
pub async fn create_key(
    State(state): State<AppState>,
    Json(request): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // RBAC check
    if let Ok(false) = state.storage.check_policy("unknown", "keys", "create").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement key creation
    let key = KeyResponse {
        id: uuid::Uuid::new_v4().to_string(),
        name: request.name,
        key_type: request.key_type,
        algorithm: request.algorithm,
        size: request.size.unwrap_or(256),
        usage: request.usage,
        metadata: request.metadata.unwrap_or_default(),
        version: 1,
        created_at: chrono::Utc::now(),
        status: "active".to_string(),
        public_key: Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string()),
    };

    // Audit: KeyGeneration
    let _ = state
        .audit
        .log_event(
            SecurityEventType::KeyGeneration {
                key_type: key.key_type.clone(),
                key_id: key.id.clone(),
                algorithm: key.algorithm.clone(),
            },
            None,
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(key)))
}

pub async fn get_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // RBAC check
    if let Ok(false) = state.storage.check_policy("unknown", &format!("keys/{}", key_id), "read").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement key retrieval
    let key = KeyResponse {
        id: key_id,
        name: "example-key".to_string(),
        key_type: "Ed25519".to_string(), // Changed from RSA to Ed25519 for security
        algorithm: "Ed25519".to_string(), // Changed from RS256 to Ed25519
        size: 256, // Ed25519 key size
        usage: vec!["sign".to_string(), "verify".to_string()],
        metadata: KeyMetadata::default(),
        version: 1,
        created_at: chrono::Utc::now(),
        status: "active".to_string(),
        public_key: Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string()),
    };

    Ok(Json(ApiResponse::success(key)))
}

pub async fn list_keys(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<KeyResponse>>>> {
    if let Ok(false) = state.storage.check_policy("unknown", "keys", "read").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement key listing
    let keys = vec![
        KeyResponse {
            id: "key-1".to_string(),
            name: "signing-key".to_string(),
            key_type: "Ed25519".to_string(), // Changed from RSA to Ed25519
            algorithm: "Ed25519".to_string(), // Changed from RS256 to Ed25519
            size: 256, // Ed25519 key size
            usage: vec!["sign".to_string()],
            metadata: KeyMetadata::default(),
            version: 1,
            created_at: chrono::Utc::now(),
            status: "active".to_string(),
            public_key: None,
        },
    ];

    Ok(Json(ApiResponse::success(keys)))
}

pub async fn rotate_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // RBAC check
    if let Ok(false) = state.storage.check_policy("unknown", &format!("keys/{}/rotate", key_id), "update").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement key rotation
    let key = KeyResponse {
        id: key_id,
        name: "example-key".to_string(),
        key_type: "Ed25519".to_string(), // Changed from RSA to Ed25519
        algorithm: "Ed25519".to_string(), // Changed from RS256 to Ed25519
        size: 256, // Ed25519 key size
        usage: vec!["sign".to_string(), "verify".to_string()],
        metadata: KeyMetadata::default(),
        version: 2, // Incremented version
        created_at: chrono::Utc::now(),
        status: "active".to_string(),
        public_key: Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string()),
    };

    // Audit: KeyRotation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::KeyRotation {
                old_key_id: key_id.clone(),
                new_key_id: key.id.clone(),
                algorithm: key.algorithm.clone(),
            },
            None,
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(key)))
}

/// Cryptographic operations
pub async fn encrypt_data(
    State(state): State<AppState>,
    Json(request): Json<EncryptRequest>,
) -> ApiResult<Json<ApiResponse<EncryptResponse>>> {
    // RBAC check
    if let Ok(false) = state.storage.check_policy("unknown", &format!("keys/{}/encrypt", request.key_id), "create").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement encryption
    let response = EncryptResponse {
        ciphertext: "encrypted_data_base64".to_string(),
        key_version: 1,
        algorithm: request.algorithm.unwrap_or("AES-GCM".to_string()),
    };

    // Audit: EncryptionOperation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::EncryptionOperation {
                key_id: request.key_id.clone(),
                user: "unknown".to_string(),
                data_size: request.plaintext.len() as u64,
            },
            None,
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

pub async fn decrypt_data(
    State(state): State<AppState>,
    Json(request): Json<DecryptRequest>,
) -> ApiResult<Json<ApiResponse<DecryptResponse>>> {
    // RBAC check
    if let Ok(false) = state.storage.check_policy("unknown", &format!("keys/{}/decrypt", request.key_id), "create").await {
        return Err(SecretonError::authz_error("Access denied"));
    }
    // TODO: Implement decryption
    let response = DecryptResponse {
        plaintext: "decrypted_data".to_string(),
        key_version: 1,
    };

    // Audit: DecryptionOperation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::DecryptionOperation {
                key_id: request.key_id.clone(),
                user: "unknown".to_string(),
                data_size: request.ciphertext.len() as u64,
            },
            None,
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

pub async fn sign_data(
    State(_state): State<AppState>,
    Json(request): Json<SignRequest>,
) -> ApiResult<Json<ApiResponse<SignResponse>>> {
    // TODO: Implement signing
    let response = SignResponse {
        signature: "signature_base64".to_string(),
        key_version: 1,
        algorithm: request.algorithm.unwrap_or("RS256".to_string()),
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn verify_signature(
    State(_state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<ApiResponse<VerifyResponse>>> {
    // TODO: Implement signature verification
    let response = VerifyResponse {
        valid: true,
        key_version: 1,
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn hash_data(
    State(_state): State<AppState>,
    Json(request): Json<HashRequest>,
) -> ApiResult<Json<ApiResponse<HashResponse>>> {
    // TODO: Implement hashing
    let response = HashResponse {
        hash: "hash_hex".to_string(),
        algorithm: request.algorithm,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Default implementations for metadata
impl Default for SecretMetadata {
    fn default() -> Self {
        Self {
            description: None,
            tags: vec![],
            owner: None,
            classification: None,
        }
    }
}

impl Default for KeyMetadata {
    fn default() -> Self {
        Self {
            description: None,
            tags: vec![],
            owner: None,
            purpose: None,
        }
    }
}
