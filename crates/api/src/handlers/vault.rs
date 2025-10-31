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
use base64;
use hex;

use crate::{
    handlers::AppState,
    services::vault,
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

/// Get secret by path
pub async fn get_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &path, "read").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Get secret from vault service
    let secret_data = state.services.vault.get_secret(&path, &user.id).await
        .map_err(|e| match e {
            vault::VaultError::SecretNotFound { .. } => crate::ApiError::NotFound("Secret not found".to_string()),
            vault::VaultError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to retrieve secret: {}", e)),
        })?;

    let response = SecretResponse {
        path: secret_data.path,
        data: secret_data.data,
        metadata: SecretMetadata {
            description: None, // TODO: Get from storage
            tags: vec![], // TODO: Get from storage
            owner: Some(user.username.clone()),
            classification: None, // TODO: Get from storage
        },
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: None, // TODO: Implement TTL
    };

    // Audit: SecretAccess
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SecretAccess {
                secret_path: path,
                user: user.username,
                action: "read".to_string(),
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Create new secret
pub async fn create_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &path, "create").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Create secret via vault service
    let secret_data = state.services.vault.put_secret(&path, request.data, &user.id).await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to create secret: {}", e)))?;

    let response = SecretResponse {
        path: secret_data.path,
        data: secret_data.data,
        metadata: request.metadata.unwrap_or_else(|| SecretMetadata {
            description: None,
            tags: vec![],
            owner: Some(user.username.clone()),
            classification: None,
        }),
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: request.ttl.map(|ttl| chrono::Utc::now() + chrono::Duration::seconds(ttl as i64)),
    };

    // Audit: SecretCreation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SecretCreation {
                secret_path: path,
                user: user.username,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Update existing secret
pub async fn update_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &path, "update").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Get current secret to determine version
    let current_secret = match state.services.vault.get_secret(&path, &user.id).await {
        Ok(secret) => secret,
        Err(vault::VaultError::SecretNotFound { .. }) => {
            return Err(crate::ApiError::NotFound("Secret not found".to_string()));
        }
        Err(e) => return Err(crate::ApiError::Internal(format!("Failed to retrieve current secret: {}", e))),
    };

    // Update secret via vault service
    let secret_data = state.services.vault.put_secret(&path, request.data, &user.id).await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to update secret: {}", e)))?;

    let response = SecretResponse {
        path: secret_data.path,
        data: secret_data.data,
        metadata: request.metadata.unwrap_or_else(|| SecretMetadata {
            description: None,
            tags: vec![],
            owner: Some(user.username.clone()),
            classification: None,
        }),
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: request.ttl.map(|ttl| chrono::Utc::now() + chrono::Duration::seconds(ttl as i64)),
    };

    // Audit: SecretVersionChange
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SecretVersionChange {
                secret_path: path,
                old_version: current_secret.version,
                new_version: secret_data.version,
                user: user.username,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Delete secret
pub async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &path, "delete").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Delete secret via vault service
    state.services.vault.delete_secret(&path, &user.id).await
        .map_err(|e| match e {
            vault::VaultError::SecretNotFound { .. } => crate::ApiError::NotFound("Secret not found".to_string()),
            vault::VaultError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to delete secret: {}", e)),
        })?;

    let data = serde_json::json!({
        "message": "Secret deleted successfully",
        "path": path.clone()
    });

    // Audit: SecretDeletion
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SecretDeletion {
                secret_path: path,
                user: user.username,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// List secrets
pub async fn list_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<SecretListItem>>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC) - allow listing with generic check
    if let Ok(false) = state.services.storage.check_policy(&user.username, "secrets:list", "read").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // List secrets via vault service
    let secret_paths = state.services.vault.list_secrets(query.filter.as_deref(), &user.id).await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to list secrets: {}", e)))?;

    // Convert to response format (placeholder - in production, get full metadata)
    let secrets: Vec<SecretListItem> = secret_paths.into_iter().map(|path| {
        SecretListItem {
            path,
            metadata: SecretMetadata {
                description: None, // TODO: Get from storage
                tags: vec![], // TODO: Get from storage
                owner: Some(user.username.clone()),
                classification: None, // TODO: Get from storage
            },
            version: 1, // TODO: Get actual version
            created_at: chrono::Utc::now(), // TODO: Get actual timestamp
            updated_at: chrono::Utc::now(), // TODO: Get actual timestamp
        }
    }).collect();

    Ok(Json(ApiResponse::success(secrets)))
}

/// Key operations
pub async fn create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, "keys", "create").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Create key via vault service
    let key_info = state.services.vault.create_key(&request.name, &request.key_type, &user.id).await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to create key: {}", e)))?;

    // Get public key if available (for asymmetric keys)
    let public_key = match request.key_type.as_str() {
        "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => {
            // For asymmetric keys, we would extract the public key
            // For now, return a placeholder
            Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string())
        }
        _ => None, // Symmetric keys don't have public keys
    };

    let response = KeyResponse {
        id: key_info.id,
        name: key_info.name,
        key_type: key_info.key_type,
        algorithm: request.algorithm,
        size: request.size.unwrap_or(256),
        usage: request.usage,
        metadata: request.metadata.unwrap_or_else(|| KeyMetadata {
            description: None,
            tags: vec![],
            owner: Some(user.username.clone()),
            purpose: None,
        }),
        version: key_info.version,
        created_at: key_info.created_at,
        status: "active".to_string(),
        public_key,
    };

    // Audit: KeyGeneration
    let _ = state
        .audit
        .log_event(
            SecurityEventType::KeyGeneration {
                key_type: key_info.key_type,
                key_id: key_info.id,
                algorithm: request.algorithm,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

pub async fn get_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &format!("keys/{}", key_id), "read").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Get key via vault service
    let key_info = state.services.vault.get_key(&key_id, &user.id).await
        .map_err(|e| match e {
            vault::VaultError::KeyNotFound { .. } => crate::ApiError::NotFound("Key not found".to_string()),
            vault::VaultError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to retrieve key: {}", e)),
        })?;

    // Get public key if available (for asymmetric keys)
    let public_key = match key_info.key_type.as_str() {
        "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => {
            // For asymmetric keys, we would extract the public key
            // For now, return a placeholder
            Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string())
        }
        _ => None, // Symmetric keys don't have public keys
    };

    let response = KeyResponse {
        id: key_info.id,
        name: key_info.name,
        key_type: key_info.key_type,
        algorithm: key_info.key_type.clone(), // Use key_type as algorithm for now
        size: 256, // Default size
        usage: vec!["encrypt".to_string(), "decrypt".to_string()], // Default usage
        metadata: KeyMetadata {
            description: None,
            tags: vec![],
            owner: Some(user.username.clone()),
            purpose: None,
        },
        version: key_info.version,
        created_at: key_info.created_at,
        status: "active".to_string(),
        public_key,
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<KeyResponse>>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, "keys", "read").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // List keys via vault service
    let key_infos = state.services.vault.list_keys(&user.id, query.filter.as_deref()).await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to list keys: {}", e)))?;

    // Convert to response format
    let keys: Vec<KeyResponse> = key_infos.into_iter().map(|key_info| {
        // Get public key if available (for asymmetric keys)
        let public_key = match key_info.key_type.as_str() {
            "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => {
                Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string())
            }
            _ => None,
        };

        KeyResponse {
            id: key_info.id,
            name: key_info.name,
            key_type: key_info.key_type,
            algorithm: key_info.key_type.clone(), // Use key_type as algorithm for now
            size: 256, // Default size
            usage: vec!["encrypt".to_string(), "decrypt".to_string()], // Default usage
            metadata: KeyMetadata {
                description: None,
                tags: vec![],
                owner: Some(user.username.clone()),
                purpose: None,
            },
            version: key_info.version,
            created_at: key_info.created_at,
            status: "active".to_string(),
            public_key,
        }
    }).collect();

    Ok(Json(ApiResponse::success(keys)))
}

pub async fn rotate_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &format!("keys/{}/rotate", key_id), "update").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Rotate key via vault service
    let key_info = state.services.vault.rotate_key(&key_id, &user.id).await
        .map_err(|e| match e {
            vault::VaultError::KeyNotFound { .. } => crate::ApiError::NotFound("Key not found".to_string()),
            vault::VaultError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to rotate key: {}", e)),
        })?;

    // Get public key if available (for asymmetric keys)
    let public_key = match key_info.key_type.as_str() {
        "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => {
            Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string())
        }
        _ => None,
    };

    let response = KeyResponse {
        id: key_info.id,
        name: key_info.name,
        key_type: key_info.key_type,
        algorithm: key_info.key_type.clone(), // Use key_type as algorithm for now
        size: 256, // Default size
        usage: vec!["encrypt".to_string(), "decrypt".to_string()], // Default usage
        metadata: KeyMetadata {
            description: None,
            tags: vec![],
            owner: Some(user.username.clone()),
            purpose: None,
        },
        version: key_info.version,
        created_at: key_info.created_at,
        status: "active".to_string(),
        public_key,
    };

    // Audit: KeyRotation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::KeyRotation {
                old_key_id: key_info.id.clone(),
                new_key_id: format!("{}_v{}", key_info.id, key_info.version),
                algorithm: key_info.key_type,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Cryptographic operations
pub async fn encrypt_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EncryptRequest>,
) -> ApiResult<Json<ApiResponse<EncryptResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &format!("keys/{}/encrypt", request.key_id), "create").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Decode plaintext from base64 if needed
    let plaintext = base64::decode(&request.plaintext)
        .unwrap_or_else(|_| request.plaintext.as_bytes().to_vec());

    // Encrypt data via vault service
    let encrypted_data = state.services.vault.encrypt(&request.key_id, &plaintext, &user.id).await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to encrypt data: {}", e)))?;

    // Encode ciphertext as base64
    let ciphertext_b64 = base64::encode(&encrypted_data.ciphertext);

    let response = EncryptResponse {
        ciphertext: ciphertext_b64,
        key_version: 1, // TODO: Get actual key version
        algorithm: request.algorithm.unwrap_or("AES-GCM".to_string()),
    };

    // Audit: EncryptionOperation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::EncryptionOperation {
                key_id: request.key_id,
                user: user.username,
                data_size: plaintext.len() as u64,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

pub async fn decrypt_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DecryptRequest>,
) -> ApiResult<Json<ApiResponse<DecryptResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &format!("keys/{}/decrypt", request.key_id), "create").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Decode ciphertext from base64
    let ciphertext = base64::decode(&request.ciphertext)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 ciphertext: {}", e)))?;

    // For now, create a placeholder EncryptedData structure
    // In a real implementation, the nonce and key_id would be stored/encoded with the ciphertext
    let encrypted_data = vault::EncryptedData {
        ciphertext,
        nonce: vec![0u8; 12], // Placeholder nonce
        key_id: format!("{}/{}", user.id, request.key_id),
    };

    // Decrypt data via vault service
    let plaintext = state.services.vault.decrypt(&request.key_id, &encrypted_data, &user.id).await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to decrypt data: {}", e)))?;

    // Encode plaintext as base64
    let plaintext_b64 = base64::encode(&plaintext);

    let response = DecryptResponse {
        plaintext: plaintext_b64,
        key_version: 1, // TODO: Get actual key version
    };

    // Audit: DecryptionOperation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::DecryptionOperation {
                key_id: request.key_id,
                user: user.username,
                data_size: plaintext.len() as u64,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

pub async fn sign_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> ApiResult<Json<ApiResponse<SignResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &format!("keys/{}/sign", request.key_id), "create").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Decode data from base64 if needed
    let data = base64::decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    // For now, create a simple HMAC signature using SHA-256
    // In a real implementation, this would use the actual key for proper signing
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Get a dummy key for HMAC (in production, get the actual key)
    let dummy_key = b"dummy_signing_key_for_development";
    let mut mac = Hmac::<Sha256>::new_from_slice(dummy_key)
        .map_err(|e| crate::ApiError::Internal(format!("Failed to create HMAC: {}", e)))?;

    mac.update(&data);
    let signature = mac.finalize().into_bytes();

    // Encode signature as base64
    let signature_b64 = base64::encode(&signature);

    let response = SignResponse {
        signature: signature_b64,
        key_version: 1, // TODO: Get actual key version
        algorithm: request.algorithm.unwrap_or("HMAC-SHA256".to_string()),
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn verify_signature(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<ApiResponse<VerifyResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC)
    if let Ok(false) = state.services.storage.check_policy(&user.username, &format!("keys/{}/verify", request.key_id), "read").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Decode data and signature from base64
    let data = base64::decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    let signature = base64::decode(&request.signature)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 signature: {}", e)))?;

    // For now, verify using the same HMAC approach
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let dummy_key = b"dummy_signing_key_for_development";
    let mut mac = Hmac::<Sha256>::new_from_slice(dummy_key)
        .map_err(|e| crate::ApiError::Internal(format!("Failed to create HMAC: {}", e)))?;

    mac.update(&data);
    let expected_signature = mac.finalize().into_bytes();

    let valid = signature == expected_signature.as_slice();

    let response = VerifyResponse {
        valid,
        key_version: 1, // TODO: Get actual key version
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn hash_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<HashRequest>,
) -> ApiResult<Json<ApiResponse<HashResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Check permissions (RBAC) - hashing is generally allowed
    if let Ok(false) = state.services.storage.check_policy(&user.username, "crypto:hash", "create").await {
        return Err(crate::ApiError::Authorization("Access denied".to_string()));
    }

    // Decode data from base64 if needed
    let data = base64::decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    // Compute hash based on algorithm
    let hash = match request.algorithm.as_str() {
        "SHA-256" | "sha256" => {
            use sha2::Sha256;
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hasher.finalize().to_vec()
        }
        "SHA-512" | "sha512" => {
            use sha2::Sha512;
            use sha2::Digest;
            let mut hasher = Sha512::new();
            hasher.update(&data);
            hasher.finalize().to_vec()
        }
        "SHA3-256" | "sha3-256" => {
            use sha3::Sha3_256;
            use sha3::Digest;
            let mut hasher = Sha3_256::new();
            hasher.update(&data);
            hasher.finalize().to_vec()
        }
        _ => {
            return Err(crate::ApiError::BadRequest(format!("Unsupported hash algorithm: {}", request.algorithm)));
        }
    };

    // Encode hash as hex
    let hash_hex = hex::encode(&hash);

    let response = HashResponse {
        hash: hash_hex,
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
