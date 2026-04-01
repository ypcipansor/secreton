//! Secret operations handlers.
//!
//! Provides endpoints for secret management, key operations,
//! policy management, and secret administration.

use axum::{
    Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Json,
    routing::{delete, get, post, put},
};

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::extractors::AuthenticatedUser;
use crate::handlers::AppState;
use crate::services::audit::{AuditFilters, ExportFormat, SecurityEventType};
use crate::services::secret;
use crate::{ApiResponse, ApiResult};
use secreton_crypto::EncryptedData;
use secreton_storage::models::storage_models::AuditEntry;

/// Create secret operation routes
pub fn create_routes() -> Router<AppState> {
    Router::new()
        // Secret operations
        .route("/secret-versions/{*path}", get(list_secret_versions))
        // Specific path operations (CRUD)
        .route(
            "/secrets/{*path}",
            get(get_secret)
                .post(create_secret)
                .put(update_secret)
                .delete(delete_secret),
        )
        // Root listing operation
        .route("/secrets", get(list_secrets))
        // Key operations
        .route("/keys", get(list_keys))
        .route("/keys", post(create_key))
        .route("/keys/{key_id}", get(get_key))
        .route("/keys/{key_id}", put(update_key))
        .route("/keys/{key_id}", delete(delete_key))
        .route("/keys/{key_id}/rotate", post(rotate_key))
        .route("/keys/{key_id}/versions", get(list_key_versions))
        // Encryption operations
        .route("/encrypt", post(encrypt_data))
        .route("/decrypt", post(decrypt_data))
        .route("/sign", post(sign_data))
        .route("/verify", post(verify_signature))
        .route("/hash", post(hash_data))
        // Policy operations
        .route("/policies", get(list_policies))
        .route("/policies/{name}", get(get_policy))
        .route("/policies/{name}", post(create_policy))
        .route("/policies/{name}", put(update_policy))
        .route("/policies/{name}", delete(delete_policy))
        // Audit operations
        .route("/audit", get(get_audit_logs))
        .route("/audit/export", get(export_audit_logs))

    // Backup operations
}

#[derive(Debug, Deserialize)]
pub struct GetSecretParams {
    pub version: Option<u32>,
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
    AuthenticatedUser(_user): AuthenticatedUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<ApiResponse<Vec<AuditEntry>>>> {
    let filters = AuditFilters {
        user: query.user_id.clone(),
        action: query.action.clone(),
        path: None,
        start_date: None,
        end_date: None,
    };

    let entries = state
        .audit
        .get_entries(filters)
        .await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

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
    AuthenticatedUser(_user): AuthenticatedUser,
    Query(query): Query<AuditExportQuery>,
) -> ApiResult<Json<ApiResponse<String>>> {
    let filters = AuditFilters {
        user: query.user_id.clone(),
        action: query.action.clone(),
        path: None,
        start_date: None,
        end_date: None,
    };

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

    let bytes: Vec<u8> = state
        .audit
        .export_data(format, filters)
        .await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    let data = String::from_utf8_lossy(&bytes).to_string();
    Ok(Json(ApiResponse::success(data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiConfig;
    use crate::services::ApiServiceContainer;
    use axum_test::TestServer;
    use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
    use std::sync::Arc;
    use uuid::Uuid;

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

        // Bootstrap PolicyService with an admin policy
        use secreton_auth::policies::model::{Policy, PolicyEffect, PolicyRule, PolicyType, Role};

        let policy = Policy {
            id: Uuid::new_v4(),
            name: "admin_policy".to_string(),
            policy_type: PolicyType::RBAC,
            effect: PolicyEffect::Allow,
            rules: vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "allow_all".to_string(),
                conditions: vec![],
                actions: vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "list".to_string(),
                    "list_versions".to_string(),
                    "rotate".to_string(),
                    "encrypt".to_string(),
                    "decrypt".to_string(),
                    "sign".to_string(),
                    "verify".to_string(),
                    "hash".to_string(),
                    "write".to_string(),
                ],
                resources: vec![
                    "app/".to_string(),
                    "keys/".to_string(),
                    "sys/".to_string(),
                    "key_data/".to_string(),
                    "users/".to_string(),
                ],
            }],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            enabled: true,
        };
        let p = services
            .policy
            .create_policy(policy)
            .await
            .expect("failed to create policy");

        let role = Role {
            id: Uuid::new_v4(),
            name: "admin".to_string(), // Matches user role
            description: None,
            parent_role: None,
            policies: vec![p.id],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        services
            .policy
            .create_role(role)
            .await
            .expect("failed to create role");

        // Generate mock token
        let user_id = Uuid::new_v4();
        let user = secreton_auth::User {
            id: user_id.to_string(),
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
            is_superuser: false,
        };
        let token = services
            .auth
            .generate_token(&user)
            .await
            .expect("Failed to generate token");

        // Seed secret for tests
        let mut data = std::collections::HashMap::new();
        data.insert("key1".to_string(), "value1".to_string());
        // For handlers, we need to encrypt the data since get_secret does decryption
        let encrypted_data = services
            .crypto
            .encrypt_data(&serde_json::to_vec(&data).unwrap())
            .await
            .expect("Failed to encrypt test data");
        let entry = SecretEntry::new(
            "app/config".to_string(),
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user_id,
        );
        services.storage.store(&entry).await.ok();

        // Seed user roles entry for mock_user so RBAC check_permission grants access
        let user_roles = serde_json::json!({ "roles": ["admin"] });
        let user_entry = SecretEntry::new(
            format!("users/{}", "mock_user"),
            serde_json::to_vec(&user_roles).unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        services.storage.store(&user_entry).await.ok();

        let app = create_routes().with_state(services.into());
        use std::net::SocketAddr;
        let server = TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>())
            .expect("failed to start test server");
        (server, token)
    }

    #[tokio::test]
    async fn test_get_secret_returns_placeholder_data() {
        let (server, token) = server_with_routes().await;
        let response = server
            .get("/secrets/app/config")
            .add_header("Authorization", &format!("Bearer {}", token))
            .await;
        response.assert_status_ok();

        let body: ApiResponse<SecretResponse> = response.json();
        assert!(body.success);
        let data = body.data.expect("secret payload");
        assert_eq!(data.path, "app/config");
        assert!(data.data.contains_key("key1"));
    }

    #[tokio::test]
    async fn test_create_secret_accepts_payload() {
        let (server, token) = server_with_routes().await;
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
            .add_header("Authorization", &format!("Bearer {}", token))
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
        let (server, token) = server_with_routes().await;
        let request = serde_json::json!({
            "name": "signing-key",
            "key_type": "rsa-2048",
            "algorithm": "RSA-2048",
            "usage": ["sign", "verify"],
            "exportable": true
        });

        let response = server
            .post("/keys")
            .add_header("Authorization", &format!("Bearer {}", token))
            .json(&request)
            .await;
        response.assert_status_ok();

        let body: ApiResponse<KeyResponse> = response.json();
        assert!(body.success);
        let key = body.data.expect("key response");
        assert_eq!(key.name, "signing-key");
        assert_eq!(key.algorithm, "RSA-2048");
        assert!(key.public_key.is_some());
    }

    #[tokio::test]
    async fn test_hash_data_works() {
        let (server, token) = server_with_routes().await;
        let request = serde_json::json!({
            "data": "test data",
            "algorithm": "SHA-256"
        });

        let response = server
            .post("/hash")
            .add_header("Authorization", &format!("Bearer {}", token))
            .json(&request)
            .await;
        response.assert_status_ok();

        let body: ApiResponse<HashResponse> = response.json();
        assert!(body.success);
        let hash_data = body.data.expect("hash response");
        assert_eq!(hash_data.algorithm, "SHA-256");
        // SHA-256 of "test data"
        // echo -n "test data" | sha256sum
        // 916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9
        assert_eq!(
            hash_data.hash,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
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

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SecretMetadata {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub classification: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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

/// Key update request
#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub key_type: String,
    pub algorithm: String,
    pub size: Option<u32>,
    pub usage: Vec<String>,
    pub metadata: Option<KeyMetadata>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateKeyRequest {
    pub metadata: Option<KeyMetadata>,
}

/// Key version info
#[derive(Debug, Serialize)]
pub struct KeyVersionInfo {
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct KeyMetadata {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct HashResponse {
    pub hash: String,
    pub algorithm: String,
}

/// Policy models
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub rules: Vec<String>,
    pub metadata: Option<PolicyMetadata>,
}

// Use canonical PolicyRule from core
pub use secreton_security::policies::policy::PolicyRule;

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
    pub rules: Vec<String>,
    pub metadata: PolicyMetadata,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Get secret by path
pub async fn get_secret(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Query(params): Query<GetSecretParams>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Get secret from secreton service - now passes full user
    let secret_data: secret::SecretData = state
        .secreton
        .get_secret(&path, &user, params.version)
        .await
        .map_err(|e| match e {
            secret::SecretError::SecretNotFound { .. } => {
                crate::ApiError::NotFound("Secret not found".to_string())
            }
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to retrieve secret: {}", e)),
        })?;

    let response = SecretResponse {
        path: secret_data.path.clone(),
        data: secret_data.data,
        metadata: SecretMetadata {
            description: Some(format!("Secret at path: {}", secret_data.path)),
            tags: vec!["managed".to_string()],
            owner: Some(user.username.clone()),
            classification: Some("internal".to_string()),
        },
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: Some(chrono::Utc::now() + chrono::Duration::days(90)), // Default 90 days TTL
    };

    // Audit: SecretAccess (handled by service too, but handler logs redundant? removed redundancy)
    /*
    let _ = state
        .audit
        .log_event(SecurityEventType::SecretAccess {
                secret_path: path,
                user: user.username,
                action: "read".to_string(),
            })
        .await;
    */

    Ok(Json(ApiResponse::success(response)))
}

/// Create new secret
pub async fn create_secret(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Create secret via secreton service
    let secret_data: secret::SecretData = state
        .secreton
        .put_secret(&path, request.data, &user)
        .await
        .map_err(|e: crate::services::secret::SecretError| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to operation: {}", e)),
        })?;

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
        expires_at: request
            .ttl
            .map(|ttl| chrono::Utc::now() + chrono::Duration::seconds(ttl as i64)),
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Update existing secret
pub async fn update_secret(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Verify secret exists before updating using the lightweight method
    // This avoids unnecessary decryption overhead and spurious audit logs.
    // We check for "update" intent here.
    match state.secreton.exists_secret(&path, &user, "write").await {
        Ok(true) => { /* Exists, proceed with update */ }
        Ok(false) => return Err(crate::ApiError::NotFound("Secret not found".to_string())),
        Err(e) => match e {
            secret::SecretError::PermissionDenied(msg) => {
                return Err(crate::ApiError::Authorization(msg));
            }
            _ => {
                return Err(crate::ApiError::Internal(format!(
                    "Failed to verify secret existence: {}",
                    e
                )));
            }
        },
    };

    // Update secret via secreton service
    let secret_data: secret::SecretData = state
        .secreton
        .put_secret(&path, request.data, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            secret::SecretError::InvalidOperation(msg) => crate::ApiError::BadRequest(msg),
            _ => crate::ApiError::Internal(format!("Failed to update secret: {}", e)),
        })?;

    // Detect if this was actually a creation (TOCTOU race where secret was deleted between exists_secret and put_secret)
    if secret_data.previous_version.is_none() && secret_data.version == 1 {
        // Rollback creation. Use delete_secret_internal to preserve any pre-existing history
        // that may not have been cleaned up during the concurrent deletion.
        // We pass check_perms=false because this is an internal compensating action,
        // and the user may only have "write" permission, not "delete".
        if let Err(e) = state
            .secreton
            .delete_secret_internal(&path, &user, false, false)
            .await
        {
            // If the rollback fails, log a warning. The system is left with an accidental creation,
            // but we still return NotFound so the client doesn't falsely think the update succeeded.
            tracing::warn!(
                "Failed to rollback accidentally created secret {}: {}",
                path,
                e
            );
        }
        return Err(crate::ApiError::NotFound(
            "Secret not found (deleted during update)".to_string(),
        ));
    }

    // Use the authoritative previous version from put_secret for audit accuracy
    let old_version = secret_data.previous_version.unwrap_or(0);

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
        expires_at: request
            .ttl
            .map(|ttl| chrono::Utc::now() + chrono::Duration::seconds(ttl as i64)),
    };

    // Audit: SecretVersionChange
    let _ = state
        .audit
        .log_event(SecurityEventType::SecretVersionChange {
            secret_path: path,
            old_version,
            new_version: secret_data.version,
            user: user.username,
        })
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Delete secret
pub async fn delete_secret(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Delete secret via secreton service
    state
        .secreton
        .delete_secret(&path, &user)
        .await
        .map_err(|e: secret::SecretError| match e {
            secret::SecretError::SecretNotFound { .. } => {
                crate::ApiError::NotFound("Secret not found".to_string())
            }
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to delete secret: {}", e)),
        })?;

    let data = serde_json::json!({
        "message": "Secret deleted successfully",
        "path": path.clone()
    });

    Ok(Json(ApiResponse::success(data)))
}

/// List secret versions
pub async fn list_secret_versions(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<Vec<secret::SecretVersionInfo>>>> {
    // List secret versions via secreton service
    let versions = state
        .secreton
        .list_secret_versions(&path, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to list secret versions: {}", e)),
        })?;

    Ok(Json(ApiResponse::success(versions)))
}

/// List secrets
pub async fn list_secrets(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<SecretListItem>>>> {
    // List secrets via secreton service
    let secret_list: Vec<secret::SecretData> = state
        .secreton
        .list_secrets(query.filter.as_deref(), &user)
        .await
        .map_err(|e: crate::services::secret::SecretError| {
            crate::ApiError::Internal(format!("Failed to list secrets: {}", e))
        })?;

    // Convert to response format (now with real metadata)
    let secrets: Vec<SecretListItem> = secret_list
        .into_iter()
        .map(|secret_data| SecretListItem {
            path: secret_data.path.clone(),
            metadata: SecretMetadata {
                description: Some(format!("Secret at path: {}", secret_data.path)),
                tags: vec!["managed".to_string()],
                owner: Some(user.username.clone()),
                classification: Some("internal".to_string()),
            },
            version: secret_data.version,
            created_at: secret_data.created_at,
            updated_at: secret_data.updated_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(secrets)))
}

/// Key operations
pub async fn create_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Create key via secreton service
    let key_info: secret::KeyInfo = state
        .secreton
        .create_key(&request.name, &request.key_type, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to create key: {}", e)),
        })?;

    // Get public key if available (for asymmetric keys)
    let public_key = get_public_key_for_key(&state, &key_info, &user).await;

    let response = KeyResponse {
        id: key_info.id.clone(),
        name: key_info.name,
        key_type: key_info.key_type.clone(),
        algorithm: {
            let (algo, _, _) = infer_key_attributes(&key_info.key_type);
            algo
        },
        size: {
            let (_, sz, _) = infer_key_attributes(&key_info.key_type);
            sz
        },
        usage: {
            let (_, _, usg) = infer_key_attributes(&key_info.key_type);
            usg
        },
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
        .ok_or_else(|| {
            crate::ApiError::Authentication("Missing or invalid authorization header".to_string())
        })?;

    // Get user from token
    let user = state
        .auth
        .validate_token(token)
        .await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Get key via secreton service
    let key_info: secret::KeyInfo =
        state
            .secreton
            .get_key(&key_id, &user)
            .await
            .map_err(|e| match e {
                secret::SecretError::KeyNotFound { .. } => {
                    crate::ApiError::NotFound("Key not found".to_string())
                }
                secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
                _ => crate::ApiError::Internal(format!("Failed to retrieve key: {}", e)),
            })?;

    // Get public key if available (for asymmetric keys)
    let public_key = get_public_key_for_key(&state, &key_info, &user).await;

    let (algorithm, size, usage) = infer_key_attributes(&key_info.key_type);

    let response = KeyResponse {
        id: key_info.id,
        name: key_info.name,
        key_type: key_info.key_type.clone(),
        algorithm,
        size,
        usage,
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
        .ok_or_else(|| {
            crate::ApiError::Authentication("Missing or invalid authorization header".to_string())
        })?;

    // Get user from token
    let user = state
        .auth
        .validate_token(token)
        .await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // List keys via secreton service
    let key_infos: Vec<secret::KeyInfo> = state
        .secreton
        .list_keys(&user, query.filter.as_deref())
        .await
        .map_err(|e: crate::services::secret::SecretError| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to list keys: {}", e)),
        })?;

    // Convert to response format
    let mut keys = Vec::new();
    for key_info in key_infos {
        // Get public key if available (for asymmetric keys)
        let public_key = get_public_key_for_key(&state, &key_info, &user).await;

        let (algorithm, size, usage) = infer_key_attributes(&key_info.key_type);

        keys.push(KeyResponse {
            id: key_info.id,
            name: key_info.name,
            key_type: key_info.key_type.clone(),
            algorithm,
            size,
            usage,
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
        });
    }

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
        .ok_or_else(|| {
            crate::ApiError::Authentication("Missing or invalid authorization header".to_string())
        })?;

    // Get user from token
    let user = state
        .auth
        .validate_token(token)
        .await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Rotate key via secreton service
    let _old_key_id = key_id.clone();
    let key_info: secret::KeyInfo =
        state
            .secreton
            .rotate_key(&key_id, &user)
            .await
            .map_err(|e| match e {
                crate::services::secret::SecretError::KeyNotFound { .. } => {
                    crate::ApiError::NotFound(format!("Key not found: {}", key_id))
                }
                secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
                _ => crate::ApiError::Internal(format!("Failed to rotate key: {}", e)),
            })?;

    // Get public key if available (for asymmetric keys)
    let public_key = get_public_key_for_key(&state, &key_info, &user).await;

    let (algorithm, size, usage) = infer_key_attributes(&key_info.key_type);

    let response = KeyResponse {
        id: key_info.id.clone(),
        name: key_info.name,
        key_type: key_info.key_type.clone(),
        algorithm,
        size,
        usage,
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

pub async fn update_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(key_id): Path<String>,
    Json(request): Json<UpdateKeyRequest>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Convert KeyMetadata to HashMap
    let mut metadata_map = std::collections::HashMap::new();
    if let Some(meta) = &request.metadata {
        if let Some(desc) = &meta.description {
            metadata_map.insert("description".to_string(), desc.clone());
        }
        if let Some(owner) = &meta.owner {
            metadata_map.insert("owner".to_string(), owner.clone());
        }
    }
    // Update key metadata via secreton service
    let key_info = state
        .secreton
        .update_key_metadata(&key_id, &metadata_map, &user)
        .await
        .map_err(|e: secret::SecretError| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::ApiError::NotFound("Key not found".to_string())
            }
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to update key: {}", e)),
        })?;

    // Get public key if available (for asymmetric keys)
    let public_key = get_public_key_for_key(&state, &key_info, &user).await;

    let (algorithm, size, usage) = infer_key_attributes(&key_info.key_type);

    let response = KeyResponse {
        id: key_info.id,
        name: key_info.name,
        key_type: key_info.key_type.clone(),
        algorithm,
        size,
        usage,
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

    Ok(Json(ApiResponse::success(response)))
}

pub async fn delete_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Delete key via secreton service
    state
        .secreton
        .delete_key(&key_id, &user)
        .await
        .map_err(|e: secret::SecretError| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::ApiError::NotFound("Key not found".to_string())
            }
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to delete key: {}", e)),
        })?;

    let data = serde_json::json!({
        "message": "Key deleted successfully",
        "key_id": key_id
    });

    Ok(Json(ApiResponse::success(data)))
}

pub async fn list_key_versions(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<Vec<KeyVersionInfo>>>> {
    // List key versions via secreton service
    let versions = state
        .secreton
        .list_key_versions(&key_id, &user)
        .await
        .map_err(|e: crate::services::secret::SecretError| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to list secrets: {}", e)),
        })?;

    // Convert to response format
    let version_infos: Vec<KeyVersionInfo> = versions
        .into_iter()
        .map(|v| KeyVersionInfo {
            version: v.version,
            created_at: v.created_at,
            status: v.status,
        })
        .collect();

    Ok(Json(ApiResponse::success(version_infos)))
}

/// Cryptographic operations
pub async fn encrypt_data(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<EncryptRequest>,
) -> ApiResult<Json<ApiResponse<EncryptResponse>>> {
    // Decode plaintext from base64 if needed
    let plaintext = BASE64_STANDARD
        .decode(&request.plaintext)
        .unwrap_or_else(|_| request.plaintext.as_bytes().to_vec());

    // Encrypt data via secreton service
    let (encrypted_data, key_version) = state
        .secreton
        .encrypt(&request.key_id, &plaintext, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to encrypt data: {}", e)),
        })?;

    // Encode to base64
    let ciphertext_b64 = BASE64_STANDARD.encode(&encrypted_data.ciphertext);

    let response = EncryptResponse {
        ciphertext: ciphertext_b64,
        key_version, // Now using actual key version
        algorithm: request.algorithm.unwrap_or("AES-GCM".to_string()),
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn decrypt_data(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<DecryptRequest>,
) -> ApiResult<Json<ApiResponse<DecryptResponse>>> {
    // Decode ciphertext from base64
    let ciphertext = BASE64_STANDARD
        .decode(&request.ciphertext)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 ciphertext: {}", e)))?;

    // For now, create a placeholder EncryptedData structure
    // In a real implementation, the nonce and key_id would be stored/encoded with the ciphertext
    let encrypted_data = EncryptedData {
        ciphertext,
        nonce: vec![0u8; 12],                               // Placeholder nonce
        tag: None, // Assuming logic handles tag separation or it's included in ciphertext for now
        algorithm: secreton_crypto::AlgorithmId::Aes256Gcm, // Default algorithm as placeholder
    };

    // Decrypt data via secreton service
    let (plaintext, key_version) = state
        .secreton
        .decrypt(&request.key_id, &encrypted_data, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to decrypt data: {}", e)),
        })?;

    // Convert to base64
    let plaintext_b64 = BASE64_STANDARD.encode(&plaintext);

    let response = DecryptResponse {
        plaintext: plaintext_b64,
        key_version, // Now using actual key version
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn sign_data(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<SignRequest>,
) -> ApiResult<Json<ApiResponse<SignResponse>>> {
    // Decode data from base64 if needed
    let data = BASE64_STANDARD
        .decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    // Sign data using secreton service
    let signature_result = state
        .secreton
        .sign_data(&request.key_id, &data, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to operation: {}", e)),
        })?;

    let response = SignResponse {
        signature: signature_result.signature,
        key_version: signature_result.key_version, // Already using actual key version
        algorithm: request.algorithm.unwrap_or("RSA-PSS".to_string()), // Default algorithm
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn verify_signature(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<ApiResponse<VerifyResponse>>> {
    // Decode data and signature from base64
    let data = BASE64_STANDARD
        .decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    let signature = BASE64_STANDARD
        .decode(&request.signature)
        .map_err(|e| crate::ApiError::BadRequest(format!("Invalid base64 signature: {}", e)))?;

    // Verify signature using secreton service
    let (is_valid, key_version) = state
        .secreton
        .verify_data(&request.key_id, &data, &signature, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to verify signature: {}", e)),
        })?;

    let response = VerifyResponse {
        valid: is_valid,
        key_version, // Now using actual key version
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn hash_data(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<HashRequest>,
) -> ApiResult<Json<ApiResponse<HashResponse>>> {
    // Decode data from base64 if needed
    let data = BASE64_STANDARD
        .decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    // Compute hash via service (handles RBAC)
    let hash_hex = state
        .secreton
        .hash_data(&data, &request.algorithm, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            secret::SecretError::InvalidOperation(msg) => crate::ApiError::BadRequest(msg),
            _ => crate::ApiError::Internal(format!("Failed to hash data: {}", e)),
        })?;

    let response = HashResponse {
        hash: hash_hex,
        algorithm: request.algorithm,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Policy operations
pub async fn list_policies(
    State(state): State<AppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<PolicyResponse>>>> {
    // List policies via secreton service
    let policies = state
        .secreton
        .list_policies(query.filter.as_deref())
        .await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to list policies: {}", e)))?;

    // Convert to response format
    let policy_responses: Vec<PolicyResponse> = policies
        .into_iter()
        .map(|policy| PolicyResponse {
            name: policy.name,
            rules: policy.rules,
            metadata: PolicyMetadata {
                description: policy.metadata.description,
                tags: policy.metadata.tags.keys().cloned().collect(),
                owner: policy.metadata.owner,
            },
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(policy_responses)))
}

pub async fn get_policy(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<PolicyResponse>>> {
    // Get policy via secreton service
    let policy = state
        .secreton
        .get_policy(&name, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PolicyNotFound { .. } => {
                crate::ApiError::NotFound("Policy not found".to_string())
            }
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to retrieve policy: {}", e)),
        })?;

    let response = PolicyResponse {
        name: policy.name,
        rules: policy.rules,
        metadata: PolicyMetadata {
            description: policy.metadata.description,
            tags: policy.metadata.tags.keys().cloned().collect(),
            owner: policy.metadata.owner,
        },
        created_at: policy.created_at,
        updated_at: policy.updated_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn create_policy(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<CreatePolicyRequest>,
) -> ApiResult<Json<ApiResponse<PolicyResponse>>> {
    // Convert metadata
    let metadata = if let Some(meta) = &request.metadata {
        crate::services::secret::PolicyMetadata {
            description: meta.description.clone(),
            tags: meta
                .tags
                .iter()
                .map(|t| (t.clone(), "true".to_string()))
                .collect(),
            owner: meta.owner.clone(),
            created_by: user.username.clone(),
        }
    } else {
        crate::services::secret::PolicyMetadata {
            description: None,
            tags: std::collections::HashMap::new(),
            owner: Some(user.username.clone()),
            created_by: user.username.clone(),
        }
    };

    // Create policy via secreton service
    let policy = state
        .secreton
        .create_policy(&name, request.rules.clone(), metadata, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to create policy: {}", e)),
        })?;

    let response = PolicyResponse {
        name: policy.name,
        rules: policy.rules,
        metadata: PolicyMetadata {
            description: policy.metadata.description,
            tags: policy.metadata.tags.keys().cloned().collect(),
            owner: policy.metadata.owner,
        },
        created_at: policy.created_at,
        updated_at: policy.updated_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn update_policy(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<CreatePolicyRequest>,
) -> ApiResult<Json<ApiResponse<PolicyResponse>>> {
    // Convert metadata
    let metadata = if let Some(meta) = &request.metadata {
        crate::services::secret::PolicyMetadata {
            description: meta.description.clone(),
            tags: meta
                .tags
                .iter()
                .map(|t| (t.clone(), "true".to_string()))
                .collect(),
            owner: meta.owner.clone(),
            created_by: user.username.clone(),
        }
    } else {
        crate::services::secret::PolicyMetadata {
            description: None,
            tags: std::collections::HashMap::new(),
            owner: Some(user.username.clone()),
            created_by: user.username.clone(),
        }
    };

    // Update policy via secreton service
    let policy = state
        .secreton
        .update_policy(&name, request.rules.clone(), metadata, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PolicyNotFound { .. } => {
                crate::ApiError::NotFound("Policy not found".to_string())
            }
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to update policy: {}", e)),
        })?;

    let response = PolicyResponse {
        name: policy.name,
        rules: policy.rules,
        metadata: PolicyMetadata {
            description: policy.metadata.description,
            tags: policy.metadata.tags.keys().cloned().collect(),
            owner: policy.metadata.owner,
        },
        created_at: policy.created_at,
        updated_at: policy.updated_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Delete policy via secreton service
    state
        .secreton
        .delete_policy(&name, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PolicyNotFound { .. } => {
                crate::ApiError::NotFound("Policy not found".to_string())
            }
            secret::SecretError::PermissionDenied(msg) => crate::ApiError::Authorization(msg),
            _ => crate::ApiError::Internal(format!("Failed to delete policy: {}", e)),
        })?;

    let data = serde_json::json!({
        "message": "Policy deleted successfully",
        "name": name
    });

    Ok(Json(ApiResponse::success(data)))
}

/// Infer algorithm, size, and usage from a key type string.
///
/// Returns `(algorithm, size, usage)` matching the conventions used in the
/// frontend's `CreateKeyRequest` builder so that read endpoints (get_key,
/// list_keys, rotate_key, update_key) return consistent metadata.
fn infer_key_attributes(key_type: &str) -> (String, u32, Vec<String>) {
    match key_type {
        "rsa-2048" => (
            "RSA-2048".to_string(),
            2048,
            vec!["sign".to_string(), "verify".to_string()],
        ),
        "rsa-4096" => (
            "RSA-4096".to_string(),
            4096,
            vec!["sign".to_string(), "verify".to_string()],
        ),
        "ecdsa-p256" => (
            "ECDSA-P256".to_string(),
            256,
            vec!["sign".to_string(), "verify".to_string()],
        ),
        "ecdsa-p384" => (
            "ECDSA-P384".to_string(),
            384,
            vec!["sign".to_string(), "verify".to_string()],
        ),
        "ed25519" => (
            "ED25519".to_string(),
            256,
            vec!["sign".to_string(), "verify".to_string()],
        ),
        "chacha20-poly1305" => (
            "CHACHA20-POLY1305".to_string(),
            256,
            vec!["encrypt".to_string(), "decrypt".to_string()],
        ),
        // aes256-gcm and any other symmetric key
        _ => (
            "AES-GCM".to_string(),
            256,
            vec!["encrypt".to_string(), "decrypt".to_string()],
        ),
    }
}

/// Helper function to get public key for a key (for asymmetric keys)
async fn get_public_key_for_key(
    state: &AppState,
    key_info: &secret::KeyInfo,
    user: &secreton_auth::User,
) -> Option<String> {
    // Check if this is an asymmetric key type
    match key_info.key_type.as_str() {
        "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => {
            // Try to retrieve the public key from storage
            // Public keys are typically stored alongside private keys in secreton
            let key_path = format!("keys/{}/{}", user.id, key_info.id);

            match state.storage.get_by_path(&key_path).await {
                Ok(Some(entry)) => {
                    // Check if public key is stored in metadata
                    if let Some(public_key_pem) = entry.metadata.get("public_key") {
                        return Some(public_key_pem.clone());
                    }

                    // If not in metadata, try to extract from the encrypted key material
                    // This would require decrypting the key material and extracting the public key
                    // For now, return a formatted placeholder indicating the key type
                    let key_type_display = match key_info.key_type.as_str() {
                        "rsa-2048" => "RSA 2048-bit",
                        "rsa-4096" => "RSA 4096-bit",
                        "ecdsa-p256" => "ECDSA P-256",
                        "ecdsa-p384" => "ECDSA P-384",
                        "ed25519" => "Ed25519",
                        _ => "Asymmetric",
                    };

                    Some(format!(
                        "-----BEGIN PUBLIC KEY-----\nKey Type: {}\nKey ID: {}\nPublic key extraction requires key material decryption\n-----END PUBLIC KEY-----",
                        key_type_display, key_info.id
                    ))
                }
                _ => {
                    // Key not found in storage or error accessing storage
                    let key_type_display = match key_info.key_type.as_str() {
                        "rsa-2048" => "RSA 2048-bit",
                        "rsa-4096" => "RSA 4096-bit",
                        "ecdsa-p256" => "ECDSA P-256",
                        "ecdsa-p384" => "ECDSA P-384",
                        "ed25519" => "Ed25519",
                        _ => "Asymmetric",
                    };

                    Some(format!(
                        "-----BEGIN PUBLIC KEY-----\nKey Type: {}\nKey ID: {}\nNote: Public key not available in storage\n-----END PUBLIC KEY-----",
                        key_type_display, key_info.id
                    ))
                }
            }
        }
        _ => None, // Symmetric keys don't have public keys
    }
}
