//! Secret operations handlers.
//!
//! Provides endpoints for secret management, key operations,
//! policy management, and secret administration.

use secreton_domain::SecretonError;
use secreton_engines::Services;

use axum::{
    Router,
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post, put},
};

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::ApiResult;
use crate::extractors::AuthenticatedUser;
use crate::handlers::AppState;
use secreton_crypto::EncryptedData;
use secreton_domain::ApiResponse;
use secreton_engines::services::audit::{AuditFilters, ExportFormat, SecurityEventType};
use secreton_engines::services::secret;

/// Create secret operation routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Secret operations
        .route("/secret-versions/{*path}", get(list_secret_versions))
        .route("/secret-rollback/{*path}", post(rollback_secret))
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
    State(state): State<Services>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<ApiResponse<Vec<serde_json::Value>>>> {
    let filters = AuditFilters {
        user: query.user_id.clone(),
        action: query.action.clone(),
        path: None,
        start_date: None,
        end_date: None,
        limit: None,
    };

    let entries = state.audit.get_entries(filters).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;

    // Convert entries to clean JSON values with the original username.
    let mut clean_entries: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|rich| {
            let e = rich.entry;
            serde_json::json!({
                "id": e.id.to_string(),
                "timestamp": e.timestamp,
                "user": rich.original_user,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "details": e.details,
                "ip_address": e.ip_address,
                "user_agent": e.user_agent,
                "success": e.success,
                "error_message": e.error_message,
            })
        })
        .collect();

    // Apply offset and limit
    if let Some(offset) = query.offset {
        let offset = offset as usize;
        if offset < clean_entries.len() {
            clean_entries = clean_entries.split_off(offset);
        } else {
            clean_entries.clear();
        }
    }
    if let Some(limit) = query.limit {
        clean_entries.truncate(limit as usize);
    }

    Ok(Json(ApiResponse::success(clean_entries)))
}

#[derive(Debug, Deserialize)]
pub struct AuditExportQuery {
    pub format: Option<String>,
    pub user_id: Option<String>,
    pub action: Option<String>,
}

pub async fn export_audit_logs(
    State(state): State<Services>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Query(query): Query<AuditExportQuery>,
) -> ApiResult<Json<ApiResponse<String>>> {
    let filters = AuditFilters {
        user: query.user_id.clone(),
        action: query.action.clone(),
        path: None,
        start_date: None,
        end_date: None,
        limit: None,
    };

    let format_str = query
        .format
        .as_deref()
        .unwrap_or("JSON")
        .to_ascii_uppercase();
    let format = match format_str.as_str() {
        "CSV" => ExportFormat::CSV,
        "JSON" => ExportFormat::JSON,
        other => {
            return Err(crate::error::ApiError(SecretonError::Validation {
                message: format!(
                    "Unsupported export format: {}. Supported formats: JSON, CSV",
                    other
                ),
            }));
        }
    };

    let bytes: Vec<u8> = state
        .audit
        .export_data(format, filters)
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Internal {
                message: e.to_string(),
            })
        })?;

    let data = String::from_utf8_lossy(&bytes).to_string();
    Ok(Json(ApiResponse::success(data)))
}

/// Query parameters accepted by the list endpoints.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort: Option<String>,
    pub filter: Option<String>,
}

use secreton_engines::services::secret::SecretMetadata;

/// Secret request/response models
#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub data: HashMap<String, String>,
    pub metadata: Option<SecretMetadata>,
    pub ttl: Option<u64>,
    /// Explicitly clear any existing `expires_at` on the stored secret,
    /// making it non-expiring.  Must be combined with `ttl: None`; sending
    /// `clear_ttl: true` with a `ttl: Some(_)` is a contradiction and is
    /// rejected with a 400.  Provides a REST-level escape hatch from the
    /// TTL carry-forward semantics documented on
    /// `SecretService::put_secret`, so users do not need to delete and
    /// recreate a secret just to drop its expiration.
    #[serde(default)]
    pub clear_ttl: bool,
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
    /// Key version to encrypt with. If omitted, the latest version is used.
    pub key_version: Option<u32>,
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
    /// Key version used during encryption. If omitted, the latest version is used.
    pub key_version: Option<u32>,
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
    /// Key version used during signing. If omitted, the latest version is used.
    pub key_version: Option<u32>,
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
    /// Key version used during signing. If omitted, the latest version is used.
    pub key_version: Option<u32>,
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
    /// Policy name.  Both `create_policy` and `update_policy` take the
    /// authoritative name from the URL path parameter, so this field is
    /// effectively ignored.  It is kept for backward compatibility with
    /// clients that include it in the request body.
    #[serde(default)]
    pub name: String,
    pub rules: Vec<String>,
    pub metadata: Option<PolicyMetadata>,
}

// Use canonical PolicyRule from core
pub use secreton_auth::policies::model::PolicyRule;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub name: String,
    pub rules: Vec<String>,
    pub metadata: PolicyMetadata,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Response discriminator: `"structured"` (rules-based) or `"raw"`
    /// (opaque content).  Added to preserve backward compatibility for
    /// strongly-typed clients while supporting dual-mode policies.
    #[serde(rename = "type", default = "default_policy_type")]
    pub policy_type: String,
    /// Raw policy content — only populated when `policy_type == "raw"`.
    /// `None` (and omitted from JSON) for structured policies, so existing
    /// clients that deserialize structured responses keep working unchanged.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content: Option<String>,
}

fn default_policy_type() -> String {
    "structured".to_string()
}

/// Strongly-typed request body for `PUT /policies/{name}`.
///
/// `update_policy` supports two distinct request shapes:
///   - **Structured**: `{ "rules": [...], "metadata": {...} }` — full
///     RBAC-style policy with rule strings.
///   - **Raw**: `{ "content": "..." }` — opaque policy content (HCL/text)
///     stored under `sys/policies/content/{name}` for admin UI management.
///
/// Dispatch is based on the **presence** of the `rules` key rather than on
/// whether the `Structured` variant happens to deserialize successfully.
/// A prior implementation used `#[serde(untagged)]` which silently fell
/// through to `Raw` whenever `Structured` failed for *any* reason — e.g.
/// `{"rules": "not-an-array", "content": "..."}` would be reinterpreted
/// as a raw-content update, silently overwriting a structured policy
/// with the request's `content` field as raw HCL.  The custom
/// `Deserialize` impl below surfaces structured-shape errors instead of
/// masking them, so malformed `rules`/`metadata` produce a 400 error.
#[derive(Debug)]
pub enum UpdatePolicyRequest {
    /// Structured update with rules.  Selected when the request body
    /// contains a `rules` key (regardless of whether the value is a
    /// valid `Vec<String>` — malformed rules surface as errors instead
    /// of falling through to `Raw`).
    Structured {
        /// Policy name — ignored; the authoritative name comes from the URL
        /// path.  Kept for backward compatibility with clients that include
        /// it in the body.
        name: Option<String>,
        rules: Vec<String>,
        metadata: Option<PolicyMetadata>,
        /// Accepted and ignored when `rules` is present.  Captured here so
        /// the handler can detect `{rules: [], content: "..."}` and reject
        /// it rather than silently wiping the raw content.
        content: Option<String>,
    },
    /// Raw-content update (admin-only).  Selected when the request body
    /// does not contain a `rules` key but does contain a `content` key.
    Raw { content: String },
}

impl<'de> Deserialize<'de> for UpdatePolicyRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Buffer the input as a `serde_json::Value` so we can peek at the
        // object keys before committing to a variant.  This is an
        // acceptable cost for an admin-only endpoint and avoids the
        // silent-fallthrough pitfall of `#[serde(untagged)]`.
        let v = serde_json::Value::deserialize(deserializer)?;
        let obj = v.as_object().ok_or_else(|| {
            serde::de::Error::custom(
                "UpdatePolicyRequest: expected a JSON object with either 'rules' or 'content'",
            )
        })?;

        if obj.contains_key("rules") {
            // Commit to the Structured variant — surface any deserialization
            // errors (e.g. `rules` not an array, malformed `metadata`)
            // rather than falling through to `Raw`.
            #[derive(Deserialize)]
            struct StructuredHelper {
                #[serde(default)]
                name: Option<String>,
                rules: Vec<String>,
                #[serde(default)]
                metadata: Option<PolicyMetadata>,
                #[serde(default)]
                content: Option<String>,
            }
            let s =
                serde_json::from_value::<StructuredHelper>(v).map_err(serde::de::Error::custom)?;
            Ok(UpdatePolicyRequest::Structured {
                name: s.name,
                rules: s.rules,
                metadata: s.metadata,
                content: s.content,
            })
        } else if obj.contains_key("content") {
            #[derive(Deserialize)]
            struct RawHelper {
                content: String,
            }
            let r = serde_json::from_value::<RawHelper>(v).map_err(serde::de::Error::custom)?;
            Ok(UpdatePolicyRequest::Raw { content: r.content })
        } else {
            Err(serde::de::Error::custom(
                "UpdatePolicyRequest: request body must contain either 'rules' \
                 (structured update) or 'content' (raw update)",
            ))
        }
    }
}

/// Get secret by path
pub async fn get_secret(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Query(params): Query<GetSecretParams>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Get secret from secreton service - now passes full user
    let secret_data: secret::SecretData = state
        .secret
        .get_secret(&path, &user, params.version)
        .await
        .map_err(|e| match e {
            secret::SecretError::SecretNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Secret not found".to_string(),
                })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to retrieve secret: {}", e),
            }),
        })?;

    let response = SecretResponse {
        path: secret_data.path.clone(),
        data: secret_data.data,
        metadata: secret_data.metadata,
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: secret_data.expires_at,
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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Reject contradictory TTL flags.  `clear_ttl: true` means "drop any
    // existing expiration" and only makes sense when `ttl` is unset.
    if request.clear_ttl && request.ttl.is_some() {
        return Err(crate::error::ApiError(SecretonError::Validation {
            message: "`clear_ttl: true` cannot be combined with a non-null `ttl`; \
             omit `ttl` to clear, or omit `clear_ttl` to set a fresh TTL"
                .to_string(),
        }));
    }

    // Dispatch on `clear_ttl`: when set, route through `put_secret_internal`
    // with `expires_at_override = Some(None)` so the carry-forward branch is
    // bypassed and the new entry has no `expires_at`.  Otherwise use the
    // public `put_secret` path which honours the carry-forward semantics
    // documented on `SecretService::put_secret`.
    let secret_data: secret::SecretData = if request.clear_ttl {
        state
            .secret
            .put_secret_internal(
                &path,
                request.data,
                request.metadata,
                &user,
                None,
                Some(None),
            )
            .await
    } else {
        state
            .secret
            .put_secret(&path, request.data, request.metadata, &user, request.ttl)
            .await
    }
    .map_err(
        |e: secreton_engines::services::secret::SecretError| match e {
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to create secret: {}", e),
            }),
        },
    )?;

    let response = SecretResponse {
        path: secret_data.path,
        data: secret_data.data,
        metadata: secret_data.metadata,
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: secret_data.expires_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Update existing secret
pub async fn update_secret(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Json(request): Json<CreateSecretRequest>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    // Verify secret exists before updating using the lightweight method
    // This avoids unnecessary decryption overhead and spurious audit logs.
    // We check for "update" intent here.
    match state.secret.exists_secret(&path, &user, "write").await {
        Ok(true) => { /* Exists, proceed with update */ }
        Ok(false) => {
            return Err(crate::error::ApiError(SecretonError::NotFound {
                resource: "Secret not found".to_string(),
            }));
        }
        Err(e) => match e {
            secret::SecretError::PermissionDenied(msg) => {
                return Err(crate::error::ApiError(SecretonError::Authorization {
                    message: msg,
                }));
            }
            _ => {
                return Err(crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to verify secret existence: {}", e),
                }));
            }
        },
    };

    // Reject contradictory TTL flags (mirrors `create_secret` validation).
    if request.clear_ttl && request.ttl.is_some() {
        return Err(crate::error::ApiError(SecretonError::Validation {
            message: "`clear_ttl: true` cannot be combined with a non-null `ttl`; \
             omit `ttl` to clear, or omit `clear_ttl` to set a fresh TTL"
                .to_string(),
        }));
    }

    // Dispatch on `clear_ttl`: when set, route through `put_secret_internal`
    // with `expires_at_override = Some(None)` to bypass the carry-forward
    // branch and produce a non-expiring new version.  Otherwise use the
    // public `put_secret` path.
    let secret_data: secret::SecretData = if request.clear_ttl {
        state
            .secret
            .put_secret_internal(
                &path,
                request.data,
                request.metadata,
                &user,
                None,
                Some(None),
            )
            .await
    } else {
        state
            .secret
            .put_secret(&path, request.data, request.metadata, &user, request.ttl)
            .await
    }
    .map_err(|e| match e {
        secret::SecretError::PermissionDenied(msg) => {
            crate::error::ApiError(SecretonError::Authorization { message: msg })
        }
        secret::SecretError::InvalidOperation(msg) => {
            crate::error::ApiError(SecretonError::Validation { message: msg })
        }
        _ => crate::error::ApiError(SecretonError::Internal {
            message: format!("Failed to update secret: {}", e),
        }),
    })?;

    // Detect if this was actually a creation (TOCTOU race where secret was deleted between exists_secret and put_secret)
    if secret_data.previous_version.is_none() && secret_data.version == 1 {
        // Rollback creation. Use delete_secret_internal to preserve any pre-existing history
        // that may not have been cleaned up during the concurrent deletion.
        // We pass check_perms=false because this is an internal compensating action,
        // and the user may only have "write" permission, not "delete".
        if let Err(e) = state
            .secret
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
        return Err(crate::error::ApiError(SecretonError::NotFound {
            resource: "Secret not found (deleted during update)".to_string(),
        }));
    }

    // Use the authoritative previous version from put_secret for audit accuracy
    let old_version = secret_data.previous_version.unwrap_or(0);

    let response = SecretResponse {
        path: secret_data.path,
        data: secret_data.data,
        metadata: secret_data.metadata,
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: secret_data.expires_at,
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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Delete secret via secreton service
    state
        .secret
        .delete_secret(&path, &user)
        .await
        .map_err(|e: secret::SecretError| match e {
            secret::SecretError::SecretNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Secret not found".to_string(),
                })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to delete secret: {}", e),
            }),
        })?;

    let data = serde_json::json!({
        "message": "Secret deleted successfully",
        "path": path.clone()
    });

    Ok(Json(ApiResponse::success(data)))
}

/// List secret versions
pub async fn list_secret_versions(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
) -> ApiResult<Json<ApiResponse<Vec<secret::SecretVersionInfo>>>> {
    // List secret versions via secreton service
    let versions = state
        .secret
        .list_secret_versions(&path, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::SecretNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Secret not found".to_string(),
                })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to list secret versions: {}", e),
            }),
        })?;

    Ok(Json(ApiResponse::success(versions)))
}

/// Rollback secret to a specific version
pub async fn rollback_secret(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(path): Path<String>,
    Query(params): Query<GetSecretParams>,
) -> ApiResult<Json<ApiResponse<SecretResponse>>> {
    let version = params.version.ok_or_else(|| {
        crate::error::ApiError(SecretonError::Validation {
            message: "Version parameter is required for rollback".to_string(),
        })
    })?;

    let secret_data = state
        .secret
        .rollback_secret(&path, version, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::SecretNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Secret version not found".to_string(),
                })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to rollback secret: {}", e),
            }),
        })?;

    // Detect TOCTOU race: if the secret was deleted between get_secret and put_secret
    // inside rollback_secret, put_secret will have created a brand-new v1 entry.
    // Roll back the accidental creation and return NotFound.
    if secret_data.previous_version.is_none() && secret_data.version == 1 {
        if let Err(e) = state
            .secret
            .delete_secret_internal(&path, &user, false, false)
            .await
        {
            tracing::warn!(
                "Failed to rollback accidentally created secret during rollback {}: {}",
                path,
                e
            );
        }
        return Err(crate::error::ApiError(SecretonError::NotFound {
            resource: "Secret not found (deleted during rollback)".to_string(),
        }));
    }

    let response = SecretResponse {
        path: secret_data.path,
        data: secret_data.data,
        metadata: secret_data.metadata,
        version: secret_data.version,
        created_at: secret_data.created_at,
        updated_at: secret_data.updated_at,
        expires_at: secret_data.expires_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// List secrets
pub async fn list_secrets(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<SecretListItem>>>> {
    // List secrets via secreton service
    let secret_list: Vec<secret::SecretData> = state
        .secret
        .list_secrets(query.filter.as_deref(), &user, query.limit, query.offset)
        .await
        .map_err(|e: secreton_engines::services::secret::SecretError| {
            crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to list secrets: {}", e),
            })
        })?;

    // Convert to response format (now with real metadata)
    let secrets: Vec<SecretListItem> = secret_list
        .into_iter()
        .map(|secret_data| SecretListItem {
            path: secret_data.path.clone(),
            metadata: secret_data.metadata,
            version: secret_data.version,
            created_at: secret_data.created_at,
            updated_at: secret_data.updated_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(secrets)))
}

/// Key operations
pub async fn create_key(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<CreateKeyRequest>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Validate key name to prevent path-traversal and encoding issues
    crate::handlers::validate_name(&request.name)?;

    // Create key via secreton service
    let key_info: secret::KeyInfo = state
        .secret
        .create_key(&request.name, &request.key_type, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to create key: {}", e),
            }),
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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Get key via secreton service
    let key_info: secret::KeyInfo =
        state
            .secret
            .get_key(&key_id, &user)
            .await
            .map_err(|e| match e {
                secret::SecretError::KeyNotFound { .. } => {
                    crate::error::ApiError(SecretonError::NotFound {
                        resource: "Key not found".to_string(),
                    })
                }
                secret::SecretError::PermissionDenied(msg) => {
                    crate::error::ApiError(SecretonError::Authorization { message: msg })
                }
                _ => crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to retrieve key: {}", e),
                }),
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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<KeyResponse>>>> {
    // List keys via secreton service
    let key_infos: Vec<secret::KeyInfo> = state
        .secret
        .list_keys(&user, query.filter.as_deref())
        .await
        .map_err(
            |e: secreton_engines::services::secret::SecretError| match e {
                secret::SecretError::PermissionDenied(msg) => {
                    crate::error::ApiError(SecretonError::Authorization { message: msg })
                }
                _ => crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to list keys: {}", e),
                }),
            },
        )?;

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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<KeyResponse>>> {
    // Rotate key via secreton service
    let key_info: secret::KeyInfo =
        state
            .secret
            .rotate_key(&key_id, &user)
            .await
            .map_err(|e| match e {
                secreton_engines::services::secret::SecretError::KeyNotFound { .. } => {
                    crate::error::ApiError(SecretonError::NotFound {
                        resource: format!("Key not found: {}", key_id),
                    })
                }
                secret::SecretError::InvalidOperation(msg) => {
                    crate::error::ApiError(SecretonError::Validation { message: msg })
                }
                secret::SecretError::PermissionDenied(msg) => {
                    crate::error::ApiError(SecretonError::Authorization { message: msg })
                }
                _ => crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to rotate key: {}", e),
                }),
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
    State(state): State<Services>,
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
        .secret
        .update_key_metadata(&key_id, &metadata_map, &user)
        .await
        .map_err(|e: secret::SecretError| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Key not found".to_string(),
                })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to update key: {}", e),
            }),
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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Delete key via secreton service
    state
        .secret
        .delete_key(&key_id, &user)
        .await
        .map_err(|e: secret::SecretError| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Key not found".to_string(),
                })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to delete key: {}", e),
            }),
        })?;

    let data = serde_json::json!({
        "message": "Key deleted successfully",
        "key_id": key_id
    });

    Ok(Json(ApiResponse::success(data)))
}

pub async fn list_key_versions(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(key_id): Path<String>,
) -> ApiResult<Json<ApiResponse<Vec<KeyVersionInfo>>>> {
    // List key versions via secreton service
    let versions = state
        .secret
        .list_key_versions(&key_id, &user)
        .await
        .map_err(
            |e: secreton_engines::services::secret::SecretError| match e {
                secret::SecretError::KeyNotFound { .. } => {
                    crate::error::ApiError(SecretonError::NotFound {
                        resource: "Key not found".to_string(),
                    })
                }
                secret::SecretError::PermissionDenied(msg) => {
                    crate::error::ApiError(SecretonError::Authorization { message: msg })
                }
                _ => crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to list key versions: {}", e),
                }),
            },
        )?;

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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<EncryptRequest>,
) -> ApiResult<Json<ApiResponse<EncryptResponse>>> {
    // Decode plaintext from base64 if needed
    let plaintext = BASE64_STANDARD
        .decode(&request.plaintext)
        .unwrap_or_else(|_| request.plaintext.as_bytes().to_vec());

    // Encrypt data via secreton service
    let (encrypted_data, key_version) = state
        .secret
        .encrypt(&request.key_id, &plaintext, &user, request.key_version)
        .await
        .map_err(|e| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Key not found".to_string(),
                })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to encrypt data: {}", e),
            }),
        })?;

    // Serialize the full EncryptedData (including nonce, tag, algorithm) so the
    // client can pass it back to the decrypt endpoint for a successful round-trip.
    // Use a compact envelope that base64-encodes the byte fields instead of
    // relying on serde's default Vec<u8> → JSON number-array serialization,
    // which is ~3-4× larger on the wire.
    let compact_envelope = serde_json::json!({
        "algorithm": encrypted_data.algorithm,
        "nonce": BASE64_STANDARD.encode(&encrypted_data.nonce),
        "ciphertext": BASE64_STANDARD.encode(&encrypted_data.ciphertext),
        "tag": encrypted_data.tag.as_ref().map(|t| BASE64_STANDARD.encode(t)),
        "key_version": key_version,
    });
    let envelope_json = serde_json::to_vec(&compact_envelope).map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: format!("Failed to serialize encrypted data: {}", e),
        })
    })?;
    let ciphertext_b64 = BASE64_STANDARD.encode(&envelope_json);

    let response = EncryptResponse {
        ciphertext: ciphertext_b64,
        key_version, // Now using actual key version
        algorithm: match encrypted_data.algorithm {
            secreton_crypto::AlgorithmId::Aes256Gcm => "AES-GCM".to_string(),
            secreton_crypto::AlgorithmId::ChaCha20Poly1305 => "CHACHA20-POLY1305".to_string(),
            // The service layer only allows Aes256Gcm and ChaCha20Poly1305 for
            // encryption, so this branch should never be reached. Use Debug
            // formatting as a safe fallback rather than silently returning a
            // wrong name.
            other => format!("{:?}", other),
        },
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn decrypt_data(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<DecryptRequest>,
) -> ApiResult<Json<ApiResponse<DecryptResponse>>> {
    // Decode base64 ciphertext — this should be a JSON-serialized EncryptedData envelope
    // produced by the encrypt endpoint.
    let ciphertext_bytes = BASE64_STANDARD.decode(&request.ciphertext).map_err(|e| {
        crate::error::ApiError(SecretonError::Validation {
            message: format!("Invalid base64 ciphertext: {}", e),
        })
    })?;

    // Deserialize the EncryptedData envelope. Try the compact base64-field format
    // first (produced by the updated encrypt endpoint), then fall back to the raw
    // serde format (Vec<u8> as number arrays) for backward compatibility.
    let mut envelope_key_version: Option<u32> = None;
    let encrypted_data: EncryptedData = {
        // Try compact format: byte fields are base64-encoded strings
        #[derive(Deserialize)]
        struct CompactEnvelope {
            algorithm: secreton_crypto::AlgorithmId,
            nonce: String,
            ciphertext: String,
            tag: Option<String>,
            key_version: Option<u32>,
        }
        if let Ok(compact) = serde_json::from_slice::<CompactEnvelope>(&ciphertext_bytes) {
            let nonce = BASE64_STANDARD.decode(&compact.nonce).map_err(|e| {
                crate::error::ApiError(SecretonError::Validation {
                    message: format!("Invalid base64 nonce: {}", e),
                })
            })?;
            let ct = BASE64_STANDARD.decode(&compact.ciphertext).map_err(|e| {
                crate::error::ApiError(SecretonError::Validation {
                    message: format!("Invalid base64 ciphertext: {}", e),
                })
            })?;
            let tag = compact
                .tag
                .map(|t| BASE64_STANDARD.decode(&t))
                .transpose()
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Validation {
                        message: format!("Invalid base64 tag: {}", e),
                    })
                })?;
            // If the envelope contains a key_version and the request didn't
            // explicitly specify one, use the version from the envelope so
            // that decryption uses the correct key material even after rotation.
            if request.key_version.is_none() {
                envelope_key_version = compact.key_version;
            }
            EncryptedData {
                algorithm: compact.algorithm,
                nonce,
                ciphertext: ct,
                tag,
            }
        } else {
            // Fall back to raw serde format (Vec<u8> as number arrays)
            serde_json::from_slice(&ciphertext_bytes).map_err(|e| {
                crate::error::ApiError(SecretonError::Validation {
                    message: format!("Invalid encrypted data envelope: {}", e),
                })
            })?
        }
    };

    // Use the key version from the request if explicitly provided, otherwise
    // fall back to the version embedded in the ciphertext envelope, or None
    // (which causes the service to use the latest version).
    let effective_key_version = request.key_version.or(envelope_key_version);

    // Decrypt data via secreton service
    let (plaintext, key_version) = state
        .secret
        .decrypt(
            &request.key_id,
            &encrypted_data,
            &user,
            effective_key_version,
        )
        .await
        .map_err(|e| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Key not found".to_string(),
                })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to decrypt data: {}", e),
            }),
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
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<SignRequest>,
) -> ApiResult<Json<ApiResponse<SignResponse>>> {
    // Decode data from base64 if needed
    let data = BASE64_STANDARD
        .decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    // Sign data using secreton service
    let signature_result = state
        .secret
        .sign_data(&request.key_id, &data, &user, request.key_version)
        .await
        .map_err(|e| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Key not found".to_string(),
                })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to sign data: {}", e),
            }),
        })?;

    let response = SignResponse {
        signature: signature_result.signature,
        key_version: signature_result.key_version, // Already using actual key version
        algorithm: request.algorithm.unwrap_or(signature_result.algorithm),
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn verify_signature(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<ApiResponse<VerifyResponse>>> {
    // Decode data from base64
    let data = BASE64_STANDARD
        .decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    // Pass the base64-encoded signature string directly to verify_data,
    // which performs its own base64 decoding internally.
    let signature_bytes = request.signature.as_bytes();

    // Verify signature using secreton service
    let (is_valid, key_version) = state
        .secret
        .verify_data(
            &request.key_id,
            &data,
            signature_bytes,
            &user,
            request.key_version,
        )
        .await
        .map_err(|e| match e {
            secret::SecretError::KeyNotFound { .. } => {
                crate::error::ApiError(SecretonError::NotFound {
                    resource: "Key not found".to_string(),
                })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to verify signature: {}", e),
            }),
        })?;

    let response = VerifyResponse {
        valid: is_valid,
        key_version, // Now using actual key version
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn hash_data(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<HashRequest>,
) -> ApiResult<Json<ApiResponse<HashResponse>>> {
    // Decode data from base64 if needed
    let data = BASE64_STANDARD
        .decode(&request.data)
        .unwrap_or_else(|_| request.data.as_bytes().to_vec());

    // Compute hash via service (handles RBAC)
    let hash_hex = state
        .secret
        .hash_data(&data, &request.algorithm, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            secret::SecretError::InvalidOperation(msg) => {
                crate::error::ApiError(SecretonError::Validation { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to hash data: {}", e),
            }),
        })?;

    let response = HashResponse {
        hash: hash_hex,
        algorithm: request.algorithm,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Policy operations
pub async fn list_policies(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<PolicyResponse>>>> {
    // List policies via secreton service
    let policies = state
        .secret
        .list_policies(query.filter.as_deref())
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to list policies: {}", e),
            })
        })?;

    // Convert to response format
    let mut policy_responses: Vec<PolicyResponse> = policies
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
            policy_type: "structured".to_string(),
            content: None,
        })
        .collect();

    // Also surface policies created via the raw-content path
    // (`update_policy` with `{"content": "..."}`, stored under
    // `sys/policies/content/`) so they are visible and manageable in the UI.
    //
    // Only admin/root users see raw-content-only policies — mirrors the role
    // gates in `get_policy`, `update_policy`, and `delete_policy`.  Non-admin
    // users only see structured policies, preserving the existing information
    // boundary.
    //
    // Names already present in the structured list are not re-added: when a
    // policy exists in both namespaces the structured definition is the
    // authoritative representation for listing purposes.  Clients can still
    // fetch the raw form via `GET /policies/{name}` when applicable.
    if user.roles.contains(&"admin".to_string()) || user.roles.contains(&"root".to_string()) {
        // Use `list_policy_content_metadata` to obtain the timestamps from the
        // storage listing directly, avoiding an N+1 pattern of one extra
        // `get_policy_content` (storage read + crypto decrypt) per raw-content
        // policy.  The full content is not needed for a listing response.
        match state.admin.list_policy_content_metadata().await {
            Ok(raw_entries) => {
                let existing: std::collections::HashSet<String> =
                    policy_responses.iter().map(|p| p.name.clone()).collect();
                for (name, created_at, updated_at) in raw_entries {
                    if existing.contains(&name) {
                        continue;
                    }
                    // Apply the same `filter` semantics used by
                    // `SecretService::list_policies` (substring match on name).
                    if let Some(f) = query.filter.as_deref()
                        && !name.contains(f)
                    {
                        continue;
                    }
                    policy_responses.push(PolicyResponse {
                        name,
                        rules: Vec::new(),
                        metadata: PolicyMetadata {
                            description: None,
                            tags: Vec::new(),
                            owner: None,
                        },
                        created_at,
                        updated_at,
                        policy_type: "raw".to_string(),
                        content: None,
                    });
                }
            }
            Err(e) => {
                // Don't fail the whole listing on raw-content enumeration
                // failures — structured policies are still useful on their own.
                tracing::warn!("Failed to enumerate raw policy content: {}", e);
            }
        }
    }

    Ok(Json(ApiResponse::success(policy_responses)))
}

pub async fn get_policy(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<PolicyResponse>>> {
    // Validate policy name to prevent path-traversal attacks.
    // The name comes from a URL path parameter and is used to construct
    // storage paths like `sys/policies/content/{name}`.
    crate::handlers::validate_name(&name)?;

    // Attempt to load the structured policy.  `get_policy` calls
    // `check_permission` internally (permissions checked BEFORE existence),
    // so a successful result or a `PolicyNotFound` error proves the RBAC
    // check passed.  The admin/root role gate below provides an additional
    // safety net for the raw-content fallback path.
    let policy_result = state.secret.get_policy(&name, &user).await;

    // Fast path: structured policy found — return it directly.
    // The `policy_type` discriminator field on `PolicyResponse` lets clients
    // reliably distinguish structured responses from raw-content responses
    // while preserving a single strongly-typed response shape for SDK
    // consumers.
    if let Ok(policy) = policy_result {
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
            policy_type: "structured".to_string(),
            content: None,
        };
        return Ok(Json(ApiResponse::success(response)));
    }

    // Propagate definitive errors that are NOT "policy not found".
    // PermissionDenied, Internal, Storage, Crypto — all must be
    // returned immediately.
    let Err(policy_err) = policy_result else {
        unreachable!("the success branch above returns");
    };
    if !matches!(policy_err, secret::SecretError::PolicyNotFound { .. }) {
        return Err(match policy_err {
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            e => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to retrieve policy: {}", e),
            }),
        });
    }

    // Structured policy not found — fall back to raw policy content.
    //
    // Only admin/root users may access raw policy content.
    // Non-admin users get a generic 404 to avoid revealing
    // whether a raw-content policy exists at this path.
    if !user.roles.contains(&"admin".to_string()) && !user.roles.contains(&"root".to_string()) {
        return Err(crate::error::ApiError(SecretonError::NotFound {
            resource: "Policy not found".to_string(),
        }));
    }

    // The first `get_policy` call above performed the RBAC check
    // (SecretService::get_policy calls check_permission BEFORE checking
    // existence, so PolicyNotFound implies RBAC passed).  The admin/root
    // role gate above provides an additional safety net.
    //
    // DEFENSIVE: If the `get_policy` implementation ever changes to check
    // existence before permissions (returning PolicyNotFound without
    // evaluating RBAC), the fallback path would bypass fine-grained RBAC.
    // To guard against this, explicitly verify read permission on the
    // policy path.  This is a cheap in-memory RBAC evaluation.
    if let Err(e) = state
        .secret
        .check_policy_permission(&name, &user, "read")
        .await
    {
        if let secret::SecretError::PermissionDenied(msg) = e {
            return Err(crate::error::ApiError(SecretonError::Authorization {
                message: msg,
            }));
        }
        // Other errors (e.g. storage) — fail closed
        return Err(crate::error::ApiError(SecretonError::Internal {
            message: format!("Failed to verify policy permissions: {}", e),
        }));
    }

    match state.admin.get_policy_content(&name).await {
        Ok(Some((content, created_at, updated_at))) => {
            // Return the same `PolicyResponse` shape as structured policies,
            // with `policy_type = "raw"` and the raw `content` populated.
            // Existing clients that deserialize `PolicyResponse` continue to
            // work (all previously-required fields are present); clients that
            // need to handle the raw variant can inspect `policy_type` and
            // read `content`.
            let response = PolicyResponse {
                name: name.clone(),
                rules: Vec::new(),
                metadata: PolicyMetadata {
                    description: None,
                    tags: Vec::new(),
                    owner: None,
                },
                created_at,
                updated_at,
                policy_type: "raw".to_string(),
                content: Some(content),
            };
            Ok(Json(ApiResponse::success(response)))
        }
        Ok(None) => Err(crate::error::ApiError(SecretonError::NotFound {
            resource: "Policy not found".to_string(),
        })),
        Err(e) => Err(crate::error::ApiError(SecretonError::Internal {
            message: format!("Failed to retrieve policy content: {}", e),
        })),
    }
}

pub async fn create_policy(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<CreatePolicyRequest>,
) -> ApiResult<Json<ApiResponse<PolicyResponse>>> {
    // Validate policy name to prevent path-traversal attacks.
    crate::handlers::validate_name(&name)?;

    // Convert metadata
    let metadata = if let Some(meta) = &request.metadata {
        secreton_engines::services::secret::PolicyMetadata {
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
        secreton_engines::services::secret::PolicyMetadata {
            description: None,
            tags: std::collections::HashMap::new(),
            owner: Some(user.username.clone()),
            created_by: user.username.clone(),
        }
    };

    // Create policy via secreton service
    let policy = state
        .secret
        .create_policy(&name, request.rules.clone(), metadata, &user)
        .await
        .map_err(|e| match e {
            secret::SecretError::PermissionDenied(msg) => {
                crate::error::ApiError(SecretonError::Authorization { message: msg })
            }
            _ => crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to create policy: {}", e),
            }),
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
        policy_type: "structured".to_string(),
        content: None,
    };

    Ok(Json(ApiResponse::success(response)))
}

pub async fn update_policy(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
    Json(request): Json<UpdatePolicyRequest>,
) -> ApiResult<Json<ApiResponse<PolicyResponse>>> {
    // Validate policy name to prevent path-traversal attacks.
    crate::handlers::validate_name(&name)?;

    // `UpdatePolicyRequest` is an `#[serde(untagged)]` enum whose
    // `Structured` variant matches any body containing `rules` and whose
    // `Raw` variant matches any body containing only `content`.  This
    // gives us strongly-typed request handling while preserving the
    // original wire format (no discriminator tag on the client side).

    match request {
        UpdatePolicyRequest::Structured {
            name: _body_name,
            rules,
            metadata: req_metadata,
            content: stray_content,
        } => {
            // Reject an empty `rules` array accompanied by a non-null `content`:
            // this is almost certainly a client mistake — sending an empty
            // structured update would silently wipe rules AND drop the raw
            // content the caller also supplied.  Fail fast instead of losing
            // data.
            let content_present = stray_content.is_some();
            if rules.is_empty() && content_present {
                return Err(crate::error::ApiError(SecretonError::Validation {
                    message: "Invalid request: 'rules' is empty and 'content' is also provided; \
                 send either 'rules' with at least one rule or 'content' alone"
                        .to_string(),
                }));
            }
            // If both 'rules' and 'content' are present, 'rules' takes precedence.
            // Log a warning so operators can spot unintentional data loss.
            if content_present {
                tracing::warn!(
                    "update_policy '{}': request contains both 'rules' and 'content'; \
                 only 'rules' will be processed (raw content is ignored)",
                    name
                );
            }

            // Now that the request is known-valid, remove any stale raw-content
            // entry at `sys/policies/content/{name}` so that the two namespaces do
            // not drift out of sync.  Without this cleanup, a policy that previously
            // received a raw-content update followed by a structured update would
            // leave an orphaned raw entry in storage — which would resurface in
            // `list_policies` / `get_policy` fallback reads and could be misread
            // after the structured policy is later deleted.
            //
            // Only admin/root users may touch raw content; for non-admin users this
            // block is a no-op, which is safe because only admins can have created
            // raw content in the first place.
            if user.roles.contains(&"admin".to_string()) || user.roles.contains(&"root".to_string())
            {
                // Enforce fine-grained RBAC before touching raw content, consistent
                // with the update_policy raw-content branch and `delete_policy`.
                // The structured `update_policy` call below performs its own RBAC
                // check on the same path with "update" action, but the raw-content
                // cleanup is a logically distinct operation (delete on
                // sys/policies/content/{name}) so we verify explicitly.  A permission
                // failure here is a soft error — log and continue with the
                // structured update, since an admin who cannot clean up stale raw
                // content should still be able to update the structured policy.
                match state
                    .secret
                    .check_policy_permission(&name, &user, "delete")
                    .await
                {
                    Ok(()) => {
                        if let Err(e) = state.admin.delete_policy_content(&name).await {
                            // Don't fail the structured update on raw-content cleanup
                            // failures — log and continue.  The structured policy is the
                            // authoritative representation after this update.
                            tracing::warn!(
                                "update_policy '{}': failed to delete stale raw content during \
                             structured update: {}",
                                name,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "update_policy '{}': skipping raw-content cleanup during structured \
                         update because RBAC check failed: {}",
                            name,
                            e
                        );
                    }
                }
            }

            let metadata = if let Some(meta) = &req_metadata {
                secreton_engines::services::secret::PolicyMetadata {
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
                secreton_engines::services::secret::PolicyMetadata {
                    description: None,
                    tags: std::collections::HashMap::new(),
                    owner: Some(user.username.clone()),
                    created_by: user.username.clone(),
                }
            };

            let policy = state
                .secret
                .update_policy(&name, rules, metadata, &user)
                .await
                .map_err(|e| match e {
                    secret::SecretError::PolicyNotFound { .. } => {
                        crate::error::ApiError(SecretonError::NotFound {
                            resource: "Policy not found".to_string(),
                        })
                    }
                    secret::SecretError::PermissionDenied(msg) => {
                        crate::error::ApiError(SecretonError::Authorization { message: msg })
                    }
                    _ => crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to update policy: {}", e),
                    }),
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
                policy_type: "structured".to_string(),
                content: None,
            };

            Ok(Json(ApiResponse::success(response)))
        }
        UpdatePolicyRequest::Raw { content } => {
            // Only admin/root may update raw policy content
            if !user.roles.contains(&"admin".to_string())
                && !user.roles.contains(&"root".to_string())
            {
                return Err(crate::error::ApiError(SecretonError::Authorization {
                    message: "Admin privileges required".to_string(),
                }));
            }

            // Enforce RBAC policy checks for the policy path, not just role
            // membership.  This ensures that an admin whose access has been
            // restricted via fine-grained RBAC policies cannot bypass those
            // restrictions through the raw content update path.
            if let Err(e) = state
                .secret
                .check_policy_permission(&name, &user, "update")
                .await
            {
                if let secret::SecretError::PermissionDenied(msg) = e {
                    return Err(crate::error::ApiError(SecretonError::Authorization {
                        message: msg,
                    }));
                }
                return Err(crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to verify policy permissions: {}", e),
                }));
            }

            // `update_policy_content` returns the authoritative
            // `(created_at, updated_at)` for the write it just performed, so we
            // don't need to read back the entry — which would race with a
            // concurrent update and could surface the other writer's timestamps.
            let (created_at, updated_at) = state
                .admin
                .update_policy_content(&name, &content)
                .await
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to update policy content: {}", e),
                    })
                })?;
            // Return the same `PolicyResponse` shape as structured policies so
            // strongly-typed clients can parse either variant.  `policy_type =
            // "raw"` and the raw `content` is echoed back so callers can verify
            // the stored value without an additional GET round-trip.
            let response = PolicyResponse {
                name: name.clone(),
                rules: Vec::new(),
                metadata: PolicyMetadata {
                    description: None,
                    tags: Vec::new(),
                    owner: None,
                },
                created_at,
                updated_at,
                policy_type: "raw".to_string(),
                content: Some(content),
            };
            Ok(Json(ApiResponse::success(response)))
        }
    }
}

pub async fn delete_policy(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(name): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Validate policy name to prevent path-traversal attacks.
    crate::handlers::validate_name(&name)?;

    // Delete raw content FIRST so that a failure does not leave the system
    // in a partially-deleted state (structured policy gone, raw content
    // orphaned).  By attempting the raw content deletion before the
    // structured deletion, a storage error aborts the entire operation
    // and the caller can safely retry.
    //
    // Only admin/root users may manage raw policy content — mirrors the
    // role gates in `get_policy` and `update_policy`.  Non-admin users
    // skip this step; the structured deletion below is sufficient for them.
    let raw_deleted =
        if user.roles.contains(&"admin".to_string()) || user.roles.contains(&"root".to_string()) {
            // Enforce fine-grained RBAC in addition to the role check, consistent
            // with the update_policy raw-content path.
            if let Err(e) = state
                .secret
                .check_policy_permission(&name, &user, "delete")
                .await
            {
                if let secret::SecretError::PermissionDenied(msg) = e {
                    return Err(crate::error::ApiError(SecretonError::Authorization {
                        message: msg,
                    }));
                }
                return Err(crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to verify policy permissions: {}", e),
                }));
            }

            state
                .admin
                .delete_policy_content(&name)
                .await
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to delete raw policy content: {}", e),
                    })
                })?
        } else {
            false
        };

    // Delete structured policy via secreton service.
    // Track whether the structured policy existed so we can decide whether
    // to return 404 when neither the structured nor raw content entry exists.
    let structured_deleted = match state.secret.delete_policy(&name, &user).await {
        Ok(_) => true,
        Err(secret::SecretError::PolicyNotFound { .. }) => false,
        Err(secret::SecretError::PermissionDenied(msg)) => {
            return Err(crate::error::ApiError(SecretonError::Authorization {
                message: msg,
            }));
        }
        Err(e) => {
            return Err(crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to delete policy: {}", e),
            }));
        }
    };

    // If neither a structured policy nor a raw content entry was found,
    // return 404 — the policy does not exist in any form.
    if !structured_deleted && !raw_deleted {
        return Err(crate::error::ApiError(SecretonError::NotFound {
            resource: "Policy not found".to_string(),
        }));
    }

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
        "ecdsa-secp256k1" => (
            "ECDSA-secp256k1".to_string(),
            256,
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
        "xchacha20-poly1305" => (
            "XCHACHA20-POLY1305".to_string(),
            256,
            vec!["encrypt".to_string(), "decrypt".to_string()],
        ),
        "x25519" => ("X25519".to_string(), 256, vec!["key-agreement".to_string()]),
        "aes256-gcm" => (
            "AES-GCM".to_string(),
            256,
            vec!["encrypt".to_string(), "decrypt".to_string()],
        ),
        "aes128-gcm" => (
            "AES-GCM".to_string(),
            128,
            vec!["encrypt".to_string(), "decrypt".to_string()],
        ),
        // Unknown key type — default to AES-GCM but log a warning so new
        // key types are not silently misclassified.
        other => {
            tracing::warn!(
                "infer_key_attributes: unrecognised key type '{}', defaulting to AES-GCM",
                other
            );
            (
                "AES-GCM".to_string(),
                256,
                vec!["encrypt".to_string(), "decrypt".to_string()],
            )
        }
    }
}

/// Helper function to get public key for a key (for asymmetric keys)
async fn get_public_key_for_key(
    state: &Services,
    key_info: &secret::KeyInfo,
    user: &secreton_auth::User,
) -> Option<String> {
    // Check if this is an asymmetric key type
    match key_info.key_type.as_str() {
        "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ecdsa-secp256k1" | "ed25519" => {
            // Try to retrieve the public key from storage.
            // The storage path uses the user-friendly key name (key_info.name),
            // not the internal UUID-based key_id (key_info.id).
            let key_path = format!("keys/{}/{}", user.id, key_info.name);

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
                        "ecdsa-secp256k1" => "ECDSA secp256k1",
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
                        "ecdsa-secp256k1" => "ECDSA secp256k1",
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
