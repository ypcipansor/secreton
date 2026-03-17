//! Database Secrets Engine API endpoints

use axum::{
    Router,
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
};
use chrono::Utc;
use secreton_secrets::{DatabaseConfig, DatabaseEngine, EngineConfig, EngineType, SecretEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::ApiResponse;

/// API state for Database engine
#[derive(Clone)]
pub struct DatabaseApiState {
    pub engine: Arc<RwLock<DatabaseEngine>>,
}

impl DatabaseApiState {
    pub async fn new(storage: Arc<dyn secreton_storage::StorageBackend>) -> Self {
        // Create a default config
        let config = DatabaseConfig {
            plugin_name: "database".to_string(),
            connection_url: String::new(),
            allowed_roles: Vec::new(),
            username: None,
            password: None,
            max_open_connections: Some(10),
            max_idle_connections: Some(5),
            max_connection_lifetime: Some(30),
        };
        // Manually enable the engine since init isn't called via standard flow here
        // Derive encryption key from the SECRETON_ENCRYPTION_KEY environment variable
        // to ensure encrypted data survives restarts.
        let env_key = std::env::var("SECRETON_ENCRYPTION_KEY").unwrap_or_else(|_| {
            tracing::warn!("SECRETON_ENCRYPTION_KEY is not set! Using an insecure default key. DO NOT use this in production.");
            "your-32-byte-encryption-key-here".to_string()
        });
        let key = match secreton_crypto::hashing::compute_hash(
            secreton_crypto::AlgorithmId::Sha256,
            env_key.as_bytes(),
        ) {
            Ok(result) => result.hash,
            Err(e) => {
                tracing::error!("CRITICAL: Failed to derive encryption key via SHA-256: {:?}. Database engine encryption will be unavailable.", e);
                // Return early with an engine that has no crypto configured
                let mut engine = DatabaseEngine::new(config, storage);
                if let Err(e) = engine.load_state().await {
                    tracing::error!("Failed to load database engine state: {}", e);
                }
                engine.enable();
                return Self {
                    engine: Arc::new(RwLock::new(engine)),
                };
            }
        };
        let cipher = Arc::new(secreton_crypto::encryption::Aes256GcmCipher);
        let mut engine = DatabaseEngine::new(config, storage).with_crypto(cipher, key);
        if let Err(e) = engine.load_state().await {
            tracing::error!("Failed to load database engine state: {}", e);
        }
        engine.enable();

        let engine_arc = Arc::new(RwLock::new(engine));

        // Spawn background task for TTL enforcement.
        // We collect expired IDs under a brief read lock, then revoke each
        // lease individually so the RwLock is not held across all the async
        // network I/O, allowing write operations to proceed between revocations.
        let background_engine = engine_arc.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;

                // Phase 1: collect expired lease IDs (brief read lock)
                let expired_ids = {
                    let engine_read = background_engine.read().await;
                    match engine_read.collect_expired_lease_ids() {
                        Ok(ids) => ids,
                        Err(e) => {
                            tracing::error!("Background TTL enforcement: failed to collect expired leases: {}", e);
                            continue;
                        }
                    }
                }; // read lock released here

                // Phase 2: revoke each lease, re-acquiring the read lock per lease
                for lease_id in &expired_ids {
                    let engine_read = background_engine.read().await;
                    match engine_read.revoke_lease(lease_id).await {
                        Ok(_) => tracing::info!("Background TTL: revoked expired lease {}", lease_id),
                        Err(e) => tracing::error!("Background TTL: failed to revoke lease {}: {}", lease_id, e),
                    }
                    // read lock dropped at end of each iteration
                }
            }
        });

        Self {
            engine: engine_arc,
        }
    }
}

/// Request to configure the database connection
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigRequest {
    pub connection_url: String,
    pub plugin_name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub allowed_roles: Option<Vec<String>>,
}

/// Request to create/update a role
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub sql: String,
    pub max_ttl: Option<u64>,
    pub default_ttl: Option<u64>,
}

/// Response for configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub success: bool,
    pub message: String,
}

/// Response for credential generation
#[derive(Debug, Serialize, Deserialize)]
pub struct CredsResponse {
    pub username: String,
    pub password: String,
    pub lease_id: String,
    pub lease_duration: u64,
}

/// Response for listing roles
#[derive(Debug, Serialize, Deserialize)]
pub struct ListRolesResponse {
    pub roles: Vec<String>,
}

/// Response for lease information
#[derive(Debug, Serialize, Deserialize)]
pub struct LeaseResponse {
    pub lease_id: String,
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub lease_duration: u64,
}

/// Create the Database router with all endpoints
pub fn create_database_router() -> Router<()> {
    Router::new()
        .route("/config", post(configure_database))
        .route("/roles", get(list_roles))
        .route("/roles/{name}", post(create_role))
        .route("/creds/{name}", get(get_credentials))
        .route("/leases", get(list_leases))
        .route("/leases/{id}", delete(revoke_lease))
}

/// Configure the database engine
#[axum::debug_handler]
pub async fn configure_database(
    Extension(state): Extension<crate::ApiState>,
    Json(request): Json<ConfigRequest>,
) -> Result<Json<ApiResponse<ConfigResponse>>, StatusCode> {
    let mut engine = state.database.engine.write().await;

    // Construct EngineConfig
    let db_config = DatabaseConfig {
        plugin_name: request
            .plugin_name
            .unwrap_or_else(|| "database".to_string()),
        connection_url: request.connection_url,
        allowed_roles: request.allowed_roles.unwrap_or_default(),
        username: request.username,
        password: request.password,
        max_open_connections: Some(10),
        max_idle_connections: Some(5),
        max_connection_lifetime: Some(30),
    };

    let config_map = serde_json::to_value(db_config).map_err(|e| {
        error!("Failed to serialize config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut engine_config_map = HashMap::new();
    engine_config_map.insert("database".to_string(), config_map);

    let engine_config = EngineConfig {
        name: "database".to_string(),
        engine_type: EngineType::Database,
        enabled: true,
        config: engine_config_map,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    match engine.init(&engine_config).await {
        Ok(_) => {
            info!("Database engine configured successfully");
            Ok(Json(ApiResponse::success(ConfigResponse {
                success: true,
                message: "Database engine configured".to_string(),
            })))
        }
        Err(e) => {
            error!("Failed to configure database engine: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// List all roles
#[axum::debug_handler]
pub async fn list_roles(
    Extension(state): Extension<crate::ApiState>,
) -> Result<Json<ApiResponse<ListRolesResponse>>, StatusCode> {
    let engine = state.database.engine.read().await;
    match engine.list("roles").await {
        Ok(roles) => Ok(Json(ApiResponse::success(ListRolesResponse { roles }))),
        Err(e) => {
            error!("Failed to list roles: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create or update a role
#[axum::debug_handler]
pub async fn create_role(
    Extension(state): Extension<crate::ApiState>,
    Path(name): Path<String>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<ApiResponse<ConfigResponse>>, StatusCode> {
    let mut engine = state.database.engine.write().await;

    let mut data = HashMap::new();
    data.insert("sql".to_string(), Value::String(request.sql));
    if let Some(ttl) = request.max_ttl {
        data.insert(
            "max_ttl".to_string(),
            Value::Number(serde_json::Number::from(ttl)),
        );
    }
    if let Some(ttl) = request.default_ttl {
        data.insert(
            "default_ttl".to_string(),
            Value::Number(serde_json::Number::from(ttl)),
        );
    }

    match engine.write(&format!("roles/{}", name), data).await {
        Ok(_) => {
            info!("Role '{}' created/updated", name);
            Ok(Json(ApiResponse::success(ConfigResponse {
                success: true,
                message: format!("Role '{}' configured", name),
            })))
        }
        Err(e) => {
            error!("Failed to create role '{}': {:?}", name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Generate credentials
#[axum::debug_handler]
pub async fn get_credentials(
    Extension(state): Extension<crate::ApiState>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<CredsResponse>>, StatusCode> {
    let engine = state.database.engine.read().await;

    match engine.read(&format!("creds/{}", name)).await {
        Ok(Some(secret)) => {
            // Extract username/password from secret.data
            let username = secret
                .data
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let password = secret
                .data
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Ok(Json(ApiResponse::success(CredsResponse {
                username,
                password,
                lease_id: secret.metadata.lease_id.unwrap_or_default(),
                lease_duration: secret.metadata.lease_duration.unwrap_or(0),
            })))
        }
        Ok(None) => {
            warn!("Role '{}' not found or returned no secret", name);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!(
                "Failed to generate credentials for role '{}': {:?}",
                name, e
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// List active leases
#[axum::debug_handler]
pub async fn list_leases(
    Extension(state): Extension<crate::ApiState>,
) -> Result<Json<ApiResponse<Vec<LeaseResponse>>>, StatusCode> {
    let engine = state.database.engine.read().await;

    // We use the new public method on DatabaseEngine
    let leases = engine
        .list_leases()
        .into_iter()
        .map(|l| LeaseResponse {
            lease_id: l.lease_id,
            username: l.username,
            role: l.role,
            created_at: l.created_at,
            lease_duration: l.lease_duration,
        })
        .collect();

    Ok(Json(ApiResponse::success(leases)))
}

/// Revoke a lease
#[axum::debug_handler]
pub async fn revoke_lease(
    Extension(state): Extension<crate::ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<ConfigResponse>>, StatusCode> {
    let engine = state.database.engine.read().await;

    // We use the new public method on DatabaseEngine
    match engine.revoke_lease(&id).await {
        Ok(_) => {
            info!("Lease '{}' revoked", id);
            Ok(Json(ApiResponse::success(ConfigResponse {
                success: true,
                message: format!("Lease '{}' revoked", id),
            })))
        }
        Err(e) => {
            error!("Failed to revoke lease '{}': {:?}", id, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
