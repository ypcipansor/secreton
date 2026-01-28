//! Database Secrets Engine API endpoints

use axum::{
    Router,
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use chrono::Utc;
use secreton_secrets::{DatabaseEngine, SecretEngine, EngineConfig, DatabaseConfig, EngineType};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use crate::ApiResponse;

/// API state for Database engine
#[derive(Clone)]
pub struct DatabaseApiState {
    pub engine: Arc<RwLock<DatabaseEngine>>,
}

impl Default for DatabaseApiState {
    fn default() -> Self {
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
        Self {
            engine: Arc::new(RwLock::new(DatabaseEngine::new(config))),
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

/// Create the Database router with all endpoints
pub fn create_database_router() -> Router<()> {
    Router::new()
        .route("/config", post(configure_database))
        .route("/roles", get(list_roles))
        .route("/roles/{name}", post(create_role))
        .route("/creds/{name}", get(get_credentials))
}

/// Configure the database engine
#[axum::debug_handler]
pub async fn configure_database(
    Extension(state): Extension<DatabaseApiState>,
    Json(request): Json<ConfigRequest>,
) -> Result<Json<ApiResponse<ConfigResponse>>, StatusCode> {
    let mut engine = state.engine.write().await;

    // Construct EngineConfig
    let db_config = DatabaseConfig {
        plugin_name: request.plugin_name.unwrap_or_else(|| "database".to_string()),
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
    Extension(state): Extension<DatabaseApiState>,
) -> Result<Json<ApiResponse<ListRolesResponse>>, StatusCode> {
    let engine = state.engine.read().await;
    match engine.list("roles").await {
        Ok(roles) => {
            Ok(Json(ApiResponse::success(ListRolesResponse { roles })))
        }
        Err(e) => {
            error!("Failed to list roles: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create or update a role
#[axum::debug_handler]
pub async fn create_role(
    Extension(state): Extension<DatabaseApiState>,
    Path(name): Path<String>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<ApiResponse<ConfigResponse>>, StatusCode> {
    let mut engine = state.engine.write().await;

    let mut data = HashMap::new();
    data.insert("sql".to_string(), Value::String(request.sql));
    if let Some(ttl) = request.max_ttl {
        data.insert("max_ttl".to_string(), Value::Number(serde_json::Number::from(ttl)));
    }
    if let Some(ttl) = request.default_ttl {
        data.insert("default_ttl".to_string(), Value::Number(serde_json::Number::from(ttl)));
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
    Extension(state): Extension<DatabaseApiState>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<CredsResponse>>, StatusCode> {
    let engine = state.engine.read().await;

    match engine.read(&format!("creds/{}", name)).await {
        Ok(Some(secret)) => {
            // Extract username/password from secret.data
            let username = secret.data.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let password = secret.data.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();

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
            error!("Failed to generate credentials for role '{}': {:?}", name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
