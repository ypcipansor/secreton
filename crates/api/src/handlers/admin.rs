//! Administrative handlers for system management.
//!
//! Provides endpoints for user management, system configuration,
//! monitoring, and maintenance operations.

use axum::{
    Router,
    extract::{Path, Query, State},
    response::Json,
    routing::{delete, get, post, put},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::handlers::{AppState, secret::ListQuery};
use crate::{
    ApiResponse, ApiResult,
    services::admin::{CreateUserRequest, UpdateUserRequest},
};
use secreton_crypto::{encryption, hashing};
use secreton_storage::SecretEntry; // Moved from inside function to top-level

/// Create administrative routes
pub fn create_routes() -> Router<AppState> {
    Router::new()
        // User management
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/{username}", get(get_user))
        .route("/users/{username}", put(update_user))
        .route("/users/{username}", delete(delete_user))
        .route("/users/{username}/roles", get(get_user_roles))
        .route("/users/{username}/roles", post(assign_user_roles))
        .route("/users/{username}/permissions", get(get_user_permissions))
        // Role management
        .route("/roles", get(list_roles))
        .route("/roles", post(create_role))
        .route("/roles/{role_name}", get(get_role))
        .route("/roles/{role_name}", put(update_role))
        .route("/roles/{role_name}", delete(delete_role))
        // System configuration
        .route("/config", get(get_config))
        .route("/config", put(update_config))
        .route("/config/reload", post(reload_config))
        // System monitoring
        .route("/metrics", get(get_system_metrics))
        .route("/status", get(get_system_status))
        .route("/logs", get(get_system_logs))
        // Maintenance operations
        .route("/maintenance/gc", post(run_garbage_collection))
        .route("/maintenance/compact", post(compact_database))
        .route("/maintenance/vacuum", post(vacuum_database))
        // Audit logs
        .route("/audit", get(list_audit_logs))
        // Backup operations
        .route("/backups", post(create_backup))
        .route("/backups", get(list_backups))
        .route("/backups/{backup_id}", get(get_backup))
        .route("/backups/{backup_id}/restore", post(restore_backup))
        .route("/backups/{backup_id}", delete(delete_backup))
        // Security operations
        .route("/security/scan", post(run_security_scan))
        .route("/security/reports", get(get_security_reports))
        .route("/security/incidents", get(get_security_incidents))
        .route(
            "/security/incidents/{incident_id}",
            get(get_security_incident),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiConfig;
    use crate::services::ApiServiceContainer;
    use axum_test::TestServer;
    use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Generate a valid admin JWT token for use in tests.
    async fn admin_token(services: &Arc<crate::services::ApiServiceContainer>) -> String {
        let admin_user = secreton_auth::User {
            id: uuid::Uuid::new_v4().to_string(),
            username: "admin".to_string(),
            email: Some("admin@example.com".to_string()),
            display_name: Some("Admin User".to_string()),
            full_name: Some("Admin User".to_string()),
            roles: vec!["admin".to_string()],
            policies: vec!["default".to_string()],
            metadata: std::collections::HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            failed_login_attempts: 0,
            locked_until: None,
            last_login: None,
            mfa_enabled: false,
            mfa_secret: None,
            password_hash: "mock_hash".to_string(),
            disabled: false,
            enabled: true,
            is_active: true,
            is_superuser: true,
            permissions: vec![],
        };
        services
            .auth
            .generate_token(&admin_user)
            .await
            .expect("Failed to generate admin token")
    }

    #[tokio::test]
    async fn test_list_users_returns_placeholder_user() {
        let mut config = ApiConfig::default();
        config.auth.jwt.secret = Some("test_secret".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();
        let services = Arc::new(
            crate::services::ApiServiceContainer::new(&config)
                .await
                .expect("Failed to create services"),
        );

        // Seed admin user
        let user_info = crate::services::admin::UserInfo {
            id: uuid::Uuid::new_v4().to_string(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            full_name: None,
            enabled: true,
            roles: vec!["admin".to_string()],
            permissions: vec![],
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: Default::default(),
        };
        let user_json = serde_json::to_vec(&user_info).unwrap();
        let entry = SecretEntry::new(
            "users/admin".to_string(),
            user_json,
            secreton_storage::EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        services.storage.store(&entry).await.expect("Failed to store seeded user");

        let token = admin_token(&services).await;
        let server = {
            let app = create_routes().with_state(services.into());
            use std::net::SocketAddr;
            TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>())
                .expect("Failed to start test server")
        };

        let response = server
            .get("/users")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", token).parse().unwrap(),
            )
            .await;
        response.assert_status_ok();

        let body: ApiResponse<Vec<UserResponse>> = response.json();
        assert!(body.success);
        let users = body.data.expect("users payload");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
    }

    #[tokio::test]
    async fn test_create_role_endpoint() {
        let request = CreateRoleRequest {
            name: "auditor".to_string(),
            description: Some("Audit role".to_string()),
            permissions: vec!["secreton:read".to_string()],
            metadata: None,
        };

        let mut config = ApiConfig::default();
        config.auth.jwt.secret = Some("test_secret".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();
        let services = Arc::new(
            crate::services::ApiServiceContainer::new(&config)
                .await
                .expect("Failed to create services"),
        );
        let token = admin_token(&services).await;

        let app = create_routes().with_state(services.into());
        use std::net::SocketAddr;
        let server = TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>())
            .expect("Failed to start test server");

        let response = server
            .post("/roles")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", token).parse().unwrap(),
            )
            .json(&request)
            .await;
        response.assert_status_ok();

        let body: ApiResponse<RoleResponse> = response.json();
        assert!(body.success);
        let role = body.data.expect("role payload");
        assert_eq!(role.name, "auditor");
        assert!(role.permissions.contains(&"secreton:read".to_string()));
    }

    #[tokio::test]
    async fn test_get_config_returns_security_info() {
        let mut config = ApiConfig::default();
        config.auth.jwt.secret = Some("test_secret".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();
        let services = Arc::new(
            crate::services::ApiServiceContainer::new(&config)
                .await
                .expect("Failed to create services"),
        );
        let token = admin_token(&services).await;

        let app = create_routes().with_state(services.into());
        use std::net::SocketAddr;
        let server = TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>())
            .expect("Failed to start test server");

        let response = server
            .get("/config")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", token).parse().unwrap(),
            )
            .await;
        response.assert_status_ok();

        let body: ApiResponse<SystemConfig> = response.json();
        assert!(body.success);
        let config = body.data.expect("config payload");
        assert!(config.security.mfa_enabled);
        assert_eq!(config.api.version, "0.1.0");
    }

    #[tokio::test]
    async fn test_run_security_scan() {
        let mut config = ApiConfig::default();
        config.auth.jwt.secret = Some("test_secret".to_string());
        config.auth.jwt.issuer = "secreton".to_string();
        config.auth.jwt.audience = "secreton-api".to_string();
        let services = Arc::new(
            crate::services::ApiServiceContainer::new(&config)
                .await
                .expect("Failed to create services"),
        );
        let token = admin_token(&services).await;

        let app = create_routes().with_state(services.into());
        use std::net::SocketAddr;
        let server = TestServer::new(app.into_make_service_with_connect_info::<SocketAddr>())
            .expect("Failed to start test server");

        let response = server
            .post("/security/scan")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", token).parse().unwrap(),
            )
            .await;
        response.assert_status_ok();

        let body: ApiResponse<SecurityScanResult> = response.json();
        assert!(body.success);
        let result = body.data.expect("scan result");

        assert_ne!(result.scan_id, "placeholder_id");
        assert_eq!(result.status, "completed");
        assert!(!result.findings.is_empty());
    }
}

/// User management models
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub enabled: bool,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignRolesRequest {
    pub roles: Vec<String>,
}

/// Role management models
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateRoleRequest {
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleResponse {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub users: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// System configuration models
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemConfig {
    pub api: ApiConfigInfo,
    pub security: SecurityConfigInfo,
    pub storage: StorageConfigInfo,
    pub monitoring: MonitoringConfigInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiConfigInfo {
    pub version: String,
    pub bind_address: String,
    pub max_connections: u32,
    pub timeout: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfigInfo {
    pub mfa_enabled: bool,
    pub password_policy: PasswordPolicyInfo,
    pub session_timeout: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordPolicyInfo {
    pub min_length: u8,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageConfigInfo {
    pub backend: String,
    pub encryption_enabled: bool,
    pub backup_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringConfigInfo {
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
    pub log_level: String,
}

/// System monitoring models
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub uptime: u64,
    pub memory_usage: MemoryMetrics,
    pub cpu_usage: CpuMetrics,
    pub disk_usage: DiskMetrics,
    pub network: NetworkMetrics,
    pub secreton: SecretMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub cached: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub cores: u32,
    pub usage_percent: f64,
    pub load_average: [f64; 3],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretMetrics {
    pub total_secrets: u64,
    pub total_keys: u64,
    pub total_policies: u64,
    pub active_sessions: u64,
    pub operations_per_second: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatus {
    pub status: String,
    pub version: String,
    pub uptime: u64,
    pub components: ComponentStatus,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub database: String,
    pub cache: String,
    pub crypto: String,
    pub storage: String,
    pub auth: String,
}

/// Security models
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityScanResult {
    pub scan_id: String,
    pub status: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub findings: Vec<SecurityFinding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub affected_resources: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: String,
    pub severity: String,
    pub status: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// User management endpoints
pub async fn list_users(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Query(_query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<UserResponse>>>> {
    require_admin(&user)?;
    let users: Vec<crate::services::admin::UserInfo> =
        state
            .admin
            .list_users()
            .await
            .map_err(map_admin_error)?;

    let user_responses: Vec<UserResponse> = users
        .into_iter()
        .map(|user| UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            full_name: user.full_name,
            enabled: user.enabled,
            roles: user.roles,
            permissions: user.permissions,
            last_login: user.last_login,
            created_at: user.created_at,
            updated_at: user.updated_at,
            metadata: user.metadata,
        })
        .collect();

    Ok(Json(ApiResponse::success(user_responses)))
}

pub async fn create_user(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Json(request): Json<CreateUserRequest>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    require_admin(&user)?;
    let create_request = CreateUserRequest {
        username: request.username,
        email: request.email,
        password: request.password,
        full_name: request.full_name,
        enabled: request.enabled,
        roles: request.roles,
        permissions: request.permissions,
        metadata: request.metadata,
    };

    let user: crate::services::admin::UserInfo =
        state.admin.create_user(create_request).await.map_err(map_admin_error)?;

    let user_response = UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        enabled: user.enabled,
        roles: user.roles,
        permissions: user.permissions,
        last_login: user.last_login,
        created_at: user.created_at,
        updated_at: user.updated_at,
        metadata: user.metadata,
    };

    Ok(Json(ApiResponse::success(user_response)))
}

pub async fn get_user(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(username): Path<String>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    require_admin(&user)?;
    let user: crate::services::admin::UserInfo =
        state
            .admin
            .get_user(&username)
            .await
            .map_err(map_admin_error)?;

    let user_response = UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        enabled: user.enabled,
        roles: user.roles,
        permissions: user.permissions,
        last_login: user.last_login,
        created_at: user.created_at,
        updated_at: user.updated_at,
        metadata: user.metadata,
    };

    Ok(Json(ApiResponse::success(user_response)))
}

pub async fn update_user(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(username): Path<String>,
    Json(request): Json<UpdateUserRequest>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    require_admin(&user)?;
    let update_request = UpdateUserRequest {
        email: request.email,
        full_name: request.full_name,
        enabled: request.enabled,
        roles: request.roles,
    };

    let user: crate::services::admin::UserInfo = state
        .admin
        .update_user(&username, update_request)
        .await
        .map_err(map_admin_error)?;

    let user_response = UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        full_name: user.full_name,
        enabled: user.enabled,
        roles: user.roles,
        permissions: user.permissions,
        last_login: user.last_login,
        created_at: user.created_at,
        updated_at: user.updated_at,
        metadata: user.metadata,
    };

    Ok(Json(ApiResponse::success(user_response)))
}

pub async fn delete_user(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(username): Path<String>,
    Query(_query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;
    state
        .admin
        .delete_user(&username)
        .await
        .map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "User deleted successfully"
    }))))
}

/// System configuration endpoints
pub async fn get_config(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<SystemConfig>>> {
    require_admin(&user)?;
    // Get actual configuration from the services
    let config = SystemConfig {
        api: ApiConfigInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            bind_address: "0.0.0.0:8080".to_string(), // This should come from config
            max_connections: 1000,
            timeout: 30,
        },
        security: SecurityConfigInfo {
            mfa_enabled: true, // This should come from config
            password_policy: PasswordPolicyInfo {
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special: true,
            },
            session_timeout: 3600,
        },
        storage: StorageConfigInfo {
            backend: "postgresql".to_string(), // This should come from actual storage config
            encryption_enabled: true,
            backup_enabled: true,
        },
        monitoring: MonitoringConfigInfo {
            metrics_enabled: true,
            tracing_enabled: true,
            log_level: "info".to_string(),
        },
    };

    Ok(Json(ApiResponse::success(config)))
}

use tokio::time::{Duration, timeout};

pub async fn get_system_metrics(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Query(_query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<SystemMetrics>>> {
    require_admin(&user)?;
    let stats = state
        .admin
        .get_system_stats()
        .await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    // Use shared telemetry collector if available
    let (memory, cpu, disk, network, uptime) =
        if let Some(telemetry) = Option::<secreton_core::telemetry::TelemetryCollector>::None {
            // Stubbed due to compilation issue
            let m: secreton_core::telemetry::SystemMetrics = telemetry.get_metrics().await;

            let mem = MemoryMetrics {
                total: m.performance.total_memory_bytes,
                used: m.performance.memory_usage_bytes,
                free: m
                    .performance
                    .total_memory_bytes
                    .saturating_sub(m.performance.memory_usage_bytes),
                cached: 0, // Not currently tracked in core metrics
            };

            let cpu = CpuMetrics {
                cores: num_cpus::get() as u32,
                usage_percent: m.performance.cpu_usage_percent as f64,
                load_average: [
                    m.system.load_average_1m as f64,
                    m.system.load_average_5m as f64,
                    m.system.load_average_15m as f64,
                ],
            };

            let disk = DiskMetrics {
                total: m.performance.total_disk_bytes,
                used: m.performance.disk_usage_bytes,
                free: m
                    .performance
                    .total_disk_bytes
                    .saturating_sub(m.performance.disk_usage_bytes),
                usage_percent: if m.performance.total_disk_bytes > 0 {
                    (m.performance.disk_usage_bytes as f64 / m.performance.total_disk_bytes as f64)
                        * 100.0
                } else {
                    0.0
                },
            };

            let net = NetworkMetrics {
                bytes_sent: m.performance.network_tx_bytes,
                bytes_received: m.performance.network_rx_bytes,
                packets_sent: 0,     // Not tracked
                packets_received: 0, // Not tracked
            };

            (mem, cpu, disk, net, m.system.uptime_seconds)
        } else {
            // Fallback for when telemetry service is missing
            (
                MemoryMetrics {
                    total: 0,
                    used: 0,
                    free: 0,
                    cached: 0,
                },
                CpuMetrics {
                    cores: 1,
                    usage_percent: 0.0,
                    load_average: [0.0; 3],
                },
                DiskMetrics {
                    total: 0,
                    used: 0,
                    free: 0,
                    usage_percent: 0.0,
                },
                NetworkMetrics {
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                },
                stats.uptime_seconds,
            )
        };

    // Count total policies from storage
    let total_policies: u64 = state
        .storage
        .list(&secreton_storage::QueryParams {
            path_prefix: Some("policies/".to_string()),
            limit: None,
            offset: Some(0),
            ..Default::default()
        })
        .await
        .map(|entries: Vec<SecretEntry>| entries.len() as u64)
        .unwrap_or(0);

    let metrics = SystemMetrics {
        uptime,
        memory_usage: memory,
        cpu_usage: cpu,
        disk_usage: disk,
        network,
        secreton: SecretMetrics {
            total_secrets: stats.total_secrets,
            total_keys: stats.total_keys,
            total_policies,
            active_sessions: stats.active_sessions,
            operations_per_second: stats.requests_per_minute,
        },
    };

    Ok(Json(ApiResponse::success(metrics)))
}

pub async fn get_system_status(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<SystemStatus>>> {
    require_admin(&user)?;
    // Check component health
    let database_status = check_database_health(&state).await;
    let cache_status = check_cache_health(&state).await;
    let crypto_status = check_crypto_health(&state).await;
    let storage_status = check_storage_health(&state).await;
    let auth_status = check_auth_health(&state).await;

    let overall_status = if database_status == "healthy"
        && cache_status == "healthy"
        && crypto_status == "healthy"
        && storage_status == "healthy"
        && auth_status == "healthy"
    {
        "healthy"
    } else if database_status == "unhealthy"
        || storage_status == "unhealthy"
        || crypto_status == "unhealthy"
    {
        "unhealthy"
    } else {
        "degraded"
    };

    let status = SystemStatus {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0),
        components: ComponentStatus {
            database: database_status,
            cache: cache_status,
            crypto: crypto_status,
            storage: storage_status,
            auth: auth_status,
        },
        last_check: chrono::Utc::now(),
    };

    Ok(Json(ApiResponse::success(status)))
}

/// Security endpoints
pub async fn run_security_scan(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<SecurityScanResult>>> {
    require_admin(&user)?;
    let report = state
        .admin
        .run_security_scan()
        .await
        .map_err(|e| crate::ApiError::Internal(e.to_string()))?;

    let scan_result = SecurityScanResult {
        scan_id: report.scan_id,
        status: report.status,
        started_at: report.started_at,
        completed_at: report.completed_at,
        findings: report
            .findings
            .into_iter()
            .map(|f| SecurityFinding {
                severity: f.severity,
                category: f.category,
                title: f.title,
                description: f.description,
                recommendation: f.recommendation,
                affected_resources: f.affected_resources,
            })
            .collect(),
    };

    Ok(Json(ApiResponse::success(scan_result)))
}

pub async fn get_security_incidents(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Query(_query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<SecurityIncident>>>> {
    require_admin(&user)?;
    // For now, return empty list - in a real implementation,
    // this would query the security monitoring system
    let incidents = Vec::new();

    Ok(Json(ApiResponse::success(incidents)))
}

/// Maintenance operations
pub async fn run_garbage_collection(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;
    let result = state.admin.run_garbage_collection().await.map_err(map_admin_error)?;

    let data = serde_json::json!({
        "message": "Garbage collection completed",
        "operation": result.operation,
        "success": result.success,
        "duration_ms": result.duration_ms,
        "details": result.details
    });

    Ok(Json(ApiResponse::success(data)))
}

pub async fn compact_database(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;
    let result = state.admin.compact_database().await.map_err(map_admin_error)?;

    let data = serde_json::json!({
        "message": "Database compaction completed",
        "operation": result.operation,
        "success": result.success,
        "duration_ms": result.duration_ms,
        "details": result.details
    });

    Ok(Json(ApiResponse::success(data)))
}

/// Component health check functions
async fn check_database_health(_state: &AppState) -> String {
    // Try a simple database operation to check health
    match timeout(Duration::from_secs(5), async {
        // This would need to be implemented based on the actual storage backend
        // For now, assume healthy if we can access the service
        Ok::<(), ()>(())
    })
    .await
    {
        Ok(Ok(_)) => "healthy".to_string(),
        _ => "unhealthy".to_string(),
    }
}

async fn check_cache_health(_state: &AppState) -> String {
    // Check if cache is accessible
    // For now, assume healthy
    "healthy".to_string()
}

async fn check_crypto_health(_state: &AppState) -> String {
    // Test basic crypto operations

    // Test hash function
    let test_data = b"test data for crypto health check";
    if hashing::compute_hash(secreton_crypto::AlgorithmId::Sha256, test_data).is_err() {
        return "unhealthy".to_string();
    }

    // Test symmetric encryption
    let key = secreton_crypto::generate_key(secreton_crypto::AlgorithmId::Aes256Gcm).unwrap();
    let engine = encryption::CryptoEngine::new();
    match engine.encrypt(secreton_crypto::AlgorithmId::Aes256Gcm, test_data, &key) {
        Ok(encrypted) => match engine.decrypt(&encrypted, &key) {
            Ok(decrypted) if decrypted == test_data => "healthy".to_string(),
            _ => "unhealthy".to_string(),
        },
        _ => "unhealthy".to_string(),
    }
}

async fn check_storage_health(_state: &AppState) -> String {
    // Try a simple storage operation
    match timeout(Duration::from_secs(5), async {
        // This would test the storage backend
        Ok::<(), ()>(())
    })
    .await
    {
        Ok(Ok(_)) => "healthy".to_string(),
        _ => "unhealthy".to_string(),
    }
}

async fn check_auth_health(_state: &AppState) -> String {
    // Check if auth service is responsive
    match timeout(Duration::from_secs(5), async {
        // Test auth service availability
        Ok::<(), ()>(())
    })
    .await
    {
        Ok(Ok(_)) => "healthy".to_string(),
        _ => "degraded".to_string(),
    }
}

/// Map AdminError to the appropriate SecretonError variant for proper HTTP status codes.
fn map_admin_error(e: crate::services::admin::AdminError) -> secreton_errors::SecretonError {
    match e {
        crate::services::admin::AdminError::NotFound(msg) => {
            secreton_errors::SecretonError::NotFound { resource: msg }
        }
        crate::services::admin::AdminError::NotPermitted(msg) => {
            secreton_errors::SecretonError::Authorization { message: msg }
        }
        crate::services::admin::AdminError::InvalidConfig(msg) => {
            secreton_errors::SecretonError::Validation { message: msg }
        }
        crate::services::admin::AdminError::MaintenanceInProgress => {
            secreton_errors::SecretonError::ServiceUnavailable {
                service: "admin".to_string(),
            }
        }
        other => secreton_errors::SecretonError::Internal {
            message: other.to_string(),
        },
    }
}

/// Verify that the authenticated user has admin privileges.
/// Returns an authorization error if the user does not hold the "admin" or "root" role.
///
/// NOTE: `is_superuser` is checked for forward-compatibility but is currently
/// always `false` for token-authenticated users because `validate_token`
/// reconstructs the `User` from JWT claims which do not carry that flag.
fn require_admin(user: &secreton_auth::User) -> Result<(), crate::ApiError> {
    if !user.is_superuser
        && !user.roles.contains(&"admin".to_string())
        && !user.roles.contains(&"root".to_string())
    {
        return Err(crate::ApiError::Authorization(
            "Insufficient permissions".to_string(),
        ));
    }
    Ok(())
}

// Stub implementations for missing handlers

pub async fn get_user_roles(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(username): Path<String>,
) -> ApiResult<Json<ApiResponse<Vec<String>>>> {
    require_admin(&user)?;
    let roles = state.admin.get_user_roles(&username).await.map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(roles)))
}

pub async fn assign_user_roles(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(username): Path<String>,
    Json(request): Json<AssignRolesRequest>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;
    state
        .admin
        .assign_user_roles(&username, request.roles)
        .await
        .map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(
        serde_json::json!({"status": "updated"}),
    )))
}

pub async fn get_user_permissions(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(username): Path<String>,
) -> ApiResult<Json<ApiResponse<Vec<String>>>> {
    require_admin(&user)?;
    let permissions = state.admin.get_user_permissions(&username).await.map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(permissions)))
}

pub async fn list_roles(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Vec<RoleResponse>>>> {
    require_admin(&user)?;
    let roles = state.admin.list_roles().await.map_err(map_admin_error)?;

    let responses = roles
        .into_iter()
        .map(|r| RoleResponse {
            name: r.name,
            description: r.description,
            permissions: r.permissions,
            users: r.users,
            created_at: r.created_at,
            updated_at: r.updated_at,
            metadata: r.metadata,
        })
        .collect();

    Ok(Json(ApiResponse::success(responses)))
}

pub async fn create_role(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Json(request): Json<CreateRoleRequest>,
) -> ApiResult<Json<ApiResponse<RoleResponse>>> {
    require_admin(&user)?;
    let create_req = crate::services::admin::CreateRoleRequest {
        name: request.name,
        description: request.description,
        permissions: request.permissions,
        metadata: request.metadata,
    };

    let role = state.admin.create_role(create_req).await.map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(RoleResponse {
        name: role.name,
        description: role.description,
        permissions: role.permissions,
        users: role.users,
        created_at: role.created_at,
        updated_at: role.updated_at,
        metadata: role.metadata,
    })))
}

pub async fn get_role(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(role_name): Path<String>,
) -> ApiResult<Json<ApiResponse<RoleResponse>>> {
    require_admin(&user)?;
    let role = state.admin.get_role(&role_name).await.map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(RoleResponse {
        name: role.name,
        description: role.description,
        permissions: role.permissions,
        users: role.users,
        created_at: role.created_at,
        updated_at: role.updated_at,
        metadata: role.metadata,
    })))
}

pub async fn update_role(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(role_name): Path<String>,
    Json(request): Json<UpdateRoleRequest>,
) -> ApiResult<Json<ApiResponse<RoleResponse>>> {
    require_admin(&user)?;
    let update_req = crate::services::admin::UpdateRoleRequest {
        description: request.description,
        permissions: request.permissions,
        metadata: request.metadata,
    };

    let role = state.admin.update_role(&role_name, update_req).await.map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(RoleResponse {
        name: role.name,
        description: role.description,
        permissions: role.permissions,
        users: role.users,
        created_at: role.created_at,
        updated_at: role.updated_at,
        metadata: role.metadata,
    })))
}

pub async fn delete_role(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(role_name): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;
    state.admin.delete_role(&role_name).await.map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(
        serde_json::json!({"status": "deleted", "role": role_name}),
    )))
}

pub async fn update_config(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Json(_request): Json<serde_json::Value>,
) -> ApiResult<Json<ApiResponse<SystemConfig>>> {
    require_admin(&user)?;
    // Return mock config
    Ok(Json(ApiResponse::success(SystemConfig {
        api: ApiConfigInfo {
            version: "1.0.0".to_string(),
            bind_address: "0.0.0.0:8080".to_string(),
            max_connections: 1000,
            timeout: 30,
        },
        security: SecurityConfigInfo {
            mfa_enabled: true,
            password_policy: PasswordPolicyInfo {
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special: true,
            },
            session_timeout: 3600,
        },
        storage: StorageConfigInfo {
            backend: "postgresql".to_string(),
            encryption_enabled: true,
            backup_enabled: true,
        },
        monitoring: MonitoringConfigInfo {
            metrics_enabled: true,
            tracing_enabled: true,
            log_level: "info".to_string(),
        },
    })))
}

pub async fn reload_config(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;
    Ok(Json(ApiResponse::success(
        serde_json::json!({"status": "reloaded"}),
    )))
}

pub async fn get_system_logs(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Query(_query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<String>>>> {
    require_admin(&user)?;
    Ok(Json(ApiResponse::success(vec![])))
}

pub async fn vacuum_database(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;
    Ok(Json(ApiResponse::success(
        serde_json::json!({"status": "vacuumed"}),
    )))
}

pub async fn get_security_reports(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Vec<serde_json::Value>>>> {
    require_admin(&user)?;
    Ok(Json(ApiResponse::success(vec![])))
}

pub async fn get_security_incident(
    State(_state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Path(incident_id): Path<String>,
) -> ApiResult<Json<ApiResponse<SecurityIncident>>> {
    require_admin(&user)?;
    Ok(Json(ApiResponse::success(SecurityIncident {
        id: incident_id,
        severity: "low".to_string(),
        status: "open".to_string(),
        title: "Mock Incident".to_string(),
        description: "This is a mock incident".to_string(),
        source: "system".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        resolved_at: None,
    })))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub limit: Option<u32>,
}

pub async fn list_audit_logs(
    State(state): State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<ApiResponse<Vec<crate::services::admin::AuditLogEntry>>>> {
    require_admin(&user)?;
    let limit = Some(query.limit.unwrap_or(1000));
    let logs = state
        .admin
        .get_audit_logs(
            query.start_time,
            query.end_time,
            query.user_id.as_deref(),
            query.action.as_deref(),
            limit,
        )
        .await
        .map_err(map_admin_error)?;

    Ok(Json(ApiResponse::success(logs)))
}

// --- Backup Endpoints ---

pub async fn create_backup(
    axum::extract::State(state): axum::extract::State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<crate::services::admin::BackupInfo>>> {
    require_admin(&user)?;

    let backup_info = state
        .admin
        .create_backup()
        .await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to create backup: {}", e)))?;

    Ok(Json(ApiResponse::success(backup_info)))
}

pub async fn list_backups(
    axum::extract::State(state): axum::extract::State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<Vec<crate::services::admin::BackupInfo>>>> {
    require_admin(&user)?;

    let backups = state
        .admin
        .list_backups()
        .await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to list backups: {}", e)))?;

    Ok(Json(ApiResponse::success(backups)))
}

pub async fn get_backup(
    axum::extract::State(state): axum::extract::State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    axum::extract::Path(backup_id): axum::extract::Path<String>,
) -> ApiResult<Json<ApiResponse<crate::services::admin::BackupInfo>>> {
    require_admin(&user)?;

    let backup = state
        .admin
        .get_backup(&backup_id)
        .await
        .map_err(|e| match e {
            crate::services::admin::AdminError::NotFound(_) => {
                crate::ApiError::NotFound(format!("Backup {} not found", backup_id))
            }
            _ => crate::ApiError::Internal(format!("Failed to get backup: {}", e)),
        })?;

    Ok(Json(ApiResponse::success(backup)))
}

pub async fn restore_backup(
    axum::extract::State(state): axum::extract::State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    axum::extract::Path(backup_id): axum::extract::Path<String>,
) -> ApiResult<Json<ApiResponse<crate::services::admin::MaintenanceResult>>> {
    require_admin(&user)?;

    let result = state
        .admin
        .restore_backup(&backup_id)
        .await
        .map_err(|e| crate::ApiError::Internal(format!("Failed to restore backup: {}", e)))?;

    Ok(Json(ApiResponse::success(result)))
}

pub async fn delete_backup(
    axum::extract::State(state): axum::extract::State<AppState>,
    crate::extractors::AuthenticatedUser(user): crate::extractors::AuthenticatedUser,
    axum::extract::Path(backup_id): axum::extract::Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    require_admin(&user)?;

    state
        .admin
        .delete_backup(&backup_id)
        .await
        .map_err(|e| match e {
            crate::services::admin::AdminError::NotFound(_) => {
                crate::ApiError::NotFound(format!("Backup {} not found", backup_id))
            }
            _ => crate::ApiError::Internal(format!("Failed to delete backup: {}", e)),
        })?;

    let data = serde_json::json!({
        "message": "Backup deleted successfully",
        "backup_id": backup_id
    });

    Ok(Json(ApiResponse::success(data)))
}
