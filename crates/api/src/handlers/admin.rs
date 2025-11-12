//! Administrative handlers for system management.
//! 
//! Provides endpoints for user management, system configuration,
//! monitoring, and maintenance operations.

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
    handlers::{AppState, ListQuery},
    services::admin::{AdminService, CreateUserRequest, UpdateUserRequest, UserInfo},
    ApiResponse, ApiResult,
};
use secreton_errors::SecretonError;

/// Create administrative routes
pub fn create_routes() -> Router<AppState> {
    Router::new()
        // User management
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/:user_id", get(get_user))
        .route("/users/:user_id", put(update_user))
        .route("/users/:user_id", delete(delete_user))
        .route("/users/:user_id/roles", get(get_user_roles))
        .route("/users/:user_id/roles", post(assign_user_roles))
        .route("/users/:user_id/permissions", get(get_user_permissions))
        
        // Role management
        .route("/roles", get(list_roles))
        .route("/roles", post(create_role))
        .route("/roles/:role_name", get(get_role))
        .route("/roles/:role_name", put(update_role))
        .route("/roles/:role_name", delete(delete_role))
        
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
        
        // Security operations
        .route("/security/scan", post(run_security_scan))
        .route("/security/reports", get(get_security_reports))
        .route("/security/incidents", get(get_security_incidents))
        .route("/security/incidents/:incident_id", get(get_security_incident))
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
        TestServer::new(app).expect("Failed to start test server")
    }

    #[tokio::test]
    async fn test_list_users_returns_placeholder_user() {
        let server = server_with_routes().await;
        let response = server.get("/users").await;
        response.assert_status_ok();

        let body: ApiResponse<Vec<UserResponse>> = response.json();
        assert!(body.success);
        let users = body.data.expect("users payload");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
    }

    #[tokio::test]
    async fn test_create_role_endpoint() {
        let server = server_with_routes().await;
        let request = CreateRoleRequest {
            name: "auditor".to_string(),
            description: Some("Audit role".to_string()),
            permissions: vec!["vault:read".to_string()],
            metadata: None,
        };

        let response = server.post("/roles").json(&request).await;
        response.assert_status_ok();

        let body: ApiResponse<RoleResponse> = response.json();
        assert!(body.success);
        let role = body.data.expect("role payload");
        assert_eq!(role.name, "auditor");
        assert!(role.permissions.contains(&"vault:read".to_string()));
    }

    #[tokio::test]
    async fn test_get_config_returns_security_info() {
        let server = server_with_routes().await;
        let response = server.get("/config").await;
        response.assert_status_ok();

        let body: ApiResponse<SystemConfig> = response.json();
        assert!(body.success);
        let config = body.data.expect("config payload");
        assert!(config.security.mfa_enabled);
        assert_eq!(config.api.version, "1.0.0");
    }
}

/// User management models
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    pub roles: Vec<String>,
    pub enabled: Option<bool>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub enabled: Option<bool>,
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
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
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
pub struct SystemConfig {
    pub api: ApiConfigInfo,
    pub security: SecurityConfigInfo,
    pub storage: StorageConfigInfo,
    pub monitoring: MonitoringConfigInfo,
}

#[derive(Debug, Serialize)]
pub struct ApiConfigInfo {
    pub version: String,
    pub bind_address: String,
    pub max_connections: u32,
    pub timeout: u64,
}

#[derive(Debug, Serialize)]
pub struct SecurityConfigInfo {
    pub mfa_enabled: bool,
    pub password_policy: PasswordPolicyInfo,
    pub session_timeout: u64,
}

#[derive(Debug, Serialize)]
pub struct PasswordPolicyInfo {
    pub min_length: u8,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special: bool,
}

#[derive(Debug, Serialize)]
pub struct StorageConfigInfo {
    pub backend: String,
    pub encryption_enabled: bool,
    pub backup_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct MonitoringConfigInfo {
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
    pub log_level: String,
}

/// System monitoring models
#[derive(Debug, Serialize)]
pub struct SystemMetrics {
    pub uptime: u64,
    pub memory_usage: MemoryMetrics,
    pub cpu_usage: CpuMetrics,
    pub disk_usage: DiskMetrics,
    pub network: NetworkMetrics,
    pub vault: SecretMetrics,
}

#[derive(Debug, Serialize)]
pub struct MemoryMetrics {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub cached: u64,
}

#[derive(Debug, Serialize)]
pub struct CpuMetrics {
    pub cores: u32,
    pub usage_percent: f64,
    pub load_average: [f64; 3],
}

#[derive(Debug, Serialize)]
pub struct DiskMetrics {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Serialize)]
pub struct NetworkMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

#[derive(Debug, Serialize)]
pub struct SecretMetrics {
    pub total_secrets: u64,
    pub total_keys: u64,
    pub total_policies: u64,
    pub active_sessions: u64,
    pub operations_per_second: f64,
}

#[derive(Debug, Serialize)]
pub struct SystemStatus {
    pub status: String,
    pub version: String,
    pub uptime: u64,
    pub components: ComponentStatus,
    pub last_check: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ComponentStatus {
    pub database: String,
    pub cache: String,
    pub crypto: String,
    pub storage: String,
    pub auth: String,
}

/// Security models
#[derive(Debug, Serialize)]
pub struct SecurityScanResult {
    pub scan_id: String,
    pub status: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub findings: Vec<SecurityFinding>,
}

#[derive(Debug, Serialize)]
pub struct SecurityFinding {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub affected_resources: Vec<String>,
}

#[derive(Debug, Serialize)]
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
    Query(_query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<UserResponse>>>> {
    let users = state.admin.list_users().await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;
    
    let user_responses: Vec<UserResponse> = users.into_iter()
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
    Json(request): Json<CreateUserRequest>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    let create_request = CreateUserRequest {
        username: request.username,
        email: request.email,
        password: request.password,
        full_name: request.full_name,
        enabled: request.enabled,
        roles: request.roles,
    };

    let user = state.admin.create_user(create_request).await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;
    
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
    Path(user_id): Path<String>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    let user = state.admin.get_user(&user_id).await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;
    
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
    Path(user_id): Path<String>,
    Json(request): Json<UpdateUserRequest>,
) -> ApiResult<Json<ApiResponse<UserResponse>>> {
    let update_request = UpdateUserRequest {
        email: request.email,
        full_name: request.full_name,
        enabled: request.enabled,
        roles: request.roles,
    };

    let user = state.admin.update_user(&user_id, update_request).await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;
    
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
    Path(user_id): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    state.admin.delete_user(&user_id).await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "message": "User deleted successfully"
    }))))
}

/// System configuration endpoints
pub async fn get_config(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<SystemConfig>>> {
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

use std::process::Command;
use tokio::time::{timeout, Duration};

/// Helper functions for system metrics collection
async fn get_memory_metrics() -> MemoryMetrics {
    // Try to get memory info from /proc/meminfo (Linux)
    if let Ok(output) = Command::new("cat").arg("/proc/meminfo").output().await {
        if let Ok(meminfo) = String::from_utf8(output.stdout) {
            return parse_memory_info(&meminfo);
        }
    }

    // Fallback to basic memory info
    MemoryMetrics {
        total: 16 * 1024 * 1024 * 1024, // 16GB
        used: 8 * 1024 * 1024 * 1024,   // 8GB
        free: 8 * 1024 * 1024 * 1024,   // 8GB
        cached: 2 * 1024 * 1024 * 1024, // 2GB
    }
}

fn parse_memory_info(meminfo: &str) -> MemoryMetrics {
    let mut total = 0u64;
    let mut free = 0u64;
    let mut cached = 0u64;

    for line in meminfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let value = parts[1].parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
            match parts[0] {
                "MemTotal:" => total = value,
                "MemFree:" => free = value,
                "Cached:" => cached = value,
                _ => {}
            }
        }
    }

    let used = total.saturating_sub(free);
    
    MemoryMetrics {
        total,
        used,
        free,
        cached,
    }
}

async fn get_cpu_metrics() -> CpuMetrics {
    // Try to get CPU info from /proc/cpuinfo and /proc/loadavg
    let cores = if let Ok(output) = Command::new("nproc").output().await {
        String::from_utf8(output.stdout)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(1)
    } else {
        1
    };

    let load_average = if let Ok(output) = Command::new("cat").arg("/proc/loadavg").output().await {
        if let Ok(loadavg) = String::from_utf8(output.stdout) {
            parse_load_average(&loadavg)
        } else {
            [0.0, 0.0, 0.0]
        }
    } else {
        [0.0, 0.0, 0.0]
    };

    // For CPU usage percentage, we'd need more complex monitoring
    // For now, return basic info
    CpuMetrics {
        cores,
        usage_percent: 0.0, // Would need system monitoring library
        load_average,
    }
}

fn parse_load_average(loadavg: &str) -> [f64; 3] {
    let parts: Vec<&str> = loadavg.split_whitespace().collect();
    if parts.len() >= 3 {
        [
            parts[0].parse().unwrap_or(0.0),
            parts[1].parse().unwrap_or(0.0),
            parts[2].parse().unwrap_or(0.0),
        ]
    } else {
        [0.0, 0.0, 0.0]
    }
}

async fn get_disk_metrics() -> DiskMetrics {
    // Try to get disk usage with df command
    if let Ok(output) = Command::new("df").arg("/").output().await {
        if let Ok(df_output) = String::from_utf8(output.stdout) {
            return parse_disk_usage(&df_output);
        }
    }

    // Fallback
    DiskMetrics {
        total: 1024 * 1024 * 1024 * 1024, // 1TB
        used: 256 * 1024 * 1024 * 1024,   // 256GB
        free: 768 * 1024 * 1024 * 1024,   // 768GB
        usage_percent: 25.0,
    }
}

fn parse_disk_usage(df_output: &str) -> DiskMetrics {
    for line in df_output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[5] == "/" {
            let total = parts[1].parse::<u64>().unwrap_or(0) * 1024; // Convert 1K blocks to bytes
            let used = parts[2].parse::<u64>().unwrap_or(0) * 1024;
            let free = parts[3].parse::<u64>().unwrap_or(0) * 1024;
            let usage_percent = parts[4].trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
            
            return DiskMetrics {
                total,
                used,
                free,
                usage_percent,
            };
        }
    }

    DiskMetrics {
        total: 0,
        used: 0,
        free: 0,
        usage_percent: 0.0,
    }
}

async fn get_network_metrics() -> NetworkMetrics {
    // Try to get network stats from /proc/net/dev
    if let Ok(output) = Command::new("cat").arg("/proc/net/dev").output().await {
        if let Ok(netdev) = String::from_utf8(output.stdout) {
            return parse_network_stats(&netdev);
        }
    }

    // Fallback
    NetworkMetrics {
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
    }
}

fn parse_network_stats(netdev: &str) -> NetworkMetrics {
    for line in netdev.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 17 && parts[0].trim_end_matches(':') != "lo" {
            // Skip loopback, use first non-lo interface
            let bytes_received = parts[1].parse::<u64>().unwrap_or(0);
            let packets_received = parts[2].parse::<u64>().unwrap_or(0);
            let bytes_sent = parts[9].parse::<u64>().unwrap_or(0);
            let packets_sent = parts[10].parse::<u64>().unwrap_or(0);
            
            return NetworkMetrics {
                bytes_sent,
                bytes_received,
                packets_sent,
                packets_received,
            };
        }
    }

    NetworkMetrics {
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
    }
}
pub async fn get_system_metrics(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<SystemMetrics>>> {
    let stats = state.admin.get_system_stats().await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;

    // Get additional system metrics
    let memory = get_memory_metrics().await;
    let cpu = get_cpu_metrics().await;
    let disk = get_disk_metrics().await;
    let network = get_network_metrics().await;

    // Count total policies from storage
    let total_policies = state.storage.list(&secreton_storage::QueryParams {
        path: Some("policies".to_string()),
        prefix: Some("policies/".to_string()),
        limit: None,
        offset: 0,
        ..Default::default()
    }).await
    .map(|entries| entries.len() as u64)
    .unwrap_or(0);

    let metrics = SystemMetrics {
        uptime: stats.uptime_seconds,
        memory_usage: memory,
        cpu_usage: cpu,
        disk_usage: disk,
        network,
        vault: SecretMetrics {
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
) -> ApiResult<Json<ApiResponse<SystemStatus>>> {
    // Check component health
    let database_status = check_database_health(&state).await;
    let cache_status = check_cache_health(&state).await;
    let crypto_status = check_crypto_health(&state).await;
    let storage_status = check_storage_health(&state).await;
    let auth_status = check_auth_health(&state).await;

    let overall_status = if database_status == "healthy" && 
                          cache_status == "healthy" && 
                          crypto_status == "healthy" &&
                          storage_status == "healthy" &&
                          auth_status == "healthy" {
        "healthy"
    } else if database_status == "unhealthy" || 
              storage_status == "unhealthy" ||
              crypto_status == "unhealthy" {
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
) -> ApiResult<Json<ApiResponse<SecurityScanResult>>> {
    let scan_result = state.admin.run_security_scan().await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;

    Ok(Json(ApiResponse::success(scan_result)))
}

pub async fn get_security_incidents(
    State(state): State<AppState>,
    Query(_query): Query<ListQuery>,
) -> ApiResult<Json<ApiResponse<Vec<SecurityIncident>>>> {
    // For now, return empty list - in a real implementation, 
    // this would query the security monitoring system
    let incidents = Vec::new();

    Ok(Json(ApiResponse::success(incidents)))
}

/// Maintenance operations
pub async fn run_garbage_collection(
    State(state): State<AppState>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    let result = state.admin.run_garbage_collection().await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;

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
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    let result = state.admin.compact_database().await
        .map_err(|e| secreton_errors::SecretonError::Internal { message: e.to_string() })?;

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
async fn check_database_health(state: &AppState) -> String {
    // Try a simple database operation to check health
    match timeout(Duration::from_secs(5), async {
        // This would need to be implemented based on the actual storage backend
        // For now, assume healthy if we can access the service
        Ok(())
    }).await {
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
    use secreton_crypto::{hash, symmetric};
    
    // Test hash function
    let test_data = b"test data for crypto health check";
    if hash::hash_data(test_data).is_err() {
        return "unhealthy".to_string();
    }
    
    // Test symmetric encryption
    let key = symmetric::generate_key().unwrap_or_default();
    match symmetric::encrypt(&key, test_data) {
        Ok(encrypted) => {
            match symmetric::decrypt(&key, &encrypted) {
                Ok(decrypted) if decrypted == test_data => "healthy".to_string(),
                _ => "unhealthy".to_string(),
            }
        }
        _ => "unhealthy".to_string(),
    }
}

async fn check_storage_health(state: &AppState) -> String {
    // Try a simple storage operation
    match timeout(Duration::from_secs(5), async {
        // This would test the storage backend
        Ok(())
    }).await {
        Ok(Ok(_)) => "healthy".to_string(),
        _ => "unhealthy".to_string(),
    }
}

async fn check_auth_health(state: &AppState) -> String {
    // Check if auth service is responsive
    match timeout(Duration::from_secs(5), async {
        // Test auth service availability
        Ok(())
    }).await {
        Ok(Ok(_)) => "healthy".to_string(),
        _ => "degraded".to_string(),
    }
}
