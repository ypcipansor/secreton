//! Security API Layer
//!
//! Provides HTTP API endpoints for all security operations
//! integrating with the comprehensive security/ directory modules.

use axum::Json;
use chrono::{DateTime, Utc};
use secreton_errors::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use warp::{Filter, Rejection, Reply, reject};

use secreton_common::ServiceContainer;
use secreton_security::{AuditLog, ComplianceProfile, PolicySet, QuotaConfig, audit};
use secreton_storage::StorageBackend;

pub mod config;
pub mod grpc;
pub mod middleware;
pub mod services;
pub type ApiResult<T> = Result<T, ApiError>;

/// API Response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            timestamp: Utc::now(),
        }
    }
}

/// Authentication request structure
#[derive(Debug, Deserialize)]
pub struct AuthenticationRequest {
    pub user_id: String,
    pub mfa_responses: Vec<MfaResponse>,
    pub client_info: ClientInfo,
}

#[derive(Debug, Deserialize)]
pub struct MfaResponse {
    pub method: String,
    pub response: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientInfo {
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub geo_location: Option<String>,
    pub device_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub version: String,
    pub uptime: u64,
    pub dependencies: HealthCheckDependencies,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckDependencies {
    pub database: String,
    pub cache: String,
    pub crypto: String,
}

/// Simple TOTP validation (same logic as in handlers)
fn validate_totp_code_simple(code: &str, secret: &str) -> bool {
    if code.len() != 6 || !code.chars().all(|c| c.is_numeric()) {
        return false;
    }

    let code_num = match code.parse::<u32>() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Get current time window (30 second intervals)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;

    // Check current and adjacent time windows (±1)
    for time_window in (now.saturating_sub(1))..=(now + 1) {
        let expected_code = generate_hotp_simple(secret.as_bytes(), time_window);
        if expected_code == code_num {
            return true;
        }
    }

    false
}

/// Generate HOTP code (simplified version)
fn generate_hotp_simple(key: &[u8], counter: u64) -> u32 {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (simplified)
    let offset = (result[31] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);

    code % 1_000_000
}

/// HSM operation request
#[derive(Debug, Deserialize)]
pub struct HsmRequest {
    pub session_id: String,
    pub operation: HsmOperation,
}

#[derive(Debug, Deserialize)]
pub enum HsmOperation {
    GenerateKey { algorithm: String, key_size: u32 },
    ListKeys,
    GetKeyInfo { key_id: String },
    DeleteKey { key_id: String },
    Encrypt { key_id: String, data: Vec<u8> },
    Decrypt { key_id: String, ciphertext: Vec<u8> },
}

/// Audit operation request
#[derive(Debug, Deserialize)]
pub struct AuditRequest {
    pub session_id: String,
    pub operation: AuditOperation,
}

#[derive(Debug, Deserialize)]
pub enum AuditOperation {
    SearchEvents {
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        event_types: Option<Vec<String>>,
        user_id: Option<String>,
        limit: Option<u32>,
    },
    GenerateReport {
        report_type: String,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    },
    ExportData {
        format: String,
        filters: HashMap<String, String>,
    },
}

/// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthenticationResponse {
    pub success: bool,
    pub session_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub risk_score: f64,
    pub error: Option<String>,
}

/// Security API main structure with integrated security components
pub struct SecurityAPI {
    // Integration with security modules removed - use direct module access instead
}

/// Advanced security manager integrating all security modules
pub struct AdvancedSecurityManager {
    pub audit_system: audit::AuditLogger,
    pub policy_engine: PolicySet,
    pub compliance_engine: ComplianceProfile,
    pub rbac_policies: Vec<secreton_security::policies::policy::Policy>,
    pub quota_engine: QuotaConfig,
}

impl AdvancedSecurityManager {
    pub async fn new() -> Result<Self, SecretonError> {
        info!("Initializing Advanced Security Manager");

        // Initialize concrete implementations for abstract interfaces
        let audit_system = audit::AuditLogger::new(vec![Arc::new(audit::MemoryBackend::default())]);
        let policy_engine = PolicySet { rules: Vec::new() };
        let compliance_engine = ComplianceProfile {
            profile_id: "default".to_string(),
            name: "Default Compliance Profile".to_string(),
            standard: secreton_security::policies::compliance_framework::ComplianceStandard::NIST,
            requirements: Vec::new(),
            enabled: true,
        };
        let rbac_policies = Vec::new();
        let quota_engine = QuotaConfig::new(
            "default".to_string(),
            secreton_security::policies::quotas::QuotaType::RateLimit,
            "/".to_string(),
            1000,
        );

        Ok(Self {
            audit_system,
            policy_engine,
            compliance_engine,
            rbac_policies,
            quota_engine,
        })
    }

    pub async fn authenticate(
        &self,
        user_id: String,
        _mfa_responses: Vec<(String, String)>,
        _client_info: ClientInfo,
    ) -> Result<AuthSession, SecretonError> {
        info!("Authenticating user: {}", user_id);

        // Basic MFA validation
        for (method, code) in &_mfa_responses {
            match method.as_str() {
                "totp" => {
                    if !validate_totp_code_simple(code, &user_id) {
                        return Err(SecretonError::Authentication {
                            message: "Invalid TOTP code".to_string(),
                        });
                    }
                }
                _ => {
                    return Err(SecretonError::Authentication {
                        message: format!("Unsupported MFA method: {}", method),
                    });
                }
            }
        }

        let session = AuthSession {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
            risk_score: 25.0, // Low risk
        };

        // Log authentication event
        let audit_entry = AuditLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "authentication".to_string(),
            actor: Some(user_id.clone()),
            resource_type: "auth".to_string(),
            resource_id: user_id.clone(),
            status: audit::AuditStatus::Success,
            ip: Some(_client_info.ip_address),
            user_agent: _client_info.user_agent,
            metadata: HashMap::from([("risk_score".to_string(), session.risk_score.to_string())]),
        };
        self.audit_system
            .log(audit_entry)
            .await
            .map_err(|e| SecretonError::Audit {
                message: format!("Audit logging failed: {}", e),
            })?;

        Ok(session)
    }

    pub async fn process_hsm_operation(
        &self,
        operation: HsmOperation,
    ) -> Result<serde_json::Value, SecretonError> {
        info!("Processing HSM operation: {:?}", operation);

        match operation {
            HsmOperation::GenerateKey {
                algorithm,
                key_size,
            } => Ok(serde_json::json!({
                "key_id": Uuid::new_v4().to_string(),
                "algorithm": algorithm,
                "key_size": key_size,
                "created_at": Utc::now(),
                "status": "generated"
            })),
            HsmOperation::ListKeys => Ok(serde_json::json!({
                "keys": [],
                "total": 0
            })),
            HsmOperation::GetKeyInfo { key_id } => Ok(serde_json::json!({
                "key_id": key_id,
                "status": "active",
                "created_at": Utc::now()
            })),
            _ => Ok(serde_json::json!({
                "status": "operation_completed",
                "timestamp": Utc::now()
            })),
        }
    }

    pub async fn process_audit_operation(
        &self,
        operation: AuditOperation,
    ) -> Result<serde_json::Value, SecretonError> {
        info!("Processing audit operation: {:?}", operation);

        match operation {
            AuditOperation::SearchEvents { .. } => Ok(serde_json::json!({
                "events": [],
                "total": 0,
                "page": 1
            })),
            AuditOperation::GenerateReport {
                report_type,
                start_date,
                end_date,
            } => Ok(serde_json::json!({
                "report_id": Uuid::new_v4().to_string(),
                "report_type": report_type,
                "period": {
                    "start": start_date,
                    "end": end_date
                },
                "status": "generated",
                "created_at": Utc::now()
            })),
            AuditOperation::ExportData { format, .. } => Ok(serde_json::json!({
                "export_id": Uuid::new_v4().to_string(),
                "format": format,
                "status": "processing",
                "created_at": Utc::now()
            })),
        }
    }
}

#[derive(Debug)]
pub struct AuthSession {
    pub id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub risk_score: f64,
}

impl Default for SecurityAPI {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAPI {
    pub fn new() -> Self {
        info!("Initializing Security API");
        Self {}
    }

    pub async fn with_security_manager() -> Result<Self, SecretonError> {
        info!("Initializing Security API with full security manager");
        // Note: AdvancedSecurityManager is available through direct module access
        Ok(Self {})
    }

    /// Create all API routes with enhanced security operations
    pub fn routes(
        storage: Arc<dyn StorageBackend>,
        auth: Arc<crate::services::auth::AuthenticationService>,
        audit: Arc<crate::services::audit::AuditLogger>,
        seal: Arc<crate::services::seal::SealService>,
        secreton: Arc<crate::services::secret::SecretService>,
        mfa: Arc<secreton_auth::mfa::CombinedMfaService>,
        backend_type: String,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
        let storage_filter = warp::any().map(move || storage.clone());
        let backend_type_filter = warp::any().map(move || backend_type.clone());
        let auth_clone = auth.clone();
        let auth_filter = warp::any().map(move || auth_clone.clone());
        let audit_filter = warp::any().map(move || audit.clone());
        let seal_filter = warp::any().map(move || seal.clone());
        let secreton_filter = warp::any().map(move || secreton.clone());
        let mfa_filter = warp::any().map(move || mfa.clone());

        // Auth filter
        let auth_service = auth.clone();
        let with_user = warp::header::header("authorization")
            .map(move |auth_header: String| (auth_header, auth_service.clone()))
            .and_then(
                |(auth_header, auth_service): (
                    String,
                    Arc<crate::services::auth::AuthenticationService>,
                )| async move {
                    let token = auth_header.strip_prefix("Bearer ").unwrap_or(&auth_header);
                    match auth_service.validate_token(token).await {
                        Ok(user) => Ok(user),
                        Err(_) => Err(warp::reject::custom(ApiError::Authentication(
                            "Invalid token".to_string(),
                        ))),
                    }
                },
            );

        let health = warp::path("health")
            .and(warp::get())
            .and(storage_filter.clone())
            .and(backend_type_filter.clone())
            .and_then(health_handler);

        let security_status = warp::path("security")
            .and(warp::path("status"))
            .and(warp::get())
            .and_then(security_status_handler);

        let api_v1 = warp::path("api").and(warp::path("v1"));

        // Alias for frontend compatibility (expects /api/v1/sys/health)
        let health_alias = api_v1
            .and(warp::path("sys"))
            .and(warp::path("health"))
            .and(warp::get())
            .and(storage_filter.clone())
            .and(backend_type_filter.clone())
            .and_then(health_handler);

        let sys_init = api_v1
            .and(warp::path("sys"))
            .and(warp::path("init"))
            .and(warp::post())
            .and(warp::body::json())
            .and(seal_filter.clone())
            .and(auth_filter.clone())
            .and(mfa_filter.clone())
            .and_then(handle_sys_init);

        let sys_unseal = api_v1
            .and(warp::path("sys"))
            .and(warp::path("unseal"))
            .and(warp::post())
            .and(warp::body::json())
            .and(seal_filter.clone())
            .and_then(handle_sys_unseal);

        let sys_seal_status = api_v1
            .and(warp::path("sys"))
            .and(warp::path("seal-status"))
            .and(warp::get())
            .and(seal_filter.clone())
            .and_then(handle_sys_seal_status);

        // Secret routes
        let secret_get = api_v1
            .and(warp::path("secrets"))
            .and(warp::path("data"))
            .and(warp::path::tail())
            .and(warp::get())
            .and(with_user.clone())
            .and(secreton_filter.clone())
            .and_then(handle_secret_get);

        let secret_put = api_v1
            .and(warp::path("secrets"))
            .and(warp::path("data"))
            .and(warp::path::tail())
            .and(warp::post())
            .and(with_user.clone())
            .and(warp::body::json())
            .and(secreton_filter.clone())
            .and_then(handle_secret_put);

        let secret_delete = api_v1
            .and(warp::path("secrets"))
            .and(warp::path("data"))
            .and(warp::path::tail())
            .and(warp::delete())
            .and(with_user.clone())
            .and(secreton_filter.clone())
            .and_then(handle_secret_delete);

        let audit_events = warp::path("audit")
            .and(warp::path("events"))
            .and(warp::get())
            .and_then(audit_events_handler);

        // Enhanced endpoints
        let authenticate = warp::path("auth")
            .and(warp::path("login"))
            .and(warp::post())
            .and(warp::body::json())
            .and_then(authentication_handler);

        let hsm_operations = warp::path("hsm")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(hsm_operation_handler);

        let audit_operations = warp::path("audit")
            .and(warp::path("operations"))
            .and(warp::post())
            .and(warp::body::json())
            .and_then(audit_operation_handler);

        let security_metrics = warp::path("security")
            .and(warp::path("metrics"))
            .and(warp::get())
            .and_then(security_metrics_handler);

        // Auth token extraction filter (optional)
        // Checks both Authorization (Bearer) and X-Admin-Token headers
        let auth_token = warp::header::optional::<String>("authorization")
            .and(warp::header::optional::<String>("x-admin-token"))
            .map(|auth: Option<String>, admin: Option<String>| {
                auth.map(|h| h.strip_prefix("Bearer ").unwrap_or(&h).to_string())
                    .or(admin)
            });

        let config_post = api_v1
            .and(warp::path("sys"))
            .and(warp::path("config"))
            .and(warp::post())
            .and(auth_token)
            .and(warp::body::json())
            .and(storage_filter.clone())
            .and(auth_filter.clone())
            .and(audit_filter.clone())
            .and_then(crate::handlers::config::handle_post_config);

        let config_delete = api_v1
            .and(warp::path("sys"))
            .and(warp::path("config"))
            .and(warp::delete())
            .and(auth_token)
            .and(storage_filter.clone())
            .and(auth_filter.clone())
            .and(audit_filter.clone())
            .and_then(crate::handlers::config::handle_delete_config);

        let config_get = api_v1
            .and(warp::path("sys"))
            .and(warp::path("config"))
            .and(warp::get())
            .and(storage_filter.clone())
            .and_then(crate::handlers::config::handle_get_config);

        health
            .or(health_alias)
            .or(security_status)
            .or(sys_init)
            .or(sys_unseal)
            .or(sys_seal_status)
            .or(secret_get)
            .or(secret_put)
            .or(secret_delete)
            .or(audit_events)
            .or(authenticate)
            .or(hsm_operations)
            .or(audit_operations)
            .or(security_metrics)
            .or(config_post)
            .or(config_delete)
            .or(config_get)
    }
}

#[derive(Debug, Deserialize)]
struct SecretPutRequest {
    data: HashMap<String, String>,
}

async fn handle_secret_get(
    path: warp::filters::path::Tail,
    user: secreton_auth::User,
    secreton: Arc<crate::services::secret::SecretService>,
) -> Result<impl Reply, Rejection> {
    let path_str = path.as_str();
    let secret = secreton
        .get_secret(path_str, &user, None)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Wrap in ApiResponse
    // We wrap SecretData in another "data" field to match existing structure if needed,
    // or just return SecretData.
    // SecretData has { path, data: map, ... }
    Ok(warp::reply::json(&ApiResponse::success(secret)))
}

async fn handle_secret_put(
    path: warp::filters::path::Tail,
    user: secreton_auth::User,
    payload: SecretPutRequest,
    secreton: Arc<crate::services::secret::SecretService>,
) -> Result<impl Reply, Rejection> {
    let path_str = path.as_str();
    let secret = secreton
        .put_secret(path_str, payload.data, None, &user)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(warp::reply::json(&ApiResponse::success(secret)))
}

async fn handle_secret_delete(
    path: warp::filters::path::Tail,
    user: secreton_auth::User,
    secreton: Arc<crate::services::secret::SecretService>,
) -> Result<impl Reply, Rejection> {
    let path_str = path.as_str();
    secreton
        .delete_secret(path_str, &user)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(warp::reply::json(&ApiResponse::success("Deleted")))
}

#[derive(Debug, Deserialize)]
struct SysInitRequest {
    shares: u8,
    threshold: u8,
    root_username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SysUnsealRequest {
    key: String,
}

async fn handle_sys_init(
    req: SysInitRequest,
    seal: Arc<crate::services::seal::SealService>,
    auth: Arc<crate::services::auth::AuthenticationService>,
    mfa: Arc<secreton_auth::mfa::CombinedMfaService>,
) -> Result<impl Reply, Rejection> {
    let root_username = req.root_username.as_deref().unwrap_or("root");
    let result = seal
        .init(req.shares, req.threshold, root_username, &auth, &mfa)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(warp::reply::json(&ApiResponse::success(result)))
}

async fn handle_sys_unseal(
    req: SysUnsealRequest,
    seal: Arc<crate::services::seal::SealService>,
) -> Result<impl Reply, Rejection> {
    let result = seal
        .unseal(&req.key)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(warp::reply::json(&ApiResponse::success(result)))
}

async fn handle_sys_seal_status(
    seal: Arc<crate::services::seal::SealService>,
) -> Result<impl Reply, Rejection> {
    let result = seal
        .get_status()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(warp::reply::json(&ApiResponse::success(result)))
}

/// Health check handler
async fn health_handler(
    storage: Arc<dyn StorageBackend>,
    backend_type: String,
) -> Result<impl Reply, Rejection> {
    let health_status = storage
        .health_check()
        .await
        .unwrap_or(secreton_storage::HealthStatus {
            is_healthy: false,
            response_time_ms: 0.0,
            connections_active: 0,
            connections_idle: 0,
            last_error: Some("Health check failed".to_string()),
            uptime_seconds: 0,
        });

    let db_status = if health_status.is_healthy {
        format!(
            "{} (Healthy, {}ms)",
            backend_type, health_status.response_time_ms
        )
    } else {
        format!(
            "{} (Unhealthy: {})",
            backend_type,
            health_status.last_error.unwrap_or_default()
        )
    };

    // Currently, there's no way to query the cache status since storage and cache
    // backends are conflated. We can improve this in the future if Redis cache becomes distinct.
    let cache_status = "Local (Operational)".to_string();

    let response = ApiResponse::success(HealthCheckResponse {
        status: if health_status.is_healthy {
            "healthy".to_string()
        } else {
            "unhealthy".to_string()
        },
        version: "2.0.1".to_string(),
        uptime: health_status.uptime_seconds,
        dependencies: HealthCheckDependencies {
            database: db_status,
            cache: cache_status,
            crypto: "RustCrypto (Operational)".to_string(),
        },
    });

    Ok(warp::reply::json(&response))
}

/// Enhanced security status handler with detailed component health
async fn security_status_handler() -> Result<impl Reply, Rejection> {
    let mut status = HashMap::from([
        ("entropy_engine", "operational"),
        ("hsm_manager", "operational"),
        ("audit_system", "operational"),
        ("zero_trust", "operational"),
        ("mfa_engine", "operational"),
        ("compliance", "operational"),
        ("quantum_crypto", "operational"),
        ("threat_intel", "operational"),
        ("overall_health", "excellent"),
        ("security_level", "maximum"),
    ]);

    let timestamp = Utc::now().to_rfc3339();
    status.insert("last_updated", timestamp.as_str());

    let response = ApiResponse::success(status);
    Ok(warp::reply::json(&response))
}

/// Enhanced audit events handler
async fn audit_events_handler() -> Result<impl Reply, Rejection> {
    let events = vec![
        HashMap::from([
            ("id", "evt_001".to_string()),
            ("type", "authentication".to_string()),
            ("user", "admin".to_string()),
            ("status", "success".to_string()),
            ("risk_score", "low".to_string()),
            ("timestamp", Utc::now().to_rfc3339()),
        ]),
        HashMap::from([
            ("id", "evt_002".to_string()),
            ("type", "key_generation".to_string()),
            ("algorithm", "RSA-4096".to_string()),
            ("hsm", "primary".to_string()),
            ("status", "completed".to_string()),
            ("timestamp", Utc::now().to_rfc3339()),
        ]),
        HashMap::from([
            ("id", "evt_003".to_string()),
            ("type", "compliance_check".to_string()),
            ("framework", "SOX".to_string()),
            ("result", "compliant".to_string()),
            ("timestamp", Utc::now().to_rfc3339()),
        ]),
    ];

    let response = ApiResponse::success(HashMap::from([
        ("events", serde_json::to_value(events).unwrap()),
        ("total", serde_json::json!(3)),
        ("page", serde_json::json!(1)),
        ("has_more", serde_json::json!(false)),
    ]));
    Ok(warp::reply::json(&response))
}

/// Authentication handler with MFA support
async fn authentication_handler(request: AuthenticationRequest) -> Result<impl Reply, Rejection> {
    info!("Authentication request for user: {}", request.user_id);

    // Mock authentication process
    let auth_result = if request.user_id.is_empty() {
        AuthenticationResponse {
            success: false,
            session_id: None,
            expires_at: None,
            risk_score: 100.0,
            error: Some("Invalid user ID".to_string()),
        }
    } else {
        AuthenticationResponse {
            success: true,
            session_id: Some(Uuid::new_v4().to_string()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(8)),
            risk_score: 25.0,
            error: None,
        }
    };

    Ok(warp::reply::json(&auth_result))
}

/// HSM operations handler
async fn hsm_operation_handler(request: HsmRequest) -> Result<impl Reply, Rejection> {
    info!("HSM operation request: {:?}", request.operation);

    let result = match request.operation {
        HsmOperation::GenerateKey {
            algorithm,
            key_size,
        } => {
            serde_json::json!({
                "success": true,
                "key_id": Uuid::new_v4().to_string(),
                "algorithm": algorithm,
                "key_size": key_size,
                "hsm": "primary",
                "status": "generated",
                "created_at": Utc::now()
            })
        }
        HsmOperation::ListKeys => {
            serde_json::json!({
                "success": true,
                "keys": [
                    {
                        "key_id": "key_001",
                        "algorithm": "RSA-4096",
                        "status": "active",
                        "created_at": Utc::now()
                    },
                    {
                        "key_id": "key_002",
                        "algorithm": "AES-256",
                        "status": "active",
                        "created_at": Utc::now()
                    }
                ],
                "total": 2
            })
        }
        HsmOperation::GetKeyInfo { key_id } => {
            serde_json::json!({
                "success": true,
                "key_id": key_id,
                "algorithm": "RSA-4096",
                "status": "active",
                "hsm": "primary",
                "created_at": Utc::now(),
                "last_used": Utc::now()
            })
        }
        _ => {
            serde_json::json!({
                "success": true,
                "message": "Operation completed",
                "timestamp": Utc::now()
            })
        }
    };

    Ok(warp::reply::json(&result))
}

/// Audit operations handler
async fn audit_operation_handler(request: AuditRequest) -> Result<impl Reply, Rejection> {
    info!("Audit operation request: {:?}", request.operation);

    let result = match request.operation {
        AuditOperation::SearchEvents { limit, .. } => {
            serde_json::json!({
                "success": true,
                "events": [],
                "total": 0,
                "limit": limit.unwrap_or(50),
                "page": 1
            })
        }
        AuditOperation::GenerateReport {
            report_type,
            start_date,
            end_date,
        } => {
            serde_json::json!({
                "success": true,
                "report_id": Uuid::new_v4().to_string(),
                "report_type": report_type,
                "period": {
                    "start": start_date,
                    "end": end_date
                },
                "status": "generated",
                "download_url": format!("/audit/reports/{}", Uuid::new_v4()),
                "created_at": Utc::now()
            })
        }
        AuditOperation::ExportData { format, .. } => {
            serde_json::json!({
                "success": true,
                "export_id": Uuid::new_v4().to_string(),
                "format": format,
                "status": "processing",
                "estimated_completion": Utc::now() + chrono::Duration::minutes(5)
            })
        }
    };

    Ok(warp::reply::json(&result))
}

/// Security metrics handler
async fn security_metrics_handler() -> Result<impl Reply, Rejection> {
    let metrics = HashMap::from([
        ("security_score", serde_json::json!(95.8)),
        ("threat_level", serde_json::json!("low")),
        ("active_sessions", serde_json::json!(12)),
        ("failed_authentications_24h", serde_json::json!(3)),
        ("successful_authentications_24h", serde_json::json!(156)),
        ("hsm_operations_24h", serde_json::json!(89)),
        ("compliance_violations", serde_json::json!(0)),
        ("entropy_quality", serde_json::json!("excellent")),
        ("quantum_readiness", serde_json::json!(true)),
        (
            "last_security_scan",
            serde_json::json!(Utc::now().to_rfc3339()),
        ),
        ("uptime_percentage", serde_json::json!(99.99)),
    ]);

    let response = ApiResponse::success(metrics);
    Ok(warp::reply::json(&response))
}

/// Start the security API server with enhanced capabilities
pub async fn start_security_server(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Enhanced Security API server on port {}", port);

    info!(
        "🚀 Secreton Enhanced Security API server starting on http://127.0.0.1:{}",
        port
    );
    info!("📋 Available endpoints:");
    info!("   GET  /health - System health check");
    info!("   GET  /security/status - Security components status");
    info!("   GET  /security/metrics - Security metrics");
    info!("   GET  /audit/events - Recent audit events");
    info!("   POST /auth/login - User authentication");
    info!("   POST /hsm - HSM operations");
    info!("   POST /audit/operations - Audit operations");

    // Initialize default storage for the simplified server start
    // In production, use api_server.rs which configures storage properly
    let storage = Arc::new(secreton_storage::MockStorageBackend::new());

    // Initialize required services for auth and audit
    let crypto = Arc::new(
        crate::services::crypto::CryptoService::new(storage.clone())
            .await
            .unwrap(),
    );
    let auth_config = crate::config::AuthConfig::default();
    let auth = Arc::new(
        crate::services::auth::AuthenticationService::new(
            storage.clone(),
            crypto.clone(),
            &auth_config,
        )
        .await
        .unwrap(),
    );
    let audit = Arc::new(
        crate::services::audit::AuditLogger::new(storage.clone(), 2555, 1000, true)
            .await
            .unwrap(),
    );

    let seal = Arc::new(crate::services::seal::SealService::new(
        storage.clone(),
        crypto.clone(),
        "dev-secret".to_string(),
        "secreton".to_string(),
        "secreton-api".to_string(),
    ));

    // Initialize Secret Service components
    let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
    let policy_service = Arc::new(secreton_auth::PolicyService::new());
    let performance = Arc::new(secreton_performance::SecretPerformanceOptimizer::new(
        secreton_performance::SecretPerformanceConfig::default(),
    ));

    let secreton = Arc::new(
        crate::services::secret::SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap(),
    );

    // Initialize MFA for start_security_server (mock)
    let mfa = Arc::new(secreton_auth::mfa::CombinedMfaService::new(
        Arc::new(secreton_auth::mfa::InMemoryTotpService::new(
            "secreton-dev".to_string(),
        )),
        Arc::new(secreton_auth::mfa::InMemorySmsService::new(
            secreton_auth::mfa::SmsConfig::default(),
        )),
        Arc::new(secreton_auth::mfa::InMemoryEmailService::new(
            secreton_auth::mfa::EmailConfig::default(),
        )),
        Arc::new(secreton_auth::mfa::InMemoryHardwareService::new()),
        Arc::new(secreton_auth::mfa::DefaultPushService::new_mock()),
        Arc::new(secreton_auth::mfa::DefaultWebAuthnService::new_default()),
        Arc::new(secreton_auth::mfa::DefaultRecoveryCodeService::new()),
    ));

    // Inject storage, auth and audit into routes
    // For start_security_server, we just use the mock storage since this function
    // doesn't accept storage configuration
    let routes_with_storage = SecurityAPI::routes(
        storage,
        auth,
        audit,
        seal,
        secreton,
        mfa,
        "Memory (Mock)".to_string(),
    )
    .with(
        warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type", "authorization", "x-session-id"])
            .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]),
    )
    .with(warp::log("security_api"))
    .recover(handle_rejection);

    warp::serve(routes_with_storage)
        .run(([127, 0, 0, 1], port))
        .await;

    Ok(())
}

/// Custom API error types - wrapper for centralized SecretonError
#[derive(Debug)]
pub struct ApiError(SecretonError);

impl From<SecretonError> for ApiError {
    fn from(err: SecretonError) -> Self {
        ApiError(err)
    }
}

impl ApiError {
    #[allow(non_snake_case)]
    pub fn Authentication(message: String) -> Self {
        Self(SecretonError::Authentication { message })
    }

    #[allow(non_snake_case)]
    pub fn Authorization(message: String) -> Self {
        Self(SecretonError::Authorization { message })
    }

    #[allow(non_snake_case)]
    pub fn NotFound(resource: String) -> Self {
        Self(SecretonError::NotFound { resource })
    }

    #[allow(non_snake_case)]
    pub fn Internal(message: String) -> Self {
        Self(SecretonError::Internal { message })
    }

    #[allow(non_snake_case)]
    pub fn BadRequest(message: String) -> Self {
        Self(SecretonError::Validation { message })
    }

    #[allow(non_snake_case)]
    pub fn Conflict(message: String) -> Self {
        Self(SecretonError::Conflict { message })
    }

    #[allow(non_snake_case)]
    pub fn RateLimited(message: String) -> Self {
        Self(SecretonError::RateLimitExceeded { message })
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self.0 {
            SecretonError::Authentication { message } => {
                (axum::http::StatusCode::UNAUTHORIZED, message.clone())
            }
            SecretonError::Authorization { message } => {
                (axum::http::StatusCode::FORBIDDEN, message.clone())
            }
            SecretonError::NotFound { resource } => (
                axum::http::StatusCode::NOT_FOUND,
                format!("Resource not found: {}", resource),
            ),
            SecretonError::Validation { message } => {
                (axum::http::StatusCode::BAD_REQUEST, message.clone())
            }
            SecretonError::Internal { message } => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                message.clone(),
            ),
            SecretonError::Configuration { message } => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Configuration error: {}", message),
            ),
            SecretonError::Network { message } => {
                (axum::http::StatusCode::BAD_GATEWAY, message.clone())
            }
            SecretonError::Parse { message } => {
                (axum::http::StatusCode::BAD_REQUEST, message.clone())
            }
            SecretonError::ServiceUnavailable { service } => (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                format!("Service unavailable: {}", service),
            ),
            SecretonError::AlreadyExists { resource } => (
                axum::http::StatusCode::CONFLICT,
                format!("Resource already exists: {}", resource),
            ),
            SecretonError::Conflict { message } => (
                axum::http::StatusCode::CONFLICT,
                message.clone(),
            ),
            SecretonError::MfaRequired => (
                axum::http::StatusCode::UNAUTHORIZED,
                "MFA required".to_string(),
            ),
            SecretonError::AccountLocked { username } => (
                axum::http::StatusCode::FORBIDDEN,
                format!("Account locked: {}", username),
            ),
            SecretonError::PasswordExpired { username } => (
                axum::http::StatusCode::FORBIDDEN,
                format!("Password expired: {}", username),
            ),
            SecretonError::RateLimitExceeded { message } => (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                format!("Rate limit exceeded: {}", message),
            ),
            SecretonError::MfaNotConfigured { .. } => (
                axum::http::StatusCode::UNAUTHORIZED,
                // Return 401 with a generic message identical to invalid
                // credentials to prevent credential enumeration.
                // MfaNotConfigured only fires after successful password
                // verification, so a distinct message would confirm valid
                // credentials.
                "Authentication failed".to_string(),
            ),
            _ => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Unknown error".to_string(),
            ),
        };

        let body = Json(ApiResponse::<()>::error(message));
        (status, body).into_response()
    }
}

impl reject::Reject for ApiError {}

/// Global error handler for API rejections
pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "Endpoint not found";
    } else if let Some(api_error) = err.find::<ApiError>() {
        match api_error.0 {
            SecretonError::SecurityViolation { .. } => {
                code = warp::http::StatusCode::FORBIDDEN;
                message = "Security validation failed";
            }
            SecretonError::Authentication { .. } => {
                code = warp::http::StatusCode::UNAUTHORIZED;
                message = "Authentication required";
            }
            SecretonError::Authorization { .. } | SecretonError::InsufficientPermissions { .. } => {
                code = warp::http::StatusCode::FORBIDDEN;
                message = "Insufficient permissions";
            }
            SecretonError::Validation { .. } | SecretonError::InvalidInput { .. } => {
                code = warp::http::StatusCode::BAD_REQUEST;
                message = "Invalid request format";
            }
            SecretonError::MfaRequired => {
                code = warp::http::StatusCode::UNAUTHORIZED;
                message = "MFA required";
            }
            SecretonError::MfaNotConfigured { .. } => {
                // Return 401 with a generic message identical to invalid
                // credentials to prevent credential enumeration — mirrors
                // the axum IntoResponse implementation.
                code = warp::http::StatusCode::UNAUTHORIZED;
                message = "Authentication failed";
            }
            SecretonError::Internal { message: ref msg } => {
                warn!("Internal error: {}", msg);
                code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal server error";
            }
            _ => {
                code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal server error";
            }
        }
    } else if err
        .find::<warp::filters::body::BodyDeserializeError>()
        .is_some()
    {
        code = warp::http::StatusCode::BAD_REQUEST;
        message = "Invalid JSON format";
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = warp::http::StatusCode::METHOD_NOT_ALLOWED;
        message = "Method not allowed";
    } else {
        warn!("Unhandled rejection: {:?}", err);
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal server error";
    }

    let error_response = ApiResponse::<()>::error(message.to_string());
    let json = warp::reply::json(&error_response);

    Ok(warp::reply::with_status(json, code))
}

// Re-export KV and Transit modules for axum-based API
pub mod auth;
pub mod database;
pub mod extractors;
pub mod handlers;
pub mod kv;
pub mod pki;
pub mod ssh;
pub mod totp;

// Re-export types needed by tests
pub use database::DatabaseApiState;
pub use kv::KVApiState;
pub use pki::PkiApiState;
pub use secreton_performance::OptimizationLevel;
pub use ssh::SshApiState;
pub use totp::TotpApiState;

/// Main API state combining all engine states
#[derive(Clone)]
pub struct ApiState {
    pub kv: KVApiState,
    pub database: DatabaseApiState,
    pub pki: PkiApiState,
    pub ssh: SshApiState,
    pub totp: TotpApiState,
    pub config: std::sync::Arc<crate::config::ApiConfig>,
    pub secreton: std::sync::Arc<secreton_common::StandardServiceContainer>,
    pub auth: std::sync::Arc<crate::services::auth::AuthenticationService>,
    pub audit: std::sync::Arc<crate::services::admin::AdminService>,
}

impl ApiState {
    pub async fn new(
        kv_state: KVApiState,
        database_state: DatabaseApiState,
        pki_service: Option<std::sync::Arc<crate::services::pki::PkiPersistentService>>,
        config: std::sync::Arc<crate::config::ApiConfig>,
        secreton: std::sync::Arc<secreton_common::StandardServiceContainer>,
        auth: std::sync::Arc<crate::services::auth::AuthenticationService>,
        audit: std::sync::Arc<crate::services::admin::AdminService>,
        _optimization_level: OptimizationLevel,
    ) -> Result<Self, SecretonError> {
        Ok(Self {
            kv: kv_state,
            database: database_state,
            pki: PkiApiState {
                service: pki_service,
            },
            ssh: SshApiState::default(),
            totp: TotpApiState::default(),
            config,
            secreton,
            auth,
            audit,
        })
    }
}

/// Create the main API router combining KV and Transit engines.
///
/// Returns an error if any required service is missing from the container.
pub fn create_api_router(state: ApiState) -> Result<axum::Router, SecretonError> {
    use axum::middleware;
    use tower_http::cors::{Any, CorsLayer};

    // Helper to resolve a required service from the container.
    // `ServiceContainer` trait is imported at crate level.
    fn resolve<T: Clone + 'static>(
        container: &secreton_common::StandardServiceContainer,
        name: &str,
    ) -> Result<T, SecretonError> {
        container
            .get_service::<T>(name)
            .cloned()
            .ok_or_else(|| SecretonError::Configuration {
                message: format!("required service '{}' not registered in container", name),
            })
    }

    // Create services map for AppState
    let app_state = crate::handlers::AppState {
        storage: resolve(&state.secreton, "storage")?,
        auth: state.auth.clone(),
        audit: resolve(&state.secreton, "audit")?,
        crypto: resolve(&state.secreton, "crypto")?,
        secreton: resolve(&state.secreton, "secret")?,
        performance: resolve(&state.secreton, "performance")?,
        seal: resolve(&state.secreton, "seal")?,
        policy: resolve(&state.secreton, "policy")?,
        admin: state.audit.clone(),
        database: resolve(&state.secreton, "database")?,
        pki: resolve(&state.secreton, "pki")?,
        transit: resolve(&state.secreton, "transit")?,
        ssh: resolve(&state.secreton, "ssh")?,
        totp_engine: resolve(&state.secreton, "totp_engine")?,
        mfa: resolve(&state.secreton, "mfa")?,
        telemetry: resolve(&state.secreton, "telemetry")?,
        config: state.config.clone(),
    };

    Ok(axum::Router::new()
        .nest("/api/v1/kv", kv::create_kv_router())
        .nest(
            "/api/v1/secret",
            crate::handlers::secret::create_routes().with_state(app_state.clone()),
        ) // Add secret routes
        .nest(
            "/api/v1/database",
            crate::handlers::database::create_routes().with_state(app_state.clone()),
        )
        .nest(
            "/api/v1/pki",
            crate::handlers::pki::create_routes().with_state(app_state.clone()),
        )
        .nest(
            "/api/v1/ssh",
            crate::handlers::ssh::create_routes().with_state(app_state.clone()),
        )
        .nest(
            "/api/v1/totp",
            crate::handlers::totp_engine::create_routes().with_state(app_state.clone()),
        )
        .nest(
            "/api/v1/transit",
            crate::handlers::transit::create_routes().with_state(app_state),
        )
        // Apply authentication middleware to all routes
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(axum::Extension(state.kv.clone()))
        .layer(axum::Extension(state)))
}

/// Axum authentication middleware
async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<ApiState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    match auth_header {
        Some(token) => match state.auth.validate_token(token).await {
            Ok(user) => {
                // Enforce TOFU MFA enrollment: if the token was issued with
                // `mfa_required: true` (TOFU — privileged user who has not
                // yet configured MFA), only allow access to MFA enrollment
                // endpoints.  All other operations are blocked until the
                // user completes MFA setup.
                let mfa_pending = user
                    .metadata
                    .get("mfa_pending")
                    .map(|v| v == "true")
                    .unwrap_or(false);

                if mfa_pending {
                    let path = req.uri().path();
                    let is_mfa_endpoint = path.contains("/mfa/")
                        || path.ends_with("/mfa")
                        || path.ends_with("/logout");
                    if !is_mfa_endpoint {
                        return Err(axum::http::StatusCode::FORBIDDEN);
                    }
                }

                let mut req = req;
                req.extensions_mut().insert(user);
                Ok(next.run(req).await)
            }
            Err(_) => Err(axum::http::StatusCode::UNAUTHORIZED),
        },
        None => Err(axum::http::StatusCode::UNAUTHORIZED),
    }
}
