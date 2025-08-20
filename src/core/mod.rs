use axum::{
    routing::{get, post, put, delete},
    Router,
    http::StatusCode,
    Json,
    extract::{State, Path},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum_prometheus::PrometheusMetricLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use utoipa::ToSchema;
use crate::routes::api;
use crate::core::AppState;
use crate::utils::error::AppError;
use crate::storage::StorageBackend;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crate::auth::AuthManager;
use crate::secrets::SecretManager;
use crate::utils::config::Config;
use metrics_exporter_prometheus::PrometheusHandle;
use crate::services::plugin::{PluginRegistry};
use hyper::StatusCode as HyperStatusCode;
use hyper::response::IntoResponse;
use serde::{Debug, Clone};
use std::sync::Mutex;
use chrono::Utc;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::io::{self, Write};
use std::path::Path;
use crate::secrets::auto_unseal_master_key;
use crate::services::audit::{AuditDevice, AuditDeviceType, DbAuditDevice, FileAuditDevice, log_audit, ExternalAuditDevice, WebhookAuditDevice, log_audit_external};
use crate::routes::api::{totp_generate, ssh_generate, cloud_secret_generate};
use bc_shamir::{combine_mnemonics, split_mnemonic};
use std::collections::HashMap;
use sha2::{Sha256, Digest};

lazy_static::lazy_static! {
    static ref APPROVAL_REQUESTS: Mutex<HashMap<String, ApprovalRequest>> = Mutex::new(HashMap::new());
    static ref AUDIT_HASHES: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub path: String,
    pub action: String,
    pub requested_by: String,
    pub approved_by: Vec<String>,
    pub required_approvals: u32,
    pub status: String, // pending/approved/rejected
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    pub request_id: String,
    pub approver: String,
}

#[derive(Serialize)]
pub struct ApproveResponse {
    pub status: String,
    pub request_id: String,
    pub approved_by: Vec<String>,
    pub required_approvals: u32,
}

pub async fn approve_control_group(Json(payload): Json<ApproveRequest>, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut store = APPROVAL_REQUESTS.lock().unwrap();
    let mut status = "not_found".to_string();
    let mut approved_by = vec![];
    let mut required_approvals = 0;
    if let Some(req) = store.get_mut(&payload.request_id) {
        if !req.approved_by.contains(&payload.approver) {
            req.approved_by.push(payload.approver.clone());
        }
        if req.approved_by.len() as u32 >= req.required_approvals {
            req.status = "approved".to_string();
        }
        status = req.status.clone();
        approved_by = req.approved_by.clone();
        required_approvals = req.required_approvals;
    }
    let _ = log_audit_external(&state.external_audit_devices, "approve_control_group", &payload.approver, &payload.request_id, &status).await;
    ApproveResponse {
        status,
        request_id: payload.request_id,
        approved_by,
        required_approvals,
    }
}

#[derive(Deserialize)]
pub struct StatusRequest {
    pub request_id: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: String,
    pub request_id: String,
    pub approved_by: Vec<String>,
    pub required_approvals: u32,
}

pub async fn status_control_group(Json(payload): Json<StatusRequest>) -> impl IntoResponse {
    let store = APPROVAL_REQUESTS.lock().unwrap();
    if let Some(req) = store.get(&payload.request_id) {
        StatusResponse {
            status: req.status.clone(),
            request_id: req.id.clone(),
            approved_by: req.approved_by.clone(),
            required_approvals: req.required_approvals,
        }
    } else {
        StatusResponse {
            status: "not_found".to_string(),
            request_id: payload.request_id,
            approved_by: vec![],
            required_approvals: 0,
        }
    }
}

mod plugins;
use plugins::dyn_password::DynPasswordPlugin;
use plugins::sops_file::SopsFilePlugin;
use plugins::kms::KmsPlugin;

#[derive(OpenApi)]
#[openapi(
    paths(
        login, get_secret, create_secret, update_secret, delete_secret, get_secret_versions,
        add_role, assign_role_to_user, add_policy_to_role, revoke_token,
        backup_data, restore_data, get_leader, health_check, list_plugins
    ),
    components(
        schemas(CreateSecretRequest, AddRoleRequest, AssignRoleRequest, AddPolicyRequest, RevokeTokenRequest, RestoreRequest)
    ),
    tags(
        (name = "Vault Adhyaksa API", description = "API for secure secret management")
    )
)]
pub struct ApiDoc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatus {
    pub mode: String,
    pub peers: Vec<String>,
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub node_id: String,
    pub is_active: bool,
    pub peers: Vec<String>,
    pub leader_id: Option<String>,
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    pub replication: Option<ReplicationStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealStatus {
    pub sealed: bool,
    pub auto_unseal: bool,
    pub recovery_key: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn StorageBackend>,
    pub auth_manager: Arc<AuthManager>,
    pub secret_manager: Arc<SecretManager>,
    pub config: Config,
    pub plugin_registry: Arc<PluginRegistry>,
    pub node_id: String,
    pub peers: Vec<String>,
    pub is_active: bool,
    pub cluster_status: Arc<Mutex<ClusterStatus>>,
    pub replication_mode: String,
    pub replication_peers: Vec<String>,
    pub replication_status: Arc<Mutex<ReplicationStatus>>,
    pub audit_devices: Arc<Vec<Box<dyn AuditDevice>>>,
    pub external_audit_devices: Arc<Vec<Box<dyn ExternalAuditDevice>>>,
    pub engine_registry: Arc<Mutex<HashMap<String, String>>>, // path -> engine_name
}

pub struct VaultServer {
    state: Arc<AppState>,
}

fn try_acquire_file_lock(lock_path: &str) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(lock_path)
}

impl VaultServer {
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let backend = config.backend.as_deref().unwrap_or("sqlite");
        let storage = crate::storage::StorageType::from_config(backend, &config.database_url).await?;
        let auth_manager = Arc::new(AuthManager::new(&config.jwt_secret, storage.clone())?);
        let secret_manager = Arc::new(SecretManager::new(&config.encryption_key).await?);
        let mut plugin_registry = PluginRegistry::new();
        let dyn_password = DynPasswordPlugin;
        dyn_password.register(&mut plugin_registry);
        let sops_file = SopsFilePlugin;
        sops_file.register(&mut plugin_registry);
        let kms = KmsPlugin;
        kms.register(&mut plugin_registry);
        // Daftarkan plugin stub secret engine
        plugin_registry.register_secret_engine("totp", Box::new(|| Box::new(|| async { /* TOTP stub */ }))); // stub
        plugin_registry.register_secret_engine("ssh", Box::new(|| Box::new(|| async { /* SSH stub */ }))); // stub
        plugin_registry.register_secret_engine("cloud", Box::new(|| Box::new(|| async { /* Cloud stub */ }))); // stub
        let plugin_registry = Arc::new(plugin_registry);
        let node_id = config.node_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let peers = config.peers.clone().unwrap_or_else(Vec::new);
        // File lock untuk leader election
        let lock_path = "/tmp/vault_adhyaksa_leader.lock";
        let is_active = match try_acquire_file_lock(lock_path) {
            Ok(mut file) => {
                file.set_len(0)?;
                file.write_all(node_id.as_bytes())?;
                true
            },
            Err(_) => false,
        };
        let leader_id = if is_active { Some(node_id.clone()) } else { None };
        let cluster_status = Arc::new(Mutex::new(ClusterStatus {
            node_id: node_id.clone(),
            is_active,
            peers: peers.clone(),
            leader_id: leader_id.clone(),
            last_heartbeat: Some(chrono::Utc::now()),
            replication: None,
        }));
        let replication_status = Arc::new(Mutex::new(ReplicationStatus {
            mode: "none".to_string(),
            peers: Vec::new(),
            last_sync: None,
            is_primary: false,
        }));
        // Inisialisasi audit devices
        let mut devices: Vec<Box<dyn AuditDevice>> = Vec::new();
        if let Some(cfg) = &config.audit_devices {
            for dev in cfg {
                if dev == "db" {
                    devices.push(Box::new(DbAuditDevice));
                } else if dev.starts_with("file:") {
                    let path = dev.trim_start_matches("file:").to_string();
                    devices.push(Box::new(FileAuditDevice { file: path }));
                }
                // Tambah syslog/socket jika perlu
            }
        } else {
            devices.push(Box::new(DbAuditDevice));
        }
        let audit_devices = Arc::new(devices);
        let mut external_audit_devices: Vec<Box<dyn ExternalAuditDevice>> = vec![];
        if let Some(devices) = &config.audit_devices {
            for dev in devices {
                if dev == "webhook" {
                    if let Some(url) = &config.webhook_audit_url {
                        external_audit_devices.push(Box::new(WebhookAuditDevice { url: url.clone() }));
                    }
                }
            }
        }
        let engine_registry = Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(AppState {
            storage,
            auth_manager,
            secret_manager,
            config,
            plugin_registry,
            node_id,
            peers,
            is_active,
            cluster_status,
            replication_mode: "none".to_string(),
            replication_peers: Vec::new(),
            replication_status,
            audit_devices,
            external_audit_devices: Arc::new(external_audit_devices),
            engine_registry,
        });
        // Background task: cek lock dan failover otomatis
        let state_bg = state.clone();
        tokio::spawn(async move {
            loop {
                let mut status = state_bg.cluster_status.lock().unwrap();
                let is_leader = try_acquire_file_lock(lock_path).is_ok();
                status.is_active = is_leader;
                if is_leader {
                    status.leader_id = Some(state_bg.node_id.clone());
                }
                drop(status);
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
        Ok(Self { state })
    }

    pub async fn start(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.create_router();
        
        info!("Starting server on {}", addr);
        
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let addr = format!("{}:{}", self.state.config.server_host, self.state.config.server_port);
        axum::Server::bind(&addr.parse().unwrap()).serve(app.into_make_service()).await?;
        
        Ok(())
    }

    fn create_router(&self) -> Router {
        Router::new()
            .route("/health", get(health_check))
            .route("/v1/auth/login", post(api::login))
            .route("/v1/auth/ldap/login", post(api::ldap_login))
            .route("/v1/auth/logout", post(logout))
            .route("/v1/auth/revoke", post(revoke_token))
            .route("/v1/auth/oidc/login", get(api::oidc_login))
            .route("/v1/auth/oidc/callback", get(api::oidc_callback))
            .route("/v1/secrets/:path", get(api::get_secret))
            .route("/v1/secrets/:path", post(api::create_secret))
            .route("/v1/secrets/:path", put(api::update_secret))
            .route("/v1/secrets/:path", delete(api::delete_secret))
            .route("/v1/secrets/:path/versions", get(api::get_secret_versions))
            .route("/v1/dynamic/db/:role", get(api::generate_dynamic_db_credential))
            .route("/v1/dynamic/aws/:role", get(api::generate_dynamic_aws_credential))
            .route("/v1/dynamic/{engine}/credential", post(api::generate_dynamic_credential))
            .route("/v1/dynamic/{engine}/credential", delete(api::revoke_dynamic_credential))
            .route("/v1/sys/init", post(init_vault))
            .route("/v1/sys/unseal", post(unseal_vault))
            .route("/v1/sys/leader", get(api::get_leader))
            .route("/v1/sys/health", get(api::health_check))
            .route("/v1/sys/ready", get(api::ready_check))
            .route("/v1/sys/backup", get(api::backup_data))
            .route("/v1/sys/restore", post(api::restore_data))
            .route("/v1/sys/seal_status", get(seal_status))
            .route("/v1/admin/roles", post(api::add_role))
            .route("/v1/admin/assign-role", post(api::assign_role_to_user))
            .route("/v1/admin/policies", post(api::add_policy_to_role))
            .route("/v1/lease/renew/:id", post(api::renew_lease))
            .route("/v1/lease/revoke/:id", post(api::revoke_lease))
            .route("/v1/auth/approle/role", post(api::generate_approle))
            .route("/v1/auth/approle/login", post(api::approle_login))
            .route("/v1/auth/approle/secret-id/rotate", post(api::rotate_approle_secret_id))
            .route("/v1/sys/plugins", get(list_plugins))
            .route("/v1/plugins/:name/:action", axum::routing::post(api::plugin_action))
            .route("/v1/cluster/status", get(cluster_status))
            .route("/v1/cluster/promote", post(promote_node))
            .route("/v1/cluster/heartbeat", post(cluster_heartbeat))
            .route("/v1/replication/status", get(replication_status))
            .route("/v1/replication/sync", post(sync_replication))
            .route("/v1/secret/totp/generate", post(totp_generate))
            .route("/v1/secret/ssh/generate", post(ssh_generate))
            .route("/v1/secret/cloud/generate", post(cloud_secret_generate))
            .route("/v1/sys/mount", post(mount_engine))
            .route("/v1/sys/unmount", post(unmount_engine))
            .route("/v1/sys/remount", post(remount_engine))
            .route("/v1/engine/:engine_path/:action", post(generic_engine_route))
            .route("/v1/sys/approve_control_group", post(approve_control_group))
            .route("/v1/sys/status_control_group", post(status_control_group))
            .route("/v1/sys/audit_hash", post(audit_hash))
            .route("/v1/sys/audit_verify", post(audit_verify))
            .with_state(self.state.clone())
    }

    pub fn create_router_with_metrics_and_docs(&self) -> (Router, PrometheusHandle) {
        let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();
        let swagger = SwaggerUi::new("/swagger-ui").url("/openapi.json", ApiDoc::openapi());
        let app = self.create_router()
            .layer(prometheus_layer)
            .route("/metrics", axum::routing::get(|| async move { metric_handle.render() }))
            .merge(SwaggerUi::new("/swagger-ui").into());
        (app, metric_handle)
    }
}

static RATE_LIMITER: once_cell::sync::Lazy<DashMap<String, (u32, Instant)>> = once_cell::sync::Lazy::new(DashMap::new);
const RATE_LIMIT: u32 = 5;
const RATE_WINDOW: Duration = Duration::from_secs(10);

fn check_rate_limit(ip: &str) -> bool {
    let now = Instant::now();
    let mut entry = RATE_LIMITER.entry(ip.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) > RATE_WINDOW {
        *entry = (1, now);
        false
    } else {
        if entry.0 >= RATE_LIMIT {
            true
        } else {
            entry.0 += 1;
            false
        }
    }
}

// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "healthy"}))
}

async fn ready_check(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ready": state.config.is_leader}))
}

// Authentication endpoints
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_in: i64,
}

async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let ip = addr.ip().to_string();
    if check_rate_limit(&ip) {
        return Err(AppError::TooManyRequests);
    }
    let username = payload.username.clone();
    match state.auth_manager.authenticate(&payload.username, &payload.password).await {
        Ok(token) => {
            let _ = state.storage.log_audit(&username, "login", "-", "success").await;
            Ok(Json(LoginResponse {
                token,
                expires_in: 3600, // 1 hour
            }))
        },
        Err(_) => {
            let _ = state.storage.log_audit(&username, "login", "-", "failed").await;
            Err(AppError::Unauthorized)
        },
    }
}

async fn logout() -> StatusCode {
    StatusCode::OK
}

// Dummy extract username from header (nanti bisa dari JWT claims)
fn extract_username_from_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers.get("x-username").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

async fn extract_username_and_validate_token(headers: &HeaderMap, storage: &std::sync::Arc<dyn StorageBackend>) -> Result<String, AppError> {
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if storage.is_token_valid(token).await.unwrap_or(false) {
                // TODO: extract username from JWT claims
                return Ok("admin".to_string()); // dummy: return admin jika token valid
            } else {
                return Err(AppError::Unauthorized);
            }
        }
    }
    Err(AppError::Unauthorized)
}

async fn rbac_guard(state: Arc<AppState>, username: &str, path: &str, action: &str) -> Result<(), AppError> {
    if state.storage.check_policy(username, path, action).await.unwrap_or(false) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

// Secret management endpoints
async fn get_secret(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let ip = addr.ip().to_string();
    if check_rate_limit(&ip) {
        return Err(AppError::TooManyRequests);
    }
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    rbac_guard(state.clone(), &username, &path, "read").await?;
    match state.secret_manager.get_secret(&path).await {
        Ok(secret) => {
            let _ = state.storage.log_audit(&username, "get_secret", &path, "success").await;
            Ok(Json(secret))
        },
        Err(_) => {
            let _ = state.storage.log_audit(&username, "get_secret", &path, "failed").await;
            Err(AppError::NotFound)
        },
    }
}

#[derive(Deserialize, ToSchema)]
struct CreateSecretRequest {
    data: serde_json::Value,
}

async fn create_secret(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Json(payload): Json<CreateSecretRequest>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    rbac_guard(state.clone(), &username, &path, "write").await?;
    // require_leader!(state);
    match state.secret_manager.create_secret(&path, &payload.data).await {
        Ok(version) => {
            let _ = state.storage.log_audit(&username, "create_secret", &path, "success").await;
            Ok(Json(serde_json::json!({"version": version})))
        },
        Err(_) => {
            let _ = state.storage.log_audit(&username, "create_secret", &path, "failed").await;
            Err(AppError::Internal)
        },
    }
}

async fn update_secret(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Json(payload): Json<CreateSecretRequest>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    rbac_guard(state.clone(), &username, &path, "write").await?;
    // require_leader!(state);
    match state.secret_manager.update_secret(&path, &payload.data).await {
        Ok(version) => {
            let _ = state.storage.log_audit(&username, "update_secret", &path, "success").await;
            Ok(Json(serde_json::json!({"version": version})))
        },
        Err(_) => {
            let _ = state.storage.log_audit(&username, "update_secret", &path, "failed").await;
            Err(AppError::Internal)
        },
    }
}

async fn delete_secret(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    rbac_guard(state.clone(), &username, &path, "delete").await?;
    // require_leader!(state);
    match state.secret_manager.delete_secret(&path).await {
        Ok(_) => {
            let _ = state.storage.log_audit(&username, "delete_secret", &path, "success").await;
            Ok(StatusCode::OK)
        },
        Err(_) => {
            let _ = state.storage.log_audit(&username, "delete_secret", &path, "failed").await;
            Err(AppError::Internal)
        },
    }
}

async fn get_secret_versions(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    rbac_guard(state.clone(), &username, &path, "read").await?;
    match state.secret_manager.get_secret_versions(&path).await {
        Ok(versions) => {
            let versions_json: Vec<_> = versions.into_iter().map(|(v, d)| serde_json::json!({"version": v, "data": d})).collect();
            let _ = state.storage.log_audit(&username, "get_secret_versions", &path, "success").await;
            Ok(Json(serde_json::json!({"versions": versions_json})))
        },
        Err(_) => {
            let _ = state.storage.log_audit(&username, "get_secret_versions", &path, "failed").await;
            Err(AppError::NotFound)
        },
    }
}

// System endpoints
#[derive(Deserialize)]
pub struct InitRequest {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

#[derive(Serialize)]
pub struct InitResponse {
    pub shares: Vec<String>,
    pub root_token: String,
}

pub async fn init_vault(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<InitRequest>,
) -> Result<Json<InitResponse>, StatusCode> {
    // Generate random master key
    use rand::RngCore;
    let mut master_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master_key);
    let master_key_hex = hex::encode(&master_key);
    // Split dengan Shamir
    let shares = split_mnemonic(&master_key_hex, payload.secret_shares as usize, payload.secret_threshold as usize)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Simpan hash master key di storage (dummy: plaintext, seharusnya hash)
    // TODO: Simpan ke storage backend
    // state.storage.set_vault_state(true, Some(master_key_hex.clone())).await?;
    // Generate root token
    let root_token = "hvs.root.token".to_string();
    // Audit event
    let _ = log_audit_external(&state.external_audit_devices, "init_vault", "system", "", "success").await;
    Ok(Json(InitResponse {
        shares,
        root_token,
    }))
}

lazy_static::lazy_static! {
    static ref UNSEAL_PROGRESS: Mutex<UnsealState> = Mutex::new(UnsealState::default());
}

#[derive(Default)]
pub struct UnsealState {
    pub shares: Vec<String>,
    pub threshold: usize,
    pub sealed: bool,
}

#[derive(Deserialize)]
pub struct UnsealRequest {
    pub share: String,
}

#[derive(Serialize)]
pub struct UnsealResponse {
    pub progress: usize,
    pub threshold: usize,
    pub sealed: bool,
    pub message: String,
}

pub async fn unseal_vault(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, StatusCode> {
    let mut progress = UNSEAL_PROGRESS.lock().unwrap();
    // TODO: threshold seharusnya diambil dari storage/init, sementara hardcode 3
    if progress.threshold == 0 {
        progress.threshold = 3;
        progress.sealed = true;
    }
    if !progress.sealed {
        return Ok(Json(UnsealResponse {
            progress: 0,
            threshold: progress.threshold,
            sealed: false,
            message: "Vault already unsealed".to_string(),
        }));
    }
    progress.shares.push(payload.share.clone());
    let status;
    match combine_mnemonics(&progress.shares) {
        Ok(master_key_hex) => {
            // TODO: Simpan master_key ke SecretManager, set sealed=false
            progress.sealed = false;
            progress.shares.clear();
            status = Ok(Json(UnsealResponse {
                progress: progress.threshold,
                threshold: progress.threshold,
                sealed: false,
                message: "Vault unsealed successfully".to_string(),
            }));
            let _ = log_audit_external(&state.external_audit_devices, "unseal_vault", "system", "", "success").await;
        }
        Err(_e) => {
            status = Err(StatusCode::BAD_REQUEST);
        }
    }
    status
} 

#[derive(Deserialize, ToSchema)]
struct AddRoleRequest {
    name: String,
}

async fn add_role(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddRoleRequest>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    if username != "admin" {
        return Err(AppError::Unauthorized);
    }
    sqlx::query("INSERT INTO roles (name) VALUES (?)")
        .bind(&payload.name)
        .execute(&state.storage.pool)
        .await
        .map_err(|_| AppError::Internal)?;
    Ok(Json(serde_json::json!({"role": payload.name})))
}

#[derive(Deserialize, ToSchema)]
struct AssignRoleRequest {
    username: String,
    role: String,
}

async fn assign_role_to_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AssignRoleRequest>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    if username != "admin" {
        return Err(AppError::Unauthorized);
    }
    state.storage.assign_role_to_user(&payload.username, &payload.role).await?;
    Ok(Json(serde_json::json!({"assigned": true})))
}

#[derive(Deserialize, ToSchema)]
struct AddPolicyRequest {
    role: String,
    path: String,
    action: String,
    effect: String, // allow/deny
}

async fn add_policy_to_role(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AddPolicyRequest>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    if username != "admin" {
        return Err(AppError::Unauthorized);
    }
    state.storage.add_policy_to_role(&payload.role, &payload.path, &payload.action, &payload.effect).await?;
    Ok(Json(serde_json::json!({"policy": true})))
} 

#[derive(Deserialize, ToSchema)]
pub struct RevokeTokenRequest {
    pub token: String,
}

async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RevokeTokenRequest>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    // Hanya user yang punya token ini atau admin yang boleh revoke
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    // TODO: validasi user pemilik token (dummy: allow admin)
    if username != "admin" {
        return Err(AppError::Unauthorized);
    }
    state.storage.revoke_token(&payload.token).await?;
    Ok(Json(serde_json::json!({"revoked": true})))
} 

// Hapus atau komen semua require_leader!(state); // TODO: implement macro jika dibutuhkan

async fn backup_data(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    // require_leader!(state);
    if username != "admin" {
        return Err(AppError::Unauthorized);
    }
    // Export all tables as JSON
    let users: Vec<serde_json::Value> = sqlx::query("SELECT * FROM users").fetch_all(&state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap().pool).await
        .map_err(|_| AppError::Internal)?
        .into_iter().map(|row| {
            serde_json::json!({
                "id": row.get::<i64,_>("id"),
                "username": row.get::<String,_>("username"),
                "password_hash": row.get::<String,_>("password_hash"),
                "created_at": row.get::<String,_>("created_at"),
            })
        }).collect();
    let secrets: Vec<serde_json::Value> = sqlx::query("SELECT * FROM secrets").fetch_all(&state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap().pool).await
        .map_err(|_| AppError::Internal)?
        .into_iter().map(|row| {
            serde_json::json!({
                "id": row.get::<i64,_>("id"),
                "path": row.get::<String,_>("path"),
                "version": row.get::<i64,_>("version"),
                "data": row.get::<String,_>("data"),
                "created_at": row.get::<String,_>("created_at"),
                "updated_at": row.get::<String,_>("updated_at"),
            })
        }).collect();
    // TODO: export roles, user_roles, policies, tokens, audit_logs
    Ok(Json(serde_json::json!({
        "users": users,
        "secrets": secrets
    })))
}

#[derive(Deserialize, ToSchema)]
struct RestoreRequest {
    users: Vec<serde_json::Value>,
    secrets: Vec<serde_json::Value>,
}

async fn restore_data(State(state): State<Arc<AppState>>, Json(payload): Json<RestoreRequest>, headers: axum::http::HeaderMap) -> Result<Json<serde_json::Value>, AppError> {
    let username = extract_username_and_validate_token(&headers, &state.storage).await?;
    // require_leader!(state);
    if username != "admin" {
        return Err(AppError::Unauthorized);
    }
    // Restore users
    for user in payload.users {
        let username = user["username"].as_str().unwrap_or("");
        let password_hash = user["password_hash"].as_str().unwrap_or("");
        sqlx::query("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)")
            .bind(username)
            .bind(password_hash)
            .execute(&state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap().pool)
            .await.map_err(|_| AppError::Internal)?;
    }
    // Restore secrets
    for secret in payload.secrets {
        let path = secret["path"].as_str().unwrap_or("");
        let version = secret["version"].as_i64().unwrap_or(1);
        let data = secret["data"].as_str().unwrap_or("");
        sqlx::query("INSERT OR IGNORE INTO secrets (path, version, data) VALUES (?, ?, ?)")
            .bind(path)
            .bind(version)
            .bind(data)
            .execute(&state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap().pool)
            .await.map_err(|_| AppError::Internal)?;
    }
    Ok(Json(serde_json::json!({"restored": true})))
} 

#[derive(Deserialize)]
pub struct RekeyRequest {
    pub secret_shares: u8,
    pub secret_threshold: u8,
}

#[derive(Serialize)]
pub struct RekeyResponse {
    pub shares: Vec<String>,
    pub message: String,
}

pub async fn rekey_vault(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RekeyRequest>,
) -> Result<Json<RekeyResponse>, StatusCode> {
    let mut progress = UNSEAL_PROGRESS.lock().unwrap();
    if progress.sealed {
        return Ok(Json(RekeyResponse {
            shares: vec![],
            message: "Vault must be unsealed before rekey".to_string(),
        }));
    }
    // Generate new master key
    use rand::RngCore;
    let mut master_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master_key);
    let master_key_hex = hex::encode(&master_key);
    // Split dengan Shamir
    let shares = split_mnemonic(&master_key_hex, payload.secret_shares as usize, payload.secret_threshold as usize)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // TODO: Simpan master_key baru ke storage/backend
    // Reset progress unseal
    progress.threshold = payload.secret_threshold as usize;
    progress.shares.clear();
    progress.sealed = true;
    let _ = log_audit_external(&state.external_audit_devices, "rekey_vault", "system", "", "success").await;
    Ok(Json(RekeyResponse {
        shares,
        message: "Vault rekeyed, please unseal with new shares".to_string(),
    }))
} 

pub async fn list_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let plugins = state.plugin_registry.list();
    Json(serde_json::json!({"plugins": plugins}))
}

// Endpoint status cluster
pub async fn cluster_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let status = state.cluster_status.lock().unwrap().clone();
    Json(status)
} 

#[derive(Deserialize)]
pub struct PromoteRequest {
    pub leader_id: String,
}

pub async fn promote_node(State(state): State<Arc<AppState>>, Json(payload): Json<PromoteRequest>) -> impl IntoResponse {
    let mut status = state.cluster_status.lock().unwrap();
    status.leader_id = Some(payload.leader_id.clone());
    status.is_active = status.node_id == payload.leader_id;
    state.is_active = status.is_active;
    Json(status.clone())
} 

pub async fn cluster_heartbeat(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut status = state.cluster_status.lock().unwrap();
    status.last_heartbeat = Some(Utc::now());
    Json(status.clone())
} 

// Endpoint status replication
pub async fn replication_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let status = state.replication_status.lock().unwrap().clone();
    Json(status)
} 

pub async fn sync_replication(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Dummy: push/pull secrets/policy ke peers
    let mut status = state.replication_status.lock().unwrap();
    // TODO: implementasi sync nyata (HTTP call ke peers, dsb)
    status.last_sync = Some(chrono::Utc::now());
    Json(serde_json::json!({"status": "sync triggered", "last_sync": status.last_sync}))
} 

pub async fn seal_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = &state.config;
    let auto_unseal = config.auto_unseal_enabled.unwrap_or(false);
    let recovery_key = if auto_unseal {
        Some("dummy_recovery_key".to_string())
    } else {
        None
    };
    let sealed = !auto_unseal; // dummy: jika auto_unseal aktif, dianggap unsealed
    Json(SealStatus {
        sealed,
        auto_unseal,
        recovery_key,
    })
} 

#[derive(Deserialize)]
pub struct MountEngineRequest {
    pub path: String,
    pub engine: String,
}

#[derive(Serialize)]
pub struct MountEngineResponse {
    pub status: String,
    pub path: String,
    pub engine: String,
}

pub async fn mount_engine(State(state): State<Arc<AppState>>, Json(payload): Json<MountEngineRequest>) -> impl IntoResponse {
    let mut reg = state.engine_registry.lock().unwrap();
    reg.insert(payload.path.clone(), payload.engine.clone());
    let _ = log_audit_external(&state.external_audit_devices, "mount_engine", "system", &payload.path, "success").await;
    MountEngineResponse {
        status: "mounted".to_string(),
        path: payload.path,
        engine: payload.engine,
    }
}

#[derive(Deserialize)]
pub struct UnmountEngineRequest {
    pub path: String,
}

#[derive(Serialize)]
pub struct UnmountEngineResponse {
    pub status: String,
    pub path: String,
}

pub async fn unmount_engine(State(state): State<Arc<AppState>>, Json(payload): Json<UnmountEngineRequest>) -> impl IntoResponse {
    let mut reg = state.engine_registry.lock().unwrap();
    reg.remove(&payload.path);
    let _ = log_audit_external(&state.external_audit_devices, "unmount_engine", "system", &payload.path, "success").await;
    UnmountEngineResponse {
        status: "unmounted".to_string(),
        path: payload.path,
    }
}

#[derive(Deserialize)]
pub struct RemountEngineRequest {
    pub from: String,
    pub to: String,
}

#[derive(Serialize)]
pub struct RemountEngineResponse {
    pub status: String,
    pub from: String,
    pub to: String,
}

pub async fn remount_engine(State(state): State<Arc<AppState>>, Json(payload): Json<RemountEngineRequest>) -> impl IntoResponse {
    let mut reg = state.engine_registry.lock().unwrap();
    let mut status = "not_found".to_string();
    if let Some(engine) = reg.remove(&payload.from) {
        reg.insert(payload.to.clone(), engine);
        status = "remounted".to_string();
    }
    let _ = log_audit_external(&state.external_audit_devices, "remount_engine", "system", &payload.to, &status).await;
    RemountEngineResponse {
        status,
        from: payload.from,
        to: payload.to,
    }
} 

pub async fn generic_engine_route(
    State(state): State<Arc<AppState>>,
    Path((engine_path, action)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let reg = state.engine_registry.lock().unwrap();
    if let Some(engine) = reg.get(&engine_path) {
        // Dummy: arahkan ke engine sesuai registry
        return Json(serde_json::json!({
            "status": "ok",
            "engine": engine,
            "path": engine_path,
            "action": action,
            "payload": payload,
        }));
    }
    Json(serde_json::json!({
        "status": "not_found",
        "path": engine_path,
        "action": action,
    }))
} 

#[derive(Deserialize)]
pub struct AuditHashRequest {
    pub event: String,
}

#[derive(Serialize)]
pub struct AuditHashResponse {
    pub event: String,
    pub hash: String,
}

pub async fn audit_hash(Json(payload): Json<AuditHashRequest>, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Dummy: hash event string, bisa dikembangkan ke hash log nyata
    let mut hasher = Sha256::new();
    hasher.update(payload.event.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    let mut store = AUDIT_HASHES.lock().unwrap();
    store.insert(payload.event.clone(), hash.clone());
    let _ = log_audit_external(&state.external_audit_devices, "audit_hash", "system", &payload.event, "success").await;
    AuditHashResponse { event: payload.event, hash }
}

#[derive(Deserialize)]
pub struct AuditVerifyRequest {
    pub event: String,
    pub hash: String,
}

#[derive(Serialize)]
pub struct AuditVerifyResponse {
    pub event: String,
    pub valid: bool,
}

pub async fn audit_verify(Json(payload): Json<AuditVerifyRequest>, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = AUDIT_HASHES.lock().unwrap();
    let valid = store.get(&payload.event).map(|h| h == &payload.hash).unwrap_or(false);
    let _ = log_audit_external(&state.external_audit_devices, "audit_verify", "system", &payload.event, if valid { "success" } else { "failed" }).await;
    AuditVerifyResponse { event: payload.event, valid }
} 