use axum::{extract::{Json, State, Path, ConnectInfo, Query}, response::IntoResponse, http::HeaderMap};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::controllers::{auth, secret, policy};
use crate::models::{user::User, secret::Secret, policy::Policy};
use crate::utils::error::AppError;
use crate::AppState;
use crate::auth::AuthManager;
use crate::services::lease::{create_lease, renew_lease, revoke_lease, get_expired_leases};
use crate::models::lease::Lease;
use std::sync::Mutex;
use crate::storage::Storage;
use crate::utils::config::Config;
use crate::services::dynamic::generate_db_credential_postgres;
use crate::services::dynamic::aws::{generate_aws_credential, revoke_aws_credential, AwsCredential};
use crate::services::auth::ldap::ldap_authenticate;
use crate::services::auth::oidc::{build_authorize_url, handle_callback};
use crate::services::auth::approle::{generate_role, login_approle, rotate_secret_id};
use crate::models::approle::AppRole;
use crate::services::rbac::{check_policy, resolve_user_roles};
use utoipa::ToSchema;
use crate::core::RevokeTokenRequest;
use crate::plugins::dyn_password::DynPasswordPlugin;
use crate::plugins::sops_file::SopsFilePlugin;
use crate::plugins::kms::KmsPlugin;
use crate::k8s::k8s_webhook;
use crate::k8s::sealed::{encrypt_sealed_secret, decrypt_sealed_secret};
use serde_json::Value;
use crate::pki::{generate_ca, issue_cert, CaCert, CertRequest, IssuedCert};
use crate::models::pki::{PkiCa, PkiCert};
use chrono::Utc;
use crate::services::plugin::PluginRegistry;
use crate::models::sentinel::SentinelPolicy;
use crate::services::policy::check_policy_with_sentinel;
use crate::services::audit::log_audit_external;
use std::io::Write;
use crate::core::cluster::{VaultRaftCmd, VaultRaftData, VaultRaftTypeConfig, VaultRaftStorage};
use openraft::Raft;
use crate::core::APPROVAL_REQUESTS;
use crate::models::policy::PolicyRule;
use uuid::Uuid;
use crate::models::user::Token;
use chrono::{Utc, Duration};
use crate::models::plugin::PluginCatalogEntry;
use sha2::{Sha256, Digest};
use crate::services::dynamic::{generate_mysql_credential, generate_mongo_credential, generate_aws_credential, generate_gcp_credential, generate_azure_credential};
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub user: String,
    pub orphan: bool,
    pub batch: bool,
    pub expires_in: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub token: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
pub struct RenewTokenRequest {
    pub token: String,
    pub additional_secs: i64,
}

#[derive(Serialize)]
pub struct RenewTokenResponse {
    pub token: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
pub struct RevokeTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct RevokeTokenResponse {
    pub status: String,
    pub token: String,
}

#[derive(Deserialize)]
pub struct LockoutUserRequest {
    pub user: String,
}

#[derive(Serialize)]
pub struct LockoutUserResponse {
    pub status: String,
    pub user: String,
}

static mut APPROLE: Option<Mutex<AppRole>> = None;

#[derive(serde::Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(serde::Deserialize, ToSchema)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(serde::Deserialize, ToSchema)]
pub struct AppRoleLoginRequest {
    pub role_id: String,
    pub secret_id: String,
}

#[derive(serde::Deserialize, ToSchema)]
pub struct AppRolePolicyRequest {
    pub policies: Vec<String>,
}

#[derive(serde::Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: i64,
}

/// Helper untuk ekstrak user_id, entity_alias, dan policies dari JWT dan storage
async fn extract_user_info_and_policies(
    headers: &HeaderMap,
    state: &Arc<AppState>,
) -> Result<(String, Option<String>, Vec<Policy>), AppError> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let jwt_secret = &state.config.jwt_secret;
    let auth_manager = AuthManager::new(jwt_secret, state.storage.clone()).unwrap();
    if let Some(auth_header) = auth_header {
        if let Some(token) = AuthManager::extract_token_from_header(auth_header) {
            let claims = auth_manager.verify_token(&token).map_err(|_| AppError::Unauthorized)?;
            let user_id = claims.sub;
            // entity_alias dari JWT claims jika ada (misal OIDC/LDAP/AppRole)
            let entity_alias = claims.entity_alias.clone();
            let policies = state.storage.get_policies_for_user(&user_id, entity_alias.as_deref()).await.map_err(|_| AppError::InternalError)?;
            Ok((user_id, entity_alias, policies))
        } else {
            Err(AppError::Unauthorized)
        }
    } else {
        Err(AppError::Unauthorized)
    }
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // Panggil controller auth
    let jwt_secret = &state.config.jwt_secret;
    let auth_manager = AuthManager::new(jwt_secret, state.storage.clone()).unwrap();
    let login_result = auth_manager.authenticate_user(&payload.username, &payload.password).await;
    let status = if login_result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "login", &payload.username, "", status).await;
    todo!("Implementasi login handler di sini")
}

pub async fn ldap_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LdapLoginRequest>,
) -> impl IntoResponse {
    let config = &state.config;
    match ldap_authenticate(config, &payload.username, &payload.password).await {
        Ok(true) => Json("LDAP login success").into_response(),
        _ => (axum::http::StatusCode::UNAUTHORIZED, "LDAP login failed").into_response(),
    }
}

pub async fn get_secret(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Path((namespace, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (user_id, entity_alias, policies) = extract_user_info_and_policies(&headers, &state).await?;
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    let policyset_json = headers.get("X-Policy-Set").and_then(|v| v.to_str().ok());
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let sentinel_policies: Vec<SentinelPolicy> = storage.list_sentinel_policies(&namespace).await.unwrap_or_default();
    let allowed = check_policy_with_sentinel(&sentinel_policies, &user_id, &path, "read", None, &roles, &policies, policyset_json).await;
    let status = if allowed { "success" } else { "denied" };
    let _ = log_audit_external(&state.external_audit_devices, "get_secret", &user_id, &path, status).await;
    if !allowed {
        return Err(AppError::Forbidden("Akses ditolak oleh Sentinel policy atau RBAC".into()));
    }
    let secret = storage.get_secret(&path, &namespace).await?;
    Ok(Json(secret.unwrap_or_default()))
}

pub async fn generate_dynamic_db_credential(
    State(state): State<Arc<AppState>>,
    Path(role): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = match extract_user_info_and_policies(&headers, &state).await {
        Ok(res) => res,
        Err(e) => return e.into_response(),
    };
    let path = format!("db/role/{}", role);
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    if !check_policy(&roles, &policies, &path, "create") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    let config = &state.config;
    let db_url = match &config.dynamic_db_url {
        Some(url) => url,
        None => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "dynamic_db_url not set").into_response(),
    };
    let pool = match sqlx::PgPool::connect(db_url).await {
        Ok(pool) => pool,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("DB connect error: {}", e)).into_response(),
    };
    let cred = generate_db_credential_postgres(&pool, &role).await;
    let lease = create_lease(state.storage.as_any().downcast_ref::<Storage>().unwrap(), "admin", "db", &cred.username, 30).await;
    match lease {
        Ok(lease) => Json((cred, lease)).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn create_dynamic_lease(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = match extract_user_info_and_policies(&headers, &state).await {
        Ok(res) => res,
        Err(e) => return e.into_response(),
    };
    let path = "lease/create".to_string();
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    if !check_policy(&roles, &policies, &path, "create") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    // Dummy: create lease, simpan ke DB
    let lease = create_lease(&state.storage.as_any().downcast_ref::<Storage>().unwrap(), "admin", "db", "db-cred-1", 30).await;
    match lease {
        Ok(lease) => Json(lease).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn renew_lease(State(state): State<Arc<AppState>>, Path(id): Path<String>, headers: HeaderMap) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = match extract_user_info_and_policies(&headers, &state).await {
        Ok(res) => res,
        Err(e) => return e.into_response(),
    };
    let path = format!("lease/renew/{}", id);
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    if !check_policy(&roles, &policies, &path, "renew") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    let result = renew_lease(&state.storage.as_any().downcast_ref::<Storage>().unwrap(), &id, 30).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "renew_lease", &user_id, &id, status).await;
    match result {
        Ok(Some(lease)) => Json(lease).into_response(),
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "Lease not found").into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn revoke_lease(State(state): State<Arc<AppState>>, Path(id): Path<String>, headers: HeaderMap) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = match extract_user_info_and_policies(&headers, &state).await {
        Ok(res) => res,
        Err(e) => return e.into_response(),
    };
    let path = format!("lease/revoke/{}", id);
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    if !check_policy(&roles, &policies, &path, "revoke") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    let result = revoke_lease(
        state.storage.as_any().downcast_ref::<Storage>().unwrap(),
        &id
    ).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "revoke_lease", &user_id, &id, status).await;
    match result {
        Ok(Some(lease)) => Json(lease).into_response(),
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "Lease not found").into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn generate_dynamic_aws_credential(
    State(state): State<Arc<AppState>>,
    Path(role): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = match extract_user_info_and_policies(&headers, &state).await {
        Ok(res) => res,
        Err(e) => return e.into_response(),
    };
    let path = format!("aws/role/{}", role);
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    if !check_policy(&roles, &policies, &path, "create") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    let config = &state.config;
    let cred = match generate_aws_credential(config, &role).await {
        Ok(cred) => cred,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let lease = create_lease(state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap(), "admin", "aws", &cred.username, 30).await;
    match lease {
        Ok(lease) => Json((cred, lease)).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn oidc_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = &state.config;
    if let Some(url) = build_authorize_url(config) {
        axum::response::Redirect::temporary(&url).into_response()
    } else {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "OIDC config error").into_response()
    }
}

pub async fn oidc_callback(State(state): State<Arc<AppState>>, axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>) -> impl IntoResponse {
    let config = &state.config;
    let code = params.get("code").cloned().unwrap_or_default();
    if let Some(username) = handle_callback(config, &code).await {
        Json(format!("OIDC login success: {}", username)).into_response()
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "OIDC login failed").into_response()
    }
}

pub async fn generate_approle(Json(payload): Json<AppRolePolicyRequest>) -> impl IntoResponse {
    let role = generate_role(payload.policies);
    unsafe {
        APPROLE = Some(Mutex::new(role.clone()));
    }
    Json(role)
}

pub async fn approle_login(Json(payload): Json<AppRoleLoginRequest>) -> impl IntoResponse {
    unsafe {
        if let Some(ref role) = APPROLE {
            let role = role.lock().unwrap();
            if login_approle(&role, &payload.role_id, &payload.secret_id) {
                return Json("AppRole login success").into_response();
            }
        }
    }
    (axum::http::StatusCode::UNAUTHORIZED, "AppRole login failed").into_response()
}

pub async fn rotate_approle_secret_id() -> impl IntoResponse {
    unsafe {
        if let Some(ref role) = APPROLE {
            let mut role = role.lock().unwrap();
            rotate_secret_id(&mut role);
            return Json(role.clone()).into_response();
        }
    }
    (axum::http::StatusCode::NOT_FOUND, "AppRole not found").into_response()
} 

// Tambahkan stub pub async fn untuk endpoint yang dibutuhkan router
pub async fn get_secret_versions() { todo!("get_secret_versions") }
pub async fn get_leader() { todo!("get_leader") }
pub async fn health_check() { todo!("health_check") }
pub async fn ready_check() { todo!("ready_check") }
pub async fn backup_data() { todo!("backup_data") }
pub async fn restore_data() { todo!("restore_data") }
pub async fn add_role() { todo!("add_role") }
pub async fn assign_role_to_user() { todo!("assign_role_to_user") }
pub async fn add_policy_to_role(
    State(state): State<Arc<AppState>>,
    Path((namespace, role)): Path<(String, String)>,
    Json(payload): Json<AddPolicyRequest>,
) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = extract_user_info_and_policies(&axum::http::HeaderMap::new(), &state).await?;
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    let path_str = format!("{}/{}", namespace, role);
    if !check_policy(&roles, &policies, &path_str, "create") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    let result = state.storage.add_policy_to_role(&role, &payload.path, &payload.action, &payload.effect, &namespace).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "add_policy_to_role", &user_id, &role, status).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "created"})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn create_token(State(state): State<Arc<AppState>>, Json(payload): Json<CreateTokenRequest>) -> impl IntoResponse {
    let token = uuid::Uuid::new_v4().to_string();
    let expires_at = payload.expires_in.map(|secs| Utc::now() + Duration::seconds(secs));
    let t = Token {
        token: token.clone(),
        user: payload.user.clone(),
        expires_at,
        orphan: payload.orphan,
        batch: payload.batch,
        locked: false,
        created_at: Utc::now(),
    };
    // Simpan ke storage Postgres
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let _ = storage.insert_token(&t).await;
    let _ = log_audit_external(&state.external_audit_devices, "create_token", &payload.user, &token, "success").await;
    CreateTokenResponse { token, expires_at }
}

pub async fn renew_token(State(state): State<Arc<AppState>>, Json(payload): Json<RenewTokenRequest>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let expires_at = Some(Utc::now() + Duration::seconds(payload.additional_secs));
    let _ = storage.update_token_expiry(&payload.token, expires_at.unwrap()).await;
    let _ = log_audit_external(&state.external_audit_devices, "renew_token", "system", &payload.token, "success").await;
    RenewTokenResponse { token: payload.token, expires_at }
}

pub async fn revoke_token(State(state): State<Arc<AppState>>, Json(payload): Json<RevokeTokenRequest>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let _ = storage.delete_token(&payload.token).await;
    let _ = log_audit_external(&state.external_audit_devices, "revoke_token", "system", &payload.token, "success").await;
    RevokeTokenResponse { status: "revoked".to_string(), token: payload.token }
}

#[derive(Deserialize)]
pub struct LockoutUserRequest {
    pub user: String,
}

#[derive(Serialize)]
pub struct LockoutUserResponse {
    pub status: String,
    pub user: String,
}

pub async fn lockout_user(State(state): State<Arc<AppState>>, Json(payload): Json<LockoutUserRequest>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let _ = storage.lockout_user_tokens(&payload.user).await;
    let _ = log_audit_external(&state.external_audit_devices, "lockout_user", &payload.user, "", "success").await;
    LockoutUserResponse { status: "locked_out".to_string(), user: payload.user }
}

// Tambahkan stub endpoint
pub async fn create_secret(
    State(state): State<Arc<AppState>>,
    Path((namespace, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = extract_user_info_and_policies(&headers, &state).await?;
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    let path_str = format!("{}/{}", namespace, path);
    if !check_policy(&roles, &policies, &path_str, "create") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    // Cek apakah policy butuh approval control group
    let mut need_approval = false;
    let mut required_approvals = 0;
    let mut need_mfa = false;
    for pol in &policies {
        if pol.path == path_str && pol.action == "create" {
            if let Some(cg) = &pol.control_group {
                need_approval = true;
                required_approvals = cg.required_approvals;
            }
            if pol.mfa == Some(true) {
                need_mfa = true;
            }
        }
    }
    if need_mfa {
        let mfa_token = headers.get("x-mfa-token").and_then(|v| v.to_str().ok());
        let valid = mfa_token == Some("123456"); // Dummy validasi MFA
        let _ = log_audit_external(&state.external_audit_devices, "mfa_verify", &user_id, &path_str, if valid { "success" } else { "failed" }).await;
        if !valid {
            return AppError::Forbidden("MFA tidak valid atau tidak disertakan").into_response();
        }
    }
    if need_approval {
        // Buat approval request
        let req_id = uuid::Uuid::new_v4().to_string();
        let mut store = crate::core::APPROVAL_REQUESTS.lock().unwrap();
        store.insert(req_id.clone(), crate::core::ApprovalRequest {
            id: req_id.clone(),
            path: path_str.clone(),
            action: "create".to_string(),
            requested_by: user_id.clone(),
            approved_by: vec![],
            required_approvals,
            status: "pending".to_string(),
        });
        return Json(serde_json::json!({
            "status": "pending_approval",
            "request_id": req_id,
            "required_approvals": required_approvals,
        })).into_response();
    }
    let secret = serde_json::to_vec(&payload).map_err(|_| AppError::BadRequest("Invalid secret payload".into()))?;
    if state.is_active {
        println!("[RAFT] Submit PutSecret: {}", path_str);
    } else {
        let result = state.storage.create_secret(&path_str, &namespace, &payload).await;
        let status = if result.is_ok() { "success" } else { "failed" };
        let _ = log_audit_external(&state.external_audit_devices, "create_secret", &user_id, &path_str, status).await;
        return match result {
            Ok(_) => Json(serde_json::json!({ "status": "created" })).into_response(),
            Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }
    Json(serde_json::json!({ "status": "submitted_to_raft" }))
}

pub async fn update_secret(
    State(state): State<Arc<AppState>>,
    Path((namespace, path)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = extract_user_info_and_policies(&axum::http::HeaderMap::new(), &state).await?;
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    let policyset_json = None;
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let sentinel_policies: Vec<SentinelPolicy> = storage.list_sentinel_policies(&namespace).await.unwrap_or_default();
    let allowed = check_policy_with_sentinel(&sentinel_policies, &user_id, &path, "update", None, &roles, &policies, policyset_json).await;
    let status = if allowed { "success" } else { "denied" };
    let _ = log_audit_external(&state.external_audit_devices, "update_secret", &user_id, &path, status).await;
    if !allowed {
        return AppError::Forbidden("Akses ditolak oleh Sentinel policy atau RBAC".into()).into_response();
    }
    let secret = serde_json::to_vec(&payload).map_err(|_| AppError::BadRequest("Invalid secret payload".into()))?;
    if state.is_active {
        // TODO: gunakan instance raft dari AppState
        // let raft = ...
        // let cmd = VaultRaftCmd::PutSecret { path: path.clone(), data: secret.clone() };
        // raft.client_write(VaultRaftData(cmd)).await;
        println!("[RAFT] Submit PutSecret (update): {}", path);
        return Json(serde_json::json!({ "status": "submitted_to_raft" }));
    }
    let result = state.storage.update_secret(&path, &namespace, &payload).await;
    match result {
        Ok(_) => Json(serde_json::json!({ "status": "updated" })).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn delete_secret(
    State(state): State<Arc<AppState>>,
    Path((namespace, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let (user_id, entity_alias, policies) = extract_user_info_and_policies(&headers, &state).await?;
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    let policyset_json = None;
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let sentinel_policies: Vec<SentinelPolicy> = storage.list_sentinel_policies(&namespace).await.unwrap_or_default();
    let allowed = check_policy_with_sentinel(&sentinel_policies, &user_id, &path, "delete", None, &roles, &policies, policyset_json).await;
    let status = if allowed { "success" } else { "denied" };
    let _ = log_audit_external(&state.external_audit_devices, "delete_secret", &user_id, &path, status).await;
    if !allowed {
        return Err(AppError::Forbidden("Akses ditolak oleh Sentinel policy atau RBAC".into()));
    }
    if state.is_active {
        // TODO: gunakan instance raft dari AppState
        // let raft = ...
        // let cmd = VaultRaftCmd::DeleteSecret { path: path.clone() };
        // raft.client_write(VaultRaftData(cmd)).await;
        println!("[RAFT] Submit DeleteSecret: {}", path);
        return Ok(StatusCode::ACCEPTED);
    }
    let result = state.storage.delete_secret(&path, &namespace).await;
    match result {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err(AppError::InternalError(e.to_string())),
    }
} 

pub async fn plugin_action(
    State(state): State<Arc<AppState>>,
    Path((name, action)): Path<(String, String)>,
    Json(params): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(plugin) = state.plugin_registry.get(&name) {
        if name == "dyn_password" && action == "generate" {
            let length = params.get("length").and_then(|v| v.as_u64()).unwrap_or(12) as usize;
            let dyn_plugin = plugin.as_any().downcast_ref::<DynPasswordPlugin>().unwrap();
            let result = dyn_plugin.generate(length);
            return Json(serde_json::json!({ "password": result }));
        }
        if name == "sops_file" && action == "encrypt" {
            let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let key_b64 = params.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let key = base64::decode(key_b64).unwrap_or(vec![0u8; 32]);
            let plugin = plugin.as_any().downcast_ref::<SopsFilePlugin>().unwrap();
            let encrypted = plugin.encrypt_file(content, &key);
            return Json(serde_json::json!({ "encrypted": encrypted }));
        }
        if name == "sops_file" && action == "decrypt" {
            let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let key_b64 = params.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let key = base64::decode(key_b64).unwrap_or(vec![0u8; 32]);
            let plugin = plugin.as_any().downcast_ref::<SopsFilePlugin>().unwrap();
            let decrypted = plugin.decrypt_file(content, &key);
            return Json(serde_json::json!({ "decrypted": decrypted }));
        }
        if name == "kms" && action == "encrypt" {
            let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let key_id = params.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
            let plugin = plugin.as_any().downcast_ref::<KmsPlugin>().unwrap();
            let encrypted = plugin.encrypt_with_kms(content, key_id);
            return Json(serde_json::json!({ "encrypted": encrypted }));
        }
        if name == "kms" && action == "decrypt" {
            let content = params.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let key_id = params.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
            let plugin = plugin.as_any().downcast_ref::<KmsPlugin>().unwrap();
            let decrypted = plugin.decrypt_with_kms(content, key_id);
            return Json(serde_json::json!({ "decrypted": decrypted }));
        }
    }
    (axum::http::StatusCode::NOT_FOUND, "Plugin/action not found").into_response()
} 

pub async fn k8s_webhook(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let result = k8s_webhook(&payload).await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(e)) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
} 

pub async fn encrypt_sealed_secret(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let result = encrypt_sealed_secret(&payload).await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(e)) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn decrypt_sealed_secret(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let result = decrypt_sealed_secret(&payload).await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(e)) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
} 

// Create lease
pub async fn api_create_lease(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let user = payload.get("user").and_then(|v| v.as_str()).unwrap_or("");
    let resource = payload.get("resource").and_then(|v| v.as_str()).unwrap_or("");
    let resource_type = payload.get("resource_type").and_then(|v| v.as_str()).unwrap_or("");
    let ttl = payload.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
    let result = create_lease(state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap(), user, resource, resource_type, ttl, &namespace).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "create_lease", user, resource, status).await;
    match result {
        Ok(lease) => Json(lease).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// Renew lease
pub async fn api_renew_lease(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = match extract_user_info_and_policies(&axum::http::HeaderMap::new(), &state).await {
        Ok(res) => res,
        Err(e) => return e.into_response(),
    };
    let path = format!("lease/renew/{}", id);
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    if !check_policy(&roles, &policies, &path, "renew") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    let ttl = payload.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
    let result = renew_lease(state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap(), &id, ttl).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "renew_lease", &user_id, &id, status).await;
    match result {
        Ok(lease) => Json(lease).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// Revoke lease
pub async fn api_revoke_lease(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let (user_id, entity_alias, policies) = match extract_user_info_and_policies(&axum::http::HeaderMap::new(), &state).await {
        Ok(res) => res,
        Err(e) => return e.into_response(),
    };
    let path = format!("lease/revoke/{}", id);
    let roles = resolve_user_roles(&user_id, entity_alias.as_deref(), &policies);
    if !check_policy(&roles, &policies, &path, "revoke") {
        return AppError::Forbidden("Akses ditolak oleh policy".into()).into_response();
    }
    let result = revoke_lease(state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap(), &id).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "revoke_lease", &user_id, &id, status).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "revoked"})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// Get expired leases
pub async fn api_get_expired_leases(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match get_expired_leases(state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap()).await {
        Ok(leases) => Json(leases).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
} 

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub user: Option<String>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub limit: Option<u32>,
}

pub async fn get_audit_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    match storage.get_audit_logs(params.user, params.action, params.status, params.limit.unwrap_or(100)).await {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
} 

// Model Namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    pub name: String,
}

// Create namespace
pub async fn create_namespace(State(state): State<Arc<AppState>>, Json(payload): Json<Namespace>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let result = storage.create_namespace(&payload.name).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "created"})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// List namespaces
pub async fn list_namespaces(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    match storage.list_namespaces().await {
        Ok(list) => Json(list).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// Delete namespace
pub async fn delete_namespace(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let result = storage.delete_namespace(&name).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "deleted"})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
} 

pub async fn pki_generate_ca(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let cn = payload.get("common_name").and_then(|v| v.as_str()).unwrap_or("My CA");
    let ca = generate_ca(cn);
    let ca_model = PkiCa {
        id: 0,
        namespace: namespace.clone(),
        common_name: cn.to_string(),
        pem: ca.pem.clone(),
        private_key: ca.private_key.clone(),
        created_at: Utc::now(),
    };
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let _ = storage.create_ca(&ca_model).await;
    Json(ca_model)
}

pub async fn pki_issue_cert(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let ca_cn = payload.get("ca_common_name").and_then(|v| v.as_str()).unwrap_or("");
    let req = CertRequest {
        common_name: payload.get("common_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        alt_names: payload.get("alt_names").and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
        ttl_days: payload.get("ttl_days").and_then(|v| v.as_u64()).unwrap_or(365) as u32,
    };
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let ca = storage.get_ca(&namespace, ca_cn).await.unwrap().unwrap();
    let cert = issue_cert(&CaCert { pem: ca.pem.clone(), private_key: ca.private_key.clone() }, &req);
    let cert_model = PkiCert {
        id: 0,
        namespace: namespace.clone(),
        common_name: req.common_name.clone(),
        pem: cert.pem.clone(),
        private_key: cert.private_key.clone(),
        ca_id: ca.id,
        serial: format!("serial-{}-{}", ca.id, Utc::now().timestamp()),
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::days(req.ttl_days as i64),
        revoked: false,
    };
    let _ = storage.create_cert(&cert_model).await;
    Json(cert_model)
}

pub async fn pki_renew_cert(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let serial = payload.get("serial").and_then(|v| v.as_str()).unwrap_or("");
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    if let Some(old_cert) = storage.get_cert(&namespace, serial).await.unwrap() {
        let ca = storage.get_ca(&namespace, &old_cert.common_name).await.unwrap().unwrap();
        let req = CertRequest {
            common_name: old_cert.common_name.clone(),
            alt_names: vec![],
            ttl_days: 365,
        };
        let cert = issue_cert(&CaCert { pem: ca.pem.clone(), private_key: ca.private_key.clone() }, &req);
        let cert_model = PkiCert {
            id: 0,
            namespace: namespace.clone(),
            common_name: req.common_name.clone(),
            pem: cert.pem.clone(),
            private_key: cert.private_key.clone(),
            ca_id: ca.id,
            serial: format!("serial-{}-{}", ca.id, Utc::now().timestamp()),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(req.ttl_days as i64),
            revoked: false,
        };
        let _ = storage.create_cert(&cert_model).await;
        Json(cert_model)
    } else {
        (axum::http::StatusCode::NOT_FOUND, "Certificate not found").into_response()
    }
}

pub async fn pki_revoke_cert(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let serial = payload.get("serial").and_then(|v| v.as_str()).unwrap_or("");
    let storage = state.storage.as_any().downcast_ref::<crate::storage::Storage>().unwrap();
    let _ = storage.revoke_cert(&namespace, serial).await;
    Json(serde_json::json!({"status": "revoked", "serial": serial}))
} 

// List plugins
pub async fn admin_list_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let list = state.plugin_registry.list();
    Json(list)
}

// Load plugin (dummy: hanya register ulang plugin statis)
pub async fn admin_load_plugin(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let name = payload.get("name").and_then(|v| v.as_str());
    if name.is_none() || name.unwrap().is_empty() {
        return Json(serde_json::json!({"status": "error", "error": "Field 'name' wajib diisi"}));
    }
    let name = name.unwrap();
    // Dummy: hanya reload plugin statis
    state.plugin_registry.reload(name);
    Json(serde_json::json!({"status": "loaded", "name": name}))
}

// Load plugin eksternal dari file .so (hanya dari /opt/vault_plugins/)
pub async fn admin_load_plugin_dynamic(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
    if !path.starts_with("/opt/vault_plugins/") {
        return Json(serde_json::json!({
            "status": "denied",
            "error": "Path plugin harus di /opt/vault_plugins/"
        }));
    }
    let result = unsafe { state.plugin_registry.load_dynamic_library(path) };
    let status = if result.is_ok() { "success" } else { "failed" };
    if let Err(ref err) = result {
        let _ = writeln!(std::io::stderr(), "[ALERT] Plugin gagal load: {} ({})", path, err);
    }
    Json(serde_json::json!({"status": status, "path": path, "error": result.err()}))
}

// Reload plugin
pub async fn admin_reload_plugin(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let name = payload.get("name").and_then(|v| v.as_str());
    if name.is_none() || name.unwrap().is_empty() {
        return Json(serde_json::json!({"status": "error", "error": "Field 'name' wajib diisi"}));
    }
    let name = name.unwrap();
    state.plugin_registry.reload(name);
    Json(serde_json::json!({"status": "reloaded", "name": name}))
}

// Unload plugin
pub async fn admin_unload_plugin(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let name = payload.get("name").and_then(|v| v.as_str());
    if name.is_none() || name.unwrap().is_empty() {
        return Json(serde_json::json!({"status": "error", "error": "Field 'name' wajib diisi"}));
    }
    let name = name.unwrap();
    state.plugin_registry.unload(name);
    Json(serde_json::json!({"status": "unloaded", "name": name}))
} 

// Upload Sentinel policy
pub async fn admin_upload_sentinel_policy(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Json(payload): Json<serde_json::Value>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, _, _) = extract_user_info_and_policies(&headers, &state).await.unwrap_or(("anonymous".to_string(), None, vec![]));
    let name = payload.get("name").and_then(|v| v.as_str());
    let policy_type = payload.get("policy_type").and_then(|v| v.as_str());
    let source_code = payload.get("source_code").and_then(|v| v.as_str());
    if name.is_none() || name.unwrap().is_empty() || policy_type.is_none() || policy_type.unwrap().is_empty() || source_code.is_none() || source_code.unwrap().is_empty() {
        return Json(serde_json::json!({"status": "error", "error": "Field 'name', 'policy_type', dan 'source_code' wajib diisi"}));
    }
    let result = state.storage.create_sentinel_policy(&namespace, payload.clone()).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    if let Err(ref err) = result {
        let _ = writeln!(std::io::stderr(), "[ALERT] Sentinel policy gagal upload: {} ({}): {}", namespace, name.unwrap_or(""), err);
    }
    let _ = log_audit_external(&state.external_audit_devices, "upload_sentinel_policy", &user_id, name.unwrap(), status).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "uploaded"})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// List Sentinel policies
pub async fn admin_list_sentinel_policies(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, _, _) = extract_user_info_and_policies(&headers, &state).await.unwrap_or(("anonymous".to_string(), None, vec![]));
    let result = state.storage.list_sentinel_policies(&namespace).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "list_sentinel_policies", &user_id, &namespace, status).await;
    match result {
        Ok(policies) => Json(policies).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// Delete Sentinel policy
pub async fn admin_delete_sentinel_policy(
    State(state): State<Arc<AppState>>,
    Path((namespace, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, _, _) = extract_user_info_and_policies(&headers, &state).await.unwrap_or(("anonymous".to_string(), None, vec![]));
    let result = state.storage.delete_sentinel_policy(&namespace, &name).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "delete_sentinel_policy", &user_id, &name, status).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "deleted"})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
} 

pub async fn userpass_login(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let user = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let pass = payload.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let valid = user == "user" && pass == "pass"; // Dummy
    let _ = log_audit_external(&state.external_audit_devices, "userpass_login", user, "", if valid { "success" } else { "failed" }).await;
    if valid {
        Json(serde_json::json!({"token": "userpass_token", "method": "userpass"}))
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "Userpass login failed").into_response()
    }
}

pub async fn cert_login(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let cert = payload.get("cert").and_then(|v| v.as_str()).unwrap_or("");
    let valid = cert == "dummy-cert"; // Dummy
    let _ = log_audit_external(&state.external_audit_devices, "cert_login", cert, "", if valid { "success" } else { "failed" }).await;
    if valid {
        Json(serde_json::json!({"token": "cert_token", "method": "cert"}))
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "Cert login failed").into_response()
    }
}

pub async fn approle_login(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let role_id = payload.get("role_id").and_then(|v| v.as_str()).unwrap_or("");
    let secret_id = payload.get("secret_id").and_then(|v| v.as_str()).unwrap_or("");
    let valid = role_id == "role" && secret_id == "secret"; // Dummy
    let _ = log_audit_external(&state.external_audit_devices, "approle_login", role_id, "", if valid { "success" } else { "failed" }).await;
    if valid {
        Json(serde_json::json!({"token": "approle_token", "method": "approle"}))
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "AppRole login failed").into_response()
    }
}

pub async fn kerberos_login(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let user = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let pass = payload.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let valid = user == "kerberos_user" && pass == "kerberos_pass"; // Dummy
    let _ = log_audit_external(&state.external_audit_devices, "kerberos_login", user, "", if valid { "success" } else { "failed" }).await;
    if valid {
        Json(serde_json::json!({"token": "kerberos_token", "method": "kerberos"}))
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "Kerberos login failed").into_response()
    }
}

pub async fn radius_login(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let user = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let pass = payload.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let valid = user == "radius_user" && pass == "radius_pass"; // Dummy
    let _ = log_audit_external(&state.external_audit_devices, "radius_login", user, "", if valid { "success" } else { "failed" }).await;
    if valid {
        Json(serde_json::json!({"token": "radius_token", "method": "radius"}))
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "Radius login failed").into_response()
    }
}

pub async fn cloud_iam_login(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let provider = payload.get("provider").and_then(|v| v.as_str()).unwrap_or("");
    let valid = provider == "aws"; // Dummy
    let _ = log_audit_external(&state.external_audit_devices, "cloud_iam_login", provider, "", if valid { "success" } else { "failed" }).await;
    if valid {
        Json(serde_json::json!({"token": "cloud_iam_token", "method": provider}))
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "Cloud IAM login failed").into_response()
    }
}

pub async fn mfa_login(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let user = payload.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let code = payload.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let valid = code == "123456"; // Dummy
    let _ = log_audit_external(&state.external_audit_devices, "mfa_login", user, "", if valid { "success" } else { "failed" }).await;
    if valid {
        Json(serde_json::json!({"token": "mfa_token", "method": "mfa"}))
    } else {
        (axum::http::StatusCode::UNAUTHORIZED, "MFA login failed").into_response()
    }
}

#[derive(Deserialize)]
pub struct ExecuteSentinelRequest {
    pub namespace: String,
    pub name: String,
    pub user: String,
    pub path: String,
    pub action: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ExecuteSentinelResponse {
    pub allowed: bool,
    pub policy: String,
}

pub async fn execute_sentinel_policy(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ExecuteSentinelRequest>,
) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let policies = storage.list_sentinel_policy_versions(&payload.namespace, &payload.name).await.unwrap_or_default();
    if policies.is_empty() {
        return Json(serde_json::json!({"allowed": false, "policy": payload.name, "error": "not found"})).into_response();
    }
    let found = policies;
    let allowed = crate::services::policy::evaluate_with_sentinel(&found, &payload.user, &payload.path, &payload.action, payload.context.as_ref(), &state).await;
    Json(ExecuteSentinelResponse { allowed, policy: payload.name }).into_response()
} 

#[derive(Deserialize)]
pub struct UploadPluginRequest {
    pub name: String,
    pub version: String,
    pub artifact_b64: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct UploadPluginResponse {
    pub status: String,
    pub name: String,
    pub version: String,
    pub checksum: String,
}

pub async fn upload_plugin_artifact(State(state): State<Arc<AppState>>, Json(payload): Json<UploadPluginRequest>) -> impl IntoResponse {
    let artifact_bytes = base64::decode(&payload.artifact_b64).unwrap_or(vec![]);
    let mut hasher = Sha256::new();
    hasher.update(&artifact_bytes);
    let checksum = format!("{:x}", hasher.finalize());
    // Simpan file plugin ke /opt/vault_plugins/{name}-{version}.so
    let path = format!("/opt/vault_plugins/{}-{}.so", payload.name, payload.version);
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(&artifact_bytes);
    }
    Json(UploadPluginResponse {
        status: "uploaded".to_string(),
        name: payload.name,
        version: payload.version,
        checksum,
    }).into_response()
}

#[derive(Deserialize)]
pub struct PinPluginRequest {
    pub name: String,
    pub version: String,
    pub pinned: bool,
}

#[derive(Serialize)]
pub struct PinPluginResponse {
    pub status: String,
    pub name: String,
    pub version: String,
    pub pinned: bool,
}

pub async fn pin_plugin(State(state): State<Arc<AppState>>, Json(payload): Json<PinPluginRequest>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let _ = storage.pin_plugin(&payload.name, &payload.version, payload.pinned).await;
    let _ = log_audit_external(&state.external_audit_devices, "pin_plugin", "system", &payload.name, if payload.pinned { "pinned" } else { "unpinned" }).await;
    Json(PinPluginResponse {
        status: "ok".to_string(),
        name: payload.name,
        version: payload.version,
        pinned: payload.pinned,
    }).into_response()
}

#[derive(Serialize)]
pub struct ListPluginCatalogResponse {
    pub plugins: Vec<PluginCatalogEntry>,
}

pub async fn list_plugin_catalog(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let plugins = storage.list_plugin_catalog().await.unwrap_or_default();
    Json(ListPluginCatalogResponse { plugins }).into_response()
} 

#[derive(Deserialize)]
pub struct BackupRestoreRequest {
    pub backup: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct BackupRestoreResponse {
    pub status: String,
}

pub async fn get_secret_versions(
    State(state): State<Arc<AppState>>,
    Path((namespace, path)): Path<(String, String)>,
) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let path_str = format!("{}/{}", namespace, path);
    let versions = storage.get_secret_versions(&path_str).await.unwrap_or_default();
    let _ = log_audit_external(&state.external_audit_devices, "get_secret_versions", "system", &path_str, "success").await;
    Json(serde_json::json!({"versions": versions}))
}

pub async fn backup_data(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    let backup = storage.backup_data().await.ok();
    Json(BackupRestoreResponse { status: "ok".to_string() }).into_response()
}

pub async fn restore_data(State(state): State<Arc<AppState>>, Json(payload): Json<BackupRestoreRequest>) -> impl IntoResponse {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    if let Some(backup) = payload.backup {
        let _ = storage.restore_data(&backup).await;
        return Json(BackupRestoreResponse { status: "restored".to_string() }).into_response();
    }
    Json(BackupRestoreResponse { status: "no_backup".to_string() }).into_response()
} 

pub async fn transit_engine(action: &str, payload: &serde_json::Value) -> serde_json::Value {
    match action {
        "create_key" => serde_json::json!({"status": "created", "key_name": payload.get("name").unwrap_or(&serde_json::json!("default"))}),
        "encrypt" => serde_json::json!({"ciphertext": "vault:v1:encrypted..."}),
        "decrypt" => serde_json::json!({"plaintext": "decrypted..."}),
        "list_keys" => serde_json::json!({"keys": ["key1", "key2"]}),
        _ => serde_json::json!({"error": "not implemented"}),
    }
}

pub async fn identity_engine(action: &str, payload: &serde_json::Value) -> serde_json::Value {
    match action {
        "lookup" => serde_json::json!({"entity_id": "entity-123", "aliases": ["user1"]}),
        _ => serde_json::json!({"error": "not implemented"}),
    }
}

pub async fn transform_engine(action: &str, payload: &serde_json::Value) -> serde_json::Value {
    match action {
        "encode" => serde_json::json!({"encoded": "fpe-encoded-abc123"}),
        "decode" => serde_json::json!({"decoded": "fpe-decoded-xyz"}),
        "create_transform" => serde_json::json!({"status": "created", "name": payload.get("name").unwrap_or(&serde_json::json!("default"))}),
        "list_transforms" => serde_json::json!({"transforms": ["ccn_fpe", "ssn_fpe"]}),
        _ => serde_json::json!({"error": "not implemented"}),
    }
}

pub async fn database_engine(action: &str, payload: &serde_json::Value) -> serde_json::Value {
    match action {
        "generate_credential" => serde_json::json!({"username": "dbuser1", "password": "secret123", "expiry": "2024-12-31T23:59:59Z"}),
        "revoke_credential" => serde_json::json!({"status": "revoked"}),
        "list_roles" => serde_json::json!({"roles": ["readonly", "admin"]}),
        _ => serde_json::json!({"error": "not implemented"}),
    }
}

pub async fn totp_engine(action: &str, payload: &serde_json::Value) -> serde_json::Value {
    match action {
        "generate" => serde_json::json!({"totp": "123456", "valid_for": 30}),
        "validate" => serde_json::json!({"valid": payload.get("code") == Some(&serde_json::json!("123456"))}),
        _ => serde_json::json!({"error": "not implemented"}),
    }
}

pub async fn ssh_engine(action: &str, payload: &serde_json::Value) -> serde_json::Value {
    match action {
        "sign_key" => serde_json::json!({"signed_key": "ssh-rsa AAAAB3Nza..."}),
        "generate_key" => serde_json::json!({"private_key": "...", "public_key": "..."}),
        _ => serde_json::json!({"error": "not implemented"}),
    }
}

pub async fn kv2_engine(action: &str, payload: &serde_json::Value, state: &Arc<AppState>) -> serde_json::Value {
    let storage = state.storage.as_any().downcast_ref::<crate::storage::PostgresStorage>().unwrap();
    match action {
        "put" => {
            let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let data = payload.get("data").unwrap_or(&serde_json::json!({}));
            let version = storage.store_secret_versioned(path, data).await.unwrap_or(0);
            serde_json::json!({"status": "ok", "version": version})
        },
        "get" => {
            let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let version = payload.get("version").and_then(|v| v.as_u64());
            let versions = storage.get_secret_versions(path).await.unwrap_or_default();
            let data = if let Some(v) = version {
                versions.into_iter().find(|(ver,_)| *ver as u64 == v).map(|(_,d)| d).unwrap_or(serde_json::json!({}))
            } else {
                versions.first().map(|(_,d)| d.clone()).unwrap_or(serde_json::json!({}))
            };
            serde_json::json!({"data": data})
        },
        "delete" => {
            let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
            // Soft delete: insert tombstone version
            let tombstone = serde_json::json!({"deleted": true, "timestamp": Utc::now()});
            let version = storage.store_secret_versioned(path, &tombstone).await.unwrap_or(0);
            serde_json::json!({"status": "deleted", "version": version})
        },
        "undelete" => {
            let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let versions = storage.get_secret_versions(path).await.unwrap_or_default();
            let last_valid = versions.into_iter().rev().find(|(_,d)| !d.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false));
            if let Some((ver, data)) = last_valid {
                let version = storage.store_secret_versioned(path, &data).await.unwrap_or(0);
                return serde_json::json!({"status": "undeleted", "version": version});
            }
            serde_json::json!({"status": "not_found"})
        },
        "list" => {
            let prefix = payload.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
            // Dummy: list all paths with prefix
            serde_json::json!({"keys": [prefix]})
        },
        "versions" => {
            let path = payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let versions = storage.get_secret_versions(path).await.unwrap_or_default();
            serde_json::json!({"versions": versions})
        },
        _ => serde_json::json!({"error": "not implemented"}),
    }
}

pub async fn generic_engine_route(
    State(state): State<Arc<AppState>>,
    Path((engine_path, action)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let reg = state.engine_registry.lock().unwrap();
    if let Some(engine) = reg.get(&engine_path) {
        let resp = match engine.as_str() {
            "kv2" => kv2_engine(&action, &payload, &state).await,
            "database" => database_engine(&action, &payload).await,
            "transit" => transit_engine(&action, &payload).await,
            "identity" => identity_engine(&action, &payload).await,
            "transform" => transform_engine(&action, &payload).await,
            "totp" => totp_engine(&action, &payload).await,
            "ssh" => ssh_engine(&action, &payload).await,
            _ => serde_json::json!({"status": "ok", "engine": engine, "path": engine_path, "action": action, "payload": payload}),
        };
        return Json(resp);
    }
    Json(serde_json::json!({
        "status": "not_found",
        "path": engine_path,
        "action": action,
    }))
} 

pub async fn sys_tools_echo(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let _ = log_audit_external(&state.external_audit_devices, "sys_tools_echo", "system", "", "access").await;
    Json(serde_json::json!({"echo": payload}))
}

pub async fn sys_experiment_feature(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let _ = log_audit_external(&state.external_audit_devices, "sys_experiment_feature", "system", "", "access").await;
    Json(serde_json::json!({"experiment": "feature stub", "input": payload}))
}

pub async fn sys_internal_diagnostic(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = log_audit_external(&state.external_audit_devices, "sys_internal_diagnostic", "system", "", "access").await;
    Json(serde_json::json!({"diagnostic": "ok", "timestamp": chrono::Utc::now()}))
} 

// Upload versi baru Sentinel policy
#[utoipa::path(post, path = "/admin/sentinel/{namespace}/policy/{name}", request_body = SentinelPolicy, responses((status = 200, description = "Uploaded", body = serde_json::Value)))]
pub async fn admin_upload_sentinel_policy_version(
    State(state): State<Arc<AppState>>,
    Path((namespace, name)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, _, _) = extract_user_info_and_policies(&headers, &state).await.unwrap_or(("anonymous".to_string(), None, vec![]));
    let policy_type = payload.get("policy_type").and_then(|v| v.as_str());
    let source_code = payload.get("source_code").and_then(|v| v.as_str());
    let egp = payload.get("egp").and_then(|v| v.as_bool()).unwrap_or(false);
    let rgp = payload.get("rgp").and_then(|v| v.as_bool()).unwrap_or(false);
    if policy_type.is_none() || policy_type.unwrap().is_empty() || source_code.is_none() || source_code.unwrap().is_empty() {
        return Json(serde_json::json!({"status": "error", "error": "Field 'policy_type' dan 'source_code' wajib diisi"}));
    }
    // Ambil versi terakhir, +1
    let versi_lama = state.storage.list_sentinel_policy_versions(&namespace, &name).await.unwrap_or_default();
    let next_version = versi_lama.first().map(|p| p.version + 1).unwrap_or(1);
    let policy = crate::models::sentinel::SentinelPolicy {
        id: 0,
        namespace: namespace.clone(),
        name: name.clone(),
        version: next_version,
        policy_type: policy_type.unwrap().to_string(),
        source_code: source_code.unwrap().to_string(),
        egp,
        rgp,
        created_at: chrono::Utc::now(),
    };
    let result = state.storage.insert_sentinel_policy_version(&policy).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    if let Err(ref err) = result {
        let _ = writeln!(std::io::stderr(), "[ALERT] Sentinel policy gagal upload versi: {} ({}): {}", namespace, name, err);
    }
    let _ = log_audit_external(&state.external_audit_devices, "upload_sentinel_policy_version", &user_id, &name, status).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "uploaded", "version": next_version})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// List semua versi Sentinel policy
#[utoipa::path(get, path = "/admin/sentinel/{namespace}/policy/{name}/versions", responses((status = 200, description = "List", body = [SentinelPolicy])))]
pub async fn admin_list_sentinel_policy_versions(
    State(state): State<Arc<AppState>>,
    Path((namespace, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, _, _) = extract_user_info_and_policies(&headers, &state).await.unwrap_or(("anonymous".to_string(), None, vec![]));
    let result = state.storage.list_sentinel_policy_versions(&namespace, &name).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "list_sentinel_policy_versions", &user_id, &name, status).await;
    match result {
        Ok(policies) => Json(policies).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// Delete versi Sentinel policy tertentu
#[utoipa::path(delete, path = "/admin/sentinel/{namespace}/policy/{name}/version/{version}", responses((status = 200, description = "Deleted", body = serde_json::Value)))]
pub async fn admin_delete_sentinel_policy_version(
    State(state): State<Arc<AppState>>,
    Path((namespace, name, version)): Path<(String, String, u32)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (user_id, _, _) = extract_user_info_and_policies(&headers, &state).await.unwrap_or(("anonymous".to_string(), None, vec![]));
    let result = state.storage.delete_sentinel_policy_version(&namespace, &name, version).await;
    let status = if result.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "delete_sentinel_policy_version", &user_id, &name, status).await;
    match result {
        Ok(_) => Json(serde_json::json!({"status": "deleted", "version": version})).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
} 

#[utoipa::path(
    post,
    path = "/v1/dynamic/{engine}/credential",
    params(
        ("engine" = String, Path, description = "Engine: mysql|mongo|aws|gcp|azure"),
        ("role" = String, Query, description = "Role name")
    ),
    responses(
        (status = 200, description = "Generated credential", body = serde_json::Value)
    )
)]
pub async fn generate_dynamic_credential(
    Path(engine): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    State(state): State<std::sync::Arc<crate::core::AppState>>,
    headers: HeaderMap,
) -> impl axum::response::IntoResponse {
    let role = params.get("role").cloned().unwrap_or("default".to_string());
    let user_id = headers.get("x-user").and_then(|v| v.to_str().ok()).unwrap_or("anonymous");
    let (resource, resource_type, cred_json) = match engine.as_str() {
        "mysql" => {
            let cred = generate_mysql_credential(&role).await;
            (cred.username.clone(), "mysql", serde_json::to_value(&cred).unwrap())
        },
        "mongo" => {
            let cred = generate_mongo_credential(&role).await;
            (cred.username.clone(), "mongo", serde_json::to_value(&cred).unwrap())
        },
        "aws" => {
            let cred = generate_aws_credential(&role).await;
            (cred.access_key.clone(), "aws", serde_json::to_value(&cred).unwrap())
        },
        "gcp" => {
            let cred = generate_gcp_credential(&role).await;
            (role.clone(), "gcp", serde_json::to_value(&cred).unwrap())
        },
        "azure" => {
            let cred = generate_azure_credential(&role).await;
            (cred.client_id.clone(), "azure", serde_json::to_value(&cred).unwrap())
        },
        _ => return Json(json!({"status": "error", "error": "engine not supported"})),
    };
    let storage = state.storage.as_any().downcast_ref::<Storage>().unwrap();
    let lease = create_lease(storage, user_id, &resource, resource_type, 3600).await;
    let status = if lease.is_ok() { "success" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "generate_dynamic_credential", user_id, &resource, status).await;
    match lease {
        Ok(lease) => Json(json!({"status": "success", "credential": cred_json, "lease": lease})),
        Err(e) => Json(json!({"status": "error", "error": e.to_string()})),
    }
}

#[utoipa::path(
    delete,
    path = "/v1/dynamic/{engine}/credential",
    params(
        ("engine" = String, Path, description = "Engine: mysql|mongo|aws|gcp|azure"),
        ("username" = String, Query, description = "Username/ID to revoke"),
        ("lease_id" = String, Query, description = "Lease ID")
    ),
    responses(
        (status = 200, description = "Revoked", body = serde_json::Value)
    )
)]
pub async fn revoke_dynamic_credential(
    Path(engine): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    State(state): State<std::sync::Arc<crate::core::AppState>>,
    headers: HeaderMap,
) -> impl axum::response::IntoResponse {
    let username = params.get("username").cloned().unwrap_or_default();
    let lease_id = params.get("lease_id").cloned().unwrap_or_default();
    let user_id = headers.get("x-user").and_then(|v| v.to_str().ok()).unwrap_or("anonymous");
    let storage = state.storage.as_any().downcast_ref::<Storage>().unwrap();
    let result = if !lease_id.is_empty() {
        revoke_lease(storage, &lease_id).await
    } else {
        // Fallback: cari lease by resource (username)
        // TODO: implementasi pencarian lease by resource
        Err(anyhow::anyhow!("lease_id wajib diisi"))
    };
    let status = if result.is_ok() { "revoked" } else { "failed" };
    let _ = log_audit_external(&state.external_audit_devices, "revoke_dynamic_credential", user_id, &username, status).await;
    match result {
        Ok(_) => Json(json!({"status": "revoked", "username": username, "lease_id": lease_id})),
        Err(e) => Json(json!({"status": "error", "error": e.to_string()})),
    }
}