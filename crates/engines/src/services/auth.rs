//! Authentication service facade for the API layer.
//!
//! This service provides a simplified interface to the unified authentication system,
//! delegating actual authentication logic to the auth crate while maintaining
//! API-specific concerns like session management and storage integration.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::services::crypto::CryptoService;
use secreton_auth::MfaService; // Import MfaService trait
use secreton_auth::{
    AuthResult, AuthService as UnifiedAuthService, JwtTokenService, LoginRequest, TokenConfig,
    User, UserPassAuthMethod,
};
use secreton_storage::{
    EncryptionMetadata, QueryParams, SecretEntry, SecurityLevel, StorageBackend,
};
use thiserror::Error;

pub const USER_STORAGE_PREFIX: &str = "users/";
const SESSION_STORAGE_PREFIX: &str = "sys/auth/sessions/";
/// Storage prefix for persisted revoked tokens.  Each entry is keyed by the
/// SHA-256 hash of the token so the raw token material is never written to
/// storage.  Entries carry `expires_at` equal to the token's own expiry and
/// are cleaned up via `delete_expired`.
const REVOKED_TOKEN_STORAGE_PREFIX: &str = "sys/auth/revoked-tokens/";

#[derive(Debug, Deserialize)]
pub struct ApiLoginRequest {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
}

/// JWT Claims structure
///
/// NOTE: The `email` field is `Option<String>` to match the canonical
/// `secreton_auth::jwt::Claims` struct.  Tokens created with
/// `email: None` serialize as `"email": null`; using a bare `String`
/// here would cause deserialization to fail for those tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// Email
    pub email: Option<String>,
    /// Roles
    pub roles: Vec<String>,
    /// Associated policies
    #[serde(default)]
    pub policies: Vec<String>,
    /// MFA required flag
    #[serde(default)]
    pub mfa_required: bool,
    /// Issued at
    pub iat: usize,
    /// Expiration time
    pub exp: usize,
    /// JWT ID
    pub jti: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
}

/// Authentication service errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("MFA required")]
    MfaRequired,

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("MFA not configured for user '{0}'; please enroll in MFA before logging in")]
    MfaNotConfigured(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Storage error: {0}")]
    Storage(#[from] secreton_storage::StorageError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] secreton_crypto::CryptoError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

// User is now imported from secreton_core::models

/// Role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub refresh_token: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed: chrono::DateTime<chrono::Utc>,
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: User,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiLoginResponse {
    pub token: AuthToken,
}

/// Cached effective configuration (session timeout + global MFA flag).
///
/// Avoids a storage round-trip on every authentication call by caching
/// the result of `get_effective_config()` with a short TTL.
struct CachedEffectiveConfig {
    session_timeout: u64,
    mfa_enabled: bool,
    fetched_at: std::time::Instant,
}

/// Authentication service facade
pub struct AuthenticationService {
    /// Unified authentication service
    auth_service: Arc<UnifiedAuthService>,

    /// UserPass method (kept for direct user management)
    userpass_method: Arc<UserPassAuthMethod>,

    /// Token service for JWT operations
    token_service: JwtTokenService,

    /// Storage backend for sessions
    storage: Arc<dyn StorageBackend + Send + Sync>,

    /// Configuration
    config: AuthConfig,

    /// Token blacklist
    token_blacklist: Arc<tokio::sync::RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,

    /// Crypto service
    crypto: Arc<CryptoService>,

    /// Audit logger
    audit: Option<Arc<crate::services::audit::AuditLogger>>,

    /// MFA service
    mfa_service: Option<Arc<secreton_auth::mfa::CombinedMfaService>>,

    /// Cached effective config to avoid per-request storage reads.
    /// Protected by an RwLock so concurrent auth calls can share the
    /// cached value; only one caller refreshes when the TTL expires.
    effective_config_cache: Arc<tokio::sync::RwLock<Option<CachedEffectiveConfig>>>,
}

/// TTL for the effective-config cache.  30 seconds is short enough that
/// admin config changes propagate quickly, but long enough to avoid a
/// storage round-trip on every authentication call in high-throughput
/// deployments.
const EFFECTIVE_CONFIG_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

impl AuthenticationService {
    /// Get current security config from storage, merging with defaults.
    ///
    /// Results are cached for [`EFFECTIVE_CONFIG_CACHE_TTL`] to avoid a
    /// storage round-trip on every call to `login()`, `authenticate()`,
    /// `refresh_token()`, and `generate_token()`.
    async fn get_effective_config(&self) -> (u64, bool) {
        // Fast path: return cached value if still fresh.
        {
            let cache = self.effective_config_cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < EFFECTIVE_CONFIG_CACHE_TTL {
                    return (cached.session_timeout, cached.mfa_enabled);
                }
            }
        }

        // Slow path: read from storage and update the cache.
        let (session_timeout, mfa_enabled) = self.fetch_effective_config_from_storage().await;

        {
            let mut cache = self.effective_config_cache.write().await;
            *cache = Some(CachedEffectiveConfig {
                session_timeout,
                mfa_enabled,
                fetched_at: std::time::Instant::now(),
            });
        }

        (session_timeout, mfa_enabled)
    }

    /// Read `system/config` from storage and merge with static defaults.
    ///
    /// This is the uncached inner implementation of [`get_effective_config`].
    async fn fetch_effective_config_from_storage(&self) -> (u64, bool) {
        let config_path = "system/config";
        let mut session_timeout = self.config.jwt.expiration;
        let mut mfa_enabled = self.config.mfa.enabled;

        match self.storage.get_by_path(config_path).await {
            Ok(Some(entry)) => {
                if let Some(config_data) = entry.metadata.get("config_data") {
                    match serde_json::from_str::<serde_json::Value>(config_data) {
                        Ok(config) => {
                            if let Some(timeout) =
                                config.get("session_timeout").and_then(|v| v.as_u64())
                            {
                                // Apply the same validation range (60-86400 seconds)
                                // that the admin service enforces during updates.
                                if timeout >= 60 && timeout <= 86400 {
                                    session_timeout = timeout;
                                } else {
                                    tracing::warn!(
                                        "Dynamic session_timeout {} is outside valid range \
                                         (60-86400); using static default {}",
                                        timeout,
                                        self.config.jwt.expiration,
                                    );
                                }
                            }
                            if let Some(mfa) = config.get("enable_mfa").and_then(|v| v.as_bool()) {
                                mfa_enabled = mfa;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse system/config config_data as JSON: {}; \
                                 using static defaults",
                                e,
                            );
                        }
                    }
                }
            }
            Ok(None) => {
                // No dynamic config stored yet — use static defaults (not an error)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read system/config from storage: {}; \
                     using static defaults",
                    e,
                );
            }
        }

        (session_timeout, mfa_enabled)
    }

    /// Get current password policy from storage, merging with defaults
    pub async fn get_password_policy(&self) -> secreton_domain::password::PasswordPolicy {
        let config_path = "system/config";

        // Defaults
        let mut policy = secreton_domain::password::PasswordPolicy {
            min_length: 8,
            max_length: None,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            allowed_special_chars: None,
        };

        match self.storage.get_by_path(config_path).await {
            Ok(Some(entry)) => {
                if let Some(config_data) = entry.metadata.get("config_data") {
                    match serde_json::from_str::<serde_json::Value>(config_data) {
                        Ok(config) => {
                            if let Some(v) = config
                                .get("password_policy_min_length")
                                .and_then(|v| v.as_u64())
                            {
                                // Clamp to usize::MAX to avoid silent truncation on 32-bit platforms.
                                policy.min_length = usize::try_from(v).unwrap_or(usize::MAX);
                            }
                            if let Some(v) = config
                                .get("password_policy_require_uppercase")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_uppercase = v;
                            }
                            if let Some(v) = config
                                .get("password_policy_require_lowercase")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_lowercase = v;
                            }
                            if let Some(v) = config
                                .get("password_policy_require_numbers")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_digit = v;
                            }
                            if let Some(v) = config
                                .get("password_policy_require_special")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_special = v;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse system/config config_data for password policy: {}; \
                                 using defaults",
                                e,
                            );
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "Failed to read system/config for password policy: {}; using defaults",
                    e,
                );
            }
        }

        policy
    }

    /// Create new authentication service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        config: &AuthConfig,
    ) -> Result<Self> {
        // Create token service
        let token_config = TokenConfig {
            jwt_secret: config
                .jwt
                .secret
                .clone()
                .expect("JWT secret must be configured"),
            jwt_refresh_secret: config
                .jwt
                .secret
                .clone()
                .expect("JWT secret must be configured"), // Use same secret as no refresh_secret field
            access_token_duration: chrono::Duration::from_std(std::time::Duration::from_secs(
                config.jwt.expiration,
            ))
            .unwrap_or(chrono::Duration::hours(1)),
            refresh_token_duration: chrono::Duration::from_std(std::time::Duration::from_secs(
                config.jwt.refresh_expiration,
            ))
            .unwrap_or(chrono::Duration::days(7)),
            issuer: config.jwt.issuer.clone(),
            audience: config.jwt.audience.clone(),
        };
        let token_service = JwtTokenService::new(token_config);

        // Create unified auth service
        let auth_service = Arc::new(UnifiedAuthService::new());

        // Register default authentication methods
        let mut userpass_method_impl = UserPassAuthMethod::new();
        // Initialize/Enable the method
        // Manually enable as we are skipping the full init flow for built-in method
        use secreton_auth::service::AuthMethodImpl;
        let _ = userpass_method_impl
            .init(&secreton_auth::model::AuthMethod {
                method_type: secreton_auth::model::AuthMethodType::UserPass,
                enabled: true,
                config: HashMap::new(),
            })
            .await;

        let userpass_method = Arc::new(userpass_method_impl);
        auth_service
            .register_method("userpass".to_string(), userpass_method.clone())
            .await;

        // Load existing users from storage.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded to 100 users; without an explicit
        // limit it would now load every user row into memory (and decrypt
        // each one) on every service construction. 50k is generous enough
        // for typical deployments while still bounding worst-case startup
        // memory.
        //
        // TODO: Move user-cache hydration off the startup path entirely so
        // that `UserPassAuthMethod` lazy-loads users on first authentication
        // instead of bulk-loading them up front.
        const USER_LOAD_MAX_ENTRIES: u32 = 50_000;
        let params = QueryParams::new()
            .with_path_prefix(USER_STORAGE_PREFIX.to_string())
            .with_limit(USER_LOAD_MAX_ENTRIES);
        if let Ok(entries) = storage.list(&params).await {
            for entry in entries {
                // Try decrypting the data, strictly requiring encryption
                let user_data = match crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted) => decrypted,
                    Err(_) => {
                        // Skip users with invalid encryption (removes plaintext fallback weakness)
                        continue;
                    }
                };

                if let Ok(user) = serde_json::from_slice::<User>(&user_data) {
                    userpass_method
                        .add_user(
                            user.username.clone(),
                            user.password_hash.clone(),
                            user.id.clone(),
                            user.roles.clone(),
                            user.policies.clone(),
                            user.permissions.clone(),
                        )
                        .await;
                }
            }
        }

        Ok(Self {
            auth_service,
            userpass_method,
            token_service,
            storage,
            config: config.clone(),
            token_blacklist: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            audit: None,
            mfa_service: None,
            crypto,
            effective_config_cache: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    pub fn with_audit(mut self, audit: Arc<crate::services::audit::AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn with_mfa(mut self, mfa: Arc<secreton_auth::mfa::CombinedMfaService>) -> Self {
        self.mfa_service = Some(mfa);
        self
    }

    /// Enforce MFA for the given user, returning `Ok(mfa_verified)` if the
    /// user is allowed to proceed.
    ///
    /// The boolean indicates whether MFA was actually verified:
    /// - `true`  — MFA code was validated successfully.
    /// - `false` — MFA was not required (non-privileged + global MFA off)
    ///             or TOFU applies (privileged user without MFA configured).
    ///
    /// Callers should set `mfa_required: true` on issued tokens when the
    /// return value is `false` and the user is privileged (TOFU), so that
    /// downstream authorization middleware can restrict scope until MFA
    /// enrollment is completed.
    ///
    /// This is the single source of truth for MFA enforcement so that
    /// `login()` and `authenticate()` stay in sync.
    /// Create and store a new session, returning the session ID and expiry.
    ///
    /// This helper encapsulates the session object creation, serialization,
    /// encryption, and storage, ensuring consistent metadata handling across
    /// all authentication flows.
    async fn create_and_store_session(
        &self,
        user_id: &str,
        session_id: String,
        access_token: String,
        refresh_token: Option<String>,
        ip_address: String,
        user_agent: String,
        duration_secs: u64,
    ) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
        let now = chrono::Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(std::time::Duration::from_secs(duration_secs))
                .unwrap_or(chrono::Duration::hours(1));

        let session = Session {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            token: access_token,
            refresh_token,
            ip_address,
            user_agent,
            created_at: now,
            expires_at,
            last_accessed: now,
        };

        let session_json = serde_json::to_vec(&session).map_err(|e| {
            AuthError::Internal(anyhow::anyhow!("Failed to serialize session: {}", e))
        })?;

        let session_data = self.crypto.encrypt_data(&session_json).await.map_err(|e| {
            AuthError::Internal(anyhow::anyhow!("Failed to encrypt session: {}", e))
        })?;

        let entry = SecretEntry::new(
            format!("{}{}", SESSION_STORAGE_PREFIX, session_id),
            session_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(user_id).unwrap_or_default(),
        )
        .with_expiration(expires_at);

        self.storage
            .store(&entry)
            .await
            .map_err(AuthError::Storage)?;

        Ok(expires_at)
    }

    async fn enforce_mfa(
        &self,
        username: &str,
        user_id: &str,
        is_privileged: bool,
        global_mfa_enabled: bool,
        mfa_code: Option<String>,
    ) -> Result<bool, AuthError> {
        if !(is_privileged || global_mfa_enabled) {
            return Ok(false);
        }

        let mut mfa_verified = false;

        if let Some(mfa) = &self.mfa_service {
            let user_uuid = Uuid::parse_str(user_id).map_err(|_| {
                tracing::error!(
                    "enforce_mfa: failed to parse user_id '{}' as UUID for user '{}'; \
                     denying access to prevent nil-UUID TOFU bypass",
                    user_id,
                    username
                );
                AuthError::Internal(anyhow::anyhow!(
                    "Cannot enforce MFA: invalid user ID format"
                ))
            })?;
            let mfa_configured = match mfa.is_mfa_required(user_uuid).await {
                Ok(configured) => configured,
                Err(e) => {
                    // Fail-safe: treat MFA service errors as "MFA is required"
                    // rather than silently bypassing.  A transient MFA service
                    // failure should not allow a privileged user through without
                    // MFA when they have already configured it.
                    tracing::warn!(
                        "MFA service error for user '{}': {}; \
                         treating as MFA-required (fail-safe)",
                        username,
                        e
                    );
                    true
                }
            };

            if mfa_configured {
                let code = mfa_code.ok_or_else(|| AuthError::MfaRequired)?;

                use secreton_auth::mfa::{MfaMethod, MfaValidationRequest};
                let validation_request = MfaValidationRequest {
                    entity_id: user_uuid,
                    method: MfaMethod::Totp,
                    code: Some(code),
                    hardware_request: None,
                    push_notification_id: None,
                    push_response: None,
                    webauthn_response: None,
                };

                if !mfa.validate(validation_request).await.unwrap_or(false) {
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: username.to_string(),
                                    method: "totp".to_string(),
                                    reason: "Invalid MFA code".to_string(),
                                },
                            )
                            .await;
                    }
                    return Err(AuthError::InvalidMfaCode);
                }
                mfa_verified = true;
            } else {
                // TOFU (Trust On First Use) — the user has not yet
                // configured MFA, but MFA is required (either because the
                // user is privileged or because global MFA is enabled).
                //
                // Rather than hard-denying the login — which would lock
                // out every non-privileged user the moment an admin flips
                // on global MFA, since there is no self-service enrollment
                // path without an authenticated session — we issue a
                // restricted-scope token.  The callers (`login()` and
                // `authenticate()`) set `mfa_required: true` on the issued
                // token when TOFU applies (`!mfa_verified` and MFA was
                // required), and the `enforce_mfa_pending` middleware
                // restricts the token's scope to MFA-enrollment and
                // logout endpoints only.  The user must complete MFA
                // enrollment before the token grants access to anything
                // else.
                let reason = if is_privileged {
                    "privileged user authenticated without MFA"
                } else {
                    "global MFA enabled but user has not enrolled; \
                     granting restricted token for enrollment"
                };
                tracing::warn!(
                    "TOFU: user '{}' — {}; MFA enrollment should be completed immediately",
                    username,
                    reason
                );
                if let Some(audit) = &self.audit {
                    let _ = audit
                        .log_event(
                            crate::services::audit::SecurityEventType::AuthenticationSuccess {
                                user: username.to_string(),
                                method: "password_no_mfa_setup".to_string(),
                            },
                        )
                        .await;
                }
            }
        } else if is_privileged {
            return Err(AuthError::Internal(anyhow::anyhow!(
                "MFA service not configured but required for privileged access"
            )));
        } else {
            // Global MFA is enabled but the MFA service is not registered.
            // Fail-safe: deny login rather than silently bypassing the
            // admin's explicit MFA enforcement.
            tracing::error!(
                "Global MFA enabled but MFA service not configured; \
                 denying login for user '{}'",
                username
            );
            return Err(AuthError::Internal(anyhow::anyhow!(
                "MFA service not configured but global MFA is enabled; \
                 please contact your administrator"
            )));
        }

        Ok(mfa_verified)
    }

    /// Authenticate user with username and password
    pub async fn login(
        &self,
        req: ApiLoginRequest,
        ip_address: String,
        user_agent: String,
    ) -> secreton_domain::Result<ApiLoginResponse> {
        // Get effective config for session timeout and MFA enforcement
        let (session_timeout_secs, global_mfa_enabled) = self.get_effective_config().await;

        // Root user cannot login via password (authentication is handled via unseal/SSS token)
        if req.username == "root" {
            return Err(secreton_domain::SecretonError::Authentication {
                message: "Root login disabled via password. Use unseal process.".to_string(),
            }
            .into());
        }

        // Check lockout status before attempting login.
        // Propagate storage errors so that a transient failure does not
        // silently skip the lockout check (which would allow a locked-out
        // user to authenticate).  This mirrors the fail-closed approach
        // used in `authenticate()`.
        let user_path = format!("{}{}", USER_STORAGE_PREFIX, req.username);
        let user_entry = match self.storage.get_by_path(&user_path).await {
            Ok(entry) => entry,
            Err(e) => {
                tracing::warn!(
                    "Failed to load user '{}' from storage during login: {}",
                    req.username,
                    e
                );
                return Err(secreton_domain::SecretonError::Internal {
                    message: "An internal error occurred during authentication".to_string(),
                }
                .into());
            }
        };
        let mut stored_user: Option<User> = None;

        if let Some(ref entry) = user_entry {
            // Decrypt and deserialize user
            if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await {
                if let Ok(u) = serde_json::from_slice::<User>(&decrypted) {
                    stored_user = Some(u.clone());
                    if let Some(locked_until) = u.locked_until {
                        if locked_until > chrono::Utc::now() {
                            if let Some(audit) = &self.audit {
                                let _ = audit.log_event(crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: req.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked".to_string(),
                                }).await;
                            }
                            return Err(secreton_domain::SecretonError::Authentication {
                                message: "Account is locked. Please try again later.".to_string(),
                            }
                            .into());
                        }
                    }

                    // Also check disabled/inactive status — mirrors authenticate()
                    if u.disabled || !u.enabled || !u.is_active {
                        return Err(secreton_domain::SecretonError::Authentication {
                            message: "Invalid credentials".to_string(),
                        }
                        .into());
                    }
                }
            }
        }

        // Create login request.
        // Do NOT pass mfa_code to auth_service.login() — MFA is validated
        // explicitly below via `enforce_mfa()`.  Passing it here could cause
        // double-validation issues if the underlying auth service ever starts
        // consuming TOTP codes (which are single-use).  This mirrors the same
        // pattern used in `authenticate()`.
        let request = LoginRequest {
            username: req.username.clone(),
            password: req.password.clone(),
            mfa_code: None,
            remember_me: Some(false),
        };

        // Authenticate using unified auth service
        let response = self.auth_service.login(&request).await.map_err(|e| {
            secreton_domain::SecretonError::Authentication {
                message: e.to_string(),
            }
        })?;

        if !response.success {
            // Handle failed login attempt
            if let Some(mut u) = stored_user {
                u.failed_login_attempts += 1;

                // Max attempts check (e.g. 5), but exempt privileged users from auto-lockout (DoS protection)
                if !u.is_privileged() && u.failed_login_attempts >= 5 {
                    u.locked_until = Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                    // Log lockout
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: req.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked due to too many failed attempts"
                                        .to_string(),
                                },
                            )
                            .await;
                    }
                }

                // Encrypt and update user in storage
                if let Ok(user_data) = serde_json::to_vec(&u) {
                    if let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await {
                        if let Some(mut entry) = user_entry {
                            entry.encrypted_data = encrypted;
                            let _ = self.storage.store(&entry).await;
                        }
                    }
                }
            }

            return Err(secreton_domain::SecretonError::Authentication {
                message: "Invalid credentials".to_string(),
            }
            .into());
        }

        let user_info =
            response
                .user_info
                .ok_or_else(|| secreton_domain::SecretonError::Internal {
                    message: "No user info returned".to_string(),
                })?;

        // Convert UserInfo to User (simplified)
        let mut user = if let Some(u) = stored_user {
            u
        } else {
            User {
                id: user_info.id.clone().unwrap_or_default(),
                username: user_info.username.clone(),
                email: user_info.email,
                display_name: user_info.display_name.clone(),
                full_name: user_info.display_name,
                password_hash: "".to_string(), // Not used in API responses
                is_active: true,
                is_superuser: false,
                disabled: false,
                roles: user_info.roles.clone(),
                permissions: vec![],
                policies: vec!["default".to_string()], // Default policies as UserInfo lacks them
                enabled: true,
                mfa_enabled: false,
                mfa_secret: None,
                last_login: None,               // UserInfo lacks last_login
                created_at: chrono::Utc::now(), // UserInfo lacks created_at
                updated_at: chrono::Utc::now(),
                metadata: user_info.metadata.clone(),
                failed_login_attempts: 0,
                locked_until: None,
            }
        };

        // Enforce MFA for privileged users (admin/root) or if globally enabled.
        // Delegates to the shared `enforce_mfa()` helper so that `login()` and
        // `authenticate()` use identical enforcement logic.
        let is_privileged =
            user.roles.contains(&"admin".to_string()) || user.roles.contains(&"root".to_string());

        // Guard against empty user IDs for privileged users — mirrors the
        // check in `authenticate()` at lines 1624-1632.  An empty user ID
        // would cause `Uuid::parse_str("").unwrap_or_default()` inside
        // `enforce_mfa()` to yield `Uuid::nil()`, making
        // `is_mfa_required(nil_uuid)` return `false` and triggering the
        // TOFU path — silently bypassing MFA for the privileged user.
        if user.id.is_empty() && is_privileged {
            return Err(secreton_domain::SecretonError::Internal {
                message: "Cannot enforce MFA: no valid user ID available for privileged user"
                    .to_string(),
            }
            .into());
        }

        let mfa_verified = match self
            .enforce_mfa(
                &req.username,
                &user.id,
                is_privileged,
                global_mfa_enabled,
                req.mfa_code.clone(),
            )
            .await
        {
            Ok(verified) => verified,
            Err(mfa_err) => {
                // Increment failed_login_attempts on MFA failure so that the
                // lockout mechanism also covers MFA brute-force attempts.
                // Without this, an attacker who knows the password could try
                // unlimited MFA codes without ever triggering account lockout.
                //
                // Only count `InvalidMfaCode` — an actual wrong code — toward
                // lockout.  `MfaRequired` (first step of a two-step login) and
                // `MfaNotConfigured` (user hasn't enrolled yet) are NOT attack
                // indicators and should not accumulate lockout attempts:
                //   - MfaRequired fires on every first-step login attempt in a
                //     two-step flow; counting it would lock out legitimate users
                //     after a few page refreshes.
                //   - MfaNotConfigured fires every time a user who hasn't
                //     enrolled tries to log in; counting it would permanently
                //     lock them out before they can ever enroll.
                if matches!(mfa_err, AuthError::InvalidMfaCode) {
                    user.failed_login_attempts += 1;

                    if !user.is_privileged() && user.failed_login_attempts >= 5 {
                        user.locked_until =
                            Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                        if let Some(audit) = &self.audit {
                            let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: req.username.clone(),
                                    method: "mfa".to_string(),
                                    reason: "Account locked due to too many failed attempts"
                                        .to_string(),
                                },
                            )
                            .await;
                        }
                    }

                    // Persist the updated counter
                    if let Ok(user_data) = serde_json::to_vec(&user) {
                        if let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await {
                            if let Some(mut entry) = user_entry {
                                entry.encrypted_data = encrypted;
                                let _ = self.storage.store(&entry).await;
                            }
                        }
                    }
                }

                return Err(match mfa_err {
                    AuthError::MfaRequired => secreton_domain::SecretonError::MfaRequired,
                    AuthError::MfaNotConfigured(ref user) => {
                        secreton_domain::SecretonError::MfaNotConfigured { user: user.clone() }
                    }
                    AuthError::InvalidMfaCode => secreton_domain::SecretonError::Authentication {
                        message: "Authentication failed".to_string(),
                    },
                    AuthError::Internal(ref inner) => {
                        secreton_domain::SecretonError::Configuration {
                            message: inner.to_string(),
                        }
                    }
                    other => secreton_domain::SecretonError::Authentication {
                        message: other.to_string(),
                    },
                }
                .into());
            }
        };

        // Reset failed login attempts on success
        // Also ensure user is persisted if it didn't exist (new user)
        let should_persist =
            user_entry.is_none() || user.failed_login_attempts > 0 || user.locked_until.is_some();

        if user.failed_login_attempts > 0 || user.locked_until.is_some() {
            user.failed_login_attempts = 0;
            user.locked_until = None;
        }

        if should_persist {
            // Update user in storage
            if let Ok(user_data) = serde_json::to_vec(&user)
                && let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await
            {
                let entry = if let Some(mut e) = user_entry {
                    e.encrypted_data = encrypted;
                    e
                } else {
                    SecretEntry::new(
                        user_path,
                        encrypted,
                        EncryptionMetadata::default(),
                        SecurityLevel::Secret,
                        Uuid::parse_str(&user.id).unwrap_or_default(),
                    )
                };
                let _ = self.storage.store(&entry).await;
            }
        }

        // Create token pair with session binding, using the dynamic timeout so
        // that the JWT `exp` claim stays in sync with the session `expires_at`.
        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Set mfa_required on the token when TOFU was used (user
        // authenticated without MFA but MFA was required — either because
        // they are privileged or because global MFA is enabled).  This
        // allows downstream authorization middleware (`enforce_mfa_pending`)
        // to restrict token scope to MFA-enrollment endpoints until the
        // user completes enrollment.
        let token_mfa_required = (is_privileged || global_mfa_enabled) && !mfa_verified;

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token_pair = self
            .token_service
            .create_token_pair_with_duration(
                &user.id,
                &user.username,
                user.email.as_deref(), // Convert Option<&String> to Option<&str>
                &user.roles,
                &user.policies, // Use user.policies which we just created
                token_mfa_required,
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|e| secreton_domain::SecretonError::Authentication {
                message: e.to_string(),
            })?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                &user.id,
                temp_session_id,
                token_pair.access_token.clone(),
                Some(token_pair.refresh_token.clone()),
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await
            .map_err(|e| match e {
                AuthError::MfaRequired => secreton_domain::SecretonError::MfaRequired,
                AuthError::MfaNotConfigured(u) => {
                    secreton_domain::SecretonError::MfaNotConfigured { user: u }
                }
                AuthError::InvalidMfaCode => secreton_domain::SecretonError::Authentication {
                    message: "Authentication failed".to_string(),
                },
                _ => secreton_domain::SecretonError::Authentication {
                    message: "Authentication failed".to_string(),
                },
            })?;

        Ok(ApiLoginResponse {
            token: AuthToken {
                access_token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                token_type: token_pair.token_type,
                expires_in: token_pair.expires_in,
                user,
            },
        })
    }

    /// Validate access token.
    ///
    /// # Contract: MFA-pending metadata propagation
    ///
    /// When the JWT carries `mfa_required: true` (a TOFU token issued to a
    /// user who has not yet completed MFA enrollment), this method **must**
    /// insert `metadata["mfa_pending"] = "true"` on the returned `User`.
    ///
    /// Downstream authorization layers rely on this contract:
    ///   - `crate::middleware::enforce_mfa_pending` (`crates/api/src/middleware.rs`)
    ///     reads `metadata["mfa_pending"]` to restrict the token's scope to
    ///     MFA-enrollment endpoints.
    ///   - The refresh handler (`crates/api/src/handlers/auth.rs`) propagates
    ///     the flag onto refreshed tokens so TOFU users cannot escape the
    ///     restriction by refreshing.
    ///
    /// Removing or changing this propagation silently disables the entire
    /// TOFU MFA enforcement chain — any change here must be accompanied by
    /// matching changes in both call sites above.
    pub async fn validate_token(&self, token: &str) -> Result<User, AuthError> {
        // Check blacklist
        if self.is_token_revoked(token).await {
            return Err(AuthError::InvalidToken);
        }

        let claims = self
            .token_service
            .validate_access_token(token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Verify session binding (Security hardening)
        // Ensure the session associated with this token still exists and is valid
        let session_path = format!("{}{}", SESSION_STORAGE_PREFIX, claims.claims.jti);
        if !self.storage.exists(&session_path).await.unwrap_or(false) {
            return Err(AuthError::InvalidToken);
        }

        // Track TOFU MFA enrollment status on the returned User via
        // metadata so that callers (middleware, handlers) can enforce
        // restricted scope for privileged users who have not yet
        // completed MFA enrollment.
        //
        // We do NOT reject TOFU tokens here because doing so creates a
        // deadlock: the user needs an authenticated session to reach the
        // `/mfa/setup` endpoint, but `validate_token` is called by both
        // the global `auth_middleware` and the `AuthenticatedUser`
        // extractor.  Blanket rejection would lock the user out of every
        // endpoint — including the one they need to complete enrollment.
        //
        // Instead, the `mfa_pending` metadata flag is set so that
        // authorization layers can selectively deny access to sensitive
        // operations while still allowing MFA enrollment endpoints.
        let mfa_pending = claims.claims.mfa_required;

        // Convert claims to User — use the roles AND policies embedded in the
        // JWT so that authorization checks after token validation see the same
        // claims the token was issued with.  Previously `policies` was hardcoded
        // to `["default"]`, which stripped any non-default policies the user had
        // at login time.
        let mut metadata = HashMap::new();
        if mfa_pending {
            metadata.insert("mfa_pending".to_string(), "true".to_string());
        }

        Ok(User {
            id: claims.claims.sub,
            username: claims.claims.username.clone(),
            email: claims.claims.email.clone(),
            password_hash: "".to_string(),
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: claims.claims.roles.clone(),
            permissions: vec![],
            policies: claims.claims.policies.clone(),
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata,
            failed_login_attempts: 0,
            locked_until: None,
        })
    }

    /// Compute the storage path for a revoked-token entry.
    ///
    /// Uses SHA-256 so the raw token material is never written to storage —
    /// we only persist a hash that's sufficient to detect replay of the same
    /// token.
    fn revoked_token_path(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        format!("{}{}", REVOKED_TOKEN_STORAGE_PREFIX, hex::encode(digest))
    }

    /// Revoke a token.
    ///
    /// Writes the revocation to both the in-memory blacklist (fast path for
    /// the local instance) and the shared storage backend (so other
    /// instances see the revocation).  Storage failures are logged but do
    /// not fail the call — the in-memory entry still prevents replay on
    /// this instance, and the session-binding check in `validate_token`
    /// provides additional defense when sessions are deleted.
    pub async fn revoke_token(&self, token: String, expires_at: chrono::DateTime<chrono::Utc>) {
        // In-memory update (fast path).
        {
            let mut blacklist = self.token_blacklist.write().await;
            // Clean up expired entries while we're at it
            blacklist.retain(|_, &mut exp| exp > chrono::Utc::now());
            blacklist.insert(token.clone(), expires_at);
        }

        // Persist the revocation so other instances see it.  We store an
        // empty encrypted payload — the presence of the entry at the
        // hash-keyed path is what signals revocation, and `expires_at`
        // drives automatic cleanup via `delete_expired`.
        let path = Self::revoked_token_path(&token);
        let entry = SecretEntry::new(
            path,
            Vec::new(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        )
        .with_expiration(expires_at);

        if let Err(e) = self.storage.store(&entry).await {
            tracing::warn!(
                "Failed to persist revoked token to storage: {}; \
                 revocation is still active on this instance but may not \
                 propagate to other instances",
                e
            );
        }
    }

    /// Check if a token is revoked.
    ///
    /// Checks the in-memory blacklist first (fast path), then falls back to
    /// the shared storage backend so revocations made on other instances
    /// are honored.  A storage lookup failure is treated as "not revoked"
    /// (fail-open) so that a transient storage hiccup does not lock out
    /// every user — the session-binding check in `validate_token` remains
    /// the authoritative defense.
    pub async fn is_token_revoked(&self, token: &str) -> bool {
        // In-memory fast path.
        {
            let blacklist = self.token_blacklist.read().await;
            if let Some(expires_at) = blacklist.get(token) {
                if *expires_at > chrono::Utc::now() {
                    return true;
                }
            }
        }

        // Shared-storage fallback: check whether another instance has
        // persisted a revocation for this token.
        let path = Self::revoked_token_path(token);
        match self.storage.get_by_path(&path).await {
            Ok(Some(entry)) => {
                // If the entry exists and has not yet expired, the token is
                // revoked.  Populate the in-memory cache so subsequent
                // checks hit the fast path.
                let still_valid = entry
                    .expires_at
                    .map(|exp| exp > chrono::Utc::now())
                    .unwrap_or(true);
                if still_valid {
                    if let Some(exp) = entry.expires_at {
                        let mut blacklist = self.token_blacklist.write().await;
                        blacklist.insert(token.to_string(), exp);
                    }
                    return true;
                }
                false
            }
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    "Failed to check persisted revoked-token store: {}; \
                     falling back to in-memory check only",
                    e
                );
                false
            }
        }
    }

    /// Refresh access token
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthToken, AuthError> {
        // Fast-path early reject for a previously-exchanged refresh token.
        // This is purely an optimisation — the authoritative single-use
        // check is the atomic check-and-insert on the in-memory blacklist
        // below, which closes the TOCTOU window between this check and the
        // eventual `revoke_token` call.
        if self.is_token_revoked(refresh_token).await {
            return Err(AuthError::InvalidToken);
        }

        // Validate first to get user info for session creation.  Validation
        // is side-effect-free so performing it before the CAS is safe —
        // two concurrent requests will both validate, but only one will win
        // the atomic insert below.
        let claims = self
            .token_service
            .validate_refresh_token(refresh_token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Revoke the old refresh token so it cannot be reused.
        // This implements single-use refresh token rotation: each refresh
        // token can only be exchanged once.  Without this, a captured
        // refresh token could be replayed indefinitely to generate new
        // sessions without invalidating previous ones.
        //
        // We also attempt to find and revoke the old session that was
        // associated with this refresh token, so that the old access token
        // is invalidated as well.
        let refresh_expiry = chrono::Utc::now() + chrono::Duration::days(8);
        // Atomically check-and-insert the refresh token into the in-memory
        // blacklist while holding the write lock across both operations.
        // This closes the TOCTOU window between the `is_token_revoked` call
        // above and the `revoke_token` insert below: two concurrent requests
        // for the same refresh token will both pass the fast-path check, but
        // only the first one to acquire the write lock will find the slot
        // empty and insert — the second will observe the existing entry and
        // be rejected with `InvalidToken`.
        //
        // The shared storage layer is still updated via `revoke_token` below
        // so that cross-instance revocation continues to work; that call is
        // idempotent on the storage side (same hash-keyed path).
        {
            let mut blacklist = self.token_blacklist.write().await;
            if let Some(expires_at) = blacklist.get(refresh_token) {
                if *expires_at > chrono::Utc::now() {
                    return Err(AuthError::InvalidToken);
                }
            }
            blacklist.insert(refresh_token.to_string(), refresh_expiry);
        }
        {
            // Revoke the refresh token itself (add to blacklist with a
            // generous expiry — refresh tokens are long-lived).
            //
            // The in-memory insert was already done atomically above; this
            // call re-inserts the same entry (idempotent) and additionally
            // persists the revocation to shared storage for cross-instance
            // propagation.
            self.revoke_token(refresh_token.to_string(), refresh_expiry)
                .await;

            // Best-effort: find and delete the old session whose refresh_token
            // matches the one being exchanged.  This is a scan over the
            // session prefix — acceptable because refresh is infrequent.
            //
            // Cap the scan with an explicit upper bound.  Before the
            // PostgreSQL backend's default `LIMIT 100` was removed (in the
            // lifecycle PR), this scan was implicitly bounded; without an
            // explicit limit it would now load every active session into
            // memory on every refresh.
            //
            // TODO: Index sessions by refresh-token hash so this scan can be
            // replaced with a direct lookup.
            const SESSION_REFRESH_SCAN_MAX_ENTRIES: u32 = 10_000;
            let params = secreton_storage::QueryParams {
                path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
                include_expired: false,
                limit: Some(SESSION_REFRESH_SCAN_MAX_ENTRIES),
                ..Default::default()
            };
            if let Ok(entries) = self.storage.list(&params).await {
                for entry in entries {
                    let session_bytes = match self.crypto.decrypt(&entry.encrypted_data).await {
                        Ok(decrypted) => decrypted,
                        Err(decrypt_err) => {
                            // Only fall back to raw bytes if they look like
                            // valid JSON (legacy plaintext session).
                            if serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data)
                                .is_ok()
                            {
                                tracing::warn!(
                                    "Session '{}': decryption failed, using legacy plaintext fallback",
                                    entry.path
                                );
                                entry.encrypted_data.clone()
                            } else {
                                tracing::warn!(
                                    "Session '{}': decryption failed ({}) and raw data is not valid JSON; \
                                     skipping corrupt entry",
                                    entry.path,
                                    decrypt_err
                                );
                                continue; // skip corrupt entries
                            }
                        }
                    };
                    if let Ok(session) = serde_json::from_slice::<Session>(&session_bytes) {
                        if session.refresh_token.as_deref() == Some(refresh_token) {
                            // Revoke the old access token
                            self.revoke_token(session.token.clone(), session.expires_at)
                                .await;
                            // Delete the old session record
                            let _ = self.storage.delete_by_path(&entry.path).await;
                            break;
                        }
                    }
                }
            }
        }

        // Get effective config for session timeout
        let (session_timeout_secs, _) = self.get_effective_config().await;

        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Load user from storage to get current roles/policies instead of
        // using empty slices which would strip all authorization claims.
        // A storage or decryption failure here is treated as an error rather
        // than silently downgrading the token to empty roles — a transient
        // storage hiccup should not strip a user's authorization.
        let user_path = format!("{}{}", USER_STORAGE_PREFIX, claims.username);
        let user_entry = self
            .storage
            .get_by_path(&user_path)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to load user '{}' during token refresh: {}",
                    claims.username,
                    e
                );
                AuthError::Storage(e)
            })?
            .ok_or_else(|| {
                tracing::warn!(
                    "User '{}' not found in storage during token refresh",
                    claims.username
                );
                AuthError::UserNotFound
            })?;
        let decrypted = self
            .crypto
            .decrypt(&user_entry.encrypted_data)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to decrypt user '{}' during token refresh: {}",
                    claims.username,
                    e
                );
                AuthError::Internal(anyhow::anyhow!("Failed to decrypt user data: {}", e))
            })?;
        let stored_user: User = serde_json::from_slice(&decrypted).map_err(|e| {
            tracing::warn!(
                "Failed to deserialize user '{}' during token refresh: {}",
                claims.username,
                e
            );
            AuthError::Internal(anyhow::anyhow!("Failed to deserialize user data: {}", e))
        })?;

        // Reject token refresh for disabled or locked accounts.
        // Without this check a user whose account was disabled/locked after
        // login could keep refreshing tokens indefinitely.
        if stored_user.disabled || !stored_user.enabled || !stored_user.is_active {
            tracing::warn!(
                "Token refresh denied for user '{}': account is disabled/inactive",
                claims.username
            );
            return Err(AuthError::InvalidCredentials);
        }
        if let Some(locked_until) = stored_user.locked_until {
            if locked_until > chrono::Utc::now() {
                tracing::warn!(
                    "Token refresh denied for user '{}': account is locked until {}",
                    claims.username,
                    locked_until
                );
                return Err(AuthError::InvalidCredentials);
            }
        }

        let is_privileged = stored_user.roles.contains(&"admin".to_string())
            || stored_user.roles.contains(&"root".to_string());

        // Re-read the global MFA flag so that a user who authenticated under
        // the TOFU path (non-privileged + global MFA on) cannot escape the
        // `mfa_pending` restriction simply by refreshing their token.
        let (_, global_mfa_enabled_for_refresh) = self.get_effective_config().await;

        // Check whether the user still needs MFA enrollment.  If MFA is
        // required for this user (privileged or global MFA enabled) and
        // they have not yet configured it, the refreshed token must carry
        // `mfa_required: true` so that the auth_middleware continues to
        // restrict scope.  Without this, a TOFU user could call the refresh
        // endpoint (which does not go through validate_token) to obtain a
        // new access token with `mfa_required: false`, completely bypassing
        // MFA enforcement.
        let token_mfa_required = if is_privileged || global_mfa_enabled_for_refresh {
            if let Some(mfa) = &self.mfa_service {
                let user_uuid = Uuid::parse_str(&stored_user.id).map_err(|_| {
                    tracing::error!(
                        "refresh_token: failed to parse user_id '{}' as UUID for user '{}'; \
                         denying refresh to prevent nil-UUID TOFU bypass",
                        stored_user.id,
                        claims.username
                    );
                    AuthError::Internal(anyhow::anyhow!(
                        "Cannot check MFA status: invalid user ID format"
                    ))
                })?;
                let mfa_configured = match mfa.is_mfa_required(user_uuid).await {
                    Ok(configured) => configured,
                    Err(e) => {
                        // Fail-safe: treat MFA service errors as "MFA is
                        // required" and deny the refresh entirely, consistent
                        // with `enforce_mfa()`.  A transient MFA service
                        // failure should not allow a privileged user to obtain
                        // a new token — even a restricted one — when their MFA
                        // enrollment status cannot be verified.
                        tracing::warn!(
                            "MFA service error during token refresh for user '{}': {}; \
                             denying refresh (fail-safe)",
                            claims.username,
                            e
                        );
                        return Err(AuthError::Internal(anyhow::anyhow!(
                            "Cannot verify MFA status during token refresh; please try again later"
                        )));
                    }
                };
                !mfa_configured // mfa_required = true when NOT configured
            } else {
                // MFA service not available — fail-safe: deny the refresh
                // rather than issuing a token without MFA verification.
                return Err(AuthError::Internal(anyhow::anyhow!(
                    "MFA service not configured but required for privileged token refresh"
                )));
            }
        } else {
            false
        };

        let (user_roles, user_policies, user_email) =
            (stored_user.roles, stored_user.policies, stored_user.email);

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token_pair = self
            .token_service
            .create_token_pair_with_duration(
                &claims.sub,
                &claims.username,
                user_email.as_deref(),
                &user_roles,
                &user_policies,
                token_mfa_required,
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|_| AuthError::InvalidToken)?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                &claims.sub,
                temp_session_id,
                token_pair.access_token.clone(),
                Some(token_pair.refresh_token.clone()),
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await
            .map_err(AuthError::from)?;

        // Build the User from the data we already loaded from storage
        // (or from the token claims as a fallback).
        //
        // Propagate the `mfa_pending` metadata flag when the refreshed token
        // carries `mfa_required: true`, matching the contract documented on
        // `validate_token`.  This lets the refresh handler (and any other
        // caller that consumes `AuthToken.user` directly) read the TOFU flag
        // without having to re-validate the just-issued access token.
        let mut metadata = HashMap::new();
        if token_mfa_required {
            metadata.insert("mfa_pending".to_string(), "true".to_string());
        }
        let user = User {
            id: claims.sub.clone(),
            username: claims.username.clone(),
            email: user_email,
            display_name: None,
            disabled: false,
            password_hash: "".to_string(),
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: user_roles,
            permissions: vec![],
            policies: user_policies,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata,
            failed_login_attempts: 0,
            locked_until: None,
        };

        Ok(AuthToken {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_in: token_pair.expires_in,
            user,
        })
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<User, AuthError> {
        // Check if user exists
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        if self.storage.exists(&path).await? {
            return Err(AuthError::UserAlreadyExists);
        }

        let user_id = Uuid::new_v4().to_string();

        // Create in UserPass method (generates hash)
        let password_hash = self
            .userpass_method
            .create_user(
                username.to_string(),
                password,
                user_id.clone(),
                roles.clone(),
                vec!["default".to_string()],
                permissions.clone(),
            )
            .await
            .map_err(|_| {
                AuthError::Internal(anyhow::anyhow!("Failed to create user in auth method"))
            })?;

        let user = User {
            id: user_id,
            username: username.to_string(),
            email: email.clone(),
            password_hash,
            full_name: None,
            is_active: true,
            is_superuser: roles.contains(&"admin".to_string())
                || roles.contains(&"root".to_string()),
            roles,
            permissions,
            policies: vec!["default".to_string()],
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };

        // Store user
        let user_data = serde_json::to_vec(&user)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        // Encrypt user data
        let encrypted_data = self.crypto.encrypt_data(&user_data).await.map_err(|e| {
            AuthError::Crypto(secreton_crypto::CryptoError::Internal(e.to_string()))
        })?;

        let entry = SecretEntry::new(
            path,
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(&user.id).unwrap_or_default(),
        );

        self.storage.store(&entry).await?;

        Ok(user)
    }

    /// Create user (wrapper for register_user)
    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<User, AuthError> {
        self.register_user(
            username,
            password,
            Some(email.to_string()),
            roles,
            permissions,
        )
        .await
    }

    /// Check if user has permission (simplified)
    pub async fn has_permission(&self, user: &User, permission: &str) -> Result<bool, AuthError> {
        // Simplified permission check based on roles
        // In production, this would use a proper RBAC system
        if user.is_admin() {
            return Ok(true);
        }

        // Check for specific permissions based on roles
        match permission {
            "secreton:read" | "secreton:list" => Ok(user.roles.contains(&"user".to_string())
                || user.roles.contains(&"viewer".to_string())),
            "secreton:write" => Ok(user.roles.contains(&"user".to_string())),
            _ => Ok(false),
        }
    }

    /// Get total user count
    pub async fn get_user_count(&self) -> Result<u64, AuthError> {
        let params = QueryParams::new().with_path_prefix(USER_STORAGE_PREFIX.to_string());
        let count = self.storage.count(&params).await?;
        Ok(count)
    }

    /// Get active session count
    pub async fn get_active_session_count(&self) -> Result<u64, AuthError> {
        let params = QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            ..Default::default()
        };

        let count = self
            .storage
            .count(&params)
            .await
            .map_err(AuthError::Storage)?;

        Ok(count)
    }

    /// List sessions for a specific user
    pub async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, AuthError> {
        // We scan all sessions and filter by user_id
        // In a real DB we would index this or use a secondary index.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now load every active session into memory and decrypt each
        // one. 10k is generous for a single user's session list while still
        // bounding worst-case memory.
        //
        // TODO: Index sessions by `user_id` so this scan can be replaced
        // with a direct lookup.
        const SESSION_LIST_MAX_ENTRIES: u32 = 10_000;
        let params = QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            include_expired: false,
            limit: Some(SESSION_LIST_MAX_ENTRIES),
            ..Default::default()
        };

        let entries = self
            .storage
            .list(&params)
            .await
            .map_err(AuthError::Storage)?;

        let mut sessions = Vec::new();
        for entry in entries {
            // Decrypt session data, with fallback for legacy plaintext entries.
            let session_bytes = match self.crypto.decrypt(&entry.encrypted_data).await {
                Ok(decrypted) => decrypted,
                Err(decrypt_err) => {
                    // Only fall back to raw bytes if they look like valid JSON
                    // (i.e. a legacy plaintext session).  If the raw bytes are
                    // NOT valid JSON either, this is genuine data corruption —
                    // log it and skip the entry rather than silently producing
                    // a garbage Session.
                    if serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data).is_ok() {
                        tracing::warn!(
                            "Session '{}': decryption failed, using legacy plaintext fallback",
                            entry.path
                        );
                        entry.encrypted_data.clone()
                    } else {
                        tracing::warn!(
                            "Session '{}': decryption failed ({}) and raw data is not valid JSON; \
                             skipping corrupt entry",
                            entry.path,
                            decrypt_err
                        );
                        continue;
                    }
                }
            };
            if let Ok(session) = serde_json::from_slice::<Session>(&session_bytes) {
                if session.user_id == user_id {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    /// Revoke a specific user session
    pub async fn revoke_user_session(
        &self,
        session_id: &str,
        user_id: &str,
    ) -> Result<(), AuthError> {
        let path = format!("{}{}", SESSION_STORAGE_PREFIX, session_id);

        // Verify ownership
        if let Some(entry) = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AuthError::Storage)?
        {
            // Decrypt session data, with fallback for legacy plaintext entries.
            let session_bytes = match self.crypto.decrypt(&entry.encrypted_data).await {
                Ok(decrypted) => decrypted,
                Err(decrypt_err) => {
                    // Only fall back to raw bytes if they look like valid JSON
                    // (i.e. a legacy plaintext session).  If the raw bytes are
                    // NOT valid JSON either, this is genuine data corruption —
                    // deny the request rather than risking a failed ownership check.
                    if serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data).is_ok() {
                        tracing::warn!(
                            "Session '{}': decryption failed, using legacy plaintext fallback",
                            session_id
                        );
                        entry.encrypted_data.clone()
                    } else {
                        tracing::warn!(
                            "Session '{}': decryption failed ({}) and raw data is not valid JSON; \
                             cannot verify ownership",
                            session_id,
                            decrypt_err
                        );
                        return Err(AuthError::Internal(anyhow::anyhow!(
                            "Cannot verify session ownership: failed to decrypt session data"
                        )));
                    }
                }
            };
            // The ownership check is security-critical: we MUST verify that
            // the caller owns this session before deleting it.  If
            // deserialization fails (e.g. because the encrypted data could
            // not be decrypted and the raw ciphertext is not valid JSON),
            // deny the request rather than skipping the ownership check and
            // allowing any authenticated user to delete arbitrary sessions.
            let session = serde_json::from_slice::<Session>(&session_bytes).map_err(|e| {
                tracing::warn!(
                    "Failed to deserialize session '{}' during revocation \
                     (ownership check cannot be performed): {}",
                    session_id,
                    e
                );
                AuthError::Internal(anyhow::anyhow!(
                    "Cannot verify session ownership: failed to read session data"
                ))
            })?;
            if session.user_id != user_id {
                return Err(AuthError::PermissionDenied);
            }
            // Revoke the token associated with this session
            self.revoke_token(session.token, session.expires_at).await;
        } else {
            return Err(AuthError::Storage(
                secreton_storage::StorageError::NotFound {
                    resource_type: "session".to_string(),
                    id: session_id.to_string(),
                },
            ));
        }

        self.storage
            .delete_by_path(&path)
            .await
            .map_err(AuthError::Storage)?;

        Ok(())
    }

    /// Cleanup expired sessions and revoked-token entries.
    ///
    /// Also prunes stale revocations from the shared storage backend so the
    /// revoked-token store does not grow unboundedly.  The in-memory
    /// blacklist is self-cleaning on every `revoke_token` call.
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, AuthError> {
        let deleted_count = self
            .storage
            .delete_expired(Some(SESSION_STORAGE_PREFIX.to_string()))
            .await
            .map_err(AuthError::Storage)?;

        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired sessions", deleted_count);
        }

        // Also prune expired revocation entries.  Failures are logged but
        // not propagated — session cleanup succeeding is still useful even
        // if the revocation store is temporarily unavailable.
        match self
            .storage
            .delete_expired(Some(REVOKED_TOKEN_STORAGE_PREFIX.to_string()))
            .await
        {
            Ok(n) if n > 0 => {
                tracing::info!("Cleaned up {} expired token revocations", n);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up expired token revocations: {}", e);
            }
        }

        Ok(deleted_count)
    }

    /// Verify password for a user
    pub async fn verify_password(&self, username: &str, password: &str) -> Result<bool, AuthError> {
        let request = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            mfa_code: None,
            remember_me: None,
        };

        match self.auth_service.login(&request).await {
            Ok(response) => Ok(response.success),
            Err(_) => Ok(false),
        }
    }

    /// Generate access token for user
    pub async fn generate_token(
        &self,
        user: &User,
        ip_address: String,
        user_agent: String,
    ) -> Result<String, AuthError> {
        // Get effective config for session timeout
        let (session_timeout_secs, _) = self.get_effective_config().await;

        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token = self
            .token_service
            .create_access_token_with_duration(
                &user.id,
                &user.username,
                user.email.as_deref(),
                &user.roles,
                &user.policies,
                false, // MFA not required for simple token generation
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Token generation failed: {}", e)))?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                &user.id,
                temp_session_id,
                token.clone(),
                None,
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await
            .map_err(AuthError::from)?;

        Ok(token)
    }

    /// Generate refresh token for user
    ///
    /// Uses the token service's `create_refresh_token` method to produce a
    /// `RefreshTokenClaims`-based token signed with `jwt_refresh_secret`.
    /// This ensures the token can be validated by `validate_refresh_token`
    /// (which expects `RefreshTokenClaims` and uses `jwt_refresh_secret`).
    ///
    /// Previously this method used the API-local `Claims` struct and signed
    /// with `jwt_secret`, creating a structural and key mismatch that would
    /// cause `refresh_token()` → `validate_refresh_token()` to fail.
    pub async fn generate_refresh_token(&self, user: &User) -> Result<String, AuthError> {
        self.token_service
            .create_refresh_token(&user.id, &user.username)
            .map_err(|e| {
                AuthError::Internal(anyhow::anyhow!("Refresh token generation failed: {}", e))
            })
    }

    /// Authenticate user
    pub async fn authenticate(
        &self,
        credentials: crate::services::auth::LoginRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult, AuthError> {
        // Root user cannot login via password — mirrors the check in `login()`
        // so that the root account is consistently blocked from password-based
        // authentication regardless of which code path is used.
        if credentials.username == "root" {
            return Err(AuthError::InvalidCredentials);
        }

        // Load user from storage ONCE at the start so that lockout checks,
        // failed-attempt increments, policy loading, and counter resets all
        // operate on the same snapshot.  This eliminates the TOCTOU window
        // that existed when the user was re-read up to 3 times, and avoids
        // the extra storage + decryption overhead.
        let user_path = format!("{}{}", USER_STORAGE_PREFIX, credentials.username);
        let (mut pre_auth_user, mut pre_auth_entry) = match self
            .storage
            .get_by_path(&user_path)
            .await
        {
            Ok(Some(entry)) => {
                let decrypted = self
                    .crypto
                    .decrypt(&entry.encrypted_data)
                    .await
                    .map_err(|e| {
                        tracing::warn!(
                            "Failed to decrypt user '{}' during authenticate: {}",
                            credentials.username,
                            e
                        );
                        AuthError::Internal(anyhow::anyhow!("Failed to decrypt user data: {}", e))
                    })?;
                let u: User = serde_json::from_slice(&decrypted).map_err(|e| {
                    tracing::warn!(
                        "Failed to deserialize user '{}' during authenticate: {}",
                        credentials.username,
                        e
                    );
                    AuthError::Internal(anyhow::anyhow!("Failed to deserialize user data: {}", e))
                })?;
                (Some(u), Some(entry))
            }
            Ok(None) => (None, None),
            Err(e) => {
                tracing::warn!(
                    "Failed to load user '{}' from storage during authenticate: {}",
                    credentials.username,
                    e
                );
                return Err(AuthError::Storage(e));
            }
        };

        // Check lockout status before attempting login — mirrors the check in
        // `login()` so that locked accounts cannot authenticate through this
        // code path.
        if let Some(ref u) = pre_auth_user {
            if let Some(locked_until) = u.locked_until {
                if locked_until > chrono::Utc::now() {
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: credentials.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked".to_string(),
                                },
                            )
                            .await;
                    }
                    return Err(AuthError::InvalidCredentials);
                }
            }
            if u.disabled || !u.enabled || !u.is_active {
                return Err(AuthError::InvalidCredentials);
            }
        }

        // Do NOT pass mfa_code to auth_service.login() — MFA is validated
        // explicitly below.  Passing it here could cause double-validation
        // issues if the underlying auth service ever starts consuming TOTP
        // codes (which are single-use).
        let request = secreton_auth::LoginRequest {
            username: credentials.username.clone(),
            password: credentials.password,
            mfa_code: None,
            remember_me: credentials.remember_me,
        };

        let result = self
            .auth_service
            .login(&request)
            .await
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Auth failed: {}", e)))?;

        if !result.success {
            // Increment failed_login_attempts and persist — mirrors the logic
            // in `login()` so that the lockout check at the top of this method
            // actually triggers after repeated failures.
            if let Some(ref mut u) = pre_auth_user {
                u.failed_login_attempts += 1;

                // Max attempts check (e.g. 5), but exempt privileged
                // users from auto-lockout (DoS protection).
                if !u.is_privileged() && u.failed_login_attempts >= 5 {
                    u.locked_until = Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: credentials.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked due to too many failed attempts"
                                        .to_string(),
                                },
                            )
                            .await;
                    }
                }

                // Encrypt and update user in storage
                if let Ok(user_data) = serde_json::to_vec(&u) {
                    if let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await {
                        if let Some(mut entry) = pre_auth_entry.take() {
                            entry.encrypted_data = encrypted;
                            let _ = self.storage.store(&entry).await;
                        }
                    }
                }
            }

            return Err(AuthError::InvalidCredentials);
        }

        // Generate token explicitly if not part of AuthResult yet in this version,
        // or ensure AuthResult has what we need.
        // Logic in login() (line 175) generates tokens using self.token_service.
        // We should replicate that or use it.

        let user_info = result
            .user_info
            .as_ref()
            .ok_or(AuthError::Internal(anyhow::anyhow!("No user info")))?;

        let user_roles = &user_info.roles;

        // Use the user loaded at the start of the method for policies and
        // the MFA / counter-reset logic below.  Fall back to ["default"]
        // only when the user is not yet persisted (e.g. first login via
        // external auth).
        //
        // NOTE: The failed_login_attempts counter is reset AFTER MFA
        // enforcement (below) so that failed MFA attempts still count toward
        // the lockout threshold.  This matches the order used in `login()`.
        //
        // Capture the stored user's ID before moving pre_auth_user into
        // stored_user_entry.  This is used for MFA enforcement below so
        // that we always pass a real user ID to `enforce_mfa()` instead of
        // relying on `user_info.id` which may be `None` for external auth
        // methods.  A nil UUID would cause `is_mfa_required` to return
        // `false`, triggering the TOFU path and bypassing MFA for
        // privileged users.
        let stored_user_id: Option<String> = pre_auth_user.as_ref().map(|u| u.id.clone());
        let (policies, stored_user_entry) = match (pre_auth_user, pre_auth_entry) {
            (Some(u), Some(entry)) => (u.policies.clone(), Some((u, entry))),
            _ => (vec!["default".to_string()], None),
        };

        // Generate session ID
        let session_id = Uuid::new_v4().to_string();

        // Get effective config for session timeout and MFA enforcement
        let (session_timeout_secs, global_mfa_enabled) = self.get_effective_config().await;

        // Enforce MFA for privileged users (admin/root) or if globally enabled.
        // Uses the shared `enforce_mfa()` helper so that `login()` and
        // `authenticate()` have identical enforcement logic.
        //
        // This MUST happen BEFORE resetting failed_login_attempts so that
        // failed MFA attempts still count toward the lockout threshold,
        // preventing unlimited MFA brute-force.
        let is_privileged =
            user_roles.contains(&"admin".to_string()) || user_roles.contains(&"root".to_string());

        // Prefer the user ID loaded from storage (which is always a valid
        // UUID) over `user_info.id` (which may be `None` for external auth
        // providers).  An empty/nil UUID would cause `enforce_mfa` to query
        // the MFA service for the nil UUID, get `mfa_configured = false`,
        // and take the TOFU path — silently bypassing MFA for privileged
        // users.
        let effective_user_id = stored_user_id
            .as_deref()
            .or(user_info.id.as_deref())
            .unwrap_or_default();

        if effective_user_id.is_empty() && is_privileged {
            // A privileged user with no resolvable user ID is a serious
            // configuration error — deny login rather than risk an MFA
            // bypass via the nil-UUID TOFU path.
            return Err(AuthError::Internal(anyhow::anyhow!(
                "Cannot enforce MFA: no valid user ID available for privileged user '{}'",
                credentials.username
            )));
        }

        let mfa_verified = match self
            .enforce_mfa(
                &credentials.username,
                effective_user_id,
                is_privileged,
                global_mfa_enabled,
                credentials.mfa_code,
            )
            .await
        {
            Ok(verified) => verified,
            Err(mfa_err) => {
                // Only count `InvalidMfaCode` toward lockout — see the
                // matching comment in `login()` for the full rationale.
                if matches!(mfa_err, AuthError::InvalidMfaCode) {
                    if let Some((mut u, entry)) = stored_user_entry {
                        u.failed_login_attempts += 1;

                        if !u.is_privileged() && u.failed_login_attempts >= 5 {
                            u.locked_until =
                                Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                            if let Some(audit) = &self.audit {
                                let _ = audit
                                .log_event(
                                    crate::services::audit::SecurityEventType::AuthenticationFailure {
                                        user: credentials.username.clone(),
                                        method: "mfa".to_string(),
                                        reason: "Account locked due to too many failed attempts"
                                            .to_string(),
                                    },
                                )
                                .await;
                            }
                        }

                        // Persist the updated counter
                        if let Ok(user_data) = serde_json::to_vec(&u) {
                            if let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await {
                                let mut updated_entry = entry;
                                updated_entry.encrypted_data = encrypted;
                                let _ = self.storage.store(&updated_entry).await;
                            }
                        }
                    }
                }

                return Err(mfa_err);
            }
        };

        // Reset failed login attempts on success — mirrors the logic in
        // `login()` so that the counter does not accumulate across
        // successful logins, which would cause premature lockout on the
        // next failure.  This runs AFTER MFA enforcement so that a failed
        // MFA code does not reset the counter.
        if let Some((mut u, entry)) = stored_user_entry {
            if u.failed_login_attempts > 0 || u.locked_until.is_some() {
                u.failed_login_attempts = 0;
                u.locked_until = None;

                if let Ok(user_data) = serde_json::to_vec(&u) {
                    if let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await {
                        let mut updated_entry = entry;
                        updated_entry.encrypted_data = encrypted;
                        let _ = self.storage.store(&updated_entry).await;
                    }
                }
            }
        }

        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Generate tokens with session binding, using the dynamic timeout so
        // that the JWT `exp` claim stays in sync with the session `expires_at`.
        // Set mfa_required on the token when TOFU was used (user
        // authenticated without MFA but MFA was required), mirroring the
        // logic in `login()`.  Uses the same formula as `login()` —
        // `(is_privileged || global_mfa_enabled) && !mfa_verified`.
        // Previously this also OR'd in `result.mfa_required` from the underlying
        // auth service, but `login()` did not, creating an inconsistency.  Since
        // we pass `mfa_code: None` to `auth_service.login()` and handle MFA
        // entirely via `enforce_mfa()`, `result.mfa_required` is not meaningful
        // here and would only cause divergent behavior if the auth service
        // evolves to set it independently.
        let token_mfa_required = (is_privileged || global_mfa_enabled) && !mfa_verified;

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token_pair = self
            .token_service
            .create_token_pair_with_duration(
                user_info.id.as_deref().unwrap_or_default(),
                &user_info.username,
                user_info.email.as_deref(),
                user_roles,
                &policies,
                token_mfa_required,
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|_| AuthError::Internal(anyhow::anyhow!("Token generation failed")))?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                user_info.id.as_deref().unwrap_or_default(),
                temp_session_id,
                token_pair.access_token.clone(),
                Some(token_pair.refresh_token.clone()),
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await
            .map_err(AuthError::from)?;

        let mut result_metadata = std::collections::HashMap::new();
        result_metadata.insert("expires_in".to_string(), token_pair.expires_in.to_string());

        Ok(AuthResult {
            success: true,
            token: Some(token_pair.access_token),
            refresh_token: Some(token_pair.refresh_token),
            user_info: result.user_info,
            policies,
            metadata: result_metadata,
            mfa_required: token_mfa_required,
        })
    }

    /// OAuth login - create or update user from OAuth info
    pub async fn oauth_login(
        &self,
        oauth_user: &OAuthUserInfo,
    ) -> Result<User, AuthError> {
        // Try to find existing user by OAuth ID or email
        // For now, create a stub user
        let user = User {
            id: oauth_user.id.clone(),
            username: if oauth_user.username.is_empty() {
                // Fall back to the email, then to the provider id, so a provider that
                // omits a username can still produce a usable account rather than one
                // with an empty primary identifier.
                oauth_user
                    .email
                    .clone()
                    .unwrap_or_else(|| oauth_user.id.clone())
            } else {
                oauth_user.username.clone()
            },
            email: oauth_user.email.clone(),
            display_name: oauth_user.display_name.clone(),
            disabled: false,
            password_hash: "".to_string(), // OAuth users don't have password
            full_name: oauth_user.display_name.clone(),
            is_active: true,
            is_superuser: false,
            roles: vec!["user".to_string()],
            permissions: vec![],
            policies: vec!["default".to_string()],
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::services::crypto::CryptoService;
    // use secreton_crypto::SecurityParams;
    use secreton_storage::backends::MemoryBackend;

    #[tokio::test]
    async fn test_auth_service_creation() {
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();

        let auth_service = AuthenticationService::new(storage, crypto, &config).await;
        assert!(auth_service.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};
        use uuid::Uuid;

        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();

        let auth_service = AuthenticationService::new(storage.clone(), crypto, &config)
            .await
            .unwrap();

        // Add expired session
        let expired_session = SecretEntry::new(
            "sys/auth/sessions/expired1".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() - chrono::Duration::hours(1));
        storage.store(&expired_session).await.unwrap();

        // Add active session
        let active_session = SecretEntry::new(
            "sys/auth/sessions/active1".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() + chrono::Duration::hours(1));
        storage.store(&active_session).await.unwrap();

        // Add unrelated expired entry
        let unrelated_expired = SecretEntry::new(
            "other/path/expired2".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() - chrono::Duration::hours(1));
        storage.store(&unrelated_expired).await.unwrap();

        // Run cleanup
        let cleaned_count = auth_service.cleanup_expired_sessions().await.unwrap();

        // Verify results
        assert_eq!(cleaned_count, 1, "Should cleanup exactly 1 session");

        // Check storage state
        assert!(
            !storage.exists("sys/auth/sessions/expired1").await.unwrap(),
            "Expired session should be removed"
        );
        assert!(
            storage.exists("sys/auth/sessions/active1").await.unwrap(),
            "Active session should remain"
        );
        assert!(
            storage.exists("other/path/expired2").await.unwrap(),
            "Unrelated expired entry should remain"
        );
    }

    #[tokio::test]
    async fn test_get_user_count() {
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};

        let storage = Arc::new(MemoryBackend::new());

        // Add some dummy users
        let user1 = SecretEntry::new(
            format!("{}user1", USER_STORAGE_PREFIX),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let user2 = SecretEntry::new(
            format!("{}user2", USER_STORAGE_PREFIX),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let other = SecretEntry::new(
            "secrets/something".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );

        storage.store(&user1).await.unwrap();
        storage.store(&user2).await.unwrap();
        storage.store(&other).await.unwrap();

        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        let auth_service = AuthenticationService::new(storage, crypto, &config)
            .await
            .unwrap();

        let count = auth_service.get_user_count().await.unwrap();
        assert_eq!(count, 2);
    }
}

/// Profile returned by an OAuth provider's userinfo endpoint.
///
/// Defined here rather than in the HTTP layer: the service consumes it, so the service
/// crate owns it and the handler merely deserialises into it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuthUserInfo {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}
