//! Data models and DTOs for authentication methods

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Authentication method configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethod {
    pub id: Uuid,
    pub name: String,
    pub method_type: AuthMethodType,
    pub config: HashMap<String, serde_json::Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthMethod {{ id: {}, name: {}, type: {:?}, enabled: {} }}",
               self.id, self.name, self.method_type, self.enabled)
    }
}

/// Supported authentication method types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethodType {
    Token,
    UserPass,
    Ldap,
    Oidc,
    OAuth2,
    AppRole,
    Kubernetes,
    Aws,
    Github,
    Okta,
    Radius,
    Saml,
}

/// Authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthCredentials {
    /// Username/password authentication
    UserPass { username: String, password: String },
    /// Token-based authentication
    Token { token: String },
    /// LDAP authentication
    Ldap { username: String, password: String },
    /// OIDC authentication
    Oidc { code: String, state: String },
    /// OAuth2 authentication
    OAuth2 { provider: String, code: String },
    /// AppRole authentication
    AppRole { role_id: String, secret_id: String },
    /// Kubernetes JWT authentication
    Kubernetes { jwt: String },
    /// AWS IAM authentication
    Aws { access_key: String, secret_key: String, session_token: Option<String> },
    /// GitHub token authentication
    Github { token: String },
    /// Okta authentication
    Okta { username: String, password: String },
    /// RADIUS authentication
    Radius { username: String, password: String },
    /// SAML assertion authentication
    Saml { assertion: String },
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub authenticated: bool,
    pub user_info: Option<UserInfo>,
    pub policies: Vec<String>,
    pub lease_duration: Option<i64>,
    pub renewable: Option<bool>,
    pub token: Option<String>,
    pub accessor: Option<String>,
    pub metadata: HashMap<String, String>,
    pub mfa_required: bool,
    pub mfa_methods: Vec<String>,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

impl std::fmt::Display for UserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserInfo {{ id: {}, username: {}, email: {:?}, display_name: {:?}, groups: [{}], metadata: {{{}}} }}",
               self.id,
               self.username,
               self.email,
               self.display_name,
               self.groups.join(", "),
               self.metadata.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join(", "))
    }
}

/// Login request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub method: String,
    pub credentials: AuthCredentials,
    pub mfa_code: Option<String>,
}

/// Login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub auth: AuthResult,
    pub warnings: Vec<String>,
}

/// MFA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub method: MfaMethod,
    pub enabled: bool,
    pub required: bool,
    pub config: HashMap<String, serde_json::Value>,
}

/// MFA methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaMethod {
    Totp,
    Sms,
    Email,
    Push,
    Hardware,
    WebAuthn,
    Recovery,
}

/// MFA setup request
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupRequest {
    pub method: MfaMethod,
    pub email: Option<String>, // Required if method is Email
}

/// MFA setup response
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupResponse {
    pub qr_code_url: Option<String>,                          // For TOTP
    pub secret: Option<String>,                               // For TOTP
    pub webauthn_register_options: Option<serde_json::Value>, // For WebAuthn
}

/// MFA verification request
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerifyRequest {
    pub code: String, // TOTP code or recovery code
}

/// MFA status response
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaStatusResponse {
    pub is_enabled: bool,
    pub method: Option<String>,
    pub setup_required: bool,
    pub enabled_methods: Vec<String>,
}

/// MFA login request
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaLoginRequest {
    pub username: String,
    pub password: String,
    pub code: Option<String>, // MFA code if MFA is enabled
}

/// MFA recovery codes response
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaRecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

/// MFA verification result
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerificationResult {
    pub is_valid: bool,
    pub method: MfaMethod,
    pub message: Option<String>,
}

/// Refresh token request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Authentication request (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthRequest {
    Token { token: String },
    UserPass { username: String, password: String },
    Ldap { username: String, password: String },
    Oidc { code: String, state: String },
    Okta { username: String, password: String },
    Github { token: String },
    Radius { username: String, password: String },
    AppRole { role_id: String, secret_id: String },
    Kubernetes { jwt: String },
}

/// Authentication response (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub authenticated: bool,
    pub user_info: UserInfo,
    pub policies: Vec<String>,
    pub lease_duration: i64,
    pub renewable: bool,
    pub token: String,
    pub accessor: String,
    pub metadata: HashMap<String, String>,
}

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    /// Unique user ID (UUID for consistency)
    pub id: Uuid,
    /// Username for login
    pub username: String,
    /// Email address
    pub email: String,
    /// Argon2id password hash (never expose in API responses)
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// Full name (optional)
    pub full_name: Option<String>,
    /// Account active status
    pub is_active: bool,
    /// Superuser/admin privileges
    pub is_superuser: bool,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Last successful login
    pub last_login: Option<DateTime<Utc>>,
    /// MFA enabled flag
    pub mfa_enabled: bool,
    /// User roles (set for deduplication)
    pub roles: HashSet<String>,
    /// Namespace/tenant (for multi-tenancy)
    pub namespace: String,
    /// Account locked (due to failed attempts)
    pub is_locked: bool,
    /// Failed login attempts counter
    pub failed_attempts: u32,
    /// Lock expiration time
    pub locked_until: Option<DateTime<Utc>>,
}

impl User {
    /// Create new user with defaults
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            full_name: None,
            is_active: true,
            is_superuser: false,
            created_at: now,
            updated_at: now,
            last_login: None,
            mfa_enabled: false,
            roles: HashSet::new(),
            namespace: "default".to_string(),
            is_locked: false,
            failed_attempts: 0,
            locked_until: None,
        }
    }

    /// Check if account is currently locked
    pub fn is_currently_locked(&self) -> bool {
        if !self.is_locked {
            return false;
        }

        if let Some(until) = self.locked_until {
            Utc::now() < until
        } else {
            self.is_locked
        }
    }

    /// Check if user has specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role) || self.is_superuser
    }

    /// Add role to user
    pub fn add_role(&mut self, role: String) {
        self.roles.insert(role);
        self.updated_at = Utc::now();
    }

    /// Remove role from user
    pub fn remove_role(&mut self, role: &str) -> bool {
        let removed = self.roles.remove(role);
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }
}

/// Legacy token structure for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyToken {
    pub token: String,
    pub user: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub orphan: bool,
    pub batch: bool,
    pub locked: bool,
    pub created_at: DateTime<Utc>,
}