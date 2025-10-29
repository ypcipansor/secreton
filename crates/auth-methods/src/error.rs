//! Authentication method specific error types

use secreton_errors::SecretonError;
use thiserror::Error;

/// Errors specific to authentication methods
#[derive(Error, Debug)]
pub enum AuthMethodError {
    #[error("Authentication method not found: {0}")]
    MethodNotFound(String),

    #[error("Authentication method already exists: {0}")]
    MethodAlreadyExists(String),

    #[error("Authentication method disabled")]
    MethodDisabled,

    #[error("Authentication method not supported")]
    MethodNotSupported,

    #[error("Invalid authentication method configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Account locked: {0}")]
    AccountLocked(String),

    #[error("Account disabled: {0}")]
    AccountDisabled(String),

    #[error("Password expired")]
    PasswordExpired,

    #[error("Access denied")]
    AccessDenied,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token invalid: {0}")]
    TokenInvalid(String),

    #[error("Invalid token")]
    InvalidToken,

    #[error("MFA required")]
    MfaRequired,

    #[error("MFA verification failed: {0}")]
    MfaVerificationFailed(String),

    #[error("LDAP connection failed: {0}")]
    LdapConnectionFailed(String),

    #[error("LDAP authentication failed: {0}")]
    LdapAuthFailed(String),

    #[error("LDAP error: {0}")]
    LdapError(String),

    #[error("OIDC provider error: {0}")]
    OidcProviderError(String),

    #[error("OIDC error: {0}")]
    OidcError(String),

    #[error("OAuth2 flow error: {0}")]
    OAuth2FlowError(String),

    #[error("AWS error: {0}")]
    AwsError(String),

    #[error("Kubernetes error: {0}")]
    KubernetesError(String),

    #[error("GitHub error: {0}")]
    GithubError(String),

    #[error("Okta error: {0}")]
    OktaError(String),

    #[error("RADIUS error: {0}")]
    RadiusError(String),

    #[error("SAML assertion error: {0}")]
    SamlAssertionError(String),

    #[error("SAML error: {0}")]
    SamlError(String),

    #[error("Certificate parse error: {0}")]
    CertificateParseError(String),

    #[error("Certificate not yet valid")]
    CertificateNotYetValid,

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Certificate revoked")]
    CertificateRevoked,

    #[error("Certificate untrusted CA")]
    CertificateUntrustedCa,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid input: {field} - {reason}")]
    InvalidInput { field: String, reason: String },

    #[error("Unsupported method: {method}")]
    UnsupportedMethod { method: String },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

impl From<AuthMethodError> for SecretonError {
    fn from(err: AuthMethodError) -> Self {
        match err {
            // Authentication method management
            AuthMethodError::MethodNotFound(method) => SecretonError::NotFound {
                resource: format!("auth-method:{}", method),
            },
            AuthMethodError::MethodAlreadyExists(method) => SecretonError::AlreadyExists {
                resource: format!("auth-method:{}", method),
            },
            AuthMethodError::MethodDisabled => SecretonError::Authentication {
                message: "Authentication method disabled".to_string(),
            },
            AuthMethodError::MethodNotSupported => SecretonError::Authentication {
                message: "Authentication method not supported".to_string(),
            },

            // Configuration
            AuthMethodError::InvalidConfiguration(msg) => SecretonError::Configuration { message: msg },
            AuthMethodError::ConfigurationError(msg) => SecretonError::Configuration { message: msg },

            // Authentication
            AuthMethodError::AuthenticationFailed(msg) => SecretonError::Authentication { message: msg },
            AuthMethodError::InvalidCredentials(msg) => SecretonError::Authentication { message: msg },
            AuthMethodError::AccessDenied => SecretonError::Authorization {
                message: "Access denied".to_string(),
            },

            // User management
            AuthMethodError::UserNotFound(username) => SecretonError::UserNotFound { username },
            AuthMethodError::RoleNotFound(role) => SecretonError::NotFound {
                resource: format!("role:{}", role),
            },
            AuthMethodError::AccountLocked(username) => SecretonError::AccountLocked { username },
            AuthMethodError::AccountDisabled(username) => SecretonError::AccountDisabled { username },
            AuthMethodError::PasswordExpired => SecretonError::PasswordExpired {
                username: "unknown".to_string(),
            },

            // Token management
            AuthMethodError::TokenExpired => SecretonError::TokenExpired,
            AuthMethodError::TokenInvalid(reason) => SecretonError::TokenInvalid { reason },
            AuthMethodError::InvalidToken => SecretonError::TokenInvalid {
                reason: "Invalid token".to_string(),
            },

            // MFA
            AuthMethodError::MfaRequired => SecretonError::MfaRequired,
            AuthMethodError::MfaVerificationFailed(msg) => SecretonError::MfaAuthError { message: msg },

            // External services
            AuthMethodError::LdapConnectionFailed(msg) |
            AuthMethodError::LdapAuthFailed(msg) |
            AuthMethodError::LdapError(msg) => SecretonError::ServiceUnavailable {
                service: format!("LDAP: {}", msg),
            },
            AuthMethodError::OidcProviderError(msg) |
            AuthMethodError::OidcError(msg) => SecretonError::ServiceUnavailable {
                service: format!("OIDC: {}", msg),
            },
            AuthMethodError::OAuth2FlowError(msg) => SecretonError::ServiceUnavailable {
                service: format!("OAuth2: {}", msg),
            },
            AuthMethodError::AwsError(msg) => SecretonError::ServiceUnavailable {
                service: format!("AWS: {}", msg),
            },
            AuthMethodError::KubernetesError(msg) => SecretonError::ServiceUnavailable {
                service: format!("Kubernetes: {}", msg),
            },
            AuthMethodError::GithubError(msg) => SecretonError::ServiceUnavailable {
                service: format!("GitHub: {}", msg),
            },
            AuthMethodError::OktaError(msg) => SecretonError::ServiceUnavailable {
                service: format!("Okta: {}", msg),
            },
            AuthMethodError::RadiusError(msg) => SecretonError::ServiceUnavailable {
                service: format!("RADIUS: {}", msg),
            },
            AuthMethodError::SamlAssertionError(msg) |
            AuthMethodError::SamlError(msg) => SecretonError::ServiceUnavailable {
                service: format!("SAML: {}", msg),
            },

            // Certificate errors
            AuthMethodError::CertificateParseError(msg) => SecretonError::Validation { message: format!("Certificate parse error: {}", msg) },
            AuthMethodError::CertificateNotYetValid => SecretonError::Validation { message: "Certificate not yet valid".to_string() },
            AuthMethodError::CertificateExpired => SecretonError::Validation { message: "Certificate expired".to_string() },
            AuthMethodError::CertificateRevoked => SecretonError::Validation { message: "Certificate revoked".to_string() },
            AuthMethodError::CertificateUntrustedCa => SecretonError::Validation { message: "Certificate untrusted CA".to_string() },

            // Rate limiting and permissions
            AuthMethodError::RateLimitExceeded => SecretonError::RateLimitExceeded,
            AuthMethodError::PermissionDenied(msg) => SecretonError::Authorization { message: msg },
            AuthMethodError::InvalidInput { field, reason } => SecretonError::InvalidInput { field, reason },
            AuthMethodError::UnsupportedMethod { method } => SecretonError::Validation { message: format!("Unsupported method: {}", method) },
        }
    }
}

impl From<SecretonError> for AuthMethodError {
    fn from(err: SecretonError) -> Self {
        match err {
            // Authentication & Authorization
            SecretonError::Authentication { message } => AuthMethodError::AuthenticationFailed(message),
            SecretonError::Authorization { message } => AuthMethodError::PermissionDenied(message),
            SecretonError::TokenExpired => AuthMethodError::TokenExpired,
            SecretonError::TokenInvalid { reason } => AuthMethodError::TokenInvalid(reason),
            SecretonError::TokenRevoked => AuthMethodError::TokenInvalid("Token revoked".to_string()),
            SecretonError::TokenNotFound { token: _ } => AuthMethodError::InvalidToken,
            SecretonError::TokenRenewalFailed { reason } => AuthMethodError::TokenInvalid(reason),
            SecretonError::InsufficientPermissions { required: _ } => AuthMethodError::AccessDenied,

            // User Management
            SecretonError::UserNotFound { username } => AuthMethodError::UserNotFound(username),
            SecretonError::UserAlreadyExists { username: _ } => AuthMethodError::InvalidCredentials("User already exists".to_string()),
            SecretonError::InvalidCredentials => AuthMethodError::InvalidCredentials("Invalid credentials".to_string()),
            SecretonError::AccountDisabled { username } => AuthMethodError::AccountDisabled(username),
            SecretonError::AccountLocked { username } => AuthMethodError::AccountLocked(username),
            SecretonError::PasswordExpired { username: _ } => AuthMethodError::PasswordExpired,

            // MFA
            SecretonError::MfaRequired => AuthMethodError::MfaRequired,
            SecretonError::MfaCredentialError { message } |
            SecretonError::MfaAuthError { message } => AuthMethodError::MfaVerificationFailed(message),
            SecretonError::MfaAlreadyConfigured { method: _ } => AuthMethodError::InvalidConfiguration("MFA already configured".to_string()),
            SecretonError::MfaNotConfigured { user: _ } => AuthMethodError::MfaVerificationFailed("MFA not configured".to_string()),
            SecretonError::MfaCodeReused => AuthMethodError::MfaVerificationFailed("MFA code reused".to_string()),
            SecretonError::RecoveryCodeUsed => AuthMethodError::MfaVerificationFailed("Recovery code used".to_string()),
            SecretonError::RecoveryCodeNotFound => AuthMethodError::MfaVerificationFailed("Recovery code not found".to_string()),

            // Resource Management
            SecretonError::NotFound { resource } => {
                if resource.starts_with("auth-method:") {
                    AuthMethodError::MethodNotFound(resource[12..].to_string())
                } else if resource.starts_with("role:") {
                    AuthMethodError::RoleNotFound(resource[5..].to_string())
                } else {
                    AuthMethodError::UserNotFound(resource)
                }
            },
            SecretonError::AlreadyExists { resource } => {
                if resource.starts_with("auth-method:") {
                    AuthMethodError::MethodAlreadyExists(resource[12..].to_string())
                } else {
                    AuthMethodError::InvalidConfiguration(format!("{} already exists", resource))
                }
            },
            SecretonError::Conflict { message } => AuthMethodError::InvalidConfiguration(message),

            // Validation
            SecretonError::Validation { message } => AuthMethodError::InvalidConfiguration(message),
            SecretonError::InvalidInput { field, reason } => AuthMethodError::InvalidInput { field, reason },

            // Service & Infrastructure
            SecretonError::ServiceUnavailable { service } => {
                if service.starts_with("LDAP:") {
                    AuthMethodError::LdapError(service[5..].to_string())
                } else if service.starts_with("OIDC:") {
                    AuthMethodError::OidcError(service[5..].to_string())
                } else if service.starts_with("OAuth2:") {
                    AuthMethodError::OAuth2FlowError(service[7..].to_string())
                } else if service.starts_with("AWS:") {
                    AuthMethodError::AwsError(service[4..].to_string())
                } else if service.starts_with("Kubernetes:") {
                    AuthMethodError::KubernetesError(service[12..].to_string())
                } else if service.starts_with("GitHub:") {
                    AuthMethodError::GithubError(service[7..].to_string())
                } else if service.starts_with("Okta:") {
                    AuthMethodError::OktaError(service[5..].to_string())
                } else if service.starts_with("RADIUS:") {
                    AuthMethodError::RadiusError(service[7..].to_string())
                } else if service.starts_with("SAML:") {
                    AuthMethodError::SamlError(service[5..].to_string())
                } else {
                    AuthMethodError::ConfigurationError(format!("Service unavailable: {}", service))
                }
            },

            // Rate Limiting
            SecretonError::RateLimitExceeded => AuthMethodError::RateLimitExceeded,

            // Configuration
            SecretonError::Configuration { message } => AuthMethodError::ConfigurationError(message),

            // Other errors map to generic auth errors
            SecretonError::Database { message } => AuthMethodError::ConfigurationError(format!("Database error: {}", message)),
            SecretonError::Cache { message } => AuthMethodError::ConfigurationError(format!("Cache error: {}", message)),
            SecretonError::Network { message } => AuthMethodError::ConfigurationError(format!("Network error: {}", message)),
            SecretonError::Timeout { operation } => AuthMethodError::ConfigurationError(format!("Timeout: {}", operation)),
            SecretonError::SecurityViolation { violation } => AuthMethodError::PermissionDenied(format!("Security violation: {}", violation)),
            SecretonError::PolicyViolation { policy, reason } => AuthMethodError::PermissionDenied(format!("Policy violation: {} - {}", policy, reason)),
            SecretonError::ComplianceViolation { standard, requirement } => AuthMethodError::PermissionDenied(format!("Compliance violation: {} - {}", standard, requirement)),
            SecretonError::Audit { message } => AuthMethodError::ConfigurationError(format!("Audit error: {}", message)),
            SecretonError::Cryptographic { message } => AuthMethodError::ConfigurationError(format!("Cryptographic error: {}", message)),
            SecretonError::Key { message } => AuthMethodError::ConfigurationError(format!("Key error: {}", message)),
            SecretonError::Encryption { message } => AuthMethodError::ConfigurationError(format!("Encryption error: {}", message)),
            SecretonError::Decryption { message } => AuthMethodError::ConfigurationError(format!("Decryption error: {}", message)),
            SecretonError::QuotaExceeded { resource: _, limit: _, used: _ } => AuthMethodError::RateLimitExceeded,
            SecretonError::Io(err) => AuthMethodError::ConfigurationError(format!("IO error: {}", err)),
            SecretonError::Serialization(err) => AuthMethodError::ConfigurationError(format!("Serialization error: {}", err)),
            SecretonError::TomlSerialization(err) => AuthMethodError::ConfigurationError(format!("TOML serialization error: {}", err)),
            SecretonError::TomlDeserialization(err) => AuthMethodError::ConfigurationError(format!("TOML deserialization error: {}", err)),
            SecretonError::Parse { message } => AuthMethodError::ConfigurationError(format!("Parse error: {}", message)),
            SecretonError::Internal { message } => AuthMethodError::ConfigurationError(format!("Internal error: {}", message)),
            SecretonError::Unknown { message } => AuthMethodError::ConfigurationError(format!("Unknown error: {}", message)),

            // Agent and other specific errors
            SecretonError::AgentConfigError { message } => AuthMethodError::ConfigurationError(format!("Agent config error: {}", message)),
            SecretonError::AgentSinkWriteError { message } => AuthMethodError::ConfigurationError(format!("Agent sink error: {}", message)),
            SecretonError::AgentRenewalError { message } => AuthMethodError::ConfigurationError(format!("Agent renewal error: {}", message)),
            SecretonError::AuthenticatedKeyAuthError { message } => AuthMethodError::AuthenticationFailed(format!("Authenticated key error: {}", message)),
            SecretonError::AuthenticatedKeyPermissionError { message } => AuthMethodError::PermissionDenied(format!("Authenticated key permission error: {}", message)),

            // Identity
            SecretonError::EntityNotFound { entity } => AuthMethodError::UserNotFound(entity),
            SecretonError::AliasExists { alias: _ } => AuthMethodError::InvalidConfiguration("Alias exists".to_string()),
            SecretonError::AliasNotFound { alias: _ } => AuthMethodError::UserNotFound("Alias not found".to_string()),
            SecretonError::EntitySelfMerge => AuthMethodError::InvalidConfiguration("Entity self merge not allowed".to_string()),

            // Hashing
            SecretonError::HashingFailed { message } => AuthMethodError::ConfigurationError(format!("Hashing failed: {}", message)),
        }
    }
}

/// Result type for authentication operations
pub type AuthMethodResult<T> = Result<T, AuthMethodError>;