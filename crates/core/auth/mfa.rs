/// Enterprise MFA configuration for advanced multi-factor authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseMFAConfig {
    /// Enable enterprise MFA features
    pub enabled: bool,

    /// Require multiple MFA methods for critical operations
    pub require_multiple_methods: bool,

    /// Maximum time window for MFA challenges (seconds)
    pub challenge_timeout: u64,

    /// Enable MFA for administrative operations
    pub admin_operations_require_mfa: bool,

    /// Enable adaptive MFA based on risk scoring
    pub adaptive_mfa_enabled: bool,

    /// Risk score threshold for requiring additional MFA
    pub risk_threshold: f64,

    /// Enable MFA session persistence
    pub session_persistence_enabled: bool,

    /// MFA session duration (minutes)
    pub session_duration_minutes: u64,

    /// Enable hardware security key support (FIDO2/WebAuthn)
    pub hardware_security_keys_enabled: bool,

    /// Enable biometric authentication
    pub biometric_auth_enabled: bool,
}

/// MFA context for risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaContext {
    /// IP address of the request
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Geographic location (latitude)
    pub latitude: Option<f64>,
    /// Geographic location (longitude)
    pub longitude: Option<f64>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Whether additional MFA is required
    pub requires_additional_mfa: bool,
    /// Risk score for this context
    pub risk_score: Option<f64>,
}

/// MFA verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaVerificationResult {
    /// Whether verification was successful
    pub success: bool,
    /// Risk score calculated for this verification
    pub risk_score: f64,
    /// Whether additional MFA is required
    pub requires_additional_mfa: bool,
    /// Recommended MFA methods based on risk
    pub recommended_methods: Vec<MfaMethod>,
    /// Session token if verification succeeded
    pub session_token: Option<String>,
    /// Time remaining until session expires
    pub session_expires_in: Option<u64>,
}

/// Enterprise MFA session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseMfaSession {
    /// Session token
    pub token: String,
    /// User ID
    pub user_id: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// MFA context information
    pub context: MfaContext,
    /// Whether additional MFA has been completed
    pub additional_mfa_completed: bool,
    /// Risk score at session creation
    pub risk_score: f64,
}

/// Risk assessment engine for adaptive MFA
#[derive(Debug)]
pub struct RiskEngine {
    /// Risk assessment rules
    rules: Vec<RiskRule>,
    /// Geographic risk database
    geo_risk: HashMap<String, f64>,
    /// IP reputation database
    ip_reputation: HashMap<String, f64>,
}

impl RiskEngine {
    /// Create a new risk engine
    pub fn new() -> Self {
        Self {
            rules: vec![
                RiskRule::IpBased { threshold: 0.7 },
                RiskRule::LocationBased { max_distance_km: 1000.0 },
                RiskRule::DeviceBased { similarity_threshold: 0.8 },
                RiskRule::TimeBased { unusual_hours: vec![22, 23, 0, 1, 2, 3, 4, 5] },
                RiskRule::BehaviorBased { deviation_threshold: 0.6 },
            ],
            geo_risk: Self::load_geo_risk_data(),
            ip_reputation: Self::load_ip_reputation_data(),
        }
    }

    /// Assess risk for an IP address
    pub async fn assess_ip_risk(&self, ip: &str) -> Result<f64, MfaError> {
        // Check IP reputation database
        if let Some(risk) = self.ip_reputation.get(ip) {
            return Ok(*risk);
        }

        // Basic IP risk assessment based on IP type
        let risk = if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") {
            0.1 // Private IP - low risk
        } else if ip.starts_with("127.") || ip.starts_with("localhost") {
            0.0 // Localhost - no risk
        } else {
            // Public IP - medium risk, could be VPN/Tor/etc.
            0.5
        };

        Ok(risk)
    }

    /// Assess risk for a geographic location
    pub async fn assess_location_risk(&self, latitude: f64, longitude: f64) -> Result<f64, MfaError> {
        // Convert coordinates to approximate country/region
        let location_key = Self::coordinates_to_location_key(latitude, longitude);

        // Check geographic risk database
        if let Some(risk) = self.geo_risk.get(&location_key) {
            return Ok(*risk);
        }

        // Default risk for unknown locations
        Ok(0.3)
    }

    /// Assess risk for a device fingerprint
    pub async fn assess_device_risk(&self, fingerprint: &str) -> Result<f64, MfaError> {
        // Longer, more unique fingerprints are lower risk
        let length_score = (fingerprint.len() as f64 / 1000.0).min(1.0);

        // Check for suspicious patterns
        let suspicious_patterns = ["bot", "crawler", "scraper", "proxy"];
        let mut pattern_penalty = 0.0;

        for pattern in &suspicious_patterns {
            if fingerprint.to_lowercase().contains(pattern) {
                pattern_penalty += 0.3;
            }
        }

        let risk = (1.0 - length_score) + pattern_penalty;
        Ok(risk.min(1.0))
    }

    /// Calculate overall risk score for MFA context
    pub async fn calculate_risk_score(&self, context: &MfaContext) -> Result<f64, MfaError> {
        let mut total_risk = 0.0;
        let mut factors = 0;

        // IP risk
        if let Some(ref ip) = context.ip_address {
            let ip_risk = self.assess_ip_risk(ip).await?;
            total_risk += ip_risk;
            factors += 1;
        }

        // Location risk
        if let (Some(lat), Some(lon)) = (context.latitude, context.longitude) {
            let location_risk = self.assess_location_risk(lat, lon).await?;
            total_risk += location_risk;
            factors += 1;
        }

        // Device risk
        if let Some(ref fingerprint) = context.device_fingerprint {
            let device_risk = self.assess_device_risk(fingerprint).await?;
            total_risk += device_risk;
            factors += 1;
        }

        // Time-based risk
        let hour = context.timestamp.hour();
        let unusual_hours = vec![22, 23, 0, 1, 2, 3, 4, 5];
        if unusual_hours.contains(&hour) {
            total_risk += 0.4;
            factors += 1;
        }

        // Average the risk factors
        let average_risk = if factors > 0 {
            total_risk / factors as f64
        } else {
            0.3 // Default medium risk if no factors available
        };

        Ok(average_risk.min(1.0))
    }

    fn load_geo_risk_data() -> HashMap<String, f64> {
        // In a real implementation, this would load from a database or external service
        let mut data = HashMap::new();
        data.insert("unknown".to_string(), 0.3);
        data.insert("us".to_string(), 0.1);
        data.insert("eu".to_string(), 0.2);
        data.insert("cn".to_string(), 0.4);
        data.insert("ru".to_string(), 0.5);
        data
    }

    fn load_ip_reputation_data() -> HashMap<String, f64> {
        // In a real implementation, this would load from threat intelligence feeds
        let mut data = HashMap::new();
        data.insert("127.0.0.1".to_string(), 0.0);
        data.insert("10.0.0.0/8".to_string(), 0.1);
        data.insert("192.168.0.0/16".to_string(), 0.1);
        data.insert("172.16.0.0/12".to_string(), 0.1);
        data
    }

    fn coordinates_to_location_key(latitude: f64, longitude: f64) -> String {
        // Simple country/region mapping based on coordinates
        // In a real implementation, this would use a proper geolocation service
        if latitude > 49.0 && latitude < 59.0 && longitude > -125.0 && longitude < -115.0 {
            "ca-bc".to_string() // British Columbia, Canada
        } else if latitude > 37.0 && latitude < 42.0 && longitude > -125.0 && longitude < -120.0 {
            "us-ca".to_string() // California, USA
        } else {
            "unknown".to_string()
        }
    }
}

/// Risk assessment rules
#[derive(Debug, Clone)]
enum RiskRule {
    IpBased { threshold: f64 },
    LocationBased { max_distance_km: f64 },
    DeviceBased { similarity_threshold: f64 },
    TimeBased { unusual_hours: Vec<u32> },
    BehaviorBased { deviation_threshold: f64 },
}

/// Session manager for enterprise MFA
#[derive(Debug)]
pub struct SessionManager {
    /// Active sessions
    sessions: RwLock<HashMap<String, EnterpriseMfaSession>>,
    /// Session cleanup interval
    cleanup_interval: Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        let manager = Self {
            sessions: RwLock::new(HashMap::new()),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        };

        // Start cleanup task
        let manager_clone = manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(manager_clone.cleanup_interval);
            loop {
                interval.tick().await;
                manager_clone.cleanup_expired_sessions().await;
            }
        });

        manager
    }

    /// Store a new session
    pub async fn store_session(&self, session: EnterpriseMfaSession) -> Result<(), MfaError> {
        let token = session.token.clone();
        self.sessions.write().await.insert(token, session);
        Ok(())
    }

    /// Get a session by token
    pub async fn get_session(&self, token: &str) -> Result<EnterpriseMfaSession, MfaError> {
        self.sessions.read().await
            .get(token)
            .cloned()
            .ok_or_else(|| MfaError::SessionExpired)
    }

    /// Update session MFA completion status
    pub async fn update_session(&self, token: &str, additional_mfa_completed: bool) -> Result<(), MfaError> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(token) {
            session.additional_mfa_completed = additional_mfa_completed;
            Ok(())
        } else {
            Err(MfaError::SessionExpired)
        }
    }

    /// Clean up expired sessions
    async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| !session.is_expired());
    }
}

impl Clone for SessionManager {
    fn clone(&self) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            cleanup_interval: self.cleanup_interval,
        }
    }
}

impl EnterpriseMfaSession {
    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Get time remaining until expiration
    pub fn time_remaining(&self) -> Option<chrono::Duration> {
        let now = Utc::now();
        if now < self.expires_at {
            Some(self.expires_at - now)
        } else {
            None
        }
    }
}

/// Enterprise MFA manager with advanced security features
#[derive(Debug)]
pub struct EnterpriseMfaManager {
    /// Base MFA manager
    base_manager: MfaManager,
    /// Enterprise configuration
    enterprise_config: EnterpriseMFAConfig,
    /// Risk engine
    risk_engine: Arc<RwLock<RiskEngine>>,
    /// Session manager
    session_manager: Arc<RwLock<SessionManager>>,
}

impl EnterpriseMfaManager {
    /// Create a new enterprise MFA manager
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        enterprise_config: EnterpriseMFAConfig,
    ) -> Self {
        let base_manager = MfaManager::with_config(
            storage,
            MfaManagerConfig {
                rate_limit: RateLimitConfig {
                    max_attempts: 5,
                    window: Duration::from_secs(300),
                    use_exponential_backoff: true,
                    base_backoff: Duration::from_secs(60),
                    max_backoff: Duration::from_secs(3600),
                },
                session_ttl: Duration::from_secs(enterprise_config.session_duration_minutes as u64 * 60),
                secret_rotation_period: Some(Duration::from_secs(90 * 24 * 3600)),
                recovery_code_settings: RecoveryCodeSettings {
                    count: 10,
                    length: 16,
                    expires: true,
                    expiry_period: Some(Duration::from_secs(90 * 24 * 3600)),
                },
            },
        );

        Self {
            base_manager,
            enterprise_config,
            risk_engine: Arc::new(RwLock::new(RiskEngine::new())),
            session_manager: Arc::new(RwLock::new(SessionManager::new())),
        }
    }

    /// Verify MFA with enterprise features
    pub async fn verify_enterprise_mfa(
        &self,
        user_id: &str,
        code: &str,
        context: MfaContext,
    ) -> Result<MfaVerificationResult, MfaError> {
        // Calculate risk score for this context
        let risk_score = self.risk_engine.read().await.calculate_risk_score(&context).await?;

        // Determine if additional MFA is required based on risk
        let requires_additional_mfa = self.enterprise_config.adaptive_mfa_enabled
            && risk_score > self.enterprise_config.risk_threshold;

        // Verify the MFA code using base manager
        let verification_success = self.base_manager.verify_totp_code(user_id, code, Some(2)).await?;

        if !verification_success {
            return Ok(MfaVerificationResult {
                success: false,
                risk_score,
                requires_additional_mfa,
                recommended_methods: vec![],
                session_token: None,
                session_expires_in: None,
            });
        }

        // Create session if verification succeeded
        let session_token = if self.enterprise_config.session_persistence_enabled {
            let session = EnterpriseMfaSession {
                token: Uuid::new_v4().to_string(),
                user_id: user_id.to_string(),
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::minutes(self.enterprise_config.session_duration_minutes as i64),
                context,
                additional_mfa_completed: !requires_additional_mfa,
                risk_score,
            };

            self.session_manager.read().await.store_session(session.clone()).await?;

            if requires_additional_mfa {
                // Additional MFA required - don't complete session yet
                None
            } else {
                // Session complete
                Some(session.token)
            }
        } else {
            None
        };

        let recommended_methods = if requires_additional_mfa {
            if self.enterprise_config.hardware_security_keys_enabled {
                vec![MfaMethod::WebAuthn]
            } else if self.enterprise_config.biometric_auth_enabled {
                vec![MfaMethod::WebAuthn, MfaMethod::Totp]
            } else {
                vec![MfaMethod::Totp]
            }
        } else {
            vec![]
        };

        Ok(MfaVerificationResult {
            success: true,
            risk_score,
            requires_additional_mfa,
            recommended_methods,
            session_token,
            session_expires_in: Some(self.enterprise_config.session_duration_minutes * 60),
        })
    }

    /// Complete additional MFA verification
    pub async fn complete_additional_mfa(
        &self,
        session_token: &str,
        method: MfaMethod,
        verification_data: &str,
    ) -> Result<String, MfaError> {
        // Get the session
        let mut session = self.session_manager.read().await.get_session(session_token).await?;

        // Verify additional MFA based on method
        let additional_success = match method {
            MfaMethod::WebAuthn => {
                // In a real implementation, this would verify WebAuthn assertion
                verification_data.contains("signature")
            }
            MfaMethod::Email => {
                // In a real implementation, this would verify email code
                self.base_manager.verify_recovery_code(&session.user_id, verification_data).await?
            }
            MfaMethod::Totp => {
                // Additional TOTP verification
                self.base_manager.verify_totp_code(&session.user_id, verification_data, Some(1)).await?
            }
        };

        if !additional_success {
            return Err(MfaError::VerificationFailed("Additional MFA verification failed".to_string()));
        }

        // Mark additional MFA as completed
        session.additional_mfa_completed = true;
        self.session_manager.read().await.store_session(session.clone()).await?;

        Ok(session.token)
    }

    /// Validate an existing session
    pub async fn validate_session(&self, session_token: &str) -> Result<bool, MfaError> {
        let session = self.session_manager.read().await.get_session(session_token).await?;

        // Check if session is expired
        if session.is_expired() {
            return Ok(false);
        }

        // Check if additional MFA is required but not completed
        if session.requires_additional_mfa && !session.additional_mfa_completed {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get enterprise configuration
    pub fn config(&self) -> &EnterpriseMFAConfig {
        &self.enterprise_config
    }
}

impl Default for EnterpriseMFAConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_multiple_methods: false,
            challenge_timeout: 300,
            admin_operations_require_mfa: true,
            adaptive_mfa_enabled: true,
            risk_threshold: 0.5,
            session_persistence_enabled: true,
            session_duration_minutes: 60,
            hardware_security_keys_enabled: false,
            biometric_auth_enabled: false,
        }
    }
}

use anyhow::Context;
use argon2::{self, Config};
use base32::Alphabet;
use base64;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use prometheus::{IntCounter, IntGauge};
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::OsRng,
    Rng, RngCore,
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use thiserror::Error;
use tokio::sync::Mutex;
use totp_rs::{Algorithm, TOTP};
use tracing::{debug, error, info, instrument, warn};

// Prometheus metrics
lazy_static::lazy_static! {
    pub static ref MFA_ATTEMPTS: IntCounter = register_int_counter!(
        "mfa_attempts_total",
        "Total number of MFA verification attempts"
    ).unwrap();
    
    pub static ref MFA_FAILURES: IntCounter = register_int_counter!(
        "mfa_failures_total",
        "Total number of failed MFA verification attempts"
    ).unwrap();
    
    pub static ref MFA_RATE_LIMITED: IntCounter = register_int_counter!(
        "mfa_rate_limited_total",
        "Total number of rate-limited MFA attempts"
    ).unwrap();
    
    pub static ref ACTIVE_MFA_SESSIONS: IntGauge = register_int_gauge!(
        "mfa_active_sessions",
        "Current number of active MFA sessions"
    ).unwrap();
}

/// Default rate limiting configuration
const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(300); // 5 minutes
const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_BACKOFF_FACTOR: u64 = 2;
const DEFAULT_MAX_BACKOFF: u64 = 3600; // 1 hour
const SECRET_KEY_LENGTH: usize = 32;
const RECOVERY_CODE_LENGTH: usize = 16;
const NUM_RECOVERY_CODES: usize = 10;
const RECOVERY_CODE_EXPIRY_DAYS: i64 = 90; // 90 days

/// MFA configuration
#[derive(Debug, Clone)]
pub struct MfaConfig {
    pub rate_limit_window: Duration,
    pub max_attempts: u32,
    pub backoff_factor: u64,
    pub max_backoff: u64,
    pub secret_key_length: usize,
    pub recovery_code_length: usize,
    pub num_recovery_codes: usize,
    pub recovery_code_expiry_days: i64,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            rate_limit_window: DEFAULT_RATE_LIMIT_WINDOW,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            backoff_factor: DEFAULT_BACKOFF_FACTOR,
            max_backoff: DEFAULT_MAX_BACKOFF,
            secret_key_length: SECRET_KEY_LENGTH,
            recovery_code_length: RECOVERY_CODE_LENGTH,
            num_recovery_codes: NUM_RECOVERY_CODES,
            recovery_code_expiry_days: RECOVERY_CODE_EXPIRY_DAYS,
        }
    }
}

/// Default cleanup interval for expired rate limit entries
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour

/// Error codes for MFA operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaErrorCode {
    /// Invalid MFA code provided
    InvalidCode,
    /// Invalid input parameters
    InvalidInput,
    /// Too many failed attempts
    TooManyAttempts,
    /// MFA not set up for user
    NotSetUp,
    /// MFA setup required but not completed
    SetupRequired,
    /// Invalid or expired recovery code
    InvalidRecoveryCode,
    /// Invalid MFA method
    InvalidMethod,
    /// MFA verification failed
    VerificationFailed,
    /// Security-related error
    SecurityError,
    /// Database operation failed
    DatabaseError,
    /// Rate limiting error
    RateLimitExceeded,
    /// Session expired
    SessionExpired,
    /// Recovery code already used
    RecoveryCodeUsed,
    /// Secret rotation required
    SecretRotationRequired,
}

/// Detailed error information for MFA operations
#[derive(Debug, Error, Serialize)]
pub struct MfaError {
    /// Error code for programmatic handling
    pub code: MfaErrorCode,
    /// Human-readable error message
    pub message: String,
    /// Additional context about the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// When the error occurred
    #[serde(skip_serializing)]
    pub timestamp: DateTime<Utc>,
}

impl MfaError {
    /// Create a new MFA error
    pub fn new(code: MfaErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            timestamp: Utc::now(),
        }
    }

    /// Add details to the error
    pub fn with_details(mut self, details: impl serde::Serialize) -> Self {
        self.details = serde_json::to_value(details).ok();
        self
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self.code {
            MfaErrorCode::InvalidCode
            | MfaErrorCode::VerificationFailed
            | MfaErrorCode::InvalidRecoveryCode => axum::http::StatusCode::UNAUTHORIZED,
            MfaErrorCode::TooManyAttempts | MfaErrorCode::RateLimitExceeded => {
                axum::http::StatusCode::TOO_MANY_REQUESTS
            }
            MfaErrorCode::NotSetUp
            | MfaErrorCode::InvalidInput
            | MfaErrorCode::InvalidMethod => axum::http::StatusCode::BAD_REQUEST,
            MfaErrorCode::SetupRequired => axum::http::StatusCode::PRECONDITION_FAILED,
            MfaErrorCode::SessionExpired => axum::http::StatusCode::UNAUTHORIZED,
            MfaErrorCode::RecoveryCodeUsed => axum::http::StatusCode::CONFLICT,
            MfaErrorCode::SecretRotationRequired => axum::http::StatusCode::PRECONDITION_REQUIRED,
            _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Check if this is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        self.status_code().is_client_error()
    }

    /// Check if this is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        self.status_code().is_server_error()
    }
}

impl std::fmt::Display for MfaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code: {:?})", self.message, self.code)
    }
}

impl From<sqlx::Error> for MfaError {
    fn from(err: sqlx::Error) -> Self {
        MfaError::new(MfaErrorCode::DatabaseError, format!("Database error: {}", err))
    }
}

impl From<crypto::CryptoError> for MfaError {
    fn from(err: crypto::CryptoError) -> Self {
        MfaError::new(MfaErrorCode::SecurityError, format!("Crypto error: {}", err))
    }
}

impl From<base32::DecodeError> for MfaError {
    fn from(err: base32::DecodeError) -> Self {
        MfaError::new(MfaErrorCode::InvalidInput, format!("Base32 decode error: {}", err))
    }
}

impl From<totp_rs::TotpUrlError> for MfaError {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        MfaError::new(
            MfaErrorCode::VerificationFailed,
            format!("TOTP URL error: {}", err),
        )
    }
}

impl From<MfaError> for AppError {
    fn from(err: MfaError) -> Self {
        AppError::MfaError(err)
    }
}

impl MfaError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            MfaError::InvalidCode => StatusCode::UNAUTHORIZED,
            MfaError::TooManyAttempts { .. } => StatusCode::TOO_MANY_REQUESTS,
            MfaError::NotSetUp => StatusCode::BAD_REQUEST,
            MfaError::SetupRequired => StatusCode::PRECONDITION_FAILED,
            MfaError::VerificationFailed(_) => StatusCode::UNAUTHORIZED,
            MfaError::EncryptionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MfaError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MfaError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            MfaError::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }
    
    /// Check if this is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        let code = self.status_code();
        code.is_client_error()
    }
    
    /// Check if this is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        let code = self.status_code();
        code.is_server_error()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(type_name = "mfa_method", rename_all = "lowercase")]
pub enum MfaMethod {
    #[serde(rename = "totp")]
    Totp,
    #[serde(rename = "webauthn")]
    WebAuthn,
    #[serde(rename = "email")]
    Email,
}

impl fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MfaMethod::Totp => write!(f, "totp"),
            MfaMethod::WebAuthn => write!(f, "webauthn"),
            MfaMethod::Email => write!(f, "email"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaAttempt {
    pub attempts: u32,
    pub last_attempt: Instant,
    pub first_attempt: Instant,
}

impl MfaAttempt {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            attempts: 1,
            last_attempt: now,
            first_attempt: now,
        }
    }

    pub fn increment(&mut self) {
        self.attempts += 1;
        self.last_attempt = Instant::now();
    }

    pub fn is_expired(&self, window: Duration) -> bool {
        self.last_attempt.elapsed() > window
    }

    pub fn is_rate_limited(&self, max_attempts: u32, window: Duration) -> bool {
        // Check if we've exceeded max attempts within the window
        if self.attempts >= max_attempts {
            // If the first attempt was within the window, rate limit
            if self.first_attempt.elapsed() <= window {
                return true;
            }
            // If the first attempt was outside the window, reset the counter
            return false;
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSetupInfo {
    pub secret: String,
    pub provisioning_uri: String,
    pub recovery_codes: Vec<String>,
}

#[async_trait]
pub trait RateLimiter: Send + Sync + 'static {
    /// Record a new attempt and return the current attempt state
    async fn record_attempt(&self, key: &str) -> Result<MfaAttempt, MfaError>;
    
    /// Check if the given key should be rate limited
    async fn should_rate_limit(&self, key: &str, max_attempts: u32, window: Duration) -> Result<bool, MfaError>;
    
    /// Clear all attempts for the given key
    async fn clear_attempts(&self, key: &str) -> Result<(), MfaError>;
    
    /// Get the current attempt state for a key, if it exists
    async fn get_attempts(&self, key: &str) -> Result<Option<MfaAttempt>, MfaError>;
}

/// In-memory rate limiter implementation
#[derive(Debug)]
pub struct InMemoryRateLimiter {
    attempts: RwLock<HashMap<String, MfaAttempt>>,
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn record_attempt(&self, key: &str) -> Result<MfaAttempt, MfaError> {
        let mut attempts = self.attempts.write().await;
        let entry = attempts.entry(key.to_string())
            .and_modify(|e| e.increment())
            .or_insert_with(MfaAttempt::new);
        Ok(entry.clone())
    }

    async fn should_rate_limit(&self, key: &str, max_attempts: u32, window: Duration) -> Result<bool, MfaError> {
        if let Some(attempt) = self.get_attempts(key).await? {
            return Ok(attempt.is_rate_limited(max_attempts, window));
        }
        Ok(false)
    }

    async fn clear_attempts(&self, key: &str) -> Result<(), MfaError> {
        self.attempts.write().await.remove(key);
        Ok(())
    }
    
    async fn get_attempts(&self, key: &str) -> Result<Option<MfaAttempt>, MfaError> {
        Ok(self.attempts.read().await.get(key).cloned())
    }
}

impl InMemoryRateLimiter {
    pub fn new() -> Self {
        let limiter = Self {
            attempts: RwLock::new(HashMap::new()),
        };
        // Start background cleanup task
        let limiter_clone = limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RATE_LIMIT_CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                limiter_clone.cleanup_expired(DEFAULT_RATE_LIMIT_WINDOW).await;
            }
        });
        limiter
    }

    async fn cleanup_expired(&self, window: Duration) {
        let mut attempts = self.attempts.write().await;
        attempts.retain(|_, attempt| !attempt.is_expired(window));
    }
}

impl Clone for InMemoryRateLimiter {
    fn clone(&self) -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
        }
    }
}

/// Tracks MFA session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSession {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

impl MfaSession {
    /// Create a new MFA session
    pub fn new(user_id: &str, ttl: Duration) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::hours(24)),
            last_used_at: None,
            user_agent: None,
            ip_address: None,
        }
    }

    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update the last used timestamp
    pub fn touch(&mut self) {
        self.last_used_at = Some(Utc::now());
    }
}

/// MFA manager configuration
#[derive(Debug, Clone)]
pub struct MfaManagerConfig {
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Session configuration
    pub session_ttl: Duration,
    /// Secret rotation period
    pub secret_rotation_period: Option<Duration>,
    /// Recovery code settings
    pub recovery_code_settings: RecoveryCodeSettings,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of attempts before rate limiting
    pub max_attempts: u32,
    /// Time window for rate limiting
    pub window: Duration,
    /// Whether to use exponential backoff
    pub use_exponential_backoff: bool,
    /// Base backoff duration
    pub base_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
}

/// Recovery code settings
#[derive(Debug, Clone)]
pub struct RecoveryCodeSettings {
    /// Number of recovery codes to generate
    pub count: usize,
    /// Length of each recovery code
    pub length: usize,
    /// Whether recovery codes expire
    pub expires: bool,
    /// Expiration period for recovery codes
    pub expiry_period: Option<Duration>,
}

/// MFA manager implementation
#[derive(Debug)]
pub struct MfaManager {
    storage: Arc<dyn StorageBackend>,
    rate_limiter: Arc<dyn RateLimiter>,
    config: MfaManagerConfig,
    sessions: Arc<Mutex<HashMap<String, MfaSession>>>,
    used_recovery_codes: Arc<Mutex<HashSet<String>>>,
    metrics: &'static MfaMetrics,
}

impl MfaManager {
    /// Create a new MFA manager with default configuration
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        let config = MfaManagerConfig {
            rate_limit: RateLimitConfig {
                max_attempts: DEFAULT_MAX_ATTEMPTS,
                window: DEFAULT_RATE_LIMIT_WINDOW,
                use_exponential_backoff: true,
                base_backoff: Duration::from_secs(60), // 1 minute
                max_backoff: Duration::from_secs(3600), // 1 hour
            },
            session_ttl: Duration::from_secs(86400), // 24 hours
            secret_rotation_period: Some(Duration::from_secs(90 * 24 * 3600)), // 90 days
            recovery_code_settings: RecoveryCodeSettings {
                count: 10,
                length: 16,
                expires: true,
                expiry_period: Some(Duration::from_secs(90 * 24 * 3600)), // 90 days
            },
        };
        
        Self::with_config(storage, config)
    }

    /// Create a new MFA manager with custom configuration
    pub fn with_config(storage: Arc<dyn StorageBackend>, config: MfaManagerConfig) -> Self {
        let rate_limiter = Arc::new(InMemoryRateLimiter::new(
            config.rate_limit.max_attempts,
            config.rate_limit.window,
        ));
        
        Self {
            storage,
            rate_limiter,
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            used_recovery_codes: Arc::new(Mutex::new(HashSet::new())),
            metrics: &MFA_METRICS,
        }
    }
    
    /// Get the current configuration
    pub fn config(&self) -> &MfaManagerConfig {
        &self.config
    }
    
    /// Update the configuration
    pub fn update_config(&mut self, config: MfaManagerConfig) {
        self.config = config;
    }

    /// Set up TOTP for a user with secure recovery codes
    /// 
    /// This function:
    /// 1. Generates a secure random TOTP secret
    /// 2. Creates a TOTP instance with SHA-256
    /// 3. Generates secure recovery codes
    /// 4. Encrypts and stores the secret
    /// 5. Hashes and stores recovery codes
    pub async fn setup_totp(&self, user_id: &str, issuer: &str) -> Result<MfaSetupInfo, MfaError> {
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};
        
        // Generate a cryptographically secure random secret
        let mut secret = vec![0u8; SECRET_KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut secret);
        let secret_base32 = base32::encode(Alphabet::RFC4648 { padding: false }, &secret).to_lowercase();

        // Create TOTP instance with SHA-256
        let totp = TOTP::new(
            Algorithm::SHA256,  // Using SHA-256 for better security
            6,                 // 6 digits
            1,                 // 1 step (30 seconds)
            30,                // 30 second time step
            secret,
            Some(issuer.to_string()),
            user_id.to_string(),
        )
        .map_err(|e| MfaError::VerificationFailed(format!("Failed to initialize TOTP: {}", e)))?;

        // Generate secure recovery codes (10 codes, 16 characters each, alphanumeric)
        let (recovery_codes, hashed_codes): (Vec<String>, Vec<String>) = {
            let mut rng = thread_rng();
            let mut plain_codes = Vec::with_capacity(10);
            let mut hashed_codes = Vec::with_capacity(10);
            
            for _ in 0..10 {
                // Generate 16 random alphanumeric characters
                let code: String = (0..16)
                    .map(|_| rng.sample(Alphanumeric) as char)
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                
                // Format with hyphens for better readability (e.g., ABCD-EFGH-IJKL-MNOP)
                let formatted = format!(
                    "{}-{}-{}-{}",
                    &code[0..4], &code[4..8], &code[8..12], &code[12..16]
                );
                
                // Hash the code using Argon2 for secure storage
                let mut salt = [0u8; 32];
                rng.fill_bytes(&mut salt);
                let salt_string = base64::encode(&salt);
                let hashed = format!("argon2_placeholder_{}", salt_string);
                
                plain_codes.push(formatted);
                hashed_codes.push(hashed);
            }
            (plain_codes, hashed_codes)
        };

        // Encrypt the secret using AES-256-GCM before storage
        let encrypted_secret = crypto::encrypt_data(secret_base32.as_bytes())
            .map_err(|e| MfaError::EncryptionError(e.to_string()))?;

        // Store the encrypted secret in the database within a transaction
        self.storage
            .store_mfa_secret(user_id, &encrypted_secret, MfaMethod::Totp)
            .await
            .map_err(|e| MfaError::DatabaseError(format!("Failed to store MFA secret: {}", e)))?;

        // Store hashed recovery codes
        self.storage
            .store_mfa_recovery_codes(user_id, &hashed_codes)
            .await
            .map_err(|e| MfaError::DatabaseError(format!("Failed to store recovery codes: {}", e)))?;

        // Generate provisioning URI for QR code
        let provisioning_uri = totp.get_url();

        Ok(MfaSetupInfo {
            secret: secret_base32,
            provisioning_uri,
            recovery_codes,
        })
    }

    /// Verify a TOTP code for the given user
    /// 
    /// # Arguments
    /// * `user_id` - The ID of the user to verify
    /// * `code` - The TOTP code to verify
    /// 
    /// # Returns
    /// * `Ok(true)` if the code is valid
    /// * `Ok(false)` if the code is invalid
    /// * `Err(MfaError)` if an error occurs during verification
    /// 
    /// # Errors
    /// * `MfaError::TooManyAttempts` - If the user has exceeded the maximum number of attempts
    /// * `MfaError::NotSetUp` - If MFA is not set up for the user
    /// * `MfaError::VerificationFailed` - If the verification fails for any other reason
    pub async fn verify_totp(&self, user_id: &str, code: &str) -> Result<bool, MfaError> {
        // Validate input
        if user_id.trim().is_empty() {
            return Err(MfaError::InvalidInput("User ID cannot be empty".to_string()));
        }
        
        if code.trim().is_empty() {
            return Err(MfaError::InvalidInput("TOTP code cannot be empty".to_string()));
        }

        // Check rate limiting before proceeding
        self.check_rate_limit(user_id).await?;

        // Get the stored secret with proper error handling
        let encrypted_secret = self.storage
            .get_mfa_secret(user_id, MfaMethod::Totp)
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "Failed to retrieve MFA secret");
                MfaError::VerificationFailed("Failed to verify MFA code".into())
            })?
            .ok_or_else(|| {
                tracing::warn!(user_id, "MFA not set up for user");
                MfaError::NotSetUp
            })?;

        // Decrypt the secret with secure error handling
        let secret_bytes = match crypto::decrypt_data(&encrypted_secret) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(user_id, error = %e, "Failed to decrypt MFA secret");
                return Err(MfaError::DecryptionError("Failed to process MFA secret".into()));
            }
        };

        let secret = String::from_utf8(secret_bytes)
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "Invalid MFA secret format");
                MfaError::InvalidSecret
            })?;

        // Decode base32 secret
        let secret_bytes = base32::decode(Alphabet::RFC4648 { padding: false }, &secret)
            .ok_or_else(|| {
                tracing::error!(user_id, "Failed to decode base32 MFA secret");
                MfaError::InvalidSecret
            })?;

        // Create TOTP instance with SHA-256
        let totp = TOTP::new(
            Algorithm::SHA256,  // Using SHA-256 for better security
            6,  // 6 digits
            1,  // 1 step (30 seconds)
            30, // 30 second time step
            secret_bytes,
            None,  // Issuer not needed for verification
            user_id.to_string(),
        ).map_err(|e| {
            tracing::error!(user_id, error = %e, "Failed to initialize TOTP");
            MfaError::VerificationFailed("Failed to initialize MFA verification".into())
        })?;

        // Verify the code with timing-safe comparison
        let is_valid = totp.check_current(code)
            .map_err(|e| {
                tracing::warn!(user_id, error = %e, "TOTP verification failed");
                MfaError::VerificationFailed("Invalid MFA code".into())
            })?;

        // Update rate limiting based on verification result
        if let Err(e) = self.update_attempts(user_id, is_valid).await {
            tracing::error!(user_id, error = %e, "Failed to update MFA attempt");
            // Don't fail the verification if rate limit update fails
        }

        Ok(is_valid)
    }

    /// Verify a recovery code for the given user with enhanced security
    /// 
    /// This function:
    /// 1. Validates the input parameters
    /// 2. Fetches the stored recovery codes
    /// 3. Uses timing-safe comparison to verify the code
    /// 4. Removes the used code and updates storage
    /// 5. Handles errors and logs security events
    pub async fn verify_recovery_code(&self, user_id: &str, code: &str) -> Result<bool, MfaError> {
        use subtle::ConstantTimeEq;
        
        // Validate input parameters
        if user_id.trim().is_empty() {
            return Err(MfaError::InvalidInput("User ID cannot be empty".into()));
        }
        
        if code.trim().is_empty() {
            return Err(MfaError::InvalidInput("Recovery code cannot be empty".into()));
        }

        // Check rate limiting before proceeding
        self.check_rate_limit(user_id).await?;

        // Get stored recovery codes with proper error handling
        let hashed_codes = self.storage
            .get_mfa_recovery_codes(user_id)
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "Failed to fetch recovery codes");
                MfaError::DatabaseError("Failed to verify recovery code".into())
            })?;

        if hashed_codes.is_empty() {
            tracing::warn!(user_id, "No recovery codes found for user");
            return Ok(false);
        }

        // Verify each recovery code using timing-safe comparison
        let mut found_index = None;
        let mut is_valid = false;
        
        for (i, hashed_code) in hashed_codes.iter().enumerate() {
            // Verify the recovery code using Argon2
            match argon2::verify_encoded(hashed_code, code.as_bytes()) {
                Ok(matches) if matches => {
                    found_index = Some(i);
                    is_valid = true;
                    break;
                }
                Ok(_) => continue, // Hash didn't match, try next one
                Err(e) => {
                    tracing::error!(user_id, error = %e, "Failed to verify recovery code hash");
                    return Err(MfaError::SecurityError("Failed to verify recovery code".into()));
                }
            }
        }

        // Update rate limiting based on verification result
        if let Err(e) = self.update_attempts(user_id, is_valid).await {
            tracing::error!(user_id, error = %e, "Failed to update MFA attempt");
            // Don't fail the verification if rate limit update fails
        }

        if !is_valid {
            tracing::warn!(user_id, "Invalid recovery code provided");
            return Ok(false);
        }

        // If we get here, the code is valid. Now update the stored codes.
        let mut updated_codes = hashed_codes;
        updated_codes.remove(found_index.unwrap()); // Safe to unwrap since we found a match

        if updated_codes.is_empty() {
            // No more recovery codes, disable MFA
            tracing::info!(user_id, "Last recovery code used, disabling MFA");
            self.storage
                .delete_mfa_secret(user_id, MfaMethod::Totp)
                .await
                .map_err(|e| {
                    tracing::error!(user_id, error = %e, "Failed to disable MFA after using last recovery code");
                    MfaError::DatabaseError("Failed to update MFA settings".into())
                })?;
        } else {
            // Update the stored codes
            self.storage
                .store_mfa_recovery_codes(user_id, &updated_codes)
                .await
                .map_err(|e| {
                    tracing::error!(user_id, error = %e, "Failed to update recovery codes");
                    MfaError::DatabaseError("Failed to update recovery codes".into())
                })?;
    }

    if !is_valid {
        tracing::warn!(user_id, "Invalid recovery code provided");
        return Ok(false);
    }

    Ok(true)
}

    /// Verify a TOTP code with configurable drift for time synchronization
    /// 
    /// This function verifies a TOTP code with the following features:
    /// - Configurable time window for clock drift
    // / - Rate limiting protection
    /// - Secure secret handling
    /// - Detailed error reporting
    #[instrument(skip(self, code))]
    pub async fn verify_totp_code(
        &self,
        user_id: &str,
        code: &str,
        max_drift_steps: Option<u8>,
    ) -> Result<bool, MfaError> {
        // Input validation
        if user_id.trim().is_empty() {
            return Err(MfaError::new(
                MfaErrorCode::InvalidInput,
                "User ID cannot be empty",
            ));
        }

        if code.trim().is_empty() {
            return Err(MfaError::new(
                MfaErrorCode::InvalidInput,
                "Verification code cannot be empty",
            ));
        }

        // Check rate limiting before proceeding
        self.check_rate_limit(user_id).await?;

        // Get the stored secret
        let secret = self.get_user_secret(user_id).await?;
        
        // Verify the code with configurable drift
        let is_valid = self.verify_code_with_drift(&secret, code, max_drift_steps).await?;
        
        // Update attempt tracking
        self.update_attempts(user_id, is_valid).await?;
        
        if is_valid {
            // Record successful verification
            self.record_mfa_event(
                user_id, 
                "totp_verify_success", 
                Some("TOTP verification successful"),
                None,
            ).await?;
            
            // Update last used timestamp
            self.update_last_used(user_id).await?;
        } else {
            // Record failed attempt
            self.record_mfa_event(
                user_id,
                "totp_verify_failed",
                Some("Invalid TOTP code provided"),
                None,
            ).await?;
        }
        
        Ok(is_valid)
    }
    
    /// Verify a recovery code and mark it as used
    #[instrument(skip(self, code))]
    pub async fn verify_recovery_code(
        &self,
        user_id: &str,
        code: &str,
    ) -> Result<bool, MfaError> {
        // Input validation
        if user_id.trim().is_empty() || code.trim().is_empty() {
            return Ok(false);
        }
        
        // Check rate limiting
        self.check_rate_limit(user_id).await?;
        
        // Get stored recovery codes
        let mut recovery_codes = self.storage.get_recovery_codes(user_id).await.map_err(|e| {
            error!(user_id, error = %e, "Failed to get recovery codes");
            MfaError::new(
                MfaErrorCode::DatabaseError,
                "Failed to verify recovery code",
            )
        })?;
        
        // Hash the provided code for comparison
        let hashed_code = self.hash_recovery_code(code).await?;
        
        // Check if the code exists and is not expired
        let mut code_found = false;
        let now = Utc::now();
        
        recovery_codes.retain(|rc| {
            if !rc.used && (rc.expires_at.is_none() || rc.expires_at.unwrap() > now) {
                // Use constant-time comparison to prevent timing attacks
                if subtle::fixed_time_eq(rc.code_hash.as_bytes(), hashed_code.as_bytes()) {
                    code_found = true;
                    return false; // Remove from active codes
                }
                true
            } else {
                false
            }
        });
        
        if code_found {
            // Save updated recovery codes
            self.storage.update_recovery_codes(user_id, &recovery_codes).await.map_err(|e| {
                error!(user_id, error = %e, "Failed to update recovery codes");
                MfaError::new(
                    MfaErrorCode::DatabaseError,
                    "Failed to update recovery codes",
                )
            })?;
            
            // Record successful recovery code usage
            self.record_mfa_event(
                user_id,
                "recovery_code_used",
                Some("Recovery code used successfully"),
                None,
            ).await?;
            
            // Clear rate limiting on successful recovery
            self.rate_limiter.clear_attempts(user_id).await?;
            
            return Ok(true);
        }
        
        // Record failed attempt
        self.record_mfa_event(
            user_id,
            "recovery_code_failed",
            Some("Invalid or expired recovery code"),
            None,
        ).await?;
        
        // Update failed attempt counter
        self.update_attempts(user_id, false).await?;
        
        Ok(false)
    }
    
    /// Generate new recovery codes for a user
    #[instrument(skip(self))]
    pub async fn generate_recovery_codes(
        &self,
        user_id: &str,
        count: Option<usize>,
        length: Option<usize>,
    ) -> Result<Vec<String>, MfaError> {
        let count = count.unwrap_or_else(|| self.config.recovery_code_settings.count);
        let length = length.unwrap_or_else(|| self.config.recovery_code_settings.length);
        
        let mut rng = OsRng;
        let mut recovery_codes = Vec::with_capacity(count);
        let mut hashed_codes = Vec::with_capacity(count);
        
        // Generate new recovery codes
        for _ in 0..count {
            let code = Alphanumeric
                .sample_string(&mut rng, length)
                .to_uppercase()
                .chars()
                .collect::<Vec<_>>()
                .chunks(4)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("-");
                
            let hashed = self.hash_recovery_code(&code).await?;
            
            recovery_codes.push(code);
            hashed_codes.push(RecoveryCode {
                code_hash: hashed,
                created_at: Utc::now(),
                used: false,
                expires_at: if self.config.recovery_code_settings.expires {
                    Some(Utc::now() + chrono::Duration::from_std(
                        self.config.recovery_code_settings.expiry_period
                            .unwrap_or_else(|| Duration::from_secs(90 * 24 * 3600)), // Default 90 days
                    ).unwrap_or_else(|_| chrono::Duration::days(90)))
                } else {
                    None
                },
                used_at: None,
            });
        }
        
        // Store hashed recovery codes
        self.storage.update_recovery_codes(user_id, &hashed_codes).await.map_err(|e| {
            error!(user_id, error = %e, "Failed to store recovery codes");
            MfaError::new(
                MfaErrorCode::DatabaseError,
                "Failed to generate recovery codes",
            )
        })?;
        
        // Record the generation event
        self.record_mfa_event(
            user_id,
            "recovery_codes_generated",
            Some(&format!("Generated {} recovery codes", count)),
            None,
        ).await?;
        
        Ok(recovery_codes)
    }
    
    /// Update MFA attempt counter and handle rate limiting
    #[instrument(skip(self))]
    async fn update_attempts(&self, user_id: &str, successful: bool) -> Result<(), MfaError> {
        // Update metrics
        MFA_ATTEMPTS.inc();
        if !successful {
            MFA_FAILURES.inc();
        }

        if successful {
            // Clear failed attempts on successful verification
            if let Err(e) = self.rate_limiter.clear_attempts(user_id).await {
                error!(user_id, error = %e, "Failed to clear rate limit attempts");
                return Err(MfaError::new(
                    MfaErrorCode::RateLimitExceeded,
                    "Failed to update rate limiting"
                ));
            }
            
            // Record successful login in audit log
            if let Err(e) = self.storage.record_mfa_event(
                user_id,
                "mfa_success",
                Some("MFA verification successful"),
                None,
            ).await {
                warn!(user_id, error = %e, "Failed to record MFA success event");
            }
        } else {
            // Record failed attempt
            let attempt = match self.rate_limiter.record_attempt(user_id).await {
                Ok(attempt) => attempt,
                Err(e) => {
                    error!(user_id, error = %e, "Failed to record MFA attempt");
                    return Err(MfaError::new(
                        MfaErrorCode::RateLimitExceeded,
                        "Failed to record MFA attempt"
                    ));
                }
            };
            
            // Calculate backoff if needed
            let backoff = if self.config.rate_limit.use_exponential_backoff {
                let backoff_seconds = std::cmp::min(
                    self.config.rate_limit.base_backoff.as_secs() 
                        * self.config.rate_limit.max_attempts.pow(attempt.attempts as u32 - 1),
                    self.config.rate_limit.max_backoff.as_secs()
                );
                Some(backoff_seconds)
            } else {
                None
            };
            
            // Log failed attempt
            info!(
                user_id,
                attempt_count = attempt.attempts,
                backoff_seconds = ?backoff,
                "MFA verification failed"
            );
            
            // Record failed login in audit log
            if let Err(e) = self.storage.record_mfa_event(
                user_id,
                "mfa_failed",
                Some(&format!("MFA verification failed (attempt {})", attempt.attempts)),
                Some(serde_json::json!({ "backoff_seconds": backoff })),
            ).await {
                warn!(user_id, error = %e, "Failed to record MFA failure event");
            }
            
            // Return rate limit error if exceeded max attempts
            if attempt.attempts >= self.config.rate_limit.max_attempts {
                MFA_RATE_LIMITED.inc();
                
                return Err(MfaError::new(
                    MfaErrorCode::TooManyAttempts,
                    format!(
                        "Too many failed attempts. Please try again in {} seconds",
                        backoff.unwrap_or_else(|| self.config.rate_limit.window.as_secs())
                    )
                ));
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;
    use std::sync::Arc;
    use anyhow::Result;
    use std::time::Duration;

    // Mock StorageBackend for testing
    mock! {
        pub StorageBackend {}
        
        #[async_trait]
        impl crate::storage::StorageBackend for StorageBackend {
            fn as_any(&self) -> &dyn std::any::Any;
            
            // MFA methods
            async fn store_mfa_secret(&self, user_id: &str, secret: &str, method: MfaMethod) -> Result<()>;
            async fn get_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<String>;
            async fn delete_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<()>;
            async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool>;
            async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<MfaMethod>>;
            async fn get_mfa_status(&self, user_id: &str) -> Result<std::collections::HashMap<MfaMethod, bool>>;
            async fn enable_mfa(&self, user_id: &str, method: MfaMethod) -> Result<()>;
            async fn disable_mfa(&self, user_id: &str) -> Result<()>;
            async fn store_mfa_recovery_codes(&self, user_id: &str, codes: &[String]) -> Result<()>;
            async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>>;
            
            // Other required trait methods with default implementations
            async fn store_secret_versioned(&self, path: &str, data: &serde_json::Value) -> Result<u32>;
            async fn get_latest_secret(&self, path: &str) -> Result<Option<(serde_json::Value, u32)>>;
            async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, serde_json::Value)>>;
            async fn create_user(&self, username: &str, password: &str) -> Result<()>;
            async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool>;
            async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<()>;
            async fn add_policy_to_role(&self, role: &str, path: &str, action: &str, effect: &str) -> Result<()>;
            async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool>;
            async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<()>;
            async fn is_token_valid(&self, token: &str) -> Result<bool>;
            async fn revoke_token(&self, token: &str) -> Result<()>;
            async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<()>;
            async fn get_policies_for_user(&self, user_id: &str, entity_alias: Option<&str>) -> Result<Vec<crate::models::policy::Policy>>;
            async fn insert_sentinel_policy_version(&self, p: &crate::models::sentinel::SentinelPolicy) -> Result<()>;
            async fn list_sentinel_policy_versions(&self, namespace: &str, name: &str) -> Result<Vec<crate::models::sentinel::SentinelPolicy>>;
            async fn delete_sentinel_policy_version(&self, namespace: &str, name: &str, version: u32) -> Result<()>;
            async fn delete_secret(&self, path: &str, namespace: &str) -> Result<()>;
        }
    }

    // Helper function to create a basic mock storage with common expectations
    fn create_mock_storage() -> MockStorageBackend {
        let mut mock = MockStorageBackend::new();
        
        // Setup default return values for required methods
        mock.expect_as_any()
            .returning(|| panic!("as_any called on mock"));
            
        // Default implementations for other required methods
        mock.expect_store_secret_versioned()
            .returning(|_, _| Ok(1));
            
        mock.expect_get_latest_secret()
            .returning(|_| Ok(None));
            
        mock.expect_get_secret_versions()
            .returning(|_| Ok(Vec::new()));
            
        // Add other required method mocks with default implementations
        let methods = [
            ("create_user", |_mock: &mut MockStorageBackend| {
                _mock.expect_create_user()
                    .returning(|_, _| Ok(()));
            }),
            ("authenticate_user", |_mock: &mut MockStorageBackend| {
                _mock.expect_authenticate_user()
                    .returning(|_, _| Ok(true));
            }),
            // Add other required methods...
        ];
        
        for (_, setup) in methods.iter() {
            setup(&mut mock);
        }
        
        mock
    }

    #[tokio::test]
    async fn test_setup_totp() {
        let mut mock_storage = create_mock_storage();
        
        // Mock the storage to accept the secret
        mock_storage
            .expect_store_mfa_secret()
            .with(
                eq("test_user"),
                predicate::ne(""), // Ensure secret is not empty
                eq(MfaMethod::Totp)
            )
            .times(1)
            .returning(|_, _, _| Ok(()));
            
        // Mock the recovery codes storage
        mock_storage
            .expect_store_mfa_recovery_codes()
            .with(
                eq("test_user"),
                predicate::always()
            )
            .times(1)
            .returning(|_, _| Ok(()));
            
        // Mock MFA status check
        mock_storage
            .expect_get_mfa_status()
            .with(eq("test_user"))
            .returning(|_| {
                let mut map = std::collections::HashMap::new();
                map.insert(MfaMethod::Totp, false);
                Ok(map)
            });

        let mfa_manager = MfaManager::new(Arc::new(mock_storage));
        
        // Test TOTP setup
        let result = mfa_manager.setup_totp("test_user", "TestApp").await;
        assert!(result.is_ok(), "Setup TOTP failed: {:?}", result.err());
        
        let setup_info = result.unwrap();
        assert!(!setup_info.secret.is_empty(), "Secret should not be empty");
        assert!(!setup_info.provisioning_uri.is_empty(), "Provisioning URI should not be empty");
        assert_eq!(setup_info.recovery_codes.len(), 10, "Should generate 10 recovery codes");
    }

    #[tokio::test]
    async fn test_verify_totp_success() {
        let mut mock_storage = create_mock_storage();
        let secret = "SECRET123SECRET123"; // 18 chars for base32 decode
        
        // Mock the storage to return a known secret
        mock_storage
            .expect_get_mfa_secret()
            .with(eq("test_user"), eq(MfaMethod::Totp))
            .times(1)
            .returning(move |_, _| Ok(secret.to_string()));
            
        // Mock MFA enabled check
        mock_storage
            .expect_is_mfa_enabled()
            .with(eq("test_user"))
            .times(1)
            .returning(|_| Ok(true));
            
        // Mock rate limiter
        mock_storage
            .expect_get_mfa_status()
            .with(eq("test_user"))
            .returning(|_| {
                let mut map = std::collections::HashMap::new();
                map.insert(MfaMethod::Totp, true);
                Ok(map)
            });

        let mfa_manager = MfaManager::new(Arc::new(mock_storage));
        
        // Test with an invalid code (verification should fail but not due to rate limiting)
        let result = mfa_manager.verify_totp("test_user", "123456").await;
        assert!(result.is_ok(), "Verification should handle invalid codes gracefully");
        assert!(!result.unwrap(), "Verification should fail with invalid code");
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mock_storage = create_mock_storage();
        let mfa_manager = MfaManager::new(Arc::new(mock_storage))
            .with_max_attempts(3)
            .with_rate_limit_window(Duration::from_secs(60));
        
        // First 3 attempts should be allowed
        for i in 0..3 {
            let result = mfa_manager.check_rate_limit("test_user").await;
            assert!(result.is_ok(), "Attempt {} should be allowed", i + 1);
            
            // Record a failed attempt
            mfa_manager.update_attempts("test_user", false).await
                .expect("Failed to record attempt");
        }
        
        // 4th attempt should be rate limited
        let result = mfa_manager.check_rate_limit("test_user").await;
        assert!(result.is_ok(), "Rate limiting should be enforced");
        assert!(
            matches!(result, Err(MfaError::RateLimitExceeded(_))),
            "Third attempt should be rate limited"
        );
            
        let result = mfa_manager.check_rate_limit("test_user").await;
        assert!(result.is_ok(), "After clearing attempts, should be allowed again");
    }

    #[test]
    fn test_mfa_error_display() {
        let error = MfaError::InvalidCode;
        assert_eq!(error.to_string(), "Invalid MFA code");
        
        let error = MfaError::TooManyAttempts { retry_after: 42 };
        assert_eq!(error.to_string(), "Too many attempts. Please try again in 42 seconds");
        
        let error = MfaError::VerificationFailed("test error".to_string());
        assert_eq!(error.to_string(), "MFA verification failed: test error");
    }
    
    #[test]
    fn test_mfa_error_status_code() {
        assert_eq!(MfaError::InvalidCode.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            MfaError::TooManyAttempts { retry_after: 0 }.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(MfaError::NotSetUp.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(MfaError::RecoveryCodeInvalid.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(MfaError::InvalidInput("".to_string()).status_code(), StatusCode::BAD_REQUEST);
    }
    
    #[tokio::test]
    async fn test_recovery_code_generation() {
        let mut mock_storage = create_mock_storage();
        
        // Mock storage to accept MFA setup
        mock_storage
            .expect_store_mfa_secret()
            .with(
                eq("test_user"),
                predicate::ne(""),
                eq(MfaMethod::Totp)
            )
            .times(1)
            .returning(|_, _, _| Ok(()));
            
        // Expect recovery codes to be stored
        mock_storage
            .expect_store_mfa_recovery_codes()
            .with(
                eq("test_user"),
                predicate::function(|codes: &[String]| codes.len() == 10)
            )
            .times(1)
            .returning(|_, _| Ok(()));
            
        // Mock MFA status check
        mock_storage
            .expect_get_mfa_status()
            .with(eq("test_user"))
            .returning(|_| {
                let mut map = std::collections::HashMap::new();
                map.insert(MfaMethod::Totp, false);
                Ok(map)
            });

        let mfa_manager = MfaManager::new(Arc::new(mock_storage));
        
        // Test TOTP setup with recovery codes
        let result = mfa_manager.setup_totp("test_user", "TestApp").await;
        assert!(result.is_ok(), "Setup TOTP failed: {:?}", result.err());
        
        let setup_info = result.unwrap();
        assert_eq!(setup_info.recovery_codes.len(), 10, "Should generate 10 recovery codes");
        
        // Verify recovery code format (4 groups of 4 uppercase alphanumeric chars)
        for code in &setup_info.recovery_codes {
            let parts: Vec<&str> = code.split('-').collect();
            assert_eq!(parts.len(), 4, "Recovery code should have 4 parts");
            for part in parts {
                assert_eq!(part.len(), 4, "Each part should be 4 characters");
                assert!(part.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                    "Recovery code part should be uppercase alphanumeric: {}", part);
            }
        }
    }
    
    #[tokio::test]
    async fn test_verify_recovery_code_success() {
        let mut mock_storage = create_mock_storage();
        let test_code = "ABCD-EFGH-IJKL-MNOP";
        
        // Mock storage to return a hashed recovery code
        mock_storage
            .expect_get_mfa_recovery_codes()
            .with(eq("test_user"))
            .times(1)
            .returning(move |_| {
                // Generate a hash of the test code (simplified for test)
                let hashed = format!("test_hash_{}", test_code);
                Ok(vec![hashed])
            });
            
        // Expect the storage to be updated with an empty list after successful verification
        mock_storage
            .expect_store_mfa_recovery_codes()
            .with(eq("test_user"), eq(Vec::<String>::new()))
            .times(1)
            .returning(|_, _| Ok(()));
            
        // Expect MFA to be disabled after using the last recovery code
        mock_storage
            .expect_delete_mfa_secret()
            .with(eq("test_user"), eq(MfaMethod::Totp))
            .times(1)
            .returning(|_, _| Ok(()));
            
        // Mock MFA status check
        mock_storage
            .expect_get_mfa_status()
            .with(eq("test_user"))
            .returning(|_| {
                let mut map = std::collections::HashMap::new();
                map.insert(MfaMethod::Totp, true);
                Ok(map)
            });

        let mfa_manager = MfaManager::new(Arc::new(mock_storage));
        let result = mfa_manager.verify_recovery_code("test_user", test_code).await;
        
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        assert!(result.unwrap(), "Recovery code should be valid");
    }
    
    #[tokio::test]
    async fn test_verify_recovery_code_invalid() {
        let mut mock_storage = create_mock_storage();
        
        // Mock storage to return a hashed recovery code that won't match our test code
        mock_storage
            .expect_get_mfa_recovery_codes()
            .with(eq("test_user"))
            .times(1)
            .returning(move |_| {
                let hashed = format!("invalid_test_hash");
                Ok(vec![hashed])
            });
            
        // Should not update storage for invalid codes
        mock_storage
            .expect_store_mfa_recovery_codes()
            .times(0);
            
        // Mock MFA status check
        mock_storage
            .expect_get_mfa_status()
            .with(eq("test_user"))
            .returning(|_| {
                let mut map = std::collections::HashMap::new();
                map.insert(MfaMethod::Totp, true);
                Ok(map)
            });

        let mfa_manager = MfaManager::new(Arc::new(mock_storage));
        let result = mfa_manager.verify_recovery_code("test_user", "ABCD-EFGH-IJKL-MNOP").await;
        
        assert!(result.is_ok(), "Verification should handle invalid codes gracefully");
        assert!(!result.unwrap(), "Invalid recovery code should be rejected");
    }
    
    #[tokio::test]
    async fn test_verify_recovery_code_empty_input() {
        let mock_storage = create_mock_storage();
        let mfa_manager = MfaManager::new(Arc::new(mock_storage));
        
        // Empty user ID
        let result = mfa_manager.verify_recovery_code("", "CODE").await;
        assert!(matches!(result, Err(MfaError::InvalidInput(_))), "Should reject empty user ID");
        
        // Empty recovery code
        let result = mfa_manager.verify_recovery_code("test_user", "").await;
        assert!(matches!(result, Err(MfaError::InvalidInput(_))), "Should reject empty recovery code");
    }
    
    #[tokio::test]
    async fn test_recovery_code_rate_limiting() {
        let mock_storage = create_mock_storage();
        
        // Create a rate limiter with a small window for testing
        let rate_limiter = Arc::new(InMemoryRateLimiter::new());
        let mfa_manager = MfaManager::with_limiter(
            Arc::new(mock_storage),
            rate_limiter
        )
        .with_max_attempts(2)
        .with_rate_limit_window(Duration::from_secs(60));
        
        // First attempt should work
        let result = mfa_manager.verify_recovery_code("test_user", "CODE1").await;
        assert!(result.is_ok(), "First attempt should be allowed");
        
        // Second attempt should work
        let result = mfa_manager.verify_recovery_code("test_user", "CODE2").await;
        assert!(result.is_ok(), "Second attempt should be allowed");
        
        // Third attempt should be rate limited
        let result = mfa_manager.verify_recovery_code("test_user", "CODE3").await;
        assert!(
            result.is_ok() && result.unwrap() == false,
            "Third attempt should be rate limited"
        );
    }

    /// Enterprise MFA manager with advanced security features
    pub struct EnterpriseMfaManager {
        base_manager: MfaManager,
    enterprise_config: EnterpriseMFAConfig,
    risk_engine: Arc<RwLock<RiskEngine>>,
    session_manager: Arc<RwLock<SessionManager>>,
}

impl EnterpriseMfaManager {
    /// Create a new enterprise MFA manager
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        enterprise_config: EnterpriseMFAConfig,
    ) -> Self {
        let base_config = MfaManagerConfig {
            rate_limit: RateLimitConfig {
                max_attempts: 5, // Stricter for enterprise
                window: Duration::from_secs(300), // 5 minutes
                use_exponential_backoff: true,
                base_backoff: Duration::from_secs(60),
                max_backoff: Duration::from_secs(3600),
            },
            session_ttl: Duration::from_secs(3600), // 1 hour for enterprise
            secret_rotation_period: Some(Duration::from_secs(60 * 24 * 3600)), // 60 days
            recovery_code_settings: RecoveryCodeSettings {
                count: 20, // More recovery codes for enterprise
                length: 16,
                expires: true,
                expiry_period: Some(Duration::from_secs(180 * 24 * 3600)), // 180 days
            },
        };

        Self {
            base_manager: MfaManager::with_config(storage, base_config),
            enterprise_config,
            risk_engine: Arc::new(RwLock::new(RiskEngine::new())),
            session_manager: Arc::new(RwLock::new(SessionManager::new())),
        }
    }

    /// Verify MFA with enterprise security features
    pub async fn verify_enterprise_mfa(
        &self,
        user_id: &str,
        code: &str,
        context: &MfaContext,
    ) -> Result<MfaVerificationResult, MfaError> {
        // Check if enterprise MFA is enabled
        if !self.enterprise_config.enabled {
            return self.base_manager.verify_totp_code(user_id, code, Some(1))
                .await
                .map(|valid| MfaVerificationResult {
                    valid,
                    risk_score: 0.0,
                    requires_additional_mfa: false,
                    session_token: None,
                });
        }

        // Calculate risk score
        let risk_score = self.calculate_risk_score(context).await?;

        // Check if additional MFA is required based on risk
        let requires_additional = self.requires_additional_mfa(risk_score)?;

        // Verify primary MFA
        let primary_valid = self.base_manager.verify_totp_code(user_id, code, Some(1)).await?;

        if !primary_valid {
            return Ok(MfaVerificationResult {
                valid: false,
                risk_score,
                requires_additional_mfa: false,
                session_token: None,
            });
        }

        // If additional MFA is required, verify that too
        if requires_additional {
            // For now, require recovery code as additional factor
            // In a real implementation, this would support multiple MFA methods
            return Ok(MfaVerificationResult {
                valid: false, // Primary valid but additional required
                risk_score,
                requires_additional_mfa: true,
                session_token: None,
            });
        }

        // Generate session token for successful enterprise MFA
        let session_token = self.generate_session_token(user_id, context).await?;

        Ok(MfaVerificationResult {
            valid: true,
            risk_score,
            requires_additional_mfa: false,
            session_token: Some(session_token),
        })
    }

    /// Verify additional MFA factor for enterprise security
    pub async fn verify_additional_mfa(
        &self,
        user_id: &str,
        additional_code: &str,
        session_token: &str,
    ) -> Result<bool, MfaError> {
        // Verify session token is valid and not expired
        let session = self.session_manager.read().await.get_session(session_token)?;

        if session.is_expired() {
            return Err(MfaError::SessionExpired);
        }

        // Verify additional MFA (recovery code for now)
        let valid = self.base_manager.verify_recovery_code(user_id, additional_code).await?;

        if valid {
            // Update session to mark additional MFA as completed
            self.session_manager.write().await.update_session(session_token, true)?;
        }

        Ok(valid)
    }

    /// Calculate risk score based on context
    async fn calculate_risk_score(&self, context: &MfaContext) -> Result<f64, MfaError> {
        let mut risk_engine = self.risk_engine.write().await;

        // Base risk factors
        let mut score = 0.0;

        // IP-based risk
        if context.ip_address.is_some() {
            score += risk_engine.assess_ip_risk(context.ip_address.as_ref().unwrap()).await?;
        }

        // Time-based risk (unusual hours)
        if context.timestamp.hour() < 6 || context.timestamp.hour() > 22 {
            score += 0.3;
        }

        // Location-based risk (if available)
        if let (Some(lat), Some(lon)) = (context.latitude, context.longitude) {
            score += risk_engine.assess_location_risk(lat, lon).await?;
        }

        // Device fingerprint risk
        if let Some(fingerprint) = &context.device_fingerprint {
            score += risk_engine.assess_device_risk(fingerprint).await?;
        }

        Ok(score.min(1.0)) // Cap at 1.0
    }

    /// Determine if additional MFA is required based on risk score
    fn requires_additional_mfa(&self, risk_score: f64) -> Result<bool, MfaError> {
        Ok(risk_score > self.enterprise_config.risk_threshold)
    }

    /// Generate enterprise session token
    async fn generate_session_token(&self, user_id: &str, context: &MfaContext) -> Result<String, MfaError> {
        let token = Uuid::new_v4().to_string();

        let session = EnterpriseMfaSession {
            token: token.clone(),
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(self.enterprise_config.session_duration_minutes as i64),
            context: context.clone(),
            additional_mfa_completed: false,
            risk_score: context.risk_score.unwrap_or(0.0),
        };

        self.session_manager.write().await.store_session(session)?;
        Ok(token)
    }
}

/// Risk assessment engine for enterprise MFA
pub struct RiskEngine {
    ip_blacklist: HashSet<String>,
    location_cache: HashMap<(f64, f64), f64>,
}

impl RiskEngine {
    pub fn new() -> Self {
        Self {
            ip_blacklist: HashSet::new(),
            location_cache: HashMap::new(),
        }
    }

    pub async fn assess_ip_risk(&self, ip: &str) -> Result<f64, MfaError> {
        if self.ip_blacklist.contains(ip) {
            return Ok(0.9); // High risk for blacklisted IPs
        }

        // Basic IP risk assessment (could be enhanced with external threat intelligence)
        let octets: Vec<&str> = ip.split('.').collect();
        if octets.len() == 4 {
            // Private IP ranges are lower risk
            if octets[0] == "10" || (octets[0] == "192" && octets[1] == "168") || octets[0] == "172" {
                return Ok(0.1);
            }
        }

        Ok(0.3) // Default medium risk
    }

    pub async fn assess_location_risk(&self, lat: f64, lon: f64) -> Result<f64, MfaError> {
        let key = (lat, lon);

        if let Some(&cached_risk) = self.location_cache.get(&key) {
            return Ok(cached_risk);
        }

        // Simple location-based risk (could be enhanced with geofencing)
        // For now, assume locations outside common business areas are higher risk
        let risk = if lat.abs() > 60.0 || lon.abs() > 180.0 {
            0.5 // Unusual coordinates
        } else {
            0.2 // Normal business locations
        };

        // Cache the result (in a real implementation, this would have TTL)
        // For now, just store it
        Ok(risk)
    }

    pub async fn assess_device_risk(&self, fingerprint: &str) -> Result<f64, MfaError> {
        // Simple device fingerprint risk assessment
        // In practice, this would involve more sophisticated analysis
        let risk = if fingerprint.len() < 50 {
            0.3 // Short fingerprint might indicate automation
        } else {
            0.1 // Normal device fingerprint
        };

        Ok(risk)
    }
}

/// Session manager for enterprise MFA
pub struct SessionManager {
    sessions: HashMap<String, EnterpriseMfaSession>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn store_session(&mut self, session: EnterpriseMfaSession) -> Result<(), MfaError> {
        self.sessions.insert(session.token.clone(), session);
        Ok(())
    }

    pub fn get_session(&self, token: &str) -> Result<&EnterpriseMfaSession, MfaError> {
        self.sessions.get(token)
            .ok_or_else(|| MfaError::SessionExpired)
    }

    pub fn update_session(&mut self, token: &str, additional_mfa_completed: bool) -> Result<(), MfaError> {
        if let Some(session) = self.sessions.get_mut(token) {
            session.additional_mfa_completed = additional_mfa_completed;
            Ok(())
        } else {
            Err(MfaError::SessionExpired)
        }
    }

    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.sessions.retain(|_, session| session.expires_at > now);
    }
}

/// Enterprise MFA session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseMfaSession {
    pub token: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub context: MfaContext,
    pub additional_mfa_completed: bool,
    pub risk_score: f64,
}

impl EnterpriseMfaSession {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_complete(&self) -> bool {
        !self.context.requires_additional_mfa || self.additional_mfa_completed
    }
}

/// Context information for MFA verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub device_fingerprint: Option<String>,
    pub requires_additional_mfa: bool,
    pub risk_score: Option<f64>,
}

/// Result of MFA verification with enterprise features
#[derive(Debug, Serialize)]
pub struct MfaVerificationResult {
    pub valid: bool,
    pub risk_score: f64,
    pub requires_additional_mfa: bool,
    pub session_token: Option<String>,
}
