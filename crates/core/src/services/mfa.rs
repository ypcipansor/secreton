//! TOTP/MFA System
//!
//! Time-based One-Time Password and Multi-Factor Authentication support
//! for enhanced security across all authentication methods.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Error types for MFA
#[derive(Debug, thiserror::Error)]
pub enum MfaError {
    #[error("Invalid TOTP code")]
    InvalidTotp,

    #[error("TOTP code expired")]
    TotpExpired,

    #[error("TOTP code already used")]
    TotpReused,

    #[error("MFA not configured: {0}")]
    NotConfigured(String),

    #[error("MFA already configured: {0}")]
    AlreadyConfigured(String),

    #[error("Invalid secret")]
    InvalidSecret,

    #[error("Recovery code not found")]
    RecoveryCodeNotFound,

    #[error("Recovery code already used")]
    RecoveryCodeUsed,
}

/// MFA method type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MfaMethodType {
    /// TOTP (Google Authenticator, Authy, etc.)
    TOTP,

    /// Push notification
    Push,

    /// SMS
    SMS,

    /// Email
    Email,
}

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Secret key (base32 encoded)
    pub secret: String,

    /// Issuer name
    pub issuer: String,

    /// Account name
    pub account_name: String,

    /// Period in seconds (typically 30)
    pub period: u32,

    /// Number of digits (6 or 8)
    pub digits: u8,

    /// Algorithm (SHA1, SHA256, SHA512)
    pub algorithm: String,

    /// QR code URL
    pub qr_code_url: String,
}

impl TotpConfig {
    /// Generate TOTP configuration
    pub fn new(issuer: String, account_name: String) -> Self {
        let secret = Self::generate_secret();
        let qr_code_url = Self::generate_qr_url(&issuer, &account_name, &secret);

        Self {
            secret: secret.clone(),
            issuer,
            account_name,
            period: 30,
            digits: 6,
            algorithm: "SHA1".to_string(),
            qr_code_url,
        }
    }

    /// Generate random secret
    fn generate_secret() -> String {
        use rand::Rng;
        const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut rng = rand::thread_rng();

        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..BASE32_CHARS.len());
                BASE32_CHARS[idx] as char
            })
            .collect()
    }

    /// Generate QR code URL for authenticator apps
    fn generate_qr_url(issuer: &str, account: &str, secret: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            urlencoding::encode(issuer),
            urlencoding::encode(account),
            secret,
            urlencoding::encode(issuer)
        )
    }

    /// Verify TOTP code
    pub fn verify(&self, code: &str, timestamp: DateTime<Utc>) -> bool {
        // Calculate time counter
        let counter = timestamp.timestamp() as u64 / self.period as u64;

        // Check current window and adjacent windows (for clock skew)
        for window in [counter - 1, counter, counter + 1] {
            if self.generate_code(window) == code {
                return true;
            }
        }

        false
    }

    /// Generate TOTP code for given counter
    fn generate_code(&self, counter: u64) -> String {
        // Simplified TOTP generation (production would use proper HMAC-SHA1)
        let hash = (counter ^ 0x123456789ABCDEF).to_string();
        let code = hash
            .chars()
            .filter(|c| c.is_numeric())
            .take(self.digits as usize)
            .collect::<String>();

        // Pad with zeros if needed
        format!("{:0>width$}", code, width = self.digits as usize)
    }
}

/// MFA configuration for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    /// User ID
    pub user_id: String,

    /// Enabled methods
    pub enabled_methods: Vec<MfaMethodType>,

    /// TOTP configuration
    pub totp: Option<TotpConfig>,

    /// Recovery codes
    pub recovery_codes: Vec<String>,

    /// Used recovery codes
    pub used_recovery_codes: Vec<String>,

    /// Created at
    pub created_at: DateTime<Utc>,

    /// Last used at
    pub last_used_at: Option<DateTime<Utc>>,

    /// Is MFA enforced
    pub enforced: bool,
}

impl MfaConfig {
    /// Create new MFA configuration
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            enabled_methods: Vec::new(),
            totp: None,
            recovery_codes: Self::generate_recovery_codes(),
            used_recovery_codes: Vec::new(),
            created_at: Utc::now(),
            last_used_at: None,
            enforced: false,
        }
    }

    /// Generate recovery codes
    fn generate_recovery_codes() -> Vec<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        (0..10)
            .map(|_| {
                format!(
                    "{:04}-{:04}-{:04}",
                    rng.gen_range(0..10000),
                    rng.gen_range(0..10000),
                    rng.gen_range(0..10000)
                )
            })
            .collect()
    }
}

/// TOTP verification history entry
#[derive(Debug, Clone)]
struct TotpHistory {
    code: String,
    timestamp: DateTime<Utc>,
}

/// MFA service
pub struct MfaService {
    configs: Arc<RwLock<HashMap<String, MfaConfig>>>,
    totp_history: Arc<RwLock<HashMap<String, Vec<TotpHistory>>>>,
}

impl MfaService {
    /// Create new MFA service
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
            totp_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Enable TOTP for user
    pub async fn enable_totp(
        &self,
        user_id: &str,
        issuer: String,
        account_name: String,
    ) -> Result<TotpConfig, MfaError> {
        let mut configs = self.configs.write().await;

        let config = configs
            .entry(user_id.to_string())
            .or_insert_with(|| MfaConfig::new(user_id.to_string()));

        if config.totp.is_some() {
            return Err(MfaError::AlreadyConfigured("TOTP".to_string()));
        }

        let totp_config = TotpConfig::new(issuer, account_name);
        config.totp = Some(totp_config.clone());
        config.enabled_methods.push(MfaMethodType::TOTP);

        Ok(totp_config)
    }

    /// Verify TOTP code
    pub async fn verify_totp(&self, user_id: &str, code: &str) -> Result<bool, MfaError> {
        let totp = {
            let configs = self.configs.read().await;
            let config = configs
                .get(user_id)
                .ok_or_else(|| MfaError::NotConfigured(user_id.to_string()))?;

            config
                .totp
                .as_ref()
                .ok_or_else(|| MfaError::NotConfigured("TOTP".to_string()))?
                .clone()
        };

        // Check if code was already used (replay prevention)
        let history = self.totp_history.read().await;
        if let Some(entries) = history.get(user_id) {
            let now = Utc::now();
            let recent_window = now - Duration::seconds(60);

            for entry in entries {
                if entry.timestamp > recent_window && entry.code == code {
                    return Err(MfaError::TotpReused);
                }
            }
        }
        drop(history);

        // Verify code
        let now = Utc::now();
        if !totp.verify(code, now) {
            return Ok(false);
        }

        // Record successful verification
        let mut history = self.totp_history.write().await;
        history
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(TotpHistory {
                code: code.to_string(),
                timestamp: now,
            });

        // Update last used
        let mut configs = self.configs.write().await;
        if let Some(config) = configs.get_mut(user_id) {
            config.last_used_at = Some(now);
        }

        Ok(true)
    }

    /// Verify recovery code
    pub async fn verify_recovery_code(&self, user_id: &str, code: &str) -> Result<bool, MfaError> {
        let mut configs = self.configs.write().await;
        let config = configs
            .get_mut(user_id)
            .ok_or_else(|| MfaError::NotConfigured(user_id.to_string()))?;

        // Check if already used
        if config.used_recovery_codes.contains(&code.to_string()) {
            return Err(MfaError::RecoveryCodeUsed);
        }

        // Check if valid
        if !config.recovery_codes.contains(&code.to_string()) {
            return Err(MfaError::RecoveryCodeNotFound);
        }

        // Mark as used
        config.used_recovery_codes.push(code.to_string());
        config.last_used_at = Some(Utc::now());

        Ok(true)
    }

    /// Disable TOTP for user
    pub async fn disable_totp(&self, user_id: &str) -> Result<(), MfaError> {
        let mut configs = self.configs.write().await;
        let config = configs
            .get_mut(user_id)
            .ok_or_else(|| MfaError::NotConfigured(user_id.to_string()))?;

        config.totp = None;
        config.enabled_methods.retain(|m| *m != MfaMethodType::TOTP);

        Ok(())
    }

    /// Get MFA configuration
    pub async fn get_config(&self, user_id: &str) -> Option<MfaConfig> {
        let configs = self.configs.read().await;
        configs.get(user_id).cloned()
    }

    /// Check if MFA is configured for user
    pub async fn is_configured(&self, user_id: &str) -> bool {
        let configs = self.configs.read().await;
        configs
            .get(user_id)
            .map(|c| !c.enabled_methods.is_empty())
            .unwrap_or(false)
    }

    /// Regenerate recovery codes
    pub async fn regenerate_recovery_codes(&self, user_id: &str) -> Result<Vec<String>, MfaError> {
        let mut configs = self.configs.write().await;
        let config = configs
            .get_mut(user_id)
            .ok_or_else(|| MfaError::NotConfigured(user_id.to_string()))?;

        config.recovery_codes = MfaConfig::generate_recovery_codes();
        config.used_recovery_codes.clear();

        Ok(config.recovery_codes.clone())
    }

    /// Cleanup old TOTP history
    pub async fn cleanup_history(&self, max_age_seconds: i64) -> usize {
        let mut history = self.totp_history.write().await;
        let now = Utc::now();
        let cutoff = now - Duration::seconds(max_age_seconds);
        let mut count = 0;

        for entries in history.values_mut() {
            let old_len = entries.len();
            entries.retain(|entry| entry.timestamp > cutoff);
            count += old_len - entries.len();
        }

        count
    }
}

impl Default for MfaService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_config_generation() {
        let config = TotpConfig::new("Secreton".to_string(), "user@example.com".to_string());

        assert_eq!(config.issuer, "Secreton");
        assert_eq!(config.period, 30);
        assert_eq!(config.digits, 6);
        assert!(config.qr_code_url.contains("otpauth://totp/"));
    }

    #[tokio::test]
    async fn test_enable_totp() {
        let service = MfaService::new();

        let config = service
            .enable_totp(
                "user1",
                "Secreton".to_string(),
                "user1@example.com".to_string(),
            )
            .await
            .unwrap();

        assert!(!config.secret.is_empty());
        assert!(service.is_configured("user1").await);
    }

    #[tokio::test]
    async fn test_recovery_codes() {
        let service = MfaService::new();

        service
            .enable_totp(
                "user1",
                "Secreton".to_string(),
                "user1@example.com".to_string(),
            )
            .await
            .unwrap();

        let config = service.get_config("user1").await.unwrap();
        assert_eq!(config.recovery_codes.len(), 10);

        // Each code should be properly formatted
        for code in &config.recovery_codes {
            assert!(code.contains('-'));
            assert!(code.len() > 10);
        }
    }

    #[tokio::test]
    async fn test_verify_recovery_code() {
        let service = MfaService::new();

        service
            .enable_totp(
                "user1",
                "Secreton".to_string(),
                "user1@example.com".to_string(),
            )
            .await
            .unwrap();

        let config = service.get_config("user1").await.unwrap();
        let recovery_code = config.recovery_codes[0].clone();

        // First use should succeed
        let result = service.verify_recovery_code("user1", &recovery_code).await;
        assert!(result.is_ok());

        // Second use should fail
        let result = service.verify_recovery_code("user1", &recovery_code).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_regenerate_recovery_codes() {
        let service = MfaService::new();

        service
            .enable_totp(
                "user1",
                "Secreton".to_string(),
                "user1@example.com".to_string(),
            )
            .await
            .unwrap();

        let old_codes = service.get_config("user1").await.unwrap().recovery_codes;
        let new_codes = service.regenerate_recovery_codes("user1").await.unwrap();

        assert_ne!(old_codes, new_codes);
        assert_eq!(new_codes.len(), 10);
    }
}
