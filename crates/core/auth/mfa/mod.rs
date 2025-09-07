// use crate::crypto::CryptoService;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::storage::StorageBackend as MfaStorage;

// Re-export MfaMethod
pub use method::MfaMethod;

mod method;
use base32;
use hex;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::sync::Arc;
use thiserror::Error;
use totp_rs::{Algorithm, TOTP};

/// Error type for MFA operations
#[derive(Error, Debug)]
pub enum MfaError {
    #[error("MFA verification failed")]
    VerificationFailed,
    #[error("MFA setup required")]
    SetupRequired,
    #[error("Invalid MFA code")]
    InvalidCode,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Invalid recovery code")]
    InvalidRecoveryCode,
    #[error("MFA method not supported")]
    MethodNotSupported,
    #[error("MFA already set up")]
    AlreadySetUp,
    #[error("Storage error: {0}")]
    Storage(#[from] anyhow::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("System time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
}

impl From<totp_rs::TotpUrlError> for MfaError {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        MfaError::Crypto(format!("TOTP error: {}", err))
    }
}

/// Result type for MFA operations
pub type MfaResult<T> = std::result::Result<T, MfaError>;

/// Configuration for MFA rate limiting
#[derive(Debug, Clone)]
pub struct MfaRateLimitConfig {
    /// Maximum number of attempts allowed in the time window
    pub max_attempts: u32,
    /// Time window in seconds
    pub window_seconds: u64,
}

impl Default for MfaRateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_seconds: 300, // 5 minutes
        }
    }
}

/// Represents the status of MFA for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStatus {
    /// Whether MFA is enabled
    pub enabled: bool,
    /// The MFA methods that are set up
    pub methods: Vec<MfaMethod>,
    /// Whether recovery codes have been generated
    pub has_recovery_codes: bool,
    /// Number of recovery codes remaining
    pub remaining_recovery_codes: usize,
}

/// Represents the result of an MFA verification attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaVerificationResult {
    /// Whether verification was successful
    pub success: bool,
    /// Whether a recovery code was used
    pub used_recovery_code: bool,
    /// Number of recovery codes remaining
    pub remaining_recovery_codes: usize,
}

/// Manages MFA operations for users
#[derive(Clone)]
pub struct MfaManager<S>
where
    S: MfaStorage + Send + Sync + 'static,
{
    storage: Arc<S>,
    rate_limit_config: MfaRateLimitConfig,
    // In-memory rate limiting state
    #[cfg(not(feature = "distributed"))]
    rate_limits: Arc<dashmap::DashMap<String, (u32, u64)>>,
}

impl<S> MfaManager<S>
where
    S: MfaStorage + Send + Sync + 'static,
{
    /// Create a new MFA manager
    pub fn new(storage: S) -> Self {
        Self {
            storage: Arc::new(storage),
            rate_limit_config: MfaRateLimitConfig::default(),
            #[cfg(not(feature = "distributed"))]
            rate_limits: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Configure rate limiting
    pub fn with_rate_limit(mut self, max_attempts: u32, window_seconds: u64) -> Self {
        self.rate_limit_config = MfaRateLimitConfig {
            max_attempts,
            window_seconds,
        };
        self
    }

    /// Generate a new TOTP secret
    pub async fn generate_totp_secret(
        &self,
        user_id: &str,
        issuer: &str,
    ) -> MfaResult<(String, String)> {
        // Check if MFA is already set up
        if self.storage.is_mfa_enabled(user_id).await? {
            return Err(MfaError::AlreadySetUp);
        }

        // Generate a random secret
        let mut secret = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut secret);
        let secret_base32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);

        // Generate a TOTP URL for QR code generation
        // TODO: Fix TOTP creation with correct parameters
        let _totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.to_vec())?;

        let otp_url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            issuer, user_id, secret_base32, issuer
        );

        Ok((secret_base32, otp_url))
    }

    /// Verify a TOTP code
    pub async fn verify_totp(&self, user_id: &str, code: &str) -> MfaResult<MfaVerificationResult> {
        self.check_rate_limit(user_id).await?;

        // Get the stored secret
        let encrypted_secret = self
            .storage
            .get_mfa_secret(user_id, MfaMethod::Totp)
            .await?;
        let secret_bytes = decrypt_data(&encrypted_secret, "default-key")
            .map_err(|e| MfaError::Crypto(e.to_string()))?;

        let secret_base32 = secret_bytes;

        // Verify the code
        let totp =
            TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_base32.as_bytes().to_vec());

        let verified = totp.check_current(code)?;

        if !verified {
            self.increment_attempt(user_id).await?;
            return Err(MfaError::InvalidCode);
        }

        // Reset rate limiting on successful verification
        self.reset_attempts(user_id).await;

        Ok(MfaVerificationResult {
            success: true,
            used_recovery_code: false,
            remaining_recovery_codes: self.storage.get_mfa_recovery_codes(user_id).await?.len(),
        })
    }

    /// Generate recovery codes
    pub async fn generate_recovery_codes(
        &self,
        user_id: &str,
        count: usize,
    ) -> MfaResult<Vec<String>> {
        let mut rng = rand::thread_rng();
        let mut codes = Vec::with_capacity(count);

        for _ in 0..count {
            let mut code = [0u8; 8];
            rng.fill_bytes(&mut code);
            let code_hex = hex::encode(code);
            codes.push(code_hex);
        }

        // Store hashed versions of the codes
        let hashed_codes: Vec<String> = codes
            .iter()
            .map(|code| {
                let mut mac = Hmac::<Sha1>::new_from_slice(code.as_bytes())
                    .expect("HMAC can take key of any size");
                mac.update(b"vault-recovery-code");
                hex::encode(mac.finalize().into_bytes())
            })
            .collect();

        self.storage
            .store_mfa_recovery_codes(user_id, &hashed_codes)
            .await?;

        Ok(codes)
    }

    /// Verify a recovery code
    pub async fn verify_recovery_code(
        &self,
        user_id: &str,
        code: &str,
    ) -> MfaResult<MfaVerificationResult> {
        self.check_rate_limit(user_id).await?;

        let mut is_valid = false;
        let mut remaining_codes = Vec::new();
        let stored_codes = self.storage.get_mfa_recovery_codes(user_id).await?;

        // Check each stored code
        for stored_code in stored_codes {
            let mut mac = Hmac::<Sha1>::new_from_slice(code.as_bytes())
                .expect("HMAC can take key of any size");
            mac.update(b"vault-recovery-code");
            let computed_hash = hex::encode(mac.finalize().into_bytes());

            if !is_valid && computed_hash == stored_code {
                is_valid = true;
                // Don't add the used code back to remaining_codes
                continue;
            }
            remaining_codes.push(stored_code);
        }

        if !is_valid {
            self.increment_attempt(user_id).await?;
            return Err(MfaError::InvalidRecoveryCode);
        }

        // Update stored codes if any remain
        self.storage
            .store_mfa_recovery_codes(user_id, &remaining_codes)
            .await?;

        // Reset rate limiting on successful verification
        self.reset_attempts(user_id).await;

        Ok(MfaVerificationResult {
            success: true,
            used_recovery_code: true,
            remaining_recovery_codes: remaining_codes.len(),
        })
    }

    /// Get MFA status for a user
    pub async fn get_status(&self, user_id: &str) -> MfaResult<MfaStatus> {
        let methods = self.storage.get_user_mfa_methods(user_id).await?;
        let recovery_codes = self.storage.get_mfa_recovery_codes(user_id).await?;

        Ok(MfaStatus {
            enabled: !methods.is_empty(),
            methods,
            has_recovery_codes: !recovery_codes.is_empty(),
            remaining_recovery_codes: recovery_codes.len(),
        })
    }

    /// Enable MFA for a user
    pub async fn enable_mfa(
        &self,
        user_id: &str,
        method: MfaMethod,
        secret: &str,
    ) -> MfaResult<()> {
        // Encrypt the secret before storing
        let encrypted_secret =
            encrypt_data(secret, "default-key").map_err(|e| MfaError::Crypto(e.to_string()))?;

        // Store the encrypted secret
        self.storage
            .store_mfa_secret(user_id, &encrypted_secret, method)
            .await?;

        // Mark MFA as enabled for this method
        self.storage.enable_mfa(user_id, method).await?;

        // Generate recovery codes if none exist
        let recovery_codes = self.storage.get_mfa_recovery_codes(user_id).await?;
        if recovery_codes.is_empty() {
            self.generate_recovery_codes(user_id, 10).await?; // Generate 10 recovery codes
        }

        Ok(())
    }

    /// Disable MFA for a user
    pub async fn disable_mfa(&self, user_id: &str) -> MfaResult<()> {
        self.storage.disable_mfa(user_id).await?;
        self.storage
            .delete_mfa_secret(user_id, MfaMethod::Totp)
            .await?;
        self.storage.store_mfa_recovery_codes(user_id, &[]).await?;
        self.reset_attempts(user_id).await;
        Ok(())
    }

    // --- Rate limiting helpers ---

    #[allow(unused_variables)]
    async fn check_rate_limit(&self, user_id: &str) -> MfaResult<()> {
        #[cfg(not(feature = "distributed"))]
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if let Some(rate_limit_data) = self.rate_limits.get(user_id) {
                let (attempts, timestamp) = *rate_limit_data;
                let elapsed = now - timestamp;
                if elapsed < self.rate_limit_config.window_seconds {
                    if attempts >= self.rate_limit_config.max_attempts {
                        return Err(MfaError::RateLimitExceeded);
                    }
                } else {
                    // Reset if window has passed
                    self.rate_limits.remove(user_id);
                }
            }
        }

        Ok(())
    }

    #[allow(unused_variables)]
    async fn increment_attempt(&self, user_id: &str) -> MfaResult<()> {
        #[cfg(not(feature = "distributed"))]
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut attempts = 1;
            if let Some(rate_limit_data) = self.rate_limits.get(user_id) {
                let (prev_attempts, timestamp) = *rate_limit_data;
                if now - timestamp < self.rate_limit_config.window_seconds {
                    attempts = prev_attempts + 1;
                }
            }

            self.rate_limits
                .insert(user_id.to_string(), (attempts, now));
        }

        Ok(())
    }

    #[allow(unused_variables)]
    async fn reset_attempts(&self, user_id: &str) {
        #[cfg(not(feature = "distributed"))]
        {
            self.rate_limits.remove(user_id);
        }
    }
}
