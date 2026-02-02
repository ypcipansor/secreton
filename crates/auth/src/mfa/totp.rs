//! TOTP (Time-based One-Time Password) MFA implementation

use async_trait::async_trait;
use base32::{decode, encode};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use secreton_errors::SecretonError;
use serde::{Serialize, Deserialize};

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub issuer: String,
    pub period: u32,       // Time step in seconds (usually 30)
    pub digits: u32,       // Number of digits (usually 6)
    pub algorithm: String, // Usually "SHA1"
}

/// TOTP enrollment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollment {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub secret: String, // Base32 encoded secret
    pub url: String,    // otpauth:// URL
    pub creation_time: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// TOTP validation request
#[derive(Debug)]
pub struct TotpValidationRequest {
    pub entity_id: Uuid,
    pub code: String,
}

/// TOTP service trait
#[async_trait]
pub trait TotpService: Send + Sync {
    /// Enroll an entity for TOTP
    async fn enroll(
        &self,
        entity_id: Uuid,
        issuer: String,
    ) -> Result<TotpEnrollment, SecretonError>;

    /// Validate a TOTP code
    async fn validate(&self, request: TotpValidationRequest) -> Result<bool, SecretonError>;

    /// Get enrollment for an entity
    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<TotpEnrollment>, SecretonError>;

    /// Remove TOTP enrollment for an entity
    async fn remove_enrollment(&self, entity_id: Uuid) -> Result<(), SecretonError>;
}

/// In-memory TOTP service implementation
pub struct InMemoryTotpService {
    enrollments: RwLock<HashMap<Uuid, TotpEnrollment>>,
    config: TotpConfig,
}

impl InMemoryTotpService {
    pub fn new(issuer: String) -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            config: TotpConfig {
                issuer,
                period: 30,
                digits: 6,
                algorithm: "SHA1".to_string(),
            },
        }
    }

    /// Generate a random secret
    fn generate_secret() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
    }

    /// Generate TOTP code from secret and time
    fn generate_totp(
        secret: &str,
        time: u64,
        period: u32,
        digits: u32,
    ) -> Result<String, SecretonError> {
        let secret_bytes = decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| SecretonError::Configuration {
                message: "Invalid base32 secret".to_string(),
            })?;

        let counter = time / period as u64;

        // HMAC-SHA1
        let mut mac = Hmac::<Sha1>::new_from_slice(&secret_bytes).map_err(|_| {
            SecretonError::Configuration {
                message: "Failed to create HMAC".to_string(),
            }
        })?;

        mac.update(&counter.to_be_bytes());
        let result = mac.finalize().into_bytes();

        // Dynamic truncation
        let offset = (result[19] & 0xf) as usize;
        let code = ((result[offset] & 0x7f) as u32) << 24
            | (u32::from(result[offset + 1])) << 16
            | (u32::from(result[offset + 2])) << 8
            | u32::from(result[offset + 3]);

        let modulus = 10u32.pow(digits);
        let totp = code % modulus;

        Ok(format!("{:0width$}", totp, width = digits as usize))
    }

    /// Generate otpauth URL
    fn generate_url(&self, secret: &str, account_name: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            self.config.issuer,
            account_name,
            secret,
            self.config.issuer,
            self.config.algorithm,
            self.config.digits,
            self.config.period
        )
    }
}

#[async_trait]
impl TotpService for InMemoryTotpService {
    async fn enroll(
        &self,
        entity_id: Uuid,
        account_name: String,
    ) -> Result<TotpEnrollment, SecretonError> {
        let secret = Self::generate_secret();
        let url = self.generate_url(&secret, &account_name);

        let enrollment = TotpEnrollment {
            id: Uuid::new_v4(),
            entity_id,
            secret: secret.clone(),
            url,
            creation_time: Utc::now(),
            last_used: None,
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(entity_id, enrollment.clone());

        Ok(enrollment)
    }

    async fn validate(&self, request: TotpValidationRequest) -> Result<bool, SecretonError> {
        let enrollments = self.enrollments.read().await;

        if let Some(enrollment) = enrollments.get(&request.entity_id) {
            let current_time = Utc::now().timestamp() as u64;

            // Check current time window and adjacent windows for clock skew
            for time_offset in [-1i64, 0, 1].iter() {
                let check_time =
                    (current_time as i64 + time_offset * self.config.period as i64) as u64;
                let expected_code = Self::generate_totp(
                    &enrollment.secret,
                    check_time,
                    self.config.period,
                    self.config.digits,
                )?;

                if expected_code == request.code {
                    // Update last used time
                    drop(enrollments);
                    let mut enrollments = self.enrollments.write().await;
                    if let Some(enrollment) = enrollments.get_mut(&request.entity_id) {
                        enrollment.last_used = Some(Utc::now());
                    }
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<TotpEnrollment>, SecretonError> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments.get(&entity_id).cloned())
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> Result<(), SecretonError> {
        let mut enrollments = self.enrollments.write().await;
        enrollments.remove(&entity_id);
        Ok(())
    }
}
