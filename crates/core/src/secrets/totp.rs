// TOTP/HOTP Secrets Engine - Time-based and Counter-based OTP generation
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum OTPError {
    #[error("OTP error: {0}")]
    OTPError(String),
    #[error("Invalid code: {0}")]
    InvalidCode(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, OTPError>;

/// OTP key type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    TOTP, // Time-based OTP
    HOTP, // Counter-based OTP
}

/// Hash algorithm for OTP
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

/// TOTP key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TOTPKey {
    pub issuer: String,
    pub account_name: String,
    pub secret: String, // Base32 encoded
    pub algorithm: Algorithm,
    pub digits: u32, // 6 or 8
    pub period: u32, // Seconds, typically 30
}

/// HOTP key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HOTPKey {
    pub issuer: String,
    pub account_name: String,
    pub secret: String, // Base32 encoded
    pub algorithm: Algorithm,
    pub digits: u32,  // 6 or 8
    pub counter: u64, // Current counter value
}

/// OTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTPConfig {
    pub name: String,
    pub issuer: String,
    pub account_name: String,
    pub key_type: KeyType,
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: Option<u32>,  // For TOTP
    pub counter: Option<u64>, // For HOTP
    pub qr_size: u32,         // QR code size in pixels
    pub skew: u32,            // Time skew tolerance in periods
    pub created_at: DateTime<Utc>,
}

/// Generated OTP code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedCode {
    pub code: String,
    pub valid_until: Option<DateTime<Utc>>, // For TOTP
    pub counter: Option<u64>,               // For HOTP
}

/// TOTP/HOTP secrets engine
pub struct TOTPEngine {
    keys: Arc<RwLock<HashMap<String, OTPConfig>>>,
}

impl TOTPEngine {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new OTP key
    pub async fn create_key(&self, mut config: OTPConfig) -> Result<String> {
        if config.name.is_empty() {
            return Err(OTPError::ConfigError("Name is required".to_string()));
        }
        if config.issuer.is_empty() {
            return Err(OTPError::ConfigError("Issuer is required".to_string()));
        }
        if config.account_name.is_empty() {
            return Err(OTPError::ConfigError(
                "Account name is required".to_string(),
            ));
        }

        // Generate secret if not provided
        if config.secret.is_empty() {
            config.secret = self.generate_secret();
        }

        // Validate configuration
        match config.key_type {
            KeyType::TOTP => {
                if config.period.is_none() {
                    config.period = Some(30); // Default 30 seconds
                }
            }
            KeyType::HOTP => {
                if config.counter.is_none() {
                    config.counter = Some(0); // Start from 0
                }
            }
        }

        if config.digits != 6 && config.digits != 8 {
            return Err(OTPError::ConfigError("Digits must be 6 or 8".to_string()));
        }

        config.created_at = Utc::now();

        let url = self.generate_url(&config);

        let mut keys = self.keys.write().await;
        keys.insert(config.name.clone(), config);

        Ok(url)
    }

    /// Generate a random secret (Base32)
    fn generate_secret(&self) -> String {
        use rand::Rng;
        const BASE32_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut rng = rand::thread_rng();

        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..BASE32_CHARSET.len());
                BASE32_CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate OTP URL for QR code
    fn generate_url(&self, config: &OTPConfig) -> String {
        let key_type = match config.key_type {
            KeyType::TOTP => "totp",
            KeyType::HOTP => "hotp",
        };

        let algorithm = match config.algorithm.clone() {
            Algorithm::SHA1 => "SHA1",
            Algorithm::SHA256 => "SHA256",
            Algorithm::SHA512 => "SHA512",
        };

        let mut url = format!(
            "otpauth://{}/{}:{}?secret={}&issuer={}&algorithm={}&digits={}",
            key_type,
            urlencoding::encode(&config.issuer),
            urlencoding::encode(&config.account_name),
            config.secret,
            urlencoding::encode(&config.issuer),
            algorithm,
            config.digits
        );

        match config.key_type {
            KeyType::TOTP => {
                if let Some(period) = config.period {
                    url.push_str(&format!("&period={}", period));
                }
            }
            KeyType::HOTP => {
                if let Some(counter) = config.counter {
                    url.push_str(&format!("&counter={}", counter));
                }
            }
        }

        url
    }

    /// Generate current OTP code
    pub async fn generate_code(&self, name: &str) -> Result<GeneratedCode> {
        let mut keys = self.keys.write().await;
        let config = keys
            .get_mut(name)
            .ok_or_else(|| OTPError::KeyNotFound(name.to_string()))?;

        match config.key_type {
            KeyType::TOTP => {
                let period = config.period.unwrap_or(30);
                let timestamp = Utc::now().timestamp() as u64;
                let counter = timestamp / period as u64;

                let code = self.generate_otp_code(
                    &config.secret,
                    counter,
                    config.digits,
                    config.algorithm.clone(),
                )?;
                let valid_until = Utc::now() + Duration::seconds(period as i64);

                Ok(GeneratedCode {
                    code,
                    valid_until: Some(valid_until),
                    counter: None,
                })
            }
            KeyType::HOTP => {
                let counter = config.counter.unwrap_or(0);
                let code = self.generate_otp_code(
                    &config.secret,
                    counter,
                    config.digits,
                    config.algorithm.clone(),
                )?;

                // Increment counter
                config.counter = Some(counter + 1);

                Ok(GeneratedCode {
                    code,
                    valid_until: None,
                    counter: Some(counter),
                })
            }
        }
    }

    /// Generate OTP code from secret and counter
    fn generate_otp_code(
        &self,
        secret: &str,
        counter: u64,
        digits: u32,
        algorithm: Algorithm,
    ) -> Result<String> {
        use base32::decode;
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        use sha2::{Sha256, Sha512};

        // Decode base32 secret to bytes
        let secret_bytes = decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| OTPError::OTPError("Invalid base32 secret".to_string()))?;

        // Convert counter to big-endian bytes (8 bytes)
        let counter_bytes = counter.to_be_bytes();

        // Compute HMAC based on algorithm
        let hash_result = match algorithm {
            Algorithm::SHA1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&secret_bytes)
                    .map_err(|_| OTPError::OTPError("HMAC initialization failed".to_string()))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&secret_bytes)
                    .map_err(|_| OTPError::OTPError("HMAC initialization failed".to_string()))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(&secret_bytes)
                    .map_err(|_| OTPError::OTPError("HMAC initialization failed".to_string()))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Dynamic truncation (RFC 4226 section 5.4)
        let offset = (hash_result[hash_result.len() - 1] & 0xf) as usize;
        let binary_code = ((hash_result[offset] & 0x7f) as u32) << 24
            | (hash_result[offset + 1] as u32) << 16
            | (hash_result[offset + 2] as u32) << 8
            | (hash_result[offset + 3] as u32);

        // Generate code with specified number of digits
        let code = binary_code % 10_u32.pow(digits);
        Ok(format!("{:0width$}", code, width = digits as usize))
    }

    /// Validate OTP code
    pub async fn validate_code(&self, name: &str, code: &str) -> Result<bool> {
        let keys = self.keys.read().await;
        let config = keys
            .get(name)
            .ok_or_else(|| OTPError::KeyNotFound(name.to_string()))?;

        match config.key_type {
            KeyType::TOTP => {
                let period = config.period.unwrap_or(30);
                let skew = config.skew;
                let timestamp = Utc::now().timestamp() as u64;
                let current_counter = timestamp / period as u64;

                // Check current and skewed periods
                for offset in 0..=skew {
                    for sign in [-1, 1] {
                        let counter = if sign > 0 {
                            current_counter + offset as u64
                        } else {
                            current_counter.saturating_sub(offset as u64)
                        };

                        let expected = self.generate_otp_code(
                            &config.secret,
                            counter,
                            config.digits,
                            config.algorithm.clone(),
                        )?;
                        if expected == code {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            }
            KeyType::HOTP => {
                // For HOTP, validate against current counter
                let counter = config.counter.unwrap_or(0);
                let expected = self.generate_otp_code(
                    &config.secret,
                    counter,
                    config.digits,
                    config.algorithm.clone(),
                )?;
                Ok(expected == code)
            }
        }
    }

    /// Generate QR code data
    pub async fn generate_qr_code(&self, name: &str) -> Result<String> {
        let keys = self.keys.read().await;
        let config = keys
            .get(name)
            .ok_or_else(|| OTPError::KeyNotFound(name.to_string()))?;

        let url = self.generate_url(config);

        // Generate QR code using qrcode crate
        let qr_code = qrcode::QrCode::new(url.as_bytes())
            .map_err(|_| OTPError::OTPError("Failed to generate QR code".to_string()))?;

        // Convert to PNG image
        let image = qr_code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();

        // For now, return the text-based QR. In a real implementation, you'd convert to PNG and base64 encode
        // But since this is text-based, we'll just return it as a string
        Ok(image)
    }

    /// Get key configuration
    pub async fn get_key(&self, name: &str) -> Result<OTPConfig> {
        let keys = self.keys.read().await;
        keys.get(name)
            .cloned()
            .ok_or_else(|| OTPError::KeyNotFound(name.to_string()))
    }

    /// List all keys
    pub async fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.read().await;
        keys.keys().cloned().collect()
    }

    /// Delete a key
    pub async fn delete_key(&self, name: &str) -> Result<()> {
        let mut keys = self.keys.write().await;
        keys.remove(name)
            .ok_or_else(|| OTPError::KeyNotFound(name.to_string()))?;
        Ok(())
    }

    /// Rotate secret for a key
    pub async fn rotate_secret(&self, name: &str) -> Result<String> {
        let mut keys = self.keys.write().await;
        let config = keys
            .get_mut(name)
            .ok_or_else(|| OTPError::KeyNotFound(name.to_string()))?;

        let new_secret = self.generate_secret();
        config.secret = new_secret.clone();

        // Reset counter for HOTP
        if config.key_type == KeyType::HOTP {
            config.counter = Some(0);
        }

        let url = self.generate_url(config);
        Ok(url)
    }
}

impl Default for TOTPEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_totp_key() {
        let engine = TOTPEngine::new();

        let config = OTPConfig {
            name: "user@example.com".to_string(),
            issuer: "MyApp".to_string(),
            account_name: "user@example.com".to_string(),
            key_type: KeyType::TOTP,
            secret: String::new(), // Will be generated
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: Some(30),
            counter: None,
            qr_size: 200,
            skew: 1,
            created_at: Utc::now(),
        };

        let url = engine.create_key(config).await.unwrap();

        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("MyApp"));
        // URL-encoded: user%40example.com or user@example.com
        assert!(url.contains("user%40example.com") || url.contains("user@example.com"));
        assert!(url.contains("&period=30"));
    }

    #[tokio::test]
    async fn test_generate_totp_code() {
        let engine = TOTPEngine::new();

        let config = OTPConfig {
            name: "test-totp".to_string(),
            issuer: "TestApp".to_string(),
            account_name: "test@example.com".to_string(),
            key_type: KeyType::TOTP,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: Some(30),
            counter: None,
            qr_size: 200,
            skew: 1,
            created_at: Utc::now(),
        };

        engine.create_key(config).await.unwrap();

        let code = engine.generate_code("test-totp").await.unwrap();

        assert_eq!(code.code.len(), 6);
        assert!(code.valid_until.is_some());
        assert!(code.counter.is_none());
    }

    #[tokio::test]
    async fn test_validate_totp_with_skew() {
        let engine = TOTPEngine::new();

        let config = OTPConfig {
            name: "validate-test".to_string(),
            issuer: "TestApp".to_string(),
            account_name: "test@example.com".to_string(),
            key_type: KeyType::TOTP,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: Some(30),
            counter: None,
            qr_size: 200,
            skew: 1,
            created_at: Utc::now(),
        };

        engine.create_key(config).await.unwrap();

        let code = engine.generate_code("validate-test").await.unwrap();

        // Should validate successfully
        let is_valid = engine
            .validate_code("validate-test", &code.code)
            .await
            .unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_hotp_counter_increment() {
        let engine = TOTPEngine::new();

        let config = OTPConfig {
            name: "test-hotp".to_string(),
            issuer: "TestApp".to_string(),
            account_name: "test@example.com".to_string(),
            key_type: KeyType::HOTP,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            counter: Some(0),
            period: None,
            qr_size: 200,
            skew: 0,
            created_at: Utc::now(),
        };

        engine.create_key(config).await.unwrap();

        let code1 = engine.generate_code("test-hotp").await.unwrap();
        assert_eq!(code1.counter, Some(0));

        let code2 = engine.generate_code("test-hotp").await.unwrap();
        assert_eq!(code2.counter, Some(1));

        let code3 = engine.generate_code("test-hotp").await.unwrap();
        assert_eq!(code3.counter, Some(2));

        // Codes should be different
        assert_ne!(code1.code, code2.code);
        assert_ne!(code2.code, code3.code);
    }

    #[tokio::test]
    async fn test_generate_qr_code() {
        let engine = TOTPEngine::new();

        let config = OTPConfig {
            name: "qr-test".to_string(),
            issuer: "MyApp".to_string(),
            account_name: "user@example.com".to_string(),
            key_type: KeyType::TOTP,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::SHA256,
            digits: 8,
            period: Some(30),
            counter: None,
            qr_size: 300,
            skew: 1,
            created_at: Utc::now(),
        };

        engine.create_key(config).await.unwrap();

        let qr_data = engine.generate_qr_code("qr-test").await.unwrap();

        assert!(!qr_data.is_empty());
    }

    #[tokio::test]
    async fn test_rotate_secret() {
        let engine = TOTPEngine::new();

        let config = OTPConfig {
            name: "rotate-test".to_string(),
            issuer: "TestApp".to_string(),
            account_name: "test@example.com".to_string(),
            key_type: KeyType::TOTP,
            secret: "OLDSECRETNEEDROTATION".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: Some(30),
            counter: None,
            qr_size: 200,
            skew: 1,
            created_at: Utc::now(),
        };

        engine.create_key(config).await.unwrap();

        let old_key = engine.get_key("rotate-test").await.unwrap();
        let old_secret = old_key.secret.clone();

        let new_url = engine.rotate_secret("rotate-test").await.unwrap();

        let new_key = engine.get_key("rotate-test").await.unwrap();
        assert_ne!(new_key.secret, old_secret);
        assert!(new_url.contains(&new_key.secret));
    }
}
