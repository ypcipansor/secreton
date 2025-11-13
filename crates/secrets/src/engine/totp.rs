//! TOTP (Time-based One-Time Password) secret engine implementation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// TOTP configuration for a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpKey {
    /// Base32-encoded secret key
    pub secret: String,
    /// Account name
    pub account_name: String,
    /// Issuer name
    pub issuer: Option<String>,
    /// Number of digits (6 or 8)
    pub digits: u32,
    /// Time step in seconds (usually 30)
    pub period: u64,
    /// Hash algorithm (SHA1, SHA256, SHA512)
    pub algorithm: String,
    /// Creation time
    pub created_at: DateTime<Utc>,
}

/// TOTP engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Default number of digits
    pub default_digits: u32,
    /// Default period in seconds
    pub default_period: u64,
    /// Default algorithm
    pub default_algorithm: String,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            default_digits: 6,
            default_period: 30,
            default_algorithm: "SHA1".to_string(),
        }
    }
}

/// TOTP secret engine
pub struct TotpEngine {
    config: TotpConfig,
    enabled: bool,
    keys: RwLock<HashMap<String, TotpKey>>,
}

impl TotpEngine {
    pub fn new() -> Self {
        Self {
            config: TotpConfig::default(),
            enabled: false,
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a TOTP code for a given key and time
    fn generate_totp(&self, key: &TotpKey, time: u64) -> SecretResult<String> {
        // Decode base32 secret
        let secret = base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            &key.secret.to_uppercase(),
        )
        .ok_or_else(|| SecretError::InvalidSecretData("Invalid base32 secret".to_string()))?;

        // Calculate time counter
        let counter = time / key.period;

        // Convert counter to bytes (big-endian)
        let counter_bytes = counter.to_be_bytes();

        // Generate HMAC
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let mut mac = Hmac::<Sha1>::new_from_slice(&secret)
            .map_err(|_| SecretError::InvalidSecretData("Invalid key length".to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize();
        let hash = result.into_bytes();

        // Dynamic truncation
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let code = ((hash[offset] & 0x7f) as u32) << 24
            | ((hash[offset + 1] & 0xff) as u32) << 16
            | ((hash[offset + 2] & 0xff) as u32) << 8
            | ((hash[offset + 3] & 0xff) as u32);

        // Generate the final code
        let modulus = 10u32.pow(key.digits);
        let totp_code = (code % modulus).to_string();

        // Pad with zeros if necessary
        Ok(format!(
            "{:0width$}",
            totp_code,
            width = key.digits as usize
        ))
    }
}

#[async_trait]
impl SecretEngine for TotpEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Totp
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        // Load TOTP-specific configuration
        if let Some(totp_config) = config.config.get("totp") {
            if let Ok(totp_config) = serde_json::from_value(totp_config.clone()) {
                self.config = totp_config;
            }
        }

        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }

        let keys = self.keys.read().await;
        if let Some(key) = keys.get(path) {
            // Generate current TOTP code
            let current_time = Utc::now().timestamp() as u64;
            let code = self.generate_totp(key, current_time)?;

            let mut data = HashMap::new();
            data.insert("code".to_string(), Value::String(code));
            data.insert(
                "account_name".to_string(),
                Value::String(key.account_name.clone()),
            );
            if let Some(issuer) = &key.issuer {
                data.insert("issuer".to_string(), Value::String(issuer.clone()));
            }
            data.insert("digits".to_string(), Value::Number(key.digits.into()));
            data.insert("period".to_string(), Value::Number(key.period.into()));
            data.insert(
                "algorithm".to_string(),
                Value::String(key.algorithm.clone()),
            );

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data,
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "totp-engine".to_string(),
                    updated_by: "totp-engine".to_string(),
                    lease_id: None,
                    lease_duration: None,
                    tags: HashMap::from([("type".to_string(), "totp".to_string())]),
                },
                created_at: key.created_at,
                updated_at: Utc::now(),
            };

            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }

        // Extract TOTP key parameters
        let secret = data
            .get("secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SecretError::InvalidSecretData("Missing 'secret' field".to_string()))?
            .to_string();

        let account_name = data
            .get("account_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SecretError::InvalidSecretData("Missing 'account_name' field".to_string())
            })?
            .to_string();

        let issuer = data
            .get("issuer")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let digits = data
            .get("digits")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .unwrap_or(self.config.default_digits);

        let period = data
            .get("period")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.config.default_period);

        let algorithm = data
            .get("algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.default_algorithm)
            .to_string();

        // Validate parameters
        if digits != 6 && digits != 8 {
            return Err(SecretError::InvalidSecretData(
                "Digits must be 6 or 8".to_string(),
            ));
        }

        if period < 10 || period > 120 {
            return Err(SecretError::InvalidSecretData(
                "Period must be between 10 and 120 seconds".to_string(),
            ));
        }

        // Validate base32 secret
        if base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            &secret.to_uppercase(),
        )
        .is_none()
        {
            return Err(SecretError::InvalidSecretData(
                "Invalid base32 secret".to_string(),
            ));
        }

        let totp_key = TotpKey {
            secret: secret.clone(),
            account_name: account_name.clone(),
            issuer: issuer.clone(),
            digits,
            period,
            algorithm: algorithm.clone(),
            created_at: Utc::now(),
        };

        // Store the key
        let mut keys = self.keys.write().await;
        keys.insert(path.to_string(), totp_key);

        // Return the secret (without the actual TOTP secret for security)
        let mut response_data = HashMap::new();
        response_data.insert("account_name".to_string(), Value::String(account_name));
        if let Some(issuer_val) = issuer {
            response_data.insert("issuer".to_string(), Value::String(issuer_val));
        }
        response_data.insert("digits".to_string(), Value::Number(digits.into()));
        response_data.insert("period".to_string(), Value::Number(period.into()));
        response_data.insert("algorithm".to_string(), Value::String(algorithm));

        let secret = Secret {
            id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            data: response_data,
            metadata: SecretMetadata {
                version: 1,
                created_by: "totp-engine".to_string(),
                updated_by: "totp-engine".to_string(),
                lease_id: None,
                lease_duration: None,
                tags: HashMap::from([("type".to_string(), "totp".to_string())]),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        Ok(secret)
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }

        let mut keys = self.keys.write().await;
        if keys.remove(path).is_some() {
            Ok(())
        } else {
            Err(SecretError::SecretNotFound(format!(
                "TOTP key not found: {}",
                path
            )))
        }
    }

    async fn list(&self, _path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }

        let keys = self.keys.read().await;
        Ok(keys.keys().cloned().collect())
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}
