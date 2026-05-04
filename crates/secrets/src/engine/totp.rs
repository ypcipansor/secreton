//! TOTP secret engine for dynamic codes

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub issuer: String,
    pub period: u64,
    pub algorithm: String,
    pub digits: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "Secreton".to_string(),
            period: 30,
            algorithm: "SHA1".to_string(),
            digits: 6,
        }
    }
}

/// TOTP key data
#[derive(Debug, Clone)]
struct TotpKey {
    pub key: String, // Base32 encoded
    pub period: u64,
    pub digits: u32,
    #[allow(dead_code)]
    pub issuer: String,
    #[allow(dead_code)]
    pub account_name: String,
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
            &key.key.to_uppercase(),
        )
        .ok_or_else(|| SecretError::InvalidSecretData("Invalid base32 key".to_string()))?;

        // Calculate counter
        let counter = time / key.period;
        let counter_bytes = counter.to_be_bytes();

        // HMAC-SHA1
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        let mut mac = HmacSha1::new_from_slice(&secret)
            .map_err(|e| SecretError::CryptoError(e.to_string()))?;
        mac.update(&counter_bytes);
        let hash = mac.finalize().into_bytes();

        // Dynamic truncation
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let code = ((hash[offset] & 0x7f) as u32) << 24
            | (u32::from(hash[offset + 1])) << 16
            | (u32::from(hash[offset + 2])) << 8
            | (u32::from(hash[offset + 3]));

        // Generate the final code
        let modulus = 10u32.pow(key.digits);
        let otp = code % modulus;

        Ok(format!("{:0width$}", otp, width = key.digits as usize))
    }
}

impl Default for TotpEngine {
    fn default() -> Self {
        Self::new()
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
            return Err(SecretError::EngineNotFound("totp".to_string()));
        }

        // Handle code generation
        if let Some(key_name) = path.strip_prefix("code/") {
            let keys = self.keys.read().await;
            let key = keys.get(key_name).ok_or_else(|| {
                SecretError::SecretNotFound(format!("Key '{}' not found", key_name))
            })?;

            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let code = self.generate_totp(key, current_time)?;

            let mut data = HashMap::new();
            data.insert("code".to_string(), Value::String(code));

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data,
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: None,
                    lease_duration: None,
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("totp".to_string()));
        }

        // Handle key creation
        if let Some(key_name) = path.strip_prefix("keys/") {
            let key_val = data
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SecretError::InvalidSecretData("Missing key data".to_string()))?;

            let period = data
                .get("period")
                .and_then(|v| v.as_u64())
                .unwrap_or(self.config.period);

            let digits = data
                .get("digits")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .unwrap_or(self.config.digits);

            let issuer = data
                .get("issuer")
                .and_then(|v| v.as_str())
                .unwrap_or(&self.config.issuer)
                .to_string();

            let account_name = data
                .get("account_name")
                .and_then(|v| v.as_str())
                .unwrap_or(key_name)
                .to_string();

            // Validate parameters
            if !(10..=120).contains(&period) {
                return Err(SecretError::InvalidSecretData(
                    "Period must be between 10 and 120 seconds".to_string(),
                ));
            }

            if digits != 6 && digits != 8 {
                return Err(SecretError::InvalidSecretData(
                    "Digits must be 6 or 8".to_string(),
                ));
            }

            let totp_key = TotpKey {
                key: key_val.to_string(),
                period,
                digits,
                issuer,
                account_name,
            };

            let mut keys = self.keys.write().await;
            keys.insert(key_name.to_string(), totp_key);

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data: HashMap::new(), // Don't return sensitive key data
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: None,
                    lease_duration: None,
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(secret)
        } else {
            Err(SecretError::InvalidSecretData(
                "Invalid TOTP path".to_string(),
            ))
        }
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("totp".to_string()));
        }

        if let Some(key_name) = path.strip_prefix("keys/") {
            let mut keys = self.keys.write().await;
            keys.remove(key_name);
            Ok(())
        } else {
            Err(SecretError::InvalidSecretData(
                "Invalid TOTP path".to_string(),
            ))
        }
    }

    async fn list(&self, path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("totp".to_string()));
        }

        if path == "keys" || path == "keys/" {
            let keys = self.keys.read().await;
            Ok(keys.keys().cloned().collect())
        } else {
            Ok(vec![])
        }
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
