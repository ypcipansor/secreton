use super::{Secret, SecretMetadata, SecretsEngine, SecretsError};
use async_trait::async_trait;
use base32::{decode, encode};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpKey {
    pub name: String,
    pub secret: String,    // Base32 encoded secret
    pub algorithm: String, // SHA1, SHA256, SHA512
    pub digits: u32,       // 6 or 8
    pub period: u64,       // Time step in seconds (usually 30)
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub usage_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTotpKeyRequest {
    pub name: String,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u64>,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub generate_secret: bool,
    pub secret: Option<String>, // If not generating, provide base32 secret
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateTotpRequest {
    pub name: String,
    pub code: String,
    pub window: Option<u32>, // Number of time steps to check (for clock drift)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpValidationResult {
    pub valid: bool,
    pub key_name: String,
    pub timestamp: i64,
    pub window_used: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpUrl {
    pub url: String,
    pub qr_code_data: String,
}

pub struct TotpSecretsEngine {
    storage: Arc<RwLock<dyn crate::storage::StorageEngine + Send + Sync>>,
}

impl TotpSecretsEngine {
    pub async fn new(
        storage: Arc<RwLock<dyn crate::storage::StorageEngine + Send + Sync>>,
    ) -> Result<Self, SecretsError> {
        Ok(Self { storage })
    }

    pub async fn create_key(&self, request: CreateTotpKeyRequest) -> Result<TotpKey, SecretsError> {
        // Validate algorithm
        let algorithm = request.algorithm.unwrap_or_else(|| "SHA1".to_string());
        if !["SHA1", "SHA256", "SHA512"].contains(&&*algorithm) {
            return Err(SecretsError::InvalidConfiguration(
                "Algorithm must be SHA1, SHA256, or SHA512".to_string(),
            ));
        }

        // Validate digits
        let digits = request.digits.unwrap_or(6);
        if digits != 6 && digits != 8 {
            return Err(SecretsError::InvalidConfiguration(
                "Digits must be 6 or 8".to_string(),
            ));
        }

        // Validate period
        let period = request.period.unwrap_or(30);
        if !(1..=300).contains(&period) {
            return Err(SecretsError::InvalidConfiguration(
                "Period must be between 1 and 300 seconds".to_string(),
            ));
        }

        // Generate or validate secret
        let secret = if request.generate_secret {
            self.generate_secret().await?
        } else {
            request.secret.ok_or_else(|| {
                SecretsError::InvalidConfiguration(
                    "Secret must be provided when generate_secret is false".to_string(),
                )
            })?
        };

        // Validate base32 secret
        if decode(base32::Alphabet::Rfc4648 { padding: false }, &secret).is_none() {
            return Err(SecretsError::InvalidConfiguration(
                "Secret must be valid base32".to_string(),
            ));
        }

        let key = TotpKey {
            name: request.name,
            secret,
            algorithm,
            digits,
            period,
            issuer: request.issuer,
            account_name: request.account_name,
            created_at: Utc::now().timestamp(),
            last_used: None,
            usage_count: 0,
        };

        // Store key
        let key_data = serde_json::to_vec(&key)
            .map_err(|e| SecretsError::SerializationError(e.to_string()))?;

        let storage_key = format!("totp/keys/{}", key.name);
        let entry = crate::storage::StorageEntry {
            key: storage_key,
            value: key_data,
            metadata: std::collections::HashMap::new(),
        };
        self.storage.write().await.put(entry).await?;

        Ok(key)
    }

    pub async fn get_key(&self, name: &str) -> Result<TotpKey, SecretsError> {
        let storage_key = format!("totp/keys/{}", name);
        let data = self
            .storage
            .read()
            .await
            .get(&storage_key)
            .await?
            .ok_or_else(|| SecretsError::NotFound(format!("TOTP key '{}' not found", name)))?;

        serde_json::from_slice(&data.value)
            .map_err(|e| SecretsError::SerializationError(e.to_string()))
    }

    pub async fn list_keys(&self) -> Result<Vec<String>, SecretsError> {
        let prefix = "totp/keys/";
        let keys = self.storage.read().await.list(prefix).await?;
        Ok(keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(prefix).map(|s| s.to_string()))
            .collect())
    }

    pub async fn delete_key(&self, name: &str) -> Result<(), SecretsError> {
        let storage_key = format!("totp/keys/{}", name);
        self.storage.write().await.delete(&storage_key).await?;
        Ok(())
    }

    pub async fn validate_code(
        &mut self,
        request: ValidateTotpRequest,
    ) -> Result<TotpValidationResult, SecretsError> {
        let mut key = self.get_key(&request.name).await?;
        let window = request.window.unwrap_or(1);

        // Get current timestamp
        let now = Utc::now().timestamp() as u64;

        // Check multiple time steps for clock drift tolerance
        for step_offset in -(window as i32)..=(window as i32) {
            let timestamp = if step_offset < 0 {
                now.saturating_sub(step_offset.unsigned_abs() as u64 * key.period)
            } else {
                now + (step_offset as u64 * key.period)
            };

            let expected_code = self.generate_totp(&key, timestamp).await?;

            if expected_code == request.code {
                // Update usage statistics
                key.last_used = Some(Utc::now().timestamp());
                key.usage_count += 1;

                // Store updated key
                let key_data = serde_json::to_vec(&key)
                    .map_err(|e| SecretsError::SerializationError(e.to_string()))?;
                let storage_key = format!("totp/keys/{}", key.name);
                let entry = crate::storage::StorageEntry {
                    key: storage_key,
                    value: key_data,
                    metadata: std::collections::HashMap::new(),
                };
                self.storage.write().await.put(entry).await?;

                return Ok(TotpValidationResult {
                    valid: true,
                    key_name: key.name,
                    timestamp: timestamp as i64,
                    window_used: Some(step_offset),
                });
            }
        }

        Ok(TotpValidationResult {
            valid: false,
            key_name: key.name,
            timestamp: now as i64,
            window_used: None,
        })
    }

    pub async fn generate_url(&self, key_name: &str) -> Result<TotpUrl, SecretsError> {
        let key = self.get_key(key_name).await?;

        let mut params = vec![
            format!("secret={}", key.secret),
            format!("digits={}", key.digits),
            format!("period={}", key.period),
        ];

        if key.algorithm != "SHA1" {
            params.push(format!("algorithm={}", key.algorithm));
        }

        if let Some(issuer) = &key.issuer {
            params.push(format!("issuer={}", urlencoding::encode(issuer)));
        }

        let account_name = key.account_name.as_deref().unwrap_or(&key.name);
        let label = if let Some(issuer) = &key.issuer {
            format!(
                "{}:{}",
                urlencoding::encode(issuer),
                urlencoding::encode(account_name)
            )
        } else {
            urlencoding::encode(account_name).to_string()
        };

        let url = format!("otpauth://totp/{}?{}", label, params.join("&"));
        let qr_code_data = self.generate_qr_code_data(&url).await?;

        Ok(TotpUrl { url, qr_code_data })
    }

    async fn generate_secret(&self) -> Result<String, SecretsError> {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32]; // 256 bits
        rng.fill_bytes(&mut secret_bytes);

        Ok(encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &secret_bytes,
        ))
    }

    async fn generate_totp(&self, key: &TotpKey, timestamp: u64) -> Result<String, SecretsError> {
        // Decode base32 secret
        let secret =
            decode(base32::Alphabet::Rfc4648 { padding: false }, &key.secret).ok_or_else(|| {
                SecretsError::InvalidConfiguration("Invalid base32 secret".to_string())
            })?;

        // Calculate time step
        let time_step = timestamp / key.period;

        // Convert time step to 8-byte big-endian
        let time_bytes = time_step.to_be_bytes();

        // Create HMAC
        let mac_bytes = match key.algorithm.as_str() {
            "SHA1" => {
                let mut hmac = HmacSha1::new_from_slice(&secret)
                    .map_err(|e| SecretsError::ExecutionError(e.to_string()))?;
                hmac.update(&time_bytes);
                hmac.finalize().into_bytes().to_vec()
            }
            "SHA256" => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(&secret)
                    .map_err(|e| SecretsError::ExecutionError(e.to_string()))?;
                hmac.update(&time_bytes);
                hmac.finalize().into_bytes().to_vec()
            }
            "SHA512" => {
                let mut hmac = Hmac::<Sha512>::new_from_slice(&secret)
                    .map_err(|e| SecretsError::ExecutionError(e.to_string()))?;
                hmac.update(&time_bytes);
                hmac.finalize().into_bytes().to_vec()
            }
            _ => {
                return Err(SecretsError::InvalidConfiguration(
                    "Unsupported algorithm".to_string(),
                ))
            }
        };

        // Dynamic truncation (RFC 4226)
        let offset = (mac_bytes[mac_bytes.len() - 1] & 0x0f) as usize;
        let code = ((mac_bytes[offset] & 0x7f) as u32) << 24
            | (mac_bytes[offset + 1] as u32) << 16
            | (mac_bytes[offset + 2] as u32) << 8
            | (mac_bytes[offset + 3] as u32);

        // Generate final code with specified digits
        let modulus = 10u32.pow(key.digits);
        let totp_code = code % modulus;

        Ok(format!(
            "{:0width$}",
            totp_code,
            width = key.digits as usize
        ))
    }

    async fn generate_qr_code_data(&self, url: &str) -> Result<String, SecretsError> {
        // For now, return the URL as QR code data
        // In a real implementation, you would generate actual QR code
        Ok(url.to_string())
    }
}

#[async_trait]
impl SecretsEngine for TotpSecretsEngine {
    fn engine_type(&self) -> &'static str {
        "totp"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // Parse TOTP key data from JSON
        let key_data: CreateTotpKeyRequest =
            serde_json::from_value(data).map_err(|e| SecretsError::InvalidData(e.to_string()))?;

        // Create the key using existing logic
        let totp_key = self
            .create_key(key_data)
            .await
            .map_err(|e| SecretsError::Other(e.into()))?;

        // Convert to Secret format
        let secret_data =
            serde_json::to_value(&totp_key).map_err(|e| SecretsError::Other(e.into()))?;

        Ok(Secret {
            id: Uuid::new_v4(),
            path: path.to_string(),
            data: secret_data,
            metadata: SecretMetadata {
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
                ttl: Some(24 * 60 * 60), // 24 hours in seconds
                expired_at: None,
                custom_metadata: None,
            },
        })
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        // Extract key name from path
        let key_name = path
            .strip_prefix("totp/")
            .ok_or_else(|| SecretsError::NotFound(format!("Invalid TOTP path: {}", path)))?;

        let totp_key = self
            .get_key(key_name)
            .await
            .map_err(|e| SecretsError::Other(e.into()))?;

        let secret_data =
            serde_json::to_value(&totp_key).map_err(|e| SecretsError::Other(e.into()))?;

        Ok(Secret {
            id: Uuid::new_v4(),
            path: path.to_string(),
            data: secret_data,
            metadata: SecretMetadata {
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
                ttl: Some(24 * 60 * 60), // 24 hours in seconds
                expired_at: None,
                custom_metadata: None,
            },
        })
    }

    async fn update_secret(
        &self,
        _path: &str,
        _data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // For TOTP, update is not directly supported
        // We could implement updating key parameters here
        Err(SecretsError::InvalidData(
            "TOTP key updates not supported".to_string(),
        ))
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        let key_name = path
            .strip_prefix("totp/")
            .ok_or_else(|| SecretsError::NotFound(format!("Invalid TOTP path: {}", path)))?;

        self.delete_key(key_name)
            .await
            .map_err(|e| SecretsError::Other(e.into()))
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError> {
        if path == "totp/" || path == "totp" {
            let keys = self
                .list_keys()
                .await
                .map_err(|e| SecretsError::Other(e.into()))?;
            Ok(keys.into_iter().map(|k| format!("totp/{}", k)).collect())
        } else {
            Ok(vec![])
        }
    }

    /// Collect metrics for this engine (optional)
    async fn collect_metrics(&self) -> Result<super::EngineMetrics, super::SecretsError> {
        Ok(super::EngineMetrics {
            engine_type: self.engine_type().to_string(),
            secrets_created: 0,        // Would be tracked by engine
            secrets_read: 0,           // Would be tracked by engine
            secrets_updated: 0,        // Would be tracked by engine
            secrets_deleted: 0,        // Would be tracked by engine
            avg_response_time_ms: 0.0, // Would be calculated from timing data
            error_count: 0,            // Would be tracked by engine
            active_secrets: 0,         // Would be calculated by engine
            storage_size_bytes: 0,     // Would be calculated by engine
        })
    }
}
