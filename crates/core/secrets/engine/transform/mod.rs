//! Transform Secrets Engine - Data transformation & tokenization
//!
//! This engine provides data transformation services including:
//! - Format-preserving encryption (FPE)
//! - Tokenization for PCI-DSS compliance
//! - Data masking and anonymization

use crate::secrets::engine::{
    BoxedSecretsEngine, Secret, SecretMetadata, SecretsEngine, SecretsError,
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::fmt;
use tokio::sync::RwLock;
use uuid::Uuid;
use rand::RngCore;

/// Transform engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformConfig {
    pub max_token_length: usize,
    pub token_ttl_seconds: u64,
    pub allow_plaintext_backup: bool,
    pub convergent_encryption: bool,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            max_token_length: 1024,
            token_ttl_seconds: 3600, // 1 hour default
            allow_plaintext_backup: false,
            convergent_encryption: false,
        }
    }
}

/// Transform rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRule {
    pub name: String,
    pub transform_type: TransformType,
    pub alphabet: Option<String>,
    pub template: Option<String>,
    pub preserve_length: bool,
    pub tweak_source: Option<String>,
    pub key_derivation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransformType {
    /// Format-preserving encryption
    Fpe,
    /// Tokenization
    Tokenization,
    /// Data masking
    Masking,
    /// Format-preserving tokenization
    Fpt,
}

/// Transform request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRequest {
    pub value: String,
    pub transform_type: TransformType,
    pub rule_name: String,
    pub tweak: Option<String>,
    pub context: Option<String>,
}

/// Transform response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformResponse {
    pub transformed_value: String,
    pub rule_name: String,
    pub metadata: HashMap<String, String>,
}

/// Tokenization response (extends TransformResponse)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizeResponse {
    pub token: String,
    pub rule_name: String,
    pub expires_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

/// Detokenization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetokenizeRequest {
    pub token: String,
    pub rule_name: String,
    pub context: Option<String>,
}

/// Stored transformation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationData {
    pub original_value: String,
    pub transformed_value: String,
    pub rule_name: String,
    pub transform_type: TransformType,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub metadata: HashMap<String, String>,
}

/// Main Transform Secrets Engine
pub struct TransformSecretsEngine {
    storage: Arc<dyn crate::storage::StorageEngine>,
    transformations: Arc<RwLock<HashMap<String, TransformationData>>>,
    rules: Arc<RwLock<HashMap<String, TransformRule>>>,
    master_key: Vec<u8>,
}

impl TransformSecretsEngine {
    pub fn new(storage: Arc<dyn crate::storage::StorageEngine>) -> Self {
        let mut master_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut master_key);

        Self {
            storage,
            transformations: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(HashMap::new())),
            master_key,
        }
    }

    /// Generate a deterministic key for convergent encryption
    fn derive_key(&self, context: &[u8]) -> Vec<u8> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, &self.master_key);
        let mut derived_key = [0u8; 32];
        hkdf.expand(context, &mut derived_key).expect("HKDF expansion failed");
        derived_key.to_vec()
    }

    /// Generate a tweak for FPE
    fn generate_tweak(&self, input: &str, tweak_source: Option<&str>) -> Vec<u8> {
        match tweak_source {
            Some(source) => source.as_bytes().to_vec(),
            None => {
                // Generate deterministic tweak from input
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(input.as_bytes());
                hasher.finalize()[..16].to_vec()
            }
        }
    }

    /// Simple format-preserving encryption (simplified implementation)
    fn fpe_encrypt(&self, plaintext: &str, key: &[u8], tweak: &[u8]) -> Result<String, SecretsError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid key: {:?}", e)))?;

        let nonce_bytes = &tweak[..12.min(tweak.len())];
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes[..12]);

        let nonce = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| SecretsError::InvalidData(format!("FPE encryption failed: {:?}", e)))?;

        Ok(general_purpose::STANDARD.encode(&ciphertext))
    }

    /// Simple format-preserving decryption (simplified implementation)
    fn fpe_decrypt(&self, ciphertext: &str, key: &[u8], tweak: &[u8]) -> Result<String, SecretsError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid key: {:?}", e)))?;

        let ciphertext_bytes = general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid ciphertext: {}", e)))?;

        let nonce_bytes = &tweak[..12.min(tweak.len())];
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes[..12]);

        let nonce = Nonce::from_slice(&nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|e| SecretsError::InvalidData(format!("FPE decryption failed: {:?}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid UTF-8: {}", e)))
    }

    /// Generate a token from original value
    fn generate_token(&self, original: &str, rule_name: &str) -> String {
        use sha2::{Digest, Sha256};
        use base64::{engine::general_purpose, Engine as _};

        let mut hasher = Sha256::new();
        hasher.update(original.as_bytes());
        hasher.update(rule_name.as_bytes());
        hasher.update(&self.master_key);

        let hash = hasher.finalize();
        general_purpose::STANDARD.encode(&hash)[..16].to_string()
    }

    /// Create a transformation rule
    pub async fn create_rule(&self, rule: TransformRule) -> Result<(), SecretsError> {
        let mut rules = self.rules.write().await;

        if rules.contains_key(&rule.name) {
            return Err(SecretsError::InvalidData(format!(
                "Rule '{}' already exists",
                rule.name
            )));
        }

        rules.insert(rule.name.clone(), rule);
        Ok(())
    }

    /// Transform data according to rule
    pub async fn transform(&self, req: TransformRequest) -> Result<TransformResponse, SecretsError> {
        let rules = self.rules.read().await;
        let rule = rules
            .get(&req.rule_name)
            .ok_or_else(|| SecretsError::NotFound(format!("Rule '{}' not found", req.rule_name)))?
            .clone();

        let transformed_value = match rule.transform_type {
            TransformType::Fpe => {
                let tweak = self.generate_tweak(&req.value, rule.tweak_source.as_deref());
                let key = if req.context.is_some() {
                    self.derive_key(req.context.unwrap().as_bytes())
                } else {
                    self.master_key.clone()
                };
                self.fpe_encrypt(&req.value, &key, &tweak)?
            }
            TransformType::Tokenization => {
                let token = self.generate_token(&req.value, &req.rule_name);
                // Store the mapping for later retrieval
                let mut transformations = self.transformations.write().await;
                transformations.insert(
                    token.clone(),
                    TransformationData {
                        original_value: req.value.clone(),
                        transformed_value: token.clone(),
                        rule_name: req.rule_name.clone(),
                        transform_type: TransformType::Tokenization,
                        created_at: Utc::now().timestamp(),
                        expires_at: None,
                        metadata: HashMap::new(),
                    },
                );
                token
            }
            TransformType::Masking => {
                self.mask_data(&req.value, rule.alphabet.as_deref(), rule.template.as_deref())?
            }
            TransformType::Fpt => {
                // Format-preserving tokenization
                let token = self.generate_token(&req.value, &req.rule_name);
                if rule.preserve_length {
                    // Truncate or pad to preserve length
                    if token.len() > req.value.len() {
                        token[..req.value.len()].to_string()
                    } else {
                        format!("{:width$}", token, width = req.value.len())
                    }
                } else {
                    token
                }
            }
        };

        let mut metadata = HashMap::new();
        metadata.insert("transform_type".to_string(), format!("{:?}", rule.transform_type));
        metadata.insert("rule_name".to_string(), req.rule_name.clone());

        Ok(TransformResponse {
            transformed_value,
            rule_name: req.rule_name,
            metadata,
        })
    }

    /// Detokenize data
    pub async fn detokenize(&self, req: DetokenizeRequest) -> Result<String, SecretsError> {
        let transformations = self.transformations.read().await;
        let transformation = transformations
            .get(&req.token)
            .ok_or_else(|| SecretsError::NotFound(format!("Token '{}' not found", req.token)))?;

        if transformation.rule_name != req.rule_name {
            return Err(SecretsError::PermissionDenied(
                "Token does not match rule".to_string(),
            ));
        }

        Ok(transformation.original_value.clone())
    }

    /// Mask data according to pattern
    fn mask_data(&self, data: &str, alphabet: Option<&str>, template: Option<&str>) -> Result<String, SecretsError> {
        let template = template.unwrap_or("*");

        if template == "*" {
            // Simple masking - replace all characters
            return Ok("*".repeat(data.len()));
        }

        if template.len() != data.len() {
            return Err(SecretsError::InvalidData(
                "Template length must match data length".to_string(),
            ));
        }

        let alphabet = alphabet.unwrap_or("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
        let mut result = String::with_capacity(data.len());

        for (i, ch) in data.chars().enumerate() {
            if template.chars().nth(i).unwrap_or(' ') == '*' {
                // Replace with random character from alphabet
                let random_char = alphabet
                    .chars()
                    .nth((ch as u32 % alphabet.len() as u32) as usize)
                    .unwrap_or('*');
                result.push(random_char);
            } else {
                result.push(ch);
            }
        }

        Ok(result)
    }
}

#[async_trait]
impl SecretsEngine for TransformSecretsEngine {
    fn engine_type(&self) -> &'static str {
        "transform"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        match path {
            "rules" => {
                if let Some(rule_name) = data.get("name").and_then(|v| v.as_str()) {
                    let transform_type = match data.get("type").and_then(|v| v.as_str()).unwrap_or("fpe") {
                        "fpe" => TransformType::Fpe,
                        "tokenization" => TransformType::Tokenization,
                        "masking" => TransformType::Masking,
                        "fpt" => TransformType::Fpt,
                        _ => return Err(SecretsError::InvalidData("Invalid transform type".to_string())),
                    };

                    let rule = TransformRule {
                        name: rule_name.to_string(),
                        transform_type,
                        alphabet: data.get("alphabet").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        template: data.get("template").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        preserve_length: data.get("preserve_length").and_then(|v| v.as_bool()).unwrap_or(false),
                        tweak_source: data.get("tweak_source").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        key_derivation: data.get("key_derivation").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    };

                    self.create_rule(rule).await?;
                    let now = Utc::now();
                    Ok(Secret {
                        id: Uuid::new_v4(),
                        path: path.to_string(),
                        data: serde_json::json!({"name": rule_name, "created": true}),
                        metadata: SecretMetadata {
                            created_at: now,
                            updated_at: now,
                            version: 1,
                            ttl: None,
                            expired_at: None,
                            custom_metadata: None,
                        },
                    })
                } else {
                    Err(SecretsError::InvalidData("Rule name required".to_string()))
                }
            }
            _ => Err(SecretsError::InvalidData(
                "Unsupported path for create".to_string(),
            )),
        }
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        if let Some(rule_name) = path.strip_prefix("rules/") {
            let rules = self.rules.read().await;
            let rule = rules
                .get(rule_name)
                .ok_or_else(|| SecretsError::NotFound(format!("Rule '{}' not found", rule_name)))?;

            let now = Utc::now();
            Ok(Secret {
                id: Uuid::new_v4(),
                path: path.to_string(),
                data: serde_json::to_value(rule).unwrap(),
                metadata: SecretMetadata {
                    created_at: now,
                    updated_at: now,
                    version: 1,
                    ttl: None,
                    expired_at: None,
                    custom_metadata: None,
                },
            })
        } else {
            Err(SecretsError::NotFound(format!("Rule not found: {}", path)))
        }
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        if let Some(rule_name) = path.strip_prefix("rules/") {
            let mut rules = self.rules.write().await;
            rules.remove(rule_name);
        }
        Ok(())
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError> {
        match path {
            "rules" => {
                let rules = self.rules.read().await;
                Ok(rules.keys().cloned().collect())
            }
            _ => Ok(vec![]),
        }
    }

    async fn collect_metrics(&self) -> Result<super::EngineMetrics, super::SecretsError> {
        Ok(super::EngineMetrics {
            engine_type: self.engine_type().to_string(),
            secrets_created: 0,
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets: 0,
            storage_size_bytes: 0,
        })
    }
}

/// Create a new Transform secrets engine
pub fn new_transform_engine(storage: Arc<dyn crate::storage::StorageEngine>) -> BoxedSecretsEngine {
    Box::new(TransformSecretsEngine::new(storage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_storage;

    async fn setup_engine() -> TransformSecretsEngine {
        let storage = create_test_storage().await;
        TransformSecretsEngine::new(storage)
    }

    #[tokio::test]
    async fn test_create_rule() {
        let engine = setup_engine().await;

        let rule = TransformRule {
            name: "test-rule".to_string(),
            transform_type: TransformType::Masking,
            alphabet: Some("0123456789".to_string()),
            template: Some("****-****".to_string()),
            preserve_length: true,
            tweak_source: None,
            key_derivation: None,
        };

        let result = engine.create_rule(rule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fpe_transform() {
        let engine = setup_engine().await;

        // Create FPE rule
        let rule = TransformRule {
            name: "fpe-rule".to_string(),
            transform_type: TransformType::Fpe,
            alphabet: None,
            template: None,
            preserve_length: true,
            tweak_source: Some("test-tweak".to_string()),
            key_derivation: None,
        };
        engine.create_rule(rule).await.unwrap();

        // Transform data
        let req = TransformRequest {
            value: "1234567890".to_string(),
            transform_type: TransformType::Fpe,
            rule_name: "fpe-rule".to_string(),
            tweak: None,
            context: Some("test-context".to_string()),
        };

        let result = engine.transform(req).await;
        assert!(result.is_ok());
        let response = result.unwrap();

        // Should produce a different value
        assert_ne!(response.transformed_value, "1234567890");
        assert_eq!(response.rule_name, "fpe-rule");
    }

    #[tokio::test]
    async fn test_tokenization() {
        let engine = setup_engine().await;

        // Create tokenization rule
        let rule = TransformRule {
            name: "token-rule".to_string(),
            transform_type: TransformType::Tokenization,
            alphabet: None,
            template: None,
            preserve_length: false,
            tweak_source: None,
            key_derivation: None,
        };
        engine.create_rule(rule).await.unwrap();

        // Tokenize data
        let req = TransformRequest {
            value: "sensitive-data-123".to_string(),
            transform_type: TransformType::Tokenization,
            rule_name: "token-rule".to_string(),
            tweak: None,
            context: None,
        };

        let result = engine.transform(req).await;
        assert!(result.is_ok());
        let response = result.unwrap();

        // Should produce a token
        assert!(!response.transformed_value.is_empty());

        // Detokenize
        let detok_req = DetokenizeRequest {
            token: response.transformed_value,
            rule_name: "token-rule".to_string(),
            context: None,
        };

        let detok_result = engine.detokenize(detok_req).await;
        assert!(detok_result.is_ok());
        assert_eq!(detok_result.unwrap(), "sensitive-data-123");
    }

    #[tokio::test]
    async fn test_data_masking() {
        let engine = setup_engine().await;

        // Create masking rule
        let rule = TransformRule {
            name: "mask-rule".to_string(),
            transform_type: TransformType::Masking,
            alphabet: Some("X".to_string()),
            template: Some("****-****".to_string()),
            preserve_length: true,
            tweak_source: None,
            key_derivation: None,
        };
        engine.create_rule(rule).await.unwrap();

        // Mask data
        let req = TransformRequest {
            value: "1234-5678".to_string(),
            transform_type: TransformType::Masking,
            rule_name: "mask-rule".to_string(),
            tweak: None,
            context: None,
        };

        let result = engine.transform(req).await;
        assert!(result.is_ok());
        let response = result.unwrap();

        // Should be masked according to template
        assert_eq!(response.transformed_value.len(), 9); // "****-****".len()
    }

    #[tokio::test]
    async fn test_rule_not_found() {
        let engine = setup_engine().await;

        let req = TransformRequest {
            value: "test-data".to_string(),
            transform_type: TransformType::Fpe,
            rule_name: "nonexistent-rule".to_string(),
            tweak: None,
            context: None,
        };

        let result = engine.transform(req).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SecretsError::NotFound(_)));
    }
}
