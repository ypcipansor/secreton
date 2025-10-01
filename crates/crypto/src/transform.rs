//! Transform Engine - Data Transformation & Tokenization
//!
//! This module provides data transformation capabilities including:
//! - Format-preserving encryption (FPE)
//! - Data tokenization for PCI-DSS compliance
//! - Data masking and anonymization
//! - Credit card number tokenization
//! - SSN/PII data transformation

use crate::error::{CryptoResult, CryptoError};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Transform operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransformType {
    /// Format-preserving encryption
    Fpe,
    /// Data tokenization
    Tokenization,
    /// Data masking
    Masking,
    /// Credit card tokenization
    CreditCardTokenization,
    /// SSN tokenization
    SsnTokenization,
}

/// Transform configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformConfig {
    /// Transform type
    pub transform_type: TransformType,
    /// Whether to allow reversible transformations
    pub reversible: bool,
    /// Token format (for tokenization)
    pub token_format: Option<String>,
    /// Masking pattern (for masking)
    pub masking_pattern: Option<String>,
    /// Allowed characters for FPE
    pub allowed_chars: Option<String>,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            transform_type: TransformType::Tokenization,
            reversible: true,
            token_format: Some("TKN_XXXX".to_string()),
            masking_pattern: None,
            allowed_chars: None,
        }
    }
}

/// Token mapping for reversible tokenization
#[derive(Debug)]
struct TokenMapping {
    /// Original value to token mapping
    original_to_token: HashMap<String, String>,
    /// Token to original value mapping
    token_to_original: HashMap<String, String>,
}

/// Transform engine for data transformation operations
#[derive(Debug)]
pub struct TransformEngine {
    /// Token mappings for reversible operations
    token_mappings: Arc<RwLock<HashMap<String, TokenMapping>>>,
    /// Encryption key for FPE operations
    fpe_key: [u8; 32],
    /// Configuration
    config: HashMap<String, TransformConfig>,
}

impl TransformEngine {
    /// Create a new transform engine
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);

        Self {
            token_mappings: Arc::new(RwLock::new(HashMap::new())),
            fpe_key: key,
            config: HashMap::new(),
        }
    }

    /// Configure a transform rule
    pub async fn configure_transform(
        &mut self,
        name: String,
        config: TransformConfig,
    ) -> CryptoResult<()> {
        self.config.insert(name, config);
        Ok(())
    }

    /// Transform data according to configured rules
    pub async fn transform(
        &self,
        transform_name: &str,
        data: &str,
    ) -> CryptoResult<String> {
        let config = self
            .config
            .get(transform_name)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Transform '{}' not found", transform_name)))?;

        match &config.transform_type {
            TransformType::Fpe => self.format_preserving_encrypt(data, &config).await,
            TransformType::Tokenization => self.tokenize(data, transform_name, &config).await,
            TransformType::Masking => self.mask_data(data, &config).await,
            TransformType::CreditCardTokenization => self.tokenize_credit_card(data, transform_name).await,
            TransformType::SsnTokenization => self.tokenize_ssn(data, transform_name).await,
        }
    }

    /// Reverse transform data
    pub async fn reverse_transform(
        &self,
        transform_name: &str,
        transformed_data: &str,
    ) -> CryptoResult<String> {
        let config = self
            .config
            .get(transform_name)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Transform '{}' not found", transform_name)))?;

        if !config.reversible {
            return Err(CryptoError::InvalidParameter("Transform is not reversible".to_string()));
        }

        match &config.transform_type {
            TransformType::Fpe => self.format_preserving_decrypt(transformed_data, &config).await,
            TransformType::Tokenization => self.detokenize(transformed_data, transform_name).await,
            TransformType::Masking => Err(CryptoError::InvalidParameter("Masking is not reversible".to_string())),
            TransformType::CreditCardTokenization => self.detokenize(transformed_data, transform_name).await,
            TransformType::SsnTokenization => self.detokenize(transformed_data, transform_name).await,
        }
    }

    /// Format-preserving encryption using AES-CBC
    async fn format_preserving_encrypt(
        &self,
        data: &str,
        config: &TransformConfig,
    ) -> CryptoResult<String> {
        if data.is_empty() {
            return Ok(String::new());
        }

        let allowed_chars = config.allowed_chars.as_deref().unwrap_or("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let allowed_chars: Vec<char> = allowed_chars.chars().collect();

        if allowed_chars.is_empty() {
            return Err(CryptoError::InvalidParameter("No allowed characters specified for FPE".to_string()));
        }

        // Convert input to numerical representation
        let mut input_nums: Vec<usize> = Vec::new();
        for ch in data.chars() {
            if let Some(pos) = allowed_chars.iter().position(|&c| c == ch) {
                input_nums.push(pos);
            } else {
                return Err(CryptoError::InvalidParameter(format!("Character '{}' not in allowed character set", ch)));
            }
        }

        // Pad to block size (16 bytes)
        let block_size = 16;
        let mut padded_input = input_nums.clone();
        while padded_input.len() % block_size != 0 {
            padded_input.push(0);
        }

        // Encrypt using AES-CBC
        type Aes256CbcEnc = Encryptor<Aes256>;
        let iv = [0u8; 16]; // In production, use random IV
        let mut buffer = [0u8; 16];

        let mut result = Vec::new();
        for chunk in padded_input.chunks(block_size) {
            // Convert chunk to bytes
            for (i, &num) in chunk.iter().enumerate() {
                buffer[i] = (num % 256) as u8;
            }

            let ciphertext = Aes256CbcEnc::new(&self.fpe_key.into(), &iv.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, block_size);

            // Convert back to allowed character set
            for &byte in &ciphertext[..chunk.len()] {
                let num = byte as usize % allowed_chars.len();
                if let Some(ch) = allowed_chars.get(num) {
                    result.push(*ch);
                }
            }
        }

        Ok(result.iter().collect())
    }

    /// Format-preserving decryption
    async fn format_preserving_decrypt(
        &self,
        data: &str,
        config: &TransformConfig,
    ) -> CryptoResult<String> {
        if data.is_empty() {
            return Ok(String::new());
        }

        let allowed_chars = config.allowed_chars.as_deref().unwrap_or("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let allowed_chars: Vec<char> = allowed_chars.chars().collect();

        // Convert input to numerical representation
        let mut input_nums: Vec<usize> = Vec::new();
        for ch in data.chars() {
            if let Some(pos) = allowed_chars.iter().position(|&c| c == ch) {
                input_nums.push(pos);
            } else {
                return Err(CryptoError::InvalidParameter(format!("Character '{}' not in allowed character set", ch)));
            }
        }

        // Pad to block size
        let block_size = 16;
        let mut padded_input = input_nums.clone();
        while padded_input.len() % block_size != 0 {
            padded_input.push(0);
        }

        // Decrypt using AES-CBC
        type Aes256CbcDec = Decryptor<Aes256>;
        let iv = [0u8; 16];
        let mut buffer = [0u8; 16];

        let mut result = Vec::new();
        for chunk in padded_input.chunks(block_size) {
            for (i, &num) in chunk.iter().enumerate() {
                buffer[i] = (num % 256) as u8;
            }

            let mut decrypted = buffer;
            Aes256CbcDec::new(&self.fpe_key.into(), &iv.into())
                .decrypt_padded_mut::<Pkcs7>(&mut decrypted)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

            for &byte in &decrypted[..chunk.len()] {
                let num = byte as usize % allowed_chars.len();
                if let Some(ch) = allowed_chars.get(num) {
                    result.push(*ch);
                }
            }
        }

        Ok(result.iter().collect())
    }

    /// Tokenize data
    async fn tokenize(
        &self,
        data: &str,
        transform_name: &str,
        config: &TransformConfig,
    ) -> CryptoResult<String> {
        let mut mappings = self.token_mappings.write().await;

        let mapping = mappings
            .entry(transform_name.to_string())
            .or_insert_with(|| TokenMapping {
                original_to_token: HashMap::new(),
                token_to_original: HashMap::new(),
            });

        // Check if already tokenized
        if let Some(token) = mapping.original_to_token.get(data) {
            return Ok(token.clone());
        }

        // Generate new token
        let token_format = config.token_format.as_deref().unwrap_or("TKN_XXXX");
        let token = if token_format.contains("XXXX") {
            let random_part: String = (0..4)
                .map(|_| {
                    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    chars.chars().nth(rand::random::<usize>() % chars.len()).unwrap()
                })
                .collect();
            token_format.replace("XXXX", &random_part)
        } else {
            format!("{}_{}", token_format, Uuid::new_v4().simple())
        };

        // Store mappings
        mapping.original_to_token.insert(data.to_string(), token.clone());
        mapping.token_to_original.insert(token.clone(), data.to_string());

        Ok(token)
    }

    /// Detokenize data
    async fn detokenize(&self, token: &str, transform_name: &str) -> CryptoResult<String> {
        let mappings = self.token_mappings.read().await;

        let mapping = mappings
            .get(transform_name)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("No mappings found for transform '{}'", transform_name)))?;

        mapping
            .token_to_original
            .get(token)
            .cloned()
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Token '{}' not found", token)))
    }

    /// Mask data according to pattern
    async fn mask_data(&self, data: &str, config: &TransformConfig) -> CryptoResult<String> {
        let pattern = config.masking_pattern.as_deref().unwrap_or("*");

        if pattern == "*" {
            // Simple masking - show only last 4 characters
            if data.len() <= 4 {
                Ok("*".repeat(data.len()))
            } else {
                Ok("*".repeat(data.len() - 4) + &data[data.len() - 4..])
            }
        } else if pattern.contains('#') {
            // Custom pattern with # representing visible characters
            let visible_count = pattern.chars().filter(|&c| c == '#').count();
            if data.len() < visible_count {
                return Err(CryptoError::InvalidParameter("Data too short for masking pattern".to_string()));
            }

            let mut result = String::new();
            let mut data_chars = data.chars();
            let mut pattern_chars = pattern.chars();

            while let (Some(data_ch), Some(pattern_ch)) = (data_chars.next(), pattern_chars.next()) {
                if pattern_ch == '#' {
                    result.push(data_ch);
                } else {
                    result.push(pattern_ch);
                }
            }

            Ok(result)
        } else {
            Ok(pattern.repeat(data.len()))
        }
    }

    /// Tokenize credit card numbers
    async fn tokenize_credit_card(&self, data: &str, transform_name: &str) -> CryptoResult<String> {
        // Basic credit card validation (should be more comprehensive in production)
        if data.len() != 16 && data.len() != 19 {
            return Err(CryptoError::InvalidParameter("Invalid credit card number length".to_string()));
        }

        let mut config = TransformConfig::default();
        config.transform_type = TransformType::CreditCardTokenization;
        config.token_format = Some("CC_TKN_XXXX".to_string());

        self.tokenize(data, transform_name, &config).await
    }

    /// Tokenize SSN numbers
    async fn tokenize_ssn(&self, data: &str, transform_name: &str) -> CryptoResult<String> {
        // Basic SSN validation (XXX-XX-XXXX format)
        if !regex::Regex::new(r"^\d{3}-\d{2}-\d{4}$").unwrap().is_match(data) {
            return Err(CryptoError::InvalidParameter("Invalid SSN format (use XXX-XX-XXXX)".to_string()));
        }

        let mut config = TransformConfig::default();
        config.transform_type = TransformType::SsnTokenization;
        config.token_format = Some("SSN_TKN_XXXX".to_string());

        self.tokenize(data, transform_name, &config).await
    }

    /// Get transform configuration
    pub fn get_transform_config(&self, name: &str) -> Option<&TransformConfig> {
        self.config.get(name)
    }

    /// List all transform configurations
    pub fn list_transforms(&self) -> Vec<String> {
        self.config.keys().cloned().collect()
    }
}

impl Default for TransformEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Transform request for API
#[derive(Debug, Deserialize)]
pub struct TransformRequest {
    pub data: String,
    pub transform_name: String,
}

/// Transform response for API
#[derive(Debug, Serialize)]
pub struct TransformResponse {
    pub transformed_data: String,
}

/// Reverse transform request for API
#[derive(Debug, Deserialize)]
pub struct ReverseTransformRequest {
    pub transformed_data: String,
    pub transform_name: String,
}

/// Reverse transform response for API
#[derive(Debug, Serialize)]
pub struct ReverseTransformResponse {
    pub original_data: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_format_preserving_encryption() {
        let mut engine = TransformEngine::new();
        let mut config = TransformConfig::default();
        config.transform_type = TransformType::Fpe;
        config.allowed_chars = Some("0123456789".to_string());

        engine.configure_transform("test_fpe".to_string(), config).await.unwrap();

        let original = "12345";
        let encrypted = engine.transform("test_fpe", original).await.unwrap();
        let decrypted = engine.reverse_transform("test_fpe", &encrypted).await.unwrap();

        assert_eq!(original, decrypted);
        assert_ne!(original, encrypted);
    }

    #[tokio::test]
    async fn test_tokenization() {
        let mut engine = TransformEngine::new();
        let config = TransformConfig::default();

        engine.configure_transform("test_token".to_string(), config).await.unwrap();

        let original = "sensitive_data_123";
        let token1 = engine.transform("test_token", original).await.unwrap();
        let token2 = engine.transform("test_token", original).await.unwrap();

        // Should return same token for same input
        assert_eq!(token1, token2);

        let recovered = engine.reverse_transform("test_token", &token1).await.unwrap();
        assert_eq!(original, recovered);
    }

    #[tokio::test]
    async fn test_data_masking() {
        let mut engine = TransformEngine::new();
        let mut config = TransformConfig::default();
        config.transform_type = TransformType::Masking;
        config.masking_pattern = Some("###-##-####".to_string());

        engine.configure_transform("test_mask".to_string(), config).await.unwrap();

        let original = "123456789";
        let masked = engine.transform("test_mask", original).await.unwrap();

        assert_eq!(masked, "123-45-6789");
    }

    #[tokio::test]
    async fn test_credit_card_tokenization() {
        let mut engine = TransformEngine::new();

        let cc_number = "4532015112830366"; // Valid test card number
        let token = engine.transform("cc_test", cc_number).await.unwrap();

        assert!(token.starts_with("CC_TKN_"));
        assert_ne!(token, cc_number);
    }
}
