//! Transform Secrets Engine
//!
//! Format-preserving encryption, tokenization, and masking for PCI/compliance
//! requirements. Protects sensitive _data while maintaining format.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Transform engine errors
#[derive(Error, Debug)]
pub enum TransformError {
    #[error("Transformation not found: {0}")]
    TransformationNotFound(String),

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Invalid alphabet")]
    InvalidAlphabet,

    #[error("Encode failed: {0}")]
    EncodeFailed(String),

    #[error("Decode failed: {0}")]
    DecodeFailed(String),

    #[error("Invalid template")]
    InvalidTemplate,
}

/// Transformation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransformationType {
    /// Format-preserving encryption (maintains format/length)
    FPE,

    /// Tokenization (replace with token, reversible)
    Tokenization,

    /// Masking (irreversible obfuscation)
    Masking,
}

/// Alphabet for FPE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Alphabet {
    /// Numeric (0-9)
    Numeric,

    /// Alphanumeric lowercase (a-z, 0-9)
    Alphanumeric,

    /// Custom alphabet
    Custom(String),
}

impl Alphabet {
    /// Get alphabet characters
    fn chars(&self) -> Vec<char> {
        match self {
            Alphabet::Numeric => "0123456789".chars().collect(),
            Alphabet::Alphanumeric => "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect(),
            Alphabet::Custom(s) => s.chars().collect(),
        }
    }
}

/// Transformation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transformation {
    /// Name
    pub _name: String,

    /// Type
    pub transformation_type: TransformationType,

    /// Template (_e.g., "####-####-####-####" for credit card)
    pub template: Option<String>,

    /// Alphabet (for FPE)
    pub alphabet: Option<Alphabet>,

    /// Tweak (additional input for FPE)
    pub tweak: Option<String>,

    /// Masking character
    pub masking_char: Option<char>,

    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Transformation {
    /// Create new transformation
    pub fn new(_name: String, transformation_type: TransformationType) -> Self {
        Self {
            _name,
            transformation_type,
            template: None,
            alphabet: Some(Alphabet::Alphanumeric),
            tweak: None,
            masking_char: Some('*'),
            created_at: Utc::now(),
        }
    }
}

/// Transform role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRole {
    /// Role _name
    pub _name: String,

    /// Transformations this role can use
    pub transformations: Vec<String>,

    /// Created at
    pub created_at: DateTime<Utc>,
}

impl TransformRole {
    /// Create new role
    pub fn new(_name: String, transformations: Vec<String>) -> Self {
        Self {
            _name,
            transformations,
            created_at: Utc::now(),
        }
    }
}

/// Token mapping (for tokenization)
#[derive(Debug, Clone)]
struct TokenMapping {
    plaintext: String,
    _token: String,
    _created_at: DateTime<Utc>,
}

/// Transform secrets engine
pub struct TransformEngine {
    transformations: Arc<RwLock<HashMap<String, Transformation>>>,
    roles: Arc<RwLock<HashMap<String, TransformRole>>>,
    token_mappings: Arc<RwLock<HashMap<String, TokenMapping>>>, // token -> mapping
    reverse_mappings: Arc<RwLock<HashMap<String, String>>>,     // plaintext -> token
}

impl TransformEngine {
    /// Create new transform engine
    pub fn new() -> Self {
        Self {
            transformations: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            token_mappings: Arc::new(RwLock::new(HashMap::new())),
            reverse_mappings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create transformation
    pub async fn create_transformation(
        &self,
        transformation: Transformation,
    ) -> Result<(), TransformError> {
        let mut transformations = self.transformations.write().await;
        transformations.insert(transformation._name.clone(), transformation);
        Ok(())
    }

    /// Get transformation
    pub async fn get_transformation(&self, _name: &str) -> Option<Transformation> {
        let transformations = self.transformations.read().await;
        transformations.get(_name).cloned()
    }

    /// Encode value
    pub async fn encode(
        &self,
        role_name: &str,
        transformation_name: &str,
        value: &str,
    ) -> Result<String, TransformError> {
        // Validate role has access
        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| TransformError::RoleNotFound(role_name.to_string()))?;

        if !role
            .transformations
            .contains(&transformation_name.to_string())
        {
            return Err(TransformError::TransformationNotFound(
                transformation_name.to_string(),
            ));
        }
        drop(roles);

        // Get transformation
        let transformations = self.transformations.read().await;
        let transformation = transformations
            .get(transformation_name)
            .ok_or_else(|| TransformError::TransformationNotFound(transformation_name.to_string()))?
            .clone();
        drop(transformations);

        // Perform transformation
        match transformation.transformation_type {
            TransformationType::FPE => self.encode_fpe(&transformation, value).await,
            TransformationType::Tokenization => {
                self.encode_tokenization(&transformation, value).await
            }
            TransformationType::Masking => self.encode_masking(&transformation, value).await,
        }
    }

    /// Decode value
    pub async fn decode(
        &self,
        role_name: &str,
        transformation_name: &str,
        value: &str,
    ) -> Result<String, TransformError> {
        // Validate role
        let roles = self.roles.read().await;
        let role = roles
            .get(role_name)
            .ok_or_else(|| TransformError::RoleNotFound(role_name.to_string()))?;

        if !role
            .transformations
            .contains(&transformation_name.to_string())
        {
            return Err(TransformError::TransformationNotFound(
                transformation_name.to_string(),
            ));
        }
        drop(roles);

        // Get transformation
        let transformations = self.transformations.read().await;
        let transformation = transformations
            .get(transformation_name)
            .ok_or_else(|| TransformError::TransformationNotFound(transformation_name.to_string()))?
            .clone();
        drop(transformations);

        // Perform reverse transformation
        match transformation.transformation_type {
            TransformationType::FPE => self.decode_fpe(&transformation, value).await,
            TransformationType::Tokenization => self.decode_tokenization(value).await,
            TransformationType::Masking => Err(TransformError::DecodeFailed(
                "Masking is irreversible".to_string(),
            )),
        }
    }

    /// Format-preserving encryption (simplified)
    async fn encode_fpe(
        &self,
        transformation: &Transformation,
        value: &str,
    ) -> Result<String, TransformError> {
        let alphabet = transformation
            .alphabet
            .as_ref()
            .ok_or(TransformError::InvalidAlphabet)?;

        let chars = alphabet.chars();
        let radix = chars.len();

        // Simplified FPE: shift each character by a fixed amount
        let shift = 7; // Use transformation _key in production

        let encoded: String = value
            .chars()
            .map(|c| {
                if let Some(pos) = chars.iter().position(|&ch| ch == c) {
                    let new_pos = (pos + shift) % radix;
                    chars[new_pos]
                } else {
                    c // Keep non-alphabet characters as-is
                }
            })
            .collect();

        Ok(encoded)
    }

    /// Decode FPE
    async fn decode_fpe(
        &self,
        transformation: &Transformation,
        value: &str,
    ) -> Result<String, TransformError> {
        let alphabet = transformation
            .alphabet
            .as_ref()
            .ok_or(TransformError::InvalidAlphabet)?;

        let chars = alphabet.chars();
        let radix = chars.len();
        let shift = 7;

        let decoded: String = value
            .chars()
            .map(|c| {
                if let Some(pos) = chars.iter().position(|&ch| ch == c) {
                    let new_pos = (pos + radix - shift) % radix;
                    chars[new_pos]
                } else {
                    c
                }
            })
            .collect();

        Ok(decoded)
    }

    /// Tokenization encoding
    async fn encode_tokenization(
        &self,
        _transformation: &Transformation,
        value: &str,
    ) -> Result<String, TransformError> {
        // Check if already tokenized
        let reverse = self.reverse_mappings.read().await;
        if let Some(existing_token) = reverse.get(value) {
            return Ok(existing_token.clone());
        }
        drop(reverse);

        // Generate new token
        let token = format!("tok_{}", Uuid::new_v4());

        // Store mapping
        let mapping = TokenMapping {
            plaintext: value.to_string(),
            _token: token.clone(),
            _created_at: Utc::now(),
        };

        let mut token_mappings = self.token_mappings.write().await;
        let mut reverse = self.reverse_mappings.write().await;

        token_mappings.insert(token.clone(), mapping);
        reverse.insert(value.to_string(), token.clone());

        Ok(token)
    }

    /// Tokenization decoding
    async fn decode_tokenization(&self, token: &str) -> Result<String, TransformError> {
        let mappings = self.token_mappings.read().await;

        let mapping = mappings
            .get(token)
            .ok_or_else(|| TransformError::DecodeFailed("Token not found".to_string()))?;

        Ok(mapping.plaintext.clone())
    }

    /// Masking encoding
    async fn encode_masking(
        &self,
        transformation: &Transformation,
        value: &str,
    ) -> Result<String, TransformError> {
        let mask_char = transformation.masking_char.unwrap_or('*');

        // Apply template if available
        if let Some(ref template) = transformation.template {
            self.apply_template(value, template, mask_char)
        } else {
            // Default: mask all but last 4 characters
            let len = value.len();
            if len <= 4 {
                Ok(mask_char.to_string().repeat(len))
            } else {
                let masked = mask_char.to_string().repeat(len - 4);
                let visible = &value[len - 4..];
                Ok(format!("{}{}", masked, visible))
            }
        }
    }

    /// Apply template (# = visible, * = masked)
    fn apply_template(
        &self,
        value: &str,
        template: &str,
        mask_char: char,
    ) -> Result<String, TransformError> {
        let value_chars: Vec<char> = value.chars().filter(|c| c.is_alphanumeric()).collect();
        let mut value_idx = 0;

        let result: String = template
            .chars()
            .map(|t| {
                match t {
                    '#' => {
                        if value_idx < value_chars.len() {
                            let c = value_chars[value_idx];
                            value_idx += 1;
                            c
                        } else {
                            mask_char
                        }
                    }
                    '*' => {
                        value_idx += 1;
                        mask_char
                    }
                    _ => t, // Keep separator characters
                }
            })
            .collect();

        Ok(result)
    }

    /// Create role
    pub async fn create_role(&self, role: TransformRole) -> Result<(), TransformError> {
        let mut roles = self.roles.write().await;
        roles.insert(role._name.clone(), role);
        Ok(())
    }

    /// Get role
    pub async fn get_role(&self, _name: &str) -> Option<TransformRole> {
        let roles = self.roles.read().await;
        roles.get(_name).cloned()
    }
}

impl Default for TransformEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fpe() {
        let engine = TransformEngine::new();

        let mut transformation =
            Transformation::new("ssn-fpe".to_string(), TransformationType::FPE);
        transformation.alphabet = Some(Alphabet::Numeric);

        engine.create_transformation(transformation).await.unwrap();

        let role = TransformRole::new("app".to_string(), vec!["ssn-fpe".to_string()]);
        engine.create_role(role).await.unwrap();

        let encoded = engine.encode("app", "ssn-fpe", "123456789").await.unwrap();
        assert_ne!(encoded, "123456789");
        assert_eq!(encoded.len(), 9); // Same length

        let decoded = engine.decode("app", "ssn-fpe", &encoded).await.unwrap();
        assert_eq!(decoded, "123456789");
    }

    #[tokio::test]
    async fn test_tokenization() {
        let engine = TransformEngine::new();

        let transformation =
            Transformation::new("cc-token".to_string(), TransformationType::Tokenization);
        engine.create_transformation(transformation).await.unwrap();

        let role = TransformRole::new("payment".to_string(), vec!["cc-token".to_string()]);
        engine.create_role(role).await.unwrap();

        let card_number = "4111111111111111";
        let token = engine
            .encode("payment", "cc-token", card_number)
            .await
            .unwrap();
        assert!(token.starts_with("tok_"));

        let decoded = engine.decode("payment", "cc-token", &token).await.unwrap();
        assert_eq!(decoded, card_number);

        // Same value should get same token
        let token2 = engine
            .encode("payment", "cc-token", card_number)
            .await
            .unwrap();
        assert_eq!(token, token2);
    }

    #[tokio::test]
    async fn test_masking() {
        let engine = TransformEngine::new();

        let mut transformation =
            Transformation::new("cc-mask".to_string(), TransformationType::Masking);
        transformation.template = Some("****-****-****-####".to_string());

        engine.create_transformation(transformation).await.unwrap();

        let role = TransformRole::new("display".to_string(), vec!["cc-mask".to_string()]);
        engine.create_role(role).await.unwrap();

        let masked = engine
            .encode("display", "cc-mask", "4111222233334444")
            .await
            .unwrap();
        assert_eq!(masked, "****-****-****-4444");

        // Masking is irreversible
        let result = engine.decode("display", "cc-mask", &masked).await;
        assert!(result.is_err());
    }
}
