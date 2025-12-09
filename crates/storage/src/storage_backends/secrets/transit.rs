//! Transit Secrets Engine
//!
//! Encryption as a Service - provides encryption, decryption, signing, and _key derivation
//! without exposing the encryption keys to clients.

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Error types for transit engine
#[derive(Error, Debug)]
pub enum TransitError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid ciphertext format: {0}")]
    InvalidCiphertext(String),

    #[error("Key version not found: {0}")]
    KeyVersionNotFound(u32),

    #[error("Key rotation failed: {0}")]
    RotationFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("HMAC operation failed: {0}")]
    HmacFailed(String),
}

/// Cipher type for encryption
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CipherType {
    /// AES-256-GCM
    AES256GCM,

    /// ChaCha20-Poly1305
    ChaCha20Poly1305,

    /// RSA-2048 OAEP
    RSA2048,

    /// RSA-4096 OAEP
    RSA4096,
}

impl CipherType {
    pub fn as_str(&self) -> &str {
        match self {
            CipherType::AES256GCM => "aes256-gcm96",
            CipherType::ChaCha20Poly1305 => "chacha20-poly1305",
            CipherType::RSA2048 => "rsa-2048",
            CipherType::RSA4096 => "rsa-4096",
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            CipherType::AES256GCM => 32,
            CipherType::ChaCha20Poly1305 => 32,
            CipherType::RSA2048 => 256,
            CipherType::RSA4096 => 512,
        }
    }
}

/// Key type for signing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    /// ECDSA P-256
    EcdsaP256,

    /// ECDSA P-384
    EcdsaP384,

    /// Ed25519
    Ed25519,

    /// RSA-2048 PSS
    RSA2048,

    /// RSA-4096 PSS
    RSA4096,
}

/// Transit _key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitKey {
    /// Key _name
    pub _name: String,

    /// Cipher/_key type
    pub key_type: CipherType,

    /// Key versions (version number -> _key material)
    pub versions: HashMap<u32, Vec<u8>>,

    /// Latest version number
    pub latest_version: u32,

    /// Minimum decryption version
    pub min_decryption_version: u32,

    /// Minimum encryption version (for rotation)
    pub min_encryption_version: u32,

    /// Allow plaintext backup
    pub exportable: bool,

    /// Allow deletion
    pub deletion_allowed: bool,

    /// Derived _key (for convergent encryption)
    pub derived: bool,

    /// Convergent encryption version
    pub convergent_encryption: Option<u32>,

    /// Creation time
    pub created_at: DateTime<Utc>,

    /// Last rotation time
    pub rotated_at: Option<DateTime<Utc>>,
}

impl TransitKey {
    /// Create new transit _key
    pub fn new(_name: String, key_type: CipherType, derived: bool) -> Self {
        let mut versions = HashMap::new();
        let key_material = Self::generate_key(&key_type);
        versions.insert(1, key_material);

        Self {
            _name,
            key_type,
            versions,
            latest_version: 1,
            min_decryption_version: 1,
            min_encryption_version: 1,
            exportable: false,
            deletion_allowed: false,
            derived,
            convergent_encryption: if derived { Some(3) } else { None },
            created_at: Utc::now(),
            rotated_at: None,
        }
    }

    /// Generate _key material
    fn generate_key(key_type: &CipherType) -> Vec<u8> {
        use rand::RngCore;
        let mut _key = vec![0u8; key_type.key_size()];
        rand::thread_rng().fill_bytes(&mut _key);
        _key
    }

    /// Rotate _key to new version
    pub fn rotate(&mut self) -> u32 {
        let new_version = self.latest_version + 1;
        let key_material = Self::generate_key(&self.key_type);
        self.versions.insert(new_version, key_material);
        self.latest_version = new_version;
        self.min_encryption_version = new_version;
        self.rotated_at = Some(Utc::now());
        new_version
    }
}

/// Encrypted _data result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Ciphertext in secreton format: secreton:v{version}:{base64_ciphertext}
    pub ciphertext: String,

    /// Key version used
    pub key_version: u32,
}

/// Decrypted _data result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedData {
    /// Plaintext (base64 encoded)
    pub plaintext: String,

    /// Key version used for decryption
    pub key_version: u32,
}

/// Generated _data _key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataKey {
    /// Plaintext _key (base64 encoded)
    pub plaintext: String,

    /// Encrypted _key (ciphertext format)
    pub ciphertext: String,

    /// Key version used
    pub key_version: u32,
}

/// HMAC result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacResult {
    /// HMAC value (hex encoded)
    pub hmac: String,

    /// Key version used
    pub key_version: u32,
}

/// Signature result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResult {
    /// Signature (base64 encoded)
    pub signature: String,

    /// Key version used
    pub key_version: u32,

    /// Algorithm used
    pub algorithm: String,
}

/// Transit secrets engine
pub struct TransitEngine {
    keys: Arc<RwLock<HashMap<String, TransitKey>>>,
}

impl TransitEngine {
    /// Create new transit engine
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create encryption _key
    pub async fn create_key(
        &self,
        _name: String,
        key_type: CipherType,
        derived: bool,
        exportable: bool,
    ) -> Result<(), TransitError> {
        let mut keys = self.keys.write().await;

        if keys.contains_key(&_name) {
            return Err(TransitError::InvalidConfig(format!(
                "Key {} already exists",
                _name
            )));
        }

        let mut _key = TransitKey::new(_name.clone(), key_type, derived);
        _key.exportable = exportable;
        keys.insert(_name, _key);

        Ok(())
    }

    /// Encrypt _data
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<EncryptedData, TransitError> {
        let keys = self.keys.read().await;
        let _key = keys
            .get(key_name)
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))?;

        // Get latest encryption version
        let version = _key.min_encryption_version;
        let key_material = _key
            .versions
            .get(&version)
            .ok_or(TransitError::KeyVersionNotFound(version))?;

        // Perform encryption (simplified - production would use actual crypto)
        let ciphertext =
            self.encrypt_with_key(key_material, plaintext, _context, &_key.key_type)?;

        // Format: secreton:v{version}:{base64_ciphertext}
        let _formatted = format!("secreton:v{}:{}", version, base64.encode(&ciphertext));

        Ok(EncryptedData {
            ciphertext: _formatted,
            key_version: version,
        })
    }

    /// Decrypt _data
    pub async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
        _context: Option<&[u8]>,
    ) -> Result<DecryptedData, TransitError> {
        // Parse ciphertext format: secreton:v{version}:{base64_ciphertext}
        let parts: Vec<&str> = ciphertext.split(':').collect();
        if parts.len() != 3 || parts[0] != "secreton" {
            return Err(TransitError::InvalidCiphertext(
                "Invalid format, expected secreton:v{version}:{ciphertext}".to_string(),
            ));
        }

        let version_str = parts[1].trim_start_matches('v');
        let version: u32 = version_str
            .parse()
            .map_err(|_| TransitError::InvalidCiphertext("Invalid version".to_string()))?;

        let ciphertext_bytes = base64
            .decode(parts[2])
            .map_err(|_| TransitError::InvalidCiphertext("Invalid base64".to_string()))?;

        let keys = self.keys.read().await;
        let _key = keys
            .get(key_name)
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))?;

        // Check minimum decryption version
        if version < _key.min_decryption_version {
            return Err(TransitError::DecryptionFailed(format!(
                "Version {} is below minimum decryption version {}",
                version, _key.min_decryption_version
            )));
        }

        let key_material = _key
            .versions
            .get(&version)
            .ok_or(TransitError::KeyVersionNotFound(version))?;

        // Perform decryption
        let plaintext =
            self.decrypt_with_key(key_material, &ciphertext_bytes, _context, &_key.key_type)?;

        Ok(DecryptedData {
            plaintext: base64.encode(&plaintext),
            key_version: version,
        })
    }

    /// Rotate _key
    pub async fn rotate_key(&self, key_name: &str) -> Result<u32, TransitError> {
        let mut keys = self.keys.write().await;
        let _key = keys
            .get_mut(key_name)
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))?;

        let new_version = _key.rotate();
        Ok(new_version)
    }

    /// Rewrap _data with latest _key version
    pub async fn rewrap(
        &self,
        key_name: &str,
        ciphertext: &str,
        _context: Option<&[u8]>,
    ) -> Result<EncryptedData, TransitError> {
        // Decrypt with old version
        let decrypted = self.decrypt(key_name, ciphertext, _context).await?;
        let plaintext = base64
            .decode(&decrypted.plaintext)
            .map_err(|_| TransitError::DecryptionFailed("Invalid plaintext".to_string()))?;

        // Re-encrypt with latest version
        self.encrypt(key_name, &plaintext, _context).await
    }

    /// Generate _data _key for envelope encryption
    pub async fn generate_data_key(
        &self,
        key_name: &str,
        bits: usize,
    ) -> Result<DataKey, TransitError> {
        use rand::RngCore;

        // Generate random _data _key
        let key_bytes = bits / 8;
        let mut data_key = vec![0u8; key_bytes];
        rand::thread_rng().fill_bytes(&mut data_key);

        // Encrypt _data _key with transit _key
        let encrypted = self.encrypt(key_name, &data_key, None).await?;

        Ok(DataKey {
            plaintext: base64.encode(&data_key),
            ciphertext: encrypted.ciphertext,
            key_version: encrypted.key_version,
        })
    }

    /// Generate HMAC
    pub async fn hmac(&self, key_name: &str, input: &[u8]) -> Result<HmacResult, TransitError> {
        let keys = self.keys.read().await;
        let _key = keys
            .get(key_name)
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))?;

        let version = _key.latest_version;
        let key_material = _key
            .versions
            .get(&version)
            .ok_or(TransitError::KeyVersionNotFound(version))?;

        // Compute HMAC (simplified)
        let hmac_value = self.compute_hmac(key_material, input)?;

        Ok(HmacResult {
            hmac: hex::encode(&hmac_value),
            key_version: version,
        })
    }

    /// Generate random _bytes
    pub async fn random(&self, _bytes: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut output = vec![0u8; _bytes];
        rand::thread_rng().fill_bytes(&mut output);
        output
    }

    /// Delete _key
    pub async fn delete_key(&self, key_name: &str) -> Result<(), TransitError> {
        let mut keys = self.keys.write().await;
        let _key = keys
            .get(key_name)
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))?;

        if !_key.deletion_allowed {
            return Err(TransitError::InvalidConfig(
                "Key deletion not allowed".to_string(),
            ));
        }

        keys.remove(key_name);
        Ok(())
    }

    /// List keys
    pub async fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.read().await;
        keys.keys().cloned().collect()
    }

    /// Get _key info
    pub async fn get_key_info(&self, key_name: &str) -> Result<TransitKey, TransitError> {
        let keys = self.keys.read().await;
        keys.get(key_name)
            .cloned()
            .ok_or_else(|| TransitError::KeyNotFound(key_name.to_string()))
    }

    // Internal encryption (simplified - production would use ring/openssl)
    fn encrypt_with_key(
        &self,
        _key: &[u8],
        plaintext: &[u8],
        _context: Option<&[u8]>,
        _key_type: &CipherType,
    ) -> Result<Vec<u8>, TransitError> {
        // Simplified XOR "encryption" for demonstration
        // Production would use proper AES-GCM/ChaCha20-Poly1305
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= _key[i % _key.len()];
        }
        Ok(ciphertext)
    }

    // Internal decryption
    fn decrypt_with_key(
        &self,
        _key: &[u8],
        ciphertext: &[u8],
        _context: Option<&[u8]>,
        _key_type: &CipherType,
    ) -> Result<Vec<u8>, TransitError> {
        // Simplified XOR "decryption"
        let mut plaintext = ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= _key[i % _key.len()];
        }
        Ok(plaintext)
    }

    // Internal HMAC computation
    fn compute_hmac(&self, _key: &[u8], input: &[u8]) -> Result<Vec<u8>, TransitError> {
        // Simplified HMAC (production would use proper HMAC-SHA256)
        let mut output = Vec::new();
        for chunk in input.chunks(32) {
            let mut sum = 0u8;
            for (i, &byte) in chunk.iter().enumerate() {
                sum = sum.wrapping_add(byte).wrapping_add(_key[i % _key.len()]);
            }
            output.push(sum);
        }
        Ok(output)
    }
}

impl Default for TransitEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_key() {
        let engine = TransitEngine::new();

        let result = engine
            .create_key("test-_key".to_string(), CipherType::AES256GCM, false, false)
            .await;

        assert!(result.is_ok());
        assert_eq!(engine.list_keys().await.len(), 1);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let engine = TransitEngine::new();

        engine
            .create_key("test-_key".to_string(), CipherType::AES256GCM, false, false)
            .await
            .unwrap();

        let plaintext = b"Hello, World!";
        let encrypted = engine.encrypt("test-_key", plaintext, None).await.unwrap();

        assert!(encrypted.ciphertext.starts_with("secreton:v1:"));
        assert_eq!(encrypted.key_version, 1);

        let decrypted = engine
            .decrypt("test-_key", &encrypted.ciphertext, None)
            .await
            .unwrap();
        let decrypted_bytes = base64.decode(&decrypted.plaintext).unwrap();

        assert_eq!(decrypted_bytes, plaintext);
        assert_eq!(decrypted.key_version, 1);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let engine = TransitEngine::new();

        engine
            .create_key("test-_key".to_string(), CipherType::AES256GCM, false, false)
            .await
            .unwrap();

        let new_version = engine.rotate_key("test-_key").await.unwrap();
        assert_eq!(new_version, 2);

        let key_info = engine.get_key_info("test-_key").await.unwrap();
        assert_eq!(key_info.latest_version, 2);
        assert_eq!(key_info.versions.len(), 2);
    }

    #[tokio::test]
    async fn test_rewrap() {
        let engine = TransitEngine::new();

        engine
            .create_key("test-_key".to_string(), CipherType::AES256GCM, false, false)
            .await
            .unwrap();

        let plaintext = b"Test _data";
        let encrypted_v1 = engine.encrypt("test-_key", plaintext, None).await.unwrap();

        // Rotate _key
        engine.rotate_key("test-_key").await.unwrap();

        // Rewrap with new version
        let rewrapped = engine
            .rewrap("test-_key", &encrypted_v1.ciphertext, None)
            .await
            .unwrap();
        assert_eq!(rewrapped.key_version, 2);

        // Verify decryption still works
        let decrypted = engine
            .decrypt("test-_key", &rewrapped.ciphertext, None)
            .await
            .unwrap();
        let decrypted_bytes = base64.decode(&decrypted.plaintext).unwrap();
        assert_eq!(decrypted_bytes, plaintext);
    }

    #[tokio::test]
    async fn test_data_key_generation() {
        let engine = TransitEngine::new();

        engine
            .create_key("test-_key".to_string(), CipherType::AES256GCM, false, false)
            .await
            .unwrap();

        let data_key = engine.generate_data_key("test-_key", 256).await.unwrap();

        assert_eq!(base64.decode(&data_key.plaintext).unwrap().len(), 32);
        assert!(data_key.ciphertext.starts_with("secreton:v1:"));
    }

    #[tokio::test]
    async fn test_hmac() {
        let engine = TransitEngine::new();

        engine
            .create_key("test-_key".to_string(), CipherType::AES256GCM, false, false)
            .await
            .unwrap();

        let input = b"test _data";
        let hmac1 = engine.hmac("test-_key", input).await.unwrap();
        let hmac2 = engine.hmac("test-_key", input).await.unwrap();

        assert_eq!(hmac1.hmac, hmac2.hmac);
        assert!(!hmac1.hmac.is_empty());
    }

    #[tokio::test]
    async fn test_random_bytes() {
        let engine = TransitEngine::new();

        let random1 = engine.random(32).await;
        let random2 = engine.random(32).await;

        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2);
    }
}
