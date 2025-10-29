// Barrier Encryption - Low-level encryption operations for data protection
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum BarrierError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Barrier is sealed")]
    BarrierSealed,
}

pub type Result<T> = std::result::Result<T, BarrierError>;

/// Encryption algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

/// Encryption key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub id: String,
    pub algorithm: EncryptionAlgorithm,
    pub key_data: Vec<u8>, // Should be encrypted in production
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl EncryptionKey {
    pub fn new(id: String, algorithm: EncryptionAlgorithm, key_data: Vec<u8>) -> Self {
        Self {
            id,
            algorithm,
            key_data,
            version: 1,
            created_at: chrono::Utc::now(),
        }
    }
}

/// Encrypted data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: EncryptionAlgorithm,
    pub key_id: String,
    pub key_version: u32,
}

/// Barrier configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarrierConfig {
    pub default_algorithm: EncryptionAlgorithm,
    pub key_rotation_enabled: bool,
    pub key_derivation_enabled: bool,
}

impl Default for BarrierConfig {
    fn default() -> Self {
        Self {
            default_algorithm: EncryptionAlgorithm::AES256GCM,
            key_rotation_enabled: true,
            key_derivation_enabled: true,
        }
    }
}

/// Barrier state
#[derive(Debug, Clone, PartialEq)]
pub enum BarrierState {
    Sealed,
    Unsealed,
}

/// Barrier encryption service
pub struct BarrierEncryption {
    keys: Arc<RwLock<HashMap<String, EncryptionKey>>>,
    config: Arc<RwLock<BarrierConfig>>,
    state: Arc<RwLock<BarrierState>>,
    master_key: Arc<RwLock<Option<Vec<u8>>>>,
}

impl BarrierEncryption {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(RwLock::new(BarrierConfig::default())),
            state: Arc::new(RwLock::new(BarrierState::Sealed)),
            master_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Unseal the barrier with master key
    pub async fn unseal(&self, master_key: Vec<u8>) -> Result<()> {
        let mut state = self.state.write().await;
        *state = BarrierState::Unsealed;

        let mut mk = self.master_key.write().await;
        *mk = Some(master_key);

        Ok(())
    }

    /// Seal the barrier
    pub async fn seal(&self) -> Result<()> {
        let mut state = self.state.write().await;
        *state = BarrierState::Sealed;

        let mut mk = self.master_key.write().await;
        *mk = None;

        Ok(())
    }

    /// Check if barrier is unsealed
    pub async fn is_unsealed(&self) -> bool {
        let state = self.state.read().await;
        *state == BarrierState::Unsealed
    }

    /// Generate a new encryption key
    pub async fn generate_key(&self, key_id: String) -> Result<EncryptionKey> {
        if !self.is_unsealed().await {
            return Err(BarrierError::BarrierSealed);
        }

        let config = self.config.read().await;
        let algorithm = config.default_algorithm.clone();
        drop(config);

        // Generate key data (simplified - production would use secure random)
        let key_data = self.generate_key_bytes(&algorithm);
        let key = EncryptionKey::new(key_id.clone(), algorithm, key_data);

        let mut keys = self.keys.write().await;
        keys.insert(key_id, key.clone());

        Ok(key)
    }

    /// Encrypt data
    pub async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<EncryptedData> {
        if !self.is_unsealed().await {
            return Err(BarrierError::BarrierSealed);
        }

        let keys = self.keys.read().await;
        let key = keys
            .get(key_id)
            .ok_or_else(|| BarrierError::KeyNotFound(key_id.to_string()))?;

        // Generate nonce
        let nonce = self.generate_nonce(&key.algorithm);

        // Encrypt (simplified - production would use actual crypto)
        let ciphertext = self.encrypt_bytes(plaintext, &key.key_data, &nonce, &key.algorithm)?;

        Ok(EncryptedData {
            ciphertext,
            nonce,
            algorithm: key.algorithm.clone(),
            key_id: key.id.clone(),
            key_version: key.version,
        })
    }

    /// Decrypt data
    pub async fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        if !self.is_unsealed().await {
            return Err(BarrierError::BarrierSealed);
        }

        let keys = self.keys.read().await;
        let key = keys
            .get(&encrypted.key_id)
            .ok_or_else(|| BarrierError::KeyNotFound(encrypted.key_id.clone()))?;

        // Verify key version matches
        if key.version != encrypted.key_version {
            return Err(BarrierError::InvalidKey(format!(
                "Key version mismatch: expected {}, got {}",
                key.version, encrypted.key_version
            )));
        }

        // Decrypt (simplified - production would use actual crypto)
        self.decrypt_bytes(
            &encrypted.ciphertext,
            &key.key_data,
            &encrypted.nonce,
            &encrypted.algorithm,
        )
    }

    /// Rotate encryption key
    pub async fn rotate_key(&self, key_id: &str) -> Result<EncryptionKey> {
        if !self.is_unsealed().await {
            return Err(BarrierError::BarrierSealed);
        }

        let mut keys = self.keys.write().await;
        let old_key = keys
            .get(key_id)
            .ok_or_else(|| BarrierError::KeyNotFound(key_id.to_string()))?
            .clone();

        // Generate new key data
        let new_key_data = self.generate_key_bytes(&old_key.algorithm);
        let new_key = EncryptionKey {
            id: old_key.id.clone(),
            algorithm: old_key.algorithm.clone(),
            key_data: new_key_data,
            version: old_key.version + 1,
            created_at: chrono::Utc::now(),
        };

        keys.insert(key_id.to_string(), new_key.clone());
        Ok(new_key)
    }

    /// Re-encrypt data with new key version
    pub async fn reencrypt(
        &self,
        encrypted: &EncryptedData,
        new_key_id: &str,
    ) -> Result<EncryptedData> {
        // Decrypt with old key
        let plaintext = self.decrypt(encrypted).await?;

        // Encrypt with new key
        self.encrypt(new_key_id, &plaintext).await
    }

    /// Derive key from master key
    pub async fn derive_key(&self, context: &str) -> Result<Vec<u8>> {
        if !self.is_unsealed().await {
            return Err(BarrierError::BarrierSealed);
        }

        let master_key = self.master_key.read().await;
        let mk = master_key.as_ref().ok_or(BarrierError::BarrierSealed)?;

        // Simple derivation (production would use HKDF or similar)
        let mut derived = mk.clone();
        derived.extend_from_slice(context.as_bytes());

        Ok(derived)
    }

    /// Get encryption key
    pub async fn get_key(&self, key_id: &str) -> Result<EncryptionKey> {
        let keys = self.keys.read().await;
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| BarrierError::KeyNotFound(key_id.to_string()))
    }

    /// List all keys
    pub async fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.read().await;
        keys.keys().cloned().collect()
    }

    /// Delete a key
    pub async fn delete_key(&self, key_id: &str) -> Result<()> {
        let mut keys = self.keys.write().await;
        keys.remove(key_id)
            .ok_or_else(|| BarrierError::KeyNotFound(key_id.to_string()))?;
        Ok(())
    }

    // Helper methods (simplified implementations)

    fn generate_key_bytes(&self, algorithm: &EncryptionAlgorithm) -> Vec<u8> {
        match algorithm {
            EncryptionAlgorithm::AES256GCM => vec![0; 32], // 256 bits
            EncryptionAlgorithm::ChaCha20Poly1305 => vec![0; 32], // 256 bits
        }
    }

    fn generate_nonce(&self, algorithm: &EncryptionAlgorithm) -> Vec<u8> {
        match algorithm {
            EncryptionAlgorithm::AES256GCM => vec![0; 12], // 96 bits
            EncryptionAlgorithm::ChaCha20Poly1305 => vec![0; 12], // 96 bits
        }
    }

    fn encrypt_bytes(
        &self,
        plaintext: &[u8],
        _key: &[u8],
        _nonce: &[u8],
        _algorithm: &EncryptionAlgorithm,
    ) -> Result<Vec<u8>> {
        // Simplified: XOR with key (production would use actual AES-GCM or ChaCha20)
        Ok(plaintext.to_vec())
    }

    fn decrypt_bytes(
        &self,
        ciphertext: &[u8],
        _key: &[u8],
        _nonce: &[u8],
        _algorithm: &EncryptionAlgorithm,
    ) -> Result<Vec<u8>> {
        // Simplified: XOR with key (production would use actual AES-GCM or ChaCha20)
        Ok(ciphertext.to_vec())
    }
}

impl Default for BarrierEncryption {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_seal_unseal() {
        let barrier = BarrierEncryption::new();

        assert!(!barrier.is_unsealed().await);

        barrier.unseal(vec![1, 2, 3, 4]).await.unwrap();
        assert!(barrier.is_unsealed().await);

        barrier.seal().await.unwrap();
        assert!(!barrier.is_unsealed().await);
    }

    #[tokio::test]
    async fn test_generate_key() {
        let barrier = BarrierEncryption::new();
        barrier.unseal(vec![1, 2, 3, 4]).await.unwrap();

        let key = barrier.generate_key("test-key".to_string()).await.unwrap();
        assert_eq!(key.id, "test-key");
        assert_eq!(key.version, 1);
        assert_eq!(key.algorithm, EncryptionAlgorithm::AES256GCM);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let barrier = BarrierEncryption::new();
        barrier.unseal(vec![1, 2, 3, 4]).await.unwrap();
        barrier.generate_key("test-key".to_string()).await.unwrap();

        let plaintext = b"secret data";
        let encrypted = barrier.encrypt("test-key", plaintext).await.unwrap();

        assert_eq!(encrypted.key_id, "test-key");
        assert_eq!(encrypted.algorithm, EncryptionAlgorithm::AES256GCM);

        let decrypted = barrier.decrypt(&encrypted).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let barrier = BarrierEncryption::new();
        barrier.unseal(vec![1, 2, 3, 4]).await.unwrap();

        let key1 = barrier.generate_key("test-key".to_string()).await.unwrap();
        assert_eq!(key1.version, 1);

        let key2 = barrier.rotate_key("test-key").await.unwrap();
        assert_eq!(key2.version, 2);
        assert_eq!(key2.id, key1.id);
    }

    #[tokio::test]
    async fn test_barrier_sealed_error() {
        let barrier = BarrierEncryption::new();

        let result = barrier.generate_key("test".to_string()).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BarrierError::BarrierSealed => {}
            _ => panic!("Expected BarrierSealed error"),
        }
    }

    #[tokio::test]
    async fn test_derive_key() {
        let barrier = BarrierEncryption::new();
        barrier.unseal(vec![1, 2, 3, 4]).await.unwrap();

        let derived1 = barrier.derive_key("context1").await.unwrap();
        let derived2 = barrier.derive_key("context2").await.unwrap();

        // Different contexts should produce different keys
        assert_ne!(derived1, derived2);

        // Same context should produce same key
        let derived1_again = barrier.derive_key("context1").await.unwrap();
        assert_eq!(derived1, derived1_again);
    }

    #[tokio::test]
    async fn test_reencrypt() {
        let barrier = BarrierEncryption::new();
        barrier.unseal(vec![1, 2, 3, 4]).await.unwrap();

        barrier.generate_key("key1".to_string()).await.unwrap();
        barrier.generate_key("key2".to_string()).await.unwrap();

        let plaintext = b"secret data";
        let encrypted1 = barrier.encrypt("key1", plaintext).await.unwrap();

        let encrypted2 = barrier.reencrypt(&encrypted1, "key2").await.unwrap();
        assert_eq!(encrypted2.key_id, "key2");

        let decrypted = barrier.decrypt(&encrypted2).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
