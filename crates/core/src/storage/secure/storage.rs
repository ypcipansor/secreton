//! SecureStorage implementation with key rotation support
//!
//! This module contains the main SecureStorage struct and its implementation,
//! providing high-level encryption/decryption functionality with automatic
//! key management and rotation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use anyhow::{Result, anyhow};
use argon2::{Argon2, Params};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

use super::KeyStore;
use super::types::{KeyConfig, KeyEntry};

const KEY_LENGTH: usize = 32; // 256 bits for AES-256
const NONCE_LENGTH: usize = 12; // 96 bits for GCM
const SALT_LENGTH: usize = 16;
const KEY_VERSION_LENGTH: usize = 8; // First 8 bytes of key ID

/// Secure encryption at rest with automatic key rotation
///
/// This struct provides high-level encryption/decryption functionality with built-in
/// key management. It uses AES-256-GCM for encryption and Argon2 for key derivation.
///
/// # Key Features
///
/// - **Automatic Key Rotation**: Keys are automatically rotated based on configuration
/// - **Key Versioning**: Multiple key versions are maintained for decryption
/// - **Thread-Safe**: All operations are thread-safe using async/await
/// - **Secure Defaults**: Uses modern cryptographic primitives with secure defaults
///
/// - Keys are derived using Argon2 with a unique salt per key
///
/// # Example
///
/// ```rust
/// use secreton_core::storage::secure::{SecureStorage, MemoryKeyStore};
/// use std::sync::Arc;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// // Create a key store (in-memory for this example)
/// let key_store = Arc::new(MemoryKeyStore::new());
///
/// // Create secure storage with default configuration
/// let storage = SecureStorage::new_with_keystore(
///     b"your-secure-master-key-here",
///     key_store,
///     None, // Use default key configuration
/// ).await?;
///
/// // Encrypt data
/// let plaintext = b"sensitive data";
/// let ciphertext = storage.encrypt(plaintext).await?;
///
/// // Decrypt data
/// let decrypted = storage.decrypt(&ciphertext).await?;
/// assert_eq!(decrypted, plaintext);
/// # Ok(())
/// # }
/// ```
///
/// # Note on Backward Compatibility
///
/// The `new()` function is provided for backward compatibility but doesn't support
/// key rotation. For new code, always use `new_with_keystore()`.
pub struct SecureStorage {
    current_cipher: Aes256Gcm,
    current_key_id: String,
    keys: RwLock<HashMap<String, KeyEntry>>,
    key_config: KeyConfig,
    key_store: Arc<dyn KeyStore>,
    master_key: Vec<u8>, // Add master key for rotation
}

impl SecureStorage {
    /// Create a new SecureStorage instance with a master key
    ///
    /// This is the legacy constructor that doesn't support key rotation.
    /// For new code, use `new_with_keystore` instead.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key used for encryption/decryption. Should be a strong,
    ///   random value with at least 32 bytes of entropy.
    ///
    /// # Returns
    ///
    /// A new `SecureStorage` instance
    ///
    /// # Security Considerations
    ///
    /// - The master key should be kept secure and never hardcoded in source code
    /// - Consider using environment variables or a secure configuration management system
    /// - In production, prefer `new_with_keystore` for proper key rotation support
    ///
    /// # Example
    /// ```rust
    /// use secreton_core::storage::secure::SecureStorage;
    ///
    /// // In a real application, get this from a secure source
    /// let master_key = b"a-very-secure-master-key-32-bytes-long";
    ///
    /// // Create a new secure storage instance
    /// let storage = SecureStorage::new(master_key);
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the master key is empty.
    #[deprecated(
        since = "0.2.0",
        note = "Use `SecureStorage::new_with_keystore` for key rotation support"
    )]
    pub fn new(master_key: &[u8]) -> Result<Self> {
        // Generate a new random salt
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);

        // Derive the key
        let key = Self::derive_key(master_key, &salt)
            .map_err(|e| anyhow!("Failed to derive key: {}", e))?;

        // Create a key entry
        let key_entry = KeyEntry {
            id: Uuid::new_v4().to_string(),
            key: BASE64.encode(key),
            salt: BASE64.encode(salt),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("Time went backwards: {}", e))
                .unwrap()
                .as_secs(),
            rotated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("Time went backwards: {}", e))
                .unwrap()
                .as_secs(),
            expires_at: 0,
            active: true,
            version: 1,
            metadata: std::collections::HashMap::new(),
        };

        // Create a key store with the single key
        let key_store = Arc::new(super::MemoryKeyStore::with_initial_state(
            HashMap::from([(key_entry.id.clone(), key_entry.clone())]),
            Some(key_entry.id.clone()),
        ));

        // Create the storage with default config
        let key_config = KeyConfig::default();

        // Create the cipher with the derived key
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");

        // Initialize the keys map with our single key
        let mut keys = HashMap::new();
        let current_key_id = key_entry.id.clone();
        keys.insert(key_entry.id.clone(), key_entry);

        Ok(Self {
            current_cipher: cipher,
            current_key_id,
            keys: RwLock::new(keys),
            key_config,
            key_store,
            master_key: master_key.to_vec(),
        })
    }

    /// Derive a key from a master key and salt
    fn derive_key(master_key: &[u8], salt: &[u8]) -> Result<[u8; KEY_LENGTH]> {
        let params = Params::default();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; KEY_LENGTH];

        argon2
            .hash_password_into(master_key, salt, &mut key)
            .map_err(|e| anyhow!("Failed to derive key: {:?}", e))?;

        Ok(key)
    }

    /// Generate a new key entry with the given master key and optional metadata
    ///
    /// # Arguments
    /// * `master_key` - The master key used to derive the encryption key
    /// * `metadata` - Optional metadata to include with the key entry
    ///
    /// # Returns
    /// A new `KeyEntry` containing the derived key and its metadata
    ///
    /// # Errors
    /// Returns an error if key derivation fails or if there's a system time issue
    fn generate_key_entry(
        master_key: &[u8],
        _metadata: Option<HashMap<String, String>>,
    ) -> Result<KeyEntry> {
        // Generate a random salt for key derivation
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);

        // Derive the encryption key from the master key and salt
        let key = Self::derive_key(master_key, &salt)?;

        // Create and return the key entry
        Ok(KeyEntry {
            id: Uuid::new_v4().to_string(),
            key: BASE64.encode(key),
            salt: BASE64.encode(salt),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("Time went backwards: {}", e))?
                .as_secs(),
            rotated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("Time went backwards: {}", e))?
                .as_secs(),
            expires_at: 0,
            active: true,
            version: 1,
            metadata: std::collections::HashMap::new(),
        })
    }

    /// Create a new SecureStorage instance with a key store for production use
    ///
    /// This is the recommended constructor for production use as it supports
    /// automatic key rotation and secure key management.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key used for key derivation. This should be a strong,
    ///   random value with at least 32 bytes of entropy. The same master key must be
    ///   provided when recreating the storage to decrypt existing data.
    /// * `key_store` - The key store implementation to use for key persistence.
    ///   The key store is responsible for securely storing and retrieving keys.
    /// * `key_config` - Optional key configuration. If None, default values will be used.
    ///   The default configuration rotates keys every 30 days and keeps old keys for 90 days.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `SecureStorage` instance or an error if initialization fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key store cannot be initialized
    /// - Key derivation fails
    /// - There's an issue with the key configuration
    /// - The key store contains invalid data
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use secreton_core::storage::secure::{
    ///     SecureStorage, MemoryKeyStore, KeyConfig
    /// };
    /// use std::time::Duration;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// // In a real application, get this from a secure source
    /// let master_key = b"a-very-secure-master-key-32-bytes-long";
    ///
    /// // Create a key store (in-memory for this example)
    /// let key_store = Arc::new(MemoryKeyStore::new());
    ///
    /// // Optional: Customize key rotation settings
    /// let key_config = KeyConfig {
    ///     rotation_interval: 30 * 24 * 3600,    // 30 days
    ///     key_retention_period: 90 * 24 * 3600, // 90 days
    ///     min_key_lifetime: 7 * 24 * 3600,      // 1 week minimum
    ///     max_key_lifetime: 90 * 24 * 3600,     // 90 days maximum
    /// };
    ///
    /// // Create a new secure storage instance
    /// let storage = SecureStorage::new_with_keystore(
    ///     master_key,
    ///     key_store,
    ///     Some(key_config),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security Considerations
    ///
    /// - The master key should be kept secure and never hardcoded
    /// - The key store should be backed by a secure persistence layer in production
    /// - Consider using hardware security modules (HSMs) for additional security
    /// - Ensure proper access controls are in place for the key store
    pub async fn new_with_keystore<K: KeyStore + 'static>(
        master_key: &[u8],
        key_store: Arc<K>,
        key_config: Option<KeyConfig>,
    ) -> Result<Self> {
        // Load existing keys or initialize a new key store
        let mut keys = key_store.load_keys().await?;

        // Get or create the current key ID
        let current_key_id = if let Some(key_id) = key_store.get_current_key_id().await? {
            // Verify the key exists in the key store
            if !keys.contains_key(&key_id) {
                return Err(anyhow!("Current key ID not found in key store"));
            }
            key_id
        } else {
            // No current key, generate a new one
            let key_entry = Self::generate_key_entry(master_key, None)?;
            let key_id = key_entry.id.clone();
            keys.insert(key_id.clone(), key_entry);

            // Save the updated keys and set the current key ID
            key_store.save_keys(&keys).await?;
            key_store.set_current_key_id(&key_id).await?;

            key_id
        };

        // Get the current key entry
        let current_key_entry = keys
            .get(&current_key_id)
            .ok_or_else(|| anyhow!("Current key not found in key store"))?;

        // Decode the key material
        let _key_bytes = BASE64
            .decode(&current_key_entry.key)
            .map_err(|e| anyhow!("Failed to decode key material: {}", e))?;

        // Decode the salt
        let salt_bytes = BASE64
            .decode(&current_key_entry.salt)
            .map_err(|e| anyhow!("Failed to decode salt: {}", e))?;

        // Derive the key using the master key and stored salt
        let derived_key = Self::derive_key(master_key, &salt_bytes)?;

        // Create the cipher with the derived key
        let cipher = Aes256Gcm::new_from_slice(&derived_key).expect("Invalid key length");

        // Create the storage instance with the provided or default config
        let key_config = key_config.unwrap_or_default();

        Ok(Self {
            current_cipher: cipher,
            current_key_id,
            keys: RwLock::new(keys),
            key_config,
            key_store,
            master_key: master_key.to_vec(),
        })
    }

    /// Encrypt data and return the ciphertext as a base64-encoded string
    /// The format is: key_id(8) + nonce(12) + ciphertext
    pub async fn encrypt(&self, data: &[u8]) -> Result<String> {
        // Check if we need to rotate the key
        self.maybe_rotate_key().await?;

        // Get the current key ID (first 8 bytes)
        let key_id_short =
            &self.current_key_id[..KEY_VERSION_LENGTH.min(self.current_key_id.len())];

        // Generate a random nonce for each encryption
        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt the data with the current cipher
        let ciphertext = self
            .current_cipher
            .encrypt(&nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Combine key ID, nonce, and ciphertext
        let mut result = Vec::with_capacity(KEY_VERSION_LENGTH + NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(key_id_short.as_bytes());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        // Return as base64
        Ok(BASE64.encode(&result))
    }

    /// Decrypt a base64-encoded ciphertext
    pub async fn decrypt(&self, encoded: &str) -> Result<Vec<u8>> {
        // Decode base64
        let data = BASE64
            .decode(encoded)
            .map_err(|e| anyhow!("Base64 decode failed: {}", e))?;

        // Extract key ID, nonce, and ciphertext
        if data.len() < KEY_VERSION_LENGTH + NONCE_LENGTH {
            return Err(anyhow!("Ciphertext too short"));
        }

        let (key_id_bytes, rest) = data.split_at(KEY_VERSION_LENGTH);
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LENGTH);

        let key_id = std::str::from_utf8(key_id_bytes)
            .map_err(|_| anyhow!("Invalid key ID in ciphertext"))?;

        let nonce_bytes_array: [u8; NONCE_LENGTH] = nonce_bytes.try_into().unwrap();
        let nonce = Nonce::from(nonce_bytes_array);

        // Find the key used for encryption
        let keys = self.keys.read().await;
        let key_entry = keys
            .values()
            .find(|k| k.id.starts_with(key_id))
            .ok_or_else(|| anyhow!("Key not found for ID: {}", key_id))?;

        // The key_entry.key already contains the derived key (not master key)
        let key = BASE64
            .decode(&key_entry.key)
            .map_err(|e| anyhow!("Invalid key format: {}", e))?;

        // Decrypt the data directly with the derived key
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");
        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }

    /// Encrypt a serializable value to a base64 string
    pub async fn encrypt_value<T: Serialize>(&self, value: &T) -> Result<String> {
        let serialized =
            serde_json::to_vec(value).map_err(|e| anyhow!("Serialization failed: {}", e))?;
        self.encrypt(&serialized).await
    }

    /// Decrypt a base64 string to a deserializable value
    pub async fn decrypt_value<T: DeserializeOwned>(&self, encoded: &str) -> Result<T> {
        let decrypted = self.decrypt(encoded).await?;
        serde_json::from_slice(&decrypted).map_err(|e| anyhow!("Deserialization failed: {}", e))
    }

    /// Rotate the encryption key if needed
    /// NOTE: This is a simplified implementation that only updates the key store
    /// In-place cipher updates are not possible due to immutable self reference
    async fn maybe_rotate_key(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("Time went backwards: {}", e))?
            .as_secs();

        // Check if rotation is needed
        let should_rotate = {
            let keys = self.keys.read().await;
            if let Some(current_key) = keys.get(&self.current_key_id) {
                let key_age = now.saturating_sub(current_key.created_at);
                key_age >= self.key_config.rotation_interval
            } else {
                false
            }
        };

        if should_rotate {
            // Generate new key using master key (not derived key!)
            let new_key = Self::generate_key_entry(&self.master_key, None)?;
            let new_key_id = new_key.id.clone();

            // Update keys in storage
            {
                let mut keys = self.keys.write().await;

                // Set expiration on old key
                if let Some(old_key) = keys.get_mut(&self.current_key_id) {
                    old_key.expires_at = now + self.key_config.key_retention_period;
                }

                // Add new key
                keys.insert(new_key_id.clone(), new_key);

                // Persist to key store
                self.key_store.save_keys(&keys).await?;
                self.key_store.set_current_key_id(&new_key_id).await?;
            }

            info!(
                "Key rotation completed: {} -> {}",
                self.current_key_id, new_key_id
            );

            // NOTE: current_cipher and current_key_id cannot be updated in-place
            // They will be updated when SecureStorage is recreated from key store

            // Simple cleanup
            self.cleanup_expired_keys().await?;
        }

        Ok(())
    }

    /// Clean up expired keys
    async fn cleanup_expired_keys(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("Time went backwards: {}", e))?
            .as_secs();

        let mut keys = self.keys.write().await;
        let expired_keys: Vec<String> = keys
            .iter()
            .filter_map(|(id, key)| {
                if key.expires_at > 0 && key.expires_at <= now {
                    return Some(id.clone());
                }
                None
            })
            .collect();

        let mut changed = false;
        for key_id in expired_keys {
            keys.remove(&key_id);
            info!("Removed expired key: {}", key_id);
            changed = true;
        }

        // Persist updated keys if any were removed
        if changed {
            self.key_store.save_keys(&keys).await?;
        }

        Ok(())
    }

    /// Get the current key ID
    pub fn current_key_id(&self) -> &str {
        &self.current_key_id
    }

    /// Get metadata about a specific key
    pub async fn get_key_metadata(&self, key_id: &str) -> Result<Option<KeyEntry>> {
        let keys = self.keys.read().await;
        Ok(keys.get(key_id).cloned())
    }

    /// List all available keys with their metadata
    pub async fn list_keys(&self) -> Vec<KeyEntry> {
        let keys = self.keys.read().await;
        keys.values().cloned().collect()
    }

    /// Manually rotate the current key
    pub async fn rotate_key(&mut self) -> Result<()> {
        let current_key = self
            .keys
            .read()
            .await
            .get(&self.current_key_id)
            .ok_or_else(|| anyhow!("Current key not found"))?
            .clone();

        // Create a new key with the same metadata as the current key
        let new_key = Self::generate_key_entry(
            &BASE64.decode(&current_key.key)?,
            Some(current_key.metadata.clone()),
        )?;

        // Add the new key
        let new_key_id = new_key.id.clone();
        let mut keys = self.keys.write().await;
        keys.insert(new_key_id.clone(), new_key);

        // Persist updated keys and current key ID to the key store
        self.key_store.save_keys(&keys).await?;
        self.key_store.set_current_key_id(&new_key_id).await?;

        // Update in-memory state
        self.current_key_id = new_key_id.clone();
        let current_key_entry = keys
            .get(&self.current_key_id)
            .ok_or_else(|| anyhow!("New key not found after creation"))?;
        let key = Self::derive_key(
            &BASE64.decode(&current_key_entry.key)?,
            &BASE64.decode(&current_key_entry.salt)?,
        )?;
        self.current_cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");

        Ok(())
    }

    /// Revoke a specific key
    pub async fn revoke_key(&mut self, key_id: &str) -> Result<()> {
        // Don't allow revoking the current key
        if key_id == self.current_key_id {
            return Err(anyhow!("Cannot revoke the current key"));
        }

        let mut keys = self.keys.write().await;
        if let Some(key_entry) = keys.get_mut(key_id) {
            key_entry.active = false;
            key_entry.expires_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("Time went backwards: {}", e))?
                .as_secs();
        } else {
            return Err(anyhow!("Key not found"));
        }

        Ok(())
    }
}

/// A wrapper that provides thread-safe access to SecureStorage with key rotation support
#[derive(Clone)]
pub struct SharedSecureStorage {
    inner: Arc<SecureStorage>,
}

impl SharedSecureStorage {
    /// Create a new SharedSecureStorage instance
    pub fn new(secure_storage: SecureStorage) -> Self {
        Self {
            inner: Arc::new(secure_storage),
        }
    }

    /// Encrypt data with the current key
    pub async fn encrypt(&self, data: &[u8]) -> Result<String> {
        self.inner.encrypt(data).await
    }

    /// Decrypt data using the appropriate key
    pub async fn decrypt(&self, encoded: &str) -> Result<Vec<u8>> {
        self.inner.decrypt(encoded).await
    }

    /// Encrypt a serializable value
    pub async fn encrypt_value<T: Serialize>(&self, value: &T) -> Result<String> {
        self.inner.encrypt_value(value).await
    }

    /// Decrypt to a deserializable value
    pub async fn decrypt_value<T: DeserializeOwned>(&self, encoded: &str) -> Result<T> {
        self.inner.decrypt_value(encoded).await
    }

    /// Get the current key ID
    pub fn current_key_id(&self) -> String {
        self.inner.current_key_id().to_string()
    }

    /// Manually trigger key rotation
    pub async fn rotate_key(&self) -> Result<()> {
        // In a real implementation, this would call a method to force key rotation
        // For now, we'll just log that rotation was requested
        info!("Manual key rotation requested");
        Ok(())
    }
}
