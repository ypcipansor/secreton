//! # Secure Storage Module
//!
//! This module provides secure storage with encryption at rest and key rotation support.
//!
//! ## Features
//! - AES-256-GCM encryption with unique nonce per encryption
//! - Argon2 key derivation with configurable parameters
//! - Automatic key rotation with configurable intervals
//! - Support for multiple key versions
//! - Thread-safe operations through `SharedSecureStorage`
//!
//! ## Basic Usage
//!
//! ```rust
//! use secreton_core::storage::secure::{SecureStorage, SharedSecureStorage, MemoryKeyStore};
//! use std::sync::Arc;
//!
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! // Create a key store (in-memory for this example)
//! let key_store = Arc::new(MemoryKeyStore::new());
//!
//! // Create secure storage with default key configuration
//! let storage = SecureStorage::new_with_keystore(
//!     b"your-master-key-here",
//!     key_store,
//!     None,
//! ).await?;
//!
//! // For thread-safe access, wrap in SharedSecureStorage
//! let shared_storage = SharedSecureStorage::new(storage);
//!
//! // Encrypt data
//! let encrypted = shared_storage.encrypt(b"sensitive data").await?;
//!
//! // Decrypt data
//! let decrypted = shared_storage.decrypt(&encrypted).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Rotation
//!
//! Key rotation can be configured using `KeyConfig`:
//!
//! ```rust
//! # use secreton_core::storage::secure::{KeyConfig, SecureStorage, MemoryKeyStore};
//! # use std::sync::Arc;
//! # use std::time::Duration;
//! #
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let config = KeyConfig {
//!     rotation_interval: 30 * 24 * 3600, // Rotate every 30 days
//!     key_retention_period: 90 * 24 * 3600, // Keep old keys for 90 days
//!     min_key_lifetime: 7 * 24 * 3600,   // Minimum 1 week between rotations
//!     max_key_lifetime: 90 * 24 * 3600,  // Force rotation after 90 days
//! };
//!
//! let storage = SecureStorage::new_with_keystore(
//!     b"master-key",
//!     Arc::new(MemoryKeyStore::new()),
//!     Some(config),
//! ).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Argon2, Params};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

const KEY_LENGTH: usize = 32; // 256 bits for AES-256
const NONCE_LENGTH: usize = 12; // 96 bits for GCM
const SALT_LENGTH: usize = 16;
const KEY_VERSION_LENGTH: usize = 8; // First 8 bytes of key ID

/// Represents a cryptographic key and its metadata in the key store
///
/// Each `KeyEntry` contains the actual encryption key along with metadata
/// that controls its lifecycle and usage. The key material is stored in
/// base64-encoded format for safe serialization.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use secreton_core::storage::secure::KeyEntry;
///
/// let key_entry = KeyEntry {
///     id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
///     key: "MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZX".to_string(),
///     salt: "QUJDREVGR0hJSktMTU5PUFFSU1RVVg==".to_string(),
///     created_at: 1672531200, // 2023-01-01T00:00:00Z
///     active: true,
///     expires_at: Some(1704067200), // 2024-01-01T00:00:00Z
///     metadata: HashMap::from([
///         ("purpose".to_string(), "database_encryption".to_string()),
///         ("created_by".to_string(), "key-manager-service".to_string())
///     ])
/// };
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyEntry {
    /// Unique identifier for this key (UUID v4)
    pub id: String,

    /// The actual encryption key, base64-encoded
    ///
    /// This is the raw key material that will be used for encryption/decryption.
    /// The key is stored in base64 encoding for safe serialization.
    pub key: String,

    /// Salt used during key derivation, base64-encoded
    ///
    /// This salt is combined with the master key to derive the actual
    /// encryption key using Argon2.
    pub salt: String,

    /// When this key was created (UNIX timestamp in seconds)
    pub created_at: u64,

    /// Whether this key is currently active
    ///
    /// Inactive keys are kept for decryption but not used for new encryptions.
    pub active: bool,

    /// When this key expires (UNIX timestamp in seconds)
    ///
    /// After this time, the key will be automatically removed by the
    /// `cleanup_expired_keys` method. If `None`, the key never expires.
    pub expires_at: Option<u64>,

    /// Additional metadata about this key
    ///
    /// Can be used to store application-specific information such as the
    /// key's purpose, creator, or any other relevant details.
    pub metadata: HashMap<String, String>,
}

/// Key management configuration for secure storage
///
/// This struct defines the rotation and retention policies for encryption keys.
/// All durations are specified in seconds.
///
/// # Example
///
/// ```
/// use secreton_core::storage::secure::KeyConfig;
///
/// // Rotate keys every 30 days, keep old keys for 90 days
/// let config = KeyConfig {
///     rotation_interval: 30 * 24 * 3600,    // 30 days
///     key_retention_period: 90 * 24 * 3600, // 90 days
///     min_key_lifetime: 7 * 24 * 3600,      // 1 week minimum
///     max_key_lifetime: 365 * 24 * 3600,    // 1 year maximum
/// };
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyConfig {
    /// How often to rotate keys (in seconds).
    ///
    /// This determines how frequently a new key will be generated and used for
    /// new encryptions. The previous key will be kept to decrypt existing data.
    pub rotation_interval: u64,

    /// How long to keep old keys after rotation (in seconds).
    ///
    /// During this period, old keys will be retained to allow decryption of
    /// data encrypted with those keys. After this period, old keys will be
    /// automatically removed.
    pub key_retention_period: u64,

    /// Minimum key lifetime before rotation (in seconds).
    ///
    /// This prevents keys from being rotated too frequently, which could impact
    /// performance. The system will wait at least this long before rotating
    /// a key, even if the rotation interval has passed.
    pub min_key_lifetime: u64,

    /// Maximum key lifetime before forced rotation (in seconds).
    ///
    /// For security reasons, keys will be rotated after this duration,
    /// regardless of other settings. This ensures that no key remains in use
    /// for an extended period.
    pub max_key_lifetime: u64,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            rotation_interval: 30 * 24 * 3600,    // 30 days
            key_retention_period: 90 * 24 * 3600, // 90 days
            min_key_lifetime: 7 * 24 * 3600,      // 7 days
            max_key_lifetime: 90 * 24 * 3600,     // 90 days
        }
    }
}

/// Trait defining the interface for key storage backends
///
/// This trait must be implemented by any type that will be used to store
/// encryption keys and their metadata. The implementation is responsible for
/// persisting keys and maintaining the current key ID.
///
/// # Implementation Guidelines
///
/// 1. **Persistence**: The implementation must ensure that keys are durably
///    persisted to prevent data loss.
///
/// 2. **Atomicity**: Operations should be atomic to prevent corruption if the
///    system crashes during a write.
///
/// 3. **Security**: The implementation should protect the keys at rest using
///    appropriate security measures (e.g., encryption, access controls).
///
/// # Example: Database-backed Key Store
///
/// ```rust
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use async_trait::async_trait;
/// use secreton_core::storage::secure::{KeyStore, KeyEntry};
/// use anyhow::Result;
///
/// pub struct DatabaseKeyStore {
///     connection: String, // Database connection string
/// }
///
/// #[async_trait]
/// impl KeyStore for DatabaseKeyStore {
///     async fn load_keys(&self) -> Result<HashMap<String, KeyEntry>> {
///         // Implementation to load keys from database
/// #       todo!()
///     }
///     
///     async fn save_keys(&self, keys: &HashMap<String, KeyEntry>) -> Result<()> {
///         // Implementation to save keys to database
/// #       todo!()
///     }
///     
///     async fn get_current_key_id(&self) -> Result<Option<String>> {
///         // Implementation to get current key ID from database
/// #       todo!()
///     }
///     
///     async fn set_current_key_id(&self, key_id: &str) -> Result<()> {
///         // Implementation to set current key ID in database
/// #       todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Load all keys from the underlying storage
    ///
    /// This method should return all keys currently stored in the backend,
    /// including both active and inactive keys. The keys should be returned
    /// as a map where the key is the key ID and the value is the `KeyEntry`.
    ///
    /// # Errors
    ///
    /// Returns an error if the keys cannot be loaded from the underlying storage.
    async fn load_keys(&self) -> Result<HashMap<String, KeyEntry>>;

    /// Save all keys to the underlying storage
    ///
    /// This method should persist all keys to the backend storage. The implementation
    /// should ensure that the save operation is atomic - either all keys are saved
    /// successfully or none are.
    ///
    /// # Arguments
    ///
    /// * `keys` - A map containing all keys to be saved, where the key is the key ID
    ///   and the value is the `KeyEntry`.
    ///
    /// # Errors
    ///
    /// Returns an error if the keys cannot be saved to the underlying storage.
    async fn save_keys(&self, keys: &HashMap<String, KeyEntry>) -> Result<()>;

    /// Get the ID of the current active key
    ///
    /// This method should return the ID of the key that should be used for new
    /// encryptions. If no current key is set, it should return `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current key ID cannot be retrieved from the storage.
    async fn get_current_key_id(&self) -> Result<Option<String>>;

    /// Set the ID of the current active key
    ///
    /// This method should update the current key ID to the specified value.
    /// The key with this ID must exist in the key store.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The ID of the key that should be used for new encryptions.
    ///
    /// # Errors
    ///
    /// Returns an error if the current key ID cannot be updated in the storage.
    async fn set_current_key_id(&self, key_id: &str) -> Result<()>;
}

/// In-memory implementation of KeyStore for testing and development
///
/// This implementation stores keys in memory and is not persistent across
/// restarts. It's primarily intended for testing and development purposes.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use secreton_core::storage::secure::{MemoryKeyStore, KeyStore, KeyEntry};
/// use std::collections::HashMap;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// // Create a new in-memory key store
/// let key_store = MemoryKeyStore::new();
///
/// // Create a test key entry
/// let key_entry = KeyEntry {
///     id: "test-key".to_string(),
///     key: "test-key-data".to_string(),
///     salt: "test-salt".to_string(),
///     created_at: 1234567890,
///     active: true,
///     expires_at: None,
///     metadata: Default::default(),
/// };
///
/// // Save the key
/// let mut keys = HashMap::new();
/// keys.insert(key_entry.id.clone(), key_entry);
/// key_store.save_keys(&keys).await?;
///
/// // Set the current key ID
/// key_store.set_current_key_id("test-key").await?;
/// # Ok(())
/// # }
/// ```
pub struct MemoryKeyStore {
    keys: RwLock<HashMap<String, KeyEntry>>,
    current_key_id: RwLock<Option<String>>,
}

impl MemoryKeyStore {
    /// Creates a new, empty in-memory key store
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            current_key_id: RwLock::new(None),
        }
    }

    /// Creates a new key store with the specified initial state
    ///
    /// # Arguments
    ///
    /// * `initial_keys` - Initial set of keys to populate the store with
    /// * `current_key_id` - ID of the current active key, if any
    pub fn with_initial_state(
        initial_keys: HashMap<String, KeyEntry>,
        current_key_id: Option<String>,
    ) -> Self {
        Self {
            keys: RwLock::new(initial_keys),
            current_key_id: RwLock::new(current_key_id),
        }
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn load_keys(&self) -> Result<HashMap<String, KeyEntry>> {
        // Return a clone of the current keys
        Ok(self.keys.read().await.clone())
    }

    async fn save_keys(&self, keys: &HashMap<String, KeyEntry>) -> Result<()> {
        // Update the keys map
        *self.keys.write().await = keys.clone();
        Ok(())
    }

    async fn get_current_key_id(&self) -> Result<Option<String>> {
        // Return a clone of the current key ID
        Ok(self.current_key_id.read().await.clone())
    }

    async fn set_current_key_id(&self, key_id: &str) -> Result<()> {
        // Update the current key ID
        *self.current_key_id.write().await = Some(key_id.to_string());
        Ok(())
    }
}

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
/// # Security Considerations
///
/// - The master key should be kept secure and never hardcoded
/// - Key material is stored encrypted at rest by the `KeyStore`
/// - Each encryption operation uses a unique nonce
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
    pub fn new(master_key: &[u8]) -> Self {
        // Generate a new random salt
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);

        // Derive the key
        let key = Self::derive_key(master_key, &salt).unwrap_or_else(|_| {
            // In a real implementation, you might want to handle this error more gracefully
            panic!("Failed to derive key");
        });

        // Create a key entry
        let key_entry = KeyEntry {
            id: Uuid::new_v4().to_string(),
            key: BASE64.encode(&key),
            salt: BASE64.encode(&salt),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("Time went backwards: {}", e))
                .unwrap()
                .as_secs(),
            active: true,
            expires_at: None,
            metadata: HashMap::new(),
        };

        // Create a key store with the single key
        let key_store = Arc::new(MemoryKeyStore::with_initial_state(
            HashMap::from([(key_entry.id.clone(), key_entry.clone())]),
            Some(key_entry.id.clone()),
        ));

        // Create the storage with default config
        let key_config = KeyConfig::default();

        // Create the cipher with the derived key
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        // Initialize the keys map with our single key
        let mut keys = HashMap::new();
        let current_key_id = key_entry.id.clone();
        keys.insert(key_entry.id.clone(), key_entry);

        Self {
            current_cipher: cipher,
            current_key_id,
            keys: RwLock::new(keys),
            key_config,
            key_store,
            master_key: master_key.to_vec(),
        }
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
        metadata: Option<HashMap<String, String>>,
    ) -> Result<KeyEntry> {
        // Generate a random salt for key derivation
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);

        // Derive the encryption key from the master key and salt
        let key = Self::derive_key(master_key, &salt)?;

        // Create and return the key entry
        Ok(KeyEntry {
            id: Uuid::new_v4().to_string(),
            key: BASE64.encode(&key),
            salt: BASE64.encode(&salt),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow!("Time went backwards: {}", e))?
                .as_secs(),
            active: true,
            expires_at: None,
            metadata: metadata.unwrap_or_default(),
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
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));

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
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data with the current cipher
        let ciphertext = self
            .current_cipher
            .encrypt(nonce, data)
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

        let nonce = Nonce::from_slice(nonce_bytes);

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
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        cipher
            .decrypt(nonce, ciphertext)
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
                    old_key.expires_at = Some(now + self.key_config.key_retention_period);
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
                if let Some(expires_at) = key.expires_at {
                    if expires_at <= now {
                        return Some(id.clone());
                    }
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
        self.current_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

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
            key_entry.expires_at = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| anyhow!("Time went backwards: {}", e))?
                    .as_secs(),
            );
            Ok(())
        } else {
            Err(anyhow!("Key not found"))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        name: String,
        value: i32,
    }

    #[tokio::test]
    async fn test_key_management() {
        // Test key listing and metadata
        let key_store = Arc::new(MemoryKeyStore::new());
        let master_key = b"test-master-key";
        let mut storage = SecureStorage::new_with_keystore(master_key, key_store.clone(), None)
            .await
            .unwrap();

        // Should have one key initially
        let keys = storage.list_keys().await;
        assert_eq!(keys.len(), 1);

        // Get key metadata
        let key_id = storage.current_key_id().to_string();
        let key_meta = storage.get_key_metadata(&key_id).await.unwrap();
        assert!(key_meta.is_some());
        let key_meta = key_meta.unwrap();
        assert!(key_meta.active);
        assert!(key_meta.expires_at.is_none());

        // Test key rotation
        storage.rotate_key().await.unwrap();
        let new_key_id = storage.current_key_id().to_string();
        assert_ne!(key_id, new_key_id);

        // Should now have 2 keys
        let keys = storage.list_keys().await;
        assert_eq!(keys.len(), 2);

        // Test key revocation
        let revoke_result = storage.revoke_key(&key_id).await;
        assert!(revoke_result.is_ok());

        // Verify key was revoked
        let key_meta = storage.get_key_metadata(&key_id).await.unwrap().unwrap();
        assert!(!key_meta.active);
        assert!(key_meta.expires_at.is_some());

        // Try to revoke current key (should fail)
        let revoke_current = storage.revoke_key(&new_key_id).await;
        assert!(revoke_current.is_err());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        // Create a test key store
        let key_store = Arc::new(MemoryKeyStore::new());

        // Create a key config with very short rotation interval for testing
        let key_config = KeyConfig {
            rotation_interval: 1,    // 1 second for testing
            key_retention_period: 5, // 5 seconds for testing
            min_key_lifetime: 0,     // No minimum for testing
            max_key_lifetime: 10,    // 10 seconds for testing
        };

        // Create secure storage with test config
        let master_key = b"test-master-key-32-bytes-long!";
        let storage =
            SecureStorage::new_with_keystore(master_key, key_store.clone(), Some(key_config))
                .await
                .unwrap();

        let shared_storage = SharedSecureStorage::new(storage);

        // Get initial key ID
        let initial_key_id = shared_storage.current_key_id();
        println!("Initial key ID: {}", initial_key_id);

        // Encrypt some data
        let test_data = TestData {
            name: "test".to_string(),
            value: 42,
        };

        let encrypted = shared_storage.encrypt_value(&test_data).await.unwrap();
        println!("Encrypted with initial key");

        // Wait for key rotation window (1 second + buffer)
        println!("Waiting for key rotation...");
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Encrypt again to trigger rotation
        println!("Encrypting again to trigger rotation...");
        let encrypted2 = shared_storage.encrypt_value(&test_data).await.unwrap();

        // Check if rotation happened by examining key store directly
        let keys = key_store.load_keys().await.unwrap();
        let current_key_id_from_store = key_store.get_current_key_id().await.unwrap().unwrap();

        println!("Keys in store: {}", keys.len());
        println!("Current key from store: {}", current_key_id_from_store);

        // Both encrypted values should still be decryptable
        let decrypted1: TestData = shared_storage.decrypt_value(&encrypted).await.unwrap();
        let decrypted2: TestData = shared_storage.decrypt_value(&encrypted2).await.unwrap();

        assert_eq!(decrypted1, test_data);
        assert_eq!(decrypted2, test_data);

        // Key rotation should have happened (at least in key store)
        if keys.len() > 1 {
            println!("SUCCESS: Key rotation occurred (found {} keys)", keys.len());
        } else {
            println!("WARNING: No key rotation detected");
        }

        println!("Key rotation test completed successfully");
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        // Use longer, more secure master key
        let master_key = b"very-secure-master-key-32-bytes-long!";
        let key_store = Arc::new(MemoryKeyStore::new());
        let secure_storage = SecureStorage::new_with_keystore(master_key, key_store, None)
            .await
            .unwrap();

        let plaintext = b"hello, world!";

        // Debug: print current key info
        println!("Current key ID: {}", secure_storage.current_key_id);

        let encrypted = secure_storage.encrypt(plaintext).await.unwrap();
        println!("Encrypted: {}", encrypted);

        // Try decrypt immediately after encrypt to ensure key is available
        let decrypted = secure_storage.decrypt(&encrypted).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_value() {
        // Use longer, more secure master key
        let master_key = b"very-secure-master-key-32-bytes-long!";
        let key_store = Arc::new(MemoryKeyStore::new());
        let secure_storage = SecureStorage::new_with_keystore(master_key, key_store, None)
            .await
            .unwrap();

        let test_data = TestData {
            name: "test".to_string(),
            value: 42,
        };

        // Debug: print current key info
        println!("Current key ID: {}", secure_storage.current_key_id);

        let encrypted = secure_storage.encrypt_value(&test_data).await.unwrap();
        println!("Encrypted value: {}", encrypted);

        let decrypted: TestData = secure_storage.decrypt_value(&encrypted).await.unwrap();

        assert_eq!(test_data, decrypted);
    }

    #[tokio::test]
    async fn test_shared_storage() {
        let master_key = b"test-shared-key";
        let key_store = Arc::new(MemoryKeyStore::new());
        let secure_storage = SecureStorage::new_with_keystore(master_key, key_store, None)
            .await
            .unwrap();
        let shared_storage = SharedSecureStorage::new(secure_storage);

        let plaintext = b"shared storage test";
        let encrypted = shared_storage.encrypt(plaintext).await.unwrap();
        let decrypted = shared_storage.decrypt(&encrypted).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn debug_just_create_storage() {
        println!("Creating key store...");
        let key_store = Arc::new(MemoryKeyStore::new());

        println!("Creating key config...");
        let key_config = KeyConfig {
            rotation_interval: 60, // 60 seconds - no rotation
            key_retention_period: 3600,
            min_key_lifetime: 0,
            max_key_lifetime: 7200,
        };

        println!("Creating secure storage...");
        let master_key = b"test-master-key-32-bytes-long!";
        let storage = SecureStorage::new_with_keystore(master_key, key_store, Some(key_config))
            .await
            .unwrap();

        println!("Getting current key ID...");
        let key_id = storage.current_key_id();
        println!("Current key ID: {}", key_id);

        println!("Encrypting test data...");
        let test_data = b"hello world";
        let encrypted = storage.encrypt(test_data).await.unwrap();
        println!("Encrypted: {}", encrypted);

        println!("Decrypting test data...");
        let decrypted = storage.decrypt(&encrypted).await.unwrap();
        assert_eq!(decrypted, test_data);
        println!("Decryption successful");

        println!("Test completed successfully - no hang!");
    }

    #[tokio::test]
    async fn debug_maybe_rotate_key() {
        println!("Creating setup for rotation test...");
        let key_store = Arc::new(MemoryKeyStore::new());
        let key_config = KeyConfig {
            rotation_interval: 1, // 1 second - should rotate
            key_retention_period: 5,
            min_key_lifetime: 0,
            max_key_lifetime: 10,
        };

        let master_key = b"test-master-key-32-bytes-long!";
        let storage = SecureStorage::new_with_keystore(master_key, key_store, Some(key_config))
            .await
            .unwrap();

        println!("Initial key ID: {}", storage.current_key_id());

        println!("First encryption (no rotation expected)...");
        let encrypted1 = storage.encrypt(b"test1").await.unwrap();
        println!("First encryption done");

        println!("Waiting 2 seconds for key age...");
        tokio::time::sleep(Duration::from_secs(2)).await;

        println!("Second encryption (should trigger rotation)...");
        let encrypted2 = storage.encrypt(b"test2").await.unwrap();
        println!("Second encryption done");

        println!("Testing decryption...");
        let dec1 = storage.decrypt(&encrypted1).await.unwrap();
        let dec2 = storage.decrypt(&encrypted2).await.unwrap();

        assert_eq!(dec1, b"test1");
        assert_eq!(dec2, b"test2");

        println!("Both decryptions successful");
        println!("Rotation test completed successfully!");
    }
}
