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
//! let storage: SecureStorage<MemoryKeyStore> = SecureStorage::new_with_keystore(
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
//! let storage: SecureStorage<MemoryKeyStore> = SecureStorage::new_with_keystore(
//!     b"master-key",
//!     Arc::new(MemoryKeyStore::new()),
//!     Some(config),
//! ).await?;
//! # Ok(())
//! # }
//! ```

// Module declarations
pub mod keystore;
pub mod storage;
pub mod types;

// Re-exports for public API
pub use types::{KeyConfig, KeyEntry};
// pub use keystore::{KeyStore, MemoryKeyStore};
pub use storage::{SecureStorage, SharedSecureStorage};

// Required imports for cryptographic operations
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

// Import constants from storage module
const KEY_VERSION_LENGTH: usize = 8; // First 8 bytes of key ID
const NONCE_LENGTH: usize = 12; // 96 bits for GCM
const KEY_LENGTH: usize = 32; // 256 bits for AES-256
const SALT_LENGTH: usize = 16;

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestData {
    name: String,
    value: i32,
}

/// Key management configuration for secure storage
/// This struct defines the rotation and retention policies for encryption keys.
/// All durations are specified in seconds.
/// # Example
/// ```
/// use secreton_core::storage::secure::KeyConfig;
/// // Rotate keys every 30 days, keep old keys for 90 days
/// let config = KeyConfig {
///     rotation_interval: 30 * 24 * 3600,    // 30 days
///     key_retention_period: 90 * 24 * 3600, // 90 days
///     min_key_lifetime: 7 * 24 * 3600,      // 1 week minimum
///     max_key_lifetime: 365 * 24 * 3600,    // 1 year maximum
/// };
/// ```
/// This trait must be implemented by any type that will be used to store
/// encryption keys and their metadata. The implementation is responsible for
/// persisting keys and maintaining the current key ID.
/// # Implementation Guidelines
/// 1. **Persistence**: The implementation must ensure that keys are durably
///    persisted to prevent data loss.
/// 2. **Atomicity**: Operations should be atomic to prevent corruption if the
///    system crashes during a write.
/// 3. **Security**: The implementation should protect the keys at rest using
///    appropriate security measures (e.g., encryption, access controls).
/// # Example: Database-backed Key Store
/// ```rust
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use async_trait::async_trait;
/// use secreton_core::storage::secure::{KeyStore, KeyEntry};
/// use anyhow::Result;
/// pub struct DatabaseKeyStore {
///     connection: String, // Database connection string
/// }
/// #[async_trait]
/// impl KeyStore for DatabaseKeyStore {
///     async fn load_keys(&self) -> Result<HashMap<String, KeyEntry>> {
///         // Implementation to load keys from database
///         // This would typically involve:
///         // 1. Connecting to the database
///         // 2. Querying the keys table
///         // 3. Deserializing the key data
///         // 4. Returning the HashMap of keys
///         Ok(HashMap::new()) // Placeholder implementation
///     }
///     
///     async fn save_keys(&self, keys: &HashMap<String, KeyEntry>) -> Result<()> {
///         // Implementation to save keys to database
///         // This would typically involve:
///         // 1. Connecting to the database
///         // 2. Serializing the key data
///         // 3. Inserting/updating records in the keys table
///         // 4. Ensuring atomicity of the operation
///         Ok(()) // Placeholder implementation
///     }
///     
///     async fn get_current_key_id(&self) -> Result<Option<String>> {
///         // Implementation to get current key ID from database
///         // This would typically involve:
///         // 1. Connecting to the database
///         // 2. Querying a configuration or metadata table
///         // 3. Returning the current key ID if set
///         Ok(None) // Placeholder implementation
///     }
///     
///     async fn set_current_key_id(&self, key_id: &str) -> Result<()> {
///         // Implementation to set current key ID in database
///         // This would typically involve:
///         // 1. Connecting to the database
///         // 2. Updating a configuration or metadata table
///         // 3. Ensuring the key exists before setting it as current
///         Ok(()) // Placeholder implementation
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
    async fn load_keys(&self) -> Result<HashMap<String, KeyEntry>, anyhow::Error>;

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
    async fn save_keys(&self, keys: &HashMap<String, KeyEntry>) -> Result<(), anyhow::Error>;

    /// Get the ID of the current active key
    ///
    /// This method should return the ID of the key that should be used for new
    /// encryptions. If no current key is set, it should return `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if the current key ID cannot be retrieved from the storage.
    async fn get_current_key_id(&self) -> Result<Option<String>, anyhow::Error>;

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
    async fn set_current_key_id(&self, key_id: &str) -> Result<(), anyhow::Error>;
}

/// In-memory implementation of KeyStore for testing and development
/// This implementation stores keys in memory and is not persistent across
/// restarts. It's primarily intended for testing and development purposes.
/// # Example
/// ```rust
/// use std::sync::Arc;
/// use secreton_core::storage::secure::{MemoryKeyStore, KeyStore, KeyEntry};
/// use std::collections::HashMap;
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// // Create a new in-memory key store
/// let key_store = MemoryKeyStore::new();
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
/// // Save the key
/// let mut keys = HashMap::new();
/// keys.insert(key_entry.id.clone(), key_entry);
/// key_store.save_keys(&keys).await?;
/// // Set the current key ID
/// key_store.set_current_key_id("test-key").await?;
/// # Ok(())
/// # }

/// In-memory implementation of KeyStore for testing and development
/// This implementation stores keys in memory and is not persistent across
/// restarts. It's primarily intended for testing and development purposes.
#[derive(Debug)]
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
#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn load_keys(&self) -> Result<HashMap<String, KeyEntry>, anyhow::Error> {
        // Return a clone of the current keys
        Ok(self.keys.read().await.clone())
    }

    async fn save_keys(&self, keys: &HashMap<String, KeyEntry>) -> Result<(), anyhow::Error> {
        // Update the keys map
        *self.keys.write().await = keys.clone();
        Ok(())
    }

    async fn get_current_key_id(&self) -> Result<Option<String>, anyhow::Error> {
        // Return a clone of the current key ID
        Ok(self.current_key_id.read().await.clone())
    }

    async fn set_current_key_id(&self, key_id: &str) -> Result<(), anyhow::Error> {
        // Update the current key ID
        *self.current_key_id.write().await = Some(key_id.to_string());
        Ok(())
    }
}
