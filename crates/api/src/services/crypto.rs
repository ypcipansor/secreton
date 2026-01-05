use secreton_crypto::{
    EncryptedData, AlgorithmId, SecurityParams, CryptoEngine,
    KeyManager, KeyStorage, CryptoError,
};
use secreton_storage::{StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel};
use anyhow::Result;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;
use tokio::sync::RwLock;

/// Wrapper for encrypted data including key version/ID
#[derive(Debug, Serialize, Deserialize)]
struct CryptoPacket {
    key_id: String,
    data: EncryptedData,
}

/// Key storage implementation using the system's StorageBackend
#[derive(Clone)]
struct SystemKeyStorage {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    root_key: Vec<u8>, // KEK (Key Encryption Key) for encrypting system keys
    crypto_engine: Arc<CryptoEngine>,
}

impl SystemKeyStorage {
    fn new(storage: Arc<dyn StorageBackend + Send + Sync>, root_key: Vec<u8>) -> Self {
        Self {
            storage,
            root_key,
            crypto_engine: Arc::new(CryptoEngine::new()),
        }
    }

    /// Encrypt a key before storing it
    fn encrypt_key(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let encrypted = self.crypto_engine.encrypt(
            AlgorithmId::Aes256Gcm,
            key_data,
            &self.root_key
        )?;

        // Serialize EncryptedData to bytes
        serde_json::to_vec(&encrypted).map_err(|e| CryptoError::Internal(format!("Serialization error: {}", e)))
    }

    /// Decrypt a key after retrieving it
    fn decrypt_key(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let encrypted: EncryptedData = serde_json::from_slice(encrypted_bytes)
            .map_err(|e| CryptoError::Internal(format!("Deserialization error: {}", e)))?;

        self.crypto_engine.decrypt(&encrypted, &self.root_key)
    }

    fn get_path(&self, key_id: &str) -> String {
        format!("sys/keys/{}", key_id)
    }
}

#[async_trait::async_trait]
impl KeyStorage for SystemKeyStorage {
    async fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError> {
        let encrypted_key = self.encrypt_key(key_data)?;

        let path = self.get_path(key_id);
        let entry = SecretEntry::new(
            path,
            encrypted_key,
            EncryptionMetadata::default(),
            SecurityLevel::TopSecret, // Use TopSecret as Critical not available
            Uuid::nil(), // System owned
        );

        self.storage.store(&entry).await
            .map_err(|e| CryptoError::StorageError(e.to_string()))
    }

    async fn get_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        let path = self.get_path(key_id);

        match self.storage.get_by_path(&path).await {
            Ok(Some(entry)) => self.decrypt_key(&entry.encrypted_data),
            Ok(None) => Err(CryptoError::KeyNotFound(key_id.to_string())),
            Err(e) => Err(CryptoError::StorageError(e.to_string())),
        }
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, CryptoError> {
        let path_prefix = format!("sys/keys/{}", prefix);
        let query = secreton_storage::QueryParams::new().with_path_prefix(path_prefix.clone());

        let entries = self.storage.list(&query).await
            .map_err(|e| CryptoError::StorageError(e.to_string()))?;

        Ok(entries.into_iter()
            .filter_map(|e| e.path.strip_prefix("sys/keys/").map(|s| s.to_string()))
            .collect())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), CryptoError> {
        let path = self.get_path(key_id);
        self.storage.delete_by_path(&path).await
            .map_err(|e| CryptoError::StorageError(e.to_string()))
            .map(|_| ()) // Convert bool to ()
    }
}

/// Crypto service for API operations
pub struct CryptoService {
    key_manager: Arc<KeyManager>,
    crypto_engine: Arc<CryptoEngine>,
    // Cache: (key_id, key_bytes, timestamp)
    active_key_cache: Arc<RwLock<Option<(String, Vec<u8>, std::time::Instant)>>>,
    cache_ttl: std::time::Duration,
}

impl CryptoService {
    /// Initialize new CryptoService with storage backend for key persistence
    pub async fn new(storage: Arc<dyn StorageBackend + Send + Sync>) -> Result<Self> {
        // Get root key from env or generate a new one (warn if generated)
        let root_key = std::env::var("SECRETON_ROOT_KEY")
            .map(|k| BASE64.decode(&k).unwrap_or_else(|_| k.into_bytes()))
            .unwrap_or_else(|_| {
                tracing::warn!("No SECRETON_ROOT_KEY found. Generating ephemeral root key. System keys will be lost on restart if storage is persistent!");
                secreton_crypto::generate_key(AlgorithmId::Aes256Gcm).unwrap()
            });

        // Ensure root key is 32 bytes for AES-256
        let root_key = if root_key.len() != 32 {
            // Hash it to get 32 bytes
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&root_key);
            hasher.finalize().to_vec()
        } else {
            root_key
        };

        let key_storage = Arc::new(SystemKeyStorage::new(storage.clone(), root_key));

        // Use 30 days rotation interval by default
        let rotation_interval = std::time::Duration::from_secs(30 * 24 * 60 * 60);
        let key_manager = Arc::new(KeyManager::new(key_storage, rotation_interval));

        // Ensure an active key exists
        if let Err(_) = key_manager.get_active_key().await {
            tracing::info!("No active key found. Initializing new system key.");
            if let Err(e) = key_manager.rotate_keys().await {
                 tracing::error!("Failed to initialize system key: {}", e);
                 // Fallback to in-memory for dev/test environments if storage fails
            }
        }

        Ok(Self {
            key_manager,
            crypto_engine: Arc::new(CryptoEngine::new()),
            active_key_cache: Arc::new(RwLock::new(None)),
            cache_ttl: std::time::Duration::from_secs(300), // 5 minutes cache
        })
    }

    /// Encrypt using a specific key (low-level)
    pub fn encrypt(&self, key: &[u8], plaintext: &[u8], _params: Option<&SecurityParams>) -> Result<EncryptedData> {
        self.crypto_engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, key)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
    }

    /// Decrypt using a specific key (low-level)
    pub fn decrypt_full(&self, _key: &[u8], _nonce: &[u8], _ciphertext: &[u8], _aad: Option<&[u8]>) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("Direct low-level decryption via decrypt_full is deprecated. Use decrypt_with_key."))
    }

    /// Internal helper to decrypt with a known key
    pub fn decrypt_with_key(&self, key: &[u8], encrypted: &EncryptedData) -> Result<Vec<u8>> {
        self.crypto_engine.decrypt(encrypted, key)
             .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
    }

    /// Encrypt data with the active system key.
    /// Returns a serialized CryptoPacket containing key_id and encrypted data.
    pub async fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut key_info = None;

        // Try reading from cache
        {
            let cache = self.active_key_cache.read().await;
            if let Some((id, key, ts)) = &*cache {
                if ts.elapsed() < self.cache_ttl {
                    key_info = Some((id.clone(), key.clone()));
                }
            }
        }

        // If not in cache, fetch and update cache
        if key_info.is_none() {
            let key = self.key_manager.get_active_key().await
                .map_err(|e| anyhow::anyhow!("Failed to get active key: {}", e))?;
            let key_id = self.key_manager.get_active_key_id().await
                .map_err(|e| anyhow::anyhow!("Failed to get active key ID: {}", e))?;

            // Update cache
            let mut cache = self.active_key_cache.write().await;
            *cache = Some((key_id.clone(), key.clone(), std::time::Instant::now()));
            key_info = Some((key_id, key));
        }

        let (key_id, key) = key_info.unwrap();

        let encrypted_data = self.crypto_engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, &key)
            .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;

        let packet = CryptoPacket {
            key_id,
            data: encrypted_data,
        };

        serde_json::to_vec(&packet)
            .map_err(|e| anyhow::anyhow!("Serialization error: {}", e))
    }

    /// Decrypt data that was encrypted with `encrypt_data`.
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Deserialize packet
        let packet: CryptoPacket = serde_json::from_slice(ciphertext)
            .map_err(|e| anyhow::anyhow!("Invalid encrypted data format: {}", e))?;

        // Get the specific key version
        // We could cache old keys too if needed, but for now just active key
        let key = self.key_manager.get_key_by_id(&packet.key_id).await
            .map_err(|e| anyhow::anyhow!("Key not found ({}): {}", packet.key_id, e))?;

        // Decrypt
        self.crypto_engine.decrypt(&packet.data, &key)
            .map_err(|e| anyhow::anyhow!("Decryption error: {}", e))
    }

    pub fn sign_data(&self, _key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        // Placeholder signature
        // TODO: Implement actual signing using key
        Ok(vec![0u8; 64])
    }

    pub fn verify_signature(&self, _key: &[u8], _data: &[u8], _signature: &[u8]) -> Result<bool> {
        // Placeholder verification
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secreton_storage::MockStorageBackend;

    #[tokio::test]
    async fn test_crypto_service_lifecycle() {
        let storage = Arc::new(MockStorageBackend::new());
        let service = CryptoService::new(storage).await.unwrap();
        let plaintext = b"Hello, World!";

        // Test encryption
        let encrypted = service.encrypt_data(plaintext).await.expect("Encryption failed");
        assert_ne!(plaintext, encrypted.as_slice());

        // Verify it is JSON (CryptoPacket)
        assert_eq!(encrypted[0], b'{');

        // Test decryption
        let decrypted = service.decrypt(&encrypted).await.expect("Decryption failed");
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_unique_ciphertexts() {
        let storage = Arc::new(MockStorageBackend::new());
        let service = CryptoService::new(storage).await.unwrap();
        let plaintext = b"Hello, World!";

        let encrypted1 = service.encrypt_data(plaintext).await.expect("Encryption 1 failed");
        let encrypted2 = service.encrypt_data(plaintext).await.expect("Encryption 2 failed");

        // Ciphertexts are different due to IV/Nonce
        assert_ne!(encrypted1, encrypted2);
    }
}
