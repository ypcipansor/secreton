use crate::error::CryptoError;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{self, Duration};
use tracing::{error, info};

// Simple key-value storage trait for key manager
#[async_trait::async_trait]
pub trait KeyStorage: Send + Sync {
    async fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError>;
    async fn get_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError>;
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, CryptoError>;
    async fn delete_key(&self, key_id: &str) -> Result<(), CryptoError>;
}

// In-memory implementation for key storage
#[derive(Clone)]
pub struct InMemoryKeyStorage {
    keys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl InMemoryKeyStorage {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl KeyStorage for InMemoryKeyStorage {
    async fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| CryptoError::Internal("Lock poisoned".to_string()))?;
        keys.insert(key_id.to_string(), key_data.to_vec());
        Ok(())
    }

    async fn get_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| CryptoError::Internal("Lock poisoned".to_string()))?;
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, CryptoError> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| CryptoError::Internal("Lock poisoned".to_string()))?;
        Ok(keys
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), CryptoError> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| CryptoError::Internal("Lock poisoned".to_string()))?;
        keys.remove(key_id);
        Ok(())
    }
}

#[derive(Clone)]
pub struct KeyManager {
    storage: Arc<dyn KeyStorage>,
    rotation_interval: Duration,
}

impl KeyManager {
    pub fn new(storage: Arc<dyn KeyStorage>, rotation_interval: Duration) -> Self {
        Self {
            storage,
            rotation_interval,
        }
    }

    pub async fn rotate_keys(&self) -> Result<(), CryptoError> {
        info!("Initiating key rotation...");

        // 1. Generate new encryption key
        let new_key = self.generate_key()?;
        let new_key_id = format!("key_{}", chrono::Utc::now().timestamp());

        // 2. Store the new key
        self.storage.store_key(&new_key_id, &new_key).await?;

        // 3. Re-encrypt data with new key (in batches for large datasets)
        self.re_encrypt_data(&new_key_id, &new_key).await?;

        // 4. Update the active key
        self.update_active_key(&new_key_id).await?;

        // 5. Keep the previous key for decryption of old data
        // Previous keys are kept for decryption compatibility

        info!("Key rotation completed successfully");
        Ok(())
    }

    fn generate_key(&self) -> Result<Vec<u8>, CryptoError> {
        // Use secure random generation
        let mut key = vec![0u8; 32]; // 256-bit key
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    async fn re_encrypt_data(&self, new_key_id: &str, _new_key: &[u8]) -> Result<(), CryptoError> {
        // Get all existing keys that need re-encryption
        let all_keys = self.storage.list_keys("encrypted_data/").await?;

        for key_path in all_keys {
            // Retrieve encrypted data
            let _encrypted_data = self.storage.get_key(&key_path).await?;

            // For this implementation, we'll just mark the data as needing re-encryption
            // In a full implementation, this would decrypt with old key and re-encrypt with new key
            info!(
                "Marking {} for re-encryption with key {}",
                key_path, new_key_id
            );

            // Store re-encryption marker
            let marker_key = format!("reencrypt_{}", key_path);
            let marker_data = format!("new_key:{}", new_key_id);
            self.storage
                .store_key(&marker_key, marker_data.as_bytes())
                .await?;
        }

        Ok(())
    }

    async fn update_active_key(&self, new_key_id: &str) -> Result<(), CryptoError> {
        // Store the active key reference
        self.storage
            .store_key("active_key_ref", new_key_id.as_bytes())
            .await?;

        Ok(())
    }

    pub async fn get_active_key(&self) -> Result<Vec<u8>, CryptoError> {
        // Try to get from storage first
        match self.storage.get_key("active_key_ref").await {
            Ok(key_id_bytes) => {
                let active_key_id = String::from_utf8(key_id_bytes)
                    .map_err(|_| CryptoError::Internal("Invalid key ID format".to_string()))?;
                self.storage.get_key(&active_key_id).await
            }
            Err(_) => {
                // Fallback to default key
                self.storage.get_key("active_key").await
            }
        }
    }

    pub async fn get_key_by_id(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        self.storage.get_key(key_id).await
    }

    pub async fn archive_key(&self, key_id: &str) -> Result<(), CryptoError> {
        // Move key to archive (just add archive prefix for now)
        let archived_key_id = format!("archived/{}", key_id);
        let key_data = self.storage.get_key(key_id).await?;
        self.storage.store_key(&archived_key_id, &key_data).await?;
        self.storage.delete_key(key_id).await?;
        Ok(())
    }

    pub async fn start_key_rotation_scheduler(&self) {
        let storage = Arc::clone(&self.storage);
        let rotation_interval = self.rotation_interval;

        tokio::spawn(async move {
            let mut interval = time::interval(rotation_interval);
            let key_manager = KeyManager {
                storage,
                rotation_interval,
            };

            loop {
                interval.tick().await;
                if let Err(e) = key_manager.rotate_keys().await {
                    error!("Key rotation failed: {}", e);
                }
            }
        });
    }
}
