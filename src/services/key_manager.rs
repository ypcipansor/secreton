use std::sync::Arc;
use tokio::time::{self, Duration};
use crate::storage::StorageBackend;
use crate::utils::error::AppError;
use tracing::{info, error};

#[derive(Clone)]
pub struct KeyManager {
    storage: Arc<dyn StorageBackend>,
    rotation_interval: Duration,
}

impl KeyManager {
    pub fn new(storage: Arc<dyn StorageBackend>, rotation_interval: Duration) -> Self {
        Self {
            storage,
            rotation_interval,
        }
    }

    pub async fn rotate_keys(&self) -> Result<(), AppError> {
        info!("Initiating key rotation...");
        
        // 1. Generate new encryption key
        let new_key = self.generate_key()?;
        
        // 2. Re-encrypt data with new key (in batches for large datasets)
        self.re_encrypt_data(&new_key).await?;
        
        // 3. Update the active key
        self.storage.update_active_key(&new_key).await?;
        
        // 4. Keep the previous key for decryption of old data
        self.storage.archive_key(new_key).await?;
        
        info!("Key rotation completed successfully");
        Ok(())
    }
    
    fn generate_key(&self) -> Result<Vec<u8>, AppError> {
        // Use secure random generation
        let mut key = vec![0u8; 32]; // 256-bit key
        getrandom::getrandom(&mut key).map_err(|e| {
            error!("Failed to generate random key: {}", e);
            AppError::KeyGenerationError
        })?;
        Ok(key)
    }
    
    async fn re_encrypt_data(&self, new_key: &[u8]) -> Result<(), AppError> {
        // Implement batch processing for re-encryption
        // This is a simplified example
        let batch_size = 100;
        let mut last_id = None;
        
        loop {
            let batch = self.storage.get_secrets_batch(batch_size, last_id).await?;
            if batch.is_empty() {
                break;
            }
            
            for mut secret in batch {
                // Re-encrypt with new key
                // ...
                self.storage.update_secret(&secret).await?;
                last_id = Some(secret.id);
            }
        }
        
        Ok(())
    }
    
    pub async fn start_key_rotation_scheduler(self) {
        let mut interval = time::interval(self.rotation_interval);
        
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                if let Err(e) = self.rotate_keys().await {
                    error!("Key rotation failed: {}", e);
                }
            }
        });
    }
}
