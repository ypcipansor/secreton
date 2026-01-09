use crate::config::ApiConfig;
use secreton_storage::{
    EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend, StorageError, StorageResult,
};
use serde_json;
use tracing::{error, info};
use uuid::Uuid;

const CONFIG_PATH: &str = "sys/config/main";

pub struct ConfigService;

impl ConfigService {
    /// Save configuration to storage
    pub async fn save_config(
        storage: &dyn StorageBackend,
        config: &ApiConfig,
    ) -> StorageResult<()> {
        info!("Saving configuration to storage");

        let config_json = serde_json::to_vec(config).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        // In a real implementation, this should be encrypted with a system key.
        // For now, we store it as "encrypted_data" but it's just JSON bytes.
        // The StorageBackend might handle encryption at rest depending on configuration.

        let entry = SecretEntry::new(
            CONFIG_PATH.to_string(),
            config_json,
            EncryptionMetadata::default(), // Use default metadata
            SecurityLevel::Secret, // High security for config
            Uuid::nil(), // System owned
        );

        storage.store(&entry).await?;
        info!("Configuration saved successfully");
        Ok(())
    }

    /// Load configuration from storage
    pub async fn load_config(storage: &dyn StorageBackend) -> StorageResult<ApiConfig> {
        info!("Loading configuration from storage");

        match storage.get_by_path(CONFIG_PATH).await? {
            Some(entry) => {
                let config: ApiConfig = serde_json::from_slice(&entry.encrypted_data).map_err(|e| {
                    error!("Failed to deserialize configuration: {}", e);
                    StorageError::SerializationError {
                        message: "Failed to deserialize stored configuration".to_string(),
                    }
                })?;
                info!("Configuration loaded successfully");
                Ok(config)
            }
            None => {
                info!("No stored configuration found, using defaults");
                Ok(ApiConfig::default())
            }
        }
    }
}
