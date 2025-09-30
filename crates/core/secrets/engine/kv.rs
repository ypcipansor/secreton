use super::{EngineMetrics, Secret, SecretMetadata, SecretsEngine, SecretsError};
use anyhow;
use async_trait::async_trait;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// KV Secrets Engine for file-based secret storage
pub struct KVSecretsEngine {
    base_path: PathBuf,
}

impl KVSecretsEngine {
    /// Create a new KV secrets engine with the specified base path
    pub async fn new<P: AsRef<Path>>(base_path: P) -> Result<Self, SecretsError> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create base directory if it doesn't exist
        if !base_path.exists() {
            fs::create_dir_all(&base_path).await?;
        }

        Ok(Self { base_path })
    }

    fn get_secret_path(&self, path: &str) -> PathBuf {
        // Sanitize path to prevent directory traversal
        let sanitized_path = path.replace("..", "").replace('\\', "/");
        self.base_path.join(sanitized_path).with_extension("json")
    }
}

#[async_trait]
impl SecretsEngine for KVSecretsEngine {
    fn engine_type(&self) -> &'static str {
        "kv"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        let now = chrono::Utc::now();
        let metadata = SecretMetadata {
            created_at: now,
            updated_at: now,
            version: 1,
            ttl: None,
            expired_at: None,
            custom_metadata: None,
        };

        let secret = Secret {
            id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            data: data.clone(),
            metadata,
        };

        let secret_path = self.get_secret_path(path);

        // Create parent directories if they don't exist
        if let Some(parent) = secret_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                SecretsError::Other(anyhow::anyhow!("Failed to create directory: {}", e))
            })?;
        }

        // Write the secret to disk
        let secret_json = serde_json::to_vec_pretty(&secret)?;
        let mut file = fs::File::create(&secret_path).await?;
        file.write_all(&secret_json).await?;

        Ok(secret)
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        let secret_path = self.get_secret_path(path);

        if !secret_path.exists() {
            return Err(SecretsError::NotFound(format!(
                "Secret not found: {}",
                path
            )));
        }

        let secret_data = fs::read_to_string(&secret_path).await?;
        let secret: Secret = serde_json::from_str(&secret_data)?;

        Ok(secret)
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        let mut secret = self.read_secret(path).await?;

        // Update the secret data and metadata
        secret.data = data;
        secret.metadata.updated_at = chrono::Utc::now();
        secret.metadata.version += 1;

        // Write the updated secret back to disk
        let secret_path = self.get_secret_path(path);
        let secret_json = serde_json::to_vec_pretty(&secret)?;
        let mut file = fs::File::create(&secret_path).await?;
        file.write_all(&secret_json).await?;

        Ok(secret)
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        let secret_path = self.get_secret_path(path);

        if !secret_path.exists() {
            return Err(SecretsError::NotFound(format!(
                "Secret not found: {}",
                path
            )));
        }

        fs::remove_file(secret_path).await?;
        Ok(())
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError> {
        let dir_path = self.base_path.join(path);
        let mut entries = fs::read_dir(&dir_path).await?;
        let mut secrets = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            if let Ok(file_name) = entry.file_name().into_string() {
                if file_name.ends_with(".json") {
                    if let Some(secret_name) = file_name.strip_suffix(".json") {
                        secrets.push(secret_name.to_string());
                    }
                }
            }
        }

        Ok(secrets)
    }

    /// Collect metrics for this engine
    async fn collect_metrics(&self) -> Result<EngineMetrics, super::SecretsError> {
        let mut metrics = EngineMetrics {
            engine_type: self.engine_type().to_string(),
            secrets_created: 0,
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets: 0,
            storage_size_bytes: 0,
        };

        // Calculate active secrets and storage size
        let mut entries = fs::read_dir(&self.base_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Ok(file_name) = entry.file_name().into_string() {
                if file_name.ends_with(".json") {
                    metrics.active_secrets += 1;

                    // Calculate storage size
                    let file_path = self.base_path.join(&file_name);
                    let file_size = fs::metadata(&file_path).await?.len();
                    metrics.storage_size_bytes += file_size;
                }
            }
        }

        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_kv_secrets_engine() -> anyhow::Result<()> {
        // Create a temporary directory for testing
        let temp_dir = tempdir()?;
        let engine = KVSecretsEngine::new(temp_dir.path()).await?;

        // Test creating a secret
        let secret_data = serde_json::json!({ "username": "testuser", "password": "testpass" });
        let secret = engine
            .create_secret("test/secret", secret_data.clone(), None)
            .await?;

        assert_eq!(secret.path, "test/secret");
        assert_eq!(secret.data, secret_data);
        assert_eq!(secret.metadata.version, 1);

        // Test reading the secret
        let read_secret = engine.read_secret("test/secret").await?;
        assert_eq!(read_secret.data, secret_data);

        // Test updating the secret
        let updated_data =
            serde_json::json!({ "username": "updateduser", "password": "updatedpass" });
        let updated_secret = engine
            .update_secret("test/secret", updated_data.clone(), None)
            .await?;

        assert_eq!(updated_secret.data, updated_data);
        assert_eq!(updated_secret.metadata.version, 2);

        // Test listing secrets
        let secrets = engine.list_secrets("test").await?;
        assert_eq!(secrets, vec!["secret"]);

        // Test metrics collection
        let metrics = engine.collect_metrics().await?;
        assert_eq!(metrics.engine_type, "kv");
        assert_eq!(metrics.active_secrets, 1);
        assert!(metrics.storage_size_bytes > 0);

        // Test deleting the secret
        engine.delete_secret("test/secret").await?;
        assert!(engine.read_secret("test/secret").await.is_err());

        Ok(())
    }
}
