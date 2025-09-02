use azure_storage_blobs::prelude::*;
use azure_core::auth::TokenCredential;
use azure_identity::DefaultAzureCredential;
use std::collections::HashMap;
use chrono::{Utc, Duration};
use crate::storage::{StorageBackend, StorageResult, StorageError};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct AzureBlobConfig {
    pub account_name: String,
    pub container_name: String,
    pub endpoint: Option<String>,
    pub use_emulator: bool,
}

pub struct AzureBlobStorage {
    config: AzureBlobConfig,
    client: BlobServiceClient,
}

impl AzureBlobStorage {
    pub async fn new(config: AzureBlobConfig) -> StorageResult<Self> {
        let endpoint = if config.use_emulator {
            "http://127.0.0.1:10000".to_string()
        } else {
            config.endpoint.unwrap_or_else(|| {
                format!("https://{}.blob.core.windows.net", config.account_name)
            })
        };

        let credential = DefaultAzureCredential::default();
        let client = BlobServiceClient::new(endpoint, credential);

        Ok(Self { config, client })
    }

    async fn ensure_container_exists(&self) -> StorageResult<()> {
        let container_client = self.client.container_client(&self.config.container_name);

        match container_client.create().await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Container might already exist
                if e.to_string().contains("ContainerAlreadyExists") {
                    Ok(())
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }
}

#[async_trait]
impl StorageBackend for AzureBlobStorage {
    async fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        match blob_client.get().await {
            Ok(response) => {
                let data = response.data.collect().await
                    .map_err(|e| StorageError::BackendError(e.to_string()))?;
                Ok(data.to_vec())
            }
            Err(e) => {
                if e.to_string().contains("BlobNotFound") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn put(&self, key: &str, value: &[u8], _options: Option<HashMap<String, String>>) -> StorageResult<()> {
        self.ensure_container_exists().await?;

        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        let mut options = HashMap::new();
        options.insert("Content-Type".to_string(), "application/octet-stream".to_string());

        match blob_client.put_block_blob(value.to_vec()).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(e.to_string())),
        }
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        match blob_client.delete().await {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.to_string().contains("BlobNotFound") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let container_client = self.client.container_client(&self.config.container_name);

        let mut keys = Vec::new();
        let mut stream = container_client.list_blobs().into_stream();

        while let Some(page) = stream.next().await {
            match page {
                Ok(page) => {
                    for blob in page.blobs {
                        let blob_name = blob.name;
                        if let Some(prefix) = prefix {
                            if blob_name.starts_with(prefix) {
                                keys.push(blob_name);
                            }
                        } else {
                            keys.push(blob_name);
                        }
                    }
                }
                Err(e) => return Err(StorageError::BackendError(e.to_string())),
            }
        }

        Ok(keys)
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        match blob_client.get_properties().await {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.to_string().contains("BlobNotFound") {
                    Ok(false)
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn size(&self, key: &str) -> StorageResult<u64> {
        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        match blob_client.get_properties().await {
            Ok(properties) => {
                if let Some(size) = properties.blob.properties.content_length {
                    Ok(size as u64)
                } else {
                    Err(StorageError::BackendError("Content length not available".to_string()))
                }
            }
            Err(e) => {
                if e.to_string().contains("BlobNotFound") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn copy(&self, from_key: &str, to_key: &str) -> StorageResult<()> {
        let container_client = self.client.container_client(&self.config.container_name);
        let source_url = format!(
            "{}/{}/{}",
            self.client.endpoint(),
            self.config.container_name,
            from_key
        );

        let dest_blob_client = container_client.blob_client(to_key);

        match dest_blob_client.copy_from_url(&source_url).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(e.to_string())),
        }
    }

    async fn get_metadata(&self, key: &str) -> StorageResult<HashMap<String, String>> {
        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        match blob_client.get_properties().await {
            Ok(properties) => {
                let mut metadata = HashMap::new();

                if let Some(content_type) = &properties.blob.properties.content_type {
                    metadata.insert("content_type".to_string(), content_type.clone());
                }

                if let Some(content_length) = properties.blob.properties.content_length {
                    metadata.insert("content_length".to_string(), content_length.to_string());
                }

                if let Some(last_modified) = &properties.blob.properties.last_modified {
                    metadata.insert("last_modified".to_string(), last_modified.to_string());
                }

                if let Some(etag) = &properties.blob.properties.etag {
                    metadata.insert("etag".to_string(), etag.clone());
                }

                Ok(metadata)
            }
            Err(e) => {
                if e.to_string().contains("BlobNotFound") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn set_metadata(&self, key: &str, metadata: HashMap<String, String>) -> StorageResult<()> {
        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        // Convert metadata to Azure blob metadata format
        let azure_metadata: std::collections::HashMap<String, String> = metadata
            .into_iter()
            .map(|(k, v)| (k, v))
            .collect();

        match blob_client.set_metadata(azure_metadata).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(e.to_string())),
        }
    }

    async fn list_prefixes(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let container_client = self.client.container_client(&self.config.container_name);

        let mut prefixes = Vec::new();
        let mut stream = container_client
            .list_blobs()
            .prefix(prefix)
            .delimiter("/")
            .into_stream();

        while let Some(page) = stream.next().await {
            match page {
                Ok(page) => {
                    for blob_prefix in page.blob_prefixes {
                        prefixes.push(blob_prefix.name.trim_end_matches('/').to_string());
                    }
                }
                Err(e) => return Err(StorageError::BackendError(e.to_string())),
            }
        }

        Ok(prefixes)
    }

    async fn put_with_ttl(&self, key: &str, value: &[u8], ttl_seconds: u64, _options: Option<HashMap<String, String>>) -> StorageResult<()> {
        // Azure Blob Storage doesn't have built-in TTL for individual blobs
        // We can implement this by storing metadata with expiration time
        // and checking it on retrieval

        self.ensure_container_exists().await?;

        let blob_client = self.client
            .container_client(&self.config.container_name)
            .blob_client(key);

        let expiration_time = Utc::now() + Duration::seconds(ttl_seconds as i64);

        let mut metadata = HashMap::new();
        metadata.insert("ttl_expiration".to_string(), expiration_time.to_rfc3339());

        match blob_client.put_block_blob(value.to_vec()).await {
            Ok(_) => {
                // Set metadata separately
                let azure_metadata: std::collections::HashMap<String, String> = metadata
                    .into_iter()
                    .collect();

                if let Err(e) = blob_client.set_metadata(azure_metadata).await {
                    return Err(StorageError::BackendError(e.to_string()));
                }
                Ok(())
            }
            Err(e) => Err(StorageError::BackendError(e.to_string())),
        }
    }

    async fn get_with_ttl_check(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        // First check if the blob exists and get its metadata
        let metadata = match self.get_metadata(key).await {
            Ok(metadata) => metadata,
            Err(StorageError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };

        // Check if TTL has expired
        if let Some(expiration_str) = metadata.get("ttl_expiration") {
            if let Ok(expiration) = chrono::DateTime::parse_from_rfc3339(expiration_str) {
                if Utc::now() > expiration {
                    // TTL expired, delete the blob
                    let _ = self.delete(key).await;
                    return Ok(None);
                }
            }
        }

        // TTL not expired or not set, return the data
        match self.get(key).await {
            Ok(data) => Ok(Some(data)),
            Err(StorageError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        let container_client = self.client.container_client(&self.config.container_name);

        match container_client.get_properties().await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(format!("Health check failed: {}", e))),
        }
    }

    fn backend_type(&self) -> &'static str {
        "azure_blob"
    }

    fn supports_ttl(&self) -> bool {
        true
    }

    fn supports_metadata(&self) -> bool {
        true
    }

    fn supports_prefix_listing(&self) -> bool {
        true
    }
}
