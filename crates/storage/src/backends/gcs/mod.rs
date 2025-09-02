use google_cloud_storage::client::{Client, ClientConfig};
use google_cloud_storage::http::buckets::get::GetBucketRequest;
use google_cloud_storage::http::objects::download::Range;
use google_cloud_storage::http::objects::get::GetObjectRequest;
use google_cloud_storage::http::objects::upload::{UploadObjectRequest, UploadType};
use google_cloud_storage::http::objects::delete::DeleteObjectRequest;
use google_cloud_storage::http::objects::list::ListObjectsRequest;
use google_cloud_storage::http::objects::Object;
use std::collections::HashMap;
use chrono::{Utc, Duration};
use crate::storage::{StorageBackend, StorageResult, StorageError};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct GcsConfig {
    pub project_id: String,
    pub bucket_name: String,
    pub credentials_path: Option<String>,
}

pub struct GoogleCloudStorage {
    config: GcsConfig,
    client: Client,
}

impl GoogleCloudStorage {
    pub async fn new(config: GcsConfig) -> StorageResult<Self> {
        let client_config = if let Some(credentials_path) = &config.credentials_path {
            ClientConfig::with_credentials(credentials_path).await
                .map_err(|e| StorageError::BackendError(e.to_string()))?
        } else {
            ClientConfig::default()
        };

        let client = Client::new(client_config);

        Ok(Self { config, client })
    }

    async fn ensure_bucket_exists(&self) -> StorageResult<()> {
        let get_bucket_req = GetBucketRequest {
            bucket: self.config.bucket_name.clone(),
            ..Default::default()
        };

        match self.client.buckets().get(get_bucket_req).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.to_string().contains("404") {
                    Err(StorageError::BackendError(format!("Bucket {} does not exist", self.config.bucket_name)))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }
}

#[async_trait]
impl StorageBackend for GoogleCloudStorage {
    async fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        let get_object_req = GetObjectRequest {
            bucket: self.config.bucket_name.clone(),
            object: key.to_string(),
            ..Default::default()
        };

        match self.client.objects().download(get_object_req, &Range::default()).await {
            Ok(data) => Ok(data),
            Err(e) => {
                if e.to_string().contains("404") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn put(&self, key: &str, value: &[u8], options: Option<HashMap<String, String>>) -> StorageResult<()> {
        self.ensure_bucket_exists().await?;

        let mut upload_req = UploadObjectRequest {
            bucket: self.config.bucket_name.clone(),
            ..Default::default()
        };

        // Set content type if provided
        if let Some(opts) = &options {
            if let Some(content_type) = opts.get("content_type") {
                upload_req.content_type = Some(content_type.clone());
            }
        }

        let upload_type = UploadType::Simple(upload_req);

        match self.client.objects().upload_object(value.to_vec(), upload_type).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(e.to_string())),
        }
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let delete_req = DeleteObjectRequest {
            bucket: self.config.bucket_name.clone(),
            object: key.to_string(),
            ..Default::default()
        };

        match self.client.objects().delete(delete_req).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.to_string().contains("404") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let mut list_req = ListObjectsRequest {
            bucket: self.config.bucket_name.clone(),
            ..Default::default()
        };

        if let Some(prefix) = prefix {
            list_req.prefix = Some(prefix.to_string());
        }

        let mut keys = Vec::new();
        let mut stream = self.client.objects().list(list_req).await?;

        while let Some(page) = stream.next().await {
            match page {
                Ok(page) => {
                    for object in page.items {
                        keys.push(object.name);
                    }
                }
                Err(e) => return Err(StorageError::BackendError(e.to_string())),
            }
        }

        Ok(keys)
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let get_req = GetObjectRequest {
            bucket: self.config.bucket_name.clone(),
            object: key.to_string(),
            ..Default::default()
        };

        match self.client.objects().get(get_req, None).await {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.to_string().contains("404") {
                    Ok(false)
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn size(&self, key: &str) -> StorageResult<u64> {
        let get_req = GetObjectRequest {
            bucket: self.config.bucket_name.clone(),
            object: key.to_string(),
            ..Default::default()
        };

        match self.client.objects().get(get_req, None).await {
            Ok(object) => {
                if let Some(size) = object.size {
                    Ok(size as u64)
                } else {
                    Err(StorageError::BackendError("Size not available".to_string()))
                }
            }
            Err(e) => {
                if e.to_string().contains("404") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn copy(&self, from_key: &str, to_key: &str) -> StorageResult<()> {
        let copy_req = google_cloud_storage::http::objects::copy::CopyObjectRequest {
            source_bucket: self.config.bucket_name.clone(),
            source_object: from_key.to_string(),
            destination_bucket: self.config.bucket_name.clone(),
            destination_object: to_key.to_string(),
            ..Default::default()
        };

        match self.client.objects().copy(copy_req).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(e.to_string())),
        }
    }

    async fn get_metadata(&self, key: &str) -> StorageResult<HashMap<String, String>> {
        let get_req = GetObjectRequest {
            bucket: self.config.bucket_name.clone(),
            object: key.to_string(),
            ..Default::default()
        };

        match self.client.objects().get(get_req, None).await {
            Ok(object) => {
                let mut metadata = HashMap::new();

                if let Some(content_type) = object.content_type {
                    metadata.insert("content_type".to_string(), content_type);
                }

                if let Some(size) = object.size {
                    metadata.insert("size".to_string(), size.to_string());
                }

                if let Some(updated) = object.updated {
                    metadata.insert("last_modified".to_string(), updated.to_rfc3339());
                }

                if let Some(etag) = object.etag {
                    metadata.insert("etag".to_string(), etag);
                }

                // Add custom metadata if present
                if let Some(custom_metadata) = object.metadata {
                    for (key, value) in custom_metadata {
                        metadata.insert(format!("metadata_{}", key), value);
                    }
                }

                Ok(metadata)
            }
            Err(e) => {
                if e.to_string().contains("404") {
                    Err(StorageError::NotFound(key.to_string()))
                } else {
                    Err(StorageError::BackendError(e.to_string()))
                }
            }
        }
    }

    async fn set_metadata(&self, key: &str, metadata: HashMap<String, String>) -> StorageResult<()> {
        // GCS requires getting the current object, updating metadata, and re-uploading
        let get_req = GetObjectRequest {
            bucket: self.config.bucket_name.clone(),
            object: key.to_string(),
            ..Default::default()
        };

        let current_object = match self.client.objects().get(get_req, None).await {
            Ok(obj) => obj,
            Err(e) => {
                if e.to_string().contains("404") {
                    return Err(StorageError::NotFound(key.to_string()));
                } else {
                    return Err(StorageError::BackendError(e.to_string()));
                }
            }
        };

        // Get the current data
        let data = self.get(key).await?;

        // Prepare update request with new metadata
        let mut update_req = google_cloud_storage::http::objects::update::UpdateObjectRequest {
            bucket: self.config.bucket_name.clone(),
            object: key.to_string(),
            ..Default::default()
        };

        // Convert metadata to GCS format
        let mut gcs_metadata = HashMap::new();
        for (k, v) in metadata {
            if k.starts_with("metadata_") {
                gcs_metadata.insert(k.trim_start_matches("metadata_").to_string(), v);
            } else {
                // Handle standard metadata fields
                match k.as_str() {
                    "content_type" => update_req.content_type = Some(v),
                    _ => {} // Ignore other fields for now
                }
            }
        }

        if !gcs_metadata.is_empty() {
            update_req.metadata = Some(gcs_metadata);
        }

        match self.client.objects().update(update_req).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(e.to_string())),
        }
    }

    async fn list_prefixes(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let list_req = ListObjectsRequest {
            bucket: self.config.bucket_name.clone(),
            prefix: Some(prefix.to_string()),
            delimiter: Some("/".to_string()),
            ..Default::default()
        };

        let mut prefixes = Vec::new();
        let mut stream = self.client.objects().list(list_req).await?;

        while let Some(page) = stream.next().await {
            match page {
                Ok(page) => {
                    for prefix_item in page.prefixes {
                        prefixes.push(prefix_item.trim_end_matches('/').to_string());
                    }
                }
                Err(e) => return Err(StorageError::BackendError(e.to_string())),
            }
        }

        Ok(prefixes)
    }

    async fn put_with_ttl(&self, key: &str, value: &[u8], ttl_seconds: u64, options: Option<HashMap<String, String>>) -> StorageResult<()> {
        // GCS doesn't have built-in TTL, but we can implement it using custom metadata
        let expiration_time = Utc::now() + Duration::seconds(ttl_seconds as i64);

        let mut metadata = options.unwrap_or_default();
        metadata.insert("ttl_expiration".to_string(), expiration_time.to_rfc3339());

        self.put(key, value, Some(metadata)).await
    }

    async fn get_with_ttl_check(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        // First check metadata for TTL
        let metadata = match self.get_metadata(key).await {
            Ok(metadata) => metadata,
            Err(StorageError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };

        // Check if TTL has expired
        if let Some(expiration_str) = metadata.get("ttl_expiration") {
            if let Ok(expiration) = chrono::DateTime::parse_from_rfc3339(expiration_str) {
                if Utc::now() > expiration {
                    // TTL expired, delete the object
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
        let get_bucket_req = GetBucketRequest {
            bucket: self.config.bucket_name.clone(),
            ..Default::default()
        };

        match self.client.buckets().get(get_bucket_req).await {
            Ok(_) => Ok(()),
            Err(e) => Err(StorageError::BackendError(format!("Health check failed: {}", e))),
        }
    }

    fn backend_type(&self) -> &'static str {
        "gcs"
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
