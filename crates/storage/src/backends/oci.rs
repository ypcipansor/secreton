//! OCI storage backend for Secreton

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use reqwest::Client;
use chrono::Utc;
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, sha2::Sha256};
use rsa::signature::{Signer, SignatureEncoding};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest};

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};

/// OCI storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCIConfig {
    pub compartment_id: String,
    pub bucket: String,
    pub region: String,
    pub config_file: Option<String>,
    pub profile: Option<String>,
    // Added for manual auth if config file parsing is skipped
    pub user_ocid: Option<String>,
    pub tenancy_ocid: Option<String>,
    pub fingerprint: Option<String>,
    pub private_key_pem: Option<String>,
}

pub struct OCIStorage {
    config: OCIConfig,
    client: Client,
    key: Option<RsaPrivateKey>,
}

impl OCIStorage {
    pub fn new(config: OCIConfig) -> Self {
        let key = if let Some(pem) = &config.private_key_pem {
            RsaPrivateKey::from_pkcs8_pem(pem).ok()
        } else {
            // TODO: Load from config_file
            None
        };

        Self { config, client: Client::new(), key }
    }

    fn get_url(&self, path: &str) -> String {
        // Namespace is needed. For now hardcoded placeholder or assume bucket is full path?
        // Standard OCI Object Storage URL: https://objectstorage.{region}.oraclecloud.com/n/{namespaceName}/b/{bucketName}/o/{objectName}
        // We miss namespace in config. Assuming bucket name might include it or we need a field.
        // Let's assume namespace is derived or placeholder.
        let namespace = "namespace";
        format!("https://objectstorage.{}.oraclecloud.com/n/{}/b/{}/o/{}", self.config.region, namespace, self.config.bucket, path)
    }

    fn sign_request(&self, verb: &str, url: &str, body: Option<&[u8]>) -> StorageResult<String> {
        // Signing logic: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
        // 1. (request-target)
        // 2. date
        // 3. host
        // 4. content-length (if body)
        // 5. content-type (if body)
        // 6. x-content-sha256

        let key = self.key.as_ref().ok_or(StorageError::ConfigurationError { message: "Missing private key for OCI".to_string() })?;
        let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let uri = url.split("oraclecloud.com").nth(1).unwrap_or("/");
        let host = url.split("://").nth(1).unwrap_or("").split("/").next().unwrap_or("");

        let mut headers = vec![
            format!("(request-target): {} {}", verb.to_lowercase(), uri),
            format!("date: {}", now),
            format!("host: {}", host),
        ];

        if let Some(b) = body {
            headers.push(format!("content-length: {}", b.len()));
            headers.push("content-type: application/json".to_string());
            let mut hasher = Sha256::new();
            hasher.update(b);
            let hash = BASE64.encode(hasher.finalize());
            headers.push(format!("x-content-sha256: {}", hash));
        }

        let signing_string = headers.join("\n");
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let signature = signing_key.sign(signing_string.as_bytes());
        let signature_b64 = BASE64.encode(signature.to_bytes());

        let key_id = format!("{}/{}/{}", self.config.tenancy_ocid.as_deref().unwrap_or(""), self.config.user_ocid.as_deref().unwrap_or(""), self.config.fingerprint.as_deref().unwrap_or(""));
        let algo = "rsa-sha256";
        let headers_list = if body.is_some() {
            "(request-target) date host content-length content-type x-content-sha256"
        } else {
            "(request-target) date host"
        };

        Ok(format!("Signature version=\"1\",keyId=\"{}\",algorithm=\"{}\",headers=\"{}\",signature=\"{}\"", key_id, algo, headers_list, signature_b64))
    }
}

#[async_trait]
impl StorageBackend for OCIStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let url = self.get_url(&entry.path);
        let data = serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;

        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = BASE64.encode(hasher.finalize());

        let auth = self.sign_request("PUT", &url, Some(&data))?;

        let res = self.client.put(&url)
            .header("Date", date)
            .header("Host", url.split("://").nth(1).unwrap_or("").split("/").next().unwrap_or(""))
            .header("Content-Type", "application/json")
            .header("Content-Length", data.len())
            .header("x-content-sha256", hash)
            .header("Authorization", auth)
            .body(data)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;

        if !res.status().is_success() { return Err(StorageError::QueryFailed { message: res.status().to_string() }); }
        Ok(())
    }

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let url = self.get_url(path);
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let auth = self.sign_request("GET", &url, None)?;

        let res = self.client.get(&url)
            .header("Date", date)
            .header("Host", url.split("://").nth(1).unwrap_or("").split("/").next().unwrap_or(""))
            .header("Authorization", auth)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;

        if res.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
        if !res.status().is_success() { return Err(StorageError::QueryFailed { message: res.status().to_string() }); }
        let bytes = res.bytes().await.map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;
        let entry = serde_json::from_slice(&bytes).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;
        Ok(Some(entry))
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        Ok(false)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let url = self.get_url(path);
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let auth = self.sign_request("DELETE", &url, None)?;

        let res = self.client.delete(&url)
            .header("Date", date)
            .header("Host", url.split("://").nth(1).unwrap_or("").split("/").next().unwrap_or(""))
            .header("Authorization", auth)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;
        Ok(res.status().is_success())
    }

    async fn list(&self, _params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        Ok(Vec::new())
    }

    async fn count(&self, _params: &QueryParams) -> StorageResult<u64> {
        Ok(0)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        Ok(self.get_by_path(path).await?.is_some())
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(crate::MockTransaction))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus { is_healthy: true, response_time_ms: 0.0, connections_active: 0, connections_idle: 0, last_error: None, uptime_seconds: 0 })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats { total_entries: 0, total_size_bytes: 0, average_entry_size: 0.0, entries_by_security_level: std::collections::HashMap::new(), entries_created_today: 0, entries_updated_today: 0, expired_entries: 0 })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }
}
