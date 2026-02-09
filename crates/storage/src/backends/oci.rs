//! OCI storage backend for Secreton

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use reqwest::Client;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, sha2::Sha256};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use secreton_common::models::oauth_state::OAuthState;

fn expand_path(path: &str) -> Option<PathBuf> {
    if path.starts_with("~") {
        let home = env::var("HOME").or_else(|_| env::var("USERPROFILE")).ok()?;
        if path == "~" {
            return Some(PathBuf::from(home));
        } else if path.starts_with("~/") || path.starts_with("~\\") {
            return Some(PathBuf::from(home).join(&path[2..]));
        }
    }
    Some(PathBuf::from(path))
}

fn parse_ini_file(path: &Path, profile: &str) -> Option<HashMap<String, String>> {
    let file = fs::File::open(path).ok()?;
    let reader = io::BufReader::new(file);
    let mut props = HashMap::new();

    let mut current_section = String::new();
    let mut in_target_section = false;

    for line in reader.lines() {
        let line = line.ok()?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            in_target_section = current_section == profile;
            continue;
        }

        if in_target_section {
            if let Some((key, value)) = trimmed.split_once('=') {
                props.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    if props.is_empty() { None } else { Some(props) }
}

fn load_config_from_file(
    config_file: Option<&str>,
    profile: Option<&str>,
) -> Option<HashMap<String, String>> {
    let path = if let Some(p) = config_file {
        expand_path(p)
    } else {
        env::var("OCI_CONFIG_FILE")
            .ok()
            .and_then(|p| expand_path(&p))
            .or_else(|| expand_path("~/.oci/config"))
    };

    let path = path?;
    parse_ini_file(&path, profile.unwrap_or("DEFAULT"))
}

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
    pub fn new(mut config: OCIConfig) -> Self {
        if config.private_key_pem.is_none() {
            if let Some(props) =
                load_config_from_file(config.config_file.as_deref(), config.profile.as_deref())
            {
                if config.user_ocid.is_none() {
                    config.user_ocid = props.get("user").cloned();
                }
                if config.tenancy_ocid.is_none() {
                    config.tenancy_ocid = props.get("tenancy").cloned();
                }
                if config.fingerprint.is_none() {
                    config.fingerprint = props.get("fingerprint").cloned();
                }

                if let Some(key_file_path) = props.get("key_file") {
                    if let Some(key_path) = expand_path(key_file_path) {
                        if let Ok(content) = fs::read_to_string(key_path) {
                            config.private_key_pem = Some(content);
                        }
                    }
                }
            }
        }

        let key = if let Some(pem) = &config.private_key_pem {
            RsaPrivateKey::from_pkcs8_pem(pem).ok()
        } else {
            None
        };

        Self {
            config,
            client: Client::new(),
            key,
        }
    }

    fn get_url(&self, path: &str) -> String {
        // Namespace is needed. For now hardcoded placeholder or assume bucket is full path?
        // Standard OCI Object Storage URL: https://objectstorage.{region}.oraclecloud.com/n/{namespaceName}/b/{bucketName}/o/{objectName}
        // We miss namespace in config. Assuming bucket name might include it or we need a field.
        // Let's assume namespace is derived or placeholder.
        let namespace = "namespace";
        format!(
            "https://objectstorage.{}.oraclecloud.com/n/{}/b/{}/o/{}",
            self.config.region, namespace, self.config.bucket, path
        )
    }

    fn sign_request(&self, verb: &str, url: &str, body: Option<&[u8]>) -> StorageResult<String> {
        // Signing logic: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
        // 1. (request-target)
        // 2. date
        // 3. host
        // 4. content-length (if body)
        // 5. content-type (if body)
        // 6. x-content-sha256

        let key = self.key.as_ref().ok_or(StorageError::ConfigurationError {
            message: "Missing private key for OCI".to_string(),
        })?;
        let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let uri = url.split("oraclecloud.com").nth(1).unwrap_or("/");
        let host = url
            .split("://")
            .nth(1)
            .unwrap_or("")
            .split("/")
            .next()
            .unwrap_or("");

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

        let key_id = format!(
            "{}/{}/{}",
            self.config.tenancy_ocid.as_deref().unwrap_or(""),
            self.config.user_ocid.as_deref().unwrap_or(""),
            self.config.fingerprint.as_deref().unwrap_or("")
        );
        let algo = "rsa-sha256";
        let headers_list = if body.is_some() {
            "(request-target) date host content-length content-type x-content-sha256"
        } else {
            "(request-target) date host"
        };

        Ok(format!(
            "Signature version=\"1\",keyId=\"{}\",algorithm=\"{}\",headers=\"{}\",signature=\"{}\"",
            key_id, algo, headers_list, signature_b64
        ))
    }
}

#[async_trait]
impl StorageBackend for OCIStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let url = self.get_url(&entry.path);
        let data = serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = BASE64.encode(hasher.finalize());

        let auth = self.sign_request("PUT", &url, Some(&data))?;

        let res = self
            .client
            .put(&url)
            .header("Date", date)
            .header(
                "Host",
                url.split("://")
                    .nth(1)
                    .unwrap_or("")
                    .split("/")
                    .next()
                    .unwrap_or(""),
            )
            .header("Content-Type", "application/json")
            .header("Content-Length", data.len())
            .header("x-content-sha256", hash)
            .header("Authorization", auth)
            .body(data)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: e.to_string(),
            })?;

        if !res.status().is_success() {
            return Err(StorageError::QueryFailed {
                message: res.status().to_string(),
            });
        }
        Ok(())
    }

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let url = self.get_url(path);
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let auth = self.sign_request("GET", &url, None)?;

        let res = self
            .client
            .get(&url)
            .header("Date", date)
            .header(
                "Host",
                url.split("://")
                    .nth(1)
                    .unwrap_or("")
                    .split("/")
                    .next()
                    .unwrap_or(""),
            )
            .header("Authorization", auth)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: e.to_string(),
            })?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            return Err(StorageError::QueryFailed {
                message: res.status().to_string(),
            });
        }
        let bytes = res
            .bytes()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: e.to_string(),
            })?;
        let entry =
            serde_json::from_slice(&bytes).map_err(|e| StorageError::SerializationError {
                message: e.to_string(),
            })?;
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

        let res = self
            .client
            .delete(&url)
            .header("Date", date)
            .header(
                "Host",
                url.split("://")
                    .nth(1)
                    .unwrap_or("")
                    .split("/")
                    .next()
                    .unwrap_or(""),
            )
            .header("Authorization", auth)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: e.to_string(),
            })?;
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
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 0.0,
            connections_active: 0,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 0,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats {
            total_entries: 0,
            total_size_bytes: 0,
            average_entry_size: 0.0,
            entries_by_security_level: std::collections::HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "OCI".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "OCI".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_expand_path() {
        let home = env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .unwrap();
        // Just verify it expands ~
        let path = expand_path("~/.oci/config").unwrap();
        assert!(path.to_string_lossy().contains(&home));
        assert!(
            path.to_string_lossy().ends_with(".oci/config")
                || path.to_string_lossy().ends_with(".oci\\config")
        );

        let path = expand_path("/tmp/config").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/config"));
    }

    #[test]
    fn test_parse_ini_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[DEFAULT]").unwrap();
        writeln!(file, "user=ocid1.user...").unwrap();
        writeln!(file, "fingerprint=aa:bb:cc").unwrap();
        writeln!(file, "key_file=/path/to/key.pem").unwrap();
        writeln!(file, "[ADMIN]").unwrap();
        writeln!(file, "user=ocid1.user.admin...").unwrap();

        let path = file.path();

        // Test DEFAULT
        let props = parse_ini_file(path, "DEFAULT").unwrap();
        assert_eq!(props.get("user").unwrap(), "ocid1.user...");
        assert_eq!(props.get("fingerprint").unwrap(), "aa:bb:cc");

        // Test ADMIN
        let props = parse_ini_file(path, "ADMIN").unwrap();
        assert_eq!(props.get("user").unwrap(), "ocid1.user.admin...");
        assert!(props.get("fingerprint").is_none());
    }

    #[test]
    fn test_oci_config_load() {
        // Create a fake key file
        let mut key_file = NamedTempFile::new().unwrap();
        writeln!(key_file, "-----BEGIN PRIVATE KEY-----\nMIIEv...").unwrap();
        let key_path = key_file.path().to_str().unwrap();

        let mut config_file = NamedTempFile::new().unwrap();
        writeln!(config_file, "[DEFAULT]").unwrap();
        writeln!(config_file, "user=ocid1.user.test").unwrap();
        writeln!(config_file, "tenancy=ocid1.tenancy.test").unwrap();
        writeln!(config_file, "fingerprint=11:22:33").unwrap();
        writeln!(config_file, "key_file={}", key_path).unwrap();

        let config = OCIConfig {
            compartment_id: "comp".to_string(),
            bucket: "bucket".to_string(),
            region: "us-ashburn-1".to_string(),
            config_file: Some(config_file.path().to_str().unwrap().to_string()),
            profile: None,
            user_ocid: None,
            tenancy_ocid: None,
            fingerprint: None,
            private_key_pem: None,
        };

        let storage = OCIStorage::new(config);

        assert_eq!(storage.config.user_ocid.as_deref(), Some("ocid1.user.test"));
        assert_eq!(
            storage.config.tenancy_ocid.as_deref(),
            Some("ocid1.tenancy.test")
        );
        assert_eq!(storage.config.fingerprint.as_deref(), Some("11:22:33"));
        assert!(storage.config.private_key_pem.is_some());
        assert!(
            storage
                .config
                .private_key_pem
                .as_ref()
                .unwrap()
                .contains("-----BEGIN PRIVATE KEY-----")
        );
    }
}
