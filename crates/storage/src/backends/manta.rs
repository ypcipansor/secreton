//! Manta storage backend for Secreton

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use reqwest::Client;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, sha2::Sha256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use secreton_common::models::oauth_state::OAuthState;

/// Manta storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MantaConfig {
    pub url: String,
    pub account: String,
    pub key_path: String,
    pub timeout: u64,
    // Added for manual auth
    pub key_id: Option<String>, // fingerprint
    pub private_key_pem: Option<String>,
}

pub struct MantaStorage {
    config: MantaConfig,
    client: Client,
    key: Option<RsaPrivateKey>,
}

impl MantaStorage {
    pub fn new(config: MantaConfig) -> Self {
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
        format!("{}/{}/stor/{}", self.config.url, self.config.account, path)
    }

    fn sign_request(&self, _verb: &str, _url: &str) -> StorageResult<String> {
        // Manta HTTP Signature:
        // Signature keyId="/:login/keys/:fingerprint",algorithm="rsa-sha256",headers="date",signature="..."

        let key = self.key.as_ref().ok_or(StorageError::ConfigurationError {
            message: "Missing private key for Manta".to_string(),
        })?;
        let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let signing_string = format!("date: {}", now);
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone());
        let signature = signing_key.sign(signing_string.as_bytes());
        let signature_b64 = BASE64.encode(signature.to_bytes());

        let key_id = format!(
            "/{}/keys/{}",
            self.config.account,
            self.config.key_id.as_deref().unwrap_or("default")
        );

        Ok(format!(
            "keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"date\",signature=\"{}\"",
            key_id, signature_b64
        ))
    }
}

#[async_trait]
impl StorageBackend for MantaStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let url = self.get_url(&entry.path);
        let data = serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let auth = self.sign_request("PUT", &url)?;

        let res = self
            .client
            .put(&url)
            .header("Date", date)
            .header("Authorization", format!("Signature {}", auth))
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
        let auth = self.sign_request("GET", &url)?;

        let res = self
            .client
            .get(&url)
            .header("Date", date)
            .header("Authorization", format!("Signature {}", auth))
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
        let auth = self.sign_request("DELETE", &url)?;

        let res = self
            .client
            .delete(&url)
            .header("Date", date)
            .header("Authorization", format!("Signature {}", auth))
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
            backend: "Manta".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "Manta".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}
