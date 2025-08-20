use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error};

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    
    #[error("Vault error: {0}")]
    VaultError(String),
    
    #[error("Authentication failed: {0}")]
    AuthError(String),
}

#[derive(Clone, Debug)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub mount_path: String,
}

#[derive(Clone)]
pub struct VaultClient {
    client: reqwest::Client,
    config: Arc<VaultConfig>,
}

impl VaultClient {
    pub fn new(config: VaultConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config: Arc::new(config),
        }
    }

    /// Initialize the Vault client and authenticate
    pub async fn init(&self) -> Result<(), VaultError> {
        // Verify the token is valid
        let status = self.client
            .get(&format!("{}/v1/auth/token/lookup-self", self.config.address))
            .header("X-Vault-Token", &self.config.token)
            .send()
            .await?;

        if !status.status().is_success() {
            return Err(VaultError::AuthError("Invalid Vault token".to_string()));
        }

        // Ensure the transit engine is enabled
        self.enable_transit().await?;
        
        Ok(())
    }

    /// Enable the transit secrets engine if not already enabled
    async fn enable_transit(&self) -> Result<(), VaultError> {
        let path = format!("{}/v1/sys/mounts/{}", self.config.address, self.config.mount_path);
        
        let response = self.client
            .get(&path)
            .header("X-Vault-Token", &self.config.token)
            .send()
            .await;

        // If the mount doesn't exist, enable it
        if let Err(e) = response {
            if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                debug!("Enabling transit secrets engine at {}", self.config.mount_path);
                
                let enable_response = self.client
                    .post(&format!("{}/v1/sys/mounts/{}", self.config.address, self.config.mount_path))
                    .header("X-Vault-Token", &self.config.token)
                    .json(&json!({ "type": "transit" }))
                    .send()
                    .await?;

                if !enable_response.status().is_success() {
                    return Err(VaultError::VaultError(
                        format!("Failed to enable transit secrets engine: {}", 
                               enable_response.text().await.unwrap_or_default())
                    ));
                }
            } else {
                return Err(e.into());
            }
        }

        Ok(())
    }

    /// Encrypt data using Vault's transit engine
    pub async fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<String, VaultError> {
        let response = self.client
            .post(&format!(
                "{}/v1/{}/encrypt/{}",
                self.config.address, self.config.mount_path, key_name
            ))
            .header("X-Vault-Token", &self.config.token)
            .json(&json!({ "plaintext": base64::encode(plaintext) }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VaultError::VaultError(
                format!("Encryption failed: {}", response.text().await.unwrap_or_default())
            ));
        }

        let result: serde_json::Value = response.json().await?;
        result["data"]["ciphertext"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::VaultError("Invalid response from Vault".to_string()))
    }

    /// Decrypt data using Vault's transit engine
    pub async fn decrypt(&self, key_name: &str, ciphertext: &str) -> Result<Vec<u8>, VaultError> {
        let response = self.client
            .post(&format!(
                "{}/v1/{}/decrypt/{}",
                self.config.address, self.config.mount_path, key_name
            ))
            .header("X-Vault-Token", &self.config.token)
            .json(&json!({ "ciphertext": ciphertext }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VaultError::VaultError(
                format!("Decryption failed: {}", response.text().await.unwrap_or_default())
            ));
        }

        let result: serde_json::Value = response.json().await?;
        let plaintext_b64 = result["data"]["plaintext"]
            .as_str()
            .ok_or_else(|| VaultError::VaultError("Invalid response from Vault".to_string()))?;

        base64::decode(plaintext_b64)
            .map_err(|e| VaultError::VaultError(format!("Failed to decode plaintext: {}", e)))
    }

    /// Create a new encryption key in the transit engine
    pub async fn create_key(&self, key_name: &str) -> Result<(), VaultError> {
        let response = self.client
            .post(&format!(
                "{}/v1/{}/keys/{}",
                self.config.address, self.config.mount_path, key_name
            ))
            .header("X-Vault-Token", &self.config.token)
            .json(&json!({ "type": "aes256-gcm96" }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VaultError::VaultError(
                format!("Failed to create key: {}", response.text().await.unwrap_or_default())
            ));
        }

        Ok(())
    }

    /// Rotate an existing encryption key
    pub async fn rotate_key(&self, key_name: &str) -> Result<(), VaultError> {
        let response = self.client
            .post(&format!(
                "{}/v1/{}/keys/{}/rotate",
                self.config.address, self.config.mount_path, key_name
            ))
            .header("X-Vault-Token", &self.config.token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(VaultError::VaultError(
                format!("Failed to rotate key: {}", response.text().await.unwrap_or_default())
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{mock, Server};
    use serde_json::json;

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let mut server = Server::new();
        
        // Mock Vault server responses
        let _m1 = mock("POST", "/v1/auth/token/lookup-self")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data": {"id": "test-token"}}"#)
            .create();

        let _m2 = mock("GET", "/v1/sys/mounts/transit")
            .with_status(404)
            .create();

        let _m3 = mock("POST", "/v1/sys/mounts/transit")
            .with_status(204)
            .create();

        let _m4 = mock("POST", "/v1/transit/encrypt/test-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data": {"ciphertext": "vault:v1:testciphertext"}}"#)
            .create();

        let _m5 = mock("POST", "/v1/transit/decrypt/test-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data": {"plaintext": "dGVzdC1kYXRh"}}"#) // base64 of "test-data"
            .create();

        let config = VaultConfig {
            address: server.url(),
            token: "test-token".to_string(),
            mount_path: "transit".to_string(),
        };

        let vault = VaultClient::new(config);
        vault.init().await.unwrap();

        // Test encryption
        let ciphertext = vault.encrypt("test-key", b"test-data").await.unwrap();
        assert_eq!(ciphertext, "vault:v1:testciphertext");

        // Test decryption
        let plaintext = vault.decrypt("test-key", &ciphertext).await.unwrap();
        assert_eq!(plaintext, b"test-data");
    }
}
