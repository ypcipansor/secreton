//! SSH secret engine implementation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// ssh secret engine
pub struct SshEngine {
    config: SshConfig,
    enabled: bool,
}

impl SshEngine {
    pub fn new(config: SshConfig) -> Self {
        Self {
            config,
            enabled: false,
        }
    }
}

#[async_trait]
impl SecretEngine for SshEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Ssh
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, _path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Ssh".to_string()));
        }
        Ok(None)
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Ssh".to_string()));
        }

        match path {
            "keys" => {
                // Generate SSH key pair
                let key_data = self.generate_ssh_key(&data).await?;
                Ok(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: key_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_by: "ssh-engine".to_string(),
                        updated_by: "ssh-engine".to_string(),
                        lease_id: None,
                        lease_duration: Some(self.config.default_lease_ttl),
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
            }
            _ => Err(SecretError::InvalidPath(format!(
                "Unsupported SSH path: {}",
                path
            ))),
        }
    }

    async fn delete(&mut self, _path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Ssh".to_string()));
        }
        Ok(())
    }

    async fn list(&self, _path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Ssh".to_string()));
        }
        Ok(vec![])
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

impl SshEngine {
    /// Generate SSH key pair using Ed25519
    async fn generate_ssh_key(
        &self,
        data: &HashMap<String, Value>,
    ) -> SecretResult<HashMap<String, Value>> {
        use rand::RngCore;
        use rand::rngs::OsRng;

        // Generate 32 random bytes for the secret key
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);

        // Create signing key directly from bytes
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        // Get key name from data or use default
        let key_name = data
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("generated-key");

        // Create SSH public key format: "ssh-ed25519 AAAAB3NzaC1yc2EAAA... comment"
        let public_key_bytes = verifying_key.to_bytes();
        let encoded_pub = general_purpose::STANDARD.encode(public_key_bytes);
        let ssh_public_key = format!("ssh-ed25519 {} {}", encoded_pub, key_name);

        // Create OpenSSH private key format
        let private_key_bytes = signing_key.to_bytes();
        let encoded_priv = general_purpose::STANDARD.encode(private_key_bytes);

        // OpenSSH private key format (simplified)
        let openssh_private_key = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}-----END OPENSSH PRIVATE KEY-----\n",
            encoded_priv
        );

        let mut key_data = HashMap::new();
        key_data.insert(
            "private_key".to_string(),
            Value::String(openssh_private_key),
        );
        key_data.insert("public_key".to_string(), Value::String(ssh_public_key));
        key_data.insert("key_type".to_string(), Value::String("ed25519".to_string()));
        key_data.insert("key_name".to_string(), Value::String(key_name.to_string()));

        // Add fingerprint
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ssh-ed25519");
        hasher.update(&[0u8; 4]); // length prefix for algorithm name
        hasher.update(&public_key_bytes);
        let fingerprint = format!(
            "SHA256:{}",
            general_purpose::STANDARD.encode(hasher.finalize())
        );
        key_data.insert("fingerprint".to_string(), Value::String(fingerprint));

        Ok(key_data)
    }
}
