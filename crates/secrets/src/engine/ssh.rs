//! SSH secret engine implementation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;
use ssh_key::{PrivateKey, PublicKey, Algorithm, LineEnding};
use ssh_key::rand_core::{OsRng, RngCore};

/// ssh secret engine
pub struct SshEngine {
    config: SshConfig,
    enabled: bool,
}

impl Drop for SshEngine {
    fn drop(&mut self) {
        // Zeroize CA private key material so it is not left in freed heap
        // memory when an engine instance is replaced or discarded.
        if let Some(ref mut pk) = self.config.ca_private_key {
            zeroize::Zeroize::zeroize(pk);
        }
    }
}

impl SshEngine {
    pub fn new(config: SshConfig) -> Self {
        Self {
            config,
            enabled: false,
        }
    }

    /// Mutable access to the engine configuration.
    ///
    /// Primarily used by the persistent service layer to zeroize CA private
    /// key material when an engine instance is about to be discarded (e.g.
    /// after a failed storage write).
    pub fn config_mut(&mut self) -> &mut SshConfig {
        &mut self.config
    }

    /// Generate a new Ed25519 CA key pair
    pub fn generate_ca(&mut self) -> SecretResult<(String, String)> {
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .map_err(|e| SecretError::CryptoError(e.to_string()))?;

        let public_key = private_key.public_key();

        // Encode keys
        let priv_pem = private_key.to_openssh(LineEnding::LF)
            .map_err(|e| SecretError::CryptoError(e.to_string()))?
            .to_string();

        let pub_str = public_key.to_openssh()
            .map_err(|e| SecretError::CryptoError(e.to_string()))?;

        // Update config
        self.config.ca_private_key = Some(priv_pem.clone());
        self.config.ca_public_key = Some(pub_str.clone());

        Ok((priv_pem, pub_str))
    }

    /// Sign a public key.
    ///
    /// Returns `(signed_certificate, effective_ttl)`.  The effective TTL may be
    /// lower than the requested value because the engine clamps it to
    /// `max_lease_ttl`.
    pub fn sign_key(
        &self,
        public_key_str: &str,
        valid_principals: Vec<String>,
        ttl: u64,
    ) -> SecretResult<(String, u64)> {
        // Load CA Key
        let ca_priv_pem = self.config.ca_private_key.as_ref()
            .ok_or_else(|| SecretError::InvalidConfiguration("CA private key not configured".to_string()))?;

        let ca_key = PrivateKey::from_openssh(ca_priv_pem)
            .map_err(|e| SecretError::CryptoError(format!("Invalid CA key: {}", e)))?;

        // Parse Public Key to sign
        let user_pub_key = PublicKey::from_openssh(public_key_str)
            .map_err(|e| SecretError::InvalidSecretData(format!("Invalid public key: {}", e)))?;

        // Enforce max_lease_ttl as defense-in-depth — callers (e.g. handlers)
        // should clamp before calling, but the engine must not blindly trust
        // the value it receives.
        let effective_ttl = ttl.min(self.config.max_lease_ttl);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| SecretError::CryptoError(format!("System clock error: {}", e)))?
            .as_secs();
        let expire = now.saturating_add(effective_ttl);

        // Build Certificate
        // new_with_random_nonce(rng, pub_key, valid_after, valid_before)
        let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            user_pub_key,
            now,
            expire,
        ).map_err(|e| SecretError::CryptoError(format!("Failed to create builder: {}", e)))?;

        let serial = {
            let mut buf = [0u8; 8];
            OsRng.fill_bytes(&mut buf);
            u64::from_be_bytes(buf)
        };
        cert_builder.serial(serial).map_err(|e| SecretError::CryptoError(e.to_string()))?;
        cert_builder.cert_type(ssh_key::certificate::CertType::User).map_err(|e| SecretError::CryptoError(e.to_string()))?;

        for p in valid_principals {
            cert_builder.valid_principal(p).map_err(|e| SecretError::CryptoError(e.to_string()))?;
        }

        // Sign
        let cert = cert_builder.sign(&ca_key)
            .map_err(|e| SecretError::CryptoError(format!("Signing failed: {}", e)))?;

        Ok((cert.to_string(), effective_ttl))
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

    async fn read(&self, path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Ssh".to_string()));
        }

        match path {
            "config/ca" => {
                if let (Some(pub_key), Some(_priv_key)) = (&self.config.ca_public_key, &self.config.ca_private_key) {
                     let mut data = HashMap::new();
                     data.insert("public_key".to_string(), Value::String(pub_key.clone()));
                     // Do not return private key on read usually, unless explicitly requested or for backup
                     Ok(Some(Secret {
                        id: Uuid::new_v4(),
                        path: path.to_string(),
                        data,
                        metadata: SecretMetadata::default(),
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                    }))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None)
        }
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Ssh".to_string()));
        }

        match path {
            "config/ca" => {
                // Generate new CA
                let (priv_k, pub_k) = self.generate_ca()?;
                let mut resp_data = HashMap::new();
                resp_data.insert("public_key".to_string(), Value::String(pub_k));
                // Return private key once here? Or just store it.
                // Typically we return it once if generated.
                resp_data.insert("private_key".to_string(), Value::String(priv_k));

                Ok(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: resp_data,
                    metadata: SecretMetadata::default(),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
            }
            "sign" => {
                // Sign Key
                let public_key = data.get("public_key")
                    .and_then(|v| v.as_str())
                    .ok_or(SecretError::InvalidSecretData("Missing 'public_key'".to_string()))?;

                let principals_val = data.get("valid_principals");
                let principals: Vec<String> = if let Some(v) = principals_val {
                    if let Some(arr) = v.as_array() {
                        arr.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect()
                    } else if let Some(s) = v.as_str() {
                        vec![s.to_string()]
                    } else {
                         vec![]
                    }
                } else {
                    vec![]
                };

                let ttl = data.get("ttl")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(self.config.default_lease_ttl);

                // sign_key internally clamps to max_lease_ttl; compute the
                // same effective value so the metadata stays consistent.
                let effective_ttl = ttl.min(self.config.max_lease_ttl);

                let (signed_cert, effective_ttl) = self.sign_key(public_key, principals, effective_ttl)?;

                let mut resp_data = HashMap::new();
                resp_data.insert("signed_key".to_string(), Value::String(signed_cert));

                Ok(Secret {
                     id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: resp_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_by: "ssh-engine".to_string(),
                        updated_by: "ssh-engine".to_string(),
                        lease_id: None,
                        lease_duration: Some(effective_ttl),
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
            }
            "keys" => {
                // Generate SSH key pair (Old Logic)
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
    /// Generate SSH key pair using Ed25519 (Legacy method kept for 'keys' path)
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
        // Zeroize the raw secret bytes now that the signing key has been
        // constructed — avoids leaving key material in freed stack memory.
        zeroize::Zeroize::zeroize(&mut secret_bytes);
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
        let mut private_key_bytes = signing_key.to_bytes();
        let mut encoded_priv = general_purpose::STANDARD.encode(private_key_bytes);
        // Zeroize private key bytes after encoding
        zeroize::Zeroize::zeroize(&mut private_key_bytes);

        // OpenSSH private key format (simplified)
        let mut openssh_private_key = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}-----END OPENSSH PRIVATE KEY-----\n",
            encoded_priv
        );
        // Zeroize intermediate encoded private key now that the PEM string is built
        zeroize::Zeroize::zeroize(&mut encoded_priv);

        let mut key_data = HashMap::new();
        // Move the private key into the Value; zeroize the local copy afterwards.
        // Note: the Value::String copy cannot be zeroized, but scrubbing the
        // local allocation reduces the number of copies in memory.
        key_data.insert(
            "private_key".to_string(),
            Value::String(openssh_private_key.clone()),
        );
        zeroize::Zeroize::zeroize(&mut openssh_private_key);
        key_data.insert("public_key".to_string(), Value::String(ssh_public_key));
        key_data.insert("key_type".to_string(), Value::String("ed25519".to_string()));
        key_data.insert("key_name".to_string(), Value::String(key_name.to_string()));

        // Add fingerprint
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ssh-ed25519");
        hasher.update([0u8; 4]); // length prefix for algorithm name
        hasher.update(public_key_bytes);
        let fingerprint = format!(
            "SHA256:{}",
            general_purpose::STANDARD.encode(hasher.finalize())
        );
        key_data.insert("fingerprint".to_string(), Value::String(fingerprint));

        Ok(key_data)
    }
}
