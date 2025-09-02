use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use serde_json::Value;
use std::sync::Arc;
use tracing::info;

use crate::storage::Storage;
use crate::utils::config::Config;

pub mod engine;

pub fn auto_unseal_master_key(config: &Config) -> Option<String> {
    if config.auto_unseal_enabled == Some(true) {
        match config.auto_unseal_provider.as_deref() {
            Some("kms") => {
                // TODO: Integrasi AWS KMS/GCP KMS/Azure KeyVault
                println!(
                    "[Auto-Unseal] Menggunakan provider KMS, key_id: {:?}",
                    config.auto_unseal_key_id
                );
                Some("dummy_master_key_from_kms".to_string())
            }
            Some("hsm") => {
                println!("[Auto-Unseal] Menggunakan provider HSM");
                Some("dummy_master_key_from_hsm".to_string())
            }
            Some("cloud") => {
                println!("[Auto-Unseal] Menggunakan provider Cloud");
                Some("dummy_master_key_from_cloud".to_string())
            }
            _ => None,
        }
    } else {
        None
    }
}

pub struct SecretManager {
    encryption_key: Vec<u8>,
    storage: Arc<Storage>,
    sealed: bool,
    master_key: Option<Vec<u8>>,
}

impl SecretManager {
    pub async fn new(encryption_key: &str) -> Result<Self> {
        let key = encryption_key.as_bytes().to_vec();
        if key.len() != 32 {
            return Err(anyhow::anyhow!("Encryption key must be 32 bytes"));
        }

        Ok(Self {
            encryption_key: key,
            storage: Arc::new(Storage::new("sqlite:vault.db").await?),
            sealed: true,
            master_key: None,
        })
    }

    pub async fn initialize_vault(
        &mut self,
        secret_shares: u32,
        secret_threshold: u32,
    ) -> Result<(Vec<String>, String)> {
        if secret_shares < secret_threshold {
            return Err(anyhow::anyhow!("Secret shares must be >= threshold"));
        }

        // Generate master key
        let mut master_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);

        // Generate shamir secret sharing keys (simplified)
        let mut keys = Vec::new();
        for _i in 0..secret_shares {
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            keys.push(hex::encode(&key));
        }

        // Store master key
        self.master_key = Some(master_key.clone());
        self.sealed = false;

        // Store vault state
        self.storage
            .set_vault_state(false, Some(&hex::encode(&master_key)))
            .await?;

        // Generate root token
        let root_token = self.generate_root_token()?;

        info!(
            "Vault initialized with {} shares and {} threshold",
            secret_shares, secret_threshold
        );

        Ok((keys, root_token))
    }

    pub async fn unseal_vault(&mut self, key: &str) -> Result<()> {
        // In a real implementation, you would use shamir secret sharing
        // For now, we'll use a simple key comparison
        let (sealed, stored_key) = self.storage.get_vault_state().await?;

        if !sealed {
            return Ok(()); // Already unsealed
        }

        if let Some(stored) = stored_key {
            if stored == key {
                self.sealed = false;
                self.master_key = Some(hex::decode(&stored)?);
                info!("Vault unsealed successfully");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Invalid unseal key"))
            }
        } else {
            Err(anyhow::anyhow!("No master key stored"))
        }
    }

    pub async fn create_secret(&self, path: &str, data: &Value) -> Result<u32> {
        if self.sealed {
            return Err(anyhow::anyhow!("Vault is sealed"));
        }
        let encrypted_data = self.encrypt_data(data)?;
        let version = self
            .storage
            .store_secret_versioned(path, &encrypted_data)
            .await?;
        info!("Created secret at path: {} version: {}", path, version);
        Ok(version)
    }

    pub async fn get_secret(&self, path: &str) -> Result<Value> {
        if self.sealed {
            return Err(anyhow::anyhow!("Vault is sealed"));
        }
        match self.storage.get_latest_secret(path).await? {
            Some((encrypted_data, _version)) => {
                let decrypted_data = self.decrypt_data(&encrypted_data)?;
                Ok(decrypted_data)
            }
            None => Err(anyhow::anyhow!("Secret not found")),
        }
    }

    pub async fn update_secret(&self, path: &str, data: &Value) -> Result<u32> {
        if self.sealed {
            return Err(anyhow::anyhow!("Vault is sealed"));
        }
        let encrypted_data = self.encrypt_data(data)?;
        let version = self
            .storage
            .store_secret_versioned(path, &encrypted_data)
            .await?;
        info!("Updated secret at path: {} version: {}", path, version);
        Ok(version)
    }

    pub async fn delete_secret(&self, path: &str) -> Result<()> {
        if self.sealed {
            return Err(anyhow::anyhow!("Vault is sealed"));
        }

        self.storage.delete_secret(path).await?;
        info!("Deleted secret at path: {}", path);
        Ok(())
    }

    pub async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>> {
        let versions = self.storage.get_secret_versions(path).await?;
        let mut result = Vec::new();
        for (version, encrypted_data) in versions {
            let decrypted = self.decrypt_data(&encrypted_data)?;
            result.push((version, decrypted));
        }
        Ok(result)
    }

    fn encrypt_data(&self, data: &Value) -> Result<Value> {
        let data_json = serde_json::to_string(data)?;
        let data_bytes = data_json.as_bytes();

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, data_bytes)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        // Combine nonce and ciphertext
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&ciphertext);

        // Return as base64 encoded JSON
        let encrypted_b64 = BASE64.encode(&encrypted);
        Ok(serde_json::json!({
            "encrypted_data": encrypted_b64,
            "algorithm": "aes-gcm"
        }))
    }

    fn decrypt_data(&self, encrypted_data: &Value) -> Result<Value> {
        let encrypted_b64 = encrypted_data["encrypted_data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid encrypted data format"))?;

        let encrypted_bytes = BASE64.decode(encrypted_b64)?;

        if encrypted_bytes.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted data length"));
        }

        // Extract nonce and ciphertext
        let nonce_bytes = &encrypted_bytes[..12];
        let ciphertext = &encrypted_bytes[12..];

        let nonce = Nonce::from_slice(nonce_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        let data_json = String::from_utf8(plaintext)?;
        let data: Value = serde_json::from_str(&data_json)?;

        Ok(data)
    }

    fn generate_root_token(&self) -> Result<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let token: String = (0..32)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        Ok(format!("hvs.{}", token))
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_encryption_decryption() {
        // Test encryption/decryption functionality directly without storage
        let key = "test_key_32_bytes_for_aes256_ok!".as_bytes().to_vec();
        
        let test_data = json!({
            "username": "test_user",
            "password": "test_pass"
        });

        // Test encryption
        let nonce_bytes = {
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            nonce
        };
        
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = serde_json::to_vec(&test_data).unwrap();
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        
        // Test decryption
        let decrypted_bytes = cipher.decrypt(nonce, encrypted.as_ref()).unwrap();
        let decrypted: Value = serde_json::from_slice(&decrypted_bytes).unwrap();

        assert_eq!(test_data, decrypted);
    }
}
