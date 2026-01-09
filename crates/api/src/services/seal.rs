use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use secreton_storage::{StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel};
use uuid::Uuid;
use crate::services::crypto::CryptoService;
use secreton_crypto::{AlgorithmId, EncryptedData};
use secreton_crypto::shamir::{self, Share};
use jsonwebtoken::{encode, Header, EncodingKey};

/// Seal/Unseal Service
/// Manages the initialization and sealing status of the vault.
pub struct SealService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    jwt_secret: String,
    jwt_issuer: String,
    jwt_audience: String,

    // In-memory buffer for unseal shares
    // (share_index, share_data)
    unseal_buffer: Arc<RwLock<Vec<Share>>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    pub keys: Vec<String>, // Hex encoded shares
    pub keys_base64: Vec<String>, // Base64 encoded shares
    pub root_token: String, // Initial root token
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub sealed: bool,
    pub t: usize,
    pub n: usize,
    pub progress: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct InitConfig {
    shares: u8,
    threshold: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedRootKey {
    data: EncryptedData,
}

const INIT_PATH: &str = "sys/init";
const ROOT_KEY_PATH: &str = "sys/root_key_enc";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    username: String,
    email: String,
    roles: Vec<String>,
    iat: usize,
    exp: usize,
    jti: String,
    iss: String,
    aud: String,
}

impl SealService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        jwt_secret: String,
        jwt_issuer: String,
        jwt_audience: String,
    ) -> Self {
        Self {
            storage,
            crypto,
            jwt_secret,
            jwt_issuer,
            jwt_audience,
            unseal_buffer: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Check if the system is initialized
    pub async fn is_initialized(&self) -> bool {
        // We use list instead of get to check existence without reading full data if possible,
        // but get is safer.
        self.storage.get_by_path(INIT_PATH).await.unwrap_or(None).is_some()
    }

    /// Check if the system is sealed
    pub async fn is_sealed(&self) -> bool {
        !self.crypto.is_unsealed().await
    }

    /// Get current seal status
    pub async fn get_status(&self) -> Result<UnsealResponse> {
        let sealed = self.is_sealed().await;

        let (t, n) = if let Ok(Some(entry)) = self.storage.get_by_path(INIT_PATH).await {
             let config: InitConfig = serde_json::from_slice(&entry.encrypted_data)
                .map_err(|_| anyhow!("Failed to parse init config"))?;
             (config.threshold as usize, config.shares as usize)
        } else {
            (0, 0)
        };

        let progress = self.unseal_buffer.read().await.len();

        Ok(UnsealResponse {
            sealed,
            t,
            n,
            progress,
        })
    }

    /// Initialize the vault
    /// Generates Master Key, Splits it, Encrypts Root Key.
    pub async fn init(&self, shares: u8, threshold: u8) -> Result<InitResponse> {
        if self.is_initialized().await {
            return Err(anyhow!("System already initialized"));
        }

        if threshold > shares {
            return Err(anyhow!("Threshold cannot be greater than shares"));
        }
        if threshold < 2 {
             return Err(anyhow!("Threshold must be at least 2"));
        }

        // 1. Generate Master Key (32 bytes)
        let master_key = secreton_crypto::generate_key(AlgorithmId::Aes256Gcm)?;

        // 2. Generate Root Key (32 bytes) - The key used by CryptoService
        let root_key = secreton_crypto::generate_key(AlgorithmId::Aes256Gcm)?;

        // 3. Encrypt Root Key with Master Key
        // We use CryptoService's low-level encrypt which doesn't require unsealing
        let encrypted_root = self.crypto.encrypt(&master_key, &root_key, None)?;

        // 4. Split Master Key
        let mut rng = rand::rngs::OsRng;
        let splits = shamir::split(&master_key, threshold as usize, shares as usize, &mut rng)
            .map_err(|e| anyhow!("Shamir split failed: {}", e))?;

        // 5. Store Init Config
        let config = InitConfig { shares, threshold };
        let config_bytes = serde_json::to_vec(&config)?;

        // Save config (unencrypted in storage, but marked as protected)
        // Actually, storage expects EncryptedData usually, but here we are storing metadata
        // or we treat "encrypted_data" field as just data container if we bypass encryption?
        // StorageBackend expects Vec<u8> in 'encrypted_data'.
        // Ideally InitConfig should not be secret, but let's store it.
        self.storage.store(&SecretEntry::new(
            INIT_PATH.to_string(),
            config_bytes,
            EncryptionMetadata::default(),
            SecurityLevel::Public,
            Uuid::nil()
        )).await.map_err(|e| anyhow!("Failed to store init config: {}", e))?;

        // 6. Store Encrypted Root Key
        let enc_root_bytes = serde_json::to_vec(&EncryptedRootKey { data: encrypted_root })?;
        self.storage.store(&SecretEntry::new(
            ROOT_KEY_PATH.to_string(),
            enc_root_bytes,
            EncryptionMetadata::default(),
            SecurityLevel::TopSecret,
            Uuid::nil()
        )).await.map_err(|e| anyhow!("Failed to store root key: {}", e))?;

        // 7. Format Response
        let keys_hex: Vec<String> = splits.iter()
            .map(|s| hex::encode(serde_json::to_vec(s).unwrap())) // We encode the whole Share struct
            .collect();

        let keys_base64: Vec<String> = splits.iter()
            .map(|s| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, serde_json::to_vec(s).unwrap()))
            .collect();

        // Generate a Root Token (Initial Root Token)
        // We generate a valid JWT token with 'root' role/policy
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::days(365 * 100); // Long lived root token

        let claims = Claims {
            sub: "root".to_string(),
            username: "root".to_string(),
            email: "root@system.local".to_string(),
            roles: vec!["root".to_string(), "admin".to_string()],
            iat: now.timestamp() as usize,
            exp: exp.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
        };

        let root_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        ).map_err(|e| anyhow!("Failed to generate root token: {}", e))?;

        Ok(InitResponse {
            keys: keys_hex,
            keys_base64,
            root_token,
        })
    }

    /// Submit a share to unseal
    pub async fn unseal(&self, share_str: &str) -> Result<UnsealResponse> {
        if !self.is_initialized().await {
            return Err(anyhow!("System not initialized"));
        }
        if !self.is_sealed().await {
            return self.get_status().await;
        }

        // Try decoding hex first, then base64
        let share_bytes = if let Ok(b) = hex::decode(share_str) {
            b
        } else {
             base64::Engine::decode(&base64::engine::general_purpose::STANDARD, share_str)
                .map_err(|_| anyhow!("Invalid share format (expected hex or base64)"))?
        };

        let share: Share = serde_json::from_slice(&share_bytes)
            .map_err(|_| anyhow!("Invalid share structure"))?;

        let mut buffer = self.unseal_buffer.write().await;

        // Add if not exists
        if !buffer.iter().any(|s| s.index == share.index) {
            buffer.push(share);
        }

        // Check threshold
        let (threshold, _) = {
             let entry = self.storage.get_by_path(INIT_PATH).await
                .map_err(|e| anyhow!("Storage error: {}", e))?
                .ok_or(anyhow!("Init config missing"))?;
             let config: InitConfig = serde_json::from_slice(&entry.encrypted_data)?;
             (config.threshold as usize, config.shares as usize)
        };

        if buffer.len() >= threshold {
            // Reconstruct
            tracing::info!("Threshold reached. Attempting to unseal...");

            // Reconstruct Master Key
            let master_key = match shamir::combine(&buffer) {
                Ok(k) => k,
                Err(e) => {
                    // Wrong shares?
                    tracing::error!("Failed to combine shares: {}", e);
                    return Err(anyhow!("Failed to reconstruct key: {}", e));
                }
            };

            // Get Encrypted Root Key
            let entry = self.storage.get_by_path(ROOT_KEY_PATH).await
                .map_err(|e| anyhow!("Storage error: {}", e))?
                .ok_or(anyhow!("Root key missing"))?;

            let enc_root: EncryptedRootKey = serde_json::from_slice(&entry.encrypted_data)
                .map_err(|_| anyhow!("Invalid root key data"))?;

            // Decrypt Root Key
            match self.crypto.decrypt_with_key(&master_key, &enc_root.data) {
                Ok(root_key) => {
                    // SUCCESS!
                    self.crypto.set_root_key(root_key).await?;
                    tracing::info!("Vault unsealed successfully.");
                    buffer.clear();
                },
                Err(e) => {
                    tracing::error!("Failed to decrypt root key with reconstructed master key. Wrong shares?");
                    return Err(anyhow!("Failed to decrypt root key. Invalid shares? Error: {}", e));
                }
            }
        }

        drop(buffer);
        self.get_status().await
    }

    /// Seal the vault
    pub async fn seal(&self) {
        self.crypto.clear_root_key().await;
        self.unseal_buffer.write().await.clear();
        tracing::info!("Vault sealed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secreton_storage::MockStorageBackend;

    #[tokio::test]
    async fn test_seal_flow() {
        let storage = Arc::new(MockStorageBackend::new());
        // Clean env to ensure sealed start
        std::env::remove_var("SECRETON_ROOT_KEY");
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let seal_service = SealService::new(
            storage.clone(),
            crypto.clone(),
            "test-secret".to_string(),
            "secreton".to_string(),
            "secreton-api".to_string()
        );

        // 1. Check initial state
        assert!(!seal_service.is_initialized().await);
        assert!(seal_service.is_sealed().await);

        // 2. Initialize
        let init_res = seal_service.init(5, 3).await.expect("Init failed");
        assert_eq!(init_res.keys.len(), 5);
        assert!(!init_res.root_token.is_empty());
        assert!(seal_service.is_initialized().await);
        assert!(seal_service.is_sealed().await); // Still sealed

        // 3. Unseal (partial)
        let status = seal_service.unseal(&init_res.keys[0]).await.expect("Unseal 1 failed");
        assert!(status.sealed);
        assert_eq!(status.progress, 1);

        // 4. Unseal (partial)
        let status = seal_service.unseal(&init_res.keys[1]).await.expect("Unseal 2 failed");
        assert!(status.sealed);
        assert_eq!(status.progress, 2);

        // 5. Unseal (complete)
        let status = seal_service.unseal(&init_res.keys[2]).await.expect("Unseal 3 failed");
        assert!(!status.sealed);
        assert!(!seal_service.is_sealed().await);

        // 6. Verify Crypto works
        let enc = crypto.encrypt_data(b"test").await;
        assert!(enc.is_ok());

        // 7. Seal again
        seal_service.seal().await;
        assert!(seal_service.is_sealed().await);

        // 8. Verify Crypto blocked
        let enc = crypto.encrypt_data(b"test").await;
        assert!(enc.is_err());
    }
}
