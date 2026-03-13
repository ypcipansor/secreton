use crate::services::crypto::CryptoService;
use anyhow::{Result, anyhow};
use jsonwebtoken::{EncodingKey, Header, encode};
use secreton_crypto::shamir::{self, Share};
use secreton_crypto::{AlgorithmId, EncryptedData};
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

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
    pub keys: Vec<String>,        // Hex encoded shares
    pub keys_base64: Vec<String>, // Base64 encoded shares
    // Root token removed for security
    pub root_totp_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResponse {
    pub sealed: bool,
    pub t: usize,
    pub n: usize,
    pub progress: usize,
    pub root_token: Option<String>,
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
    policies: Vec<String>,
    iat: usize,
    exp: usize,
    jti: String,
    iss: String,
    aud: String,
    token_type: String,
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
        self.storage
            .get_by_path(INIT_PATH)
            .await
            .unwrap_or(None)
            .is_some()
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
            root_token: None,
        })
    }

    /// Initialize the vault
    /// Generates Master Key, Splits it, Encrypts Root Key.
    /// Also creates the initial Root User with MFA enabled.
    ///
    /// Refactored per comment 3822469315:
    /// - Root has NO password.
    /// - Root auth is only via Unseal (SSS).
    /// - Root manages Admins.
    pub async fn init(
        &self,
        shares: u8,
        threshold: u8,
        root_username: &str,
        auth: &crate::services::auth::AuthenticationService,
        mfa: &secreton_auth::mfa::CombinedMfaService,
    ) -> Result<InitResponse> {
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

        self.storage
            .store(&SecretEntry::new(
                INIT_PATH.to_string(),
                config_bytes,
                EncryptionMetadata::default(),
                SecurityLevel::Public,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to store init config: {}", e))?;

        // 6. Store Encrypted Root Key
        let enc_root_bytes = serde_json::to_vec(&EncryptedRootKey {
            data: encrypted_root,
        })?;
        self.storage
            .store(&SecretEntry::new(
                ROOT_KEY_PATH.to_string(),
                enc_root_bytes,
                EncryptionMetadata::default(),
                SecurityLevel::TopSecret,
                Uuid::nil(),
            ))
            .await
            .map_err(|e| anyhow!("Failed to store root key: {}", e))?;

        // 7. Format Response
        let keys_hex: Vec<String> = splits
            .iter()
            .map(|s| hex::encode(serde_json::to_vec(s).unwrap())) // We encode the whole Share struct
            .collect();

        let keys_base64: Vec<String> = splits
            .iter()
            .map(|s| {
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    serde_json::to_vec(s).unwrap(),
                )
            })
            .collect();

        // 8. Create Root User and Enable MFA
        // We must temporarily enable the root key so Auth service can encrypt user data
        self.crypto.set_root_key(root_key.clone()).await?;

        // Root has no password. Generate a random unguessable string as placeholder password
        // because register_user expects a password. This effectively disables password login.
        let random_password = Uuid::new_v4().to_string() + &Uuid::new_v4().to_string();

        // Execute user creation and MFA setup.
        // We need to ensure clear_root_key is called even if this fails.
        // Explicitly annotate result type to avoid inference issues with the error type.
        let result: Result<secreton_auth::mfa::TotpEnrollment, anyhow::Error> = async {
            let root_user = auth
                .register_user(
                    root_username,
                    &random_password,
                    Some("root@system.local".to_string()),
                    vec!["root".to_string(), "admin".to_string()],
                    vec!["*".to_string()],
                )
                .await
                .map_err(|e| anyhow!("Failed to create root user: {}", e))?;

            // Enable TOTP for Root
            // IMPORTANT: Must be done BEFORE clearing the root key because PersistentTotpService encrypts the secret!
            let user_uuid = Uuid::parse_str(&root_user.id).unwrap_or_default();
            let totp_config = mfa
                .enable_totp(user_uuid, root_user.username.clone())
                .await
                .map_err(|e| anyhow!("Failed to enable TOTP for root user: {}", e))?;

            Ok(totp_config)
        }
        .await;

        // Clear root key immediately after use, regardless of success/failure
        self.crypto.clear_root_key().await;

        let totp_config = result?;

        tracing::info!("Root token generated internally but discarded to enforce zero-trust/MFA.");

        Ok(InitResponse {
            keys: keys_hex,
            keys_base64,
            root_totp_uri: totp_config.url,
            // Secret removed for security
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

        let share: Share =
            serde_json::from_slice(&share_bytes).map_err(|_| anyhow!("Invalid share structure"))?;

        let mut buffer = self.unseal_buffer.write().await;

        // Add if not exists
        if !buffer.iter().any(|s| s.index == share.index) {
            buffer.push(share);
        }

        // Check threshold
        let (threshold, _) = {
            let entry = self
                .storage
                .get_by_path(INIT_PATH)
                .await
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
            let entry = self
                .storage
                .get_by_path(ROOT_KEY_PATH)
                .await
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

                    // Generate short-lived Root Token for Admin Management sessions
                    let now = chrono::Utc::now();
                    let exp = now + chrono::Duration::hours(1); // 1 hour for root tasks

                    let claims = Claims {
                        sub: "root".to_string(),
                        username: "root".to_string(),
                        email: "root@system.local".to_string(),
                        roles: vec!["root".to_string(), "admin".to_string()],
                        policies: vec!["root".to_string()],
                        iat: now.timestamp() as usize,
                        exp: exp.timestamp() as usize,
                        jti: Uuid::new_v4().to_string(),
                        iss: self.jwt_issuer.clone(),
                        aud: self.jwt_audience.clone(),
                        token_type: "access".to_string(),
                    };

                    let root_token = encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
                    )
                    .map_err(|e| anyhow!("Failed to generate root token: {}", e))?;

                    return Ok(UnsealResponse {
                        sealed: false,
                        t: threshold,
                        n: 0, // Not relevant here
                        progress: 0,
                        root_token: Some(root_token),
                    });
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to decrypt root key with reconstructed master key. Wrong shares?"
                    );
                    return Err(anyhow!(
                        "Failed to decrypt root key. Invalid shares? Error: {}",
                        e
                    ));
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
        use crate::config::AuthConfig;
        use crate::services::auth::AuthenticationService;
        // Updated test to use PersistentTotpService instead of InMemoryTotpService to match production config
        use crate::services::mfa_persistence::PersistentTotpService;
        use secreton_auth::mfa::{
            CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService,
            DefaultWebAuthnService, EmailConfig, InMemoryEmailService, InMemoryHardwareService,
            InMemorySmsService, SmsConfig,
        };

        let storage = Arc::new(MockStorageBackend::new());
        // Clean env to ensure sealed start
        unsafe {
            std::env::remove_var("SECRETON_ROOT_KEY");
        }
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());

        // Setup Auth and MFA for init
        let config = AuthConfig::default();
        // Manually configure JWT secret for test to avoid panic
        let mut config = config;
        config.jwt.secret = Some("test-secret-1234567890".to_string());

        let persistent_totp = Arc::new(PersistentTotpService::new(
            storage.clone(),
            crypto.clone(),
            "secreton-test".to_string(),
        ));

        let mfa = Arc::new(CombinedMfaService::new(
            persistent_totp,
            Arc::new(InMemorySmsService::new(SmsConfig::default())),
            Arc::new(InMemoryEmailService::new(EmailConfig::default())),
            Arc::new(InMemoryHardwareService::new()),
            Arc::new(DefaultPushService::new_mock()),
            Arc::new(DefaultWebAuthnService::new_default()),
            Arc::new(DefaultRecoveryCodeService::new()),
        ));

        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto.clone(), &config)
                .await
                .unwrap()
                .with_mfa(mfa.clone()),
        );

        let seal_service = SealService::new(
            storage.clone(),
            crypto.clone(),
            "test-secret".to_string(),
            "secreton".to_string(),
            "secreton-api".to_string(),
        );

        // 1. Check initial state
        assert!(!seal_service.is_initialized().await);
        assert!(seal_service.is_sealed().await);

        // 2. Initialize
        // Root password removed from init
        let init_res = seal_service
            .init(5, 3, "root", &auth, &mfa)
            .await
            .expect("Init failed");
        assert_eq!(init_res.keys.len(), 5);
        // Root token was removed, check TOTP secret instead
        // assert!(!init_res.root_totp_secret.is_empty()); // Removed
        assert!(!init_res.root_totp_uri.is_empty());
        assert!(seal_service.is_initialized().await);
        assert!(seal_service.is_sealed().await); // Still sealed

        // 3. Unseal (partial)
        let status = seal_service
            .unseal(&init_res.keys[0])
            .await
            .expect("Unseal 1 failed");
        assert!(status.sealed);
        assert_eq!(status.progress, 1);

        // 4. Unseal (partial)
        let status = seal_service
            .unseal(&init_res.keys[1])
            .await
            .expect("Unseal 2 failed");
        assert!(status.sealed);
        assert_eq!(status.progress, 2);

        // 5. Unseal (complete)
        let status = seal_service
            .unseal(&init_res.keys[2])
            .await
            .expect("Unseal 3 failed");
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
