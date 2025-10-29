//! Advanced HSM Integration
//!
//! Provides PKCS#11 interface for hardware security modules,
//! key management, cryptographic operations, and HSM failover.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum HSMError {
    #[error("HSM not initialized: {0}")]
    NotInitialized(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("HSM unavailable: {0}")]
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, HSMError>;

/// HSM provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HSMProvider {
    SoftHSM,
    AWSCloudHSM,
    ThalesLuna,
    Gemalto,
    YubiHSM,
}

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMConfig {
    pub hsm_id: String,
    pub provider: HSMProvider,
    pub pkcs11_library_path: String,
    pub slot_id: u32,
    pub pin: String,
    pub label: String,
    pub enabled: bool,
}

/// Key types supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    AES,
    RSA2048,
    RSA4096,
    ECDSA_P256,
    ECDSA_P384,
}

/// HSM key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMKey {
    pub key_id: String,
    pub key_handle: String,
    pub key_type: KeyType,
    pub key_label: String,
    pub created_at: DateTime<Utc>,
    pub extractable: bool,
    pub operations: Vec<KeyOperation>,
    pub hsm_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    WrapKey,
    UnwrapKey,
}

/// Cryptographic operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoResult {
    pub operation_id: String,
    pub operation: KeyOperation,
    pub key_id: String,
    pub result_data: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

/// HSM session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMSession {
    pub session_id: String,
    pub hsm_id: String,
    pub opened_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub authenticated: bool,
}

/// HSM cluster for failover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMCluster {
    pub cluster_id: String,
    pub name: String,
    pub primary_hsm: String,
    pub secondary_hsms: Vec<String>,
    pub failover_enabled: bool,
}

/// HSM health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HSMHealth {
    pub hsm_id: String,
    pub status: HealthStatus,
    pub last_check: DateTime<Utc>,
    pub response_time_ms: u64,
    pub active_sessions: usize,
    pub total_keys: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unavailable,
}

/// Advanced HSM integration manager
pub struct AdvancedHSM {
    hsms: Arc<RwLock<HashMap<String, HSMConfig>>>,
    keys: Arc<RwLock<HashMap<String, HSMKey>>>,
    sessions: Arc<RwLock<HashMap<String, HSMSession>>>,
    clusters: Arc<RwLock<HashMap<String, HSMCluster>>>,
}

impl AdvancedHSM {
    pub fn new() -> Self {
        Self {
            hsms: Arc::new(RwLock::new(HashMap::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            clusters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize HSM connection
    pub async fn initialize_hsm(&self, config: HSMConfig) -> Result<String> {
        // Mock PKCS#11 initialization
        let hsm_id = Uuid::new_v4().to_string();

        let mut hsm_config = config;
        hsm_config.hsm_id = hsm_id.clone();

        let mut hsms = self.hsms.write().await;
        hsms.insert(hsm_id.clone(), hsm_config);

        // Create initial session
        let session = HSMSession {
            session_id: Uuid::new_v4().to_string(),
            hsm_id: hsm_id.clone(),
            opened_at: Utc::now(),
            last_activity: Utc::now(),
            authenticated: true,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session.session_id.clone(), session);

        Ok(hsm_id)
    }

    /// Generate a new key in HSM
    pub async fn generate_key_in_hsm(
        &self,
        hsm_id: &str,
        key_type: KeyType,
        key_label: String,
        extractable: bool,
    ) -> Result<HSMKey> {
        let hsms = self.hsms.read().await;
        let _hsm = hsms
            .get(hsm_id)
            .ok_or_else(|| HSMError::NotInitialized(hsm_id.to_string()))?;

        // Mock key generation in HSM
        let key = HSMKey {
            key_id: Uuid::new_v4().to_string(),
            key_handle: format!("hsm_handle_{}", Uuid::new_v4()),
            key_type: key_type.clone(),
            key_label,
            created_at: Utc::now(),
            extractable,
            operations: match key_type {
                KeyType::AES => vec![
                    KeyOperation::Encrypt,
                    KeyOperation::Decrypt,
                    KeyOperation::WrapKey,
                    KeyOperation::UnwrapKey,
                ],
                KeyType::RSA2048 | KeyType::RSA4096 => vec![
                    KeyOperation::Encrypt,
                    KeyOperation::Decrypt,
                    KeyOperation::Sign,
                    KeyOperation::Verify,
                ],
                KeyType::ECDSA_P256 | KeyType::ECDSA_P384 => {
                    vec![KeyOperation::Sign, KeyOperation::Verify]
                }
            },
            hsm_id: hsm_id.to_string(),
        };

        let mut keys = self.keys.write().await;
        keys.insert(key.key_id.clone(), key.clone());

        Ok(key)
    }

    /// Encrypt data with HSM key
    pub async fn encrypt_with_hsm(&self, key_id: &str, plaintext: Vec<u8>) -> Result<CryptoResult> {
        let keys = self.keys.read().await;
        let key = keys
            .get(key_id)
            .ok_or_else(|| HSMError::KeyNotFound(key_id.to_string()))?;

        if !key.operations.contains(&KeyOperation::Encrypt) {
            return Err(HSMError::OperationFailed(
                "Key does not support encryption".to_string(),
            ));
        }

        // Mock encryption operation
        let ciphertext = plaintext.iter().map(|b| b.wrapping_add(1)).collect();

        Ok(CryptoResult {
            operation_id: Uuid::new_v4().to_string(),
            operation: KeyOperation::Encrypt,
            key_id: key_id.to_string(),
            result_data: ciphertext,
            timestamp: Utc::now(),
        })
    }

    /// Decrypt data with HSM key
    pub async fn decrypt_with_hsm(
        &self,
        key_id: &str,
        ciphertext: Vec<u8>,
    ) -> Result<CryptoResult> {
        let keys = self.keys.read().await;
        let key = keys
            .get(key_id)
            .ok_or_else(|| HSMError::KeyNotFound(key_id.to_string()))?;

        if !key.operations.contains(&KeyOperation::Decrypt) {
            return Err(HSMError::OperationFailed(
                "Key does not support decryption".to_string(),
            ));
        }

        // Mock decryption operation
        let plaintext = ciphertext.iter().map(|b| b.wrapping_sub(1)).collect();

        Ok(CryptoResult {
            operation_id: Uuid::new_v4().to_string(),
            operation: KeyOperation::Decrypt,
            key_id: key_id.to_string(),
            result_data: plaintext,
            timestamp: Utc::now(),
        })
    }

    /// Sign data with HSM key
    pub async fn sign_with_hsm(&self, key_id: &str, data: Vec<u8>) -> Result<CryptoResult> {
        let keys = self.keys.read().await;
        let key = keys
            .get(key_id)
            .ok_or_else(|| HSMError::KeyNotFound(key_id.to_string()))?;

        if !key.operations.contains(&KeyOperation::Sign) {
            return Err(HSMError::OperationFailed(
                "Key does not support signing".to_string(),
            ));
        }

        // Mock signature generation (simple hash for demo)
        let signature = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        let signature_data = vec![signature; 32]; // Mock 32-byte signature

        Ok(CryptoResult {
            operation_id: Uuid::new_v4().to_string(),
            operation: KeyOperation::Sign,
            key_id: key_id.to_string(),
            result_data: signature_data,
            timestamp: Utc::now(),
        })
    }

    /// Verify signature with HSM key
    pub async fn verify_with_hsm(
        &self,
        key_id: &str,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool> {
        let keys = self.keys.read().await;
        let key = keys
            .get(key_id)
            .ok_or_else(|| HSMError::KeyNotFound(key_id.to_string()))?;

        if !key.operations.contains(&KeyOperation::Verify) {
            return Err(HSMError::OperationFailed(
                "Key does not support verification".to_string(),
            ));
        }

        // Mock signature verification
        let expected_sig = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        let valid = !signature.is_empty() && signature[0] == expected_sig;

        Ok(valid)
    }

    /// Create HSM cluster for failover
    pub async fn create_cluster(
        &self,
        name: String,
        primary_hsm: String,
        secondary_hsms: Vec<String>,
    ) -> Result<HSMCluster> {
        // Verify all HSMs exist
        let hsms = self.hsms.read().await;
        if !hsms.contains_key(&primary_hsm) {
            return Err(HSMError::NotInitialized(primary_hsm));
        }
        for hsm_id in &secondary_hsms {
            if !hsms.contains_key(hsm_id) {
                return Err(HSMError::NotInitialized(hsm_id.clone()));
            }
        }

        let cluster = HSMCluster {
            cluster_id: Uuid::new_v4().to_string(),
            name,
            primary_hsm,
            secondary_hsms,
            failover_enabled: true,
        };

        let mut clusters = self.clusters.write().await;
        clusters.insert(cluster.cluster_id.clone(), cluster.clone());

        Ok(cluster)
    }

    /// Perform failover to secondary HSM
    pub async fn failover(&self, cluster_id: &str) -> Result<String> {
        let mut clusters = self.clusters.write().await;
        let cluster = clusters
            .get_mut(cluster_id)
            .ok_or_else(|| HSMError::OperationFailed("Cluster not found".to_string()))?;

        if !cluster.failover_enabled {
            return Err(HSMError::OperationFailed("Failover disabled".to_string()));
        }

        if cluster.secondary_hsms.is_empty() {
            return Err(HSMError::OperationFailed(
                "No secondary HSMs available".to_string(),
            ));
        }

        // Move current primary to secondary list
        cluster.secondary_hsms.push(cluster.primary_hsm.clone());

        // Promote first secondary to primary
        cluster.primary_hsm = cluster.secondary_hsms.remove(0);

        Ok(cluster.primary_hsm.clone())
    }

    /// Get HSM health status
    pub async fn get_hsm_health(&self, hsm_id: &str) -> Result<HSMHealth> {
        let hsms = self.hsms.read().await;
        let _hsm = hsms
            .get(hsm_id)
            .ok_or_else(|| HSMError::NotInitialized(hsm_id.to_string()))?;

        let keys = self.keys.read().await;
        let total_keys = keys.values().filter(|k| k.hsm_id == hsm_id).count();

        let sessions = self.sessions.read().await;
        let active_sessions = sessions.values().filter(|s| s.hsm_id == hsm_id).count();

        Ok(HSMHealth {
            hsm_id: hsm_id.to_string(),
            status: HealthStatus::Healthy,
            last_check: Utc::now(),
            response_time_ms: 5, // Mock response time
            active_sessions,
            total_keys,
        })
    }

    /// List all keys in HSM
    pub async fn list_keys(&self, hsm_id: &str) -> Result<Vec<HSMKey>> {
        let hsms = self.hsms.read().await;
        if !hsms.contains_key(hsm_id) {
            return Err(HSMError::NotInitialized(hsm_id.to_string()));
        }

        let keys = self.keys.read().await;
        Ok(keys
            .values()
            .filter(|k| k.hsm_id == hsm_id)
            .cloned()
            .collect())
    }

    /// Delete key from HSM
    pub async fn delete_key(&self, key_id: &str) -> Result<()> {
        let mut keys = self.keys.write().await;
        keys.remove(key_id)
            .ok_or_else(|| HSMError::KeyNotFound(key_id.to_string()))?;
        Ok(())
    }

    /// Get key metadata
    pub async fn get_key(&self, key_id: &str) -> Result<HSMKey> {
        let keys = self.keys.read().await;
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| HSMError::KeyNotFound(key_id.to_string()))
    }
}

impl Default for AdvancedHSM {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initialize_hsm() {
        let hsm = AdvancedHSM::new();
        let config = HSMConfig {
            hsm_id: String::new(),
            provider: HSMProvider::SoftHSM,
            pkcs11_library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot_id: 0,
            pin: "1234".to_string(),
            label: "TestHSM".to_string(),
            enabled: true,
        };

        let hsm_id = hsm.initialize_hsm(config).await.unwrap();
        assert!(!hsm_id.is_empty());
    }

    #[tokio::test]
    async fn test_generate_key() {
        let hsm = AdvancedHSM::new();
        let config = HSMConfig {
            hsm_id: String::new(),
            provider: HSMProvider::SoftHSM,
            pkcs11_library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot_id: 0,
            pin: "1234".to_string(),
            label: "TestHSM".to_string(),
            enabled: true,
        };

        let hsm_id = hsm.initialize_hsm(config).await.unwrap();
        let key = hsm
            .generate_key_in_hsm(&hsm_id, KeyType::AES, "test-key".to_string(), false)
            .await
            .unwrap();

        assert_eq!(key.key_type, KeyType::AES);
        assert!(!key.extractable);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let hsm = AdvancedHSM::new();
        let config = HSMConfig {
            hsm_id: String::new(),
            provider: HSMProvider::SoftHSM,
            pkcs11_library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot_id: 0,
            pin: "1234".to_string(),
            label: "TestHSM".to_string(),
            enabled: true,
        };

        let hsm_id = hsm.initialize_hsm(config).await.unwrap();
        let key = hsm
            .generate_key_in_hsm(&hsm_id, KeyType::AES, "test-key".to_string(), false)
            .await
            .unwrap();

        let plaintext = b"Hello, HSM!".to_vec();
        let encrypted = hsm
            .encrypt_with_hsm(&key.key_id, plaintext.clone())
            .await
            .unwrap();
        let decrypted = hsm
            .decrypt_with_hsm(&key.key_id, encrypted.result_data)
            .await
            .unwrap();

        assert_eq!(plaintext, decrypted.result_data);
    }

    #[tokio::test]
    async fn test_sign_verify() {
        let hsm = AdvancedHSM::new();
        let config = HSMConfig {
            hsm_id: String::new(),
            provider: HSMProvider::SoftHSM,
            pkcs11_library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot_id: 0,
            pin: "1234".to_string(),
            label: "TestHSM".to_string(),
            enabled: true,
        };

        let hsm_id = hsm.initialize_hsm(config).await.unwrap();
        let key = hsm
            .generate_key_in_hsm(&hsm_id, KeyType::ECDSA_P256, "sign-key".to_string(), false)
            .await
            .unwrap();

        let data = b"Sign this data".to_vec();
        let signature = hsm.sign_with_hsm(&key.key_id, data.clone()).await.unwrap();
        let valid = hsm
            .verify_with_hsm(&key.key_id, data, signature.result_data)
            .await
            .unwrap();

        assert!(valid);
    }

    #[tokio::test]
    async fn test_hsm_cluster_failover() {
        let hsm = AdvancedHSM::new();

        let config1 = HSMConfig {
            hsm_id: String::new(),
            provider: HSMProvider::SoftHSM,
            pkcs11_library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot_id: 0,
            pin: "1234".to_string(),
            label: "Primary".to_string(),
            enabled: true,
        };
        let hsm1 = hsm.initialize_hsm(config1).await.unwrap();

        let config2 = HSMConfig {
            hsm_id: String::new(),
            provider: HSMProvider::SoftHSM,
            pkcs11_library_path: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
            slot_id: 1,
            pin: "1234".to_string(),
            label: "Secondary".to_string(),
            enabled: true,
        };
        let hsm2 = hsm.initialize_hsm(config2).await.unwrap();

        let cluster = hsm
            .create_cluster("TestCluster".to_string(), hsm1.clone(), vec![hsm2.clone()])
            .await
            .unwrap();

        let new_primary = hsm.failover(&cluster.cluster_id).await.unwrap();
        assert_eq!(new_primary, hsm2);
    }
}
