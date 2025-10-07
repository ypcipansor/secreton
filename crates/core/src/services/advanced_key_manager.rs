//! Advanced Key Manager
//!
//! Comprehensive key lifecycle management including generation, distribution,
//! rotation, escrow, recovery, versioning, and hierarchical derivation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Insufficient shares: {0}")]
    InsufficientShares(String),
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
    #[error("Escrow failed: {0}")]
    EscrowFailed(String),
}

pub type Result<T> = std::result::Result<T, KeyManagerError>;

/// Key type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    AES256,
    RSA2048,
    RSA4096,
    ECDSA_P256,
    ECDSA_P384,
    ED25519,
    X25519,
}

/// Key purpose
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyPurpose {
    Encryption,
    Signing,
    KeyWrapping,
    MasterKey,
    DerivedKey,
}

/// Key state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyState {
    Active,
    Rotated,
    Escrowed,
    Compromised,
    Destroyed,
}

/// Managed key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedKey {
    pub key_id: String,
    pub key_type: KeyType,
    pub purpose: KeyPurpose,
    pub state: KeyState,
    pub version: u32,
    pub material: Vec<u8>,
    pub metadata: KeyMetadata,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub owner: String,
    pub tags: HashMap<String, String>,
    pub parent_key_id: Option<String>,
    pub derivation_path: Option<String>,
}

/// Key version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    pub version: u32,
    pub key_id: String,
    pub material: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub deprecated_at: Option<DateTime<Utc>>,
}

/// Key escrow entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEscrow {
    pub escrow_id: String,
    pub key_id: String,
    pub threshold: usize,
    pub shares: Vec<KeyShare>,
    pub created_at: DateTime<Utc>,
    pub recovery_policy: RecoveryPolicy,
}

/// Key share for threshold schemes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub share_id: String,
    pub share_index: usize,
    pub share_data: Vec<u8>,
    pub holder: String,
}

/// Recovery policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub required_approvers: Vec<String>,
    pub timeout_hours: u32,
    pub multi_factor_required: bool,
}

/// Key derivation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationRequest {
    pub parent_key_id: String,
    pub derivation_path: String,
    pub purpose: KeyPurpose,
}

/// Advanced Key Manager
pub struct AdvancedKeyManager {
    keys: Arc<RwLock<HashMap<String, ManagedKey>>>,
    versions: Arc<RwLock<HashMap<String, Vec<KeyVersion>>>>,
    escrows: Arc<RwLock<HashMap<String, KeyEscrow>>>,
}

impl AdvancedKeyManager {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            versions: Arc::new(RwLock::new(HashMap::new())),
            escrows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate new key
    pub async fn generate_key(
        &self,
        key_type: KeyType,
        purpose: KeyPurpose,
        metadata: KeyMetadata,
    ) -> Result<String> {
        let key_size = match key_type {
            KeyType::AES256 => 32,
            KeyType::RSA2048 => 256,
            KeyType::RSA4096 => 512,
            KeyType::ECDSA_P256 => 32,
            KeyType::ECDSA_P384 => 48,
            KeyType::ED25519 => 32,
            KeyType::X25519 => 32,
        };

        // Mock key generation
        let material = vec![0u8; key_size];

        let key = ManagedKey {
            key_id: Uuid::new_v4().to_string(),
            key_type,
            purpose,
            state: KeyState::Active,
            version: 1,
            material,
            metadata,
            created_at: Utc::now(),
            expires_at: None,
        };

        let key_id = key.key_id.clone();

        // Store initial version
        let version = KeyVersion {
            version: 1,
            key_id: key_id.clone(),
            material: key.material.clone(),
            created_at: key.created_at,
            deprecated_at: None,
        };

        let mut keys = self.keys.write().await;
        let mut versions = self.versions.write().await;

        keys.insert(key_id.clone(), key);
        versions.insert(key_id.clone(), vec![version]);

        Ok(key_id)
    }

    /// Rotate key
    pub async fn rotate_key(&self, key_id: &str) -> Result<u32> {
        let mut keys = self.keys.write().await;
        let mut versions = self.versions.write().await;

        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| KeyManagerError::KeyNotFound(key_id.to_string()))?;

        // Generate new key material
        let new_material = vec![0u8; key.material.len()];
        let new_version = key.version + 1;

        // Deprecate current version
        if let Some(version_list) = versions.get_mut(key_id) {
            if let Some(current) = version_list.last_mut() {
                current.deprecated_at = Some(Utc::now());
            }
        }

        // Create new version
        let new_version_entry = KeyVersion {
            version: new_version,
            key_id: key_id.to_string(),
            material: new_material.clone(),
            created_at: Utc::now(),
            deprecated_at: None,
        };

        versions
            .entry(key_id.to_string())
            .or_default()
            .push(new_version_entry);

        // Update key
        key.material = new_material;
        key.version = new_version;
        key.state = KeyState::Active;

        Ok(new_version)
    }

    /// Derive key from parent
    pub async fn derive_key(&self, request: KeyDerivationRequest) -> Result<String> {
        let (key_type, owner, tags) = {
            let keys = self.keys.read().await;

            let parent = keys
                .get(&request.parent_key_id)
                .ok_or_else(|| KeyManagerError::KeyNotFound(request.parent_key_id.clone()))?;

            // Mock key derivation (in real implementation, use HKDF, BIP32, etc.)
            (parent.key_type.clone(), parent.metadata.owner.clone(), parent.metadata.tags.clone())
        };

        let metadata = KeyMetadata {
            owner,
            tags,
            parent_key_id: Some(request.parent_key_id.clone()),
            derivation_path: Some(request.derivation_path),
        };

        self.generate_key(key_type, request.purpose, metadata)
            .await
    }

    /// Split key into shares (Shamir Secret Sharing)
    pub async fn split_key(&self, key_id: &str, threshold: usize, total_shares: usize) -> Result<String> {
        if threshold > total_shares {
            return Err(KeyManagerError::InsufficientShares(
                "Threshold cannot exceed total shares".to_string(),
            ));
        }

        let keys = self.keys.read().await;
        let key = keys
            .get(key_id)
            .ok_or_else(|| KeyManagerError::KeyNotFound(key_id.to_string()))?;

        // Mock share generation (real implementation would use proper Shamir scheme)
        let shares: Vec<KeyShare> = (0..total_shares)
            .map(|i| KeyShare {
                share_id: Uuid::new_v4().to_string(),
                share_index: i,
                share_data: key.material.clone(),
                holder: format!("holder_{}", i),
            })
            .collect();

        let escrow = KeyEscrow {
            escrow_id: Uuid::new_v4().to_string(),
            key_id: key_id.to_string(),
            threshold,
            shares,
            created_at: Utc::now(),
            recovery_policy: RecoveryPolicy {
                required_approvers: vec![],
                timeout_hours: 24,
                multi_factor_required: true,
            },
        };

        let escrow_id = escrow.escrow_id.clone();
        drop(keys);

        let mut escrows = self.escrows.write().await;
        escrows.insert(escrow_id.clone(), escrow);

        Ok(escrow_id)
    }

    /// Reconstruct key from shares
    pub async fn reconstruct_key(&self, escrow_id: &str, shares: Vec<KeyShare>) -> Result<Vec<u8>> {
        let escrows = self.escrows.read().await;
        let escrow = escrows
            .get(escrow_id)
            .ok_or_else(|| KeyManagerError::KeyNotFound(escrow_id.to_string()))?;

        if shares.len() < escrow.threshold {
            return Err(KeyManagerError::InsufficientShares(format!(
                "Need {} shares, got {}",
                escrow.threshold,
                shares.len()
            )));
        }

        // Mock reconstruction (real implementation would use Lagrange interpolation)
        let reconstructed = shares[0].share_data.clone();

        Ok(reconstructed)
    }

    /// Escrow key
    pub async fn escrow_key(&self, key_id: &str, policy: RecoveryPolicy) -> Result<String> {
        let escrow_id = self.split_key(key_id, 3, 5).await?;

        let mut escrows = self.escrows.write().await;
        if let Some(escrow) = escrows.get_mut(&escrow_id) {
            escrow.recovery_policy = policy;
        }

        let mut keys = self.keys.write().await;
        if let Some(key) = keys.get_mut(key_id) {
            key.state = KeyState::Escrowed;
        }

        Ok(escrow_id)
    }

    /// Recover key from escrow
    pub async fn recover_key(&self, escrow_id: &str, shares: Vec<KeyShare>) -> Result<String> {
        let material = self.reconstruct_key(escrow_id, shares).await?;

        let escrows = self.escrows.read().await;
        let escrow = escrows
            .get(escrow_id)
            .ok_or_else(|| KeyManagerError::KeyNotFound(escrow_id.to_string()))?;

        let keys = self.keys.read().await;
        let original_key = keys
            .get(&escrow.key_id)
            .ok_or_else(|| KeyManagerError::KeyNotFound(escrow.key_id.clone()))?;

        // Create recovered key
        let mut recovered = original_key.clone();
        recovered.key_id = Uuid::new_v4().to_string();
        recovered.material = material;
        recovered.state = KeyState::Active;
        recovered.created_at = Utc::now();

        let recovered_id = recovered.key_id.clone();
        drop(keys);

        let mut keys = self.keys.write().await;
        keys.insert(recovered_id.clone(), recovered);

        Ok(recovered_id)
    }

    /// Get key
    pub async fn get_key(&self, key_id: &str) -> Result<ManagedKey> {
        let keys = self.keys.read().await;
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| KeyManagerError::KeyNotFound(key_id.to_string()))
    }

    /// Get key versions
    pub async fn get_key_versions(&self, key_id: &str) -> Vec<KeyVersion> {
        let versions = self.versions.read().await;
        versions.get(key_id).cloned().unwrap_or_default()
    }

    /// Mark key as compromised
    pub async fn mark_compromised(&self, key_id: &str) -> Result<()> {
        let mut keys = self.keys.write().await;
        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| KeyManagerError::KeyNotFound(key_id.to_string()))?;

        key.state = KeyState::Compromised;
        Ok(())
    }

    /// Destroy key
    pub async fn destroy_key(&self, key_id: &str) -> Result<()> {
        let mut keys = self.keys.write().await;
        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| KeyManagerError::KeyNotFound(key_id.to_string()))?;

        // Securely wipe key material
        key.material = vec![0u8; key.material.len()];
        key.state = KeyState::Destroyed;

        Ok(())
    }

    /// List keys by purpose
    pub async fn list_keys_by_purpose(&self, purpose: KeyPurpose) -> Vec<ManagedKey> {
        let keys = self.keys.read().await;
        keys.values()
            .filter(|k| k.purpose == purpose)
            .cloned()
            .collect()
    }

    /// List active keys
    pub async fn list_active_keys(&self) -> Vec<ManagedKey> {
        let keys = self.keys.read().await;
        keys.values()
            .filter(|k| k.state == KeyState::Active)
            .cloned()
            .collect()
    }
}

impl Default for AdvancedKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_key() {
        let manager = AdvancedKeyManager::new();

        let metadata = KeyMetadata {
            owner: "alice".to_string(),
            tags: HashMap::new(),
            parent_key_id: None,
            derivation_path: None,
        };

        let key_id = manager
            .generate_key(KeyType::AES256, KeyPurpose::Encryption, metadata)
            .await
            .unwrap();

        let key = manager.get_key(&key_id).await.unwrap();
        assert_eq!(key.key_type, KeyType::AES256);
        assert_eq!(key.version, 1);
        assert_eq!(key.state, KeyState::Active);
    }

    #[tokio::test]
    async fn test_rotate_key() {
        let manager = AdvancedKeyManager::new();

        let metadata = KeyMetadata {
            owner: "bob".to_string(),
            tags: HashMap::new(),
            parent_key_id: None,
            derivation_path: None,
        };

        let key_id = manager
            .generate_key(KeyType::ED25519, KeyPurpose::Signing, metadata)
            .await
            .unwrap();

        let new_version = manager.rotate_key(&key_id).await.unwrap();
        assert_eq!(new_version, 2);

        let key = manager.get_key(&key_id).await.unwrap();
        assert_eq!(key.version, 2);

        let versions = manager.get_key_versions(&key_id).await;
        assert_eq!(versions.len(), 2);
    }

    #[tokio::test]
    async fn test_derive_key() {
        let manager = AdvancedKeyManager::new();

        let metadata = KeyMetadata {
            owner: "charlie".to_string(),
            tags: HashMap::new(),
            parent_key_id: None,
            derivation_path: None,
        };

        let parent_id = manager
            .generate_key(KeyType::AES256, KeyPurpose::MasterKey, metadata)
            .await
            .unwrap();

        let request = KeyDerivationRequest {
            parent_key_id: parent_id.clone(),
            derivation_path: "m/0/1".to_string(),
            purpose: KeyPurpose::DerivedKey,
        };

        let derived_id = manager.derive_key(request).await.unwrap();
        let derived = manager.get_key(&derived_id).await.unwrap();

        assert_eq!(derived.metadata.parent_key_id, Some(parent_id));
        assert_eq!(derived.purpose, KeyPurpose::DerivedKey);
    }

    #[tokio::test]
    async fn test_split_and_reconstruct_key() {
        let manager = AdvancedKeyManager::new();

        let metadata = KeyMetadata {
            owner: "dave".to_string(),
            tags: HashMap::new(),
            parent_key_id: None,
            derivation_path: None,
        };

        let key_id = manager
            .generate_key(KeyType::AES256, KeyPurpose::Encryption, metadata)
            .await
            .unwrap();

        let escrow_id = manager.split_key(&key_id, 3, 5).await.unwrap();

        // Get shares
        let escrows = manager.escrows.read().await;
        let escrow = escrows.get(&escrow_id).unwrap();
        let shares: Vec<KeyShare> = escrow.shares.iter().take(3).cloned().collect();
        drop(escrows);

        let reconstructed = manager.reconstruct_key(&escrow_id, shares).await.unwrap();
        assert!(!reconstructed.is_empty());
    }

    #[tokio::test]
    async fn test_escrow_and_recover() {
        let manager = AdvancedKeyManager::new();

        let metadata = KeyMetadata {
            owner: "eve".to_string(),
            tags: HashMap::new(),
            parent_key_id: None,
            derivation_path: None,
        };

        let key_id = manager
            .generate_key(KeyType::RSA2048, KeyPurpose::Encryption, metadata)
            .await
            .unwrap();

        let policy = RecoveryPolicy {
            required_approvers: vec!["admin1".to_string(), "admin2".to_string()],
            timeout_hours: 48,
            multi_factor_required: true,
        };

        let escrow_id = manager.escrow_key(&key_id, policy).await.unwrap();

        let key = manager.get_key(&key_id).await.unwrap();
        assert_eq!(key.state, KeyState::Escrowed);

        // Recover
        let escrows = manager.escrows.read().await;
        let escrow = escrows.get(&escrow_id).unwrap();
        let shares: Vec<KeyShare> = escrow.shares.iter().take(3).cloned().collect();
        drop(escrows);

        let recovered_id = manager.recover_key(&escrow_id, shares).await.unwrap();
        let recovered = manager.get_key(&recovered_id).await.unwrap();
        assert_eq!(recovered.state, KeyState::Active);
    }

    #[tokio::test]
    async fn test_mark_compromised() {
        let manager = AdvancedKeyManager::new();

        let metadata = KeyMetadata {
            owner: "frank".to_string(),
            tags: HashMap::new(),
            parent_key_id: None,
            derivation_path: None,
        };

        let key_id = manager
            .generate_key(KeyType::ECDSA_P256, KeyPurpose::Signing, metadata)
            .await
            .unwrap();

        manager.mark_compromised(&key_id).await.unwrap();

        let key = manager.get_key(&key_id).await.unwrap();
        assert_eq!(key.state, KeyState::Compromised);
    }
}
