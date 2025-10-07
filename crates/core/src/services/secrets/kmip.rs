//! KMIP (Key Management Interoperability Protocol) Secrets Engine
//!
//! Enterprise key management standard for cryptographic key lifecycle operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// KMIP errors
#[derive(Debug, thiserror::Error)]
pub enum KmipError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    
    #[error("Invalid key state: {0}")]
    InvalidKeyState(String),
    
    #[error("Operation not permitted: {0}")]
    OperationNotPermitted(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

/// KMIP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipServerConfig {
    /// KMIP server host
    pub host: String,
    
    /// KMIP server port
    pub port: u16,
    
    /// CA certificate for server validation
    pub ca_cert: Option<String>,
    
    /// Client certificate for mTLS
    pub client_cert: Option<String>,
    
    /// Client private key
    pub client_key: Option<String>,
    
    /// TLS enabled
    pub tls_enabled: bool,
}

/// KMIP operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KmipOperation {
    /// Create new key
    Create,
    
    /// Get existing key
    Get,
    
    /// Register external key
    Register,
    
    /// Revoke key
    Revoke,
    
    /// Destroy key
    Destroy,
    
    /// Query key attributes
    Query,
    
    /// Activate key
    Activate,
}

/// Key state in KMIP lifecycle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KmipKeyState {
    /// Pre-activation state
    PreActive,
    
    /// Active and usable
    Active,
    
    /// Deactivated (temporarily suspended)
    Deactivated,
    
    /// Compromised
    Compromised,
    
    /// Destroyed
    Destroyed,
}

/// Key format types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KmipKeyFormat {
    /// Raw binary format
    Raw,
    
    /// PKCS#1 format
    Pkcs1,
    
    /// PKCS#8 format
    Pkcs8,
    
    /// X.509 certificate
    X509,
}

/// KMIP key object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipKeyObject {
    /// Unique key identifier
    pub key_id: String,
    
    /// Key format
    pub key_format: KmipKeyFormat,
    
    /// Key material (encrypted in production)
    pub key_material: Vec<u8>,
    
    /// Current key state
    pub key_state: KmipKeyState,
    
    /// Algorithm (e.g., "AES", "RSA")
    pub algorithm: String,
    
    /// Key length in bits
    pub key_length: usize,
    
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last modified timestamp
    pub modified_at: DateTime<Utc>,
    
    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

/// KMIP role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipRole {
    /// Role name
    pub name: String,
    
    /// Allowed operations
    pub allowed_operations: Vec<KmipOperation>,
    
    /// Key name patterns (wildcards supported)
    pub key_name_patterns: Vec<String>,
    
    /// Policies to attach to tokens
    pub policies: Vec<String>,
    
    /// TTL for generated credentials
    pub ttl: Option<u64>,
}

/// KMIP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipRequest {
    /// Operation type
    pub operation: KmipOperation,
    
    /// Key identifier (for get/revoke/destroy)
    pub key_id: Option<String>,
    
    /// Algorithm (for create/register)
    pub algorithm: Option<String>,
    
    /// Key length (for create)
    pub key_length: Option<usize>,
    
    /// Key material (for register)
    pub key_material: Option<Vec<u8>>,
    
    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

/// KMIP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipResponse {
    /// Success status
    pub success: bool,
    
    /// Key object (for create/get/register)
    pub key_object: Option<KmipKeyObject>,
    
    /// Error message
    pub error: Option<String>,
    
    /// Result attributes
    pub attributes: HashMap<String, String>,
}

/// KMIP secrets engine
pub struct KmipEngine {
    server_config: Arc<RwLock<Option<KmipServerConfig>>>,
    keys: Arc<RwLock<HashMap<String, KmipKeyObject>>>,
    roles: Arc<RwLock<HashMap<String, KmipRole>>>,
}

impl KmipEngine {
    /// Create new KMIP engine
    pub fn new() -> Self {
        Self {
            server_config: Arc::new(RwLock::new(None)),
            keys: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Configure KMIP server connection
    pub async fn configure_server(&self, config: KmipServerConfig) -> Result<(), KmipError> {
        let mut server_config = self.server_config.write().await;
        *server_config = Some(config);
        Ok(())
    }
    
    /// Create new cryptographic key
    pub async fn create_key(
        &self,
        algorithm: String,
        key_length: usize,
        attributes: HashMap<String, String>,
    ) -> Result<KmipKeyObject, KmipError> {
        let key_id = uuid::Uuid::new_v4().to_string();
        
        // Simulate key generation (production would call KMIP server)
        let key_material = vec![0u8; key_length / 8];
        
        let key_object = KmipKeyObject {
            key_id: key_id.clone(),
            key_format: KmipKeyFormat::Raw,
            key_material,
            key_state: KmipKeyState::PreActive,
            algorithm,
            key_length,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            attributes,
        };
        
        let mut keys = self.keys.write().await;
        keys.insert(key_id, key_object.clone());
        
        Ok(key_object)
    }
    
    /// Get key by ID
    pub async fn get_key(&self, key_id: &str) -> Result<KmipKeyObject, KmipError> {
        let keys = self.keys.read().await;
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| KmipError::KeyNotFound(key_id.to_string()))
    }
    
    /// Register external key
    pub async fn register_key(
        &self,
        algorithm: String,
        key_material: Vec<u8>,
        attributes: HashMap<String, String>,
    ) -> Result<KmipKeyObject, KmipError> {
        let key_id = uuid::Uuid::new_v4().to_string();
        let key_length = key_material.len() * 8;
        
        let key_object = KmipKeyObject {
            key_id: key_id.clone(),
            key_format: KmipKeyFormat::Raw,
            key_material,
            key_state: KmipKeyState::PreActive,
            algorithm,
            key_length,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            attributes,
        };
        
        let mut keys = self.keys.write().await;
        keys.insert(key_id, key_object.clone());
        
        Ok(key_object)
    }
    
    /// Activate key
    pub async fn activate_key(&self, key_id: &str) -> Result<KmipKeyObject, KmipError> {
        let mut keys = self.keys.write().await;
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmipError::KeyNotFound(key_id.to_string()))?;
        
        if key.key_state != KmipKeyState::PreActive && key.key_state != KmipKeyState::Deactivated {
            return Err(KmipError::InvalidKeyState(format!(
                "Cannot activate key in state: {:?}",
                key.key_state
            )));
        }
        
        key.key_state = KmipKeyState::Active;
        key.modified_at = Utc::now();
        
        Ok(key.clone())
    }
    
    /// Revoke key
    pub async fn revoke_key(&self, key_id: &str) -> Result<KmipKeyObject, KmipError> {
        let mut keys = self.keys.write().await;
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmipError::KeyNotFound(key_id.to_string()))?;
        
        if key.key_state == KmipKeyState::Destroyed {
            return Err(KmipError::InvalidKeyState("Key already destroyed".to_string()));
        }
        
        key.key_state = KmipKeyState::Compromised;
        key.modified_at = Utc::now();
        
        Ok(key.clone())
    }
    
    /// Destroy key (permanent deletion)
    pub async fn destroy_key(&self, key_id: &str) -> Result<(), KmipError> {
        let mut keys = self.keys.write().await;
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmipError::KeyNotFound(key_id.to_string()))?;
        
        key.key_state = KmipKeyState::Destroyed;
        key.key_material.clear(); // Zero out key material
        key.modified_at = Utc::now();
        
        Ok(())
    }
    
    /// List all keys
    pub async fn list_keys(&self) -> Vec<String> {
        let keys = self.keys.read().await;
        keys.keys().cloned().collect()
    }
    
    /// Create role
    pub async fn create_role(&self, role: KmipRole) -> Result<(), KmipError> {
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);
        Ok(())
    }
    
    /// Get role
    pub async fn get_role(&self, name: &str) -> Option<KmipRole> {
        let roles = self.roles.read().await;
        roles.get(name).cloned()
    }
    
    /// Process KMIP request
    pub async fn process_request(&self, request: KmipRequest) -> KmipResponse {
        match request.operation {
            KmipOperation::Create => {
                match self.create_key(
                    request.algorithm.unwrap_or_else(|| "AES".to_string()),
                    request.key_length.unwrap_or(256),
                    request.attributes,
                ).await {
                    Ok(key_object) => KmipResponse {
                        success: true,
                        key_object: Some(key_object),
                        error: None,
                        attributes: HashMap::new(),
                    },
                    Err(e) => KmipResponse {
                        success: false,
                        key_object: None,
                        error: Some(e.to_string()),
                        attributes: HashMap::new(),
                    },
                }
            }
            KmipOperation::Get => {
                let key_id = request.key_id.unwrap_or_default();
                match self.get_key(&key_id).await {
                    Ok(key_object) => KmipResponse {
                        success: true,
                        key_object: Some(key_object),
                        error: None,
                        attributes: HashMap::new(),
                    },
                    Err(e) => KmipResponse {
                        success: false,
                        key_object: None,
                        error: Some(e.to_string()),
                        attributes: HashMap::new(),
                    },
                }
            }
            KmipOperation::Activate => {
                let key_id = request.key_id.unwrap_or_default();
                match self.activate_key(&key_id).await {
                    Ok(key_object) => KmipResponse {
                        success: true,
                        key_object: Some(key_object),
                        error: None,
                        attributes: HashMap::new(),
                    },
                    Err(e) => KmipResponse {
                        success: false,
                        key_object: None,
                        error: Some(e.to_string()),
                        attributes: HashMap::new(),
                    },
                }
            }
            _ => KmipResponse {
                success: false,
                key_object: None,
                error: Some("Operation not implemented".to_string()),
                attributes: HashMap::new(),
            },
        }
    }
}

impl Default for KmipEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_and_get_key() {
        let engine = KmipEngine::new();
        
        let mut attrs = HashMap::new();
        attrs.insert("application".to_string(), "test-app".to_string());
        
        let key = engine.create_key("AES".to_string(), 256, attrs).await.unwrap();
        assert_eq!(key.algorithm, "AES");
        assert_eq!(key.key_length, 256);
        assert_eq!(key.key_state, KmipKeyState::PreActive);
        
        let retrieved = engine.get_key(&key.key_id).await.unwrap();
        assert_eq!(retrieved.key_id, key.key_id);
    }
    
    #[tokio::test]
    async fn test_key_lifecycle() {
        let engine = KmipEngine::new();
        
        let key = engine.create_key("RSA".to_string(), 2048, HashMap::new()).await.unwrap();
        assert_eq!(key.key_state, KmipKeyState::PreActive);
        
        // Activate
        let activated = engine.activate_key(&key.key_id).await.unwrap();
        assert_eq!(activated.key_state, KmipKeyState::Active);
        
        // Revoke
        let revoked = engine.revoke_key(&key.key_id).await.unwrap();
        assert_eq!(revoked.key_state, KmipKeyState::Compromised);
        
        // Destroy
        engine.destroy_key(&key.key_id).await.unwrap();
        let destroyed = engine.get_key(&key.key_id).await.unwrap();
        assert_eq!(destroyed.key_state, KmipKeyState::Destroyed);
        assert!(destroyed.key_material.is_empty());
    }
    
    #[tokio::test]
    async fn test_register_external_key() {
        let engine = KmipEngine::new();
        
        let key_material = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let key = engine.register_key(
            "AES".to_string(),
            key_material.clone(),
            HashMap::new(),
        ).await.unwrap();
        
        assert_eq!(key.key_material, key_material);
        assert_eq!(key.key_length, 64); // 8 bytes * 8
    }
    
    #[tokio::test]
    async fn test_kmip_role() {
        let engine = KmipEngine::new();
        
        let role = KmipRole {
            name: "test-role".to_string(),
            allowed_operations: vec![KmipOperation::Create, KmipOperation::Get],
            key_name_patterns: vec!["app-*".to_string()],
            policies: vec!["default".to_string()],
            ttl: Some(3600),
        };
        
        engine.create_role(role.clone()).await.unwrap();
        
        let retrieved = engine.get_role("test-role").await.unwrap();
        assert_eq!(retrieved.name, "test-role");
        assert_eq!(retrieved.allowed_operations.len(), 2);
    }
}
