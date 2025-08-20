//! Key types and metadata

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Supported key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Aes256Gcm,
    HmacSha256,
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique key ID
    pub id: Uuid,
    
    /// Key name/description
    pub name: String,
    
    /// Key creation time
    pub created_at: u64,
    
    /// Key expiration time (0 for never)
    pub expires_at: u64,
    
    /// Whether the key is enabled
    pub enabled: bool,
    
    /// Key tags for organization
    pub tags: Vec<String>,
    
    /// ID of the previous key version (for key rotation)
    pub previous_version: Option<Uuid>,
}

impl Default for KeyMetadata {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_at: 0, // Never expires by default
            enabled: true,
            tags: Vec::new(),
            previous_version: None,
        }
    }
}

impl KeyMetadata {
    /// Create new metadata with the given name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
    
    /// Set the key name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
    
    /// Set the expiration time (in seconds since epoch)
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }
    
    /// Set the expiration time as a duration from now
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.expires_at = self.created_at + ttl_seconds;
        self
    }
    
    /// Add a tag to the key
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
    
    /// Check if the key is expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // Never expires
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        now >= self.expires_at
    }
}

/// Key data (the actual key material)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyData {
    Aes256Gcm(Vec<u8>),
    HmacSha256(Vec<u8>),
}

/// A cryptographic key with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    /// Unique identifier
    pub id: Uuid,
    
    /// Key metadata
    pub metadata: KeyMetadata,
    
    /// The actual key material
    pub data: KeyData,
}

impl Key {
    /// Create a new key with the given data
    pub fn new(data: KeyData) -> Self {
        Self {
            id: Uuid::new_v4(),
            metadata: KeyMetadata::default(),
            data,
        }
    }
    
    /// Create a new key with metadata
    pub fn with_metadata(mut self, metadata: KeyMetadata) -> Self {
        self.metadata = metadata;
        self.id = self.metadata.id;
        self
    }
    
    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        match self.data {
            KeyData::Aes256Gcm(_) => KeyType::Aes256Gcm,
            KeyData::HmacSha256(_) => KeyType::HmacSha256,
        }
    }
    
    /// Check if the key is valid (enabled and not expired)
    pub fn is_valid(&self) -> bool {
        self.metadata.enabled && !self.metadata.is_expired()
    }
}
