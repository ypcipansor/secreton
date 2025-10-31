//! Entity aliases for authentication method linking

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Alias lookup request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasLookupRequest {
    /// Alias name
    pub name: String,
    /// Mount accessor for the authentication method
    pub mount_accessor: String,
}

/// Alias creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasCreationRequest {
    /// Entity ID to create alias for
    pub entity_id: Uuid,
    /// Alias name
    pub name: String,
    /// Mount accessor
    pub mount_accessor: String,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

/// Alias update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasUpdateRequest {
    /// Alias name
    pub name: String,
    /// Mount accessor
    pub mount_accessor: String,
    /// Updated metadata
    pub metadata: HashMap<String, String>,
}

/// Alias deletion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasDeletionRequest {
    /// Alias name
    pub name: String,
    /// Mount accessor
    pub mount_accessor: String,
}
