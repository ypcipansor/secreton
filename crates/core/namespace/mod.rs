use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Errors that can occur in namespace operations
#[derive(Error, Debug)]
pub enum NamespaceError {
    #[error("Namespace not found: {0}")]
    NotFound(String),

    #[error("Namespace already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid namespace path: {0}")]
    InvalidPath(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Policy error: {0}")]
    PolicyError(String),
}

/// Unique identifier for namespaces
pub type NamespaceId = Uuid;

/// Resource quotas for a namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuotas {
    pub max_secrets: Option<usize>,
    pub max_engines: Option<usize>,
    pub max_policies: Option<usize>,
    pub max_users: Option<usize>,
    pub max_storage_size: Option<usize>, // in bytes
}

impl Default for ResourceQuotas {
    fn default() -> Self {
        Self {
            max_secrets: Some(10000),
            max_engines: Some(10),
            max_policies: Some(100),
            max_users: Some(1000),
            max_storage_size: Some(1024 * 1024 * 1024), // 1GB
        }
    }
}

/// Policy definition for namespace access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Policy rule for access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub path: String,
    pub capabilities: Vec<String>, // ["read", "write", "delete", "list"]
    pub conditions: Option<HashMap<String, String>>,
}

/// Hierarchical namespace structure for multi-tenancy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    pub id: NamespaceId,
    pub path: String, // "org/team/project"
    pub name: String,
    pub description: String,
    pub parent: Option<NamespaceId>,
    pub policies: Vec<Policy>,
    pub quotas: ResourceQuotas,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl Namespace {
    pub fn new(
        path: String,
        name: String,
        description: String,
        parent: Option<NamespaceId>,
    ) -> Result<Self, NamespaceError> {
        // Validate namespace path format
        if !Self::is_valid_path(&path) {
            return Err(NamespaceError::InvalidPath(format!("Invalid namespace path: {}", path)));
        }

        Ok(Self {
            id: Uuid::new_v4(),
            path,
            name,
            description,
            parent,
            policies: Vec::new(),
            quotas: ResourceQuotas::default(),
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        })
    }

    pub fn get_full_path(&self) -> String {
        if let Some(parent_id) = self.parent {
            // This would need to be resolved from the namespace tree
            format!("{}/{}", parent_id, self.path)
        } else {
            self.path.clone()
        }
    }

    pub fn get_depth(&self) -> usize {
        self.path.matches('/').count() + 1
    }

    fn is_valid_path(path: &str) -> bool {
        // Validate namespace path format
        // Should start and end with alphanumeric, contain only alphanumeric, hyphens, and slashes
        if path.is_empty() || path.len() > 255 {
            return false;
        }

        let mut prev_char = '/';
        for ch in path.chars() {
            match ch {
                '/' => {
                    if prev_char == '/' {
                        return false; // Double slashes not allowed
                    }
                }
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => {
                    // Valid characters
                }
                _ => return false,
            }
            prev_char = ch;
        }

        // Should not end with slash (except for root)
        if path != "/" && path.ends_with('/') {
            return false;
        }

        true
    }

    pub fn update_quotas(&mut self, quotas: ResourceQuotas) {
        self.quotas = quotas;
        self.updated_at = Utc::now();
    }

    pub fn add_policy(&mut self, policy: Policy) -> Result<(), NamespaceError> {
        // Check if policy name already exists
        if self.policies.iter().any(|p| p.name == policy.name) {
            return Err(NamespaceError::AlreadyExists(format!("Policy '{}' already exists", policy.name)));
        }

        self.policies.push(policy);
        self.updated_at = Utc::now();
        Ok(())
    }

    pub fn remove_policy(&mut self, policy_id: &Uuid) -> Result<Policy, NamespaceError> {
        if let Some(index) = self.policies.iter().position(|p| p.id == *policy_id) {
            let policy = self.policies.remove(index);
            self.updated_at = Utc::now();
            Ok(policy)
        } else {
            Err(NamespaceError::NotFound(format!("Policy with ID {} not found", policy_id)))
        }
    }
}

/// Namespace tree for hierarchical management
pub struct NamespaceTree {
    namespaces: Arc<RwLock<HashMap<NamespaceId, Namespace>>>,
    path_index: Arc<RwLock<HashMap<String, NamespaceId>>>,
}

impl NamespaceTree {
    pub fn new() -> Self {
        Self {
            namespaces: Arc::new(RwLock::new(HashMap::new())),
            path_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_namespace(
        &self,
        path: String,
        name: String,
        description: String,
        parent: Option<NamespaceId>,
    ) -> Result<NamespaceId, NamespaceError> {
        // Check if path already exists
        if self.path_index.read().await.contains_key(&path) {
            return Err(NamespaceError::AlreadyExists(format!("Namespace path '{}' already exists", path)));
        }

        // Validate parent exists (if specified)
        if let Some(parent_id) = parent {
            if !self.namespaces.read().await.contains_key(&parent_id) {
                return Err(NamespaceError::NotFound(format!("Parent namespace {} not found", parent_id)));
            }
        }

        let mut namespace = Namespace::new(path.clone(), name, description, parent)?;

        let namespace_id = namespace.id;
        let mut namespaces = self.namespaces.write().await;
        let mut path_index = self.path_index.write().await;

        namespaces.insert(namespace_id, namespace);
        path_index.insert(path, namespace_id);

        Ok(namespace_id)
    }

    pub async fn get_namespace(&self, namespace_id: &NamespaceId) -> Result<Option<Namespace>, NamespaceError> {
        let namespaces = self.namespaces.read().await;
        Ok(namespaces.get(namespace_id).cloned())
    }

    pub async fn get_namespace_by_path(&self, path: &str) -> Result<Option<Namespace>, NamespaceError> {
        let path_index = self.path_index.read().await;
        if let Some(&namespace_id) = path_index.get(path) {
            self.get_namespace(&namespace_id).await
        } else {
            Ok(None)
        }
    }

    pub async fn list_namespaces(&self) -> Result<Vec<Namespace>, NamespaceError> {
        let namespaces = self.namespaces.read().await;
        Ok(namespaces.values().cloned().collect())
    }

    pub async fn delete_namespace(&self, namespace_id: &NamespaceId) -> Result<(), NamespaceError> {
        let mut namespaces = self.namespaces.write().await;
        let mut path_index = self.path_index.write().await;

        if let Some(namespace) = namespaces.remove(namespace_id) {
            path_index.remove(&namespace.path);

            // TODO: Check for child namespaces and handle them appropriately
            // This might require cascading delete or preventing deletion with children

            Ok(())
        } else {
            Err(NamespaceError::NotFound(format!("Namespace {} not found", namespace_id)))
        }
    }

    pub async fn get_child_namespaces(&self, parent_id: &NamespaceId) -> Result<Vec<Namespace>, NamespaceError> {
        let namespaces = self.namespaces.read().await;
        Ok(namespaces.values()
            .filter(|ns| ns.parent.as_ref() == Some(parent_id))
            .cloned()
            .collect())
    }

    pub async fn get_root_namespaces(&self) -> Result<Vec<Namespace>, NamespaceError> {
        let namespaces = self.namespaces.read().await;
        Ok(namespaces.values()
            .filter(|ns| ns.parent.is_none())
            .cloned()
            .collect())
    }

    pub async fn get_namespace_hierarchy(&self, namespace_id: &NamespaceId) -> Result<Vec<Namespace>, NamespaceError> {
        let mut hierarchy = Vec::new();
        let mut current_id = Some(*namespace_id);

        while let Some(id) = current_id {
            if let Some(namespace) = self.get_namespace(&id).await? {
                hierarchy.push(namespace.clone());
                current_id = namespace.parent;
            } else {
                break;
            }
        }

        hierarchy.reverse(); // Root first
        Ok(hierarchy)
    }

    pub async fn validate_namespace_access(
        &self,
        namespace_id: &NamespaceId,
        user_id: &str,
        required_capabilities: &[&str],
    ) -> Result<bool, NamespaceError> {
        // Get namespace hierarchy (from leaf to root)
        let hierarchy = self.get_namespace_hierarchy(namespace_id).await?;

        for namespace in hierarchy {
            // Check policies in this namespace
            for policy in &namespace.policies {
                if self.evaluate_policy(&policy, user_id, required_capabilities).await? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn evaluate_policy(
        &self,
        policy: &Policy,
        user_id: &str,
        required_capabilities: &[&str],
    ) -> Result<bool, NamespaceError> {
        for rule in &policy.rules {
            // Check if rule path matches requested path (implement glob matching)
            if self.path_matches(&rule.path, &"") { // TODO: Implement actual path matching
                // Check if all required capabilities are granted
                let has_all_capabilities = required_capabilities.iter()
                    .all(|cap| rule.capabilities.contains(&cap.to_string()));

                if has_all_capabilities {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn path_matches(&self, rule_path: &str, requested_path: &str) -> bool {
        // TODO: Implement proper glob pattern matching for policy paths
        // For now, simple string matching
        rule_path == requested_path || rule_path == "*"
    }
}

impl Default for NamespaceTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "default".to_string(),
            description: "Default namespace policy".to_string(),
            rules: vec![
                PolicyRule {
                    path: "*".to_string(),
                    capabilities: vec!["read".to_string()],
                    conditions: None,
                }
            ],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            path: "*".to_string(),
            capabilities: vec!["read".to_string()],
            conditions: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_namespace_creation() {
        let tree = NamespaceTree::new();

        let namespace_id = tree.create_namespace(
            "test".to_string(),
            "Test Namespace".to_string(),
            "A test namespace".to_string(),
            None,
        ).await.unwrap();

        let namespace = tree.get_namespace(&namespace_id).await.unwrap().unwrap();
        assert_eq!(namespace.path, "test");
        assert_eq!(namespace.name, "Test Namespace");
    }

    #[tokio::test]
    async fn test_namespace_hierarchy() {
        let tree = NamespaceTree::new();

        // Create root namespace
        let root_id = tree.create_namespace(
            "org".to_string(),
            "Organization".to_string(),
            "Root organization".to_string(),
            None,
        ).await.unwrap();

        // Create child namespace
        let child_id = tree.create_namespace(
            "org/team".to_string(),
            "Team".to_string(),
            "Development team".to_string(),
            Some(root_id),
        ).await.unwrap();

        let hierarchy = tree.get_namespace_hierarchy(&child_id).await.unwrap();
        assert_eq!(hierarchy.len(), 2);
        assert_eq!(hierarchy[0].path, "org");
        assert_eq!(hierarchy[1].path, "org/team");
    }

    #[tokio::test]
    async fn test_namespace_validation() {
        assert!(Namespace::is_valid_path("org"));
        assert!(Namespace::is_valid_path("org/team"));
        assert!(Namespace::is_valid_path("org_team"));
        assert!(Namespace::is_valid_path("org/team/project"));

        assert!(!Namespace::is_valid_path(""));
        assert!(!Namespace::is_valid_path("org//team"));
        assert!(!Namespace::is_valid_path("org/"));
        assert!(!Namespace::is_valid_path("org/team/"));
    }
}
