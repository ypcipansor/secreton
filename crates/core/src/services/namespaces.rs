//! Namespaces
//!
//! Multi-tenancy isolation with hierarchical namespace structure.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Namespace errors
#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("Namespace not found: {0}")]
    NotFound(String),
    
    #[error("Namespace already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Invalid namespace path: {0}")]
    InvalidPath(String),
    
    #[error("Cannot delete root namespace")]
    CannotDeleteRoot,
    
    #[error("Cannot delete namespace with children")]
    HasChildren,
    
    #[error("Parent namespace not found: {0}")]
    ParentNotFound(String),
}

/// Namespace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    /// Namespace ID
    pub id: String,
    
    /// Namespace path (e.g., "root", "root/org1", "root/org1/team1")
    pub path: String,
    
    /// Parent namespace ID
    pub parent_id: Option<String>,
    
    /// Custom policies for this namespace
    pub policies: Vec<String>,
    
    /// Description
    pub description: Option<String>,
    
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Namespace {
    /// Create root namespace
    pub fn root() -> Self {
        Self {
            id: "root".to_string(),
            path: "root".to_string(),
            parent_id: None,
            policies: Vec::new(),
            description: Some("Root namespace".to_string()),
            created_at: Utc::now(),
            metadata: HashMap::new(),
        }
    }
    
    /// Get namespace depth
    pub fn depth(&self) -> usize {
        self.path.split('/').count()
    }
    
    /// Check if this is root namespace
    pub fn is_root(&self) -> bool {
        self.id == "root"
    }
}

/// Namespace tree for hierarchical management
#[derive(Debug, Clone)]
pub struct NamespaceTree {
    /// All namespaces by ID
    namespaces: HashMap<String, Namespace>,
    
    /// Children mapping: parent_id -> Vec<child_id>
    children: HashMap<String, Vec<String>>,
}

impl NamespaceTree {
    /// Create new tree with root namespace
    pub fn new() -> Self {
        let mut namespaces = HashMap::new();
        let root = Namespace::root();
        namespaces.insert(root.id.clone(), root);
        
        Self {
            namespaces,
            children: HashMap::new(),
        }
    }
    
    /// Add namespace
    pub fn add(&mut self, namespace: Namespace) -> Result<(), NamespaceError> {
        if self.namespaces.contains_key(&namespace.id) {
            return Err(NamespaceError::AlreadyExists(namespace.id.clone()));
        }
        
        // Verify parent exists
        if let Some(parent_id) = &namespace.parent_id {
            if !self.namespaces.contains_key(parent_id) {
                return Err(NamespaceError::ParentNotFound(parent_id.clone()));
            }
            
            // Add to children mapping
            self.children.entry(parent_id.clone())
                .or_insert_with(Vec::new)
                .push(namespace.id.clone());
        }
        
        self.namespaces.insert(namespace.id.clone(), namespace);
        Ok(())
    }
    
    /// Get namespace by ID
    pub fn get(&self, id: &str) -> Option<&Namespace> {
        self.namespaces.get(id)
    }
    
    /// Get namespace by path
    pub fn get_by_path(&self, path: &str) -> Option<&Namespace> {
        self.namespaces.values()
            .find(|ns| ns.path == path)
    }
    
    /// Get children of namespace
    pub fn get_children(&self, parent_id: &str) -> Vec<&Namespace> {
        if let Some(child_ids) = self.children.get(parent_id) {
            child_ids.iter()
                .filter_map(|id| self.namespaces.get(id))
                .collect()
        } else {
            Vec::new()
        }
    }
    
    /// Remove namespace
    pub fn remove(&mut self, id: &str) -> Result<(), NamespaceError> {
        if id == "root" {
            return Err(NamespaceError::CannotDeleteRoot);
        }
        
        // Check for children
        if let Some(children) = self.children.get(id) {
            if !children.is_empty() {
                return Err(NamespaceError::HasChildren);
            }
        }
        
        let namespace = self.namespaces.remove(id)
            .ok_or_else(|| NamespaceError::NotFound(id.to_string()))?;
        
        // Remove from parent's children
        if let Some(parent_id) = &namespace.parent_id {
            if let Some(children) = self.children.get_mut(parent_id) {
                children.retain(|child_id| child_id != id);
            }
        }
        
        Ok(())
    }
    
    /// List all namespaces
    pub fn list_all(&self) -> Vec<&Namespace> {
        self.namespaces.values().collect()
    }
}

impl Default for NamespaceTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Namespace service
pub struct NamespaceService {
    tree: Arc<RwLock<NamespaceTree>>,
}

impl NamespaceService {
    /// Create new namespace service
    pub fn new() -> Self {
        Self {
            tree: Arc::new(RwLock::new(NamespaceTree::new())),
        }
    }
    
    /// Create namespace
    pub async fn create(&self, mut namespace: Namespace) -> Result<String, NamespaceError> {
        // Validate path
        if namespace.path.is_empty() || namespace.path.contains("//") {
            return Err(NamespaceError::InvalidPath(namespace.path.clone()));
        }
        
        // Auto-generate ID if not provided
        if namespace.id.is_empty() {
            namespace.id = uuid::Uuid::new_v4().to_string();
        }
        
        let id = namespace.id.clone();
        
        let mut tree = self.tree.write().await;
        tree.add(namespace)?;
        
        Ok(id)
    }
    
    /// Get namespace by ID
    pub async fn get(&self, id: &str) -> Option<Namespace> {
        let tree = self.tree.read().await;
        tree.get(id).cloned()
    }
    
    /// Get namespace by path
    pub async fn get_by_path(&self, path: &str) -> Option<Namespace> {
        let tree = self.tree.read().await;
        tree.get_by_path(path).cloned()
    }
    
    /// List namespaces
    pub async fn list(&self, parent_id: Option<&str>) -> Vec<Namespace> {
        let tree = self.tree.read().await;
        
        if let Some(parent) = parent_id {
            tree.get_children(parent)
                .into_iter()
                .cloned()
                .collect()
        } else {
            tree.list_all()
                .into_iter()
                .cloned()
                .collect()
        }
    }
    
    /// Delete namespace
    pub async fn delete(&self, id: &str) -> Result<(), NamespaceError> {
        let mut tree = self.tree.write().await;
        tree.remove(id)
    }
    
    /// Resolve path with namespace prefix
    /// E.g., "ns1/secret/data" -> namespace "ns1", path "secret/data"
    pub async fn resolve_path(&self, full_path: &str) -> Result<(Namespace, String), NamespaceError> {
        if full_path.is_empty() {
            return Err(NamespaceError::InvalidPath(full_path.to_string()));
        }
        
        let tree = self.tree.read().await;
        
        // Try to find namespace by matching path prefix
        let parts: Vec<&str> = full_path.split('/').collect();
        
        // Try decreasing prefixes: "root/org1/team1", "root/org1", "root"
        for i in (1..=parts.len()).rev() {
            let ns_path = parts[..i].join("/");
            
            if let Some(namespace) = tree.get_by_path(&ns_path) {
                let remaining_path = if i < parts.len() {
                    parts[i..].join("/")
                } else {
                    String::new()
                };
                
                return Ok((namespace.clone(), remaining_path));
            }
        }
        
        // Default to root namespace
        let root = tree.get("root")
            .ok_or_else(|| NamespaceError::NotFound("root".to_string()))?;
        
        Ok((root.clone(), full_path.to_string()))
    }
    
    /// Update namespace
    pub async fn update(&self, id: &str, update_fn: impl FnOnce(&mut Namespace)) -> Result<(), NamespaceError> {
        let mut tree = self.tree.write().await;
        
        let namespace = tree.namespaces.get_mut(id)
            .ok_or_else(|| NamespaceError::NotFound(id.to_string()))?;
        
        update_fn(namespace);
        
        Ok(())
    }
    
    /// Check if path is within namespace
    pub async fn is_within_namespace(&self, namespace_id: &str, path: &str) -> bool {
        let tree = self.tree.read().await;
        
        if let Some(namespace) = tree.get(namespace_id) {
            path.starts_with(&format!("{}/", namespace.path)) || path == namespace.path
        } else {
            false
        }
    }
}

impl Default for NamespaceService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_namespace() {
        let service = NamespaceService::new();
        
        let namespace = Namespace {
            id: "org1".to_string(),
            path: "root/org1".to_string(),
            parent_id: Some("root".to_string()),
            policies: vec!["org1-policy".to_string()],
            description: Some("Organization 1".to_string()),
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        
        let id = service.create(namespace).await.unwrap();
        assert_eq!(id, "org1");
        
        let retrieved = service.get("org1").await.unwrap();
        assert_eq!(retrieved.path, "root/org1");
    }
    
    #[tokio::test]
    async fn test_hierarchical_namespaces() {
        let service = NamespaceService::new();
        
        // Create org1
        let org1 = Namespace {
            id: "org1".to_string(),
            path: "root/org1".to_string(),
            parent_id: Some("root".to_string()),
            policies: Vec::new(),
            description: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        service.create(org1).await.unwrap();
        
        // Create team1 under org1
        let team1 = Namespace {
            id: "team1".to_string(),
            path: "root/org1/team1".to_string(),
            parent_id: Some("org1".to_string()),
            policies: Vec::new(),
            description: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        service.create(team1).await.unwrap();
        
        let children = service.list(Some("org1")).await;
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].id, "team1");
    }
    
    #[tokio::test]
    async fn test_path_resolution() {
        let service = NamespaceService::new();
        
        let org1 = Namespace {
            id: "org1".to_string(),
            path: "root/org1".to_string(),
            parent_id: Some("root".to_string()),
            policies: Vec::new(),
            description: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        service.create(org1).await.unwrap();
        
        let (namespace, remaining) = service.resolve_path("root/org1/secret/data").await.unwrap();
        assert_eq!(namespace.id, "org1");
        assert_eq!(remaining, "secret/data");
        
        let (root_ns, remaining) = service.resolve_path("secret/data").await.unwrap();
        assert_eq!(root_ns.id, "root");
        assert_eq!(remaining, "secret/data");
    }
    
    #[tokio::test]
    async fn test_delete_namespace() {
        let service = NamespaceService::new();
        
        let org1 = Namespace {
            id: "org1".to_string(),
            path: "root/org1".to_string(),
            parent_id: Some("root".to_string()),
            policies: Vec::new(),
            description: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        service.create(org1).await.unwrap();
        
        service.delete("org1").await.unwrap();
        
        assert!(service.get("org1").await.is_none());
    }
    
    #[tokio::test]
    async fn test_cannot_delete_with_children() {
        let service = NamespaceService::new();
        
        let org1 = Namespace {
            id: "org1".to_string(),
            path: "root/org1".to_string(),
            parent_id: Some("root".to_string()),
            policies: Vec::new(),
            description: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        service.create(org1).await.unwrap();
        
        let team1 = Namespace {
            id: "team1".to_string(),
            path: "root/org1/team1".to_string(),
            parent_id: Some("org1".to_string()),
            policies: Vec::new(),
            description: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };
        service.create(team1).await.unwrap();
        
        let result = service.delete("org1").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NamespaceError::HasChildren));
    }
}
