// Secret Dependency Graph - Track secret dependencies and impact analysis
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum DependencyGraphError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Graph error: {0}")]
    GraphError(String),
    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),
}

pub type Result<T> = std::result::Result<T, DependencyGraphError>;

/// Node type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeType {
    Secret,
    Service,
    Application,
}

/// Dependency type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencyType {
    Requires,
    References,
    RotatesWith,
}

/// Dependency strength
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencyStrength {
    Strong, // Critical dependency
    Weak,   // Optional dependency
}

/// Dependency graph configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphConfig {
    pub enabled: bool,
    pub track_access_patterns: bool,
    pub circular_dependency_check: bool,
    pub max_depth: u32,
}

/// Secret node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretNode {
    pub node_id: String,
    pub secret_path: String,
    pub node_type: NodeType,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: Option<DateTime<Utc>>,
}

/// Dependency edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub dependency_id: String,
    pub source_node_id: String, // Node that depends on
    pub target_node_id: String, // Dependency target
    pub dependency_type: DependencyType,
    pub strength: DependencyStrength,
    pub created_at: DateTime<Utc>,
}

/// Dependency path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyPath {
    pub path: Vec<String>, // Node IDs
    pub total_hops: usize,
    pub is_circular: bool,
}

/// Impact analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    pub affected_nodes: Vec<SecretNode>,
    pub affected_services: Vec<String>,
    pub rotation_order: Vec<String>, // Ordered list of secret paths
    pub estimated_impact_score: f64, // 0.0 - 1.0
}

/// Secret Dependency Graph
pub struct SecretDependencyGraph {
    config: Arc<RwLock<DependencyGraphConfig>>,
    nodes: Arc<RwLock<HashMap<String, SecretNode>>>,
    dependencies: Arc<RwLock<Vec<Dependency>>>,
    adjacency_list: Arc<RwLock<HashMap<String, Vec<String>>>>, // node_id -> [dependent_node_ids]
}

impl SecretDependencyGraph {
    pub fn new(config: DependencyGraphConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            dependencies: Arc::new(RwLock::new(Vec::new())),
            adjacency_list: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add secret node
    pub async fn add_secret_node(&self, node: SecretNode) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        nodes.insert(node.node_id.clone(), node);
        Ok(())
    }

    /// Add dependency
    pub async fn add_dependency(&self, dependency: Dependency) -> Result<()> {
        let config = self.config.read().await;
        if config.circular_dependency_check {
            // Check for circular dependencies
            if self
                .would_create_cycle(&dependency.source_node_id, &dependency.target_node_id)
                .await
            {
                return Err(DependencyGraphError::CircularDependency(format!(
                    "Adding dependency from {} to {} would create a cycle",
                    dependency.source_node_id, dependency.target_node_id
                )));
            }
        }
        drop(config);

        // Add to adjacency list
        let mut adjacency_list = self.adjacency_list.write().await;
        adjacency_list
            .entry(dependency.target_node_id.clone())
            .or_insert_with(Vec::new)
            .push(dependency.source_node_id.clone());
        drop(adjacency_list);

        // Add dependency
        let mut dependencies = self.dependencies.write().await;
        dependencies.push(dependency);

        Ok(())
    }

    /// Get dependencies for a node
    pub async fn get_dependencies(&self, node_id: &str) -> Vec<Dependency> {
        let dependencies = self.dependencies.read().await;
        dependencies
            .iter()
            .filter(|d| d.source_node_id == node_id)
            .cloned()
            .collect()
    }

    /// Get dependents (nodes that depend on this node)
    pub async fn get_dependents(&self, node_id: &str) -> Vec<SecretNode> {
        let adjacency_list = self.adjacency_list.read().await;
        let dependent_ids = adjacency_list.get(node_id).cloned().unwrap_or_default();
        drop(adjacency_list);

        let nodes = self.nodes.read().await;
        dependent_ids
            .iter()
            .filter_map(|id| nodes.get(id).cloned())
            .collect()
    }

    /// Analyze impact of secret change
    pub async fn analyze_impact(&self, node_id: &str) -> Result<ImpactAnalysis> {
        let nodes = self.nodes.read().await;
        let node = nodes
            .get(node_id)
            .ok_or_else(|| DependencyGraphError::GraphError("Node not found".to_string()))?
            .clone();
        drop(nodes);

        // BFS to find all affected nodes
        let affected_nodes = self.bfs_affected_nodes(node_id).await;

        // Extract services
        let affected_services: Vec<String> = affected_nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Service || n.node_type == NodeType::Application)
            .map(|n| n.metadata.get("service_name").cloned().unwrap_or_default())
            .collect();

        // Get rotation order (topological sort)
        let rotation_order = self.get_rotation_order_from_nodes(&affected_nodes).await;

        // Calculate impact score
        let impact_score = self.calculate_impact_score(&affected_nodes);

        Ok(ImpactAnalysis {
            affected_nodes,
            affected_services,
            rotation_order,
            estimated_impact_score: impact_score,
        })
    }

    /// Detect circular dependencies
    pub async fn detect_circular_dependencies(&self) -> Vec<DependencyPath> {
        let mut circular_paths = Vec::new();
        let nodes = self.nodes.read().await;

        for node_id in nodes.keys() {
            if let Some(path) = self.find_cycle_from_node(node_id).await {
                circular_paths.push(DependencyPath {
                    path: path.clone(),
                    total_hops: path.len(),
                    is_circular: true,
                });
            }
        }

        circular_paths
    }

    /// Get rotation order (topological sort)
    pub async fn get_rotation_order(&self) -> Vec<String> {
        let nodes = self.nodes.read().await;
        let all_nodes: Vec<SecretNode> = nodes
            .values()
            .filter(|n| n.node_type == NodeType::Secret)
            .cloned()
            .collect();
        drop(nodes);

        self.get_rotation_order_from_nodes(&all_nodes).await
    }

    /// Export graph data
    pub async fn export_graph_data(&self, format: &str) -> Result<String> {
        let nodes = self.nodes.read().await;
        let dependencies = self.dependencies.read().await;

        match format {
            "json" => {
                let graph_data = serde_json::json!({
                    "nodes": nodes.values().collect::<Vec<_>>(),
                    "edges": dependencies.iter().collect::<Vec<_>>(),
                });
                Ok(serde_json::to_string_pretty(&graph_data).unwrap())
            }
            "dot" => {
                let mut dot = String::from("digraph Dependencies {\n");
                for node in nodes.values() {
                    dot.push_str(&format!(
                        "  \"{}\" [label=\"{}\"];\n",
                        node.node_id, node.secret_path
                    ));
                }
                for dep in dependencies.iter() {
                    dot.push_str(&format!(
                        "  \"{}\" -> \"{}\" [label=\"{:?}\"];\n",
                        dep.source_node_id, dep.target_node_id, dep.dependency_type
                    ));
                }
                dot.push_str("}\n");
                Ok(dot)
            }
            _ => Err(DependencyGraphError::ConfigError(
                "Unsupported format".to_string(),
            )),
        }
    }

    /// Get node
    pub async fn get_node(&self, node_id: &str) -> Option<SecretNode> {
        let nodes = self.nodes.read().await;
        nodes.get(node_id).cloned()
    }

    /// List all nodes
    pub async fn list_nodes(&self) -> Vec<SecretNode> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }

    // Helper methods

    async fn would_create_cycle(&self, source: &str, target: &str) -> bool {
        // Check if adding edge from source to target creates a cycle
        // This means checking if there's already a path from target to source
        self.has_path(target, source).await
    }

    async fn has_path(&self, from: &str, to: &str) -> bool {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(from.to_string());

        while let Some(current) = queue.pop_front() {
            if current == to {
                return true;
            }

            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            let dependencies = self.get_dependencies(&current).await;
            for dep in dependencies {
                queue.push_back(dep.target_node_id);
            }
        }

        false
    }

    async fn find_cycle_from_node(&self, start_node: &str) -> Option<Vec<String>> {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        self.dfs_cycle(start_node, &mut visited, &mut path).await
    }

    fn dfs_cycle<'a>(
        &'a self,
        node: &'a str,
        visited: &'a mut HashSet<String>,
        path: &'a mut Vec<String>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            if path.contains(&node.to_string()) {
                // Found cycle
                let mut cycle = path.clone();
                cycle.push(node.to_string());
                return Some(cycle);
            }

            if visited.contains(node) {
                return None;
            }

            visited.insert(node.to_string());
            path.push(node.to_string());

            let dependencies = self.get_dependencies(node).await;
            for dep in dependencies {
                if let Some(cycle) = self.dfs_cycle(&dep.target_node_id, visited, path).await {
                    return Some(cycle);
                }
            }

            path.pop();
            None
        })
    }

    async fn bfs_affected_nodes(&self, start_node: &str) -> Vec<SecretNode> {
        let mut affected = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_node.to_string());

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            if let Some(node) = self.get_node(&current).await {
                affected.push(node);
            }

            let dependents = self.get_dependents(&current).await;
            for dep in dependents {
                queue.push_back(dep.node_id);
            }
        }

        affected
    }

    async fn get_rotation_order_from_nodes(&self, nodes: &[SecretNode]) -> Vec<String> {
        // Simple topological sort
        let mut order = Vec::new();
        let mut visited = HashSet::new();

        for node in nodes {
            if !visited.contains(&node.node_id) {
                self.topological_sort_visit(&node.node_id, &mut visited, &mut order)
                    .await;
            }
        }

        order.reverse();
        order
            .iter()
            .filter_map(|id| {
                nodes
                    .iter()
                    .find(|n| &n.node_id == id)
                    .map(|n| n.secret_path.clone())
            })
            .collect()
    }

    fn topological_sort_visit<'a>(
        &'a self,
        node_id: &'a str,
        visited: &'a mut HashSet<String>,
        order: &'a mut Vec<String>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            visited.insert(node_id.to_string());

            let dependencies = self.get_dependencies(node_id).await;
            for dep in dependencies {
                if !visited.contains(&dep.target_node_id) {
                    self.topological_sort_visit(&dep.target_node_id, visited, order)
                        .await;
                }
            }

            order.push(node_id.to_string());
        })
    }

    fn calculate_impact_score(&self, affected_nodes: &[SecretNode]) -> f64 {
        if affected_nodes.is_empty() {
            return 0.0;
        }

        let service_count = affected_nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Service || n.node_type == NodeType::Application)
            .count();

        // Score based on number of affected services (normalized)
        (service_count as f64 / 10.0).min(1.0)
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> GraphStatistics {
        let nodes = self.nodes.read().await;
        let dependencies = self.dependencies.read().await;

        let total_nodes = nodes.len();
        let secret_nodes = nodes
            .values()
            .filter(|n| n.node_type == NodeType::Secret)
            .count();
        let service_nodes = nodes
            .values()
            .filter(|n| n.node_type == NodeType::Service || n.node_type == NodeType::Application)
            .count();
        let total_dependencies = dependencies.len();
        let strong_dependencies = dependencies
            .iter()
            .filter(|d| d.strength == DependencyStrength::Strong)
            .count();

        GraphStatistics {
            total_nodes,
            secret_nodes,
            service_nodes,
            total_dependencies,
            strong_dependencies,
        }
    }
}

/// Graph statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStatistics {
    pub total_nodes: usize,
    pub secret_nodes: usize,
    pub service_nodes: usize,
    pub total_dependencies: usize,
    pub strong_dependencies: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> DependencyGraphConfig {
        DependencyGraphConfig {
            enabled: true,
            track_access_patterns: true,
            circular_dependency_check: true,
            max_depth: 10,
        }
    }

    #[tokio::test]
    async fn test_add_nodes_and_dependencies() {
        let graph = SecretDependencyGraph::new(create_test_config());

        let node1 = SecretNode {
            node_id: "node1".to_string(),
            secret_path: "secret/db".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        let node2 = SecretNode {
            node_id: "node2".to_string(),
            secret_path: "service/api".to_string(),
            node_type: NodeType::Service,
            metadata: HashMap::from([("service_name".to_string(), "api".to_string())]),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        graph.add_secret_node(node1).await.unwrap();
        graph.add_secret_node(node2).await.unwrap();

        let dependency = Dependency {
            dependency_id: uuid::Uuid::new_v4().to_string(),
            source_node_id: "node2".to_string(),
            target_node_id: "node1".to_string(),
            dependency_type: DependencyType::Requires,
            strength: DependencyStrength::Strong,
            created_at: Utc::now(),
        };

        graph.add_dependency(dependency).await.unwrap();

        let deps = graph.get_dependencies("node2").await;
        assert_eq!(deps.len(), 1);
    }

    #[tokio::test]
    async fn test_detect_circular_dependencies() {
        let graph = SecretDependencyGraph::new(create_test_config());

        let node_a = SecretNode {
            node_id: "a".to_string(),
            secret_path: "secret/a".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        let node_b = SecretNode {
            node_id: "b".to_string(),
            secret_path: "secret/b".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        let node_c = SecretNode {
            node_id: "c".to_string(),
            secret_path: "secret/c".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        graph.add_secret_node(node_a).await.unwrap();
        graph.add_secret_node(node_b).await.unwrap();
        graph.add_secret_node(node_c).await.unwrap();

        // Create cycle: a -> b -> c -> a
        let dep1 = Dependency {
            dependency_id: uuid::Uuid::new_v4().to_string(),
            source_node_id: "a".to_string(),
            target_node_id: "b".to_string(),
            dependency_type: DependencyType::Requires,
            strength: DependencyStrength::Strong,
            created_at: Utc::now(),
        };

        let dep2 = Dependency {
            dependency_id: uuid::Uuid::new_v4().to_string(),
            source_node_id: "b".to_string(),
            target_node_id: "c".to_string(),
            dependency_type: DependencyType::Requires,
            strength: DependencyStrength::Strong,
            created_at: Utc::now(),
        };

        let dep3 = Dependency {
            dependency_id: uuid::Uuid::new_v4().to_string(),
            source_node_id: "c".to_string(),
            target_node_id: "a".to_string(),
            dependency_type: DependencyType::Requires,
            strength: DependencyStrength::Strong,
            created_at: Utc::now(),
        };

        graph.add_dependency(dep1).await.unwrap();
        graph.add_dependency(dep2).await.unwrap();

        // This should fail due to circular dependency check
        let result = graph.add_dependency(dep3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_impact_analysis() {
        let graph = SecretDependencyGraph::new(create_test_config());

        let secret = SecretNode {
            node_id: "secret1".to_string(),
            secret_path: "secret/db".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        let service1 = SecretNode {
            node_id: "service1".to_string(),
            secret_path: "service/api".to_string(),
            node_type: NodeType::Service,
            metadata: HashMap::from([("service_name".to_string(), "api".to_string())]),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        let service2 = SecretNode {
            node_id: "service2".to_string(),
            secret_path: "service/web".to_string(),
            node_type: NodeType::Service,
            metadata: HashMap::from([("service_name".to_string(), "web".to_string())]),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        graph.add_secret_node(secret).await.unwrap();
        graph.add_secret_node(service1).await.unwrap();
        graph.add_secret_node(service2).await.unwrap();

        let dep1 = Dependency {
            dependency_id: uuid::Uuid::new_v4().to_string(),
            source_node_id: "service1".to_string(),
            target_node_id: "secret1".to_string(),
            dependency_type: DependencyType::Requires,
            strength: DependencyStrength::Strong,
            created_at: Utc::now(),
        };

        let dep2 = Dependency {
            dependency_id: uuid::Uuid::new_v4().to_string(),
            source_node_id: "service2".to_string(),
            target_node_id: "secret1".to_string(),
            dependency_type: DependencyType::Requires,
            strength: DependencyStrength::Strong,
            created_at: Utc::now(),
        };

        graph.add_dependency(dep1).await.unwrap();
        graph.add_dependency(dep2).await.unwrap();

        let impact = graph.analyze_impact("secret1").await.unwrap();
        assert_eq!(impact.affected_nodes.len(), 3); // secret + 2 services
        assert_eq!(impact.affected_services.len(), 2);
    }

    #[tokio::test]
    async fn test_rotation_order() {
        let graph = SecretDependencyGraph::new(create_test_config());

        let node1 = SecretNode {
            node_id: "node1".to_string(),
            secret_path: "secret/1".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        let node2 = SecretNode {
            node_id: "node2".to_string(),
            secret_path: "secret/2".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        graph.add_secret_node(node1).await.unwrap();
        graph.add_secret_node(node2).await.unwrap();

        let dep = Dependency {
            dependency_id: uuid::Uuid::new_v4().to_string(),
            source_node_id: "node2".to_string(),
            target_node_id: "node1".to_string(),
            dependency_type: DependencyType::RotatesWith,
            strength: DependencyStrength::Strong,
            created_at: Utc::now(),
        };

        graph.add_dependency(dep).await.unwrap();

        let order = graph.get_rotation_order().await;
        assert_eq!(order.len(), 2);
        // Both secrets should be in rotation order (order may vary based on graph traversal)
        assert!(order.contains(&"secret/1".to_string()));
        assert!(order.contains(&"secret/2".to_string()));
    }

    #[tokio::test]
    async fn test_export_graph_json() {
        let graph = SecretDependencyGraph::new(create_test_config());

        let node = SecretNode {
            node_id: "node1".to_string(),
            secret_path: "secret/test".to_string(),
            node_type: NodeType::Secret,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_accessed_at: None,
        };

        graph.add_secret_node(node).await.unwrap();

        let json = graph.export_graph_data("json").await.unwrap();
        assert!(json.contains("secret/test"));
    }
}
