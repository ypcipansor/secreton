// Consul Service Mesh Integration - Service discovery and Connect
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ConsulError {
    #[error("Consul error: {0}")]
    ConsulError(String),
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),
}

pub type Result<T> = std::result::Result<T, ConsulError>;

/// Consul configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    pub address: String,       // http://localhost:8500
    pub token: Option<String>, // ACL token
    pub datacenter: String,
    pub enable_connect: bool,
    pub tls_enabled: bool,
    pub ca_cert: Option<String>,
}

/// Service registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRegistration {
    pub service_id: String,
    pub service_name: String,
    pub address: String,
    pub port: u16,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub check: Option<HealthCheck>,
    pub connect: Option<ConnectConfig>,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub interval: String,     // e.g., "10s"
    pub timeout: String,      // e.g., "5s"
    pub http: Option<String>, // HTTP endpoint
    pub tcp: Option<String>,  // TCP address
    pub grpc: Option<String>, // gRPC endpoint
}

/// Service intention (authorization policy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIntention {
    pub id: String,
    pub source_name: String,
    pub destination_name: String,
    pub action: IntentionAction,
    pub description: String,
    pub precedence: u32,
    pub created_at: DateTime<Utc>,
}

/// Intention action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntentionAction {
    Allow,
    Deny,
}

/// Consul Connect configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectConfig {
    pub sidecar_service: Option<SidecarService>,
    pub upstream_services: Vec<UpstreamService>,
}

/// Sidecar service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarService {
    pub proxy_id: String,
    pub local_service_port: u16,
}

/// Upstream service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamService {
    pub name: String,
    pub local_bind_port: u16,
    pub datacenter: Option<String>,
}

/// Service health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceHealth {
    Passing,
    Warning,
    Critical,
}

/// Service instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    pub service_id: String,
    pub service_name: String,
    pub address: String,
    pub port: u16,
    pub health: ServiceHealth,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
}

/// Consul Service Mesh
pub struct ConsulServiceMesh {
    _config: Arc<RwLock<ConsulConfig>>,
    services: Arc<RwLock<HashMap<String, ServiceRegistration>>>,
    intentions: Arc<RwLock<HashMap<String, ServiceIntention>>>,
    service_health: Arc<RwLock<HashMap<String, ServiceHealth>>>,
}

impl ConsulServiceMesh {
    pub fn new(config: ConsulConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(config)),
            services: Arc::new(RwLock::new(HashMap::new())),
            intentions: Arc::new(RwLock::new(HashMap::new())),
            service_health: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register service in Consul catalog
    pub async fn register_service(&self, registration: ServiceRegistration) -> Result<()> {
        if registration.service_name.is_empty() {
            return Err(ConsulError::ConfigError(
                "Service name is required".to_string(),
            ));
        }

        // Mock Consul API call to register service
        // Real implementation would use reqwest to POST /v1/agent/service/register
        self.mock_consul_register(&registration).await?;

        let mut services = self.services.write().await;
        services.insert(registration.service_id.clone(), registration.clone());

        let mut health = self.service_health.write().await;
        health.insert(registration.service_id.clone(), ServiceHealth::Passing);

        Ok(())
    }

    /// Deregister service
    pub async fn deregister_service(&self, service_id: &str) -> Result<()> {
        let mut services = self.services.write().await;
        services
            .remove(service_id)
            .ok_or_else(|| ConsulError::ServiceNotFound(service_id.to_string()))?;

        // Mock Consul API call
        self.mock_consul_deregister(service_id).await?;

        Ok(())
    }

    /// Create service intention
    pub async fn create_intention(
        &self,
        source: &str,
        destination: &str,
        action: IntentionAction,
        description: String,
    ) -> Result<ServiceIntention> {
        let intention = ServiceIntention {
            id: uuid::Uuid::new_v4().to_string(),
            source_name: source.to_string(),
            destination_name: destination.to_string(),
            action,
            description,
            precedence: 9,
            created_at: Utc::now(),
        };

        // Mock Consul API call to create intention
        // Real implementation would POST /v1/connect/intentions
        self.mock_consul_create_intention(&intention).await?;

        let mut intentions = self.intentions.write().await;
        intentions.insert(intention.id.clone(), intention.clone());

        Ok(intention)
    }

    /// Delete intention
    pub async fn delete_intention(&self, intention_id: &str) -> Result<()> {
        let mut intentions = self.intentions.write().await;
        intentions
            .remove(intention_id)
            .ok_or_else(|| ConsulError::ConsulError("Intention not found".to_string()))?;

        self.mock_consul_delete_intention(intention_id).await?;

        Ok(())
    }

    /// Get service health
    pub async fn get_service_health(&self, service_name: &str) -> Result<Vec<ServiceInstance>> {
        // Mock Consul API call to get service health
        // Real implementation would GET /v1/health/service/:name
        let instances = self.mock_consul_get_health(service_name).await?;

        Ok(instances)
    }

    /// Discover services by name
    pub async fn discover_services(&self, service_name: &str) -> Result<Vec<ServiceInstance>> {
        let services = self.services.read().await;
        let health = self.service_health.read().await;

        let instances: Vec<ServiceInstance> = services
            .values()
            .filter(|s| s.service_name == service_name)
            .map(|s| ServiceInstance {
                service_id: s.service_id.clone(),
                service_name: s.service_name.clone(),
                address: s.address.clone(),
                port: s.port,
                health: health
                    .get(&s.service_id)
                    .cloned()
                    .unwrap_or(ServiceHealth::Critical),
                tags: s.tags.clone(),
                meta: s.meta.clone(),
            })
            .collect();

        Ok(instances)
    }

    /// Authorize service connection via Connect
    pub async fn connect_authorize(&self, source: &str, destination: &str) -> Result<bool> {
        let intentions = self.intentions.read().await;

        // Find matching intention
        for intention in intentions.values() {
            if intention.source_name == source && intention.destination_name == destination {
                return Ok(intention.action == IntentionAction::Allow);
            }
        }

        // Default deny if no intention found
        Ok(false)
    }

    /// List all intentions
    pub async fn list_intentions(&self) -> Vec<ServiceIntention> {
        let intentions = self.intentions.read().await;
        intentions.values().cloned().collect()
    }

    /// List all services
    pub async fn list_services(&self) -> Vec<ServiceRegistration> {
        let services = self.services.read().await;
        services.values().cloned().collect()
    }

    /// Update service health
    pub async fn update_service_health(
        &self,
        service_id: &str,
        health: ServiceHealth,
    ) -> Result<()> {
        let services = self.services.read().await;
        if !services.contains_key(service_id) {
            return Err(ConsulError::ServiceNotFound(service_id.to_string()));
        }
        drop(services);

        let mut health_map = self.service_health.write().await;
        health_map.insert(service_id.to_string(), health);

        Ok(())
    }

    /// Get service by ID
    pub async fn get_service(&self, service_id: &str) -> Result<ServiceRegistration> {
        let services = self.services.read().await;
        services
            .get(service_id)
            .cloned()
            .ok_or_else(|| ConsulError::ServiceNotFound(service_id.to_string()))
    }

    // Mock Consul API methods
    async fn mock_consul_register(&self, _registration: &ServiceRegistration) -> Result<()> {
        // Mock successful registration
        Ok(())
    }

    async fn mock_consul_deregister(&self, _service_id: &str) -> Result<()> {
        // Mock successful deregistration
        Ok(())
    }

    async fn mock_consul_create_intention(&self, _intention: &ServiceIntention) -> Result<()> {
        // Mock successful intention creation
        Ok(())
    }

    async fn mock_consul_delete_intention(&self, _intention_id: &str) -> Result<()> {
        // Mock successful intention deletion
        Ok(())
    }

    async fn mock_consul_get_health(&self, service_name: &str) -> Result<Vec<ServiceInstance>> {
        // Mock returning healthy instances
        let instance = ServiceInstance {
            service_id: format!("{}-1", service_name),
            service_name: service_name.to_string(),
            address: "10.0.1.100".to_string(),
            port: 8080,
            health: ServiceHealth::Passing,
            tags: vec!["v1".to_string()],
            meta: HashMap::new(),
        };

        Ok(vec![instance])
    }
}

impl Default for ConsulServiceMesh {
    fn default() -> Self {
        let config = ConsulConfig {
            address: "http://localhost:8500".to_string(),
            token: None,
            datacenter: "dc1".to_string(),
            enable_connect: true,
            tls_enabled: false,
            ca_cert: None,
        };

        Self::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service_registration() -> ServiceRegistration {
        let mut meta = HashMap::new();
        meta.insert("version".to_string(), "0.1.0".to_string());

        ServiceRegistration {
            service_id: "web-1".to_string(),
            service_name: "web".to_string(),
            address: "10.0.1.10".to_string(),
            port: 8080,
            tags: vec!["http".to_string(), "primary".to_string()],
            meta,
            check: Some(HealthCheck {
                interval: "10s".to_string(),
                timeout: "5s".to_string(),
                http: Some("http://10.0.1.10:8080/health".to_string()),
                tcp: None,
                grpc: None,
            }),
            connect: None,
        }
    }

    #[tokio::test]
    async fn test_register_service() {
        let mesh = ConsulServiceMesh::default();
        let registration = create_test_service_registration();

        mesh.register_service(registration.clone()).await.unwrap();

        let service = mesh.get_service("web-1").await.unwrap();
        assert_eq!(service.service_name, "web");
        assert_eq!(service.address, "10.0.1.10");
        assert_eq!(service.port, 8080);
    }

    #[tokio::test]
    async fn test_create_intention() {
        let mesh = ConsulServiceMesh::default();

        let intention = mesh
            .create_intention(
                "web",
                "api",
                IntentionAction::Allow,
                "Allow web to call api".to_string(),
            )
            .await
            .unwrap();

        assert_eq!(intention.source_name, "web");
        assert_eq!(intention.destination_name, "api");
        assert_eq!(intention.action, IntentionAction::Allow);
    }

    #[tokio::test]
    async fn test_connect_authorization() {
        let mesh = ConsulServiceMesh::default();

        // Create allow intention
        mesh.create_intention(
            "web",
            "api",
            IntentionAction::Allow,
            "Allow web to api".to_string(),
        )
        .await
        .unwrap();

        // Create deny intention
        mesh.create_intention(
            "untrusted",
            "api",
            IntentionAction::Deny,
            "Deny untrusted to api".to_string(),
        )
        .await
        .unwrap();

        // Test authorization
        let allowed = mesh.connect_authorize("web", "api").await.unwrap();
        assert!(allowed);

        let denied = mesh.connect_authorize("untrusted", "api").await.unwrap();
        assert!(!denied);

        let no_intention = mesh.connect_authorize("random", "api").await.unwrap();
        assert!(!no_intention); // Default deny
    }

    #[tokio::test]
    async fn test_service_discovery() {
        let mesh = ConsulServiceMesh::default();

        let mut reg1 = create_test_service_registration();
        reg1.service_id = "web-1".to_string();

        let mut reg2 = create_test_service_registration();
        reg2.service_id = "web-2".to_string();
        reg2.address = "10.0.1.11".to_string();

        mesh.register_service(reg1).await.unwrap();
        mesh.register_service(reg2).await.unwrap();

        let instances = mesh.discover_services("web").await.unwrap();
        assert_eq!(instances.len(), 2);
        assert!(instances.iter().any(|i| i.service_id == "web-1"));
        assert!(instances.iter().any(|i| i.service_id == "web-2"));
    }

    #[tokio::test]
    async fn test_service_health() {
        let mesh = ConsulServiceMesh::default();
        let registration = create_test_service_registration();

        mesh.register_service(registration).await.unwrap();

        // Initial health is Passing
        let instances = mesh.discover_services("web").await.unwrap();
        assert_eq!(instances[0].health, ServiceHealth::Passing);

        // Update health
        mesh.update_service_health("web-1", ServiceHealth::Warning)
            .await
            .unwrap();

        let instances = mesh.discover_services("web").await.unwrap();
        assert_eq!(instances[0].health, ServiceHealth::Warning);
    }

    #[tokio::test]
    async fn test_list_services_and_intentions() {
        let mesh = ConsulServiceMesh::default();

        let reg = create_test_service_registration();
        mesh.register_service(reg).await.unwrap();

        mesh.create_intention("web", "api", IntentionAction::Allow, "Test".to_string())
            .await
            .unwrap();

        let services = mesh.list_services().await;
        assert_eq!(services.len(), 1);

        let intentions = mesh.list_intentions().await;
        assert_eq!(intentions.len(), 1);
    }
}
