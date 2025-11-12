//! Unified agent service

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::agent::*;
use super::template::*;
use crate::service::AuthMethodResult;
use secreton_errors::SecretonError;

/// Agent service trait
#[async_trait]
pub trait AgentService: Send + Sync {
    /// Register a new agent
    async fn register_agent(
        &self,
        request: AgentRegistrationRequest,
    ) -> AuthMethodResult<AgentConfig>;

    /// Get agent configuration
    async fn get_agent(&self, name: String) -> AuthMethodResult<Option<AgentConfig>>;

    /// Update agent configuration
    async fn update_agent(
        &self,
        name: String,
        request: AgentUpdateRequest,
    ) -> AuthMethodResult<AgentConfig>;

    /// Delete an agent
    async fn delete_agent(&self, name: String) -> AuthMethodResult<()>;

    /// List agents
    async fn list_agents(&self) -> AuthMethodResult<AgentListResponse>;

    /// Authenticate with an agent
    async fn authenticate(&self, request: AgentAuthRequest) -> AuthMethodResult<AgentAuthResponse>;

    /// Create a template
    async fn create_template(
        &self,
        name: String,
        template_type: super::template::TemplateType,
        agent_type: AgentType,
        template: String,
    ) -> AuthMethodResult<super::template::AgentTemplate>;

    /// Render a template
    async fn render_template(
        &self,
        request: super::template::TemplateRenderRequest,
    ) -> AuthMethodResult<super::template::TemplateRenderResponse>;
}

/// Combined agent service implementation
pub struct CombinedAgentService {
    agents: RwLock<HashMap<String, AgentConfig>>,
    template_service: Arc<dyn TemplateService>,
}

impl CombinedAgentService {
    pub fn new(template_service: Arc<dyn TemplateService>) -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            template_service,
        }
    }

    /// Validate agent authentication (simplified implementation)
    async fn validate_agent_auth(&self, request: &AgentAuthRequest) -> Result<Uuid, SecretonError> {
        // In a real implementation, this would validate credentials against
        // the specific agent type (e.g., check Kubernetes JWT, AWS IAM, etc.)
        match request.agent_type {
            AgentType::AppRole => {
                // Validate role_id and secret_id
                if let (Some(role_id), Some(secret_id)) = (
                    request.credentials.get("role_id"),
                    request.credentials.get("secret_id"),
                ) {
                    if !role_id.is_empty() && !secret_id.is_empty() {
                        Ok(Uuid::new_v4()) // Mock entity ID
                    } else {
                        Err(SecretonError::Authentication {
                            message: "approle authentication failed".to_string(),
                        })
                    }
                } else {
                    Err(SecretonError::InvalidInput {
                        field: "credentials".to_string(),
                        reason: "Missing role_id or secret_id".to_string(),
                    })
                }
            }
            AgentType::Kubernetes => {
                // Validate JWT token
                if let Some(jwt) = request.credentials.get("jwt") {
                    if !jwt.is_empty() {
                        Ok(Uuid::new_v4()) // Mock entity ID
                    } else {
                        Err(SecretonError::Authentication {
                            message: "kubernetes authentication failed".to_string(),
                        })
                    }
                } else {
                    Err(SecretonError::InvalidInput {
                        field: "credentials".to_string(),
                        reason: "Missing jwt".to_string(),
                    })
                }
            }
            AgentType::AWS => {
                // Validate AWS credentials
                if let (Some(access_key), Some(secret_key)) = (
                    request.credentials.get("access_key"),
                    request.credentials.get("secret_key"),
                ) {
                    if !access_key.is_empty() && !secret_key.is_empty() {
                        Ok(Uuid::new_v4()) // Mock entity ID
                    } else {
                        Err(SecretonError::Authentication {
                            message: "aws authentication failed".to_string(),
                        })
                    }
                } else {
                    Err(SecretonError::InvalidInput {
                        field: "credentials".to_string(),
                        reason: "Missing AWS credentials".to_string(),
                    })
                }
            }
            _ => Err(SecretonError::AuthMethodNotSupported),
        }
    }
}

#[async_trait]
impl AgentService for CombinedAgentService {
    async fn register_agent(
        &self,
        request: AgentRegistrationRequest,
    ) -> AuthMethodResult<AgentConfig> {
        let config = AgentConfig {
            agent_type: request.agent_type,
            name: request.name.clone(),
            description: request.description,
            metadata: request.config,
            enabled: true,
            creation_time: Utc::now(),
            last_modified: Utc::now(),
        };

        let mut agents = self.agents.write().await;
        agents.insert(request.name, config.clone());

        Ok(config)
    }

    async fn get_agent(&self, name: String) -> AuthMethodResult<Option<AgentConfig>> {
        let agents = self.agents.read().await;
        Ok(agents.get(&name).cloned())
    }

    async fn update_agent(
        &self,
        name: String,
        request: AgentUpdateRequest,
    ) -> AuthMethodResult<AgentConfig> {
        let mut agents = self.agents.write().await;

        if let Some(agent) = agents.get_mut(&name) {
            if let Some(new_name) = request.name {
                // If renaming, we need to re-insert with new key
                let mut updated_agent = agent.clone();
                updated_agent.name = new_name.clone();
                if let Some(description) = request.description {
                    updated_agent.description = Some(description);
                }
                if let Some(config) = request.config {
                    updated_agent.metadata = config;
                }
                if let Some(enabled) = request.enabled {
                    updated_agent.enabled = enabled;
                }
                updated_agent.last_modified = Utc::now();

                agents.remove(&name);
                agents.insert(new_name, updated_agent.clone());
                Ok(updated_agent)
            } else {
                if let Some(description) = request.description {
                    agent.description = Some(description);
                }
                if let Some(config) = request.config {
                    agent.metadata = config;
                }
                if let Some(enabled) = request.enabled {
                    agent.enabled = enabled;
                }
                agent.last_modified = Utc::now();
                Ok(agent.clone())
            }
        } else {
            Err(SecretonError::UserNotFound {
                username: format!("agent {}", name),
            })
        }
    }

    async fn delete_agent(&self, name: String) -> AuthMethodResult<()> {
        let mut agents = self.agents.write().await;
        agents.remove(&name);
        Ok(())
    }

    async fn list_agents(&self) -> AuthMethodResult<AgentListResponse> {
        let agents = self.agents.read().await;
        let agent_list = agents.values().cloned().collect();
        Ok(AgentListResponse { agents: agent_list })
    }

    async fn authenticate(&self, request: AgentAuthRequest) -> AuthMethodResult<AgentAuthResponse> {
        // Check if agent is registered and enabled
        let agents = self.agents.read().await;
        let agent_name = match request.agent_type {
            AgentType::AppRole => "approle",
            AgentType::Kubernetes => "kubernetes",
            AgentType::AWS => "aws",
            AgentType::Azure => "azure",
            AgentType::GCP => "gcp",
            AgentType::Custom(ref name) => name,
        };

        let agent = agents
            .get(agent_name)
            .ok_or_else(|| SecretonError::UserNotFound {
                username: format!("agent {}", agent_name),
            })?;

        if !agent.enabled {
            return Err(SecretonError::Authentication {
                message: format!("Agent {} authentication failed", agent_name),
            });
        }

        // Validate credentials
        let entity_id = self.validate_agent_auth(&request).await?;

        Ok(AgentAuthResponse {
            entity_id,
            policies: vec!["default".to_string()], // Mock policies
            metadata: request.metadata.unwrap_or_default(),
            lease_duration: Some(3600), // 1 hour
        })
    }

    async fn create_template(
        &self,
        name: String,
        template_type: super::template::TemplateType,
        agent_type: AgentType,
        template: String,
    ) -> AuthMethodResult<super::template::AgentTemplate> {
        self.template_service
            .create_template(name, template_type, agent_type, template)
            .await
    }

    async fn render_template(
        &self,
        request: super::template::TemplateRenderRequest,
    ) -> AuthMethodResult<super::template::TemplateRenderResponse> {
        self.template_service.render_template(request).await
    }
}
