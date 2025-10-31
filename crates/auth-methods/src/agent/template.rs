//! Agent templating functionality

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::*;

/// Template type
#[derive(Debug, Clone, PartialEq)]
pub enum TemplateType {
    Policy,
    Role,
    Credential,
    Metadata,
}

/// Agent template
#[derive(Debug, Clone)]
pub struct AgentTemplate {
    pub id: Uuid,
    pub name: String,
    pub template_type: TemplateType,
    pub agent_type: super::agent::AgentType,
    pub template: String,
    pub variables: Vec<String>,
    pub creation_time: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
}

/// Template rendering request
#[derive(Debug)]
pub struct TemplateRenderRequest {
    pub template_id: Uuid,
    pub variables: HashMap<String, String>,
}

/// Template rendering response
#[derive(Debug)]
pub struct TemplateRenderResponse {
    pub rendered_content: String,
}

/// Template service trait
#[async_trait]
pub trait TemplateService: Send + Sync {
    /// Create a new template
    async fn create_template(
        &self,
        name: String,
        template_type: TemplateType,
        agent_type: super::agent::AgentType,
        template: String,
    ) -> AuthMethodResult<AgentTemplate>;

    /// Get a template by ID
    async fn get_template(&self, id: Uuid) -> AuthMethodResult<Option<AgentTemplate>>;

    /// Update a template
    async fn update_template(
        &self,
        id: Uuid,
        name: Option<String>,
        template: Option<String>,
    ) -> AuthMethodResult<AgentTemplate>;

    /// Delete a template
    async fn delete_template(&self, id: Uuid) -> AuthMethodResult<()>;

    /// List templates
    async fn list_templates(
        &self,
        agent_type: Option<super::agent::AgentType>,
    ) -> AuthMethodResult<Vec<AgentTemplate>>;

    /// Render a template
    async fn render_template(
        &self,
        request: TemplateRenderRequest,
    ) -> AuthMethodResult<TemplateRenderResponse>;
}

/// In-memory template service implementation
pub struct InMemoryTemplateService {
    templates: RwLock<HashMap<Uuid, AgentTemplate>>,
}

impl InMemoryTemplateService {
    pub fn new() -> Self {
        Self {
            templates: RwLock::new(HashMap::new()),
        }
    }

    /// Extract variables from template
    fn extract_variables(template: &str) -> Vec<String> {
        let re = Regex::new(r"\{\{(\w+)\}\}").unwrap();
        re.captures_iter(template)
            .map(|cap| cap[1].to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Render template with variables
    fn render_template_content(
        template: &str,
        variables: &HashMap<String, String>,
    ) -> AuthMethodResult<String> {
        let mut result = template.to_string();

        for (key, value) in variables {
            let placeholder = format!("{{{{{}}}}}", key);
            result = result.replace(&placeholder, value);
        }

        // Check for any remaining unsubstituted variables
        if result.contains("{{") && result.contains("}}") {
            return Err(AuthMethodError::ConfigurationError(
                "Not all template variables were provided".to_string(),
            ));
        }

        Ok(result)
    }
}

#[async_trait]
impl TemplateService for InMemoryTemplateService {
    async fn create_template(
        &self,
        name: String,
        template_type: TemplateType,
        agent_type: super::agent::AgentType,
        template: String,
    ) -> AuthMethodResult<AgentTemplate> {
        let variables = Self::extract_variables(&template);

        let template_obj = AgentTemplate {
            id: Uuid::new_v4(),
            name,
            template_type,
            agent_type,
            template,
            variables,
            creation_time: Utc::now(),
            last_modified: Utc::now(),
        };

        let mut templates = self.templates.write().await;
        templates.insert(template_obj.id, template_obj.clone());

        Ok(template_obj)
    }

    async fn get_template(&self, id: Uuid) -> AuthMethodResult<Option<AgentTemplate>> {
        let templates = self.templates.read().await;
        Ok(templates.get(&id).cloned())
    }

    async fn update_template(
        &self,
        id: Uuid,
        name: Option<String>,
        template: Option<String>,
    ) -> AuthMethodResult<AgentTemplate> {
        let mut templates = self.templates.write().await;

        if let Some(existing_template) = templates.get_mut(&id) {
            if let Some(name) = name {
                existing_template.name = name;
            }
            if let Some(template) = template {
                existing_template.template = template.clone();
                existing_template.variables = Self::extract_variables(&template);
            }
            existing_template.last_modified = Utc::now();
            Ok(existing_template.clone())
        } else {
            Err(AuthMethodError::UserNotFound(format!("template {}", id)))
        }
    }

    async fn delete_template(&self, id: Uuid) -> AuthMethodResult<()> {
        let mut templates = self.templates.write().await;
        templates.remove(&id);
        Ok(())
    }

    async fn list_templates(
        &self,
        agent_type: Option<super::agent::AgentType>,
    ) -> AuthMethodResult<Vec<AgentTemplate>> {
        let templates = self.templates.read().await;

        let filtered_templates: Vec<AgentTemplate> = templates
            .values()
            .filter(|template| {
                if let Some(agent_type) = &agent_type {
                    template.agent_type == *agent_type
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        Ok(filtered_templates)
    }

    async fn render_template(
        &self,
        request: TemplateRenderRequest,
    ) -> AuthMethodResult<TemplateRenderResponse> {
        let templates = self.templates.read().await;

        let template = templates.get(&request.template_id).ok_or_else(|| {
            AuthMethodError::UserNotFound(format!("template {}", request.template_id))
        })?;

        let rendered_content =
            Self::render_template_content(&template.template, &request.variables)?;

        Ok(TemplateRenderResponse { rendered_content })
    }
}
