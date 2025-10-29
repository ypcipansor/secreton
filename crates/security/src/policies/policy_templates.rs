// Policy Templates - Parameterized reusable policies with variable substitution
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum PolicyTemplateError {
    #[error("Template not found: {0}")]
    NotFound(String),
    #[error("Invalid template: {0}")]
    InvalidTemplate(String),
    #[error("Missing required parameter: {0}")]
    MissingParameter(String),
    #[error("Template already exists: {0}")]
    AlreadyExists(String),
    #[error("Rendering failed: {0}")]
    RenderingFailed(String),
}

pub type Result<T> = std::result::Result<T, PolicyTemplateError>;

/// Parameter definition for template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateParameter {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default_value: Option<String>,
    pub param_type: ParameterType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParameterType {
    String,
    Number,
    Boolean,
    Path,
    Identity,
}

/// Policy template with placeholders
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub name: String,
    pub description: String,
    pub template_body: String, // HCL-like with {{variable}} placeholders
    pub parameters: Vec<TemplateParameter>,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

/// Rendered policy instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedPolicy {
    pub template_name: String,
    pub instance_name: String,
    pub policy_content: String,
    pub parameters_used: HashMap<String, String>,
    pub rendered_at: DateTime<Utc>,
    pub rendered_by: Option<String>,
}

impl PolicyTemplate {
    pub fn new(name: String, template_body: String) -> Self {
        Self {
            name,
            description: String::new(),
            template_body,
            parameters: Vec::new(),
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: None,
        }
    }

    pub fn add_parameter(&mut self, param: TemplateParameter) {
        self.parameters.push(param);
        self.updated_at = Utc::now();
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    pub fn with_created_by(mut self, created_by: String) -> Self {
        self.created_by = Some(created_by);
        self
    }

    /// Validate that all required parameters are present
    pub fn validate_parameters(&self, values: &HashMap<String, String>) -> Result<()> {
        for param in &self.parameters {
            if param.required && !values.contains_key(&param.name) {
                if param.default_value.is_none() {
                    return Err(PolicyTemplateError::MissingParameter(param.name.clone()));
                }
            }
        }
        Ok(())
    }

    /// Render template with provided parameter values
    pub fn render(
        &self,
        instance_name: String,
        mut values: HashMap<String, String>,
        rendered_by: Option<String>,
    ) -> Result<RenderedPolicy> {
        // Apply defaults for missing parameters
        for param in &self.parameters {
            if !values.contains_key(&param.name) {
                if let Some(default) = &param.default_value {
                    values.insert(param.name.clone(), default.clone());
                }
            }
        }

        // Validate all required parameters are present
        self.validate_parameters(&values)?;

        // Perform substitution
        let mut content = self.template_body.clone();
        for (key, value) in &values {
            let placeholder = format!("{{{{{}}}}}", key);
            content = content.replace(&placeholder, value);
        }

        // Check for unresolved placeholders
        if content.contains("{{") {
            return Err(PolicyTemplateError::RenderingFailed(
                "Template contains unresolved placeholders".to_string(),
            ));
        }

        Ok(RenderedPolicy {
            template_name: self.name.clone(),
            instance_name,
            policy_content: content,
            parameters_used: values,
            rendered_at: Utc::now(),
            rendered_by,
        })
    }
}

/// Policy template service
pub struct PolicyTemplateService {
    templates: Arc<RwLock<HashMap<String, PolicyTemplate>>>,
    rendered_policies: Arc<RwLock<HashMap<String, RenderedPolicy>>>,
}

impl PolicyTemplateService {
    pub fn new() -> Self {
        Self {
            templates: Arc::new(RwLock::new(HashMap::new())),
            rendered_policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new policy template
    pub async fn create_template(&self, template: PolicyTemplate) -> Result<()> {
        let mut templates = self.templates.write().await;

        if templates.contains_key(&template.name) {
            return Err(PolicyTemplateError::AlreadyExists(template.name.clone()));
        }

        templates.insert(template.name.clone(), template);
        Ok(())
    }

    /// Get a template by name
    pub async fn get_template(&self, name: &str) -> Result<PolicyTemplate> {
        let templates = self.templates.read().await;
        templates
            .get(name)
            .cloned()
            .ok_or_else(|| PolicyTemplateError::NotFound(name.to_string()))
    }

    /// Update a template
    pub async fn update_template(&self, name: &str, template: PolicyTemplate) -> Result<()> {
        let mut templates = self.templates.write().await;

        let existing = templates
            .get_mut(name)
            .ok_or_else(|| PolicyTemplateError::NotFound(name.to_string()))?;

        *existing = template;
        existing.version += 1;
        existing.updated_at = Utc::now();

        Ok(())
    }

    /// Delete a template
    pub async fn delete_template(&self, name: &str) -> Result<()> {
        let mut templates = self.templates.write().await;
        templates
            .remove(name)
            .ok_or_else(|| PolicyTemplateError::NotFound(name.to_string()))?;
        Ok(())
    }

    /// List all templates
    pub async fn list_templates(&self) -> Vec<PolicyTemplate> {
        let templates = self.templates.read().await;
        templates.values().cloned().collect()
    }

    /// Render a policy from template
    pub async fn render_policy(
        &self,
        template_name: &str,
        instance_name: String,
        parameters: HashMap<String, String>,
        rendered_by: Option<String>,
    ) -> Result<RenderedPolicy> {
        let template = self.get_template(template_name).await?;
        let rendered = template.render(instance_name.clone(), parameters, rendered_by)?;

        // Store rendered policy
        let mut policies = self.rendered_policies.write().await;
        policies.insert(instance_name, rendered.clone());

        Ok(rendered)
    }

    /// Get a rendered policy
    pub async fn get_rendered_policy(&self, instance_name: &str) -> Result<RenderedPolicy> {
        let policies = self.rendered_policies.read().await;
        policies
            .get(instance_name)
            .cloned()
            .ok_or_else(|| PolicyTemplateError::NotFound(instance_name.to_string()))
    }

    /// List all rendered policies
    pub async fn list_rendered_policies(&self) -> Vec<RenderedPolicy> {
        let policies = self.rendered_policies.read().await;
        policies.values().cloned().collect()
    }

    /// List rendered policies by template
    pub async fn list_rendered_by_template(&self, template_name: &str) -> Vec<RenderedPolicy> {
        let policies = self.rendered_policies.read().await;
        policies
            .values()
            .filter(|p| p.template_name == template_name)
            .cloned()
            .collect()
    }

    /// Delete a rendered policy
    pub async fn delete_rendered_policy(&self, instance_name: &str) -> Result<()> {
        let mut policies = self.rendered_policies.write().await;
        policies
            .remove(instance_name)
            .ok_or_else(|| PolicyTemplateError::NotFound(instance_name.to_string()))?;
        Ok(())
    }
}

impl Default for PolicyTemplateService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_template() {
        let template = PolicyTemplate::new(
            "read-secret".to_string(),
            r#"path "{{path}}" {
  capabilities = ["read"]
}"#
            .to_string(),
        )
        .with_description("Read-only access to a secret path".to_string());

        assert_eq!(template.name, "read-secret");
        assert_eq!(template.version, 1);
    }

    #[test]
    fn test_template_render() {
        let mut template = PolicyTemplate::new(
            "test".to_string(),
            "path \"{{path}}\" { capabilities = [\"{{capability}}\"] }".to_string(),
        );

        template.add_parameter(TemplateParameter {
            name: "path".to_string(),
            description: "Secret path".to_string(),
            required: true,
            default_value: None,
            param_type: ParameterType::Path,
        });

        template.add_parameter(TemplateParameter {
            name: "capability".to_string(),
            description: "Capability".to_string(),
            required: false,
            default_value: Some("read".to_string()),
            param_type: ParameterType::String,
        });

        let mut params = HashMap::new();
        params.insert("path".to_string(), "secret/data".to_string());

        let rendered = template
            .render("my-policy".to_string(), params, None)
            .unwrap();

        assert_eq!(
            rendered.policy_content,
            "path \"secret/data\" { capabilities = [\"read\"] }"
        );
    }

    #[test]
    fn test_missing_required_parameter() {
        let mut template = PolicyTemplate::new("test".to_string(), "{{required}}".to_string());

        template.add_parameter(TemplateParameter {
            name: "required".to_string(),
            description: "Required param".to_string(),
            required: true,
            default_value: None,
            param_type: ParameterType::String,
        });

        let params = HashMap::new();
        let result = template.render("test".to_string(), params, None);

        assert!(result.is_err());
        match result.unwrap_err() {
            PolicyTemplateError::MissingParameter(name) => assert_eq!(name, "required"),
            _ => panic!("Expected MissingParameter error"),
        }
    }

    #[tokio::test]
    async fn test_service_create_and_get() {
        let service = PolicyTemplateService::new();

        let template = PolicyTemplate::new(
            "test-template".to_string(),
            "path \"{{path}}\" { capabilities = [\"read\"] }".to_string(),
        );

        service.create_template(template).await.unwrap();

        let retrieved = service.get_template("test-template").await.unwrap();
        assert_eq!(retrieved.name, "test-template");
    }

    #[tokio::test]
    async fn test_service_render_policy() {
        let service = PolicyTemplateService::new();

        let mut template = PolicyTemplate::new(
            "test".to_string(),
            "path \"{{path}}\" { capabilities = [\"{{cap}}\"] }".to_string(),
        );

        template.add_parameter(TemplateParameter {
            name: "path".to_string(),
            description: "Path".to_string(),
            required: true,
            default_value: None,
            param_type: ParameterType::Path,
        });

        template.add_parameter(TemplateParameter {
            name: "cap".to_string(),
            description: "Capability".to_string(),
            required: false,
            default_value: Some("read".to_string()),
            param_type: ParameterType::String,
        });

        service.create_template(template).await.unwrap();

        let mut params = HashMap::new();
        params.insert("path".to_string(), "secret/data".to_string());

        let rendered = service
            .render_policy("test", "my-instance".to_string(), params, None)
            .await
            .unwrap();

        assert_eq!(rendered.instance_name, "my-instance");
        assert!(rendered.policy_content.contains("secret/data"));
    }

    #[tokio::test]
    async fn test_list_rendered_by_template() {
        let service = PolicyTemplateService::new();

        let template = PolicyTemplate::new(
            "base".to_string(),
            "path \"{{path}}\" { capabilities = [\"read\"] }".to_string(),
        );

        service.create_template(template).await.unwrap();

        // Render two instances
        let mut params1 = HashMap::new();
        params1.insert("path".to_string(), "secret/app1".to_string());
        service
            .render_policy("base", "instance1".to_string(), params1, None)
            .await
            .unwrap();

        let mut params2 = HashMap::new();
        params2.insert("path".to_string(), "secret/app2".to_string());
        service
            .render_policy("base", "instance2".to_string(), params2, None)
            .await
            .unwrap();

        let instances = service.list_rendered_by_template("base").await;
        assert_eq!(instances.len(), 2);
    }
}
