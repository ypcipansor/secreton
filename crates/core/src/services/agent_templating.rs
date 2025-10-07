// Agent Templating - Consul Template (CTL) function support for config file rendering
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum TemplatingError {
    #[error("Template parsing failed: {0}")]
    ParseError(String),
    #[error("Template rendering failed: {0}")]
    RenderError(String),
    #[error("Function evaluation failed: {0}")]
    FunctionError(String),
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    #[error("File operation failed: {0}")]
    FileError(String),
}

pub type Result<T> = std::result::Result<T, TemplatingError>;

/// CTL function types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CTLFunction {
    /// {{ with secret "secret/data/app" }}...{{ end }}
    With { path: String },
    /// {{ secret "secret/data/app" }}
    Secret { path: String },
    /// {{ pkiCert "pki/issue/role" "common_name=example.com" }}
    PkiCert { path: String, params: HashMap<String, String> },
    /// {{ key "config/key" }}
    Key { path: String },
    /// {{ range secrets "secret/data" }}...{{ end }}
    Range { path: String },
}

/// Template expression
#[derive(Debug, Clone)]
pub struct CTLExpression {
    pub function: CTLFunction,
    pub start_pos: usize,
    pub end_pos: usize,
}

/// Template content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub name: String,
    pub content: String,
    pub destination: String,
    pub permissions: u32, // Unix file permissions
    pub variables: HashMap<String, String>,
}

/// Rendered file output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedFile {
    pub path: String,
    pub content: String,
    pub permissions: u32,
    pub checksum: String,
}

/// Render context
#[derive(Debug, Clone)]
pub struct RenderContext {
    pub variables: HashMap<String, String>,
    pub vault_secrets: HashMap<String, serde_json::Value>,
}

impl RenderContext {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            vault_secrets: HashMap::new(),
        }
    }

    pub fn with_variable(mut self, key: String, value: String) -> Self {
        self.variables.insert(key, value);
        self
    }

    pub fn with_secret(mut self, path: String, data: serde_json::Value) -> Self {
        self.vault_secrets.insert(path, data);
        self
    }
}

impl Default for RenderContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Agent templating service
pub struct AgentTemplatingService {
    templates: Arc<RwLock<HashMap<String, Template>>>,
    rendered_files: Arc<RwLock<HashMap<String, RenderedFile>>>,
    // Mock vault client for testing
    vault_data: Arc<RwLock<HashMap<String, serde_json::Value>>>,
}

impl AgentTemplatingService {
    pub fn new() -> Self {
        Self {
            templates: Arc::new(RwLock::new(HashMap::new())),
            rendered_files: Arc::new(RwLock::new(HashMap::new())),
            vault_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a template
    pub async fn register_template(&self, template: Template) -> Result<()> {
        let mut templates = self.templates.write().await;
        templates.insert(template.name.clone(), template);
        Ok(())
    }

    /// Get template
    pub async fn get_template(&self, name: &str) -> Option<Template> {
        let templates = self.templates.read().await;
        templates.get(name).cloned()
    }

    /// Parse template to extract CTL expressions
    pub fn parse_template(&self, content: &str) -> Result<Vec<CTLExpression>> {
        let mut expressions = Vec::new();
        let mut pos = 0;

        while let Some(start) = content[pos..].find("{{") {
            let start_pos = pos + start;
            if let Some(end) = content[start_pos..].find("}}") {
                let end_pos = start_pos + end + 2;
                let expr = &content[start_pos + 2..end_pos - 2].trim();

                let function = self.parse_function(expr)?;
                expressions.push(CTLExpression {
                    function,
                    start_pos,
                    end_pos,
                });

                pos = end_pos;
            } else {
                break;
            }
        }

        Ok(expressions)
    }

    /// Parse a CTL function from expression
    fn parse_function(&self, expr: &str) -> Result<CTLFunction> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        
        if parts.is_empty() {
            return Err(TemplatingError::ParseError("Empty expression".to_string()));
        }

        match parts[0] {
            "secret" => {
                if parts.len() < 2 {
                    return Err(TemplatingError::ParseError("secret requires path".to_string()));
                }
                Ok(CTLFunction::Secret {
                    path: parts[1].trim_matches('"').to_string(),
                })
            }
            "with" => {
                if parts.len() < 3 || parts[1] != "secret" {
                    return Err(TemplatingError::ParseError(
                        "with requires 'secret <path>'".to_string(),
                    ));
                }
                Ok(CTLFunction::With {
                    path: parts[2].trim_matches('"').to_string(),
                })
            }
            "pkiCert" => {
                if parts.len() < 2 {
                    return Err(TemplatingError::ParseError("pkiCert requires path".to_string()));
                }
                
                let path = parts[1].trim_matches('"').to_string();
                let mut params = HashMap::new();
                
                // Parse parameters like "key=value"
                for part in parts.iter().skip(2) {
                    let param = part.trim_matches('"');
                    if let Some(idx) = param.find('=') {
                        let key = param[..idx].to_string();
                        let value = param[idx + 1..].to_string();
                        params.insert(key, value);
                    }
                }
                
                Ok(CTLFunction::PkiCert { path, params })
            }
            "key" => {
                if parts.len() < 2 {
                    return Err(TemplatingError::ParseError("key requires path".to_string()));
                }
                Ok(CTLFunction::Key {
                    path: parts[1].trim_matches('"').to_string(),
                })
            }
            "range" => {
                if parts.len() < 3 || parts[1] != "secrets" {
                    return Err(TemplatingError::ParseError(
                        "range requires 'secrets <path>'".to_string(),
                    ));
                }
                Ok(CTLFunction::Range {
                    path: parts[2].trim_matches('"').to_string(),
                })
            }
            _ => Err(TemplatingError::ParseError(format!(
                "Unknown function: {}",
                parts[0]
            ))),
        }
    }

    /// Render template with context
    pub async fn render_template(
        &self,
        template_name: &str,
        context: RenderContext,
    ) -> Result<RenderedFile> {
        let template = self
            .get_template(template_name)
            .await
            .ok_or_else(|| TemplatingError::RenderError("Template not found".to_string()))?;

        let mut content = template.content.clone();

        // Replace variables first
        for (key, value) in &context.variables {
            content = content.replace(&format!("${{{}}}", key), value);
        }

        // Parse and evaluate CTL expressions
        let expressions = self.parse_template(&content)?;
        
        // Replace from end to start to maintain positions
        for expr in expressions.iter().rev() {
            let replacement = self.evaluate_function(&expr.function, &context).await?;
            content.replace_range(expr.start_pos..expr.end_pos, &replacement);
        }

        let checksum = format!("{:x}", md5::compute(&content));

        let rendered = RenderedFile {
            path: template.destination.clone(),
            content: content.clone(),
            permissions: template.permissions,
            checksum,
        };

        // Store rendered file
        let mut files = self.rendered_files.write().await;
        files.insert(template_name.to_string(), rendered.clone());

        Ok(rendered)
    }

    /// Evaluate a CTL function
    async fn evaluate_function(
        &self,
        function: &CTLFunction,
        context: &RenderContext,
    ) -> Result<String> {
        match function {
            CTLFunction::Secret { path } => {
                self.get_secret_value(path, context).await
            }
            CTLFunction::With { path } => {
                // For 'with' blocks, just return the data
                self.get_secret_value(path, context).await
            }
            CTLFunction::PkiCert { path, params } => {
                self.get_pki_cert(path, params).await
            }
            CTLFunction::Key { path } => {
                self.get_key_value(path, context).await
            }
            CTLFunction::Range { path } => {
                self.list_secrets(path, context).await
            }
        }
    }

    /// Get secret value from Vault
    async fn get_secret_value(
        &self,
        path: &str,
        context: &RenderContext,
    ) -> Result<String> {
        // Check context first
        if let Some(data) = context.vault_secrets.get(path) {
            return Ok(serde_json::to_string_pretty(data)
                .map_err(|e| TemplatingError::RenderError(e.to_string()))?);
        }

        // Check mock vault data
        let vault_data = self.vault_data.read().await;
        if let Some(data) = vault_data.get(path) {
            return Ok(serde_json::to_string_pretty(data)
                .map_err(|e| TemplatingError::RenderError(e.to_string()))?);
        }

        Err(TemplatingError::SecretNotFound(path.to_string()))
    }

    /// Get PKI certificate
    async fn get_pki_cert(
        &self,
        path: &str,
        params: &HashMap<String, String>,
    ) -> Result<String> {
        // Mock PKI certificate generation
        let common_name = params.get("common_name").cloned().unwrap_or_default();
        
        Ok(format!(
            "-----BEGIN CERTIFICATE-----\nMockCert for {} at {}\n-----END CERTIFICATE-----",
            common_name, path
        ))
    }

    /// Get key value
    async fn get_key_value(&self, path: &str, context: &RenderContext) -> Result<String> {
        if let Some(value) = context.variables.get(path) {
            return Ok(value.clone());
        }

        Err(TemplatingError::SecretNotFound(path.to_string()))
    }

    /// List secrets at path
    async fn list_secrets(&self, path: &str, _context: &RenderContext) -> Result<String> {
        let vault_data = self.vault_data.read().await;
        
        let secrets: Vec<String> = vault_data
            .keys()
            .filter(|k| k.starts_with(path))
            .map(|k| k.to_string())
            .collect();

        Ok(secrets.join(", "))
    }

    /// Write rendered file (mock for testing)
    pub async fn write_file(&self, rendered: &RenderedFile) -> Result<()> {
        // In real implementation, this would write to filesystem
        // For testing, just store in memory
        let mut files = self.rendered_files.write().await;
        files.insert(rendered.path.clone(), rendered.clone());
        Ok(())
    }

    /// Get rendered file
    pub async fn get_rendered_file(&self, template_name: &str) -> Option<RenderedFile> {
        let files = self.rendered_files.read().await;
        files.get(template_name).cloned()
    }

    /// Add mock vault data for testing
    #[cfg(test)]
    pub async fn add_vault_data(&self, path: String, data: serde_json::Value) {
        let mut vault_data = self.vault_data.write().await;
        vault_data.insert(path, data);
    }
}

impl Default for AgentTemplatingService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_parse_template() {
        let service = AgentTemplatingService::new();
        
        let content = r#"
            Config: {{ secret "secret/data/app" }}
            {{ with secret "secret/data/db" }}
            Host: {{ .Data.host }}
            {{ end }}
        "#;

        let expressions = service.parse_template(content).unwrap();
        assert_eq!(expressions.len(), 2);

        match &expressions[0].function {
            CTLFunction::Secret { path } => {
                assert_eq!(path, "secret/data/app");
            }
            _ => panic!("Expected Secret function"),
        }

        match &expressions[1].function {
            CTLFunction::With { path } => {
                assert_eq!(path, "secret/data/db");
            }
            _ => panic!("Expected With function"),
        }
    }

    #[tokio::test]
    async fn test_render_secret_function() {
        let service = AgentTemplatingService::new();
        
        // Add mock data
        service
            .add_vault_data(
                "secret/data/app".to_string(),
                json!({
                    "username": "admin",
                    "password": "secret123"
                }),
            )
            .await;

        let template = Template {
            name: "app-config".to_string(),
            content: r#"{{ secret "secret/data/app" }}"#.to_string(),
            destination: "/etc/app/config.json".to_string(),
            permissions: 0o600,
            variables: HashMap::new(),
        };

        service.register_template(template).await.unwrap();

        let context = RenderContext::new();
        let rendered = service
            .render_template("app-config", context)
            .await
            .unwrap();

        assert!(rendered.content.contains("username"));
        assert!(rendered.content.contains("admin"));
        assert_eq!(rendered.permissions, 0o600);
    }

    #[tokio::test]
    async fn test_render_pki_cert() {
        let service = AgentTemplatingService::new();
        
        let template = Template {
            name: "cert-config".to_string(),
            content: r#"{{ pkiCert "pki/issue/server" "common_name=example.com" }}"#
                .to_string(),
            destination: "/etc/ssl/cert.pem".to_string(),
            permissions: 0o644,
            variables: HashMap::new(),
        };

        service.register_template(template).await.unwrap();

        let context = RenderContext::new();
        let rendered = service
            .render_template("cert-config", context)
            .await
            .unwrap();

        assert!(rendered.content.contains("BEGIN CERTIFICATE"));
        assert!(rendered.content.contains("example.com"));
    }

    #[tokio::test]
    async fn test_variable_substitution() {
        let service = AgentTemplatingService::new();
        
        let template = Template {
            name: "var-config".to_string(),
            content: "Environment: ${ENV}\nRegion: ${REGION}".to_string(),
            destination: "/etc/app/env.conf".to_string(),
            permissions: 0o644,
            variables: HashMap::new(),
        };

        service.register_template(template).await.unwrap();

        let context = RenderContext::new()
            .with_variable("ENV".to_string(), "production".to_string())
            .with_variable("REGION".to_string(), "us-west-2".to_string());

        let rendered = service
            .render_template("var-config", context)
            .await
            .unwrap();

        assert!(rendered.content.contains("Environment: production"));
        assert!(rendered.content.contains("Region: us-west-2"));
    }

    #[tokio::test]
    async fn test_write_file() {
        let service = AgentTemplatingService::new();
        
        let rendered = RenderedFile {
            path: "/etc/test/config".to_string(),
            content: "test content".to_string(),
            permissions: 0o644,
            checksum: "abc123".to_string(),
        };

        service.write_file(&rendered).await.unwrap();

        let retrieved = service
            .get_rendered_file("/etc/test/config")
            .await
            .unwrap();
        assert_eq!(retrieved.content, "test content");
    }

    #[tokio::test]
    async fn test_parse_pki_function() {
        let service = AgentTemplatingService::new();
        
        let expr = r#"pkiCert "pki/issue/role" "common_name=test.com" "ttl=24h""#;
        let function = service.parse_function(expr).unwrap();

        match function {
            CTLFunction::PkiCert { path, params } => {
                assert_eq!(path, "pki/issue/role");
                assert_eq!(params.get("common_name"), Some(&"test.com".to_string()));
                assert_eq!(params.get("ttl"), Some(&"24h".to_string()));
            }
            _ => panic!("Expected PkiCert function"),
        }
    }
}
