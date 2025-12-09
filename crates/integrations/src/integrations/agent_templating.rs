// Agent Templating - Consul Template (CTL) function support for _config file rendering
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
    /// {{ with _secret "_secret/_data/app" }}...{{ end }}
    With { _path: String },
    /// {{ _secret "_secret/_data/app" }}
    Secret { _path: String },
    /// {{ pkiCert "pki/issue/role" "common_name=example.com" }}
    PkiCert {
        _path: String,
        params: HashMap<String, String>,
    },
    /// {{ _key "_config/_key" }}
    Key { _path: String },
    /// {{ range secrets "_secret/_data" }}...{{ end }}
    Range { _path: String },
    /// {{ .Data.host }} - variable reference
    Variable { _path: String },
    /// {{ end }} - end control structure
    End,
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
    pub _name: String,
    pub content: String,
    pub destination: String,
    pub permissions: u32, // Unix file permissions
    pub variables: HashMap<String, String>,
}

/// Rendered file output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedFile {
    pub _path: String,
    pub content: String,
    pub permissions: u32,
    pub checksum: String,
}

/// Render _context
#[derive(Debug, Clone)]
pub struct RenderContext {
    pub variables: HashMap<String, String>,
    pub secreton_secrets: HashMap<String, serde_json::Value>,
}

impl RenderContext {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            secreton_secrets: HashMap::new(),
        }
    }

    pub fn with_variable(mut self, _key: String, value: String) -> Self {
        self.variables.insert(_key, value);
        self
    }

    pub fn with_secret(mut self, _path: String, _data: serde_json::Value) -> Self {
        self.secreton_secrets.insert(_path, _data);
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
    // Mock secreton client for testing
    secreton_data: Arc<RwLock<HashMap<String, serde_json::Value>>>,
}

impl AgentTemplatingService {
    pub fn new() -> Self {
        Self {
            templates: Arc::new(RwLock::new(HashMap::new())),
            rendered_files: Arc::new(RwLock::new(HashMap::new())),
            secreton_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a template
    pub async fn register_template(&self, template: Template) -> Result<()> {
        let mut templates = self.templates.write().await;
        templates.insert(template._name.clone(), template);
        Ok(())
    }

    /// Get template
    pub async fn get_template(&self, _name: &str) -> Option<Template> {
        let templates = self.templates.read().await;
        templates.get(_name).cloned()
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
        let expr = expr.trim();

        // Handle variable references starting with .
        if expr.starts_with('.') {
            return Ok(CTLFunction::Variable {
                _path: expr.to_string(),
            });
        }

        let parts: Vec<&str> = expr.split_whitespace().collect();

        if parts.is_empty() {
            return Err(TemplatingError::ParseError("Empty expression".to_string()));
        }

        match parts[0] {
            "_secret" => {
                if parts.len() < 2 {
                    return Err(TemplatingError::ParseError(
                        "_secret requires _path".to_string(),
                    ));
                }
                Ok(CTLFunction::Secret {
                    _path: parts[1].trim_matches('"').to_string(),
                })
            }
            "with" => {
                if parts.len() < 3 || parts[1] != "_secret" {
                    return Err(TemplatingError::ParseError(
                        "with requires '_secret <_path>'".to_string(),
                    ));
                }
                Ok(CTLFunction::With {
                    _path: parts[2].trim_matches('"').to_string(),
                })
            }
            "end" => Ok(CTLFunction::End),
            "pkiCert" => {
                if parts.len() < 2 {
                    return Err(TemplatingError::ParseError(
                        "pkiCert requires _path".to_string(),
                    ));
                }

                let _path = parts[1].trim_matches('"').to_string();
                let mut params = HashMap::new();

                // Parse parameters like "_key=value"
                for part in parts.iter().skip(2) {
                    let param = part.trim_matches('"');
                    if let Some(idx) = param.find('=') {
                        let _key = param[..idx].to_string();
                        let value = param[idx + 1..].to_string();
                        params.insert(_key, value);
                    }
                }

                Ok(CTLFunction::PkiCert { _path, params })
            }
            "_key" => {
                if parts.len() < 2 {
                    return Err(TemplatingError::ParseError(
                        "_key requires _path".to_string(),
                    ));
                }
                Ok(CTLFunction::Key {
                    _path: parts[1].trim_matches('"').to_string(),
                })
            }
            "range" => {
                if parts.len() < 3 || parts[1] != "secrets" {
                    return Err(TemplatingError::ParseError(
                        "range requires 'secrets <_path>'".to_string(),
                    ));
                }
                Ok(CTLFunction::Range {
                    _path: parts[2].trim_matches('"').to_string(),
                })
            }
            _ => Err(TemplatingError::ParseError(format!(
                "Unknown function: {}",
                parts[0]
            ))),
        }
    }

    /// Render template with _context
    pub async fn render_template(
        &self,
        template_name: &str,
        _context: RenderContext,
    ) -> Result<RenderedFile> {
        let template = self
            .get_template(template_name)
            .await
            .ok_or_else(|| TemplatingError::RenderError("Template not found".to_string()))?;

        let mut content = template.content.clone();

        // Replace variables first
        for (_key, value) in &_context.variables {
            content = content.replace(&format!("${{{}}}", _key), value);
        }

        // Parse and evaluate CTL expressions
        let expressions = self.parse_template(&content)?;

        // Replace from end to start to maintain positions
        for expr in expressions.iter().rev() {
            let replacement = self.evaluate_function(&expr.function, &_context).await?;
            content.replace_range(expr.start_pos..expr.end_pos, &replacement);
        }

        let checksum = format!("{:x}", md5::compute(&content));

        let rendered = RenderedFile {
            _path: template.destination.clone(),
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
        _context: &RenderContext,
    ) -> Result<String> {
        match function {
            CTLFunction::Secret { _path } => self.get_secret_value(_path, _context).await,
            CTLFunction::With { _path } => {
                // For 'with' blocks, just return the _data
                self.get_secret_value(_path, _context).await
            }
            CTLFunction::PkiCert { _path, params } => self.get_pki_cert(_path, params).await,
            CTLFunction::Key { _path } => self.get_key_value(_path, _context).await,
            CTLFunction::Range { _path } => self.list_secrets(_path, _context).await,
            CTLFunction::Variable { _path } => self.get_variable_value(_path, _context).await,
            CTLFunction::End => {
                // Control structure, no output
                Ok(String::new())
            }
        }
    }

    /// Get _secret value from Secret
    async fn get_secret_value(&self, _path: &str, _context: &RenderContext) -> Result<String> {
        // Check _context first
        if let Some(_data) = _context.secreton_secrets.get(_path) {
            return Ok(serde_json::to_string_pretty(_data)
                .map_err(|_e| TemplatingError::RenderError(_e.to_string()))?);
        }

        // Check mock secreton _data
        let secreton_data = self.secreton_data.read().await;
        if let Some(_data) = secreton_data.get(_path) {
            return Ok(serde_json::to_string_pretty(_data)
                .map_err(|_e| TemplatingError::RenderError(_e.to_string()))?);
        }

        Err(TemplatingError::SecretNotFound(_path.to_string()))
    }

    /// Get PKI certificate
    async fn get_pki_cert(&self, _path: &str, params: &HashMap<String, String>) -> Result<String> {
        // Mock PKI certificate generation
        let common_name = params.get("common_name").cloned().unwrap_or_default();

        Ok(format!(
            "-----BEGIN CERTIFICATE-----\nMockCert for {} at {}\n-----END CERTIFICATE-----",
            common_name, _path
        ))
    }

    /// Get _key value
    async fn get_key_value(&self, _path: &str, _context: &RenderContext) -> Result<String> {
        if let Some(value) = _context.variables.get(_path) {
            return Ok(value.clone());
        }

        Err(TemplatingError::SecretNotFound(_path.to_string()))
    }

    /// List secrets at _path
    async fn list_secrets(&self, _path: &str, _context: &RenderContext) -> Result<String> {
        let secreton_data = self.secreton_data.read().await;

        let secrets: Vec<String> = secreton_data
            .keys()
            .filter(|k| k.starts_with(_path))
            .map(|k| k.to_string())
            .collect();

        Ok(secrets.join(", "))
    }

    /// Get variable value (for .Data.field references)
    async fn get_variable_value(&self, _path: &str, _context: &RenderContext) -> Result<String> {
        // Mock implementation - in real CTL, this would access _data from 'with' blocks
        // For testing, return mock values based on the _path
        match _path {
            ".Data.host" => Ok("db.example.com".to_string()),
            ".Data.port" => Ok("5432".to_string()),
            ".Data._username" => Ok("admin".to_string()),
            _ => Err(TemplatingError::RenderError(format!(
                "Variable {} not found",
                _path
            ))),
        }
    }

    /// Write rendered file (mock for testing)
    pub async fn write_file(&self, rendered: &RenderedFile) -> Result<()> {
        // In real implementation, this would write to filesystem
        // For testing, just store in memory
        let mut files = self.rendered_files.write().await;
        files.insert(rendered._path.clone(), rendered.clone());
        Ok(())
    }

    /// Get rendered file
    pub async fn get_rendered_file(&self, template_name: &str) -> Option<RenderedFile> {
        let files = self.rendered_files.read().await;
        files.get(template_name).cloned()
    }

    /// Add mock secreton _data for testing
    #[cfg(test)]
    pub async fn add_secreton_data(&self, _path: String, _data: serde_json::Value) {
        let mut secreton_data = self.secreton_data.write().await;
        secreton_data.insert(_path, _data);
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
            Config: {{ _secret "_secret/_data/app" }}
            {{ with _secret "_secret/_data/db" }}
            Host: {{ .Data.host }}
            {{ end }}
        "#;

        let expressions = service.parse_template(content).unwrap();
        assert_eq!(expressions.len(), 4);

        match &expressions[0].function {
            CTLFunction::Secret { _path } => {
                assert_eq!(_path, "_secret/_data/app");
            }
            _ => assert!(false, "Expected Secret function"),
        }

        match &expressions[1].function {
            CTLFunction::With { _path } => {
                assert_eq!(_path, "_secret/_data/db");
            }
            _ => assert!(false, "Expected With function"),
        }

        match &expressions[2].function {
            CTLFunction::Variable { _path } => {
                assert_eq!(_path, ".Data.host");
            }
            _ => assert!(false, "Expected Variable reference"),
        }

        match &expressions[3].function {
            CTLFunction::End => {
                // Expected end control structure
            }
            _ => assert!(false, "Expected End control structure"),
        }
    }

    #[tokio::test]
    async fn test_render_secret_function() {
        let service = AgentTemplatingService::new();

        // Add mock _data
        service
            .add_secreton_data(
                "_secret/_data/app".to_string(),
                json!({
                    "_username": "admin",
                    "_password": "secret123"
                }),
            )
            .await;

        let template = Template {
            _name: "app-_config".to_string(),
            content: r#"{{ _secret "_secret/_data/app" }}"#.to_string(),
            destination: "/etc/app/_config.json".to_string(),
            permissions: 0o600,
            variables: HashMap::new(),
        };

        service.register_template(template).await.unwrap();

        let _context = RenderContext::new();
        let rendered = service
            .render_template("app-_config", _context)
            .await
            .unwrap();

        assert!(rendered.content.contains("_username"));
        assert!(rendered.content.contains("admin"));
        assert_eq!(rendered.permissions, 0o600);
    }

    #[tokio::test]
    async fn test_render_pki_cert() {
        let service = AgentTemplatingService::new();

        let template = Template {
            _name: "cert-_config".to_string(),
            content: r#"{{ pkiCert "pki/issue/server" "common_name=example.com" }}"#.to_string(),
            destination: "/etc/ssl/cert.pem".to_string(),
            permissions: 0o644,
            variables: HashMap::new(),
        };

        service.register_template(template).await.unwrap();

        let _context = RenderContext::new();
        let rendered = service
            .render_template("cert-_config", _context)
            .await
            .unwrap();

        assert!(rendered.content.contains("BEGIN CERTIFICATE"));
        assert!(rendered.content.contains("example.com"));
    }

    #[tokio::test]
    async fn test_variable_substitution() {
        let service = AgentTemplatingService::new();

        let template = Template {
            _name: "var-_config".to_string(),
            content: "Environment: ${ENV}\nRegion: ${REGION}".to_string(),
            destination: "/etc/app/env.conf".to_string(),
            permissions: 0o644,
            variables: HashMap::new(),
        };

        service.register_template(template).await.unwrap();

        let _context = RenderContext::new()
            .with_variable("ENV".to_string(), "production".to_string())
            .with_variable("REGION".to_string(), "us-west-2".to_string());

        let rendered = service
            .render_template("var-_config", _context)
            .await
            .unwrap();

        assert!(rendered.content.contains("Environment: production"));
        assert!(rendered.content.contains("Region: us-west-2"));
    }

    #[tokio::test]
    async fn test_write_file() {
        let service = AgentTemplatingService::new();

        let rendered = RenderedFile {
            _path: "/etc/test/_config".to_string(),
            content: "test content".to_string(),
            permissions: 0o644,
            checksum: "abc123".to_string(),
        };

        service.write_file(&rendered).await.unwrap();

        let retrieved = service
            .get_rendered_file("/etc/test/_config")
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
            CTLFunction::PkiCert { _path, params } => {
                assert_eq!(_path, "pki/issue/role");
                assert_eq!(params.get("common_name"), Some(&"test.com".to_string()));
                assert_eq!(params.get("ttl"), Some(&"24h".to_string()));
            }
            _ => assert!(false, "Expected PkiCert function"),
        }
    }
}
