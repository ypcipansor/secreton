//! Template rendering engine
//!
//! Handles fetching secrets and rendering them into configuration files
//! using Handlebars templates.

use crate::auth::AuthHandler;
use crate::config::TemplateConfig;
use handlebars::Handlebars;
use secreton_errors::SecretonError;
use std::collections::HashMap;
use std::path::Path;
use tokio::process::Command;
use tracing::{error, info, warn};

/// Manages template rendering and lifecycle
pub struct TemplateManager {
    auth_handler: AuthHandler,
    templates: Vec<TemplateConfig>,
    renderer: Handlebars<'static>,
}

impl TemplateManager {
    /// Create a new template manager
    pub fn new(auth_handler: AuthHandler, templates: Vec<TemplateConfig>) -> Self {
        let mut renderer = Handlebars::new();
        renderer.set_strict_mode(true);

        // Register helper is done during rendering to capture async context if needed
        // but Handlebars helpers are synchronous.
        // We will pre-fetch secrets before rendering or use a custom block helper if needed.
        // For simplicity in this MVP, we fetch secrets defined in the template first or use a known structure.

        // Actually, to support `{{ secret "path" "key" }}`, we need a way to fetch inside the helper.
        // Since helpers are sync, we can't await.
        // Strategy: Parse template, find all secret paths, fetch them async, populate data context, then render.

        Self {
            auth_handler,
            templates,
            renderer,
        }
    }

    /// Start the template rendering loop
    pub async fn start(&self, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) -> Result<(), SecretonError> {
        if self.templates.is_empty() {
            info!("No templates configured, skipping template manager start");
            return Ok(());
        }

        info!("Starting template manager for {} templates", self.templates.len());

        // Initial render
        self.render_all().await;

        // Calculate minimum interval from templates, default to 60s
        let interval_secs = self.templates.iter()
            .map(|t| t.refresh_interval_seconds)
            .min()
            .unwrap_or(60)
            .max(1); // Ensure at least 1 second

        let mut interval_timer = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    self.render_all().await;
                }
                _ = shutdown_rx.recv() => {
                    info!("Template manager shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Render all configured templates
    async fn render_all(&self) {
        for template in &self.templates {
            if let Err(e) = self.render_template(template).await {
                error!("Failed to render template {}: {}", template.source, e);
            }
        }
    }

    /// Render a single template
    async fn render_template(&self, config: &TemplateConfig) -> Result<(), SecretonError> {
        // 1. Read source template
        let source_content = tokio::fs::read_to_string(&config.source).await
            .map_err(SecretonError::Io)?;

        // 2. Identify secrets to fetch
        // Simple regex parsing to find {{ secret "path" ... }}
        // This is a naive implementation; a full parser would be better but expensive.
        // We look for patterns like: (secret "path/to/secret"
        let secret_paths = self.extract_secret_paths(&source_content);

        // 3. Fetch secrets
        let mut data_context: HashMap<String, serde_json::Value> = HashMap::new();
        let mut secrets_map: HashMap<String, serde_json::Value> = HashMap::new();

        for path in secret_paths {
            match self.auth_handler.get_secret(&path).await {
                Ok(secret_data) => {
                    // Assuming standard Vault/Secreton structure: {"data": {"data": {...}}}
                    if let Some(inner_data) = secret_data.get("data").and_then(|d| d.get("data")) {
                         secrets_map.insert(path.clone(), inner_data.clone());
                    } else if let Some(inner_data) = secret_data.get("data") {
                         secrets_map.insert(path.clone(), inner_data.clone());
                    } else {
                         secrets_map.insert(path.clone(), secret_data);
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch secret {}: {}", path, e);
                }
            }
        }

        // Add environment variables to context
        let env_vars: HashMap<String, String> = std::env::vars().collect();
        data_context.insert("env".to_string(), serde_json::to_value(env_vars).unwrap());
        data_context.insert("secrets".to_string(), serde_json::to_value(&secrets_map).unwrap());

        // 4. Render
        // We register a custom helper that looks up in our pre-fetched map
        let renderer = self.renderer.clone();

        // Helper: {{ secret "path" "key" }}
        // Since we can't move the map into the closure easily if it's not static or Arc,
        // we'll pass the whole secrets map as data and use standard handlebars lookup: {{ secrets.path.key }}
        // But users want {{ secret "path" "key" }}.
        // For MVP, we'll recommend using {{ secrets.["path/to/secret"].key }} or implement a helper that looks into root data.

        // Let's rely on the pre-filled `secrets` object in the context.
        // Transform the map keys to be handlebars friendly if possible, or just use bracket notation.

        let rendered = renderer.render_template(&source_content, &data_context)
            .map_err(|e| SecretonError::Template { message: format!("Template render error: {}", e) })?;

        // 5. Write to destination
        let dest_path = Path::new(&config.destination);

        // Check if content changed
        let changed = if dest_path.exists() {
             let current = tokio::fs::read_to_string(dest_path).await.unwrap_or_default();
             current != rendered
        } else {
            true
        };

        if changed {
            if let Some(parent) = dest_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(SecretonError::Io)?;
            }

            tokio::fs::write(dest_path, rendered).await.map_err(SecretonError::Io)?;
            info!("Updated configuration file: {}", config.destination);

            // 6. Execute command
            if let Some(cmd) = &config.command {
                info!("Executing command: {}", cmd);
                // Use sh -c to allow complex commands with pipes/args
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .output()
                    .await
                    .map_err(SecretonError::Io)?;

                if !output.status.success() {
                    warn!("Command failed: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
        }

        Ok(())
    }

    /// Extract secret paths from template string
    /// Looks for strings inside `secrets.["path"]` or custom patterns.
    /// For this implementation, we will fetch *all* secrets defined in a specific way or just support
    /// explicit `{{ secrets.['path/to/secret'].key }}` which requires us to find those paths first.
    fn extract_secret_paths(&self, content: &str) -> Vec<String> {
        // Very basic extraction: look for "secret/..." strings
        // In a real agent, we'd use a parser.
        // For this MVP, we'll scan for things that look like secret paths inside quotes.
        let mut paths = Vec::new();

        // Regex to find: secrets.['(path)'] or secrets.["(path)"]
        // This is a heuristic.
        let re = regex::Regex::new(r#"secrets\.\[['"]([^'"]+)['"]\]"#).unwrap();
        for cap in re.captures_iter(content) {
             if let Some(path) = cap.get(1) {
                 paths.push(path.as_str().to_string());
             }
        }

        paths
    }
}
