//! Authentication handler for Secreton Agent
//!
//! Handles authentication with the Secreton API and token management.

use crate::config::VaultConfig;
use secreton_errors::SecretonError;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Handles authentication with Secreton API
#[derive(Clone)]
pub struct AuthHandler {
    config: Option<VaultConfig>,
    client: reqwest::Client,
    token: Arc<RwLock<Option<String>>>,
}

impl AuthHandler {
    /// Create a new authentication handler
    pub fn new(config: Option<VaultConfig>) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            token: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize authentication (load token from config/file/env)
    pub async fn initialize(&self) -> Result<(), SecretonError> {
        let mut token_store = self.token.write().await;

        if let Some(config) = &self.config {
            // Priority 1: Direct token in config
            if let Some(token) = &config.token {
                *token_store = Some(token.clone());
                info!("Loaded authentication token from configuration");
                return Ok(());
            }

            // Priority 2: Token from file
            if let Some(path) = &config.token_file {
                if let Ok(token) = tokio::fs::read_to_string(path).await {
                    *token_store = Some(token.trim().to_string());
                    info!("Loaded authentication token from file: {}", path);
                    return Ok(());
                } else {
                    warn!("Failed to read token from file: {}", path);
                }
            }
        }

        // Priority 3: Environment variable
        if let Ok(token) = std::env::var("SECRETON_TOKEN") {
            *token_store = Some(token);
            info!("Loaded authentication token from environment");
            return Ok(());
        }

        warn!("No authentication token found. Agent may be unable to fetch secrets.");
        Ok(())
    }

    /// Get the current authentication token
    pub async fn get_token(&self) -> Option<String> {
        self.token.read().await.clone()
    }

    /// Validate the current token with the API
    pub async fn validate(&self) -> Result<bool, SecretonError> {
        let token = self.get_token().await;
        if token.is_none() {
            return Ok(false);
        }

        let config = if let Some(c) = &self.config {
            c
        } else {
            return Ok(false);
        };

        let url = format!("{}/api/v1/auth/token/lookup-self", config.server_url);

        match self.client
            .get(&url)
            .header("X-Vault-Token", token.unwrap()) // Using Vault-compatible header or Authorization
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(true)
                } else {
                    warn!("Token validation failed: {}", response.status());
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Failed to connect to Secreton API: {}", e);
                // Don't invalidate token on network error
                Ok(true)
            }
        }
    }

    /// Fetch a secret from the API
    pub async fn get_secret(&self, path: &str) -> Result<serde_json::Value, SecretonError> {
        let token = self.get_token().await.ok_or_else(|| {
            SecretonError::Authentication { message: "No authentication token available".to_string() }
        })?;

        let config = self.config.as_ref().ok_or_else(|| {
            SecretonError::Configuration { message: "Vault configuration missing".to_string() }
        })?;

        // Handle path format (ensure it starts with /v1/)
        let api_path = if path.starts_with("secret/") {
            format!("v1/{}/data/{}", "secret", path.strip_prefix("secret/").unwrap())
        } else if !path.starts_with("v1/") {
            format!("v1/secret/data/{}", path)
        } else {
            path.to_string()
        };

        let url = format!("{}/{}", config.server_url.trim_end_matches('/'), api_path);

        let response = self.client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| SecretonError::Network { message: e.to_string() })?;

        if !response.status().is_success() {
            return Err(SecretonError::ServiceUnavailable {
                service: format!("API Error: {}", response.status())
            });
        }

        let body: serde_json::Value = response.json().await
            .map_err(|e| SecretonError::Network { message: format!("Response deserialization failed: {}", e) })?;

        Ok(body)
    }
}
