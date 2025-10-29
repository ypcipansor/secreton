//! Placeholder implementation for totp secret engine

use async_trait::async_trait;
use std::collections::HashMap;
use serde_json::Value;
use crate::model::*;
use crate::error::*;
use crate::service::*;

/// totp secret engine
pub struct TotpEngine {
    enabled: bool,
}

impl TotpEngine {
    pub fn new() -> Self {
        Self {
            enabled: false,
        }
    }
}

#[async_trait]
impl SecretEngine for TotpEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Totp
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, _path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }
        Ok(None)
    }

    async fn write(&mut self, _path: &str, _data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }
        // TOTP engine doesn't support arbitrary writes - use generate endpoint instead
        Err(SecretError::InvalidOperation("TOTP engine does not support write operations. Use /generate endpoint to create TOTP secrets.".to_string()))
    }

    async fn delete(&mut self, _path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }
        Ok(())
    }

    async fn list(&self, _path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("Totp".to_string()));
        }
        Ok(vec![])
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}
