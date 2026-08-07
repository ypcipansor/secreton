//! Secret operations.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Client, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub path: String,
    pub data: HashMap<String, String>,
    pub version: u32,
}

#[derive(Debug, Serialize)]
struct PutBody<'a> {
    data: &'a HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub token: AuthToken,
}

impl Client {
    /// Exchange credentials for a bearer token.
    pub async fn login(&self, request: &LoginRequest) -> Result<LoginResponse> {
        self.post("auth/login", request).await
    }

    pub async fn get_secret(&self, path: &str) -> Result<Secret> {
        self.get(&format!("secret/secrets/{path}")).await
    }

    pub async fn put_secret(
        &self,
        path: &str,
        data: &HashMap<String, String>,
    ) -> Result<Secret> {
        self.post(&format!("secret/secrets/{path}"), &PutBody { data })
            .await
    }

    pub async fn delete_secret(&self, path: &str) -> Result<serde_json::Value> {
        self.delete(&format!("secret/secrets/{path}")).await
    }

    pub async fn list_secrets(&self) -> Result<Vec<String>> {
        self.get("secret/secrets").await
    }
}
