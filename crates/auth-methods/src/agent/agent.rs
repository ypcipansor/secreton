//! Agent authentication structures

use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};


/// Agent type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentType {
    AppRole,
    Kubernetes,
    AWS,
    Azure,
    GCP,
    Custom(String),
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_type: AgentType,
    pub name: String,
    pub description: Option<String>,
    pub metadata: HashMap<String, String>,
    pub enabled: bool,
    pub creation_time: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
}

/// Agent authentication request
#[derive(Debug, Deserialize)]
pub struct AgentAuthRequest {
    pub agent_type: AgentType,
    pub credentials: HashMap<String, String>,
    pub metadata: Option<HashMap<String, String>>,
}

/// Agent authentication response
#[derive(Debug, Serialize)]
pub struct AgentAuthResponse {
    pub entity_id: Uuid,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub lease_duration: Option<u64>,
}

/// Agent registration request
#[derive(Debug, Deserialize)]
pub struct AgentRegistrationRequest {
    pub agent_type: AgentType,
    pub name: String,
    pub description: Option<String>,
    pub config: HashMap<String, String>,
}

/// Agent update request
#[derive(Debug, Deserialize)]
pub struct AgentUpdateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config: Option<HashMap<String, String>>,
    pub enabled: Option<bool>,
}

/// Agent list response
#[derive(Debug, Serialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentConfig>,
}

/// AppRole specific structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleConfig {
    pub role_id: String,
    pub secret_id: Option<String>,
    pub policies: Vec<String>,
    pub token_ttl: Option<u64>,
    pub token_max_ttl: Option<u64>,
    pub secret_id_ttl: Option<u64>,
    pub secret_id_num_uses: Option<u32>,
}

/// Kubernetes specific structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    pub kubernetes_host: String,
    pub kubernetes_ca_cert: String,
    pub token_reviewer_jwt: String,
    pub issuer: Option<String>,
    pub disable_iss_validation: bool,
    pub disable_local_ca_jwt: bool,
}

/// AWS specific structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AWSConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub iam_endpoint: Option<String>,
    pub sts_endpoint: Option<String>,
    pub max_retries: Option<i32>,
}