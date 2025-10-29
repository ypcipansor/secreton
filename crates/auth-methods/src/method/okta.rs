//! Okta authentication method

use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::model::*;
use crate::error::*;
use crate::service::*;

/// Okta authentication method
pub struct OktaAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    okta_config: Option<OktaConfig>,
    http_client: Client,
}

impl OktaAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            okta_config: None,
            http_client: Client::new(),
        }
    }

    /// Set Okta configuration
    pub fn set_okta_config(&mut self, config: OktaConfig) {
        self.okta_config = Some(config);
    }

    /// Authenticate with Okta API
    async fn authenticate_with_okta(&self, username: &str, password: &str) -> AuthMethodResult<OktaAuthResponse> {
        let config = self.okta_config.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("Okta config not set".to_string()))?;

        let auth_request = OktaAuthRequest {
            username: username.to_string(),
            password: password.to_string(),
            options: Some(OktaAuthOptions {
                multi_optional_factor_enrollment: false,
                warn_before_password_expiration: false,
            }),
        };

        let url = format!("{}/api/v1/authn", config.org_url.trim_end_matches('/'));
        let response = self.http_client
            .post(&url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&auth_request)
            .send()
            .await
            .map_err(|e| AuthMethodError::OktaError(format!("Authentication request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthMethodError::InvalidCredentials("Invalid credentials".to_string()));
        }

        let auth_response: OktaAuthResponse = response
            .json()
            .await
            .map_err(|e| AuthMethodError::OktaError(format!("Failed to parse auth response: {}", e)))?;

        // Check if authentication was successful
        match auth_response.status.as_str() {
            "SUCCESS" => Ok(auth_response),
            "MFA_REQUIRED" => Err(AuthMethodError::MfaRequired),
            "MFA_CHALLENGE" => Err(AuthMethodError::MfaRequired),
            "LOCKED_OUT" => Err(AuthMethodError::AccountLocked("Account locked out".to_string())),
            "PASSWORD_EXPIRED" => Err(AuthMethodError::PasswordExpired),
            _ => Err(AuthMethodError::InvalidCredentials("Invalid credentials".to_string())),
        }
    }

    /// Get user information from Okta
    async fn get_user_info(&self, id: &str) -> AuthMethodResult<OktaUser> {
        let config = self.okta_config.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("Okta config not set".to_string()))?;

        let url = format!("{}/api/v1/users/{}", config.org_url.trim_end_matches('/'), id);
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("SSWS {}", config.api_token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| AuthMethodError::OktaError(format!("User info request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthMethodError::OktaError(format!("Failed to get user info: {}", response.status())));
        }

        response
            .json()
            .await
            .map_err(|e| AuthMethodError::OktaError(format!("Failed to parse user response: {}", e)))
    }

    /// Get user groups from Okta
    async fn get_user_groups(&self, id: &str) -> AuthMethodResult<Vec<OktaGroup>> {
        let config = self.okta_config.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("Okta config not set".to_string()))?;

        let url = format!("{}/api/v1/users/{}/groups", config.org_url.trim_end_matches('/'), id);
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("SSWS {}", config.api_token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| AuthMethodError::OktaError(format!("Groups request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthMethodError::OktaError(format!("Failed to get user groups: {}", response.status())));
        }

        response
            .json()
            .await
            .map_err(|e| AuthMethodError::OktaError(format!("Failed to parse groups response: {}", e)))
    }

    /// Validate group membership
    fn validate_group_membership(&self, user_groups: &[OktaGroup], allowed_groups: &[String]) -> bool {
        if allowed_groups.is_empty() {
            return true; // No group restrictions
        }

        user_groups.iter().any(|group| allowed_groups.contains(&group.profile.name))
    }
}

#[async_trait]
impl AuthMethodImpl for OktaAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Okta
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());

        // Parse Okta configuration from config
        if let (Some(org_url), Some(api_token)) = (
            config.config.get("org_url"),
            config.config.get("api_token"),
        ) {
            let okta_config = OktaConfig {
                org_url: org_url.to_string(),
                api_token: api_token.to_string(),
                client_id: config.config.get("client_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                allowed_groups: config.config.get("allowed_groups")
                    .and_then(|v| v.as_str())
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
            };
            self.set_okta_config(okta_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(AuthMethodError::MethodDisabled);
        }

        match credentials {
            AuthCredentials::UserPass { username, password } => {
                let auth_response = self.authenticate_with_okta(username, password).await?;

                // Get detailed user information
                let user_info = self.get_user_info(&auth_response._embedded.user.id).await?;
                let user_groups = self.get_user_groups(&auth_response._embedded.user.id).await?;

                // Validate group membership if configured
                let config = self.okta_config.as_ref().unwrap();
                if !self.validate_group_membership(&user_groups, &config.allowed_groups) {
                    return Err(AuthMethodError::AccessDenied);
                }

                let groups = user_groups.into_iter()
                    .map(|g| g.profile.name)
                    .collect::<Vec<String>>();

                let user_info_result = UserInfo {
                    username: user_info.profile.login,
                    id: Uuid::new_v4(), // Generate UUID since Okta ID is string
                    groups,
                    metadata: {
                        let mut meta = HashMap::new();
                        if let Some(ref email) = user_info.profile.email {
                            meta.insert("email".to_string(), email.clone());
                        }
                        if let Some(ref first_name) = user_info.profile.first_name {
                            meta.insert("first_name".to_string(), first_name.clone());
                        }
                        if let Some(ref last_name) = user_info.profile.last_name {
                            meta.insert("last_name".to_string(), last_name.clone());
                        }
                        meta
                    },
                    email: user_info.profile.email.clone(),
                    display_name: {
                        let first = user_info.profile.first_name.as_ref();
                        let last = user_info.profile.last_name.as_ref();
                        match (first, last) {
                            (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                            (Some(f), None) => Some(f.to_string()),
                            (None, Some(l)) => Some(l.to_string()),
                            _ => None,
                        }
                    },
                    created_at: Utc::now(),
                    last_login: Some(Utc::now()),
                };

                Ok(AuthResult {
                    authenticated: true,
                    user_info: Some(user_info_result),
                    policies: vec![], // Policies would be determined by groups
                    lease_duration: None,
                    renewable: Some(true),
                    token: None,
                    accessor: None,
                    metadata: HashMap::new(),
                    mfa_required: false,
                    mfa_methods: Vec::new(),
                })
            }
            _ => Err(AuthMethodError::InvalidCredentials("Invalid credentials".to_string())),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(AuthMethodError::MethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(AuthMethodError::MethodNotSupported)
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

/// Okta configuration
#[derive(Clone, Debug)]
pub struct OktaConfig {
    pub org_url: String,
    pub api_token: String,
    pub client_id: Option<String>,
    pub allowed_groups: Vec<String>,
}

/// Okta authentication request
#[derive(Clone, Debug, Serialize)]
pub struct OktaAuthRequest {
    pub username: String,
    pub password: String,
    pub options: Option<OktaAuthOptions>,
}

/// Okta authentication options
#[derive(Clone, Debug, Serialize)]
pub struct OktaAuthOptions {
    pub multi_optional_factor_enrollment: bool,
    pub warn_before_password_expiration: bool,
}

/// Okta authentication response
#[derive(Clone, Debug, Deserialize)]
pub struct OktaAuthResponse {
    pub status: String,
    pub session_token: Option<String>,
    pub _embedded: OktaEmbedded,
}

/// Okta embedded user information
#[derive(Clone, Debug, Deserialize)]
pub struct OktaEmbedded {
    pub user: OktaUserSummary,
}

/// Okta user summary
#[derive(Clone, Debug, Deserialize)]
pub struct OktaUserSummary {
    pub id: String,
    pub profile: OktaUserProfileSummary,
}

/// Okta user profile summary
#[derive(Clone, Debug, Deserialize)]
pub struct OktaUserProfileSummary {
    pub login: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Okta user information
#[derive(Clone, Debug, Deserialize)]
pub struct OktaUser {
    pub id: String,
    pub status: String,
    pub created: String,
    pub activated: Option<String>,
    pub status_changed: Option<String>,
    pub last_login: Option<String>,
    pub last_updated: String,
    pub password_changed: Option<String>,
    pub profile: OktaUserProfile,
}

/// Okta user profile
#[derive(Clone, Debug, Deserialize)]
pub struct OktaUserProfile {
    pub login: String,
    pub email: Option<String>,
    pub second_email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub middle_name: Option<String>,
    pub honorific_prefix: Option<String>,
    pub honorific_suffix: Option<String>,
    pub title: Option<String>,
    pub display_name: Option<String>,
    pub nick_name: Option<String>,
    pub profile_url: Option<String>,
    pub primary_phone: Option<String>,
    pub mobile_phone: Option<String>,
    pub street_address: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub zip_code: Option<String>,
    pub country_code: Option<String>,
    pub postal_address: Option<String>,
    pub preferred_language: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub user_type: Option<String>,
    pub employee_number: Option<String>,
    pub cost_center: Option<String>,
    pub organization: Option<String>,
    pub division: Option<String>,
    pub department: Option<String>,
    pub manager_id: Option<String>,
    pub manager: Option<String>,
}

/// Okta group
#[derive(Clone, Debug, Deserialize)]
pub struct OktaGroup {
    pub id: String,
    pub created: String,
    pub last_updated: String,
    pub last_membership_updated: String,
    pub object_class: Vec<String>,
    pub type_: String,
    pub profile: OktaGroupProfile,
}

/// Okta group profile
#[derive(Clone, Debug, Deserialize)]
pub struct OktaGroupProfile {
    pub name: String,
    pub description: Option<String>,
}