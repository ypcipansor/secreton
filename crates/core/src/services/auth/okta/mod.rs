use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{Utc, Duration};
use crate::storage::Storage;
use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaConfig {
    pub org_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub api_token: Option<String>,
    pub groups_claim: Option<String>,
    pub username_claim: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaUser {
    pub id: String,
    pub login: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub status: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaGroup {
    pub id: String,
    pub profile: GroupProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupProfile {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OktaTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: String,
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OktaUserInfo {
    sub: String,
    name: String,
    preferred_username: String,
    email: String,
    groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct OktaIntrospectResponse {
    active: bool,
    username: Option<String>,
    groups: Option<Vec<String>>,
    client_id: Option<String>,
    exp: Option<i64>,
}

pub struct OktaAuth {
    config: OktaConfig,
    http_client: Client,
}

impl OktaAuth {
    pub fn new(config: OktaConfig) -> Self {
        let http_client = Client::new();
        Self {
            config,
            http_client,
        }
    }

    pub async fn authenticate(
        &self,
        auth_request: &AuthRequest,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        match auth_request {
            AuthRequest::OAuth { code, state } => {
                self.authenticate_oauth(code, state).await
            }
            AuthRequest::Token { token } => {
                self.authenticate_token(token).await
            }
            AuthRequest::Credentials { username, password } => {
                self.authenticate_credentials(username, password).await
            }
        }
    }

    async fn authenticate_oauth(
        &self,
        code: &str,
        _state: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Exchange authorization code for access token
        let token_url = format!("{}/oauth2/v1/token", self.config.org_url);

        let params = [
            ("grant_type", "authorization_code"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
        ];

        let response = self.http_client
            .post(&token_url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("OAuth token exchange failed: {}", response.status()).into());
        }

        let token_response: OktaTokenResponse = response.json().await?;

        // Get user info using access token
        let user_info = self.get_user_info(&token_response.access_token).await?;

        let expires_at = Utc::now() + Duration::seconds(token_response.expires_in);

        Ok(AuthResponse {
            authenticated: true,
            user_info: UserInfo {
                username: user_info.preferred_username.clone(),
                email: Some(user_info.email),
                groups: user_info.groups.unwrap_or_default(),
                metadata: HashMap::new(),
            },
            policies: vec!["default".to_string()],
            lease_duration: token_response.expires_in,
            renewable: true,
            token: token_response.access_token,
            accessor: format!("okta-oauth-{}", user_info.sub),
            metadata: HashMap::new(),
        })
    }

    async fn authenticate_token(
        &self,
        token: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Introspect the token
        let introspect_url = format!("{}/oauth2/v1/introspect", self.config.org_url);

        let params = [
            ("token", token),
            ("token_type_hint", "access_token"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self.http_client
            .post(&introspect_url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Token introspection failed: {}", response.status()).into());
        }

        let introspect_response: OktaIntrospectResponse = response.json().await?;

        if !introspect_response.active {
            return Ok(AuthResponse {
                authenticated: false,
                user_info: UserInfo {
                    username: "".to_string(),
                    email: None,
                    groups: vec![],
                    metadata: HashMap::new(),
                },
                policies: vec![],
                lease_duration: 0,
                renewable: false,
                token: "".to_string(),
                accessor: "".to_string(),
                metadata: HashMap::new(),
            });
        }

        let username = introspect_response.username.unwrap_or_default();
        let groups = introspect_response.groups.unwrap_or_default();
        let expires_at = introspect_response.exp.unwrap_or(0);

        Ok(AuthResponse {
            authenticated: true,
            user_info: UserInfo {
                username: username.clone(),
                email: None,
                groups,
                metadata: HashMap::new(),
            },
            policies: vec!["default".to_string()],
            lease_duration: expires_at - Utc::now().timestamp(),
            renewable: true,
            token: token.to_string(),
            accessor: format!("okta-token-{}", username),
            metadata: HashMap::new(),
        })
    }

    async fn authenticate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Authenticate using Okta API
        let auth_url = format!("{}/api/v1/authn", self.config.org_url);

        let auth_payload = serde_json::json!({
            "username": username,
            "password": password,
            "options": {
                "multiOptionalFactorEnroll": false,
                "warnBeforePasswordExpired": false
            }
        });

        let response = self.http_client
            .post(&auth_url)
            .json(&auth_payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Authentication failed: {}", response.status()).into());
        }

        #[derive(Deserialize)]
        struct AuthResult {
            status: String,
            session_token: Option<String>,
            _embedded: Option<Embedded>,
        }

        #[derive(Deserialize)]
        struct Embedded {
            user: OktaUser,
        }

        let auth_result: AuthResult = response.json().await?;

        if auth_result.status != "SUCCESS" {
            return Ok(AuthResponse {
                authenticated: false,
                user_info: UserInfo {
                    username: username.to_string(),
                    email: None,
                    groups: vec![],
                    metadata: HashMap::new(),
                },
                policies: vec![],
                lease_duration: 0,
                renewable: false,
                token: "".to_string(),
                accessor: "".to_string(),
                metadata: HashMap::new(),
            });
        }

        let session_token = auth_result.session_token.ok_or("No session token received")?;

        // Get user groups
        let groups = if let Some(embedded) = auth_result._embedded {
            self.get_user_groups(&embedded.user.id).await.unwrap_or_default()
        } else {
            vec![]
        };

        Ok(AuthResponse {
            authenticated: true,
            user_info: UserInfo {
                username: username.to_string(),
                email: None,
                groups,
                metadata: HashMap::new(),
            },
            policies: vec!["default".to_string()],
            lease_duration: 3600, // 1 hour default
            renewable: true,
            token: session_token,
            accessor: format!("okta-creds-{}", username),
            metadata: HashMap::new(),
        })
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OktaUserInfo, Box<dyn std::error::Error + Send + Sync>> {
        let userinfo_url = format!("{}/oauth2/v1/userinfo", self.config.org_url);

        let response = self.http_client
            .get(&userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get user info: {}", response.status()).into());
        }

        let user_info: OktaUserInfo = response.json().await?;
        Ok(user_info)
    }

    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let api_token = self.config.api_token.as_ref()
            .ok_or("API token required for group lookup")?;

        let groups_url = format!("{}/api/v1/users/{}/groups", self.config.org_url, user_id);

        let response = self.http_client
            .get(&groups_url)
            .header("Authorization", format!("SSWS {}", api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get user groups: {}", response.status()).into());
        }

        let groups: Vec<OktaGroup> = response.json().await?;
        let group_names = groups
            .into_iter()
            .map(|g| g.profile.name)
            .collect();

        Ok(group_names)
    }

    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let introspect_url = format!("{}/oauth2/v1/introspect", self.config.org_url);

        let params = [
            ("token", token),
            ("token_type_hint", "access_token"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self.http_client
            .post(&introspect_url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(false);
        }

        let introspect_response: OktaIntrospectResponse = response.json().await?;
        Ok(introspect_response.active)
    }

    pub async fn revoke_token(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let revoke_url = format!("{}/oauth2/v1/revoke", self.config.org_url);

        let params = [
            ("token", token),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self.http_client
            .post(&revoke_url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Token revocation failed: {}", response.status()).into());
        }

        Ok(())
    }

    pub fn get_oauth_authorization_url(&self, state: &str) -> String {
        format!(
            "{}/oauth2/v1/authorize?client_id={}&response_type=code&scope=openid%20profile%20email%20groups&redirect_uri={}&state={}",
            self.config.org_url,
            self.config.client_id,
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(state)
        )
    }
}
