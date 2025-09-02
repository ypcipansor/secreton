use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    pub kubernetes_host: String,
    pub kubernetes_ca_cert: Option<String>,
    pub service_account_token: Option<String>,
    pub disable_local_ca_jwt: bool,
    pub token_reviewer_jwt: Option<String>,
    pub issuer: Option<String>,
    pub audiences: Vec<String>,
    pub pem_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesRole {
    pub name: String,
    pub bound_service_account_names: Vec<String>,
    pub bound_service_account_namespaces: Vec<String>,
    pub audience: Option<String>,
    pub alias_name_source: String,
    pub token_ttl: i64,
    pub token_max_ttl: i64,
    pub token_policies: Vec<String>,
    pub token_bound_cidrs: Vec<String>,
    pub token_explicit_max_ttl: i64,
    pub token_no_default_policy: bool,
    pub token_num_uses: i32,
    pub token_period: i64,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct KubernetesServiceAccountToken {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub nbf: Option<i64>,
    pub jti: String,
    pub kubernetes: KubernetesClaims,
}

#[derive(Debug, Deserialize)]
struct KubernetesClaims {
    pub namespace: String,
    pub serviceaccount: ServiceAccountClaims,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountClaims {
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct TokenReviewRequest {
    pub apiVersion: String,
    pub kind: String,
    pub spec: TokenReviewSpec,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenReviewSpec {
    pub token: String,
    pub audiences: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct TokenReviewResponse {
    pub apiVersion: String,
    pub kind: String,
    pub status: TokenReviewStatus,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenReviewStatus {
    pub authenticated: bool,
    pub user: Option<TokenReviewUser>,
    pub audiences: Option<Vec<String>>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenReviewUser {
    pub username: String,
    pub uid: String,
    pub groups: Option<Vec<String>>,
    pub extra: Option<HashMap<String, Vec<String>>>,
}

pub struct KubernetesAuth {
    config: KubernetesConfig,
    http_client: Client,
    roles: HashMap<String, KubernetesRole>,
}

impl KubernetesAuth {
    pub fn new(config: KubernetesConfig) -> Self {
        let http_client = Client::new();
        Self {
            config,
            http_client,
            roles: HashMap::new(),
        }
    }

    pub async fn authenticate(
        &self,
        auth_request: &AuthRequest,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        match auth_request {
            AuthRequest::Kubernetes { jwt } => self.authenticate_jwt(jwt).await,
            _ => Err("Kubernetes authentication only supports JWT tokens".into()),
        }
    }

    async fn authenticate_jwt(
        &self,
        jwt: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        // First, try to validate JWT locally if we have the public keys
        if !self.config.pem_keys.is_empty() {
            match self.validate_jwt_locally(jwt).await {
                Ok((claims, role)) => {
                    return self.create_auth_response(&claims, &role);
                }
                Err(_) => {
                    // Fall back to token review if local validation fails
                }
            }
        }

        // Use TokenReview API to validate the token
        self.authenticate_via_token_review(jwt).await
    }

    async fn validate_jwt_locally(
        &self,
        jwt: &str,
    ) -> Result<
        (KubernetesServiceAccountToken, KubernetesRole),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        // Try each PEM key until one works
        for pem_key in &self.config.pem_keys {
            let decoding_key = DecodingKey::from_rsa_pem(pem_key.as_bytes())?;

            let validation = Validation::new(Algorithm::RS256);
            let mut validation = validation;

            // Set expected issuer if configured
            if let Some(issuer) = &self.config.issuer {
                validation.set_issuer(&[issuer]);
            }

            // Set expected audiences if configured
            if !self.config.audiences.is_empty() {
                validation.set_audience(&self.config.audiences);
            }

            match decode::<KubernetesServiceAccountToken>(jwt, &decoding_key, &validation) {
                Ok(token_data) => {
                    // Find matching role
                    for role in self.roles.values() {
                        if self.role_matches_claims(role, &token_data.claims) {
                            return Ok((token_data.claims, role.clone()));
                        }
                    }
                    return Err("No matching role found for service account".into());
                }
                Err(_) => continue,
            }
        }

        Err("Failed to validate JWT with any configured key".into())
    }

    async fn authenticate_via_token_review(
        &self,
        jwt: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        let token_review = TokenReviewRequest {
            apiVersion: "authentication.k8s.io/v1".to_string(),
            kind: "TokenReview".to_string(),
            spec: TokenReviewSpec {
                token: jwt.to_string(),
                audiences: Some(self.config.audiences.clone()),
            },
        };

        let url = format!(
            "{}/apis/authentication.k8s.io/v1/tokenreviews",
            self.config.kubernetes_host
        );

        let response = self
            .http_client
            .post(&url)
            .json(&token_review)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("TokenReview API request failed: {}", response.status()).into());
        }

        let token_review_response: TokenReviewResponse = response.json().await?;

        if !token_review_response.status.authenticated {
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

        let user = token_review_response
            .status
            .user
            .ok_or("TokenReview response missing user information")?;

        // Extract service account information from username
        // Kubernetes service account usernames are in format: system:serviceaccount:<namespace>:<name>
        let parts: Vec<&str> = user.username.split(':').collect();
        if parts.len() != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
            return Err("Invalid service account username format".into());
        }

        let namespace = parts[2].to_string();
        let service_account_name = parts[3].to_string();

        // Find matching role
        for role in self.roles.values() {
            if self.role_matches_service_account(role, &namespace, &service_account_name) {
                return self.create_auth_response_from_token_review(&user, role);
            }
        }

        Err("No matching role found for service account".into())
    }

    fn role_matches_claims(
        &self,
        role: &KubernetesRole,
        claims: &KubernetesServiceAccountToken,
    ) -> bool {
        // Check service account name
        if !role.bound_service_account_names.is_empty()
            && !role
                .bound_service_account_names
                .contains(&claims.kubernetes.serviceaccount.name)
        {
            return false;
        }

        // Check namespace
        if !role.bound_service_account_namespaces.is_empty()
            && !role
                .bound_service_account_namespaces
                .contains(&claims.kubernetes.namespace)
        {
            return false;
        }

        // Check audience if specified in role
        if let Some(role_audience) = &role.audience {
            if !claims.aud.contains(role_audience) {
                return false;
            }
        }

        true
    }

    fn role_matches_service_account(
        &self,
        role: &KubernetesRole,
        namespace: &str,
        service_account: &str,
    ) -> bool {
        // Check service account name
        if !role.bound_service_account_names.is_empty()
            && !role
                .bound_service_account_names
                .contains(&service_account.to_string())
        {
            return false;
        }

        // Check namespace
        if !role.bound_service_account_namespaces.is_empty()
            && !role
                .bound_service_account_namespaces
                .contains(&namespace.to_string())
        {
            return false;
        }

        true
    }

    fn create_auth_response(
        &self,
        claims: &KubernetesServiceAccountToken,
        role: &KubernetesRole,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        let username = format!(
            "system:serviceaccount:{}:{}",
            claims.kubernetes.namespace, claims.kubernetes.serviceaccount.name
        );

        let mut metadata = HashMap::new();
        metadata.insert(
            "service_account_name".to_string(),
            claims.kubernetes.serviceaccount.name.clone(),
        );
        metadata.insert(
            "service_account_namespace".to_string(),
            claims.kubernetes.namespace.clone(),
        );
        metadata.insert(
            "service_account_uid".to_string(),
            claims.kubernetes.serviceaccount.uid.clone(),
        );

        Ok(AuthResponse {
            authenticated: true,
            user_info: UserInfo {
                username: username.clone(),
                email: None,
                groups: vec![],
                metadata: metadata.clone(),
            },
            policies: role.token_policies.clone(),
            lease_duration: role.token_ttl,
            renewable: true,
            token: "".to_string(), // JWT is already validated
            accessor: format!("kubernetes-{}", claims.kubernetes.serviceaccount.uid),
            metadata,
        })
    }

    fn create_auth_response_from_token_review(
        &self,
        user: &TokenReviewUser,
        role: &KubernetesRole,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        let mut metadata = HashMap::new();
        metadata.insert("kubernetes_uid".to_string(), user.uid.clone());

        if let Some(groups) = &user.groups {
            metadata.insert("kubernetes_groups".to_string(), groups.join(","));
        }

        if let Some(extra) = &user.extra {
            for (key, values) in extra {
                metadata.insert(format!("kubernetes_extra_{}", key), values.join(","));
            }
        }

        Ok(AuthResponse {
            authenticated: true,
            user_info: UserInfo {
                username: user.username.clone(),
                email: None,
                groups: user.groups.clone().unwrap_or_default(),
                metadata: metadata.clone(),
            },
            policies: role.token_policies.clone(),
            lease_duration: role.token_ttl,
            renewable: true,
            token: "".to_string(),
            accessor: format!("kubernetes-{}", user.uid),
            metadata,
        })
    }

    pub fn add_role(&mut self, name: String, role: KubernetesRole) {
        self.roles.insert(name, role);
    }

    pub fn get_role(&self, name: &str) -> Option<&KubernetesRole> {
        self.roles.get(name)
    }

    pub fn list_roles(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }

    pub fn remove_role(&mut self, name: &str) -> bool {
        self.roles.remove(name).is_some()
    }

    pub async fn validate_service_account(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Check if the service account exists in Kubernetes
        let url = format!(
            "{}/api/v1/namespaces/{}/serviceaccounts/{}",
            self.config.kubernetes_host, namespace, service_account
        );

        let response = self.http_client.get(&url).send().await?;

        Ok(response.status().is_success())
    }

    pub async fn get_service_account_info(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/api/v1/namespaces/{}/serviceaccounts/{}",
            self.config.kubernetes_host, namespace, service_account
        );

        let response = self.http_client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(
                format!("Failed to get service account info: {}", response.status()).into(),
            );
        }

        #[derive(Deserialize)]
        struct ServiceAccountResponse {
            metadata: ServiceAccountMetadata,
        }

        #[derive(Deserialize)]
        #[allow(non_snake_case)]
        struct ServiceAccountMetadata {
            uid: String,
            creationTimestamp: String,
            labels: Option<HashMap<String, String>>,
            annotations: Option<HashMap<String, String>>,
        }

        let sa_response: ServiceAccountResponse = response.json().await?;

        let mut info = HashMap::new();
        info.insert("uid".to_string(), sa_response.metadata.uid);
        info.insert(
            "creation_timestamp".to_string(),
            sa_response.metadata.creationTimestamp,
        );

        if let Some(labels) = sa_response.metadata.labels {
            for (key, value) in labels {
                info.insert(format!("label_{}", key), value);
            }
        }

        if let Some(annotations) = sa_response.metadata.annotations {
            for (key, value) in annotations {
                info.insert(format!("annotation_{}", key), value);
            }
        }

        Ok(info)
    }
}
