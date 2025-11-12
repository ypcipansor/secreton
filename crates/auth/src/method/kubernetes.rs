//! Kubernetes authentication method

use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use k8s_openapi::api::authentication::v1::TokenReview;
use k8s_openapi::api::core::v1::ServiceAccount;
use kube::{Api, Client, Config};
use std::collections::HashMap;

/// Kubernetes authentication method
pub struct KubernetesAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    k8s_config: Option<KubernetesConfig>,
    client: Option<Client>,
}

impl KubernetesAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            k8s_config: None,
            client: None,
        }
    }

    /// Set Kubernetes configuration
    pub fn set_k8s_config(&mut self, config: KubernetesConfig) {
        self.k8s_config = Some(config);
    }

    /// Initialize Kubernetes client
    async fn init_client(&mut self) -> AuthMethodResult<()> {
        if self.client.is_none() {
            let config = Config::incluster().map_err(|e| {
                SecretonError::KubernetesError(format!("Failed to load incluster config: {}", e))
            })?;

            let client = Client::try_from(config).map_err(|e| {
                SecretonError::KubernetesError(format!("Failed to create client: {}", e))
            })?;

            self.client = Some(client);
        }
        Ok(())
    }

    /// Validate JWT token with Kubernetes API
    async fn validate_jwt(&self, jwt: &str) -> AuthMethodResult<TokenReviewResult> {
        self.init_client().await?;

        let client = self
            .client
            .as_ref()
            .ok_or(SecretonError::ConfigurationError(
                "Kubernetes client not initialized".to_string(),
            ))?;

        let token_review = TokenReview {
            spec: k8s_openapi::api::authentication::v1::TokenReviewSpec {
                token: Some(jwt.to_string()),
                audiences: Some(vec![
                    "https://kubernetes.default.svc.cluster.local".to_string(),
                ]),
            },
            ..Default::default()
        };

        let api: Api<TokenReview> = Api::all(client.to_string());
        let review = api
            .create(&Default::default(), &token_review)
            .await
            .map_err(|e| SecretonError::KubernetesError(format!("Token review failed: {}", e)))?;

        if let Some(status) = review.status {
            if status.authenticated.unwrap_or(false) {
                Ok(TokenReviewResult {
                    authenticated: true,
                    user: status.user,
                })
            } else {
                Err(SecretonError::InvalidCredentials)
            }
        } else {
            Err(SecretonError::KubernetesError(
                "No status in token review response".to_string(),
            ))
        }
    }

    /// Get service account information
    async fn get_service_account_info(
        &self,
        namespace: &str,
        service_account_name: &str,
    ) -> AuthMethodResult<ServiceAccountInfo> {
        self.init_client().await?;

        let client = self
            .client
            .as_ref()
            .ok_or(SecretonError::ConfigurationError(
                "Kubernetes client not initialized".to_string(),
            ))?;

        let api: Api<ServiceAccount> = Api::namespaced(client.to_string(), namespace);
        let sa = api.get(service_account_name).await.map_err(|e| {
            SecretonError::KubernetesError(format!("Failed to get service account: {}", e))
        })?;

        let labels = sa.metadata.labels.unwrap_or_default();
        let annotations = sa.metadata.annotations.unwrap_or_default();

        Ok(ServiceAccountInfo {
            name: service_account_name.to_string(),
            namespace: namespace.to_string(),
            labels,
            annotations,
        })
    }
}

#[async_trait]
impl AuthMethodImpl for KubernetesAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Kubernetes
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.to_string());

        // Parse Kubernetes configuration from config
        let k8s_config = KubernetesConfig {
            kubernetes_host: config
                .config
                .get("kubernetes_host")
                .or_else(|| config.config.get("host"))
                .cloned()
                .unwrap_or_else(|| "https://kubernetes.default.svc".to_string()),
            kubernetes_ca_cert: config
                .config
                .get("kubernetes_ca_cert")
                .or_else(|| config.config.get("ca_cert"))
                .cloned(),
            token_reviewer_jwt: config.config.get("token_reviewer_jwt").cloned(),
            pem_keys: config
                .config
                .get("pem_keys")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                }),
            issuer: config.config.get("issuer").cloned(),
            disable_iss_validation: config
                .config
                .get("disable_iss_validation")
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            disable_local_ca_jwt: config
                .config
                .get("disable_local_ca_jwt")
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
        };
        self.set_k8s_config(k8s_config);

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(SecretonError::MethodDisabled);
        }

        match credentials {
            AuthCredentials::Kubernetes { jwt } => {
                let token_review = self.validate_jwt(jwt).await?;

                if let Some(user) = token_review.user {
                    // Extract service account info from username
                    // Kubernetes service account usernames are in format: system:serviceaccount:<namespace>:<name>
                    let username = user.username;
                    let user_id = username.to_string();

                    let (namespace, service_account) =
                        if username.starts_with("system:serviceaccount:") {
                            let parts: Vec<&str> = username.split(':').collect();
                            if parts.len() >= 4 {
                                (parts[2].to_string(), parts[3].to_string())
                            } else {
                                ("default".to_string(), username.to_string())
                            }
                        } else {
                            ("default".to_string(), username.to_string())
                        };

                    // Get service account details
                    let sa_info = self
                        .get_service_account_info(&namespace, &service_account)
                        .await
                        .unwrap_or_else(|_| ServiceAccountInfo {
                            name: service_account.to_string(),
                            namespace: namespace.to_string(),
                            labels: HashMap::new(),
                            annotations: HashMap::new(),
                        });

                    let user_info = UserInfo {
                        username,
                        user_id,
                        groups: user.groups.unwrap_or_default(),
                        metadata: HashMap::new(),
                    };

                    Ok(AuthResult {
                        authenticated: true,
                        user_info: Some(user_info),
                        token: None,
                        mfa_required: false,
                        policies: vec![], // Policies would be determined by service account labels/annotations
                        lease_duration: None,
                        renewable: Some(true),
                        metadata: HashMap::new(),
                    })
                } else {
                    Err(SecretonError::InvalidCredentials)
                }
            }
            _ => Err(SecretonError::InvalidCredentials),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(SecretonError::MethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(SecretonError::MethodNotSupported)
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

/// Kubernetes configuration
#[derive(Clone, Debug)]
pub struct KubernetesConfig {
    pub host: String,
    pub ca_cert: Option<String>,
    pub token_reviewer_jwt: Option<String>,
    pub kubernetes_host: Option<String>,
    pub disable_local_ca_jwt: bool,
}

/// Token review result
#[derive(Clone, Debug)]
pub struct TokenReviewResult {
    pub authenticated: bool,
    pub user: Option<k8s_openapi::api::authentication::v1::UserInfo>,
}

/// Service account information
#[derive(Clone, Debug)]
pub struct ServiceAccountInfo {
    pub name: String,
    pub namespace: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}
