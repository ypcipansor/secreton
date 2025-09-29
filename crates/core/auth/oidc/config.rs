// OIDC Authentication Configuration
// Support for Auth0, Okta, Azure AD, and other OpenID Connect providers

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// OIDC Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Provider name (auth0, okta, azure_ad, custom)
    pub provider_name: String,

    /// OIDC Discovery URL (e.g., https://example.auth0.com/.well-known/openid_configuration)
    pub discovery_url: Url,

    /// Client ID for OIDC application
    pub client_id: String,

    /// Client Secret (optional for public clients)
    pub client_secret: Option<String>,

    /// Required scopes (default: openid, profile, email)
    pub scopes: Vec<String>,

    /// Claims to policy mapping
    pub claims_mapping: ClaimsMapping,

    /// JWT validation settings
    pub jwt_validation: JwtValidationConfig,

    /// User provisioning settings
    pub user_provisioning: UserProvisioningConfig,

    /// Cache settings for OIDC discovery and JWKS
    pub cache_settings: CacheSettings,

    /// Provider-specific settings
    pub provider_settings: HashMap<String, serde_json::Value>,
}

/// Claims to Vault policies mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsMapping {
    /// User identifier claim (default: sub)
    pub user_id_claim: String,

    /// Username claim (default: preferred_username or email)
    pub username_claim: String,

    /// Email claim (default: email)
    pub email_claim: String,

    /// Groups claim for policy assignment
    pub groups_claim: Option<String>,

    /// Role claim for policy assignment
    pub role_claim: Option<String>,

    /// Custom claims mapping to metadata
    pub custom_claims: HashMap<String, String>,

    /// Default policies for all authenticated users
    pub default_policies: Vec<String>,

    /// Group to policies mapping
    pub group_policies: HashMap<String, Vec<String>>,

    /// Role to policies mapping  
    pub role_policies: HashMap<String, Vec<String>>,
}

/// JWT token validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtValidationConfig {
    /// Validate token expiration
    pub validate_exp: bool,

    /// Validate token not-before
    pub validate_nbf: bool,

    /// Validate audience
    pub validate_aud: bool,

    /// Expected audience values
    pub audiences: Vec<String>,

    /// Clock skew allowance in seconds
    pub clock_skew: u64,

    /// Maximum token age in seconds
    pub max_age: Option<u64>,

    /// Required algorithms (default: RS256, ES256)
    pub algorithms: Vec<String>,
}

/// User provisioning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProvisioningConfig {
    /// Enable automatic user creation
    pub auto_create_users: bool,

    /// Enable user attribute updates on login
    pub update_user_attributes: bool,

    /// Default user TTL in seconds
    pub default_user_ttl: Option<u64>,

    /// User metadata fields to extract from claims
    pub user_metadata_fields: Vec<String>,

    /// Enable user deactivation when not in groups
    pub enable_user_deactivation: bool,
}

/// Cache configuration for OIDC operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSettings {
    /// OIDC discovery cache TTL in seconds (default: 3600)
    pub discovery_cache_ttl: u64,

    /// JWKS cache TTL in seconds (default: 3600)
    pub jwks_cache_ttl: u64,

    /// User cache TTL in seconds (default: 300)
    pub user_cache_ttl: u64,

    /// Maximum cache size for JWKS
    pub max_jwks_cache_size: usize,

    /// Enable cache compression
    pub enable_compression: bool,
}

/// OIDC Discovery document structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Option<Vec<String>>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            provider_name: "generic".to_string(),
            discovery_url: Url::parse("https://example.com/.well-known/openid_configuration")
                .unwrap(),
            client_id: String::new(),
            client_secret: None,
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            claims_mapping: ClaimsMapping::default(),
            jwt_validation: JwtValidationConfig::default(),
            user_provisioning: UserProvisioningConfig::default(),
            cache_settings: CacheSettings::default(),
            provider_settings: HashMap::new(),
        }
    }
}

impl Default for ClaimsMapping {
    fn default() -> Self {
        Self {
            user_id_claim: "sub".to_string(),
            username_claim: "preferred_username".to_string(),
            email_claim: "email".to_string(),
            groups_claim: Some("groups".to_string()),
            role_claim: Some("role".to_string()),
            custom_claims: HashMap::new(),
            default_policies: vec!["default".to_string()],
            group_policies: HashMap::new(),
            role_policies: HashMap::new(),
        }
    }
}

impl Default for JwtValidationConfig {
    fn default() -> Self {
        Self {
            validate_exp: true,
            validate_nbf: true,
            validate_aud: false,
            audiences: vec![],
            clock_skew: 60,      // 1 minute
            max_age: Some(3600), // 1 hour
            algorithms: vec!["RS256".to_string(), "ES256".to_string()],
        }
    }
}

impl Default for UserProvisioningConfig {
    fn default() -> Self {
        Self {
            auto_create_users: true,
            update_user_attributes: true,
            default_user_ttl: Some(86400), // 24 hours
            user_metadata_fields: vec![
                "name".to_string(),
                "email".to_string(),
                "picture".to_string(),
                "locale".to_string(),
            ],
            enable_user_deactivation: false,
        }
    }
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            discovery_cache_ttl: 3600, // 1 hour
            jwks_cache_ttl: 3600,      // 1 hour
            user_cache_ttl: 300,       // 5 minutes
            max_jwks_cache_size: 100,
            enable_compression: true,
        }
    }
}

impl OidcConfig {
    /// Create Auth0 provider configuration
    pub fn auth0(domain: &str, client_id: &str, client_secret: Option<&str>) -> Result<Self> {
        let discovery_url = Url::parse(&format!(
            "https://{}/.well-known/openid_configuration",
            domain
        ))?;

        let mut config = Self::default();
        config.provider_name = "auth0".to_string();
        config.discovery_url = discovery_url;
        config.client_id = client_id.to_string();
        config.client_secret = client_secret.map(|s| s.to_string());
        config.scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ];
        config.jwt_validation.validate_aud = true;
        config.jwt_validation.audiences.push(client_id.to_string());

        // Auth0 specific claims mapping
        config.claims_mapping.username_claim = "nickname".to_string();
        config.claims_mapping.groups_claim = Some("https://vault.example.com/groups".to_string());

        Ok(config)
    }

    /// Create Okta provider configuration
    pub fn okta(domain: &str, client_id: &str, client_secret: Option<&str>) -> Result<Self> {
        let discovery_url = Url::parse(&format!(
            "https://{}/.well-known/openid_configuration",
            domain
        ))?;

        let mut config = Self::default();
        config.provider_name = "okta".to_string();
        config.discovery_url = discovery_url;
        config.client_id = client_id.to_string();
        config.client_secret = client_secret.map(|s| s.to_string());
        config.jwt_validation.validate_aud = true;
        config.jwt_validation.audiences.push(client_id.to_string());

        // Okta specific claims mapping
        config.claims_mapping.groups_claim = Some("groups".to_string());
        config.claims_mapping.role_claim = Some("role".to_string());

        Ok(config)
    }

    /// Create Azure AD provider configuration
    pub fn azure_ad(tenant_id: &str, client_id: &str, client_secret: Option<&str>) -> Result<Self> {
        let discovery_url = Url::parse(&format!(
            "https://login.microsoftonline.com/{}/v2.0/.well-known/openid_configuration",
            tenant_id
        ))?;

        let mut config = Self::default();
        config.provider_name = "azure_ad".to_string();
        config.discovery_url = discovery_url;
        config.client_id = client_id.to_string();
        config.client_secret = client_secret.map(|s| s.to_string());

        // Azure AD specific claims mapping
        config.claims_mapping.username_claim = "unique_name".to_string();
        config.claims_mapping.groups_claim = Some("groups".to_string());
        config.claims_mapping.role_claim = Some("roles".to_string());

        // Azure AD requires audience validation
        config.jwt_validation.validate_aud = true;
        config.jwt_validation.audiences.push(client_id.to_string());

        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(anyhow!("Client ID is required"));
        }

        if self.scopes.is_empty() {
            return Err(anyhow!("At least one scope is required"));
        }

        if !self.scopes.contains(&"openid".to_string()) {
            return Err(anyhow!("'openid' scope is required for OIDC"));
        }

        if self.jwt_validation.validate_aud && self.jwt_validation.audiences.is_empty() {
            return Err(anyhow!(
                "Audiences must be specified when audience validation is enabled"
            ));
        }

        if self.jwt_validation.algorithms.is_empty() {
            return Err(anyhow!("At least one JWT algorithm must be specified"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth0_config() {
        let config = OidcConfig::auth0("example.auth0.com", "client123", Some("secret")).unwrap();
        assert_eq!(config.provider_name, "auth0");
        assert_eq!(config.client_id, "client123");
        assert_eq!(config.client_secret, Some("secret".to_string()));
        assert!(config.discovery_url.as_str().contains("example.auth0.com"));
        assert!(config.jwt_validation.validate_aud);
        assert!(config
            .jwt_validation
            .audiences
            .contains(&"client123".to_string()));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_auth0_public_client_without_secret() {
        let config = OidcConfig::auth0("example.auth0.com", "public-client", None).unwrap();
        assert_eq!(config.client_secret, None);
        assert!(config.jwt_validation.validate_aud);
        assert!(config
            .jwt_validation
            .audiences
            .contains(&"public-client".to_string()));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_okta_config() {
        let config = OidcConfig::okta("dev-123.okta.com", "client456", None).unwrap();
        assert_eq!(config.provider_name, "okta");
        assert_eq!(config.client_id, "client456");
        assert_eq!(config.client_secret, None);
        assert!(config.jwt_validation.validate_aud);
        assert!(config
            .jwt_validation
            .audiences
            .contains(&"client456".to_string()));
        assert_eq!(
            config.claims_mapping.groups_claim.as_deref(),
            Some("groups")
        );
        assert_eq!(config.claims_mapping.role_claim.as_deref(), Some("role"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_okta_with_secret() {
        let config = OidcConfig::okta("dev-123.okta.com", "client456", Some("secret")).unwrap();
        assert_eq!(config.client_secret, Some("secret".to_string()));
        assert!(config.jwt_validation.validate_aud);
        assert!(config
            .jwt_validation
            .audiences
            .contains(&"client456".to_string()));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_azure_ad_config() {
        let config = OidcConfig::azure_ad("tenant-123", "app-456", Some("secret")).unwrap();
        assert_eq!(config.provider_name, "azure_ad");
        assert_eq!(config.client_id, "app-456");
        assert!(config
            .jwt_validation
            .audiences
            .contains(&"app-456".to_string()));
        assert_eq!(config.claims_mapping.username_claim, "unique_name");
        assert_eq!(
            config.claims_mapping.groups_claim.as_deref(),
            Some("groups")
        );
        assert_eq!(config.claims_mapping.role_claim.as_deref(), Some("roles"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_azure_ad_without_secret() {
        let config = OidcConfig::azure_ad("tenant-123", "app-456", None).unwrap();
        assert_eq!(config.client_secret, None);
        assert!(config.jwt_validation.validate_aud);
        assert!(config
            .jwt_validation
            .audiences
            .contains(&"app-456".to_string()));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = OidcConfig::default();

        // Should fail with empty client_id
        assert!(config.validate().is_err());

        config.client_id = "test".to_string();
        config.scopes.clear();

        // Should fail with empty scopes
        assert!(config.validate().is_err());

        config.scopes.push("profile".to_string());

        // Should fail without openid scope
        assert!(config.validate().is_err());

        config.scopes.push("openid".to_string());

        // Should pass
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_fails_without_algorithms() {
        let mut config = OidcConfig::default();
        config.client_id = "client-without-algorithm".to_string();
        config.jwt_validation.algorithms.clear();
        assert!(config.validate().is_err());

        config.jwt_validation.algorithms.push("RS256".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_fails_without_scopes() {
        let mut config = OidcConfig::default();
        config.client_id = "client-without-scopes".to_string();
        config.scopes.clear();
        assert!(config.validate().is_err());

        config.scopes.push("openid".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_requires_audience_when_enabled() {
        let mut config = OidcConfig::default();
        config.client_id = "client789".to_string();
        config.jwt_validation.validate_aud = true;

        // Default config has openid scope
        assert!(config.validate().is_err());

        config
            .jwt_validation
            .audiences
            .push("client789".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_custom_provider_without_audience_validation() {
        let mut config = OidcConfig::default();
        config.provider_name = "custom".to_string();
        config.client_id = "custom-client".to_string();

        // validate_aud defaults to false, should succeed without audiences
        assert!(config.validate().is_ok());

        // Enabling validation without audiences should fail
        config.jwt_validation.validate_aud = true;
        assert!(config.validate().is_err());

        // Provide an audience to recover
        config
            .jwt_validation
            .audiences
            .push("custom-client".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_user_provisioning_disable_user_deactivation() {
        let mut provisioning = UserProvisioningConfig::default();
        provisioning.enable_user_deactivation = true;
        assert!(provisioning.enable_user_deactivation);

        provisioning.enable_user_deactivation = false;
        assert!(!provisioning.enable_user_deactivation);
    }

    #[test]
    fn test_cache_settings_customization() {
        let mut cache = CacheSettings::default();
        cache.discovery_cache_ttl = 1800;
        cache.jwks_cache_ttl = 7200;
        cache.user_cache_ttl = 120;
        cache.max_jwks_cache_size = 10;
        cache.enable_compression = false;

        assert_eq!(cache.discovery_cache_ttl, 1800);
        assert_eq!(cache.jwks_cache_ttl, 7200);
        assert_eq!(cache.user_cache_ttl, 120);
        assert_eq!(cache.max_jwks_cache_size, 10);
        assert!(!cache.enable_compression);
    }

    #[test]
    fn test_claims_mapping_default_values() {
        let mapping = ClaimsMapping::default();
        assert_eq!(mapping.user_id_claim, "sub");
        assert_eq!(mapping.username_claim, "preferred_username");
        assert_eq!(mapping.email_claim, "email");
        assert_eq!(mapping.groups_claim.as_deref(), Some("groups"));
        assert_eq!(mapping.role_claim.as_deref(), Some("role"));
        assert!(mapping.custom_claims.is_empty());
        assert_eq!(mapping.default_policies, vec!["default".to_string()]);
        assert!(mapping.group_policies.is_empty());
        assert!(mapping.role_policies.is_empty());
    }

    #[test]
    fn test_cache_settings_default_values() {
        let cache = CacheSettings::default();
        assert_eq!(cache.discovery_cache_ttl, 3600);
        assert_eq!(cache.jwks_cache_ttl, 3600);
        assert_eq!(cache.user_cache_ttl, 300);
        assert_eq!(cache.max_jwks_cache_size, 100);
        assert!(cache.enable_compression);
    }

    #[test]
    fn test_user_provisioning_default_values() {
        let provisioning = UserProvisioningConfig::default();
        assert!(provisioning.auto_create_users);
        assert!(provisioning.update_user_attributes);
        assert_eq!(provisioning.default_user_ttl, Some(86400));
        assert!(provisioning
            .user_metadata_fields
            .contains(&"name".to_string()));
        assert!(provisioning
            .user_metadata_fields
            .contains(&"email".to_string()));
        assert!(!provisioning.enable_user_deactivation);
    }
}
