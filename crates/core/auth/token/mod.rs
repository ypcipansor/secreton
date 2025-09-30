use super::{AuthMethod, AuthResult, Credentials, TokenInfo};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, error, info};
use uuid::Uuid;

/// Token authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// JWT signing secret
    pub jwt_secret: String,
    /// Token TTL in seconds
    pub token_ttl: i64,
    /// Whether tokens are renewable
    pub renewable: bool,
    /// Maximum token age in seconds (for token validation)
    pub max_token_age: Option<i64>,
}

/// Claims embedded in JWT tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user identifier)
    pub sub: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Token ID for tracking
    pub jti: String,
    /// Token type (access/refresh)
    pub token_type: String,
    /// Associated policies
    pub policies: Vec<String>,
    /// User metadata
    pub metadata: HashMap<String, String>,
    /// Whether MFA was verified
    pub mfa_verified: bool,
}

/// Token authentication method
pub struct TokenAuth {
    config: TokenConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl TokenAuth {
    /// Create new token authentication method
    pub fn new(config: TokenConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_ref());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_ref());

        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    /// Generate a new token for a user
    pub fn generate_token(
        &self,
        username: &str,
        policies: Vec<String>,
        metadata: HashMap<String, String>,
        token_type: &str,
        mfa_verified: bool,
    ) -> Result<String, anyhow::Error> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.token_ttl);

        let claims = TokenClaims {
            sub: username.to_string(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: token_type.to_string(),
            policies,
            metadata,
            mfa_verified,
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;

        info!("Generated {} token for user: {}", token_type, username);
        Ok(token)
    }

    /// Validate and decode a token
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, anyhow::Error> {
        let validation = Validation::default();
        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)?;

        let claims = token_data.claims;

        // Check if token is expired
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(anyhow!("Token has expired"));
        }

        // Check maximum token age if configured
        if let Some(max_age) = self.config.max_token_age {
            if now - claims.iat > max_age {
                return Err(anyhow!("Token is too old"));
            }
        }

        debug!("Token validated successfully for user: {}", claims.sub);
        Ok(claims)
    }

    /// Create token information from claims
    fn create_token_info(&self, claims: &TokenClaims) -> TokenInfo {
        TokenInfo {
            id: claims.jti.clone(),
            policies: claims.policies.clone(),
            metadata: claims.metadata.clone(),
            ttl: Some(self.config.token_ttl as u64),
            renewable: self.config.renewable,
            entity_id: Some(format!("token-entity-{}", claims.sub)),
        }
    }
}

#[async_trait]
impl AuthMethod for TokenAuth {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResult, anyhow::Error> {
        debug!("Starting token authentication");

        // Extract token from credentials
        let token = match credentials {
            Credentials::Token { token } => token,
            _ => {
                error!("Invalid credential type for token authentication");
                return Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some("Invalid token credentials".to_string()),
                });
            }
        };

        // Validate the token
        let claims = match self.validate_token(token) {
            Ok(claims) => claims,
            Err(e) => {
                error!("Token validation failed: {}", e);
                return Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some(format!("Invalid token: {}", e)),
                });
            }
        };

        // Create user info from token claims
        let mut user_info = HashMap::new();
        user_info.insert("username".to_string(), Value::String(claims.sub.clone()));
        user_info.insert(
            "token_type".to_string(),
            Value::String(claims.token_type.clone()),
        );
        user_info.insert(
            "mfa_verified".to_string(),
            Value::String(claims.mfa_verified.to_string()),
        );

        for (key, value) in &claims.metadata {
            user_info.insert(format!("token_{}", key), Value::String(value.clone()));
        }

        // Create token info
        let token_info = self.create_token_info(&claims);

        info!("Token authentication successful for user: {}", claims.sub);

        Ok(AuthResult {
            success: true,
            token: Some(token_info),
            user_info: Some(user_info),
            policies: claims.policies,
            metadata: claims.metadata,
            error: None,
        })
    }

    async fn validate_config(&self, _config: &Value) -> Result<(), anyhow::Error> {
        // Token authentication doesn't require external service validation
        // Configuration is validated during TokenAuth creation
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<String>, anyhow::Error> {
        // Token authentication doesn't maintain a user list
        // Users are identified by the tokens they present
        Ok(vec![])
    }

    async fn create_user(&self, _username: &str, _config: &Value) -> Result<(), anyhow::Error> {
        // Token authentication doesn't support user creation
        Err(anyhow::anyhow!(
            "User creation not supported for token authentication"
        ))
    }

    async fn delete_user(&self, _username: &str) -> Result<(), anyhow::Error> {
        // Token authentication doesn't support user deletion
        Err(anyhow::anyhow!(
            "User deletion not supported for token authentication"
        ))
    }

    fn name(&self) -> &'static str {
        "token"
    }

    fn description(&self) -> &'static str {
        "Token-based authentication using JWT tokens"
    }

    fn supports_mfa(&self) -> bool {
        true // Token auth can include MFA claims
    }
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "your-secret-key-change-in-production".to_string(),
            token_ttl: 3600, // 1 hour
            renewable: true,
            max_token_age: Some(86400 * 7), // 7 days
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_config_default() {
        let config = TokenConfig::default();
        assert_eq!(config.token_ttl, 3600);
        assert!(config.renewable);
        assert_eq!(config.max_token_age, Some(86400 * 7));
    }

    #[test]
    fn test_token_auth_creation() {
        let config = TokenConfig::default();
        let token_auth = TokenAuth::new(config);

        assert_eq!(token_auth.name(), "token");
        assert_eq!(
            token_auth.description(),
            "Token-based authentication using JWT tokens"
        );
        assert!(token_auth.supports_mfa());
    }

    #[tokio::test]
    async fn test_token_generation_and_validation() {
        let config = TokenConfig::default();
        let token_auth = TokenAuth::new(config);

        // Generate a token
        let token = token_auth
            .generate_token(
                "testuser",
                vec!["default".to_string()],
                HashMap::new(),
                "access",
                false,
            )
            .unwrap();

        // Validate the token
        let claims = token_auth.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "testuser");
        assert_eq!(claims.token_type, "access");
        assert_eq!(claims.policies, vec!["default"]);
    }

    #[tokio::test]
    async fn test_token_authentication() {
        let config = TokenConfig::default();
        let token_auth = TokenAuth::new(config);

        // Generate a token
        let token = token_auth
            .generate_token(
                "testuser",
                vec!["default".to_string()],
                HashMap::from([("role".to_string(), "admin".to_string())]),
                "access",
                true,
            )
            .unwrap();

        // Test authentication with token credentials
        let credentials = Credentials::Token {
            token: token.clone(),
        };

        let result = token_auth.authenticate(&credentials).await.unwrap();
        assert!(result.success);
        assert!(result.token.is_some());
        assert_eq!(result.policies, vec!["default"]);

        // Check user info
        let user_info = result.user_info.unwrap();
        assert_eq!(user_info["username"], "testuser");
        assert_eq!(user_info["token_type"], "access");
        assert_eq!(user_info["mfa_verified"], "true");
        assert_eq!(user_info["token_role"], "admin");
    }

    #[tokio::test]
    async fn test_invalid_token_authentication() {
        let config = TokenConfig::default();
        let token_auth = TokenAuth::new(config);

        // Test with invalid credentials type
        let credentials = Credentials::Password {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let result = token_auth.authenticate(&credentials).await.unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(result.error.unwrap(), "Invalid token credentials");
    }

    #[tokio::test]
    async fn test_expired_token() {
        let mut config = TokenConfig::default();
        config.token_ttl = -3600; // Expired token
        let token_auth = TokenAuth::new(config);

        // Generate an expired token
        let token = token_auth
            .generate_token(
                "testuser",
                vec!["default".to_string()],
                HashMap::new(),
                "access",
                false,
            )
            .unwrap();

        // Try to validate expired token
        let result = token_auth.validate_token(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }
}
