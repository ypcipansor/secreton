use crate::auth::traits::{AuthMethod, AuthResult};
use crate::error::CoreError;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuthConfig {
    /// JWT signing algorithm
    pub algorithm: String,
    /// JWT secret key (for HMAC algorithms)
    pub secret_key: Option<String>,
    /// JWT public key (for RSA/ECDSA algorithms)
    pub public_key: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Expected audience
    pub audience: Option<String>,
    /// Token TTL in seconds
    pub ttl: i64,
    /// Required claims
    pub required_claims: Vec<String>,
}

impl Default for JwtAuthConfig {
    fn default() -> Self {
        Self {
            algorithm: "HS256".to_string(),
            secret_key: None,
            public_key: None,
            issuer: None,
            audience: None,
            ttl: 3600,
            required_claims: vec!["sub".to_string()],
        }
    }
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub jti: Option<String>,
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// JWT authentication method
pub struct JwtAuth {
    config: JwtAuthConfig,
}

impl JwtAuth {
    /// Create new JWT authentication method
    pub fn new(config: JwtAuthConfig) -> Result<Self, CoreError> {
        // Validate configuration
        if config.secret_key.is_none() && config.public_key.is_none() {
            return Err(CoreError::configuration("Either secret_key or public_key must be provided"));
        }

        Ok(Self { config })
    }

    /// Get decoding key based on algorithm
    fn get_decoding_key(&self) -> Result<DecodingKey, CoreError> {
        match self.config.algorithm.as_str() {
            "HS256" | "HS384" | "HS512" => {
                let secret = self.config.secret_key.as_ref()
                    .ok_or_else(|| CoreError::configuration("Secret key required for HMAC algorithms"))?;
                Ok(DecodingKey::from_secret(secret.as_bytes()))
            }
            "RS256" | "RS384" | "RS512" | "ES256" | "ES384" => {
                let public_key = self.config.public_key.as_ref()
                    .ok_or_else(|| CoreError::configuration("Public key required for RSA/ECDSA algorithms"))?;
                DecodingKey::from_rsa_pem(public_key.as_bytes())
                    .map_err(|e| CoreError::configuration(format!("Invalid public key: {}", e)))
            }
            _ => Err(CoreError::configuration(format!("Unsupported algorithm: {}", self.config.algorithm))),
        }
    }

    /// Get algorithm
    fn get_algorithm(&self) -> Result<Algorithm, CoreError> {
        match self.config.algorithm.as_str() {
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            "HS512" => Ok(Algorithm::HS512),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            _ => Err(CoreError::configuration(format!("Unsupported algorithm: {}", self.config.algorithm))),
        }
    }

    /// Verify and decode JWT token
    fn verify_token(&self, token: &str) -> Result<JwtClaims, CoreError> {
        let decoding_key = self.get_decoding_key()?;
        let algorithm = self.get_algorithm()?;

        let mut validation = Validation::new(algorithm);
        
        if let Some(issuer) = &self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        
        if let Some(audience) = &self.config.audience {
            validation.set_audience(&[audience]);
        }

        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| CoreError::authentication(format!("Invalid JWT token: {}", e)))?;

        // Verify required claims
        for claim in &self.config.required_claims {
            if claim == "sub" && token_data.claims.sub.is_empty() {
                return Err(CoreError::authentication("Missing required claim: sub"));
            }
        }

        Ok(token_data.claims)
    }

    /// Extract policies from JWT claims
    fn extract_policies(&self, claims: &JwtClaims) -> Vec<String> {
        let mut policies = Vec::new();

        // Check for roles claim
        if let Some(roles) = claims.custom.get("roles") {
            if let Some(roles_array) = roles.as_array() {
                for role in roles_array {
                    if let Some(role_str) = role.as_str() {
                        policies.push(format!("jwt-role-{}", role_str));
                    }
                }
            }
        }

        // Check for groups claim
        if let Some(groups) = claims.custom.get("groups") {
            if let Some(groups_array) = groups.as_array() {
                for group in groups_array {
                    if let Some(group_str) = group.as_str() {
                        policies.push(format!("jwt-group-{}", group_str));
                    }
                }
            }
        }

        // Default policy if none found
        if policies.is_empty() {
            policies.push("jwt-default".to_string());
        }

        policies
    }
}

#[async_trait]
impl AuthMethod for JwtAuth {
    fn method_type(&self) -> &'static str {
        "jwt"
    }

    async fn authenticate(&self, credentials: HashMap<String, String>) -> Result<AuthResult, CoreError> {
        let token = credentials.get("token")
            .ok_or_else(|| CoreError::authentication("JWT token required"))?;

        // Verify and decode token
        let claims = self.verify_token(token)?;

        // Extract policies
        let policies = self.extract_policies(&claims);

        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert("jwt_sub".to_string(), claims.sub.clone());
        
        if let Some(iss) = &claims.iss {
            metadata.insert("jwt_iss".to_string(), iss.clone());
        }
        if let Some(jti) = &claims.jti {
            metadata.insert("jwt_jti".to_string(), jti.clone());
        }

        Ok(AuthResult {
            authenticated: true,
            user_id: claims.sub.clone(),
            username: claims.sub,
            policies,
            metadata,
            ttl: self.config.ttl,
        })
    }

    async fn validate_token(&self, token: &str) -> Result<bool, CoreError> {
        self.verify_token(token).map(|_| true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_config_default() {
        let config = JwtAuthConfig::default();
        assert_eq!(config.algorithm, "HS256");
        assert_eq!(config.ttl, 3600);
    }

    #[test]
    fn test_jwt_auth_creation_without_keys() {
        let config = JwtAuthConfig::default();
        let auth = JwtAuth::new(config);
        assert!(auth.is_err());
    }

    #[test]
    fn test_jwt_auth_creation_with_secret() {
        let mut config = JwtAuthConfig::default();
        config.secret_key = Some("test-secret".to_string());
        let auth = JwtAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_algorithm_parsing() {
        let mut config = JwtAuthConfig::default();
        config.secret_key = Some("test".to_string());
        config.algorithm = "HS256".to_string();
        let auth = JwtAuth::new(config).unwrap();
        assert!(auth.get_algorithm().is_ok());
    }
}
