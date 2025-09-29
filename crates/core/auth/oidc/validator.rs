// OIDC JWT Token Validator
// Handles JWT validation, OIDC discovery, and JWKS management

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};

use super::config::{OidcConfig, OidcDiscovery};

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Standard JWT claims
    pub iss: String, // Issuer
    pub sub: String,            // Subject
    pub aud: serde_json::Value, // Audience (can be string or array)
    pub exp: u64,               // Expiration time
    pub iat: u64,               // Issued at
    pub nbf: Option<u64>,       // Not before
    pub jti: Option<String>,    // JWT ID

    /// OIDC standard claims
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,

    /// Custom claims (for groups, roles, etc.)
    #[serde(flatten)]
    pub custom_claims: HashMap<String, Value>,
}

/// JWKS (JSON Web Key Set) structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JWK (JSON Web Key) structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,                  // Key Type
    pub use_: Option<String>,         // Public Key Use
    pub key_ops: Option<Vec<String>>, // Key Operations
    pub alg: Option<String>,          // Algorithm
    pub kid: Option<String>,          // Key ID
    pub x5u: Option<String>,          // X.509 URL
    pub x5c: Option<Vec<String>>,     // X.509 Certificate Chain
    pub x5t: Option<String>,          // X.509 Thumbprint

    // RSA Key parameters
    pub n: Option<String>, // Modulus
    pub e: Option<String>, // Exponent

    // EC Key parameters
    pub crv: Option<String>, // Curve
    pub x: Option<String>,   // X Coordinate
    pub y: Option<String>,   // Y Coordinate

    // Symmetric key
    pub k: Option<String>, // Key Value
}

/// Cached OIDC data
#[derive(Debug, Clone)]
struct CachedDiscovery {
    discovery: OidcDiscovery,
    cached_at: SystemTime,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    jwks: Jwks,
    cached_at: SystemTime,
    ttl: Duration,
}

/// JWT Token validation result
#[derive(Debug)]
pub struct ValidationResult {
    pub claims: JwtClaims,
    pub header: Header,
    pub is_valid: bool,
    pub validation_errors: Vec<String>,
}

/// OIDC JWT Validator
pub struct OidcValidator {
    config: OidcConfig,
    http_client: Client,
    discovery_cache: Arc<RwLock<Option<CachedDiscovery>>>,
    jwks_cache: Arc<RwLock<Option<CachedJwks>>>,
}

impl OidcValidator {
    /// Create a new OIDC validator
    pub fn new(config: OidcConfig) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            discovery_cache: Arc::new(RwLock::new(None)),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Validate JWT token
    pub async fn validate_token(&self, token: &str) -> Result<ValidationResult> {
        debug!("Starting JWT token validation");

        let mut validation_errors = Vec::new();

        // Decode header to get key ID
        let header = decode_header(token).context("Failed to decode JWT header")?;

        debug!("Token header: {:?}", header);

        // Get OIDC discovery document
        let discovery = self
            .get_discovery()
            .await
            .context("Failed to get OIDC discovery document")?;

        // Get JWKS
        let jwks = self
            .get_jwks(&discovery.jwks_uri)
            .await
            .context("Failed to get JWKS")?;

        // Find the right key
        let key = self
            .find_key(&jwks, &header)
            .context("Failed to find matching key in JWKS")?;

        // Create validation settings
        let mut validation = self.create_validation_settings()?;

        // Set the issuer from discovery
        validation.iss = Some({
            let mut set = std::collections::HashSet::new();
            set.insert(discovery.issuer.clone());
            set
        });

        // Decode and validate token
        let token_data = match decode::<JwtClaims>(token, &key, &validation) {
            Ok(data) => data,
            Err(e) => {
                validation_errors.push(format!("JWT validation failed: {}", e));

                // Try to decode without validation to get claims for analysis
                let mut no_validation = Validation::default();
                no_validation.insecure_disable_signature_validation();
                no_validation.validate_exp = false;
                no_validation.validate_nbf = false;
                no_validation.validate_aud = false;

                let unsafe_data = decode::<JwtClaims>(token, &key, &no_validation)
                    .context("Failed to decode token even without validation")?;

                return Ok(ValidationResult {
                    claims: unsafe_data.claims,
                    header,
                    is_valid: false,
                    validation_errors,
                });
            }
        };

        // Additional custom validations
        if let Err(e) = self.validate_custom_claims(&token_data.claims) {
            validation_errors.push(format!("Custom claims validation failed: {}", e));
        }

        let is_valid = validation_errors.is_empty();

        if is_valid {
            info!(
                "JWT token validation successful for subject: {}",
                token_data.claims.sub
            );
        } else {
            warn!("JWT token validation failed: {:?}", validation_errors);
        }

        Ok(ValidationResult {
            claims: token_data.claims,
            header,
            is_valid,
            validation_errors,
        })
    }

    /// Get OIDC discovery document
    async fn get_discovery(&self) -> Result<OidcDiscovery> {
        // Check cache first
        {
            let cache = self.discovery_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.cached_at.elapsed().unwrap_or(Duration::MAX) < cached.ttl {
                    debug!("Using cached OIDC discovery document");
                    return Ok(cached.discovery.clone());
                }
            }
        }

        // Fetch from the server
        debug!(
            "Fetching OIDC discovery document from: {}",
            self.config.discovery_url
        );

        let response = self
            .http_client
            .get(self.config.discovery_url.clone())
            .send()
            .await
            .context("Failed to fetch OIDC discovery document")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "OIDC discovery request failed with status: {}",
                response.status()
            ));
        }

        let discovery: OidcDiscovery = response
            .json()
            .await
            .context("Failed to parse OIDC discovery document")?;

        // Cache the result
        {
            let mut cache = self.discovery_cache.write().await;
            *cache = Some(CachedDiscovery {
                discovery: discovery.clone(),
                cached_at: SystemTime::now(),
                ttl: Duration::from_secs(self.config.cache_settings.discovery_cache_ttl),
            });
        }

        info!(
            "Successfully fetched OIDC discovery document for issuer: {}",
            discovery.issuer
        );
        Ok(discovery)
    }

    /// Get JWKS from the provider
    async fn get_jwks(&self, jwks_uri: &str) -> Result<Jwks> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.cached_at.elapsed().unwrap_or(Duration::MAX) < cached.ttl {
                    debug!("Using cached JWKS");
                    return Ok(cached.jwks.clone());
                }
            }
        }

        // Fetch from the server
        debug!("Fetching JWKS from: {}", jwks_uri);

        let response = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .context("Failed to fetch JWKS")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "JWKS request failed with status: {}",
                response.status()
            ));
        }

        let jwks: Jwks = response.json().await.context("Failed to parse JWKS")?;

        // Cache the result
        {
            let mut cache = self.jwks_cache.write().await;
            *cache = Some(CachedJwks {
                jwks: jwks.clone(),
                cached_at: SystemTime::now(),
                ttl: Duration::from_secs(self.config.cache_settings.jwks_cache_ttl),
            });
        }

        info!("Successfully fetched JWKS with {} keys", jwks.keys.len());
        Ok(jwks)
    }

    /// Find the appropriate key from JWKS
    fn find_key(&self, jwks: &Jwks, header: &Header) -> Result<DecodingKey> {
        // Try to find key by kid first
        if let Some(kid) = &header.kid {
            for key in &jwks.keys {
                if key.kid.as_ref() == Some(kid) {
                    return self
                        .jwk_to_decoding_key(key)
                        .context("Failed to convert JWK to DecodingKey");
                }
            }
            warn!("Key with kid '{}' not found in JWKS", kid);
        }

        // Fallback: try all keys with matching algorithm
        let alg_str = match header.alg {
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::PS256 => "PS256",
            Algorithm::PS384 => "PS384",
            Algorithm::PS512 => "PS512",
            _ => return Err(anyhow!("Unsupported algorithm: {:?}", header.alg)),
        };

        for key in &jwks.keys {
            if key.alg.as_ref() == Some(&alg_str.to_string()) || key.alg.is_none() {
                if let Ok(decoding_key) = self.jwk_to_decoding_key(key) {
                    debug!("Using key without kid matching for algorithm: {}", alg_str);
                    return Ok(decoding_key);
                }
            }
        }

        Err(anyhow!(
            "No suitable key found in JWKS for algorithm: {}",
            alg_str
        ))
    }

    /// Convert JWK to DecodingKey
    fn jwk_to_decoding_key(&self, jwk: &Jwk) -> Result<DecodingKey> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing 'n' parameter for RSA key"))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing 'e' parameter for RSA key"))?;

                // Decode base64url
                let _n_bytes = general_purpose::URL_SAFE_NO_PAD
                    .decode(n)
                    .context("Failed to decode RSA modulus")?;
                let _e_bytes = general_purpose::URL_SAFE_NO_PAD
                    .decode(e)
                    .context("Failed to decode RSA exponent")?;

                DecodingKey::from_rsa_components(n, e).context("Failed to create RSA decoding key")
            }
            "EC" => {
                // For EC keys, we need the curve and coordinates
                let _crv = jwk
                    .crv
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing 'crv' parameter for EC key"))?;
                let _x = jwk
                    .x
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing 'x' parameter for EC key"))?;
                let _y = jwk
                    .y
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing 'y' parameter for EC key"))?;

                // TODO: Implement EC key support
                Err(anyhow!("EC keys not yet supported"))
            }
            "oct" => {
                let k = jwk
                    .k
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing 'k' parameter for symmetric key"))?;
                let key_bytes = general_purpose::URL_SAFE_NO_PAD
                    .decode(k)
                    .context("Failed to decode symmetric key")?;

                Ok(DecodingKey::from_secret(&key_bytes))
            }
            _ => Err(anyhow!("Unsupported key type: {}", jwk.kty)),
        }
    }

    /// Create JWT validation settings
    fn create_validation_settings(&self) -> Result<Validation> {
        let jwt_config = &self.config.jwt_validation;
        let mut validation = Validation::default();

        // Set algorithms
        validation.algorithms = jwt_config
            .algorithms
            .iter()
            .map(|alg| match alg.as_str() {
                "RS256" => Ok(Algorithm::RS256),
                "RS384" => Ok(Algorithm::RS384),
                "RS512" => Ok(Algorithm::RS512),
                "ES256" => Ok(Algorithm::ES256),
                "ES384" => Ok(Algorithm::ES384),
                "PS256" => Ok(Algorithm::PS256),
                "PS384" => Ok(Algorithm::PS384),
                "PS512" => Ok(Algorithm::PS512),
                _ => Err(anyhow!("Unsupported algorithm: {}", alg)),
            })
            .collect::<Result<Vec<_>>>()?;

        // Set validation flags
        validation.validate_exp = jwt_config.validate_exp;
        validation.validate_nbf = jwt_config.validate_nbf;
        validation.validate_aud = jwt_config.validate_aud;

        // Set audience
        if jwt_config.validate_aud {
            validation.aud = Some(jwt_config.audiences.iter().cloned().collect());
        }

        // Set clock skew
        validation.leeway = jwt_config.clock_skew;

        Ok(validation)
    }

    /// Validate custom claims
    fn validate_custom_claims(&self, claims: &JwtClaims) -> Result<()> {
        let jwt_config = &self.config.jwt_validation;

        // Check max age if specified
        if let Some(max_age) = jwt_config.max_age {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now - claims.iat > max_age {
                return Err(anyhow!("Token is too old"));
            }
        }

        // Validate required scopes are present (if available in claims)
        if let Some(scope) = claims.custom_claims.get("scope") {
            if let Some(scope_str) = scope.as_str() {
                let token_scopes: Vec<&str> = scope_str.split_whitespace().collect();
                for required_scope in &self.config.scopes {
                    if !token_scopes.contains(&required_scope.as_str()) {
                        return Err(anyhow!(
                            "Required scope '{}' not present in token",
                            required_scope
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract user information from JWT claims
    pub fn extract_user_info(&self, claims: &JwtClaims) -> Result<UserInfo> {
        let mapping = &self.config.claims_mapping;

        let user_id = self
            .extract_claim_value(claims, &mapping.user_id_claim)
            .unwrap_or_else(|| claims.sub.clone());

        let username = self
            .extract_claim_value(claims, &mapping.username_claim)
            .or_else(|| self.extract_claim_value(claims, &mapping.email_claim))
            .unwrap_or_else(|| claims.sub.clone());

        let email = self.extract_claim_value(claims, &mapping.email_claim);

        let groups = if let Some(groups_claim) = &mapping.groups_claim {
            self.extract_array_claim(claims, groups_claim)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let roles = if let Some(role_claim) = &mapping.role_claim {
            self.extract_array_claim(claims, role_claim)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Extract custom metadata
        let mut metadata = HashMap::new();
        for field in &self.config.user_provisioning.user_metadata_fields {
            if let Some(value) = self.extract_claim_value(claims, field) {
                metadata.insert(field.clone(), value);
            }
        }

        Ok(UserInfo {
            user_id,
            username,
            email,
            groups,
            roles,
            metadata,
            claims: claims.clone(),
        })
    }

    /// Extract claim value as string
    fn extract_claim_value(&self, claims: &JwtClaims, claim_name: &str) -> Option<String> {
        match claim_name {
            "sub" => Some(claims.sub.clone()),
            "email" => claims.email.clone(),
            "name" => claims.name.clone(),
            "given_name" => claims.given_name.clone(),
            "family_name" => claims.family_name.clone(),
            "preferred_username" => claims.preferred_username.clone(),
            "picture" => claims.picture.clone(),
            "locale" => claims.locale.clone(),
            _ => claims
                .custom_claims
                .get(claim_name)
                .and_then(|v| v.as_str().map(|s| s.to_string())),
        }
    }

    /// Extract claim value as array of strings
    fn extract_array_claim(&self, claims: &JwtClaims, claim_name: &str) -> Option<Vec<String>> {
        claims.custom_claims.get(claim_name).and_then(|v| {
            if let Some(arr) = v.as_array() {
                Some(
                    arr.iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect(),
                )
            } else if let Some(s) = v.as_str() {
                Some(vec![s.to_string()])
            } else {
                None
            }
        })
    }
}

/// User information extracted from JWT claims
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub claims: JwtClaims,
}

#[cfg(test)]
mod tests {
    use super::super::config::OidcConfig;
    use super::*;

    #[tokio::test]
    async fn test_validator_creation() {
        let config = OidcConfig::default();
        let validator = OidcValidator::new(config);

        // Should create successfully
        assert!(validator.discovery_cache.read().await.is_none());
        assert!(validator.jwks_cache.read().await.is_none());
    }

    #[test]
    fn test_extract_claim_value() {
        let config = OidcConfig::default();
        let validator = OidcValidator::new(config);

        let mut claims = JwtClaims {
            iss: "test".to_string(),
            sub: "user123".to_string(),
            aud: serde_json::Value::String("client".to_string()),
            exp: 1234567890,
            iat: 1234567890,
            nbf: None,
            jti: None,
            email: Some("user@example.com".to_string()),
            email_verified: None,
            name: Some("Test User".to_string()),
            given_name: None,
            family_name: None,
            preferred_username: Some("testuser".to_string()),
            picture: None,
            locale: None,
            custom_claims: HashMap::new(),
        };

        claims.custom_claims.insert(
            "custom_field".to_string(),
            serde_json::Value::String("custom_value".to_string()),
        );

        assert_eq!(
            validator.extract_claim_value(&claims, "sub"),
            Some("user123".to_string())
        );
        assert_eq!(
            validator.extract_claim_value(&claims, "email"),
            Some("user@example.com".to_string())
        );
        assert_eq!(
            validator.extract_claim_value(&claims, "custom_field"),
            Some("custom_value".to_string())
        );
        assert_eq!(validator.extract_claim_value(&claims, "nonexistent"), None);
    }
}
