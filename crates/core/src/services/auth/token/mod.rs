use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};
use crate::storage::StorageEngine;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    pub signing_key: String,
    pub issuer: String,
    pub audience: String,
    pub expiration_hours: i64,
    pub renewal_hours: i64,
    pub max_renewal_hours: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String, // Subject (user ID)
    pub iss: String, // Issuer
    pub aud: String, // Audience
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
    pub nbf: i64,    // Not before
    pub jti: String, // JWT ID
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub renewable: bool,
    pub num_uses: Option<i32>,
    pub max_ttl: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreateRequest {
    pub display_name: Option<String>,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub ttl: Option<i64>,
    pub max_ttl: Option<i64>,
    pub renewable: Option<bool>,
    pub num_uses: Option<i32>,
    pub role_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreateResponse {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub lease_duration: i64,
    pub renewable: bool,
    pub entity_id: String,
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRenewRequest {
    pub token: String,
    pub increment: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRenewResponse {
    pub client_token: String,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub lease_duration: i64,
    pub renewable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRevokeRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLookupRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLookupResponse {
    pub id: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub creation_time: i64,
    pub creation_ttl: i64,
    pub expiration_time: i64,
    pub last_renewal_time: i64,
    pub renewable: bool,
    pub num_uses: Option<i32>,
    pub max_ttl: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRole {
    pub name: String,
    pub policies: Vec<String>,
    pub allowed_policies: Vec<String>,
    pub disallowed_policies: Vec<String>,
    pub orphan: bool,
    pub renewable: bool,
    pub path_suffix: Option<String>,
    pub allowed_policies_glob: Vec<String>,
    pub token_bound_cidrs: Vec<String>,
    pub token_explicit_max_ttl: i64,
    pub token_max_ttl: i64,
    pub token_no_default_policy: bool,
    pub token_num_uses: i32,
    pub token_period: i64,
    pub token_type: String,
}

pub struct TokenAuth {
    config: TokenConfig,
    storage: Arc<dyn StorageEngine + Send + Sync>,
    roles: Arc<RwLock<HashMap<String, TokenRole>>>,
    revoked_tokens: Arc<RwLock<HashMap<String, i64>>>, // token -> revocation_time
}

impl TokenAuth {
    pub fn new(config: TokenConfig, storage: Arc<dyn StorageEngine + Send + Sync>) -> Self {
        Self {
            config,
            storage,
            roles: Arc::new(RwLock::new(HashMap::new())),
            revoked_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn authenticate(
        &self,
        auth_request: &AuthRequest,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        match auth_request {
            AuthRequest::Token { token } => self.authenticate_token(token).await,
            _ => Err("Token authentication only supports token-based auth".into()),
        }
    }

    async fn authenticate_token(
        &self,
        token: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Check if token is revoked
        {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains_key(token) {
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
        }

        // Decode and validate JWT
        let claims = self.decode_token(token)?;

        // Check if token is expired
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Ok(AuthResponse {
                authenticated: false,
                user_info: UserInfo {
                    username: claims.sub.clone(),
                    email: None,
                    groups: vec![],
                    metadata: claims.metadata.clone(),
                },
                policies: vec![],
                lease_duration: 0,
                renewable: false,
                token: "".to_string(),
                accessor: "".to_string(),
                metadata: HashMap::new(),
            });
        }

        // Check num_uses if specified
        if let Some(num_uses) = claims.num_uses {
            if num_uses <= 0 {
                return Ok(AuthResponse {
                    authenticated: false,
                    user_info: UserInfo {
                        username: claims.sub.clone(),
                        email: None,
                        groups: vec![],
                        metadata: claims.metadata.clone(),
                    },
                    policies: vec![],
                    lease_duration: 0,
                    renewable: false,
                    token: "".to_string(),
                    accessor: "".to_string(),
                    metadata: HashMap::new(),
                });
            }
        }

        Ok(AuthResponse {
            authenticated: true,
            user_info: UserInfo {
                username: claims.sub.clone(),
                email: None,
                groups: vec![],
                metadata: claims.metadata.clone(),
            },
            policies: claims.policies.clone(),
            lease_duration: claims.exp - now,
            renewable: claims.renewable,
            token: token.to_string(),
            accessor: format!("token-{}", claims.jti),
            metadata: claims.metadata.clone(),
        })
    }

    pub async fn create_token(
        &self,
        request: TokenCreateRequest,
        _creator_token: Option<&str>,
    ) -> Result<TokenCreateResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Generate unique token ID
        let token_id = uuid::Uuid::new_v4().to_string();
        let accessor = format!("token-accessor-{}", uuid::Uuid::new_v4().simple());

        // Determine policies
        let policies = if let Some(role_name) = &request.role_name {
            // Use role-based policies
            let roles = self.roles.read().await;
            if let Some(role) = roles.get(role_name) {
                role.policies.clone()
            } else {
                return Err(format!("Role {} not found", role_name).into());
            }
        } else {
            request.policies.clone()
        };

        // Set TTL
        let ttl = request.ttl.unwrap_or(self.config.expiration_hours * 3600);
        let max_ttl = request
            .max_ttl
            .unwrap_or(self.config.max_renewal_hours * 3600);

        // Create claims
        let now = Utc::now();
        let claims = TokenClaims {
            sub: token_id.clone(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: (now + Duration::seconds(ttl)).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: token_id.clone(),
            policies: policies.clone(),
            metadata: request.metadata.clone(),
            renewable: request.renewable.unwrap_or(true),
            num_uses: request.num_uses,
            max_ttl,
        };

        // Encode JWT
        let token = self.encode_token(&claims)?;

        // Store token metadata
        let token_data = serde_json::to_vec(&claims)?;
        let key = format!("auth/token/{}", token_id);
        let entry = crate::storage::StorageEntry {
            key: key.clone(),
            value: token_data,
            metadata: HashMap::new(),
        };
        self.storage.put(entry).await?;

        Ok(TokenCreateResponse {
            client_token: token,
            accessor,
            policies,
            metadata: request.metadata,
            lease_duration: ttl,
            renewable: claims.renewable,
            entity_id: token_id,
            token_type: "service".to_string(),
        })
    }

    pub async fn renew_token(
        &self,
        request: TokenRenewRequest,
    ) -> Result<TokenRenewResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Decode current token
        let mut claims = self.decode_token(&request.token)?;

        // Check if token is renewable
        if !claims.renewable {
            return Err("Token is not renewable".into());
        }

        // Calculate new expiration
        let now = Utc::now();
        let increment = request
            .increment
            .unwrap_or(self.config.renewal_hours * 3600);
        let new_exp = claims.exp + increment;

        // Check max TTL
        if new_exp > claims.iat + claims.max_ttl {
            return Err("Token renewal would exceed maximum TTL".into());
        }

        // Update claims
        claims.exp = new_exp;

        // Encode new token
        let new_token = self.encode_token(&claims)?;

        // Update stored token
        let token_data = serde_json::to_vec(&claims)?;
        let key = format!("auth/token/{}", claims.jti);
        let entry = crate::storage::StorageEntry {
            key: key.clone(),
            value: token_data,
            metadata: HashMap::new(),
        };
        self.storage.put(entry).await?;

        Ok(TokenRenewResponse {
            client_token: new_token,
            policies: claims.policies,
            metadata: claims.metadata,
            lease_duration: new_exp - now.timestamp(),
            renewable: claims.renewable,
        })
    }

    pub async fn revoke_token(
        &self,
        request: TokenRevokeRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Decode token to get token ID
        let claims = self.decode_token(&request.token)?;

        // Add to revoked tokens
        {
            let mut revoked = self.revoked_tokens.write().await;
            revoked.insert(request.token.clone(), Utc::now().timestamp());
        }

        // Remove from storage
        let key = format!("auth/token/{}", claims.jti);
        self.storage.delete(&key).await?;

        Ok(())
    }

    pub async fn lookup_token(
        &self,
        request: TokenLookupRequest,
    ) -> Result<TokenLookupResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Decode token
        let claims = self.decode_token(&request.token)?;

        // Get creation time from storage
        let key = format!("auth/token/{}", claims.jti);
        let token_entry = self.storage.get(&key).await?;
        let token_data = token_entry.ok_or("Token not found")?;
        let _stored_claims: TokenClaims = serde_json::from_slice(&token_data.value)?;

        Ok(TokenLookupResponse {
            id: claims.jti.clone(),
            accessor: format!("token-accessor-{}", claims.jti),
            policies: claims.policies,
            metadata: claims.metadata,
            creation_time: claims.iat,
            creation_ttl: claims.exp - claims.iat,
            expiration_time: claims.exp,
            last_renewal_time: claims.iat, // Simplified
            renewable: claims.renewable,
            num_uses: claims.num_uses,
            max_ttl: claims.max_ttl,
        })
    }

    pub async fn create_role(
        &self,
        name: &str,
        role: TokenRole,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut roles = self.roles.write().await;
            roles.insert(name.to_string(), role.clone());
        }

        // Store role
        let role_data = serde_json::to_vec(&role)?;
        let key = format!("auth/token/roles/{}", name);
        let entry = crate::storage::StorageEntry {
            key: key.clone(),
            value: role_data,
            metadata: HashMap::new(),
        };
        self.storage.put(entry).await?;

        Ok(())
    }

    pub async fn get_role(
        &self,
        name: &str,
    ) -> Result<TokenRole, Box<dyn std::error::Error + Send + Sync>> {
        let roles = self.roles.read().await;
        if let Some(role) = roles.get(name) {
            Ok(role.clone())
        } else {
            Err(format!("Role {} not found", name).into())
        }
    }

    pub async fn list_roles(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let roles = self.roles.read().await;
        Ok(roles.keys().cloned().collect())
    }

    pub async fn delete_role(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut roles = self.roles.write().await;
            roles.remove(name);
        }

        // Remove from storage
        let key = format!("auth/token/roles/{}", name);
        self.storage.delete(&key).await?;

        Ok(())
    }

    fn encode_token(
        &self,
        claims: &TokenClaims,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.config.signing_key.as_bytes());

        let token = encode(&header, claims, &encoding_key)?;
        Ok(token)
    }

    fn decode_token(
        &self,
        token: &str,
    ) -> Result<TokenClaims, Box<dyn std::error::Error + Send + Sync>> {
        let decoding_key = DecodingKey::from_secret(self.config.signing_key.as_bytes());
        let validation = Validation::new(Algorithm::HS256);

        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Check if token is revoked
        {
            let revoked = self.revoked_tokens.read().await;
            if revoked.contains_key(token) {
                return Ok(false);
            }
        }

        // Try to decode and validate
        match self.decode_token(token) {
            Ok(claims) => {
                let now = Utc::now().timestamp();
                Ok(claims.exp > now)
            }
            Err(_) => Ok(false),
        }
    }

    pub async fn cleanup_expired_tokens(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = Utc::now().timestamp();

        // Clean up revoked tokens (keep for 24 hours after revocation)
        {
            let mut revoked = self.revoked_tokens.write().await;
            let expired_revoked: Vec<String> = revoked
                .iter()
                .filter(|(_, &revocation_time)| now - revocation_time > 86400) // 24 hours
                .map(|(token, _)| token.clone())
                .collect();

            for token in expired_revoked {
                revoked.remove(&token);
            }
        }

        Ok(())
    }
}
