//! Authentication and authorization handlers.
//! 
//! Provides endpoints for user login, token management, MFA,
//! and OAuth2 integration.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post, delete},
    Router,
};

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// In-memory OAuth state storage (in production, use database)
lazy_static::lazy_static! {
    static ref OAUTH_STATE_STORE: Arc<RwLock<HashMap<String, OAuthState>>> = Arc::new(RwLock::new(HashMap::new()));
}

/// OAuth state information
#[derive(Debug, Clone)]
struct OAuthState {
    provider: String,
    state: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

// Simple in-memory token blacklist for invalidation
lazy_static::lazy_static! {
    static ref TOKEN_BLACKLIST: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>> = Arc::new(RwLock::new(HashMap::new()));
}

// Use types from secreton_auth
use secreton_auth::{LoginRequest, RefreshTokenRequest, UserInfo};

use crate::{
    handlers::AppState,
    ApiResponse, ApiResult,
};
use secreton_core::audit::SecurityEventType;
use secreton_errors::SecretonError;

// Import Claims from auth service for JWT decoding
use crate::services::auth::Claims;

/// Create authentication routes
pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
        .route("/verify", post(verify_token))
        .route("/mfa/setup", post(setup_mfa))
        .route("/mfa/verify", post(verify_mfa))
        .route("/mfa/disable", post(disable_mfa))
        .route("/oauth/:provider", get(oauth_login))
        .route("/oauth/:provider/callback", get(oauth_callback))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:session_id", delete(revoke_session))
}

/// Basic TOTP validation function
fn validate_totp_code(code: &str, secret: &str) -> bool {
    if code.len() != 6 || !code.chars().all(|c| c.is_numeric()) {
        return false;
    }

    let code_num = match code.parse::<u32>() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Get current time window (30 second intervals)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() / 30;

    // Check current and adjacent time windows (±1)
    for time_window in (now.saturating_sub(1))..=(now + 1) {
        let expected_code = generate_hotp(secret.as_bytes(), time_window);
        if expected_code == code_num {
            return true;
        }
    }

    false
}

/// Generate HOTP code
fn generate_hotp(key: &[u8], counter: u64) -> u32 {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Dynamic truncation
    let offset = (result[19] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | ((result[offset + 1] & 0xff) as u32) << 16
        | ((result[offset + 2] & 0xff) as u32) << 8
        | (result[offset + 3] & 0xff) as u32;

    code % 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApiConfig;
    use crate::services::ServiceContainer;
    use axum_test::TestServer;
    use std::sync::Arc;

    async fn create_test_server() -> TestServer {
        let config = ApiConfig::default();
        let services = Arc::new(
            ServiceContainer::new(&config)
                .await
                .expect("Failed to create services"),
        );

        let app = create_routes().with_state(services);
        TestServer::new(app).expect("Failed to create test server")
    }

    #[tokio::test]
    async fn test_login_endpoint_returns_tokens() {
        let server = create_test_server().await;
        let request = LoginRequest {
            username: "alice".to_string(),
            password: "password123".to_string(),
            mfa_code: None,
            remember_me: Some(true),
        };

        let response = server.post("/login").json(&request).await;
        response.assert_status_ok();

        let body: ApiResponse<LoginResponse> = response.json();
        assert!(body.success);
        let data = body.data.expect("login response");
        assert_eq!(data.token_type, "Bearer");
        assert_eq!(data.user.username, "alice");
        assert!(!data.mfa_required);
    }

    #[tokio::test]
    async fn test_mfa_setup_rejects_unsupported_method() {
        let server = create_test_server().await;
        let request = MfaSetupRequest {
            method: "sms".to_string(),
            phone_number: None,
            email: None,
        };

        let response = server.post("/mfa/setup").json(&request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: ApiResponse<serde_json::Value> = response.json();
        assert!(!body.success);
        let error = body.error.expect("error payload");
        assert_eq!(error.code, "INVALID_REQUEST");
    }

    #[tokio::test]
    async fn test_oauth_login_returns_authorization_url() {
        let server = create_test_server().await;
        let response = server.get("/oauth/github").await;
        response.assert_status_ok();

        let body: ApiResponse<serde_json::Value> = response.json();
        assert!(body.success);
        let data = body.data.expect("oauth payload");
        assert_eq!(data["provider"], "github");
        assert!(data["auth_url"].as_str().unwrap().contains("https://oauth.provider.com"));
    }
}

// LoginRequest, RefreshTokenRequest, UserInfo imported from secreton_auth

/// Login response for API
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
    pub mfa_required: bool,
}

/// Token verification request
#[derive(Debug, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

/// MFA setup request
#[derive(Debug, Deserialize)]
pub struct MfaSetupRequest {
    pub method: String, // "totp", "sms", "email", "webauthn"
    pub phone_number: Option<String>,
    pub email: Option<String>,
}

/// MFA setup response
#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub method: String,
    pub secret: Option<String>, // For TOTP
    pub qr_code: Option<String>, // For TOTP
    pub backup_codes: Vec<String>,
}

/// MFA verification request
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub method: String,
    pub code: String,
    pub backup_code: Option<String>,
}

/// MFA disable request
#[derive(Debug, Deserialize)]
pub struct MfaDisableRequest {
    pub password: String, // Require password confirmation for security
}

/// OAuth provider configuration
#[derive(Debug, Clone)]
struct OAuthProvider {
    client_id: String,
    client_secret: String,
    token_url: String,
    user_info_url: String,
    redirect_uri: String,
}

use secreton_config::OAuthProvidersConfig;

impl OAuthProvider {
    fn new(provider: &str, config: Option<&OAuthProvidersConfig>) -> Option<Self> {
        if let Some(config) = config {
            match provider {
                "google" => config.google.as_ref().map(|c| Self {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    token_url: "https://oauth2.googleapis.com/token".to_string(),
                    user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
                    redirect_uri: c.redirect_uri.clone(),
                }),
                "github" => config.github.as_ref().map(|c| Self {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    token_url: "https://github.com/login/oauth/access_token".to_string(),
                    user_info_url: "https://api.github.com/user".to_string(),
                    redirect_uri: c.redirect_uri.clone(),
                }),
                "microsoft" => config.microsoft.as_ref().map(|c| Self {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                    user_info_url: "https://graph.microsoft.com/v1.0/me".to_string(),
                    redirect_uri: c.redirect_uri.clone(),
                }),
                "okta" => config.okta.as_ref().and_then(|c| c.tenant.as_ref().map(|tenant| Self {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    token_url: format!("https://{}.okta.com/oauth2/v1/token", tenant),
                    user_info_url: format!("https://{}.okta.com/oauth2/v1/userinfo", tenant),
                    redirect_uri: c.redirect_uri.clone(),
                })),
                _ => None,
            }
        } else {
            None
        }
    }

    async fn exchange_code_for_token(&self, code: &str) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let params = [
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("code", &code.to_string()),
            ("grant_type", &"authorization_code".to_string()),
            ("redirect_uri", &self.redirect_uri),
        ];

        let response = client
            .post(&self.token_url)
            .form(&params)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Token exchange failed: {}", response.status()).into());
        }

        let token_data: serde_json::Value = response.json().await?;
        Ok(token_data)
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let response = client
            .get(&self.user_info_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("User info fetch failed: {}", response.status()).into());
        }

        let user_data: serde_json::Value = response.json().await?;

        let oauth_user = match self.user_info_url.as_str() {
            url if url.contains("googleapis.com") => OAuthUserInfo {
                id: user_data["id"].as_str().unwrap_or("google_id").to_string(),
                email: user_data["email"].as_str().unwrap_or("").to_string(),
                username: user_data["email"].as_str().unwrap_or("").split('@').next().unwrap_or("google_user").to_string(),
                name: user_data["name"].as_str().unwrap_or("Google User").to_string(),
                provider: "google".to_string(),
            },
            url if url.contains("api.github.com") => OAuthUserInfo {
                id: user_data["id"].to_string(),
                email: user_data["email"].as_str().unwrap_or("").to_string(),
                username: user_data["login"].as_str().unwrap_or("github_user").to_string(),
                name: user_data["name"].as_str().unwrap_or("GitHub User").to_string(),
                provider: "github".to_string(),
            },
            url if url.contains("graph.microsoft.com") => OAuthUserInfo {
                id: user_data["id"].as_str().unwrap_or("microsoft_id").to_string(),
                email: user_data["userPrincipalName"].as_str().or(user_data["mail"].as_str()).unwrap_or("").to_string(),
                username: user_data["userPrincipalName"].as_str().unwrap_or("").split('@').next().unwrap_or("microsoft_user").to_string(),
                name: user_data["displayName"].as_str().unwrap_or("Microsoft User").to_string(),
                provider: "microsoft".to_string(),
            },
            url if url.contains("okta.com") => OAuthUserInfo {
                id: user_data["sub"].as_str().unwrap_or("okta_id").to_string(),
                email: user_data["email"].as_str().unwrap_or("").to_string(),
                username: user_data["preferred_username"].as_str().unwrap_or("okta_user").to_string(),
                name: user_data["name"].as_str().unwrap_or("Okta User").to_string(),
                provider: "okta".to_string(),
            },
            _ => return Err("Unsupported OAuth provider".into()),
        };

        Ok(oauth_user)
    }
}

/// OAuth user information from provider
#[derive(Debug)]
pub struct OAuthUserInfo {
    pub id: String,
    pub email: String,
    pub username: String,
    pub name: String,
    pub provider: String,
}
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub is_current: bool,
}

/// User login endpoint
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Extract client information from headers
    let ip_address = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    // Authenticate user
    let auth_result = state.services.auth.authenticate(
        &request.username,
        &request.password,
        request.mfa_code.as_deref(),
        &ip_address,
        &user_agent,
    ).await;

    match auth_result {
        Ok(auth_token) => {
            let response = LoginResponse {
                access_token: auth_token.access_token,
                refresh_token: auth_token.refresh_token,
                token_type: auth_token.token_type,
                expires_in: auth_token.expires_in,
                user: UserInfo {
                    id: auth_token.user.id,
                    username: auth_token.user.username,
                    email: auth_token.user.email.unwrap_or_default(),
                    roles: auth_token.user.roles,
                    permissions: auth_token.user.permissions,
                    last_login: auth_token.user.last_login,
                },
                mfa_required: false, // Already handled in authenticate method
            };

            // Create and store session
            let session_id = Uuid::new_v4().to_string();
            let session = SessionInfo {
                id: session_id.clone(),
                user_id: response.user.id.clone(),
                ip_address: ip_address.clone(),
                user_agent: user_agent.clone(),
                created_at: chrono::Utc::now(),
                last_accessed: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(24), // 24 hour sessions
                is_current: true,
            };

            // Store session
            {
                let mut sessions = SESSION_STORE.write().await;
                sessions.insert(session_id.clone(), session);
            }

            // Audit: authentication success
            let _ = state
                .audit
                .log_event(
                    SecurityEventType::AuthenticationSuccess {
                        user: response.user.username.clone(),
                        method: "password".to_string(),
                    },
                    Some(response.user.id.clone()),
                    None,
                    None,
                    Default::default(),
                )
                .await;

            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            // Audit: authentication failure
            let _ = state
                .audit
                .log_event(
                    SecurityEventType::AuthenticationFailure {
                        user: request.username.clone(),
                        method: "password".to_string(),
                        reason: e.to_string(),
                    },
                    None,
                    None,
                    None,
                    Default::default(),
                )
                .await;

            Err(crate::ApiError::Authentication(e.to_string()))
        }
    }
}

/// User logout endpoint
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract token from Authorization header
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Extract session ID from token for accurate auditing
    let session_id = {
        use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
        let decoding_key = DecodingKey::from_secret(state.config.auth.jwt.secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&state.config.auth.jwt.issuer]);
        validation.set_audience(&[&state.config.auth.jwt.audience]);

        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(token_data) => token_data.claims.jti,
            Err(_) => "unknown".to_string(), // Fallback if token decoding fails
        }
    };

    // Invalidate the token by adding to blacklist
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24); // Blacklist for 24 hours
    {
        let mut blacklist = TOKEN_BLACKLIST.write().await;
        blacklist.insert(token.to_string(), expires_at);
    }

    // Remove all sessions for this user (or find session by token)
    // For now, we remove all sessions as logout typically invalidates all
    {
        let mut sessions_store = SESSION_STORE.write().await;
        sessions_store.retain(|_, session| session.user_id != user.id);
    }

    let data = serde_json::json!({
        "message": "Successfully logged out"
    });

    // Audit: session terminated
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SessionTerminated {
                user: user.username,
                session_id,
                reason: "logout".to_string(),
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// Refresh access token
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Validate refresh token and get new tokens
    let auth_token = state.services.auth.refresh_token(&request.refresh_token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    let response = LoginResponse {
        access_token: auth_token.access_token,
        refresh_token: auth_token.refresh_token,
        token_type: auth_token.token_type,
        expires_in: auth_token.expires_in,
        user: UserInfo {
            id: auth_token.user.id,
            username: auth_token.user.username,
            email: auth_token.user.email.unwrap_or_default(),
            roles: auth_token.user.roles,
            permissions: auth_token.user.permissions,
            last_login: auth_token.user.last_login,
        },
        mfa_required: false,
    };

    // Audit: token refresh
    let _ = state
        .audit
        .log_event(
            SecurityEventType::AuthenticationSuccess {
                user: response.user.username.clone(),
                method: "refresh_token".to_string(),
            },
            Some(response.user.id.clone()),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Verify token validity
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> ApiResult<Json<ApiResponse<UserInfo>>> {
    // Validate token and get user information
    let user = state.services.auth.validate_token(&request.token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    let user_info = UserInfo {
        id: user.id,
        username: user.username,
        email: user.email.unwrap_or_default(),
        roles: user.roles,
        permissions: user.permissions,
        last_login: user.last_login,
    };

    Ok(Json(ApiResponse::success(user_info)))
}

/// Setup MFA for user
pub async fn setup_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MfaSetupRequest>,
) -> ApiResult<Json<ApiResponse<MfaSetupResponse>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Use the proper MFA service from the auth crate
    let issuer = "Secreton";
    let totp_config = state.services.mfa.enable_totp(
        &user.id,
        issuer.to_string(),
        user.username.clone(),
    ).await.map_err(|e| {
        crate::ApiError::Internal(format!("Failed to setup MFA: {}", e))
    })?;

    // Generate backup codes
    let recovery_codes = state.services.mfa.regenerate_recovery_codes(&user.id).await.map_err(|e| {
        crate::ApiError::Internal(format!("Failed to generate recovery codes: {}", e))
    })?;

    let response = MfaSetupResponse {
        method: "totp".to_string(),
        secret: Some(totp_config.secret),
        qr_code: Some(totp_config.qr_code_url),
        backup_codes: recovery_codes,
    };

    // Audit: MFA setup
    let _ = state
        .audit
        .log_event(
            SecurityEventType::MfaSetup {
                user: user.username,
                method: request.method,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Verify MFA code
pub async fn verify_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MfaVerifyRequest>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Use the proper MFA service from the auth crate
    let is_valid = match request.method.as_str() {
        "totp" => {
            state.services.mfa.verify_totp(&user.id, &request.code).await.unwrap_or(false)
        }
        _ => false,
    };

    if !is_valid {
        return Err(crate::ApiError::Authentication("Invalid MFA code".to_string()));
    }

    let data = serde_json::json!({
        "message": "MFA successfully verified and enabled",
        "method": request.method
    });

    // Audit: MFA success
    let _ = state
        .audit
        .log_event(
            SecurityEventType::MFASuccess {
                user: user.username,
                method: request.method,
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// Disable MFA for user
pub async fn disable_mfa(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MfaDisableRequest>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Verify password for additional security
    let password_valid = state.services.auth.verify_password(&user.username, &request.password).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    if !password_valid {
        return Err(crate::ApiError::Authentication("Invalid password".to_string()));
    }

    // Use the proper MFA service to disable TOTP
    state.services.mfa.disable_totp(&user.id).await.map_err(|e| {
        crate::ApiError::Internal(format!("Failed to disable MFA: {}", e))
    })?;

    let method = "totp"; // Assume TOTP for now

    let data = serde_json::json!({
        "message": "MFA successfully disabled",
        "method": method
    });

    // Audit: MFA removal
    let _ = state
        .audit
        .log_event(
            SecurityEventType::MFARemoval {
                user: user.username,
                method: method.to_string(),
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// OAuth login redirect
pub async fn oauth_login(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Validate supported providers
    let supported_providers = vec!["google", "github", "microsoft", "okta"];
    if !supported_providers.contains(&provider.as_str()) {
        return Err(crate::ApiError::Validation(format!("Unsupported OAuth provider: {}", provider)));
    }

    // Generate secure random state
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;
    let state: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store state in memory with expiration (10 minutes)
    let oauth_state = OAuthState {
        provider: provider.clone(),
        state: state.clone(),
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
    };

    {
        let mut state_store = OAUTH_STATE_STORE.write().await;
        state_store.insert(state.clone(), oauth_state);
        
        // Clean up expired states
        state_store.retain(|_, s| s.expires_at > chrono::Utc::now());
    }

    // Build authorization URL based on provider
    let auth_url = if let Some(config) = state.config.auth_methods.as_ref().and_then(|am| am.oauth_providers.as_ref()) {
        match provider.as_str() {
            "google" => {
                let google_config = config.google.as_ref()
                    .ok_or_else(|| crate::ApiError::Validation("Google OAuth configuration not found".to_string()))?;
                format!(
                    "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                    google_config.client_id,
                    google_config.redirect_uri,
                    state
                )
            }
            "github" => {
                let github_config = config.github.as_ref()
                    .ok_or_else(|| crate::ApiError::Validation("GitHub OAuth configuration not found".to_string()))?;
                format!(
                    "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
                    github_config.client_id,
                    github_config.redirect_uri,
                    state
                )
            }
            "microsoft" => {
                let microsoft_config = config.microsoft.as_ref()
                    .ok_or_else(|| crate::ApiError::Validation("Microsoft OAuth configuration not found".to_string()))?;
                format!(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                    microsoft_config.client_id,
                    microsoft_config.redirect_uri,
                    state
                )
            }
            "okta" => {
                let okta_config = config.okta.as_ref()
                    .ok_or_else(|| crate::ApiError::Validation("Okta OAuth configuration not found".to_string()))?;
                let tenant = okta_config.tenant.as_ref()
                    .ok_or_else(|| crate::ApiError::Validation("Okta tenant not configured".to_string()))?;
                format!(
                    "https://{}.okta.com/oauth2/v1/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
                    tenant,
                    okta_config.client_id,
                    okta_config.redirect_uri,
                    state
                )
            }
            _ => return Err(crate::ApiError::Validation(format!("Unsupported OAuth provider: {}", provider))),
        }
    } else {
        return Err(crate::ApiError::Validation("OAuth providers not configured".to_string()));
    };

    let data = serde_json::json!({
        "provider": provider,
        "auth_url": auth_url,
        "state": state
    });

    Ok(Json(ApiResponse::success(data)))
}

/// OAuth callback handler
pub async fn oauth_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Extract OAuth parameters
    let code = params.get("code").ok_or_else(|| {
        crate::ApiError::Validation("Missing authorization code".to_string())
    })?;

    let state_param = params.get("state").ok_or_else(|| {
        crate::ApiError::Validation("Missing state parameter".to_string())
    })?;

    // Verify state parameter against stored state for CSRF protection
    let stored_state = {
        let mut state_store = OAUTH_STATE_STORE.write().await;
        
        // Clean up expired states first
        state_store.retain(|_, s| s.expires_at > chrono::Utc::now());
        
        state_store.remove(state_param)
    };

    let stored_state = stored_state.ok_or_else(|| {
        crate::ApiError::Authentication("Invalid or expired OAuth state".to_string())
    })?;

    // Verify the state matches the expected provider
    if stored_state.provider != provider {
        return Err(crate::ApiError::Authentication("OAuth state provider mismatch".to_string()));
    }

    // Verify state hasn't expired
    if stored_state.expires_at < chrono::Utc::now() {
        return Err(crate::ApiError::Authentication("OAuth state has expired".to_string()));
    }

    if let Some(error) = params.get("error") {
        return Err(crate::ApiError::Authentication(format!("OAuth error: {}", error)));
    }

    // Get OAuth provider configuration
    let config = state.config.auth_methods.as_ref().and_then(|am| am.oauth_providers.as_ref())
        .ok_or_else(|| crate::ApiError::Validation("OAuth providers not configured".to_string()))?;

    let oauth_provider = OAuthProvider::new(&provider, Some(config))
        .ok_or_else(|| crate::ApiError::Validation(format!("Unsupported OAuth provider: {}", provider)))?;

    // Exchange authorization code for access token
    let token_data = oauth_provider.exchange_code_for_token(code)
        .await
        .map_err(|e| crate::ApiError::Authentication(format!("Token exchange failed: {}", e)))?;

    let access_token = token_data["access_token"].as_str()
        .ok_or_else(|| crate::ApiError::Authentication("No access token in response".to_string()))?;

    // Fetch user information from provider
    let oauth_user = oauth_provider.get_user_info(access_token)
        .await
        .map_err(|e| crate::ApiError::Authentication(format!("User info fetch failed: {}", e)))?;

    // Create or update user account
    let user = state.services.auth.oauth_login(&oauth_user).await
        .map_err(|e| crate::ApiError::Authentication(format!("OAuth login failed: {}", e)))?;

    // Generate JWT tokens
    let jwt_access_token = state.services.auth.generate_token(&user).await
        .map_err(|e| crate::ApiError::Authentication(format!("Token generation failed: {}", e)))?;

    let refresh_token = state.services.auth.generate_refresh_token(&user).await
        .map_err(|e| crate::ApiError::Authentication(format!("Refresh token generation failed: {}", e)))?;

    let response = LoginResponse {
        access_token: jwt_access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600, // 1 hour
        user: UserInfo {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            roles: user.roles.into_iter().map(|r| r.to_string()).collect(),
            permissions: user.permissions.into_iter().map(|p| p.to_string()).collect(),
            last_login: user.last_login,
        },
        mfa_required: false, // OAuth users might not need MFA initially
    };

    // Audit: OAuth login success
    let _ = state
        .audit
        .log_event(
            SecurityEventType::LoginSuccess {
                user: user.username,
                method: format!("oauth_{}", provider),
                ip_address: extract_client_ip(&headers),
                user_agent: extract_user_agent(&headers),
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// List user sessions
pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiResponse<Vec<SessionInfo>>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Get all sessions for the user
    let sessions = {
        let sessions_store = SESSION_STORE.read().await;
        sessions_store
            .values()
            .filter(|session| session.user_id == user.id && session.expires_at > chrono::Utc::now())
            .cloned()
            .collect::<Vec<_>>()
    };

    // Mark the current session (based on some criteria, e.g., recent access)
    let mut sessions = sessions.into_iter().map(|mut session| {
        // For simplicity, mark the most recently accessed session as current
        session.is_current = session.last_accessed > chrono::Utc::now() - chrono::Duration::minutes(5);
        session
    }).collect::<Vec<_>>();

    Ok(Json(ApiResponse::success(sessions)))
}

/// Revoke a user session
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| crate::ApiError::Authentication("Missing or invalid authorization header".to_string()))?;

    // Get user from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Validate that session_id belongs to the current user and remove it
    let session_removed = {
        let mut sessions_store = SESSION_STORE.write().await;
        if let Some(session) = sessions_store.get(&session_id) {
            if session.user_id == user.id {
                sessions_store.remove(&session_id);
                true
            } else {
                false
            }
        } else {
            false
        }
    };

    if !session_removed {
        return Err(crate::ApiError::NotFound("Session not found or access denied".to_string()));
    }

    // Invalidate associated tokens by adding to blacklist
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
    {
        let mut blacklist = TOKEN_BLACKLIST.write().await;
        blacklist.insert(token.to_string(), expires_at);
    }

    let data = serde_json::json!({
        "message": "Session successfully revoked",
        "session_id": session_id
    });

    // Audit: Session revocation
    let _ = state
        .audit
        .log_event(
            SecurityEventType::Logout {
                user: user.username,
                session_id: session_id.clone(),
                ip_address: extract_client_ip(&headers),
                user_agent: extract_user_agent(&headers),
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// Extract client IP address from request headers
fn extract_client_ip(headers: &HeaderMap) -> String {
    // Try X-Forwarded-For first (for proxies/load balancers)
    if let Some(x_forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(value) = x_forwarded_for.to_str() {
            // X-Forwarded-For can contain multiple IPs, take the first one
            if let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // Try X-Real-IP (for nginx)
    if let Some(x_real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = x_real_ip.to_str() {
            return value.to_string();
        }
    }

    // Try X-Client-IP (for some proxies)
    if let Some(x_client_ip) = headers.get("x-client-ip") {
        if let Ok(value) = x_client_ip.to_str() {
            return value.to_string();
        }
    }

    // Fallback to unknown
    "unknown".to_string()
}

/// Extract user agent from request headers
fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
