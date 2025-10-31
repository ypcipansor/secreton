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

// Use canonical types from core
use secreton_core::models::{LoginRequest, LoginResponse, RefreshTokenRequest, UserInfo};

use crate::{
    handlers::AppState,
    ApiResponse, ApiResult,
};
use brankas_core::audit::SecurityEventType;
use secreton_errors::SecretonError;

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

// LoginRequest, LoginResponse, RefreshTokenRequest, UserInfo now imported from secreton_core::models

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

/// OAuth user information from provider
#[derive(Debug)]
pub struct OAuthUserInfo {
    pub id: String,
    pub email: String,
    pub username: String,
    pub name: String,
    pub provider: String,
}

/// Session information
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
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Extract client information from headers
    let ip_address = "127.0.0.1".to_string(); // TODO: Extract from request
    let user_agent = "Unknown".to_string(); // TODO: Extract from request

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

    // Validate and get user info from token
    let user = state.services.auth.validate_token(token).await
        .map_err(|e| crate::ApiError::Authentication(e.to_string()))?;

    // Invalidate the token (implementation depends on token service)
    // For now, we'll just log the logout
    // TODO: Implement token invalidation in token service

    let data = serde_json::json!({
        "message": "Successfully logged out"
    });

    // Audit: session terminated
    let _ = state
        .audit
        .log_event(
            SecurityEventType::SessionTerminated {
                user: user.username,
                session_id: "unknown".to_string(), // TODO: Extract session ID from token
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

    // For now, implement basic TOTP setup
    // TODO: Integrate with proper MFA service
    let response = match request.method.as_str() {
        "totp" => {
            // Generate a random secret for TOTP
            use rand::Rng;
            let secret: String = (0..32)
                .map(|_| {
                    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
                    chars[rand::thread_rng().gen_range(0..chars.len())] as char
                })
                .collect();

            // Generate backup codes
            let backup_codes: Vec<String> = (0..10)
                .map(|_| format!("{:06}", rand::thread_rng().gen_range(0..1000000)))
                .collect();

            MfaSetupResponse {
                method: "totp".to_string(),
                secret: Some(secret),
                qr_code: Some(format!("otpauth://totp/Secreton:{}?secret={}&issuer=Secreton", user.username, secret)),
                backup_codes,
            }
        }
        _ => {
            return Err(crate::ApiError::Validation(format!("Unsupported MFA method: {}", request.method)));
        }
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

    // For now, implement basic TOTP verification
    // TODO: Integrate with proper MFA service and TOTP library
    let is_valid = match request.method.as_str() {
        "totp" => {
            // Basic TOTP validation using HMAC-SHA1
            validate_totp_code(&request.code, &user.id) // Using user ID as secret for demo
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

    // For now, implement basic MFA disable
    // TODO: Integrate with proper MFA service to actually disable MFA settings
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

    // TODO: Store state in cache/database with expiration for callback verification
    // For now, we'll just return it (in production, this should be stored securely)

    // Build authorization URL based on provider
    let auth_url = match provider.as_str() {
        "google" => format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
            "google_client_id", // TODO: Get from config
            "https://api.secreton.com/auth/oauth/google/callback", // TODO: Get from config
            state
        ),
        "github" => format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
            "github_client_id", // TODO: Get from config
            "https://api.secreton.com/auth/oauth/github/callback", // TODO: Get from config
            state
        ),
        "microsoft" => format!(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
            "microsoft_client_id", // TODO: Get from config
            "https://api.secreton.com/auth/oauth/microsoft/callback", // TODO: Get from config
            state
        ),
        "okta" => format!(
            "https://{}.okta.com/oauth2/v1/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
            "tenant", // TODO: Get from config
            "okta_client_id", // TODO: Get from config
            "https://api.secreton.com/auth/oauth/okta/callback", // TODO: Get from config
            state
        ),
        _ => return Err(crate::ApiError::Validation(format!("Unsupported OAuth provider: {}", provider))),
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

    // TODO: Verify state parameter against stored state for CSRF protection
    // For now, we'll accept any state (in production, validate against stored state)

    if let Some(error) = params.get("error") {
        return Err(crate::ApiError::Authentication(format!("OAuth error: {}", error)));
    }

    // TODO: Exchange authorization code for access token with OAuth provider
    // This would involve making HTTP requests to the provider's token endpoint
    // For now, simulate successful token exchange

    // TODO: Fetch user information from provider using access token
    // This would involve making HTTP requests to the provider's user info endpoint

    // Simulate OAuth user info (in production, this comes from provider)
    let oauth_user = OAuthUserInfo {
        id: "oauth_123".to_string(),
        email: "oauth@example.com".to_string(),
        username: "oauth_user".to_string(),
        name: "OAuth User".to_string(),
        provider: provider.clone(),
    };

    // Create or update user account
    let user = state.services.auth.oauth_login(&oauth_user).await
        .map_err(|e| crate::ApiError::Authentication(format!("OAuth login failed: {}", e)))?;

    // Generate JWT tokens
    let access_token = state.services.auth.generate_token(&user).await
        .map_err(|e| crate::ApiError::Authentication(format!("Token generation failed: {}", e)))?;

    let refresh_token = state.services.auth.generate_refresh_token(&user).await
        .map_err(|e| crate::ApiError::Authentication(format!("Refresh token generation failed: {}", e)))?;

    let response = LoginResponse {
        access_token,
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
                ip_address: "127.0.0.1".to_string(), // TODO: Extract from request
                user_agent: "Unknown".to_string(), // TODO: Extract from request
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

    // TODO: Implement proper session management in auth service
    // For now, return mock sessions (in production, fetch from database/cache)
    let sessions = vec![
        SessionInfo {
            id: "current_session".to_string(),
            user_id: user.id.to_string(),
            ip_address: "127.0.0.1".to_string(), // TODO: Extract from request
            user_agent: "Unknown".to_string(), // TODO: Extract from request
            created_at: user.last_login,
            last_accessed: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            is_current: true,
        },
        // In production, this would include other active sessions for the user
    ];

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

    // TODO: Validate that session_id belongs to the current user
    // TODO: Remove session from storage/cache
    // TODO: Invalidate associated tokens

    // For now, only allow revoking the current session
    if session_id != "current_session" {
        return Err(crate::ApiError::Validation("Session not found or access denied".to_string()));
    }

    // Invalidate the current token (logout)
    // TODO: Implement proper token invalidation in auth service
    // For now, this is a placeholder - in production, add token to blacklist

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
                ip_address: "127.0.0.1".to_string(), // TODO: Extract from request
                user_agent: "Unknown".to_string(), // TODO: Extract from request
            },
            Some(user.id),
            None,
            None,
            Default::default(),
        )
        .await;

    Ok(Json(ApiResponse::success(data)))
}
