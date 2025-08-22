//! HTTP middleware for the Brankas API
//!
//! Provides authentication, rate limiting, request tracing,
//! and other middleware functionality.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn, debug};
use uuid::Uuid;

use crate::auth::{AuthService, extract_bearer_token, AuthError};
use crate::ApiState;

/// Request context passed through middleware
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub user_roles: Vec<String>,
    pub user_permissions: Vec<String>,
    pub start_time: Instant,
}

/// Rate limiting state
#[derive(Debug)]
pub struct RateLimitState {
    requests: HashMap<String, Vec<Instant>>,
    max_requests_per_minute: u32,
}

impl RateLimitState {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests_per_minute,
        }
    }
    
    pub fn check_rate_limit(&mut self, identifier: &str) -> bool {
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);
        
        // Get or create request history for this identifier
        let requests = self.requests.entry(identifier.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests (older than 1 minute)
        requests.retain(|&time| time > one_minute_ago);
        
        // Check if we're under the limit
        if requests.len() < self.max_requests_per_minute as usize {
            requests.push(now);
            true
        } else {
            false
        }
    }
}

/// Global rate limiting state
static RATE_LIMITER: Mutex<Option<RateLimitState>> = Mutex::new(None);

/// Initialize rate limiting
pub fn init_rate_limiting(max_requests_per_minute: u32) {
    let mut limiter = RATE_LIMITER.lock().unwrap();
    *limiter = Some(RateLimitState::new(max_requests_per_minute));
}

/// Request ID middleware - adds unique ID to each request
pub async fn request_id(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    
    // Add request ID to headers for downstream processing
    request.headers_mut().insert(
        "x-request-id",
        request_id.parse().unwrap()
    );
    
    debug!("Processing request: {}", request_id);
    
    let response = next.run(request).await;
    
    // Add request ID to response headers
    let mut response = response;
    response.headers_mut().insert(
        "x-request-id",
        request_id.parse().unwrap()
    );
    
    response
}

/// Authentication middleware
pub async fn auth_middleware(
    State(_state): State<ApiState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // Skip auth for health/status endpoints
    let path = request.uri().path();
    if path == "/health" || path == "/version" || path.starts_with("/health") {
        return Ok(next.run(request).await);
    }
    
    // Check if authentication is required
    // Skip authentication for now - simplified
    if false { // if !state.transit.config.require_authentication {
        debug!("Authentication disabled, skipping auth middleware");
        return Ok(next.run(request).await);
    }
    
    // Extract authorization header
    let auth_header = headers.get("authorization")
        .ok_or(AuthError::MissingAuthHeader)?;
    
    // Extract bearer token
    let token = extract_bearer_token(auth_header)
        .ok_or(AuthError::InvalidAuthHeader)?;
    
    // Create auth service (in real implementation, this would be injected)
    let auth_config = crate::auth::AuthConfig::default();
    let auth_service = AuthService::new(auth_config);
    
    // Validate token
    let token_data = auth_service.validate_token(&token)?;
    let claims = token_data.claims;
    
    info!(
        "Authenticated user: {} ({}) with roles: {:?}",
        claims.name, claims.email, claims.roles
    );
    
    // Create request context
    let context = RequestContext {
        request_id: headers.get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string(),
        user_id: Some(claims.sub.clone()),
        user_email: Some(claims.email.clone()),
        user_roles: claims.roles.clone(),
        user_permissions: claims.permissions.clone(),
        start_time: Instant::now(),
    };
    
    // Add context to request extensions
    request.extensions_mut().insert(context);
    
    Ok(next.run(request).await)
}

/// Rate limiting middleware
pub async fn rate_limit(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Get client identifier (IP address or user ID)
    let client_ip = headers.get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    
    // Check rate limit
    let mut limiter_guard = RATE_LIMITER.lock().unwrap();
    if let Some(ref mut limiter) = *limiter_guard {
        if !limiter.check_rate_limit(client_ip) {
            warn!("Rate limit exceeded for client: {}", client_ip);
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "Rate limit exceeded",
                    "status": 429,
                    "retry_after": 60
                }))
            ));
        }
    }
    drop(limiter_guard);
    
    Ok(next.run(request).await)
}

/// Request logging middleware
pub async fn request_logging(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start_time = Instant::now();
    
    info!("Incoming request: {} {}", method, uri);
    
    let response = next.run(request).await;
    
    let duration = start_time.elapsed();
    let status = response.status();
    
    info!(
        "Request completed: {} {} -> {} ({:.2}ms)",
        method,
        uri,
        status.as_u16(),
        duration.as_millis()
    );
    
    // Log slow requests
    if duration > Duration::from_millis(1000) {
        warn!(
            "Slow request detected: {} {} took {:.2}ms",
            method,
            uri,
            duration.as_millis()
        );
    }
    
    response
}

/// Security headers middleware
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    
    // Add security headers
    let headers = response.headers_mut();
    
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap()
    );
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'".parse().unwrap()
    );
    
    response
}

/// Request size limiting middleware
pub async fn request_size_limit(
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB
    
    // Check content-length header
    if let Some(content_length) = request.headers().get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > MAX_REQUEST_SIZE {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(serde_json::json!({
                            "error": "Request too large",
                            "max_size": MAX_REQUEST_SIZE,
                            "actual_size": length
                        }))
                    ));
                }
            }
        }
    }
    
    Ok(next.run(request).await)
}

/// Audit logging middleware
pub async fn audit_logging(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let user_agent = request.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    
    // Extract request context if available
    let context = request.extensions().get::<RequestContext>().cloned();
    
    let response = next.run(request).await;
    
    // Log security-relevant operations
    let path = uri.path();
    if path.contains("/keys") || path.contains("/encrypt") || path.contains("/decrypt") {
        let user_info = if let Some(ctx) = context {
            format!("user:{} email:{}", 
                   ctx.user_id.as_deref().unwrap_or("anonymous"),
                   ctx.user_email.as_deref().unwrap_or("unknown"))
        } else {
            "user:anonymous".to_string()
        };
        
        info!(
            "AUDIT: {} {} by {} from {} -> {}",
            method,
            uri,
            user_info,
            user_agent,
            response.status().as_u16()
        );
    }
    
    response
}

/// CORS preflight handling
pub async fn cors_preflight(
    request: Request,
    next: Next,
) -> Response {
    if request.method() == axum::http::Method::OPTIONS {
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
            .header("Access-Control-Max-Age", "86400")
            .body(axum::body::Body::empty())
            .unwrap();
    }
    
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rate_limiting() {
        let mut rate_limiter = RateLimitState::new(5); // 5 requests per minute
        
        // Should allow 5 requests
        for _ in 0..5 {
            assert!(rate_limiter.check_rate_limit("test-client"));
        }
        
        // Should block the 6th request
        assert!(!rate_limiter.check_rate_limit("test-client"));
        
        // Different client should be allowed
        assert!(rate_limiter.check_rate_limit("other-client"));
    }
}
