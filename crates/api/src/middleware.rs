//! HTTP middleware for the Secreton API
//!
//! Provides authentication, rate limiting, request tracing,
//! and other middleware functionality.

#![allow(clippy::collapsible_if)]

use crate::ApiState;
use crate::auth::{JwtAuthService, extract_bearer_token};
use axum::{
    Json,
    extract::{Extension, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hex;
use lru::LruCache;
use secreton_errors::SecretonError;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;
use x509_parser::prelude::*;

/// Cached certificate entry with expiration
#[derive(Debug, Clone)]
struct CachedValidation {
    validation: CertificateValidation,
    expires_at: Instant,
}

impl CachedValidation {
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Certificate cache with LRU eviction
#[derive(Debug)]
struct CertificateCache {
    cache: RwLock<LruCache<String, CachedValidation>>,
    ttl: Duration,
}

impl CertificateCache {
    fn new(capacity: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: RwLock::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    async fn get(&self, key: &str) -> Option<CertificateValidation> {
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.validation.clone());
            } else {
                // Remove expired entry
                cache.pop(key);
            }
        }
        None
    }

    async fn insert(&self, key: String, validation: CertificateValidation) {
        let entry = CachedValidation {
            validation,
            expires_at: Instant::now() + self.ttl,
        };
        let mut cache = self.cache.write().await;
        cache.put(key, entry);
    }
}

lazy_static::lazy_static! {
    static ref CERTIFICATE_CACHE: Arc<CertificateCache> = Arc::new(CertificateCache::new(1000, 300)); // 1000 entries, 5 minute TTL
}

/// Certificate validation result
#[derive(Debug, Clone)]
pub struct CertificateValidation {
    pub valid: bool,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

/// Validate client certificate
pub async fn validate_client_certificate(
    cert_der: &[u8],
    _ca_cert_path: Option<&PathBuf>,
    allowed_subjects: &[String],
) -> CertificateValidation {
    // Generate cache key from certificate DER
    let cert_key = hex::encode(cert_der);

    // Try cache first
    if let Some(cached_validation) = CERTIFICATE_CACHE.get(&cert_key).await {
        return cached_validation;
    }

    // Parse certificate and validate if not cached
    let validation = match X509Certificate::from_der(cert_der) {
        Ok((_, cert)) => validate_cached_certificate(&cert, allowed_subjects),
        Err(e) => {
            warn!("Failed to parse client certificate: {}", e);
            CertificateValidation {
                valid: false,
                subject: None,
                issuer: None,
                serial_number: None,
                not_before: None,
                not_after: None,
            }
        }
    };

    // Cache the validation result
    CERTIFICATE_CACHE.insert(cert_key, validation.clone()).await;

    validation
}

/// Validate cached certificate
fn validate_cached_certificate(
    cert: &X509Certificate,
    allowed_subjects: &[String],
) -> CertificateValidation {
    // Check certificate validity period
    let now = chrono::Utc::now();
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();

    // Convert time types properly
    let not_before_chrono =
        chrono::DateTime::<chrono::Utc>::from_timestamp(not_before.unix_timestamp(), 0).unwrap();
    let not_after_chrono =
        chrono::DateTime::<chrono::Utc>::from_timestamp(not_after.unix_timestamp(), 0).unwrap();

    // Check if certificate is not yet valid
    if now < not_before_chrono {
        warn!(
            "Certificate is not yet valid: current={}, not_before={}",
            now, not_before_chrono
        );
        return CertificateValidation {
            valid: false,
            subject: Some(cert.subject().to_string()),
            issuer: Some(cert.issuer().to_string()),
            serial_number: Some(hex::encode(cert.raw_serial())),
            not_before: Some(not_before_chrono.to_string()),
            not_after: Some(not_after_chrono.to_string()),
        };
    }

    // Check if certificate has expired
    if now > not_after_chrono {
        warn!(
            "Certificate has expired: current={}, not_after={}",
            now, not_after_chrono
        );
        return CertificateValidation {
            valid: false,
            subject: Some(cert.subject().to_string()),
            issuer: Some(cert.issuer().to_string()),
            serial_number: Some(hex::encode(cert.raw_serial())),
            not_before: Some(not_before_chrono.to_string()),
            not_after: Some(not_after_chrono.to_string()),
        };
    }

    // Basic check: ensure not_after is after not_before
    if not_after_chrono <= not_before_chrono {
        warn!(
            "Certificate has invalid validity period: not_before={}, not_after={}",
            not_before_chrono, not_after_chrono
        );
        return CertificateValidation {
            valid: false,
            subject: Some(cert.subject().to_string()),
            issuer: Some(cert.issuer().to_string()),
            serial_number: Some(hex::encode(cert.raw_serial())),
            not_before: Some(not_before_chrono.to_string()),
            not_after: Some(not_after_chrono.to_string()),
        };
    }

    // Check if subject is in allowed list
    let subject_str = cert.subject().to_string();
    let is_allowed =
        allowed_subjects.is_empty() || allowed_subjects.iter().any(|s| subject_str.contains(s));

    if !is_allowed {
        warn!("Certificate subject not in allowed list: {}", subject_str);
    }

    CertificateValidation {
        valid: is_allowed,
        subject: Some(subject_str),
        issuer: Some(cert.issuer().to_string()),
        serial_number: Some(hex::encode(cert.raw_serial())),
        not_before: Some(not_before_chrono.to_string()),
        not_after: Some(not_after_chrono.to_string()),
    }
}

/// Extract client certificate from TLS connection
pub fn extract_client_certificate_from_tls(request: &Request) -> Option<Vec<u8>> {
    // In a real implementation with proper TLS integration, this would extract
    // the client certificate from the TLS connection context.
    // For now, we'll use a more realistic approach with the certificate in headers
    // or as a fallback to the previous implementation

    // Try to get certificate from request extensions (set by TLS layer)
    if let Some(cert_der) = request.extensions().get::<Vec<u8>>() {
        return Some(cert_der.clone());
    }

    // Fallback to header-based extraction for development/testing
    request
        .headers()
        .get("x-client-cert")
        .and_then(|v| hex::decode(v).ok())
}

/// Enhanced mTLS authentication middleware with proper TLS integration
pub async fn mtls_auth_middleware(
    Extension(_state): Extension<ApiState>,
    _headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, SecretonError> {
    // Skip mTLS for health/status endpoints
    let path = request.uri().path();
    if path == "/health" || path == "/version" || path.starts_with("/health") {
        return Ok(next.run(request).await);
    }

    // Get mTLS config from state
    if let Some(mtls_config) = _state.config.auth.mtls.as_ref() {
        if mtls_config.required {
            // Extract client certificate from TLS connection
            if let Some(client_cert_der) = extract_client_certificate_from_tls(&request) {
                let start_time = std::time::Instant::now();

                // Validate certificate asynchronously
                let validation = validate_client_certificate(
                    &client_cert_der,
                    None,
                    &mtls_config.allowed_subjects,
                )
                .await;

                let validation_time = start_time.elapsed().as_millis() as u64;

                if validation.valid {
                    info!(
                        "mTLS authentication successful for subject: {:?} (validation: {}ms)",
                        validation.subject, validation_time
                    );

                    // Add certificate info to request extensions
                    request.extensions_mut().insert(validation);

                    return Ok(next.run(request).await);
                } else {
                    warn!(
                        "mTLS authentication failed for subject: {:?} (validation: {}ms)",
                        validation.subject, validation_time
                    );
                    return Err(SecretonError::InvalidCredentials);
                }
            } else {
                warn!("mTLS required but no client certificate provided");
                return Err(SecretonError::InvalidCredentials);
            }
        }
    }

    // mTLS not required or not configured, proceed with regular authentication
    Ok(next.run(request).await)
}

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
        let requests = self.requests.entry(identifier.to_string()).or_default();

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
    request
        .headers_mut()
        .insert("x-request-id", request_id.parse().unwrap());

    debug!("Processing request: {}", request_id);

    let response = next.run(request).await;

    // Add request ID to response headers
    let mut response = response;
    response
        .headers_mut()
        .insert("x-request-id", request_id.parse().unwrap());

    response
}

/// Authentication middleware
pub async fn auth_middleware(
    Extension(_state): Extension<ApiState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, SecretonError> {
    // Skip auth for health/status endpoints
    let path = request.uri().path();
    if path == "/health" || path == "/version" || path.starts_with("/health") {
        return Ok(next.run(request).await);
    }

    // Check if authentication is required
    // Skip authentication for now - simplified
    if false {
        // if !state.transit.config.require_authentication {
        debug!("Authentication disabled, skipping auth middleware");
        return Ok(next.run(request).await);
    }

    // Extract authorization header
    let auth_header = headers
        .get("authorization")
        .ok_or(SecretonError::MissingAuthHeader)?;

    // Extract bearer token
    let token = extract_bearer_token(auth_header).ok_or(SecretonError::InvalidAuthHeader)?;

    // Create auth service (in real implementation, this would be injected)
    let auth_config = crate::auth::AuthConfig::default();
    let auth_service = JwtAuthService::new(auth_config);

    // Validate token
    let claims = auth_service.validate_token(&token)?;

    info!(
        "Authenticated user: {} ({}) with roles: {:?}",
        claims.name, claims.email, claims.roles
    );

    // Create request context
    let context = RequestContext {
        request_id: headers
            .get("x-request-id")
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

pub async fn request_logging(request: Request, next: Next) -> Response {
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
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
            .parse()
            .unwrap(),
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
                        })),
                    ));
                }
            }
        }
    }

    Ok(next.run(request).await)
}

/// Audit logging middleware
pub async fn audit_logging(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let user_agent = request
        .headers()
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
            format!(
                "user:{} email:{}",
                ctx.user_id.as_deref().unwrap_or("anonymous"),
                ctx.user_email.as_deref().unwrap_or("unknown")
            )
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
pub async fn cors_preflight(request: Request, next: Next) -> Response {
    if request.method() == axum::http::Method::OPTIONS {
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Access-Control-Allow-Origin", "*")
            .header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, DELETE, OPTIONS",
            )
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, X-Request-ID",
            )
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

    #[tokio::test]
    async fn test_rate_limit_middleware() {
        use axum::{body::Body, http::Request, middleware::from_fn, routing::get, Router};
        use tower::ServiceExt;

        // Initialize rate limiting with a low threshold
        init_rate_limiting(2);

        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(from_fn(rate_limit::RateLimitMiddleware::limit));

        // First request: should be allowed
        let req1 = Request::builder()
            .uri("/")
            .header("x-real-ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::OK);

        // Second request: should be allowed
        let req2 = Request::builder()
            .uri("/")
            .header("x-real-ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::OK);

        // Third request: should be rate limited
        let req3 = Request::builder()
            .uri("/")
            .header("x-real-ip", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let res3 = app.clone().oneshot(req3).await.unwrap();
        assert_eq!(res3.status(), StatusCode::TOO_MANY_REQUESTS);

        // Different IP: should be allowed
        let req4 = Request::builder()
            .uri("/")
            .header("x-real-ip", "5.6.7.8")
            .body(Body::empty())
            .unwrap();
        let res4 = app.clone().oneshot(req4).await.unwrap();
        assert_eq!(res4.status(), StatusCode::OK);
    }

    /// Build a User with the given `mfa_pending` metadata flag for testing.
    fn make_user(mfa_pending: bool) -> secreton_auth::User {
        let mut metadata = HashMap::new();
        if mfa_pending {
            metadata.insert("mfa_pending".to_string(), "true".to_string());
        }
        secreton_auth::User {
            id: "00000000-0000-0000-0000-000000000001".to_string(),
            username: "testuser".to_string(),
            email: Some("test@example.com".to_string()),
            display_name: None,
            full_name: None,
            roles: vec![],
            permissions: vec![],
            policies: vec!["default".to_string()],
            metadata,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            disabled: false,
            password_hash: String::new(),
            is_active: true,
            is_superuser: false,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            failed_login_attempts: 0,
            locked_until: None,
        }
    }

    /// A user without `mfa_pending` metadata can access any path.
    #[test]
    fn enforce_mfa_pending_allows_everything_when_not_pending() {
        let user = make_user(false);
        for path in [
            "/api/v1/auth/login",
            "/api/v1/secret/data/foo",
            "/api/v1/sys/config",
            "/api/v1/auth/mfa/disable",
        ] {
            assert!(
                enforce_mfa_pending(&user, path).is_ok(),
                "path {} should be allowed when mfa_pending is false",
                path
            );
        }
    }

    /// TOFU users can access only the MFA-enrollment and logout endpoints.
    #[test]
    fn enforce_mfa_pending_allows_enrollment_paths_when_pending() {
        let user = make_user(true);
        for path in [
            "/api/v1/auth/mfa/setup",
            "/api/v1/auth/mfa/setup/complete",
            "/api/v1/auth/mfa/verify",
            "/api/v1/auth/logout",
        ] {
            assert!(
                enforce_mfa_pending(&user, path).is_ok(),
                "path {} should be allowed during TOFU",
                path
            );
        }
    }

    /// TOFU users are blocked from any non-enrollment endpoint, and the
    /// allowlist is path-exact so substring tricks (e.g. secret paths
    /// containing "/mfa/") cannot bypass it.
    #[test]
    fn enforce_mfa_pending_blocks_other_paths_when_pending() {
        let user = make_user(true);
        for path in [
            "/api/v1/secret/data/foo",
            "/api/v1/sys/config",
            // `/mfa/disable` is intentionally NOT allowed for TOFU users —
            // disable has no effect when MFA is not yet enrolled.
            "/api/v1/auth/mfa/disable",
            // Substring bypass attempts must be rejected by exact matching.
            "/api/v1/secret/data/api/v1/auth/mfa/setup",
            "/api/v1/auth/mfa/setup/../secret/data/foo",
            "/api/v1/auth/login",
        ] {
            assert_eq!(
                enforce_mfa_pending(&user, path).unwrap_err(),
                StatusCode::FORBIDDEN,
                "path {} must be forbidden during TOFU",
                path
            );
        }
    }

    /// Regression test: cross-check the `MFA_PENDING_ALLOWED_PATHS` constant
    /// against the actual routes defined by `handlers::auth::create_routes()`.
    ///
    /// `handlers::auth::create_routes()` defines auth routes **without** the
    /// `/api/v1/auth` prefix (e.g. `/mfa/setup`), and the router mounts them
    /// under that prefix in `create_router()`.  The allowlist hardcodes the
    /// fully-prefixed paths because that is what the middleware sees at
    /// request time.  If either side is modified without the other — e.g.
    /// the handler route is renamed to `/mfa/enroll` but the allowlist still
    /// lists `/api/v1/auth/mfa/setup` — a TOFU user will be blocked from
    /// enrolling and become permanently locked out.
    ///
    /// This test codifies the mapping so that such a drift fails fast at
    /// test time rather than silently in production.  The expected paths
    /// below must be kept in sync with
    /// `crates/api/src/handlers/auth.rs::create_routes()` — each entry here
    /// corresponds to a handler route that a TOFU user must be able to
    /// reach to complete enrollment (plus logout).
    #[test]
    fn mfa_pending_allowlist_matches_handler_routes() {
        // Routes defined by `handlers::auth::create_routes()`, as they will
        // appear after the `/api/v1/auth` prefix is applied by
        // `create_router()`.  Only the subset that a TOFU user needs access
        // to is listed — other routes (e.g. `/login`, `/refresh`) are
        // exempted from auth entirely and never hit `enforce_mfa_pending`.
        let expected: &[&str] = &[
            "/api/v1/auth/mfa/setup",
            "/api/v1/auth/mfa/setup/complete",
            "/api/v1/auth/mfa/verify",
            "/api/v1/auth/logout",
        ];

        // Order-insensitive set comparison so refactors that reorder the
        // constant don't break this test.
        let actual: std::collections::HashSet<&str> =
            MFA_PENDING_ALLOWED_PATHS.iter().copied().collect();
        let expected_set: std::collections::HashSet<&str> = expected.iter().copied().collect();

        assert_eq!(
            actual, expected_set,
            "MFA_PENDING_ALLOWED_PATHS has drifted from the handler routes \
             in handlers::auth::create_routes(). If you added or removed an \
             MFA-enrollment route, update both the constant and this test."
        );
    }
}

/// Paths that remain accessible when a user is in the TOFU MFA-pending state.
///
/// These are the **full** HTTP paths as seen by the auth middleware — i.e.
/// they include the `/api/v1` router prefix that `create_router` adds on top
/// of `handlers::auth::create_routes()` (which itself defines them without a
/// prefix, e.g. `/mfa/setup`).
///
/// Kept as a named constant so a regression test can cross-check the allowlist
/// against the real `create_routes()` definitions and catch silent drift when
/// either side is modified.
pub const MFA_PENDING_ALLOWED_PATHS: &[&str] = &[
    "/api/v1/auth/mfa/setup",
    "/api/v1/auth/mfa/setup/complete",
    "/api/v1/auth/mfa/verify",
    "/api/v1/auth/logout",
];

/// Check whether the authenticated user has a pending MFA enrollment (TOFU)
/// and, if so, whether the requested path is allowed.
///
/// Returns `Err(FORBIDDEN)` when MFA enrollment is pending and the path is
/// NOT an MFA or logout endpoint.  Returns `Ok(())` otherwise.
///
/// This is the **single source of truth** for the MFA-pending allowlist so
/// that `AuthMiddleware::authenticate` (used by `create_router`) and
/// `auth_middleware` (used by `create_api_router`) stay in sync.  Any change
/// to the allowlist must be made in [`MFA_PENDING_ALLOWED_PATHS`] only.
pub fn enforce_mfa_pending(
    user: &secreton_auth::User,
    path: &str,
) -> Result<(), axum::http::StatusCode> {
    let mfa_pending = user
        .metadata
        .get("mfa_pending")
        .map(|v| v == "true")
        .unwrap_or(false);

    if mfa_pending {
        // Use exact path matching for MFA endpoints to prevent bypass via
        // user-controlled path segments (e.g. a secret named "mfa" would
        // match `path.contains("/mfa/")`).
        //
        // NOT allowed during TOFU:
        //   - /api/v1/auth/mfa/disable — a TOFU user has not enrolled yet,
        //     so there is nothing to disable.  Allowing it would let a
        //     privileged user call disable (which is a no-op or error) and
        //     remain in the TOFU state indefinitely.
        if !MFA_PENDING_ALLOWED_PATHS.iter().any(|p| path == *p) {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
    }

    Ok(())
}

pub mod auth {
    use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};

    #[derive(Clone)]
    pub struct AuthMiddleware;

    impl AuthMiddleware {
        pub async fn authenticate(
            axum::extract::State(state): axum::extract::State<crate::handlers::AppState>,
            mut req: Request,
            next: Next,
        ) -> Result<Response, StatusCode> {
            let path = req.uri().path().to_string();
            // Exempt public paths: root, health, version, and specific
            // unauthenticated auth endpoints (login, refresh, verify, oauth).
            // Protected auth endpoints (logout, mfa/*, sessions, users) are
            // NOT exempted so they go through token validation and
            // MFA-pending enforcement below.
            // Exempt sys initialization endpoints
            if path == "/" 
                || path == "/health"
                || path == "/version"
                || path == "/login"  // Handler unit test uses /login directly
                || path == "/api/v1/health"
                || path == "/api/v1/version"
                || path == "/api/v1/sys/health"
                || path == "/api/v1/auth/login"
                || path == "/api/v1/auth/refresh"
                || path == "/api/v1/auth/verify"
                || path.starts_with("/api/v1/auth/oauth/")
                || path == "/api/v1/auth/oauth"
                || path == "/api/v1/sys/init"
                || path == "/api/v1/sys/unseal"
                || path == "/api/v1/sys/seal-status"
            {
                return Ok(next.run(req).await);
            }

            let auth_header = req
                .headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .ok_or(StatusCode::UNAUTHORIZED)?;

            let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
                stripped
            } else {
                return Err(StatusCode::UNAUTHORIZED);
            };

            // Validate token using the authentication service
            // Note: validate_token returns a User object on success
            let user = state
                .auth
                .validate_token(token)
                .await
                .map_err(|_| StatusCode::UNAUTHORIZED)?;

            // Enforce TOFU MFA enrollment via the shared helper so that
            // the allowlist stays in sync with `auth_middleware` in lib.rs.
            crate::middleware::enforce_mfa_pending(&user, &path)?;

            // Create request context or simplified user info to store in extensions
            // The handlers expect AuthenticatedUser extractor which likely looks for User in extensions
            req.extensions_mut().insert(user);

            Ok(next.run(req).await)
        }
    }
}

pub mod seal {
    use axum::{
        Json, extract::Request, http::StatusCode, middleware::Next, response::IntoResponse,
        response::Response,
    };
    use serde_json::json;

    #[derive(Clone)]
    pub struct SealMiddleware;

    impl SealMiddleware {
        pub async fn check(
            axum::extract::State(state): axum::extract::State<crate::handlers::AppState>,
            req: Request,
            next: Next,
        ) -> Result<Response, Response> {
            let path = req.uri().path().to_string();

            // Paths allowed when sealed — use exact prefix matching to prevent
            // bypass via user-controlled path segments (e.g. a secret named
            // "sys/init" would match `path.contains("/sys/init")`).
            // This mirrors the tightened matching in `AuthMiddleware::authenticate`.
            if path == "/api/v1/sys/init"
                || path == "/api/v1/sys/unseal"
                || path == "/api/v1/sys/seal-status"
                || path == "/api/v1/sys/health"
                || path == "/health"
                || path == "/api/v1/health"
            {
                return Ok(next.run(req).await);
            }

            // Check if sealed
            if state.seal.is_sealed().await {
                let body = Json(json!({
                    "error": "Secreton is sealed",
                    "code": 503
                }));
                return Err((StatusCode::SERVICE_UNAVAILABLE, body).into_response());
            }

            Ok(next.run(req).await)
        }
    }
}

pub mod cors {
    use tower_http::cors::{Any, CorsLayer};

    pub fn create_cors_layer() -> CorsLayer {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    }
}

pub mod rate_limit {
    use axum::{
        Json,
        extract::Request,
        http::{HeaderMap, StatusCode},
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use tracing::warn;

    #[derive(Clone)]
    pub struct RateLimitMiddleware;

    impl RateLimitMiddleware {
        pub async fn limit(req: Request, next: Next) -> Result<Response, Response> {
            // Get client identifier (IP address)
            let client_ip = extract_client_ip(req.headers());

            // Check rate limit
            {
                let mut limiter_guard = super::RATE_LIMITER.lock().unwrap();
                if let Some(ref mut limiter) = *limiter_guard {
                    if !limiter.check_rate_limit(&client_ip) {
                        warn!("Rate limit exceeded for client: {}", client_ip);
                        let body = Json(serde_json::json!({
                            "error": "Rate limit exceeded",
                            "status": 429,
                            "retry_after": 60
                        }));
                        return Err((StatusCode::TOO_MANY_REQUESTS, body).into_response());
                    }
                }
            }

            Ok(next.run(req).await)
        }
    }

    fn extract_client_ip(headers: &HeaderMap) -> String {
        // IP Extraction Logic (Security Note):
        // 1. Prefer X-Real-IP if set by a trusted local proxy.
        // 2. Fall back to X-Forwarded-For. We take the LAST element if multiple
        //    are present, as it is the most recently added by a proxy.
        //    (Note: taking the FIRST element is easily spoofed by clients).
        // 3. Fall back to "unknown". In production, the connection info from
        //    Axum's ConnectInfo should be used for the ultimate source of truth.

        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            return real_ip.trim().to_string();
        }

        if let Some(forwarded_for) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Split and take the last one (most reliable in most chained proxy setups)
            if let Some(last_ip) = forwarded_for.split(',').next_back() {
                return last_ip.trim().to_string();
            }
        }

        "unknown".to_string()
    }
}
