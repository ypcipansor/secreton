//! API Gateway & Rate Limiting
//!
//! Provides API gateway with intelligent routing, advanced rate limiting
//! (token bucket, sliding window), request throttling, and quota management.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Route not found: {0}")]
    RouteNotFound(String),
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, GatewayError>;

/// Rate limiting algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    LeakyBucket,
}

/// API route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub route_id: String,
    pub path_pattern: String,
    pub backend_url: String,
    pub methods: Vec<String>,
    pub rate_limit: Option<RateLimit>,
    pub authentication_required: bool,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub algorithm: RateLimitAlgorithm,
    pub requests_per_second: usize,
    pub burst_size: usize,
}

/// Request quota per tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quota {
    pub tenant_id: String,
    pub limit: usize,
    pub used: usize,
    pub reset_at: DateTime<Utc>,
    pub quota_type: QuotaType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuotaType {
    Daily,
    Monthly,
    Custom(u32),
}

/// Token bucket state
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: DateTime<Utc>,
}

/// Sliding window state
#[derive(Debug, Clone)]
struct SlidingWindow {
    requests: VecDeque<DateTime<Utc>>,
    window_size: Duration,
    max_requests: usize,
}

/// API request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequest {
    pub request_id: String,
    pub path: String,
    pub method: String,
    pub tenant_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub headers: HashMap<String, String>,
}

/// API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    pub request_id: String,
    pub status_code: u16,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
    pub latency_ms: u64,
}

/// API Gateway
pub struct ApiGateway {
    routes: Arc<RwLock<HashMap<String, Route>>>,
    token_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    sliding_windows: Arc<RwLock<HashMap<String, SlidingWindow>>>,
    quotas: Arc<RwLock<HashMap<String, Quota>>>,
}

impl ApiGateway {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            token_buckets: Arc::new(RwLock::new(HashMap::new())),
            sliding_windows: Arc::new(RwLock::new(HashMap::new())),
            quotas: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add route
    pub async fn add_route(&self, route: Route) -> Result<String> {
        let route_id = route.route_id.clone();
        let mut routes = self.routes.write().await;
        routes.insert(route_id.clone(), route);
        Ok(route_id)
    }

    /// Route request
    pub async fn route_request(&self, request: ApiRequest) -> Result<ApiResponse> {
        // Find matching route
        let route = self.find_route(&request.path).await?;

        // Check quota
        if let Some(tenant_id) = &request.tenant_id {
            self.check_quota(tenant_id).await?;
        }

        // Apply rate limiting
        if let Some(rate_limit) = &route.rate_limit {
            self.apply_rate_limit(&route.route_id, rate_limit).await?;
        }

        // Mock forwarding to backend
        let response = self.forward_to_backend(&route, &request).await?;

        // Update quota
        if let Some(tenant_id) = &request.tenant_id {
            self.increment_quota(tenant_id).await?;
        }

        Ok(response)
    }

    async fn find_route(&self, path: &str) -> Result<Route> {
        let routes = self.routes.read().await;

        for route in routes.values() {
            if self.matches_pattern(&route.path_pattern, path) {
                return Ok(route.clone());
            }
        }

        Err(GatewayError::RouteNotFound(path.to_string()))
    }

    fn matches_pattern(&self, pattern: &str, path: &str) -> bool {
        // Simple pattern matching (could be replaced with regex)
        if pattern.ends_with("*") {
            let prefix = pattern.trim_end_matches("*");
            path.starts_with(prefix)
        } else {
            pattern == path
        }
    }

    /// Apply rate limiting
    async fn apply_rate_limit(&self, route_id: &str, config: &RateLimit) -> Result<()> {
        match config.algorithm {
            RateLimitAlgorithm::TokenBucket => self.apply_token_bucket(route_id, config).await,
            RateLimitAlgorithm::SlidingWindow => self.apply_sliding_window(route_id, config).await,
            RateLimitAlgorithm::FixedWindow => self.apply_fixed_window(route_id, config).await,
            RateLimitAlgorithm::LeakyBucket => self.apply_leaky_bucket(route_id, config).await,
        }
    }

    async fn apply_token_bucket(&self, route_id: &str, config: &RateLimit) -> Result<()> {
        let mut buckets = self.token_buckets.write().await;

        let bucket = buckets
            .entry(route_id.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: config.burst_size as f64,
                capacity: config.burst_size as f64,
                refill_rate: config.requests_per_second as f64,
                last_refill: Utc::now(),
            });

        // Refill tokens
        let now = Utc::now();
        let elapsed = now
            .signed_duration_since(bucket.last_refill)
            .num_milliseconds() as f64
            / 1000.0;
        let new_tokens = elapsed * bucket.refill_rate;
        bucket.tokens = (bucket.tokens + new_tokens).min(bucket.capacity);
        bucket.last_refill = now;

        // Consume token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(GatewayError::RateLimitExceeded(
                "Token bucket exhausted".to_string(),
            ))
        }
    }

    async fn apply_sliding_window(&self, route_id: &str, config: &RateLimit) -> Result<()> {
        let mut windows = self.sliding_windows.write().await;

        let window = windows
            .entry(route_id.to_string())
            .or_insert_with(|| SlidingWindow {
                requests: VecDeque::new(),
                window_size: Duration::seconds(1),
                max_requests: config.requests_per_second,
            });

        let now = Utc::now();
        let window_start = now - window.window_size;

        // Remove old requests
        while let Some(timestamp) = window.requests.front() {
            if *timestamp < window_start {
                window.requests.pop_front();
            } else {
                break;
            }
        }

        // Check limit
        if window.requests.len() >= window.max_requests {
            return Err(GatewayError::RateLimitExceeded(
                "Sliding window limit reached".to_string(),
            ));
        }

        window.requests.push_back(now);
        Ok(())
    }

    async fn apply_fixed_window(&self, _route_id: &str, _config: &RateLimit) -> Result<()> {
        // Mock implementation
        Ok(())
    }

    async fn apply_leaky_bucket(&self, _route_id: &str, _config: &RateLimit) -> Result<()> {
        // Mock implementation
        Ok(())
    }

    async fn forward_to_backend(
        &self,
        _route: &Route,
        request: &ApiRequest,
    ) -> Result<ApiResponse> {
        // Mock backend forwarding
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        Ok(ApiResponse {
            request_id: request.request_id.clone(),
            status_code: 200,
            body: b"{\"status\":\"ok\"}".to_vec(),
            headers: HashMap::new(),
            latency_ms: 10,
        })
    }

    /// Check quota
    async fn check_quota(&self, tenant_id: &str) -> Result<()> {
        let quotas = self.quotas.read().await;

        if let Some(quota) = quotas.get(tenant_id) {
            if Utc::now() > quota.reset_at {
                // Quota reset needed
                return Ok(());
            }

            if quota.used >= quota.limit {
                return Err(GatewayError::QuotaExceeded(format!(
                    "Quota limit {} reached for tenant {}",
                    quota.limit, tenant_id
                )));
            }
        }

        Ok(())
    }

    async fn increment_quota(&self, tenant_id: &str) -> Result<()> {
        let mut quotas = self.quotas.write().await;

        let quota = quotas
            .entry(tenant_id.to_string())
            .or_insert_with(|| Quota {
                tenant_id: tenant_id.to_string(),
                limit: 10000,
                used: 0,
                reset_at: Utc::now() + Duration::days(1),
                quota_type: QuotaType::Daily,
            });

        // Reset if needed
        if Utc::now() > quota.reset_at {
            quota.used = 0;
            quota.reset_at = match quota.quota_type {
                QuotaType::Daily => Utc::now() + Duration::days(1),
                QuotaType::Monthly => Utc::now() + Duration::days(30),
                QuotaType::Custom(days) => Utc::now() + Duration::days(days as i64),
            };
        }

        quota.used += 1;
        Ok(())
    }

    /// Set quota for tenant
    pub async fn set_quota(&self, quota: Quota) -> Result<()> {
        let mut quotas = self.quotas.write().await;
        quotas.insert(quota.tenant_id.clone(), quota);
        Ok(())
    }

    /// Get quota status
    pub async fn get_quota(&self, tenant_id: &str) -> Option<Quota> {
        let quotas = self.quotas.read().await;
        quotas.get(tenant_id).cloned()
    }

    /// List routes
    pub async fn list_routes(&self) -> Vec<Route> {
        let routes = self.routes.read().await;
        routes.values().cloned().collect()
    }
}

impl Default for ApiGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_route() {
        let gateway = ApiGateway::new();
        let route = Route {
            route_id: "route1".to_string(),
            path_pattern: "/api/v1/secrets/*".to_string(),
            backend_url: "http://backend:8080".to_string(),
            methods: vec!["GET".to_string(), "POST".to_string()],
            rate_limit: None,
            authentication_required: true,
        };

        let route_id = gateway.add_route(route).await.unwrap();
        assert_eq!(route_id, "route1");
    }

    #[tokio::test]
    async fn test_route_request() {
        let gateway = ApiGateway::new();

        let route = Route {
            route_id: "route1".to_string(),
            path_pattern: "/api/v1/secrets/*".to_string(),
            backend_url: "http://backend:8080".to_string(),
            methods: vec!["GET".to_string()],
            rate_limit: None,
            authentication_required: false,
        };
        gateway.add_route(route).await.unwrap();

        let request = ApiRequest {
            request_id: Uuid::new_v4().to_string(),
            path: "/api/v1/secrets/test".to_string(),
            method: "GET".to_string(),
            tenant_id: None,
            timestamp: Utc::now(),
            headers: HashMap::new(),
        };

        let response = gateway.route_request(request).await.unwrap();
        assert_eq!(response.status_code, 200);
    }

    #[tokio::test]
    async fn test_token_bucket_rate_limit() {
        let gateway = ApiGateway::new();

        let route = Route {
            route_id: "route1".to_string(),
            path_pattern: "/api/test".to_string(),
            backend_url: "http://backend:8080".to_string(),
            methods: vec!["GET".to_string()],
            rate_limit: Some(RateLimit {
                algorithm: RateLimitAlgorithm::TokenBucket,
                requests_per_second: 2,
                burst_size: 2,
            }),
            authentication_required: false,
        };
        gateway.add_route(route).await.unwrap();

        let request = ApiRequest {
            request_id: Uuid::new_v4().to_string(),
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            tenant_id: None,
            timestamp: Utc::now(),
            headers: HashMap::new(),
        };

        // First two should succeed
        gateway.route_request(request.clone()).await.unwrap();
        gateway.route_request(request.clone()).await.unwrap();

        // Third should fail
        let result = gateway.route_request(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_quota_enforcement() {
        let gateway = ApiGateway::new();

        let quota = Quota {
            tenant_id: "tenant1".to_string(),
            limit: 2,
            used: 0,
            reset_at: Utc::now() + Duration::hours(1),
            quota_type: QuotaType::Daily,
        };
        gateway.set_quota(quota).await.unwrap();

        let route = Route {
            route_id: "route1".to_string(),
            path_pattern: "/api/test".to_string(),
            backend_url: "http://backend:8080".to_string(),
            methods: vec!["GET".to_string()],
            rate_limit: None,
            authentication_required: false,
        };
        gateway.add_route(route).await.unwrap();

        let request = ApiRequest {
            request_id: Uuid::new_v4().to_string(),
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            tenant_id: Some("tenant1".to_string()),
            timestamp: Utc::now(),
            headers: HashMap::new(),
        };

        // First two should succeed
        gateway.route_request(request.clone()).await.unwrap();
        gateway.route_request(request.clone()).await.unwrap();

        // Third should fail
        let result = gateway.route_request(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sliding_window_rate_limit() {
        let gateway = ApiGateway::new();

        let route = Route {
            route_id: "route1".to_string(),
            path_pattern: "/api/test".to_string(),
            backend_url: "http://backend:8080".to_string(),
            methods: vec!["GET".to_string()],
            rate_limit: Some(RateLimit {
                algorithm: RateLimitAlgorithm::SlidingWindow,
                requests_per_second: 3,
                burst_size: 3,
            }),
            authentication_required: false,
        };
        gateway.add_route(route).await.unwrap();

        let request = ApiRequest {
            request_id: Uuid::new_v4().to_string(),
            path: "/api/test".to_string(),
            method: "GET".to_string(),
            tenant_id: None,
            timestamp: Utc::now(),
            headers: HashMap::new(),
        };

        // Three requests should succeed
        for _ in 0..3 {
            gateway.route_request(request.clone()).await.unwrap();
        }

        // Fourth should fail
        let result = gateway.route_request(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_routes() {
        let gateway = ApiGateway::new();

        let route = Route {
            route_id: "route1".to_string(),
            path_pattern: "/api/test".to_string(),
            backend_url: "http://backend:8080".to_string(),
            methods: vec!["GET".to_string()],
            rate_limit: None,
            authentication_required: false,
        };
        gateway.add_route(route).await.unwrap();

        let routes = gateway.list_routes().await;
        assert_eq!(routes.len(), 1);
    }
}
