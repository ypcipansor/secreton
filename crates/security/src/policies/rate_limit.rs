//! Rate Limiter
//!
//! Request rate limiting and throttling for performance protection
//! and abuse prevention.

use chrono::{DateTime, Utc};
use secreton_errors::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Rate limit strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitStrategy {
    /// Token bucket algorithm
    TokenBucket {
        /// Maximum tokens in bucket
        capacity: u32,
        /// Token refill rate per second
        refill_rate: u32,
    },

    /// Sliding window
    SlidingWindow {
        /// Maximum requests in window
        max_requests: u32,
        /// Window duration in seconds
        window_seconds: u64,
    },

    /// Fixed window
    FixedWindow {
        /// Maximum requests per window
        max_requests: u32,
        /// Window duration in seconds
        window_seconds: u64,
    },
}

/// Rate limiter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Strategy
    pub strategy: RateLimitStrategy,

    /// Whether to enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            strategy: RateLimitStrategy::TokenBucket {
                capacity: 100,
                refill_rate: 10,
            },
            enabled: true,
        }
    }
}

/// Token bucket state
#[derive(Debug, Clone)]
struct TokenBucketState {
    tokens: f64,
    capacity: u32,
    refill_rate: u32,
    last_update: DateTime<Utc>,
}

impl TokenBucketState {
    fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            tokens: capacity as f64,
            capacity,
            refill_rate,
            last_update: Utc::now(),
        }
    }

    fn refill(&mut self) {
        let now = Utc::now();
        let elapsed = (now - self.last_update).num_milliseconds() as f64 / 1000.0;

        self.tokens = (self.tokens + elapsed * self.refill_rate as f64).min(self.capacity as f64);
        self.last_update = now;
    }

    fn consume(&mut self, tokens: u32) -> bool {
        self.refill();

        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }
}

/// Sliding window state
#[derive(Debug, Clone)]
struct SlidingWindowState {
    requests: VecDeque<DateTime<Utc>>,
    max_requests: u32,
    window_seconds: u64,
}

impl SlidingWindowState {
    fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            requests: VecDeque::new(),
            max_requests,
            window_seconds,
        }
    }

    fn cleanup(&mut self) {
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(self.window_seconds as i64);

        while let Some(timestamp) = self.requests.front() {
            if *timestamp < window_start {
                self.requests.pop_front();
            } else {
                break;
            }
        }
    }

    fn check(&mut self) -> bool {
        self.cleanup();

        if self.requests.len() < self.max_requests as usize {
            self.requests.push_back(Utc::now());
            true
        } else {
            false
        }
    }
}

/// Rate limiter state
#[derive(Debug, Clone)]
enum LimiterState {
    TokenBucket(TokenBucketState),
    SlidingWindow(SlidingWindowState),
}

/// Rate limiter service
pub struct RateLimiter {
    _config: Arc<RwLock<RateLimitConfig>>,
    states: Arc<RwLock<HashMap<String, LimiterState>>>,
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(_config: RateLimitConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(_config)),
            states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if _request is allowed
    pub async fn check(&self, _key: &str) -> Result<bool, SecretonError> {
        let _config = self._config.read().await;

        if !_config.enabled {
            return Ok(true);
        }

        let strategy = _config.strategy.clone();
        drop(_config);

        let mut states = self.states.write().await;

        let state = states
            .entry(_key.to_string())
            .or_insert_with(|| match &strategy {
                RateLimitStrategy::TokenBucket {
                    capacity,
                    refill_rate,
                } => LimiterState::TokenBucket(TokenBucketState::new(*capacity, *refill_rate)),
                RateLimitStrategy::SlidingWindow {
                    max_requests,
                    window_seconds,
                } => LimiterState::SlidingWindow(SlidingWindowState::new(
                    *max_requests,
                    *window_seconds,
                )),
                RateLimitStrategy::FixedWindow {
                    max_requests,
                    window_seconds,
                } => LimiterState::SlidingWindow(SlidingWindowState::new(
                    *max_requests,
                    *window_seconds,
                )),
            });

        let allowed = match state {
            LimiterState::TokenBucket(bucket) => bucket.consume(1),
            LimiterState::SlidingWindow(window) => window.check(),
        };

        if allowed {
            Ok(true)
        } else {
            Err(SecretonError::RateLimitExceeded {
                message: "Too many requests, please try again later".to_string(),
            })
        }
    }

    /// Check with custom cost
    pub async fn check_with_cost(&self, _key: &str, cost: u32) -> Result<bool, SecretonError> {
        let _config = self._config.read().await;

        if !_config.enabled {
            return Ok(true);
        }

        let strategy = _config.strategy.clone();
        drop(_config);

        let mut states = self.states.write().await;

        let state = states
            .entry(_key.to_string())
            .or_insert_with(|| match &strategy {
                RateLimitStrategy::TokenBucket {
                    capacity,
                    refill_rate,
                } => LimiterState::TokenBucket(TokenBucketState::new(*capacity, *refill_rate)),
                RateLimitStrategy::SlidingWindow {
                    max_requests,
                    window_seconds,
                } => LimiterState::SlidingWindow(SlidingWindowState::new(
                    *max_requests,
                    *window_seconds,
                )),
                RateLimitStrategy::FixedWindow {
                    max_requests,
                    window_seconds,
                } => LimiterState::SlidingWindow(SlidingWindowState::new(
                    *max_requests,
                    *window_seconds,
                )),
            });

        let allowed = match state {
            LimiterState::TokenBucket(bucket) => bucket.consume(cost),
            LimiterState::SlidingWindow(_) => {
                // For sliding window, check multiple times for cost
                for _ in 0..cost {
                    if let LimiterState::SlidingWindow(window) = state
                        && !window.check()
                    {
                        return Err(SecretonError::RateLimitExceeded {
                            message: "Too many requests, please try again later".to_string(),
                        });
                    }
                }
                true
            }
        };

        if allowed {
            Ok(true)
        } else {
            Err(SecretonError::RateLimitExceeded {
                message: "Too many requests, please try again later".to_string(),
            })
        }
    }

    /// Reset rate limit for _key
    pub async fn reset(&self, _key: &str) {
        let mut states = self.states.write().await;
        states.remove(_key);
    }

    /// Update configuration
    pub async fn update_config(&self, _config: RateLimitConfig) {
        let mut current = self._config.write().await;
        *current = _config;
    }

    /// Get current configuration
    pub async fn get_config(&self) -> RateLimitConfig {
        let _config = self._config.read().await;
        _config.clone()
    }

    /// Clear all states
    pub async fn clear(&self) {
        let mut states = self.states.write().await;
        states.clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket() {
        let _config = RateLimitConfig {
            strategy: RateLimitStrategy::TokenBucket {
                capacity: 10,
                refill_rate: 1,
            },
            enabled: true,
        };

        let limiter = RateLimiter::new(_config);

        // Should allow up to capacity
        for _ in 0..10 {
            assert!(limiter.check("user1").await.is_ok());
        }

        // Should reject after capacity
        assert!(limiter.check("user1").await.is_err());
    }

    #[tokio::test]
    async fn test_sliding_window() {
        let _config = RateLimitConfig {
            strategy: RateLimitStrategy::SlidingWindow {
                max_requests: 5,
                window_seconds: 60,
            },
            enabled: true,
        };

        let limiter = RateLimiter::new(_config);

        // Should allow up to max
        for _ in 0..5 {
            assert!(limiter.check("user1").await.is_ok());
        }

        // Should reject after max
        assert!(limiter.check("user1").await.is_err());
    }

    #[tokio::test]
    async fn test_reset() {
        let _config = RateLimitConfig {
            strategy: RateLimitStrategy::TokenBucket {
                capacity: 2,
                refill_rate: 1,
            },
            enabled: true,
        };

        let limiter = RateLimiter::new(_config);

        // Exhaust limit
        limiter.check("user1").await.unwrap();
        limiter.check("user1").await.unwrap();
        assert!(limiter.check("user1").await.is_err());

        // Reset and should work again
        limiter.reset("user1").await;
        assert!(limiter.check("user1").await.is_ok());
    }
}
