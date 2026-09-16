//! Per-client rate limiting.
//!
//! Replaces a process-global `Mutex<Option<RateLimitState>>` that was installed by an
//! `init_rate_limiting()` call at startup: if that call was skipped — as it was whenever
//! `rate_limit.enabled` was false — the limiter silently did nothing, and its
//! `.lock().unwrap()` sat on an async path where a poisoned lock would take the process
//! down. This uses `governor`, which was already a dependency and unused.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use secreton_domain::SecretonError;

use crate::error::ApiError;

type Limiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Shared limiter plus the proxy configuration used to identify a client.
#[derive(Clone)]
pub struct RateLimit {
    limiter: Arc<Limiter>,
    /// How many reverse proxies sit in front of this process.
    ///
    /// `X-Forwarded-For` is appended to by each hop, so with `n` trusted proxies the
    /// client address is the `n`-th entry counted from the right. Anything further left
    /// was supplied by the client and is forgeable. Zero — the default — means the header
    /// is ignored entirely and the socket peer address is used, which is correct when the
    /// process is exposed directly.
    trusted_proxies: usize,
}

impl std::fmt::Debug for RateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimit")
            .field("trusted_proxies", &self.trusted_proxies)
            .finish_non_exhaustive()
    }
}

impl RateLimit {
    /// `per_minute` requests per client, with a burst of the same size.
    pub fn new(per_minute: u32, trusted_proxies: usize) -> Self {
        let quota = NonZeroU32::new(per_minute.max(1))
            .map(Quota::per_minute)
            .unwrap_or_else(|| Quota::per_minute(NonZeroU32::MIN));
        Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
            trusted_proxies,
        }
    }

    /// Resolve the client address for rate-limiting purposes.
    pub fn client_ip(&self, request: &Request, peer: Option<SocketAddr>) -> Option<IpAddr> {
        if self.trusted_proxies == 0 {
            return peer.map(|p| p.ip());
        }

        let forwarded = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())?;

        let entries: Vec<&str> = forwarded.split(',').map(str::trim).collect();

        // Count `trusted_proxies` back from the right. Taking the first entry trusts
        // whatever the client wrote; taking the last gives the address the nearest proxy
        // observed, which is the proxy in front of it, not the client.
        entries
            .len()
            .checked_sub(self.trusted_proxies)
            .and_then(|i| entries.get(i))
            .and_then(|s| s.parse::<IpAddr>().ok())
            .or_else(|| peer.map(|p| p.ip()))
    }
}

pub async fn enforce(
    State(limit): State<RateLimit>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);

    // A request whose client cannot be identified is let through rather than blocked:
    // failing closed here would take the service down for everyone the moment
    // `ConnectInfo` were not wired up.
    let Some(ip) = limit.client_ip(&request, peer) else {
        return Ok(next.run(request).await);
    };

    if limit.limiter.check_key(&ip).is_err() {
        tracing::warn!(client_ip = %ip, "rate limit exceeded");
        return Err(ApiError(SecretonError::RateLimitExceeded {
            message: "too many requests".to_string(),
        }));
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request_with_xff(value: &str) -> Request {
        Request::builder()
            .uri("/")
            .header("x-forwarded-for", value)
            .body(Body::empty())
            .expect("request")
    }

    fn peer(ip: &str) -> Option<SocketAddr> {
        Some(SocketAddr::new(ip.parse().unwrap(), 1234))
    }

    #[test]
    fn without_trusted_proxies_the_header_is_ignored_entirely() {
        let limit = RateLimit::new(60, 0);
        let req = request_with_xff("1.1.1.1, 2.2.2.2");
        assert_eq!(
            limit.client_ip(&req, peer("10.0.0.5")),
            Some("10.0.0.5".parse::<IpAddr>().unwrap()),
            "a directly exposed server must not trust a client-supplied header"
        );
    }

    #[test]
    fn one_trusted_proxy_takes_the_last_entry() {
        let limit = RateLimit::new(60, 1);
        // The single proxy appended the address it saw: the real client.
        let req = request_with_xff("203.0.113.9");
        assert_eq!(
            limit.client_ip(&req, peer("10.0.0.5")),
            Some("203.0.113.9".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn a_spoofed_prefix_cannot_change_the_identified_client() {
        let limit = RateLimit::new(60, 1);
        // The client wrote "1.2.3.4"; the trusted proxy appended what it actually saw.
        // Counting from the right ignores the forged prefix.
        let req = request_with_xff("1.2.3.4, 203.0.113.9");
        assert_eq!(
            limit.client_ip(&req, peer("10.0.0.5")),
            Some("203.0.113.9".parse::<IpAddr>().unwrap()),
            "taking the first XFF entry would let any client choose its own rate-limit key"
        );
    }

    #[test]
    fn two_trusted_proxies_count_two_back() {
        let limit = RateLimit::new(60, 2);
        let req = request_with_xff("1.2.3.4, 203.0.113.9, 10.0.0.1");
        assert_eq!(
            limit.client_ip(&req, peer("10.0.0.5")),
            Some("203.0.113.9".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn a_short_header_falls_back_to_the_peer_rather_than_panicking() {
        let limit = RateLimit::new(60, 3);
        let req = request_with_xff("203.0.113.9");
        assert_eq!(
            limit.client_ip(&req, peer("10.0.0.5")),
            Some("10.0.0.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn the_quota_is_enforced_per_client_not_globally() {
        let limit = RateLimit::new(2, 0);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();

        assert!(limit.limiter.check_key(&a).is_ok());
        assert!(limit.limiter.check_key(&a).is_ok());
        assert!(limit.limiter.check_key(&a).is_err(), "a should be limited");
        assert!(
            limit.limiter.check_key(&b).is_ok(),
            "one noisy client must not exhaust another client's quota"
        );
    }
}
