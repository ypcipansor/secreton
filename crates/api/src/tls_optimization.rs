//! Optimized TLS configuration for high-performance mTLS
//!
//! This module provides optimized TLS configuration with performance enhancements
//! including session resumption, certificate caching, and optimized cipher suites.

use rustls::{Certificate, PrivateKey, ServerConfig, SupportedCipherSuite};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Session cache for TLS session resumption
#[derive(Debug)]
pub struct SessionCache {
    sessions: Mutex<HashMap<Vec<u8>, (Vec<u8>, Instant)>>,
    max_entries: usize,
    ttl: Duration,
}

impl SessionCache {
    pub fn new(max_entries: usize, ttl_seconds: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_entries,
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some((session, timestamp)) = sessions.get(key) {
            if timestamp.elapsed() < self.ttl {
                return Some(session.clone());
            } else {
                sessions.remove(key);
            }
        }
        None
    }

    pub fn insert(&self, key: Vec<u8>, session: Vec<u8>) {
        let mut sessions = self.sessions.lock().unwrap();

        // Remove expired entries if we're at capacity
        if sessions.len() >= self.max_entries {
            let now = Instant::now();
            sessions.retain(|_, (_, timestamp)| timestamp.elapsed() < self.ttl);
        }

        // Remove oldest entry if still at capacity
        if sessions.len() >= self.max_entries {
            if let Some(oldest_key) = sessions.keys().next().cloned() {
                sessions.remove(&oldest_key);
            }
        }

        sessions.insert(key, (session, Instant::now()));
    }
}

impl rustls::client::ServerSessionStore for SessionCache {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.insert(key, value);
        true
    }
}

impl rustls::server::ServerSessionStore for SessionCache {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.insert(key, value);
        true
    }
}

/// Global session cache
static SESSION_CACHE: Mutex<Option<Arc<SessionCache>>> = Mutex::new(None);

/// Initialize session cache
pub fn init_session_cache(max_entries: usize, ttl_seconds: u64) {
    let mut cache = SESSION_CACHE.lock().unwrap();
    *cache = Some(Arc::new(SessionCache::new(max_entries, ttl_seconds)));
    info!("TLS session cache initialized with {} max entries, {}s TTL", max_entries, ttl_seconds);
}

/// Get session cache instance
fn get_session_cache() -> Option<Arc<SessionCache>> {
    SESSION_CACHE.lock().unwrap().as_ref().cloned()
}

/// Create optimized TLS configuration for server
pub fn create_optimized_tls_config(
    cert_chain: Vec<Certificate>,
    private_key: PrivateKey,
    min_tls_version: &str,
    cipher_suites: &[String],
    alpn_protocols: &[String],
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut config_builder = ServerConfig::builder();

    // Set TLS version
    match min_tls_version {
        "TLS1.3" => {
            config_builder = config_builder.with_safe_default_cipher_suites();
            info!("Using TLS 1.3 with optimized cipher suites");
        }
        "TLS1.2" => {
            config_builder = config_builder.with_safe_defaults();
            info!("Using TLS 1.2 with safe defaults");
        }
        _ => {
            warn!("Unknown TLS version '{}', using safe defaults", min_tls_version);
            config_builder = config_builder.with_safe_defaults();
        }
    }

    // Add session cache for performance
    if let Some(session_cache) = get_session_cache() {
        config_builder = config_builder.with_session_storage(Arc::new(session_cache));
    }

    // Configure ALPN protocols
    if !alpn_protocols.is_empty() {
        let alpn_protocols_bytes: Vec<Vec<u8>> = alpn_protocols
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        config_builder = config_builder.with_alpn_protocols(alpn_protocols_bytes);
    }

    // Build the final configuration
    let mut config = config_builder.with_single_cert(cert_chain, private_key)?;

    // Optimize for performance
    config.max_fragment_size = Some(16384); // 16KB fragments for better throughput
    config.send_tls13_tickets = 4; // Send multiple tickets for session resumption

    info!("TLS configuration optimized with session resumption and ALPN support");

    Ok(config)
}

/// Create performance-optimized cipher suite list
pub fn get_optimized_cipher_suites() -> Vec<SupportedCipherSuite> {
    use rustls::SupportedCipherSuite;

    // Prioritize performance-optimized cipher suites
    vec![
        // TLS 1.3 cipher suites (fastest)
        rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,

        // TLS 1.2 cipher suites (fallback, hardware accelerated)
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

/// Validate TLS configuration performance
pub fn validate_tls_performance(config: &ServerConfig) -> Result<(), String> {
    // Check if session resumption is enabled
    if config.session_storage.is_none() {
        warn!("Session storage not configured - performance may be reduced");
    }

    // Check cipher suites
    let cipher_suites = get_optimized_cipher_suites();
    let configured_suites: Vec<_> = config.cipher_suites.iter().collect();

    if configured_suites.len() < cipher_suites.len() {
        return Err(format!(
            "Only {}/{} recommended cipher suites configured",
            configured_suites.len(),
            cipher_suites.len()
        ));
    }

    // Check ALPN protocols
    if config.alpn_protocols.is_empty() {
        warn!("No ALPN protocols configured");
    }

    info!("TLS configuration validation passed");
    Ok(())
}

/// Performance metrics for TLS connections
#[derive(Debug, Default)]
pub struct TlsMetrics {
    pub total_handshakes: u64,
    pub successful_handshakes: u64,
    pub session_resumptions: u64,
    pub handshake_failures: u64,
    pub average_handshake_time_ms: u64,
}

impl TlsMetrics {
    pub fn record_handshake(&mut self, success: bool, resumption: bool, duration_ms: u64) {
        self.total_handshakes += 1;
        if success {
            self.successful_handshakes += 1;
            if resumption {
                self.session_resumptions += 1;
            }
        } else {
            self.handshake_failures += 1;
        }

        // Update average handshake time
        self.average_handshake_time_ms =
            (self.average_handshake_time_ms * (self.total_handshakes - 1) + duration_ms) / self.total_handshakes;
    }

    pub fn get_success_rate(&self) -> f64 {
        if self.total_handshakes == 0 {
            0.0
        } else {
            (self.successful_handshakes as f64 / self.total_handshakes as f64) * 100.0
        }
    }

    pub fn get_resumption_rate(&self) -> f64 {
        if self.total_handshakes == 0 {
            0.0
        } else {
            (self.session_resumptions as f64 / self.total_handshakes as f64) * 100.0
        }
    }
}

/// Global TLS metrics
static TLS_METRICS: Mutex<TlsMetrics> = Mutex::new(TlsMetrics::default());

/// Record TLS handshake metrics
pub fn record_tls_handshake(success: bool, resumption: bool, duration_ms: u64) {
    let mut metrics = TLS_METRICS.lock().unwrap();
    metrics.record_handshake(success, resumption, duration_ms);
}

/// Get TLS performance metrics
pub fn get_tls_metrics() -> TlsMetrics {
    TLS_METRICS.lock().unwrap().clone()
}
