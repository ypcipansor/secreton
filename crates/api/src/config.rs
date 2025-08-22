//! Configuration management for the Brankas API server.
//! 
//! Provides comprehensive configuration options for HTTP/gRPC servers,
//! authentication, authorization, rate limiting, and security features.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Main API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// HTTP server configuration
    pub http: HttpConfig,
    
    /// gRPC server configuration  
    pub grpc: GrpcConfig,
    
    /// Authentication configuration
    pub auth: AuthConfig,
    
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    
    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
    
    /// CORS configuration
    pub cors: CorsConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Address to bind HTTP server
    pub bind_address: SocketAddr,
    
    /// Request timeout
    pub timeout: Duration,
    
    /// Maximum request body size (bytes)
    pub max_body_size: usize,
    
    /// Keep-alive timeout
    pub keep_alive: Duration,
    
    /// Enable compression
    pub compression: bool,
    
    /// Enable static file serving
    pub static_files: Option<StaticFilesConfig>,
}

/// gRPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Enable gRPC server
    pub enabled: bool,
    
    /// Address to bind gRPC server
    pub bind_address: SocketAddr,
    
    /// Request timeout
    pub timeout: Duration,
    
    /// Maximum message size (bytes)
    pub max_message_size: usize,
    
    /// Enable reflection
    pub reflection: bool,
    
    /// Enable health check service
    pub health_check: bool,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT configuration
    pub jwt: JwtConfig,
    
    /// OAuth2 configuration
    pub oauth2: Option<OAuth2Config>,
    
    /// mTLS configuration
    pub mtls: Option<MtlsConfig>,
    
    /// Session configuration
    pub session: SessionConfig,
    
    /// Multi-factor authentication
    pub mfa: MfaConfig,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT signing secret
    pub secret: String,
    
    /// Token expiration time
    pub expiration: Duration,
    
    /// Refresh token expiration
    pub refresh_expiration: Duration,
    
    /// JWT algorithm
    pub algorithm: String,
    
    /// Issuer
    pub issuer: String,
    
    /// Audience
    pub audience: String,
}

/// OAuth2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    /// OAuth2 provider URLs
    pub providers: Vec<OAuth2Provider>,
    
    /// Redirect URL
    pub redirect_url: String,
    
    /// Scopes to request
    pub scopes: Vec<String>,
}

/// OAuth2 provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Provider {
    /// Provider name
    pub name: String,
    
    /// Client ID
    pub client_id: String,
    
    /// Client secret
    pub client_secret: String,
    
    /// Authorization URL
    pub auth_url: String,
    
    /// Token URL
    pub token_url: String,
    
    /// User info URL
    pub user_info_url: String,
}

/// mTLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    /// Require client certificates
    pub required: bool,
    
    /// CA certificate path
    pub ca_cert: PathBuf,
    
    /// Allowed client certificate subjects
    pub allowed_subjects: Vec<String>,
    
    /// Certificate revocation list
    pub crl: Option<PathBuf>,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session timeout
    pub timeout: Duration,
    
    /// Session store type
    pub store: SessionStore,
    
    /// Cookie configuration
    pub cookie: CookieConfig,
}

/// Session store types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SessionStore {
    Memory,
    Redis { url: String },
    Database { table: String },
}

/// Cookie configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieConfig {
    /// Cookie name
    pub name: String,
    
    /// Cookie domain
    pub domain: Option<String>,
    
    /// Cookie path
    pub path: String,
    
    /// Secure flag
    pub secure: bool,
    
    /// HttpOnly flag
    pub http_only: bool,
    
    /// SameSite policy
    pub same_site: String,
}

/// Multi-factor authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    /// Enable MFA
    pub enabled: bool,
    
    /// TOTP configuration
    pub totp: TotpConfig,
    
    /// SMS configuration
    pub sms: Option<SmsConfig>,
    
    /// Email configuration
    pub email: Option<EmailConfig>,
    
    /// WebAuthn configuration
    pub webauthn: Option<WebAuthnConfig>,
}

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Issuer name
    pub issuer: String,
    
    /// Secret length
    pub secret_length: usize,
    
    /// Time step (seconds)
    pub time_step: u64,
    
    /// Code length
    pub code_length: usize,
    
    /// Clock skew tolerance
    pub skew_tolerance: u64,
}

/// SMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    /// SMS provider
    pub provider: String,
    
    /// API key
    pub api_key: String,
    
    /// From number
    pub from_number: String,
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server
    pub smtp_server: String,
    
    /// SMTP port
    pub smtp_port: u16,
    
    /// Username
    pub username: String,
    
    /// Password
    pub password: String,
    
    /// From address
    pub from_address: String,
    
    /// Use TLS
    pub use_tls: bool,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying party name
    pub rp_name: String,
    
    /// Relying party ID
    pub rp_id: String,
    
    /// Origin
    pub origin: String,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    
    /// Global rate limits
    pub global: RateLimitRule,
    
    /// Per-endpoint rate limits
    pub endpoints: Vec<EndpointRateLimit>,
    
    /// Per-user rate limits
    pub per_user: Option<RateLimitRule>,
    
    /// Per-IP rate limits
    pub per_ip: Option<RateLimitRule>,
}

/// Rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Requests per time window
    pub requests: u32,
    
    /// Time window duration
    pub window: Duration,
    
    /// Burst size
    pub burst: Option<u32>,
}

/// Endpoint-specific rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRateLimit {
    /// Endpoint pattern
    pub pattern: String,
    
    /// Rate limit rule
    pub rule: RateLimitRule,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate file path
    pub cert_file: PathBuf,
    
    /// Private key file path
    pub key_file: PathBuf,
    
    /// CA certificate file path
    pub ca_file: Option<PathBuf>,
    
    /// Minimum TLS version
    pub min_version: String,
    
    /// Cipher suites
    pub cipher_suites: Vec<String>,
    
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable metrics
    pub metrics: bool,
    
    /// Metrics endpoint
    pub metrics_path: String,
    
    /// Health check endpoint
    pub health_path: String,
    
    /// Enable tracing
    pub tracing: bool,
    
    /// Jaeger configuration
    pub jaeger: Option<JaegerConfig>,
}

/// Jaeger tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaegerConfig {
    /// Jaeger endpoint
    pub endpoint: String,
    
    /// Service name
    pub service_name: String,
    
    /// Sample rate
    pub sample_rate: f64,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Enable CORS
    pub enabled: bool,
    
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    
    /// Exposed headers
    pub exposed_headers: Vec<String>,
    
    /// Max age
    pub max_age: Option<Duration>,
    
    /// Allow credentials
    pub allow_credentials: bool,
}

/// Static files configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFilesConfig {
    /// Static files directory
    pub directory: PathBuf,
    
    /// URL path prefix
    pub path_prefix: String,
    
    /// Enable directory listing
    pub directory_listing: bool,
    
    /// Default index file
    pub index_file: Option<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    
    /// Log format
    pub format: String,
    
    /// Enable JSON logging
    pub json: bool,
    
    /// Log file path
    pub file: Option<PathBuf>,
    
    /// Log rotation
    pub rotation: Option<LogRotationConfig>,
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum file size
    pub max_size: u64,
    
    /// Maximum number of files
    pub max_files: u32,
    
    /// Rotation frequency
    pub frequency: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            http: HttpConfig::default(),
            grpc: GrpcConfig::default(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitConfig::default(),
            tls: None,
            monitoring: MonitoringConfig::default(),
            cors: CorsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8080".parse().unwrap(),
            timeout: Duration::from_secs(30),
            max_body_size: 16 * 1024 * 1024, // 16MB
            keep_alive: Duration::from_secs(75),
            compression: true,
            static_files: None,
        }
    }
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: "127.0.0.1:9090".parse().unwrap(),
            timeout: Duration::from_secs(30),
            max_message_size: 4 * 1024 * 1024, // 4MB
            reflection: false,
            health_check: true,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig::default(),
            oauth2: None,
            mtls: None,
            session: SessionConfig::default(),
            mfa: MfaConfig::default(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "change-this-secret-in-production".to_string(),
            expiration: Duration::from_secs(3600), // 1 hour
            refresh_expiration: Duration::from_secs(86400 * 7), // 7 days
            algorithm: "HS256".to_string(),
            issuer: "brankas".to_string(),
            audience: "secreton-api".to_string(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3600), // 1 hour
            store: SessionStore::Memory,
            cookie: CookieConfig::default(),
        }
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "secreton-session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: false,
            http_only: true,
            same_site: "Strict".to_string(),
        }
    }
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            totp: TotpConfig::default(),
            sms: None,
            email: None,
            webauthn: None,
        }
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "Brankas".to_string(),
            secret_length: 32,
            time_step: 30,
            code_length: 6,
            skew_tolerance: 1,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global: RateLimitRule {
                requests: 1000,
                window: Duration::from_secs(60),
                burst: Some(100),
            },
            endpoints: vec![],
            per_user: Some(RateLimitRule {
                requests: 100,
                window: Duration::from_secs(60),
                burst: Some(10),
            }),
            per_ip: Some(RateLimitRule {
                requests: 200,
                window: Duration::from_secs(60),
                burst: Some(20),
            }),
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics: true,
            metrics_path: "/metrics".to_string(),
            health_path: "/health".to_string(),
            tracing: true,
            jaeger: None,
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(), 
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            exposed_headers: vec![],
            max_age: Some(Duration::from_secs(3600)),
            allow_credentials: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            json: false,
            file: None,
            rotation: None,
        }
    }
}
