use serde::{Deserialize, Serialize};

/// Certificate Authentication Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// Enable certificate authentication
    pub enabled: bool,
    /// Certificate revocation list (CRL) URL
    pub crl_url: Option<String>,
    /// OCSP responder URL
    pub ocsp_url: Option<String>,
    /// Certificate validation level
    pub validation_level: ValidationLevel,
    /// Maximum certificate chain depth
    pub max_chain_depth: usize,
    /// Required certificate extensions
    pub required_extensions: Vec<String>,
    /// Allowed certificate issuers
    pub allowed_issuers: Vec<String>,
    /// Certificate cache TTL in seconds
    pub cert_cache_ttl: u64,
    /// Trusted root certificates (PEM format)
    pub trusted_roots: Vec<String>,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            crl_url: None,
            ocsp_url: None,
            validation_level: ValidationLevel::Standard,
            max_chain_depth: 10,
            required_extensions: vec![],
            allowed_issuers: vec![],
            cert_cache_ttl: 3600, // 1 hour
            trusted_roots: vec![],
        }
    }
}

/// Certificate validation levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationLevel {
    /// Basic validation (signature and expiry)
    Basic,
    /// Standard validation (basic + CRL/OCSP checks)
    Standard,
    /// Strict validation (standard + additional security checks)
    Strict,
}

impl CertificateConfig {
    /// Create a new certificate configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable certificate authentication
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Disable certificate authentication
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Set CRL URL
    pub fn with_crl_url(mut self, url: String) -> Self {
        self.crl_url = Some(url);
        self
    }

    /// Set OCSP URL
    pub fn with_ocsp_url(mut self, url: String) -> Self {
        self.ocsp_url = Some(url);
        self
    }

    /// Set validation level
    pub fn with_validation_level(mut self, level: ValidationLevel) -> Self {
        self.validation_level = level;
        self
    }

    /// Set maximum chain depth
    pub fn with_max_chain_depth(mut self, depth: usize) -> Self {
        self.max_chain_depth = depth;
        self
    }

    /// Add required extension
    pub fn with_required_extension(mut self, extension: String) -> Self {
        self.required_extensions.push(extension);
        self
    }

    /// Add allowed issuer
    pub fn with_allowed_issuer(mut self, issuer: String) -> Self {
        self.allowed_issuers.push(issuer);
        self
    }

    /// Set certificate cache TTL
    pub fn with_cert_cache_ttl(mut self, ttl: u64) -> Self {
        self.cert_cache_ttl = ttl;
        self
    }

    /// Add trusted root certificate
    pub fn with_trusted_root(mut self, cert_pem: String) -> Self {
        self.trusted_roots.push(cert_pem);
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_chain_depth == 0 {
            return Err("Maximum chain depth must be greater than 0".to_string());
        }

        if self.cert_cache_ttl == 0 {
            return Err("Certificate cache TTL must be greater than 0".to_string());
        }

        // Validate URLs if provided
        if let Some(ref crl_url) = self.crl_url {
            if !crl_url.starts_with("http://") && !crl_url.starts_with("https://") {
                return Err("CRL URL must be a valid HTTP/HTTPS URL".to_string());
            }
        }

        if let Some(ref ocsp_url) = self.ocsp_url {
            if !ocsp_url.starts_with("http://") && !ocsp_url.starts_with("https://") {
                return Err("OCSP URL must be a valid HTTP/HTTPS URL".to_string());
            }
        }

        Ok(())
    }

    /// Get configuration as JSON value
    pub fn to_json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    /// Load configuration from JSON value
    pub fn from_json_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CertificateConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_chain_depth, 10);
        assert_eq!(config.cert_cache_ttl, 3600);
        assert!(config.required_extensions.is_empty());
        assert!(config.allowed_issuers.is_empty());
    }

    #[test]
    fn test_config_builder() {
        let config = CertificateConfig::new()
            .with_crl_url("http://crl.example.com".to_string())
            .with_ocsp_url("http://ocsp.example.com".to_string())
            .with_validation_level(ValidationLevel::Strict)
            .with_max_chain_depth(5)
            .with_required_extension("keyUsage".to_string())
            .with_allowed_issuer("CN=Root CA,O=Company".to_string())
            .with_cert_cache_ttl(7200);

        assert_eq!(config.crl_url, Some("http://crl.example.com".to_string()));
        assert_eq!(config.ocsp_url, Some("http://ocsp.example.com".to_string()));
        assert!(matches!(config.validation_level, ValidationLevel::Strict));
        assert_eq!(config.max_chain_depth, 5);
        assert_eq!(config.required_extensions, vec!["keyUsage"]);
        assert_eq!(config.allowed_issuers, vec!["CN=Root CA,O=Company"]);
        assert_eq!(config.cert_cache_ttl, 7200);
    }

    #[test]
    fn test_config_validation() {
        let valid_config = CertificateConfig::new();
        assert!(valid_config.validate().is_ok());

        let invalid_config = CertificateConfig {
            max_chain_depth: 0,
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());

        let invalid_config = CertificateConfig {
            cert_cache_ttl: 0,
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_json_serialization() {
        let config = CertificateConfig::new()
            .with_crl_url("http://crl.example.com".to_string())
            .with_validation_level(ValidationLevel::Standard);

        let json_value = config.to_json_value().unwrap();
        let deserialized = CertificateConfig::from_json_value(json_value).unwrap();

        assert_eq!(config.crl_url, deserialized.crl_url);
        assert!(matches!(deserialized.validation_level, ValidationLevel::Standard));
    }
}
