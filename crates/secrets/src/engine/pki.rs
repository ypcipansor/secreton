//! PKI secret engine for certificate management

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// PKI secret engine
pub struct PkiEngine {
    config: PkiConfig,
    enabled: bool,
}

impl PkiEngine {
    pub fn new(config: PkiConfig) -> Self {
        Self {
            config,
            enabled: false,
        }
    }
}

#[async_trait]
impl SecretEngine for PkiEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Pki
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        if let Some(pki_config) = config.config.get("pki")
            && let Ok(pki_config) = serde_json::from_value(pki_config.clone())
        {
            self.config = pki_config;
        }

        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, _path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("pki".to_string()));
        }
        Ok(None)
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("pki".to_string()));
        }

        // Basic certificate generation for PKI engine
        match path {
            "issue" => {
                // Generate certificate based on CSR or parameters
                let cert_data = self.generate_certificate(&data).await?;
                Ok(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: cert_data,
                    metadata: SecretMetadata {
                        version: 1,
                        created_by: "pki-engine".to_string(),
                        updated_by: "pki-engine".to_string(),
                        lease_id: None,
                        lease_duration: Some(self.config.default_lease_ttl),
                        ..Default::default()
                    },
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
            }
            _ => Err(SecretError::InvalidPath(format!(
                "Unsupported PKI path: {}",
                path
            ))),
        }
    }

    async fn delete(&mut self, _path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("pki".to_string()));
        }
        Ok(())
    }

    async fn list(&self, _path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("pki".to_string()));
        }
        Ok(vec![])
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

impl PkiEngine {
    /// Generate a certificate based on request data
    async fn generate_certificate(
        &self,
        data: &HashMap<String, Value>,
    ) -> SecretResult<HashMap<String, Value>> {
        // Extract certificate parameters
        let common_name = data
            .get("common_name")
            .and_then(|v| v.as_str())
            .unwrap_or("example.com");

        let organization = data
            .get("organization")
            .and_then(|v| v.as_str())
            .unwrap_or("Example Organization");

        let organizational_unit = data.get("organizational_unit").and_then(|v| v.as_str());

        let country = data.get("country").and_then(|v| v.as_str()).unwrap_or("US");

        let state = data.get("state").and_then(|v| v.as_str());

        let locality = data.get("locality").and_then(|v| v.as_str());

        let _email = data.get("email").and_then(|v| v.as_str());

        let ttl_seconds = data
            .get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.config.default_lease_ttl);

        let key_type = data
            .get("key_type")
            .and_then(|v| v.as_str())
            .unwrap_or("rsa");

        let key_bits = data
            .get("key_bits")
            .and_then(|v| v.as_u64())
            .unwrap_or(2048);

        // Generate key pair based on key type
        let key_pair = match key_type {
            "rsa" => match key_bits {
                2048 => rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).map_err(|e| {
                    SecretError::InvalidConfiguration(format!("Failed to generate RSA key: {}", e))
                })?,
                3072 => rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA384).map_err(|e| {
                    SecretError::InvalidConfiguration(format!("Failed to generate RSA key: {}", e))
                })?,
                4096 => rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA512).map_err(|e| {
                    SecretError::InvalidConfiguration(format!("Failed to generate RSA key: {}", e))
                })?,
                _ => {
                    return Err(SecretError::InvalidConfiguration(
                        "Unsupported RSA key size. Use 2048, 3072, or 4096".to_string(),
                    ));
                }
            },
            "ecdsa" => match key_bits {
                256 => {
                    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| {
                        SecretError::InvalidConfiguration(format!(
                            "Failed to generate ECDSA key: {}",
                            e
                        ))
                    })?
                }
                384 => {
                    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).map_err(|e| {
                        SecretError::InvalidConfiguration(format!(
                            "Failed to generate ECDSA key: {}",
                            e
                        ))
                    })?
                }
                _ => {
                    return Err(SecretError::InvalidConfiguration(
                        "Unsupported ECDSA key size. Use 256 or 384".to_string(),
                    ));
                }
            },
            "ed25519" => rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|e| {
                SecretError::InvalidConfiguration(format!("Failed to generate Ed25519 key: {}", e))
            })?,
            _ => {
                return Err(SecretError::InvalidConfiguration(
                    "Unsupported key type. Use 'rsa', 'ecdsa', or 'ed25519'".to_string(),
                ));
            }
        };

        // Create certificate parameters
        let mut params = CertificateParams::new(vec![common_name.to_string()]).map_err(|e| {
            SecretError::InvalidConfiguration(format!("Failed to create certificate params: {}", e))
        })?;

        // Set subject
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, organization);
        if let Some(ou) = organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        dn.push(DnType::CountryName, country);
        if let Some(st) = state {
            dn.push(DnType::StateOrProvinceName, st);
        }
        if let Some(l) = locality {
            dn.push(DnType::LocalityName, l);
        }
        params.distinguished_name = dn;

        // Set validity period
        use std::time::SystemTime;
        let now = SystemTime::now();
        let not_after = now + std::time::Duration::from_secs(ttl_seconds);

        params.not_before = now.into();
        params.not_after = not_after.into();

        // Set key usage
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        // Set extended key usage for server authentication
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Generate self-signed certificate
        let cert = params.self_signed(&key_pair).map_err(|e| {
            SecretError::InvalidConfiguration(format!("Failed to generate certificate: {}", e))
        })?;

        // Get certificate and key in PEM format
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Generate serial number
        let serial_number = format!("{:x}", uuid::Uuid::new_v4().as_u128());

        let mut cert_data = HashMap::new();
        cert_data.insert("certificate".to_string(), Value::String(cert_pem));
        cert_data.insert("private_key".to_string(), Value::String(key_pem));
        cert_data.insert("serial_number".to_string(), Value::String(serial_number));
        cert_data.insert(
            "common_name".to_string(),
            Value::String(common_name.to_string()),
        );
        cert_data.insert(
            "organization".to_string(),
            Value::String(organization.to_string()),
        );
        cert_data.insert("key_type".to_string(), Value::String(key_type.to_string()));
        cert_data.insert("key_bits".to_string(), Value::Number(key_bits.into()));
        cert_data.insert("ttl".to_string(), Value::Number(ttl_seconds.into()));

        Ok(cert_data)
    }
}
