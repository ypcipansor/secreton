use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{Utc, Duration};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use crate::storage::Storage;
use crate::models::lease::Lease;
// use crate::crypto::{Certificate, PrivateKey, PublicKey, SignatureAlgorithm}; // TODO: Implement crypto types
use crate::models::pki::{PkiCa, PkiCert};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    pub ca_private_key: String,
    pub ca_certificate: String,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_servers: Vec<String>,
    pub max_ttl: i64,
    pub default_ttl: i64,
    pub enforce_hostnames: bool,
    pub allowed_domains: Vec<String>,
    pub allow_subdomains: bool,
    pub allow_glob_domains: bool,
    pub allow_any_name: bool,
    pub server_flag: bool,
    pub client_flag: bool,
    pub code_signing_flag: bool,
    pub email_protection_flag: bool,
    pub key_usage: Vec<String>,
    pub ext_key_usage: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub ip_sans: Vec<String>,
    pub uri_sans: Vec<String>,
    pub other_sans: Vec<String>,
    pub ttl: Option<i64>,
    pub not_before_duration: Option<i64>,
    pub key_type: String,
    pub key_bits: u32,
    pub signature_algorithm: String,
    pub exclude_cn_from_sans: bool,
    pub ou: Vec<String>,
    pub organization: Vec<String>,
    pub country: Vec<String>,
    pub locality: Vec<String>,
    pub province: Vec<String>,
    pub street_address: Vec<String>,
    pub postal_code: Vec<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    pub certificate: String,
    pub issuing_ca: String,
    pub ca_chain: Vec<String>,
    pub private_key: Option<String>,
    pub private_key_type: String,
    pub serial_number: String,
    pub lease_id: String,
    pub lease_duration: i64,
    pub renewable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    pub serial_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationResponse {
    pub revocation_time: i64,
    pub revocation_time_rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlResponse {
    pub crl: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaResponse {
    pub certificate: String,
    pub issuing_ca: String,
    pub ca_chain: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateListResponse {
    pub keys: Vec<String>,
    pub key_info: HashMap<String, CertificateInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub serial_number: String,
    pub certificate: String,
    pub issuing_ca: String,
    pub ca_chain: Vec<String>,
    pub revocation_time: Option<i64>,
    pub revocation_time_rfc3339: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChallenge {
    pub type_: String,
    pub status: String,
    pub url: String,
    pub token: String,
    pub validated: Option<String>,
    pub error: Option<AcmeError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeError {
    pub type_: String,
    pub detail: String,
}

pub struct PkiSecretsEngine {
    config: PkiConfig,
    ca_private_key: String, // TODO: Use PrivateKey type
    ca_certificate: String, // TODO: Use Certificate type
    issued_certificates: Arc<RwLock<HashMap<String, PkiCert>>>,
    revoked_certificates: Arc<RwLock<HashMap<String, PkiCert>>>,
    storage: Arc<Storage>,
}

impl PkiSecretsEngine {
    pub async fn new(config: PkiConfig, storage: Arc<Storage>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Parse PEM certificates properly
        let ca_private_key = config.ca_private_key.clone(); // TODO: Use PrivateKey::from_pem
        let ca_certificate = config.ca_certificate.clone(); // TODO: Use Certificate::from_pem

        // Load existing certificates from storage
        let issued_certificates = Self::load_certificates_from_storage(&storage, "issued").await?;
        let revoked_certificates = Self::load_certificates_from_storage(&storage, "revoked").await?;

        Ok(Self {
            config,
            ca_private_key,
            ca_certificate,
            issued_certificates: Arc::new(RwLock::new(issued_certificates)),
            revoked_certificates: Arc::new(RwLock::new(revoked_certificates)),
            storage,
        })
    }

    async fn load_certificates_from_storage(
        storage: &Storage,
        cert_type: &str,
    ) -> Result<HashMap<String, PkiCert>, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("pki/{}/certificates", cert_type);
        match storage.get(&key).await {
            Ok(Some(entry)) => {
                let certs: HashMap<String, PkiCert> = serde_json::from_slice(&entry.value)?;
                Ok(certs)
            }
            _ => Ok(HashMap::new()),
        }
    }

    async fn save_certificates_to_storage(
        &self,
        cert_type: &str,
        certificates: &HashMap<String, PkiCert>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("pki/{}/certificates", cert_type);
        let data = serde_json::to_vec(certificates)?;
        let entry = crate::storage::StorageEntry {
            key: key.clone(),
            value: data,
            metadata: HashMap::new(),
        };
        self.storage.put(entry).await?;
        Ok(())
    }

    pub async fn issue_certificate(
        &self,
        request: CertificateRequest,
        lease_duration: i64,
    ) -> Result<CertificateResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Validate request
        self.validate_certificate_request(&request).await?;

        // Generate private key
        let private_key = self.generate_private_key(&request.key_type, request.key_bits)?;

        // Generate certificate
        let certificate = self.generate_certificate(&request, &private_key).await?;

        // Create PKI certificate record
        let serial_number = certificate.serial_number()?;
        let pki_cert = PkiCert {
            serial_number: serial_number.clone(),
            certificate: certificate.to_pem()?,
            revocation_time: None,
            revocation_time_rfc3339: None,
            issuing_ca: self.ca_certificate.to_pem()?,
            ca_chain: vec![self.ca_certificate.to_pem()?],
            private_key: Some(private_key.to_pem()?),
            private_key_type: request.key_type.clone(),
            common_name: request.common_name.clone(),
            alt_names: request.alt_names.clone(),
            ip_sans: request.ip_sans.clone(),
            uri_sans: request.uri_sans.clone(),
            other_sans: request.other_sans.clone(),
            ou: request.ou.clone(),
            organization: request.organization.clone(),
            country: request.country.clone(),
            locality: request.locality.clone(),
            province: request.province.clone(),
            street_address: request.street_address.clone(),
            postal_code: request.postal_code.clone(),
            not_before: Utc::now(),
            not_after: Utc::now() + Duration::seconds(request.ttl.unwrap_or(self.config.default_ttl)),
        };

        // Store certificate
        {
            let mut issued = self.issued_certificates.write().await;
            issued.insert(serial_number.clone(), pki_cert.clone());
        }
        self.save_certificates_to_storage("issued", &{
            let issued = self.issued_certificates.read().await;
            issued.clone()
        }).await?;

        // Create lease
        let lease_id = format!("pki/cert/{}", serial_number);
        let lease = crate::services::lease::create_lease(
            &self.storage,
            "pki-engine",
            "certificate",
            &serial_number,
            lease_duration,
        ).await?;

        Ok(CertificateResponse {
            certificate: pki_cert.certificate.clone(),
            issuing_ca: pki_cert.issuing_ca.clone(),
            ca_chain: pki_cert.ca_chain.clone(),
            private_key: pki_cert.private_key.clone(),
            private_key_type: pki_cert.private_key_type.clone(),
            serial_number,
            lease_id,
            lease_duration,
            renewable: true,
        })
    }

    pub async fn revoke_certificate(
        &self,
        request: RevocationRequest,
    ) -> Result<RevocationResponse, Box<dyn std::error::Error + Send + Sync>> {
        let serial_number = request.serial_number;

        // Find certificate in issued certificates
        let certificate = {
            let issued = self.issued_certificates.read().await;
            issued.get(&serial_number).cloned()
        };

        if let Some(mut cert) = certificate {
            // Move to revoked certificates
            let revocation_time = Utc::now();
            cert.revocation_time = Some(revocation_time.timestamp());
            cert.revocation_time_rfc3339 = Some(revocation_time.to_rfc3339());

            {
                let mut revoked = self.revoked_certificates.write().await;
                revoked.insert(serial_number.clone(), cert.clone());
            }

            // Remove from issued certificates
            {
                let mut issued = self.issued_certificates.write().await;
                issued.remove(&serial_number);
            }

            // Save changes
            self.save_certificates_to_storage("issued", &{
                let issued = self.issued_certificates.read().await;
                issued.clone()
            }).await?;
            self.save_certificates_to_storage("revoked", &{
                let revoked = self.revoked_certificates.read().await;
                revoked.clone()
            }).await?;

            Ok(RevocationResponse {
                revocation_time: revocation_time.timestamp(),
                revocation_time_rfc3339: revocation_time.to_rfc3339(),
            })
        } else {
            Err(format!("Certificate with serial number {} not found", serial_number).into())
        }
    }

    pub async fn get_certificate(
        &self,
        serial_number: &str,
    ) -> Result<CertificateInfo, Box<dyn std::error::Error + Send + Sync>> {
        // Check issued certificates first
        {
            let issued = self.issued_certificates.read().await;
            if let Some(cert) = issued.get(serial_number) {
                return Ok(CertificateInfo {
                    serial_number: cert.serial_number.clone(),
                    certificate: cert.certificate.clone(),
                    issuing_ca: cert.issuing_ca.clone(),
                    ca_chain: cert.ca_chain.clone(),
                    revocation_time: None,
                    revocation_time_rfc3339: None,
                });
            }
        }

        // Check revoked certificates
        {
            let revoked = self.revoked_certificates.read().await;
            if let Some(cert) = revoked.get(serial_number) {
                return Ok(CertificateInfo {
                    serial_number: cert.serial_number.clone(),
                    certificate: cert.certificate.clone(),
                    issuing_ca: cert.issuing_ca.clone(),
                    ca_chain: cert.ca_chain.clone(),
                    revocation_time: cert.revocation_time,
                    revocation_time_rfc3339: cert.revocation_time_rfc3339.clone(),
                });
            }
        }

        Err(format!("Certificate with serial number {} not found", serial_number).into())
    }

    pub async fn list_certificates(&self) -> Result<CertificateListResponse, Box<dyn std::error::Error + Send + Sync>> {
        let mut keys = Vec::new();
        let mut key_info = HashMap::new();

        // Add issued certificates
        {
            let issued = self.issued_certificates.read().await;
            for (serial, cert) in issued.iter() {
                keys.push(serial.clone());
                key_info.insert(serial.clone(), CertificateInfo {
                    serial_number: cert.serial_number.clone(),
                    certificate: cert.certificate.clone(),
                    issuing_ca: cert.issuing_ca.clone(),
                    ca_chain: cert.ca_chain.clone(),
                    revocation_time: None,
                    revocation_time_rfc3339: None,
                });
            }
        }

        // Add revoked certificates
        {
            let revoked = self.revoked_certificates.read().await;
            for (serial, cert) in revoked.iter() {
                if !keys.contains(serial) {
                    keys.push(serial.clone());
                }
                key_info.insert(serial.clone(), CertificateInfo {
                    serial_number: cert.serial_number.clone(),
                    certificate: cert.certificate.clone(),
                    issuing_ca: cert.issuing_ca.clone(),
                    ca_chain: cert.ca_chain.clone(),
                    revocation_time: cert.revocation_time,
                    revocation_time_rfc3339: cert.revocation_time_rfc3339.clone(),
                });
            }
        }

        Ok(CertificateListResponse { keys, key_info })
    }

    pub async fn get_ca_certificate(&self) -> Result<CaResponse, Box<dyn std::error::Error + Send + Sync>> {
        Ok(CaResponse {
            certificate: self.ca_certificate.to_pem()?,
            issuing_ca: self.ca_certificate.to_pem()?,
            ca_chain: vec![self.ca_certificate.to_pem()?],
        })
    }

    pub async fn get_crl(&self) -> Result<CrlResponse, Box<dyn std::error::Error + Send + Sync>> {
        let revoked = self.revoked_certificates.read().await;
        let mut revoked_serials = Vec::new();

        for cert in revoked.values() {
            revoked_serials.push(cert.serial_number.clone());
        }

        // Generate CRL (simplified implementation)
        let crl = self.generate_crl(revoked_serials).await?;

        Ok(CrlResponse {
            crl,
            format: "pem".to_string(),
        })
    }

    pub async fn rotate_crl(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a full implementation, this would regenerate the CRL
        // For now, we'll just mark that it needs rotation
        let key = "pki/crl/needs_rotation";
        let data = b"true";
        let entry = crate::storage::StorageEntry {
            key: key.to_string(),
            value: data.to_vec(),
            metadata: HashMap::new(),
        };
        self.storage.put(entry).await?;
        Ok(())
    }

    pub async fn get_acme_challenge(
        &self,
        token: &str,
    ) -> Result<AcmeChallenge, Box<dyn std::error::Error + Send + Sync>> {
        // Simplified ACME challenge implementation
        // In a full implementation, this would handle ACME protocol properly
        let challenge = AcmeChallenge {
            type_: "http-01".to_string(),
            status: "pending".to_string(),
            url: format!("https://example.com/acme/challenge/{}", token),
            token: token.to_string(),
            validated: None,
            error: None,
        };

        Ok(challenge)
    }

    async fn validate_certificate_request(
        &self,
        request: &CertificateRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Validate common name
        if request.common_name.is_empty() {
            return Err("Common name cannot be empty".into());
        }

        // Validate TTL
        let ttl = request.ttl.unwrap_or(self.config.default_ttl);
        if ttl > self.config.max_ttl {
            return Err(format!("TTL {} exceeds maximum allowed TTL {}", ttl, self.config.max_ttl).into());
        }

        // Validate domains if hostname enforcement is enabled
        if self.config.enforce_hostnames {
            self.validate_hostname(&request.common_name)?;
            for alt_name in &request.alt_names {
                self.validate_hostname(alt_name)?;
            }
        }

        Ok(())
    }

    fn validate_hostname(&self, hostname: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if hostname is in allowed domains
        if !self.config.allowed_domains.is_empty() {
            let mut allowed = false;
            for allowed_domain in &self.config.allowed_domains {
                if hostname == allowed_domain {
                    allowed = true;
                    break;
                }
                if self.config.allow_subdomains && hostname.ends_with(&format!(".{}", allowed_domain)) {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Err(format!("Hostname {} is not in allowed domains", hostname).into());
            }
        }

        Ok(())
    }

    fn generate_private_key(
        &self,
        key_type: &str,
        key_bits: u32,
    ) -> Result<PrivateKey, Box<dyn std::error::Error + Send + Sync>> {
        match key_type {
            "rsa" => PrivateKey::generate_rsa(key_bits),
            "ec" => PrivateKey::generate_ec(key_bits),
            "ed25519" => PrivateKey::generate_ed25519(),
            _ => Err(format!("Unsupported key type: {}", key_type).into()),
        }
    }

    async fn generate_certificate(
        &self,
        request: &CertificateRequest,
        private_key: &PrivateKey,
    ) -> Result<Certificate, Box<dyn std::error::Error + Send + Sync>> {
        // This is a simplified certificate generation
        // In a full implementation, this would use a proper X.509 library
        let public_key = private_key.public_key()?;

        let mut cert_builder = Certificate::builder()?;

        // Set subject
        cert_builder.subject_common_name(&request.common_name)?;

        if !request.organization.is_empty() {
            cert_builder.subject_organization(&request.organization[0])?;
        }

        if !request.country.is_empty() {
            cert_builder.subject_country(&request.country[0])?;
        }

        // Set validity period
        let not_before = Utc::now();
        let not_after = not_before + Duration::seconds(request.ttl.unwrap_or(self.config.default_ttl));
        cert_builder.validity_period(not_before, not_after)?;

        // Set public key
        cert_builder.public_key(&public_key)?;

        // Set extensions
        if self.config.server_flag {
            cert_builder.key_usage_server()?;
        }

        if self.config.client_flag {
            cert_builder.key_usage_client()?;
        }

        // Sign certificate
        let signature_algorithm = match request.signature_algorithm.as_str() {
            "SHA256WithRSA" => SignatureAlgorithm::Sha256WithRsa,
            "SHA384WithRSA" => SignatureAlgorithm::Sha384WithRsa,
            "SHA512WithRSA" => SignatureAlgorithm::Sha512WithRsa,
            "ECDSAWithSHA256" => SignatureAlgorithm::EcdsaWithSha256,
            "Ed25519" => SignatureAlgorithm::Ed25519,
            _ => SignatureAlgorithm::Sha256WithRsa,
        };

        let certificate = cert_builder.sign(&self.ca_private_key, signature_algorithm)?;

        Ok(certificate)
    }

    async fn generate_crl(
        &self,
        revoked_serials: Vec<String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Simplified CRL generation
        // In a full implementation, this would generate a proper CRL
        let mut crl_content = String::new();
        crl_content.push_str("-----BEGIN X509 CRL-----\n");
        crl_content.push_str("MIIBvjCBowIBATANBgkqhkiG9w0BAQsFADCB...\n");
        crl_content.push_str("-----END X509 CRL-----\n");

        Ok(crl_content)
    }
}

pub async fn create_lease_for_pki_certificate(
    storage: &Storage,
    serial_number: &str,
    ttl_seconds: i64,
) -> Result<Lease, Box<dyn std::error::Error + Send + Sync>> {
    let lease = crate::services::lease::create_lease(
        storage,
        "pki-engine",
        "certificate",
        serial_number,
        ttl_seconds,
    ).await?;

    Ok(lease)
}

pub async fn revoke_lease_for_pki_certificate(
    storage: &Storage,
    lease_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    crate::services::lease::revoke_lease(storage, lease_id).await?;
    Ok(())
}
