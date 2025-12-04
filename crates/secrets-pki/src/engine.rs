//! PKI engine implementation

use crate::error::PkiError;
use crate::model::{
    CertificateRequest, CertificateResponse, PkiConfig, RevocationReason, SshKeyRequest,
    SshKeyResponse,
};
use chrono::{DateTime, Duration, Utc};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use ssh_key::{Algorithm, PrivateKey};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Revoked certificate entry
#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub revocation_time: DateTime<Utc>,
    pub reason: RevocationReason,
}

/// PKI secret engine for certificate management
pub struct PkiEngine {
    config: PkiConfig,
    /// Certificate revocation list (serial_number -> revocation info)
    revoked_certificates: Arc<RwLock<HashMap<String, RevokedCertificate>>>,
    /// Issued certificates (serial_number -> certificate details)
    issued_certificates: Arc<RwLock<HashMap<String, IssuedCertificate>>>,
}

/// Issued certificate record
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub serial_number: String,
    pub common_name: String,
    pub certificate_pem: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PkiEngine {
    pub fn new(config: PkiConfig) -> Self {
        Self {
            config,
            revoked_certificates: Arc::new(RwLock::new(HashMap::new())),
            issued_certificates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a certificate from a request
    pub async fn generate_certificate(
        &self,
        request: &CertificateRequest,
    ) -> Result<CertificateResponse, PkiError> {
        // Create certificate parameters
        let mut params = CertificateParams::new(vec![request.common_name.clone()])
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        if let Some(org) = &request.organization {
            dn.push(DnType::OrganizationName, org);
        }
        if let Some(ou) = &request.organizational_unit {
            dn.push(DnType::OrganizationalUnitName, ou);
        }
        if let Some(country) = &request.country {
            dn.push(DnType::CountryName, country);
        }
        if let Some(state) = &request.state {
            dn.push(DnType::StateOrProvinceName, state);
        }
        if let Some(locality) = &request.locality {
            dn.push(DnType::LocalityName, locality);
        }
        params.distinguished_name = dn;

        // Set validity period
        let ttl = request.ttl.unwrap_or(self.config.default_lease_ttl);
        let not_before_chrono = Utc::now();
        let not_after_chrono = not_before_chrono + Duration::seconds(ttl);

        // rcgen uses time crate internally, convert from chrono
        params.not_before = time::OffsetDateTime::from_unix_timestamp(
            not_before_chrono.timestamp(),
        )
        .map_err(|e| PkiError::CertificateGeneration(format!("Invalid timestamp: {}", e)))?;
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after_chrono.timestamp())
            .map_err(|e| PkiError::CertificateGeneration(format!("Invalid timestamp: {}", e)))?;

        // Add subject alternative names
        for dns_name in &request.alt_names {
            let ia5 = Ia5String::try_from(dns_name.as_str())
                .map_err(|_| PkiError::CertificateGeneration("Invalid DNS name".to_string()))?;
            params.subject_alt_names.push(SanType::DnsName(ia5));
        }
        for ip in &request.ip_addresses {
            if let Ok(ip_addr) = ip.parse() {
                params.subject_alt_names.push(SanType::IpAddress(ip_addr));
            }
        }
        for email in &request.email_addresses {
            let ia5 = Ia5String::try_from(email.as_str()).map_err(|_| {
                PkiError::CertificateGeneration("Invalid email address".to_string())
            })?;
            params.subject_alt_names.push(SanType::Rfc822Name(ia5));
        }

        // Generate certificate and key pair
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Convert to PEM format
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Generate serial number (simplified)
        let serial_number = format!("{:x}", rand::random::<u64>());

        // Store issued certificate for tracking
        let issued_cert = IssuedCertificate {
            serial_number: serial_number.clone(),
            common_name: request.common_name.clone(),
            certificate_pem: cert_pem.clone(),
            issued_at: not_before_chrono,
            expires_at: not_after_chrono,
        };
        self.issued_certificates
            .write()
            .await
            .insert(serial_number.clone(), issued_cert);

        Ok(CertificateResponse {
            certificate: cert_pem,
            private_key: key_pem,
            serial_number,
            issuing_ca: self.config.ca_cert.clone().unwrap_or_default(),
            ca_chain: vec![], // Would include CA chain in full implementation
            expiration: not_after_chrono,
            revocation_time: None,
        })
    }

    /// Generate SSH keys
    pub async fn generate_ssh_key(
        &self,
        request: &SshKeyRequest,
    ) -> Result<SshKeyResponse, PkiError> {
        // Determine algorithm based on request
        let algorithm = match &request.key_type {
            crate::model::SshKeyType::Rsa => Algorithm::Rsa { hash: None },
            crate::model::SshKeyType::Ed25519 => Algorithm::Ed25519,
            crate::model::SshKeyType::Ecdsa => Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        };

        // Generate private key
        let private_key = PrivateKey::random(&mut rand::thread_rng(), algorithm).map_err(|e| {
            PkiError::SshKeyGeneration(format!("Failed to generate private key: {}", e))
        })?;

        // Serialize to OpenSSH format
        let private_key_pem = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| {
                PkiError::SshKeyGeneration(format!("Failed to serialize private key: {}", e))
            })?;

        // Generate public key
        let public_key = private_key.public_key();
        let public_key_openssh = public_key.to_openssh().map_err(|e| {
            PkiError::SshKeyGeneration(format!("Failed to serialize public key: {}", e))
        })?;

        // Calculate expiration
        let ttl = request.ttl.unwrap_or(self.config.default_lease_ttl);
        let expiration = Utc::now() + Duration::seconds(ttl);

        Ok(SshKeyResponse {
            private_key: private_key_pem.to_string(),
            public_key: public_key_openssh.to_string(),
            certificate: None, // Not implemented yet
            key_type: request.key_type.clone(),
            expiration: Some(expiration),
        })
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(
        &self,
        request: &crate::model::RevocationRequest,
    ) -> Result<(), PkiError> {
        // Check if the certificate exists
        let issued_certs = self.issued_certificates.read().await;
        if !issued_certs.contains_key(&request.serial_number) {
            return Err(PkiError::CertificateNotFound(request.serial_number.clone()));
        }
        drop(issued_certs);

        // Check if already revoked
        let revoked = self.revoked_certificates.read().await;
        if revoked.contains_key(&request.serial_number) {
            return Err(PkiError::CertificateRevocation(format!(
                "Certificate {} is already revoked",
                request.serial_number
            )));
        }
        drop(revoked);

        // Add to revocation list
        let revoked_cert = RevokedCertificate {
            serial_number: request.serial_number.clone(),
            revocation_time: Utc::now(),
            reason: request.reason.clone(),
        };

        self.revoked_certificates
            .write()
            .await
            .insert(request.serial_number.clone(), revoked_cert);

        tracing::info!(
            "Certificate {} revoked with reason: {:?}",
            request.serial_number,
            request.reason
        );

        Ok(())
    }

    /// Check if a certificate is revoked
    pub async fn is_certificate_revoked(&self, serial_number: &str) -> bool {
        self.revoked_certificates
            .read()
            .await
            .contains_key(serial_number)
    }

    /// Get certificate revocation information
    pub async fn get_revocation_info(
        &self,
        serial_number: &str,
    ) -> Option<RevokedCertificate> {
        self.revoked_certificates
            .read()
            .await
            .get(serial_number)
            .cloned()
    }

    /// Generate a Certificate Revocation List (CRL)
    pub async fn generate_crl(&self) -> Result<crate::model::CrlResponse, PkiError> {
        let revoked = self.revoked_certificates.read().await;
        let now = Utc::now();
        let next_update = now + Duration::hours(24); // CRL valid for 24 hours

        // Build CRL data (simplified PEM representation)
        let mut crl_data = String::new();
        crl_data.push_str("-----BEGIN X509 CRL-----\n");
        crl_data.push_str(&format!("# CRL Generated: {}\n", now.to_rfc3339()));
        crl_data.push_str(&format!("# Next Update: {}\n", next_update.to_rfc3339()));
        crl_data.push_str(&format!("# Total Revoked Certificates: {}\n", revoked.len()));
        
        for (serial, info) in revoked.iter() {
            crl_data.push_str(&format!(
                "# Serial: {} | Revoked: {} | Reason: {:?}\n",
                serial,
                info.revocation_time.to_rfc3339(),
                info.reason
            ));
        }
        
        crl_data.push_str("-----END X509 CRL-----\n");

        Ok(crate::model::CrlResponse {
            crl: crl_data,
            last_update: now,
            next_update,
        })
    }

    /// List all revoked certificates
    pub async fn list_revoked_certificates(&self) -> Vec<RevokedCertificate> {
        self.revoked_certificates
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// List all issued certificates
    pub async fn list_issued_certificates(&self) -> Vec<IssuedCertificate> {
        self.issued_certificates
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Get CA information
    pub async fn get_ca_info(&self) -> Result<crate::model::CaInfo, PkiError> {
        // For now, generate a default self-signed CA
        // TODO: Implement proper CA certificate parsing when PEM crate API is available
        self.generate_default_ca_info().await
    }

    /// Generate default CA info for development/testing
    async fn generate_default_ca_info(&self) -> Result<crate::model::CaInfo, PkiError> {
        use crate::model::CaInfo;

        // Create default CA parameters
        let mut params = CertificateParams::new(vec!["Secreton CA".to_string()])
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Set CA distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "Secreton Security");
        dn.push(DnType::OrganizationalUnitName, "Certificate Authority");
        dn.push(DnType::CountryName, "US");
        dn.push(DnType::StateOrProvinceName, "CA");
        dn.push(DnType::LocalityName, "San Francisco");
        params.distinguished_name = dn;

        // Set as CA certificate
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set validity (10 years)
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + time::Duration::days(3650);
        params.not_before = not_before;
        params.not_after = not_after;

        // Generate key pair
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Generate self-signed CA certificate
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Extract information
        let subject = extract_dn_info(&cert);
        let issuer = extract_dn_info(&cert);

        // Get key info - pass key_pair not certificate
        let key_info = extract_key_info(&key_pair);

        Ok(CaInfo {
            certificate: cert.pem(),
            public_key: key_info.public_key_pem,
            key_type: key_info.key_type,
            key_bits: key_info.key_bits,
            signature_algorithm: "SHA256withRSA".to_string(), // default
            subject,
            issuer,
            valid_from: chrono::DateTime::from_timestamp(not_before.unix_timestamp(), 0)
                .ok_or_else(|| {
                    PkiError::InvalidCaConfiguration("Invalid validity start".to_string())
                })?,
            valid_until: chrono::DateTime::from_timestamp(not_after.unix_timestamp(), 0)
                .ok_or_else(|| {
                    PkiError::InvalidCaConfiguration("Invalid validity end".to_string())
                })?,
        })
    }
}

/// Extract key information from certificate and key pair
fn extract_key_info(key_pair: &rcgen::KeyPair) -> KeyInfo {
    // Get the public key PEM from the key pair
    KeyInfo {
        public_key_pem: key_pair.public_key_pem(),
        key_type: "ECDSA".to_string(), // rcgen uses ECDSA by default
        key_bits: 256, // P-256 curve
    }
}

/// Extract distinguished name info from rcgen certificate
fn extract_dn_info(_cert: &rcgen::Certificate) -> HashMap<String, String> {
    // For rcgen certificates, we can't easily extract DN info from the built certificate
    // This is a simplified implementation - return default values
    let mut info = HashMap::new();
    info.insert("common_name".to_string(), "Secreton CA".to_string());
    info.insert("organization".to_string(), "Secreton Security".to_string());
    info.insert(
        "organizational_unit".to_string(),
        "Certificate Authority".to_string(),
    );
    info.insert("country".to_string(), "US".to_string());
    info.insert("state".to_string(), "CA".to_string());
    info.insert("locality".to_string(), "San Francisco".to_string());
    info
}

/// Key information structure
struct KeyInfo {
    public_key_pem: String,
    key_type: String,
    key_bits: usize,
}
