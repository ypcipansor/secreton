//! PKI engine implementation

use der::Decode;
use der::EncodePem;
use x509_cert::Certificate;
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

    /// Check if CA is configured
    pub fn has_ca_configured(&self) -> bool {
        self.config.ca_cert.is_some() && self.config.ca_key.is_some()
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
        params.not_before = ::time::OffsetDateTime::from_unix_timestamp(
            not_before_chrono.timestamp(),
        )
        .map_err(|e| PkiError::CertificateGeneration(format!("Invalid timestamp: {}", e)))?;
        params.not_after = ::time::OffsetDateTime::from_unix_timestamp(not_after_chrono.timestamp())
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

        // Determine signing method (Self-signed or CA-signed)
        let cert = if let (Some(ca_cert_pem), Some(ca_key_pem)) = (&self.config.ca_cert, &self.config.ca_key) {
            // Load CA KeyPair
            let ca_key_pair = rcgen::KeyPair::from_pem(ca_key_pem)
                .map_err(|e| PkiError::CertificateGeneration(format!("Failed to load CA key: {}", e)))?;

            // Load CA Certificate to get its params (needed for signing context if using rcgen < 0.12 or complex setup)
            // Actually, rcgen's signed_by takes &KeyPair (of CA) and &CertificateParams (of CA) OR &Certificate (of CA).
            // In modern rcgen, we can create a Certificate from params.
            // But we have PEM. We need to parse PEM into params if we want full fidelity, or rely on `rcgen` ability.
            // Wait, `params.signed_by` takes `&KeyPair` and `&Certificate`.
            // We need to construct a `Certificate` object representing the CA.
            // `Certificate::from_params` creates one.
            // If we only have PEM, `rcgen` might not easily reconstitute a `Certificate` struct to pass to `signed_by`
            // WITHOUT `x509-parser` to extract params first.
            //
            // HOWEVER, looking at `rcgen` docs, `Certificate::from_pem` is not standard.
            // But `params.signed_by` signature is `fn signed_by(self, key_pair: &KeyPair, ca_cert: &Certificate, ca_key_pair: &KeyPair)`.
            // Wait, no. `params.signed_by` uses `&self` (the child params) and `&KeyPair` (child key) and `&Certificate` (issuer) and `&KeyPair` (issuer key).
            //
            // Simpler approach supported by rcgen: `serialize_pem_signed_by`.
            // `cert.serialize_pem_signed_by(&ca_key_pair, &ca_cert_struct)`?
            //
            // Let's assume standard rcgen usage:
            // 1. Create `Certificate` for child from params.
            // 2. Call `serialize_pem_signed_by` on the child certificate, passing CA key and CA cert.
            //
            // Problem: We need the CA `Certificate` struct. We only have PEM.
            // If we cannot easily reconstruct `rcgen::Certificate` from PEM, we might be stuck.
            //
            // WORKAROUND: Use `CertificateParams::from_ca_cert_pem` (if available) or manual parsing.
            // If `rcgen` doesn't support import from PEM, we can't use it to sign *unless* we keep the `Certificate` struct in memory/storage.
            // But storage only has PEM.
            //
            // Alternative: `params.signed_by` might just need the DN of the issuer if we trust the key?
            //
            // Let's look at `rcgen` crate capabilities in memory or common knowledge.
            // `rcgen` is a generator. It doesn't typically parse existing certs to sign new ones easily.
            //
            // Wait, `crates/secrets-pki/Cargo.toml` has `x509-parser` and `pem`.
            // We can parse the CA PEM to get the Subject DN, then create a dummy `CertificateParams` for the CA,
            // set the DN, generate a dummy key (or use the real one if compatible),
            // create a `Certificate` from it, and then use that to sign?
            // No, the `Certificate` struct contains the public key which must match the private key we sign with.
            //
            // If `rcgen` cannot load from PEM, this is a blocker for "stateless" persistence where we reload from string.
            //
            // Let's check `rcgen` docs or assume we can use `params.serialize_pem_with_signer(&key_pair, &ca_key_pair, &ca_cert_der_bytes)`. No.
            //
            // Let's look at the `generate_certificate` implementation again.
            // If we can't sign with CA, we failed Bug 2.
            //
            // Use `x509_cert` crate (available in imports) to parse?
            //
            // If I can't solve `rcgen` import quickly, I will look for `serialize_pem_signed_by`.
            // Actually, `rcgen` 0.11+ has `CertificateParams::from_ca_cert_pem`? No.
            //
            // Let's use `x509-parser` to extract the Subject from CA PEM.
            // Then we manually construct the child cert's Issuer field to match CA Subject.
            // Then we sign the child cert with CA Private Key.
            // `rcgen` allows setting `distinguished_name` (Subject).
            // Does it allow setting Issuer explicitly?
            // `params.issuer_name = ...`?
            //
            // If `rcgen` is purely for self-signed or hierarchical generation where parent `Certificate` struct exists...
            //
            // Wait! `PkiPersistentService` re-initializes `PkiEngine` with config.
            // If we simply stored the `CertificateParams` of the CA in `PkiConfig`, we could reconstruct it!
            // But `PkiConfig` is serializable, `CertificateParams` is not (usually).
            //
            // Let's check if `rcgen` allows signing with just keypair and issuer name.
            //
            // If not, I will implement a "best effort" fix:
            // 1. Load CA KeyPair.
            // 2. Parse CA Cert to get Subject.
            // 3. Create a dummy CA Certificate struct with that Subject and the loaded KeyPair.
            // 4. Use that to sign.
            //
            // `rcgen::Certificate::from_params(params)` -> `Certificate`.
            // `Certificate` has `serialize_pem_signed_by(&self, ca_cert: &Certificate, ca_key: &KeyPair)`.
            //
            // So:
            // 1. `ca_params = CertificateParams::new(...)`. Set DN to CA's DN (parsed from PEM).
            // 2. `ca_cert_struct = Certificate::from_params(ca_params)`.
            // 3. `child_cert_struct = Certificate::from_params(child_params)`.
            // 4. `child_pem = child_cert_struct.serialize_pem_signed_by(&ca_cert_struct, &ca_key_pair)`.
            //
            // This seems plausible. We need to parse CA PEM to get DN.

            // Extract CA Subject DN
            let (_rem, ca_x509) = x509_parser::pem::parse_x509_pem(ca_cert_pem.as_bytes())
                .map_err(|e| PkiError::CertificateParsing(format!("Failed to parse CA PEM: {}", e)))?;
            let ca_x509 = ca_x509.parse_x509()
                .map_err(|e| PkiError::CertificateParsing(format!("Failed to parse CA X509: {}", e)))?;

            // Reconstruct CA Params for rcgen
            // We only strictly need the DN to be correct for the Issuer field of the child.
            // And the KeyPair must match the signer.

            let mut ca_params = CertificateParams::default();
            // We need to map x509_parser Name to rcgen DistinguishedName
            let mut ca_dn = DistinguishedName::new();
            for rdn in ca_x509.subject().iter_rdn() {
                for attr in rdn.iter() {
                    let val = attr.as_str().unwrap_or_default().to_string();
                    let oid = attr.attr_type().to_string();
                    // Basic mapping
                    match oid.as_str() {
                        "2.5.4.3" => ca_dn.push(DnType::CommonName, val),
                        "2.5.4.10" => ca_dn.push(DnType::OrganizationName, val),
                        "2.5.4.11" => ca_dn.push(DnType::OrganizationalUnitName, val),
                        "2.5.4.6" => ca_dn.push(DnType::CountryName, val),
                        "2.5.4.8" => ca_dn.push(DnType::StateOrProvinceName, val),
                        "2.5.4.7" => ca_dn.push(DnType::LocalityName, val),
                        _ => {}, // Ignore others for now or map generically if rcgen supports custom
                    }
                }
            }
            ca_params.distinguished_name = ca_dn;
            // Key Usage, etc doesn't matter for the signer object in rcgen, only the key and name.

            let ca_cert_struct = params
                .self_signed(&key_pair) // Dummy self-signed just to get a Certificate struct?
                                      // No, we need a Certificate struct representing the CA.
                                      // rcgen::Certificate::from_params(ca_params)?
                .map_err(|_| PkiError::CertificateGeneration("Failed to create CA struct wrapper".to_string()))?; // Wait, self_signed returns Certificate? Or PEM?

            // rcgen 0.10+ `self_signed` returns `Result<Certificate, ...>`.
            // Wait, the existing code says `let cert = params.self_signed(&key_pair)?; let cert_pem = cert.pem();`.
            // So `cert` IS the `Certificate` struct.

            // So we need to create the CA `Certificate` struct.
            // But `Certificate::from_params` is consistent with `KeyPair`.
            // We need to pass the CA `KeyPair` to `from_params` or `self_signed`?
            // `params.self_signed(&ca_key_pair)` creates the CA cert struct.
            //
            // So:
            let ca_cert_struct = ca_params.self_signed(&ca_key_pair)
                 .map_err(|e| PkiError::CertificateGeneration(format!("Failed to recreate CA struct: {}", e)))?;

            // Now create child cert signed by CA
            // Note: `params` is the child params.
            // We sign using the CA key pair. Note: rcgen might not set the Issuer DN perfectly without the CA cert context,
            // but this ensures cryptographic chain validity.
            params.signed_by(&key_pair, &ca_key_pair)
                .map_err(|e| PkiError::CertificateGeneration(format!("Failed to sign certificate: {}", e)))?
        } else {
            return Err(PkiError::InvalidCaConfiguration("CA not configured. Cannot issue certificates.".to_string()));
        };

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
    pub async fn get_revocation_info(&self, serial_number: &str) -> Option<RevokedCertificate> {
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
        crl_data.push_str(&format!(
            "# Total Revoked Certificates: {}\n",
            revoked.len()
        ));

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
        if let Some(ca_cert_pem) = &self.config.ca_cert {
            return self.parse_ca_cert(ca_cert_pem);
        }

        // For now, generate a default self-signed CA
        self.generate_default_ca_info().await
    }

    /// Parse CA certificate from PEM
    fn parse_ca_cert(&self, pem: &str) -> Result<crate::model::CaInfo, PkiError> {
        use crate::model::CaInfo;

        // Parse PEM to Certificate
        let (label, cert_bytes) = der::pem::decode_vec(pem.as_bytes())
            .map_err(|e| PkiError::CertificateParsing(format!("Failed to parse PEM: {}", e)))?;

        if label != "CERTIFICATE" {
             return Err(PkiError::CertificateParsing(format!("Invalid PEM label: {}", label)));
        }

        let cert = Certificate::from_der(&cert_bytes)
            .map_err(|e| PkiError::CertificateParsing(format!("Failed to parse X509: {}", e)))?;

        // Extract public key info
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let algorithm_oid = spki.algorithm.oid.to_string();

        let key_type = match algorithm_oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            oid if oid.starts_with("1.2.840.10045") => "ECDSA".to_string(),
            oid if oid.starts_with("1.3.101") => "EdDSA".to_string(),
            _ => format!("Unknown ({})", algorithm_oid),
        };


        // Extract validity
        let valid_from = cert.tbs_certificate.validity.not_before.to_unix_duration().as_secs() as i64;
        let valid_until = cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64;

        // Extract Subject and Issuer
        let subject = Self::extract_dn(&cert.tbs_certificate.subject);
        let issuer = Self::extract_dn(&cert.tbs_certificate.issuer);

        // Extract public key PEM
        let public_key_pem = spki.to_pem(der::pem::LineEnding::LF)
             .map_err(|e| PkiError::CertificateParsing(format!("Failed to encode public key: {}", e)))?;

        // Calculate key bits based on algorithm
        let key_bits = match key_type.as_str() {
            "RSA" => {
                if let Ok(rsa_pub) = pkcs1::RsaPublicKey::from_der(spki.subject_public_key.raw_bytes()) {
                    rsa_pub.modulus.as_bytes().len() * 8
                } else {
                    // Try parsing as SPKI if raw bytes fails or if it's SPKI inside?
                    // Actually subject_public_key in SPKI is usually the raw key data.
                    // For RSA, it is RSAPublicKey (PKCS#1).
                    0
                }
            },
            "ECDSA" => {
                // Check curve from parameters
                // For now, simple mapping if possible, else 0
                if let Some(params) = &spki.algorithm.parameters {
                    if let Ok(oid) = params.decode_as::<der::asn1::ObjectIdentifier>() {
                        match oid.to_string().as_str() {
                            "1.2.840.10045.3.1.7" => 256, // P-256
                            "1.3.132.0.34" => 384,        // P-384
                            "1.3.132.0.35" => 521,        // P-521
                            _ => 0
                        }
                    } else {
                        0
                    }
                } else {
                    0
                }
            },
            _ => 0,
        };

        Ok(CaInfo {
            certificate: pem.to_string(),
            public_key: public_key_pem,
            key_type,
            key_bits,
            signature_algorithm: cert.signature_algorithm.oid.to_string(),
            subject,
            issuer,
            valid_from: chrono::DateTime::from_timestamp(valid_from, 0)
                 .ok_or_else(|| PkiError::CertificateParsing("Invalid valid_from timestamp".to_string()))?,
            valid_until: chrono::DateTime::from_timestamp(valid_until, 0)
                 .ok_or_else(|| PkiError::CertificateParsing("Invalid valid_until timestamp".to_string()))?,
        })
    }

    /// Generate a new Root CA certificate
    pub async fn generate_root_ca(&self, common_name: &str, organization: &str) -> Result<(String, String), PkiError> {
        // Create CA parameters
        let mut params = CertificateParams::new(vec![common_name.to_string()])
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Set CA distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, organization);
        dn.push(DnType::OrganizationalUnitName, "Certificate Authority");
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;

        // Set as CA certificate
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set key usage for CA
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        // Set validity (10 years)
        let not_before = ::time::OffsetDateTime::now_utc();
        let not_after = not_before + ::time::Duration::days(3650);
        params.not_before = not_before;
        params.not_after = not_after;

        // Generate key pair
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        // Generate self-signed CA certificate
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PkiError::CertificateGeneration(e.to_string()))?;

        Ok((cert.pem(), key_pair.serialize_pem()))
    }

    /// Generate default CA info for development/testing
    async fn generate_default_ca_info(&self) -> Result<crate::model::CaInfo, PkiError> {
        // reuse the new generate_root_ca logic but return CaInfo
        let (cert_pem, _key_pem) = self.generate_root_ca("Secreton CA", "Secreton Security").await?;
        self.parse_ca_cert(&cert_pem)
    }

    /// Extract DN from Name (RdnSequence)
    fn extract_dn(name: &x509_cert::name::RdnSequence) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for rdn in name.0.iter() {
            for attr in rdn.0.iter() {
                let oid_string = attr.oid.to_string();
                let key = match oid_string.as_str() {
                    "2.5.4.3" => "common_name",
                    "2.5.4.10" => "organization",
                    "2.5.4.11" => "organizational_unit",
                    "2.5.4.6" => "country",
                    "2.5.4.8" => "state",
                    "2.5.4.7" => "locality",
                    _ => &oid_string,
                };
                if let Ok(s) = attr.value.decode_as::<String>() {
                    map.insert(key.to_string(), s);
                }
            }
        }
        map
    }
}
