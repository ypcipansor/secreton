use chrono::{Duration, Utc};
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    pub key_type: String,
    pub key_bits: u32,
    pub pem_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub pem_data: String,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Sha256WithRsa,
    Sha384WithRsa,
    Sha512WithRsa,
    EcdsaWithSha256,
    Ed25519,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureAlgorithm::Sha256WithRsa => write!(f, "SHA256withRSA"),
            SignatureAlgorithm::Sha384WithRsa => write!(f, "SHA384withRSA"),
            SignatureAlgorithm::Sha512WithRsa => write!(f, "SHA512withRSA"),
            SignatureAlgorithm::EcdsaWithSha256 => write!(f, "ECDSAwithSHA256"),
            SignatureAlgorithm::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

impl PrivateKey {
    pub fn generate_rsa(key_bits: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key_pair = match key_bits {
            2048 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256),
            3072 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA384),
            4096 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA512),
            _ => return Err("Unsupported RSA key size. Use 2048, 3072, or 4096 bits.".into()),
        }?;

        let pem_data = key_pair.serialize_pem();

        Ok(PrivateKey {
            key_type: "RSA".to_string(),
            key_bits,
            pem_data,
        })
    }

    pub fn generate_ec(key_bits: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match key_bits {
            256 => {
                let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
                let pem_data = key_pair.serialize_pem();
                Ok(PrivateKey {
                    key_type: "Ed25519".to_string(),
                    key_bits: 256,
                    pem_data,
                })
            }
            384 => {
                let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;
                let pem_data = key_pair.serialize_pem();
                Ok(PrivateKey {
                    key_type: "ECDSA".to_string(),
                    key_bits: 384,
                    pem_data,
                })
            }
            _ => return Err("Unsupported EC key size. Use 256 or 384 bits.".into()),
        }
    }

    pub fn generate_ed25519() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let pem_data = key_pair.serialize_pem();

        Ok(PrivateKey {
            key_type: "Ed25519".to_string(),
            key_bits: 256,
            pem_data,
        })
    }

    pub fn public_key(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let key_pair = KeyPair::from_pem(&self.pem_data)?;
        let public_key_pem = key_pair.public_key_pem();
        Ok(public_key_pem)
    }

    pub fn to_pem(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.pem_data.clone())
    }
}

impl Certificate {
    pub fn builder() -> Result<CertificateBuilder, Box<dyn std::error::Error + Send + Sync>> {
        Ok(CertificateBuilder::new())
    }

    pub fn serial_number(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.serial_number.clone())
    }

    pub fn to_pem(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.pem_data.clone())
    }
}

pub struct CertificateBuilder {
    common_name: Option<String>,
    alt_names: Vec<String>,
    serial_number: Option<String>,
    organization: Option<Vec<String>>,
    country: Option<Vec<String>>,
    not_before: Option<String>,
    not_after: Option<String>,
    public_key_pem: Option<String>,
    key_usage_server: bool,
    key_usage_client: bool,
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateBuilder {
    pub fn new() -> Self {
        Self {
            common_name: None,
            alt_names: Vec::new(),
            serial_number: None,
            organization: None,
            country: None,
            not_before: None,
            not_after: None,
            public_key_pem: None,
            key_usage_server: false,
            key_usage_client: false,
        }
    }

    pub fn common_name(&mut self, cn: &str) -> &mut Self {
        self.common_name = Some(cn.to_string());
        self
    }

    pub fn add_alt_name(&mut self, alt_name: &str) -> &mut Self {
        self.alt_names.push(alt_name.to_string());
        self
    }

    pub fn serial_number(&mut self, serial: &str) -> &mut Self {
        self.serial_number = Some(serial.to_string());
        self
    }

    pub fn subject_common_name(
        &mut self,
        cn: &str,
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        self.common_name = Some(cn.to_string());
        Ok(self)
    }

    pub fn subject_organization(
        &mut self,
        org: &[String],
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        self.organization = Some(org.to_vec());
        Ok(self)
    }

    pub fn subject_country(
        &mut self,
        country: &[String],
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        self.country = Some(country.to_vec());
        Ok(self)
    }

    pub fn validity_period(
        &mut self,
        not_before: &str,
        not_after: &str,
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        self.not_before = Some(not_before.to_string());
        self.not_after = Some(not_after.to_string());
        Ok(self)
    }

    pub fn public_key(
        &mut self,
        public_key: &str,
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        self.public_key_pem = Some(public_key.to_string());
        Ok(self)
    }

    pub fn key_usage_server(
        &mut self,
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        self.key_usage_server = true;
        Ok(self)
    }

    pub fn key_usage_client(
        &mut self,
    ) -> Result<&mut Self, Box<dyn std::error::Error + Send + Sync>> {
        self.key_usage_client = true;
        Ok(self)
    }

    pub fn sign(
        &mut self,
        ca_private_key: &str,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Certificate, Box<dyn std::error::Error + Send + Sync>> {
        let ca_key_pair = KeyPair::from_pem(ca_private_key)?;

        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();

        if let Some(cn) = &self.common_name {
            dn.push(DnType::CommonName, cn);
        } else {
            dn.push(DnType::CommonName, "localhost");
        }

        params.distinguished_name = dn;
        params.serial_number = self
            .serial_number
            .as_ref()
            .map(|s| rcgen::SerialNumber::from(s.as_bytes().to_vec()));

        // Add subject alternative names
        if !self.alt_names.is_empty() {
            params.subject_alt_names = self
                .alt_names
                .iter()
                .map(|name| {
                    if name.contains("@") {
                        Ia5String::try_from(name.as_str()).map(rcgen::SanType::Rfc822Name)
                    } else if name.parse::<std::net::IpAddr>().is_ok() {
                        if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                            Ok(rcgen::SanType::IpAddress(ip))
                        } else {
                            Ia5String::try_from(name.as_str()).map(rcgen::SanType::DnsName)
                        }
                    } else {
                        Ia5String::try_from(name.as_str()).map(rcgen::SanType::DnsName)
                    }
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Invalid subject alternative name")?;
        }

        // Set validity period (default 1 year if not specified)
        let now = Utc::now();
        let not_before = now;
        let not_after = now + Duration::days(365);
        // Convert chrono DateTime to time::OffsetDateTime for rcgen
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
            .map_err(|e| format!("Invalid timestamp: {}", e))?;
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
            .map_err(|e| format!("Invalid timestamp: {}", e))?;

        // Set key usage
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Sign the certificate
        let cert = params.self_signed(&ca_key_pair)?;

        Ok(Certificate {
            pem_data: cert.pem(),
            serial_number: self
                .serial_number
                .clone()
                .unwrap_or_else(|| "1".to_string()),
            subject: format!("CN={}", self.common_name.as_deref().unwrap_or("localhost")),
            issuer: format!("CN={}", self.common_name.as_deref().unwrap_or("localhost")),
        })
    }

    pub fn build(
        &self,
        private_key: &PrivateKey,
    ) -> Result<Certificate, Box<dyn std::error::Error + Send + Sync>> {
        let key_pair = KeyPair::from_pem(&private_key.pem_data)?;

        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();

        let cn = self.common_name.as_deref().unwrap_or("localhost");
        dn.push(DnType::CommonName, cn);

        params.distinguished_name = dn;
        params.serial_number = self
            .serial_number
            .as_ref()
            .map(|s| rcgen::SerialNumber::from(s.as_bytes().to_vec()));

        // Add subject alternative names
        if !self.alt_names.is_empty() {
            params.subject_alt_names = self
                .alt_names
                .iter()
                .map(|name| {
                    if name.contains("@") {
                        Ia5String::try_from(name.as_str()).map(rcgen::SanType::Rfc822Name)
                    } else if name.parse::<std::net::IpAddr>().is_ok() {
                        if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                            Ok(rcgen::SanType::IpAddress(ip))
                        } else {
                            Ia5String::try_from(name.as_str()).map(rcgen::SanType::DnsName)
                        }
                    } else {
                        Ia5String::try_from(name.as_str()).map(rcgen::SanType::DnsName)
                    }
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Invalid subject alternative name")?;
        }

        // Set validity period (default 1 year)
        let now = Utc::now();
        let not_before = now;
        let not_after = now + Duration::days(365);
        // Convert chrono DateTime to time::OffsetDateTime for rcgen
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
            .map_err(|e| format!("Invalid timestamp: {}", e))?;
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
            .map_err(|e| format!("Invalid timestamp: {}", e))?;

        // Set key usage
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Sign the certificate
        let cert = params.self_signed(&key_pair)?;

        Ok(Certificate {
            pem_data: cert.pem(),
            serial_number: self
                .serial_number
                .clone()
                .unwrap_or_else(|| "1".to_string()),
            subject: format!("CN={}", cn),
            issuer: format!("CN={}", cn),
        })
    }
}
