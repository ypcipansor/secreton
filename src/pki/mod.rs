use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaCert {
    pub pem: String,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRequest {
    pub common_name: String,
    pub alt_names: Vec<String>,
    pub ttl_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCert {
    pub pem: String,
    pub private_key: String,
    pub ca: String,
}

pub fn generate_ca(common_name: &str) -> CaCert {
    // Dummy: generate self-signed CA (PEM string)
    CaCert {
        pem: format!("-----BEGIN CERTIFICATE-----\nCA for {}\n-----END CERTIFICATE-----", common_name),
        private_key: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_string(),
    }
}

pub fn issue_cert(ca: &CaCert, req: &CertRequest) -> IssuedCert {
    // Dummy: generate cert signed by CA
    IssuedCert {
        pem: format!("-----BEGIN CERTIFICATE-----\nCert for {}\n-----END CERTIFICATE-----", req.common_name),
        private_key: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_string(),
        ca: ca.pem.clone(),
    }
} 