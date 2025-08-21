use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultSecretSpec {
    pub encrypted_data: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VaultSecret {
    pub api_version: String,
    pub kind: String,
    pub metadata: serde_json::Value,
    pub spec: VaultSecretSpec,
}

// Contoh YAML CRD (untuk dokumentasi)
pub const VAULT_SECRET_CRD_YAML: &str = r#"
apiVersion: vault.adhyaksa/v1
kind: VaultSecret
metadata:
  name: mysecret
spec:
  encrypted_data: <base64>
  public_key: <pem>
"#; 