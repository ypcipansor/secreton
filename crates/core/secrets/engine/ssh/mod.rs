use super::{Secret, SecretMetadata, SecretsEngine, SecretsError};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshRole {
    pub name: String,
    pub ca_type: String,
    pub allowed_users: Vec<String>,
    pub allowed_domains: Option<Vec<String>>,
    pub key_type: String,
    pub key_bits: u32,
    pub max_ttl: u64,
    pub default_ttl: u64,
    pub allow_user_certificates: bool,
    pub allow_host_certificates: bool,
    pub default_extensions: Option<HashMap<String, String>>,
    pub key_id_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCa {
    pub ca_type: String,
    pub private_key: String,
    pub public_key: String,
    pub key_type: String,
    pub key_bits: u32,
    pub max_ttl: u64,
    pub default_ttl: u64,
    pub allow_user_certificates: bool,
    pub allow_host_certificates: bool,
    pub allowed_users: Option<Vec<String>>,
    pub allowed_domains: Option<Vec<String>>,
    pub default_extensions: Option<HashMap<String, String>>,
    pub key_id_format: Option<String>,
    pub serial_number: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaRequest {
    pub ca_type: String,
    pub key_type: String,
    pub key_bits: u32,
    pub max_ttl: u64,
    pub default_ttl: u64,
    pub allow_user_certificates: bool,
    pub allow_host_certificates: bool,
    pub allowed_users: Option<Vec<String>>,
    pub allowed_domains: Option<Vec<String>>,
    pub default_extensions: Option<HashMap<String, String>>,
    pub key_id_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignKeyRequest {
    pub role: String,
    pub public_key: String,
    pub valid_principals: Vec<String>,
    pub ttl: Option<u64>,
    pub cert_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificate {
    pub certificate: String,
    pub serial_number: u64,
    pub expiration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
}

pub struct SshSecretsEngine {
    storage: Arc<RwLock<dyn crate::storage::StorageEngine + Send + Sync>>,
    serial_counter: Arc<RwLock<u64>>,
}

impl SshSecretsEngine {
    pub async fn new(
        storage: Arc<RwLock<dyn crate::storage::StorageEngine + Send + Sync>>,
    ) -> Result<Self, SecretsError> {
        let serial_counter = Arc::new(RwLock::new(1u64));

        // Initialize serial counter from storage
        if let Ok(Some(data)) = storage.read().await.get("ssh/serial_counter").await {
            if let Ok(counter) = serde_json::from_slice::<u64>(&data.value) {
                *serial_counter.write().await = counter;
            }
        }

        Ok(Self {
            storage,
            serial_counter,
        })
    }

    pub async fn create_ca(&mut self, request: CreateCaRequest) -> Result<(), SecretsError> {
        // Validate CA type
        if request.ca_type != "user" && request.ca_type != "host" {
            return Err(SecretsError::InvalidConfiguration(
                "CA type must be 'user' or 'host'".to_string(),
            ));
        }

        // Generate CA key pair
        let key_pair = self
            .generate_keypair(&request.key_type, request.key_bits)
            .await?;

        let ca = SshCa {
            ca_type: request.ca_type.clone(),
            private_key: key_pair.private_key,
            public_key: key_pair.public_key,
            key_type: request.key_type,
            key_bits: request.key_bits,
            max_ttl: request.max_ttl,
            default_ttl: request.default_ttl,
            allow_user_certificates: request.allow_user_certificates,
            allow_host_certificates: request.allow_host_certificates,
            allowed_users: request.allowed_users,
            allowed_domains: request.allowed_domains,
            default_extensions: request.default_extensions,
            key_id_format: request.key_id_format,
            serial_number: 0,
            created_at: Utc::now().timestamp(),
        };

        // Store CA
        let ca_data =
            serde_json::to_vec(&ca).map_err(|e| SecretsError::SerializationError(e.to_string()))?;

        let key = format!("ssh/ca/{}", request.ca_type);
        let entry = crate::storage::StorageEntry {
            key: key.clone(),
            value: ca_data,
            metadata: std::collections::HashMap::new(),
        };
        self.storage.write().await.put(entry).await?;

        Ok(())
    }

    pub async fn get_ca(&self, ca_type: &str) -> Result<SshCa, SecretsError> {
        let key = format!("ssh/ca/{}", ca_type);
        let data = self
            .storage
            .read()
            .await
            .get(&key)
            .await?
            .ok_or_else(|| SecretsError::NotFound(format!("CA '{}' not found", ca_type)))?;

        serde_json::from_slice(&data.value)
            .map_err(|e| SecretsError::SerializationError(e.to_string()))
    }

    pub async fn list_cas(&self) -> Result<Vec<String>, SecretsError> {
        let prefix = "ssh/ca/";
        let keys = self.storage.read().await.list(prefix).await?;
        Ok(keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(prefix).map(|s| s.to_string()))
            .collect())
    }

    pub async fn create_role(&self, role: SshRole) -> Result<(), SecretsError> {
        // Validate role against CA constraints
        if let Ok(ca) = self.get_ca(&role.ca_type).await {
            // Check if role users are allowed by CA
            if let Some(allowed_users) = &ca.allowed_users {
                for user in &role.allowed_users {
                    if !allowed_users.contains(user) && !allowed_users.contains(&"*".to_string()) {
                        return Err(SecretsError::InvalidConfiguration(format!(
                            "User '{}' not allowed by CA",
                            user
                        )));
                    }
                }
            }
        }

        // Store role
        let role_data = serde_json::to_vec(&role)
            .map_err(|e| SecretsError::SerializationError(e.to_string()))?;

        let key = format!("ssh/roles/{}", role.name);
        let entry = crate::storage::StorageEntry {
            key: key.clone(),
            value: role_data,
            metadata: std::collections::HashMap::new(),
        };
        self.storage.write().await.put(entry).await?;

        Ok(())
    }

    pub async fn get_role(&self, role_name: &str) -> Result<SshRole, SecretsError> {
        let key = format!("ssh/roles/{}", role_name);
        let data = self
            .storage
            .read()
            .await
            .get(&key)
            .await?
            .ok_or_else(|| SecretsError::NotFound(format!("Role '{}' not found", role_name)))?;

        serde_json::from_slice(&data.value)
            .map_err(|e| SecretsError::SerializationError(e.to_string()))
    }

    pub async fn list_roles(&self) -> Result<Vec<String>, SecretsError> {
        let prefix = "ssh/roles/";
        let keys = self.storage.read().await.list(prefix).await?;
        Ok(keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(prefix).map(|s| s.to_string()))
            .collect())
    }

    pub async fn delete_role(&self, role_name: &str) -> Result<(), SecretsError> {
        let key = format!("ssh/roles/{}", role_name);
        self.storage.write().await.delete(&key).await?;
        Ok(())
    }

    pub async fn sign_key(
        &mut self,
        request: SignKeyRequest,
    ) -> Result<SignedCertificate, SecretsError> {
        // Get role
        let role = self.get_role(&request.role).await?;

        // Get CA
        let ca = self.get_ca(&role.ca_type).await?;

        // Validate principals
        for principal in &request.valid_principals {
            if !role.allowed_users.contains(principal)
                && !role.allowed_users.contains(&"*".to_string())
            {
                return Err(SecretsError::InvalidConfiguration(format!(
                    "Principal '{}' not allowed by role",
                    principal
                )));
            }
        }

        // Determine TTL
        let ttl = request.ttl.unwrap_or(role.default_ttl);
        if ttl > role.max_ttl {
            return Err(SecretsError::InvalidConfiguration(format!(
                "TTL {} exceeds maximum allowed {}",
                ttl, role.max_ttl
            )));
        }

        // Generate serial number
        let mut serial = self.serial_counter.write().await;
        let serial_number = *serial;
        *serial += 1;

        // Store updated serial counter
        let counter_data = serde_json::to_vec(&*serial)
            .map_err(|e| SecretsError::SerializationError(e.to_string()))?;
        let entry = crate::storage::StorageEntry {
            key: "ssh/serial_counter".to_string(),
            value: counter_data,
            metadata: std::collections::HashMap::new(),
        };
        self.storage.write().await.put(entry).await?;

        // Create certificate
        let expiration = Utc::now().timestamp() + ttl as i64;
        let certificate = self
            .create_certificate(
                &request.public_key,
                &ca.private_key,
                &request.valid_principals,
                serial_number,
                expiration,
                &request.cert_type,
            )
            .await?;

        Ok(SignedCertificate {
            certificate,
            serial_number,
            expiration,
        })
    }

    pub async fn generate_keypair(
        &self,
        key_type: &str,
        key_bits: u32,
    ) -> Result<KeyPair, SecretsError> {
        // Create temporary files for key generation
        let temp_dir = tempfile::tempdir().map_err(SecretsError::Io)?;

        let private_key_path = temp_dir.path().join("id_key");
        let public_key_path = temp_dir.path().join("id_key.pub");

        // Generate key pair using ssh-keygen
        let keygen_cmd = match key_type {
            "rsa" => format!(
                "ssh-keygen -t rsa -b {} -f {} -N ''",
                key_bits,
                private_key_path.display()
            ),
            "ecdsa" => {
                let _curve = match key_bits {
                    256 => "nistp256",
                    384 => "nistp384",
                    521 => "nistp521",
                    _ => {
                        return Err(SecretsError::InvalidConfiguration(
                            "Invalid ECDSA key size".to_string(),
                        ))
                    }
                };
                format!(
                    "ssh-keygen -t ecdsa -b {} -f {} -N ''",
                    key_bits,
                    private_key_path.display()
                )
            }
            "ed25519" => format!(
                "ssh-keygen -t ed25519 -f {} -N ''",
                private_key_path.display()
            ),
            _ => {
                return Err(SecretsError::InvalidConfiguration(format!(
                    "Unsupported key type: {}",
                    key_type
                )))
            }
        };

        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&keygen_cmd)
            .output()
            .await
            .map_err(SecretsError::Io)?;

        if !output.status.success() {
            return Err(SecretsError::ExecutionError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        // Read generated keys
        let private_key = fs::read_to_string(&private_key_path)
            .await
            .map_err(SecretsError::Io)?;

        let public_key = fs::read_to_string(&public_key_path)
            .await
            .map_err(SecretsError::Io)?;

        // Generate fingerprint
        let fingerprint = self.generate_fingerprint(&public_key).await?;

        Ok(KeyPair {
            private_key,
            public_key: public_key.trim().to_string(),
            fingerprint,
        })
    }

    async fn generate_fingerprint(&self, public_key: &str) -> Result<String, SecretsError> {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();
        let encoded = general_purpose::STANDARD.encode(hash);
        Ok(format!("SHA256:{}", encoded))
    }

    async fn create_certificate(
        &self,
        public_key: &str,
        ca_private_key: &str,
        principals: &[String],
        _serial: u64,
        expiration: i64,
        cert_type: &str,
    ) -> Result<String, SecretsError> {
        let temp_dir = tempfile::tempdir().map_err(SecretsError::Io)?;

        let pubkey_path = temp_dir.path().join("user_key.pub");
        let ca_key_path = temp_dir.path().join("ca_key");
        let cert_path = temp_dir.path().join("user_key-cert.pub");

        // Write public key to file
        fs::write(&pubkey_path, public_key)
            .await
            .map_err(SecretsError::Io)?;

        // Write CA private key to file
        fs::write(&ca_key_path, ca_private_key)
            .await
            .map_err(SecretsError::Io)?;

        // Create certificate using ssh-keygen
        let principals_str = principals.join(",");
        let cert_type_flag = match cert_type {
            "user" => "-U",
            "host" => "-h",
            _ => {
                return Err(SecretsError::InvalidConfiguration(
                    "Invalid certificate type".to_string(),
                ))
            }
        };

        let sign_cmd = format!(
            "ssh-keygen -s {} -I {} -n {} -V {}:{} {} {}",
            ca_key_path.display(),
            "secreton-cert",
            principals_str,
            "0",
            expiration,
            cert_type_flag,
            pubkey_path.display()
        );

        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&sign_cmd)
            .output()
            .await
            .map_err(SecretsError::Io)?;

        if !output.status.success() {
            return Err(SecretsError::ExecutionError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        // Read certificate
        let certificate = fs::read_to_string(&cert_path)
            .await
            .map_err(SecretsError::Io)?;

        Ok(certificate.trim().to_string())
    }
}

#[async_trait]
impl SecretsEngine for SshSecretsEngine {
    fn engine_type(&self) -> &'static str {
        "ssh"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // For SSH engine, create operations are handled via role/key management
        // This is a simplified implementation
        match path {
            "roles" => {
                if let Some(role_name) = data.get("name").and_then(|v| v.as_str()) {
                    let role = SshRole {
                        name: role_name.to_string(),
                        ca_type: data
                            .get("ca_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("user")
                            .to_string(),
                        allowed_users: data
                            .get("allowed_users")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .collect()
                            })
                            .unwrap_or_default(),
                        allowed_domains: data
                            .get("allowed_domains")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .collect()
                            }),
                        key_type: data
                            .get("key_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("rsa")
                            .to_string(),
                        key_bits: data
                            .get("key_bits")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(2048) as u32,
                        max_ttl: data
                            .get("max_ttl")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(86400),
                        default_ttl: data
                            .get("default_ttl")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(3600),
                        allow_user_certificates: data
                            .get("allow_user_certificates")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true),
                        allow_host_certificates: data
                            .get("allow_host_certificates")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        default_extensions: data
                            .get("default_extensions")
                            .and_then(|v| v.as_object())
                            .map(|obj| {
                                obj.iter()
                                    .filter_map(|(k, v)| {
                                        v.as_str().map(|s| (k.clone(), s.to_string()))
                                    })
                                    .collect()
                            }),
                        key_id_format: data
                            .get("key_id_format")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    };
                    self.create_role(role).await?;
                    let now = Utc::now();
                    Ok(Secret {
                        id: Uuid::new_v4(),
                        path: path.to_string(),
                        data: serde_json::json!({"name": role_name, "created": true}),
                        metadata: SecretMetadata {
                            created_at: now,
                            updated_at: now,
                            version: 1,
                            ttl: None,
                            expired_at: None,
                            custom_metadata: None,
                        },
                    })
                } else {
                    Err(SecretsError::InvalidData("Role name required".to_string()))
                }
            }
            _ => Err(SecretsError::InvalidData(
                "Unsupported path for create".to_string(),
            )),
        }
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        if let Some(role_name) = path.strip_prefix("roles/") {
            let role = self.get_role(role_name).await?;
            let now = Utc::now();
            Ok(Secret {
                id: Uuid::new_v4(),
                path: path.to_string(),
                data: serde_json::to_value(role).unwrap(),
                metadata: SecretMetadata {
                    created_at: now,
                    updated_at: now,
                    version: 1,
                    ttl: None,
                    expired_at: None,
                    custom_metadata: None,
                },
            })
        } else {
            Err(SecretsError::NotFound(format!(
                "SSH key not found: {}",
                path
            )))
        }
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // For SSH, updates are similar to creates
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        if let Some(role_name) = path.strip_prefix("roles/") {
            self.delete_role(role_name).await
        } else {
            Err(SecretsError::InvalidData(
                "Invalid path for deletion".to_string(),
            ))
        }
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError> {
        match path {
            "roles" => self.list_roles().await,
            _ => Ok(vec![]),
        }
    }
}
