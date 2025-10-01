//! KMIP Engine - Key Management Interoperability Protocol
//!
//! This engine implements a KMIP (Key Management Interoperability Protocol)
//! server for interoperability with external key management systems.
//! KMIP provides a standardized interface for key lifecycle management.

use crate::secrets::engine::{
    BoxedSecretsEngine, Secret, SecretMetadata, SecretsEngine, SecretsError,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

/// KMIP operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipOperation {
    Create,
    CreateKeyPair,
    Register,
    Get,
    GetAttributes,
    GetAttributeList,
    Activate,
    Revoke,
    Destroy,
    Archive,
    Recover,
    Query,
    Locate,
    ReKey,
    Certify,
    ReCertify,
    DiscoverVersions,
}

/// KMIP object types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipObjectType {
    Certificate,
    SymmetricKey,
    PublicKey,
    PrivateKey,
    SecretData,
    OpaqueObject,
    Template,
}

/// KMIP key format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipKeyFormatType {
    Raw,
    Opaque,
    PKCS1,
    PKCS8,
    X509,
    ECDSA,
    DSA,
    DH,
}

/// KMIP cryptographic algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipCryptographicAlgorithm {
    AES,
    RSA,
    ECDSA,
    HMAC,
    DES,
    TripleDES,
    Blowfish,
    Camellia,
    CAST5,
    IDEA,
    RC4,
    RC5,
    Skipjack,
}

/// KMIP cryptographic length (key size)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipCryptographicLength {
    pub length: u32,
}

/// KMIP key material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipKeyMaterial {
    pub key_data: Vec<u8>,
    pub format_type: KmipKeyFormatType,
}

/// KMIP attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipAttribute {
    pub name: String,
    pub value: KmipAttributeValue,
}

/// KMIP attribute value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipAttributeValue {
    TextString(String),
    Integer(u32),
    LongInteger(u64),
    BigInteger(Vec<u8>),
    Boolean(bool),
    DateTime(u64),
    ByteString(Vec<u8>),
    Interval(u32),
}

/// KMIP managed object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipManagedObject {
    pub object_type: KmipObjectType,
    pub unique_identifier: String,
    pub attributes: HashMap<String, KmipAttribute>,
    pub object: KmipObject,
    pub created_at: u64,
    pub last_updated: u64,
}

/// KMIP object data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipObject {
    SymmetricKey(KmipSymmetricKey),
    PublicKey(KmipPublicKey),
    PrivateKey(KmipPrivateKey),
    Certificate(KmipCertificate),
    SecretData(KmipSecretData),
    OpaqueObject(KmipOpaqueObject),
}

/// Symmetric key object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipSymmetricKey {
    pub key_block: KmipKeyBlock,
}

/// Public key object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipPublicKey {
    pub key_block: KmipKeyBlock,
}

/// Private key object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipPrivateKey {
    pub key_block: KmipKeyBlock,
}

/// Certificate object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipCertificate {
    pub certificate_type: String,
    pub certificate_value: Vec<u8>,
}

/// Secret data object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipSecretData {
    pub secret_data_type: String,
    pub value: Vec<u8>,
}

/// Opaque object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipOpaqueObject {
    pub opaque_data_type: String,
    pub opaque_data_value: Vec<u8>,
}

/// Key block containing key material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipKeyBlock {
    pub key_format_type: KmipKeyFormatType,
    pub key_compression_type: Option<String>,
    pub key_value: KmipKeyValue,
    pub cryptographic_algorithm: KmipCryptographicAlgorithm,
    pub cryptographic_length: KmipCryptographicLength,
    pub key_wrapping_data: Option<KmipKeyWrappingData>,
}

/// Key value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipKeyValue {
    pub key_material: KmipKeyMaterial,
}

/// Key wrapping data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipKeyWrappingData {
    pub wrapping_method: String,
    pub encryption_key_info: Option<KmipEncryptionKeyInformation>,
    pub mac_signature_key_info: Option<KmipMacSignatureKeyInformation>,
}

/// Encryption key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipEncryptionKeyInformation {
    pub unique_key_id: String,
    pub cryptographic_parameters: Option<KmipCryptographicParameters>,
}

/// MAC/Signature key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipMacSignatureKeyInformation {
    pub unique_key_id: String,
    pub cryptographic_parameters: Option<KmipCryptographicParameters>,
}

/// Cryptographic parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipCryptographicParameters {
    pub block_cipher_mode: Option<String>,
    pub padding_method: Option<String>,
    pub hashing_algorithm: Option<String>,
    pub key_role_type: Option<String>,
}

/// KMIP request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipRequest {
    pub protocol_version: KmipProtocolVersion,
    pub authentication: Option<KmipAuthentication>,
    pub batch_item: Vec<KmipBatchItem>,
}

/// KMIP protocol version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipProtocolVersion {
    pub protocol_version_major: u32,
    pub protocol_version_minor: u32,
}

/// KMIP authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipAuthentication {
    pub credential_type: String,
    pub credential_value: Vec<u8>,
}

/// KMIP batch item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipBatchItem {
    pub operation: KmipOperation,
    pub request_payload: Option<Value>,
    pub unique_batch_item_id: Option<String>,
}

/// KMIP response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipResponse {
    pub protocol_version: KmipProtocolVersion,
    pub time_stamp: u64,
    pub batch_item: Vec<KmipResponseBatchItem>,
}

/// KMIP response batch item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipResponseBatchItem {
    pub operation: KmipOperation,
    pub result_status: KmipResultStatus,
    pub response_payload: Option<Value>,
    pub result_message: Option<String>,
    pub unique_batch_item_id: Option<String>,
}

/// KMIP result status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipResultStatus {
    Success,
    OperationFailed,
    OperationPending,
    OperationUndone,
}

/// KMIP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipConfig {
    pub server_port: u16,
    pub server_host: String,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub authentication_required: bool,
    pub supported_operations: Vec<KmipOperation>,
    pub supported_object_types: Vec<KmipObjectType>,
    pub max_message_size: usize,
}

/// KMIP Secrets Engine
pub struct KmipSecretsEngine {
    storage: Arc<dyn crate::storage::StorageEngine>,
    objects: Arc<RwLock<HashMap<String, KmipManagedObject>>>,
    config: KmipConfig,
}

impl KmipSecretsEngine {
    pub fn new(storage: Arc<dyn crate::storage::StorageEngine>, config: KmipConfig) -> Self {
        Self {
            storage,
            objects: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new symmetric key
    pub async fn create_key(
        &self,
        key_id: &str,
        algorithm: KmipCryptographicAlgorithm,
        length: u32,
    ) -> Result<String, SecretsError> {
        // Generate key material based on algorithm
        let key_data = self.generate_key_material(&algorithm, length)?;

        let key_block = KmipKeyBlock {
            key_format_type: KmipKeyFormatType::Raw,
            key_compression_type: None,
            key_value: KmipKeyValue {
                key_material: KmipKeyMaterial {
                    key_data,
                    format_type: KmipKeyFormatType::Raw,
                },
            },
            cryptographic_algorithm: algorithm.clone(),
            cryptographic_length: KmipCryptographicLength { length },
            key_wrapping_data: None,
        };

        let symmetric_key = KmipSymmetricKey { key_block };

        let managed_object = KmipManagedObject {
            object_type: KmipObjectType::SymmetricKey,
            unique_identifier: key_id.to_string(),
            attributes: HashMap::new(),
            object: KmipObject::SymmetricKey(symmetric_key),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let mut objects = self.objects.write().await;
        objects.insert(key_id.to_string(), managed_object);

        Ok(key_id.to_string())
    }

    /// Generate key material for different algorithms
    fn generate_key_material(
        &self,
        algorithm: &KmipCryptographicAlgorithm,
        length: u32,
    ) -> Result<Vec<u8>, SecretsError> {
        use rand::RngCore;

        match algorithm {
            KmipCryptographicAlgorithm::AES => {
                let byte_length = length / 8;
                let mut key = vec![0u8; byte_length as usize];
                rand::thread_rng().fill_bytes(&mut key);
                Ok(key)
            }
            KmipCryptographicAlgorithm::RSA => {
                // For RSA, generate a simple key (in practice, use proper RSA key generation)
                let byte_length = length / 8;
                let mut key = vec![0u8; byte_length as usize];
                rand::thread_rng().fill_bytes(&mut key);
                Ok(key)
            }
            _ => Err(SecretsError::InvalidData(format!(
                "Unsupported algorithm: {:?}",
                algorithm
            ))),
        }
    }

    /// Get a managed object by ID
    pub async fn get_object(&self, object_id: &str) -> Result<Option<KmipManagedObject>, SecretsError> {
        let objects = self.objects.read().await;
        Ok(objects.get(object_id).cloned())
    }

    /// Register a new object
    pub async fn register_object(
        &self,
        object_id: &str,
        object_type: KmipObjectType,
        object: KmipObject,
        attributes: HashMap<String, KmipAttribute>,
    ) -> Result<String, SecretsError> {
        let managed_object = KmipManagedObject {
            object_type,
            unique_identifier: object_id.to_string(),
            attributes,
            object,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let mut objects = self.objects.write().await;
        objects.insert(object_id.to_string(), managed_object);

        Ok(object_id.to_string())
    }

    /// Get object attributes
    pub async fn get_attributes(&self, object_id: &str) -> Result<HashMap<String, KmipAttribute>, SecretsError> {
        let objects = self.objects.read().await;
        let object = objects
            .get(object_id)
            .ok_or_else(|| SecretsError::NotFound(format!("Object '{}' not found", object_id)))?;

        Ok(object.attributes.clone())
    }

    /// Destroy an object
    pub async fn destroy_object(&self, object_id: &str) -> Result<(), SecretsError> {
        let mut objects = self.objects.write().await;
        objects.remove(object_id);
        Ok(())
    }

    /// Query objects based on criteria
    pub async fn query_objects(
        &self,
        object_type: Option<KmipObjectType>,
        max_items: Option<usize>,
    ) -> Result<Vec<String>, SecretsError> {
        let objects = self.objects.read().await;
        let mut matching_objects: Vec<String> = objects
            .iter()
            .filter(|(_, obj)| {
                if let Some(ref obj_type) = object_type {
                    obj.object_type == *obj_type
                } else {
                    true
                }
            })
            .map(|(id, _)| id.clone())
            .collect();

        if let Some(max) = max_items {
            matching_objects.truncate(max);
        }

        Ok(matching_objects)
    }

    /// Process a KMIP request
    pub async fn process_request(&self, request: KmipRequest) -> Result<KmipResponse, SecretsError> {
        let mut response_batch = Vec::new();

        for batch_item in request.batch_item {
            let result = self.process_batch_item(batch_item).await;
            response_batch.push(result);
        }

        Ok(KmipResponse {
            protocol_version: request.protocol_version,
            time_stamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            batch_item: response_batch,
        })
    }

    /// Process a single batch item
    async fn process_batch_item(&self, batch_item: KmipBatchItem) -> KmipResponseBatchItem {
        let result_status = match self.execute_operation(&batch_item.operation, batch_item.request_payload.as_ref()).await {
            Ok(payload) => {
                KmipResultStatus::Success
            }
            Err(e) => {
                KmipResultStatus::OperationFailed
            }
        };

        KmipResponseBatchItem {
            operation: batch_item.operation,
            result_status,
            response_payload: None, // Would be populated based on operation result
            result_message: None,
            unique_batch_item_id: batch_item.unique_batch_item_id,
        }
    }

    /// Execute a KMIP operation
    async fn execute_operation(&self, operation: &KmipOperation, payload: Option<&Value>) -> Result<Value, SecretsError> {
        match operation {
            KmipOperation::Create => {
                // Extract parameters from payload and create a key
                if let Some(payload) = payload {
                    if let Some(object_type) = payload.get("object_type").and_then(|v| v.as_str()) {
                        match object_type {
                            "SymmetricKey" => {
                                let algorithm = payload
                                    .get("algorithm")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("AES");
                                let length = payload
                                    .get("length")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(256) as u32;

                                let alg = match algorithm {
                                    "AES" => KmipCryptographicAlgorithm::AES,
                                    _ => return Err(SecretsError::InvalidData("Unsupported algorithm".to_string())),
                                };

                                let object_id = Uuid::new_v4().to_string();
                                self.create_key(&object_id, alg, length).await?;
                                Ok(serde_json::json!({"unique_identifier": object_id}))
                            }
                            _ => Err(SecretsError::InvalidData("Unsupported object type".to_string())),
                        }
                    } else {
                        Err(SecretsError::InvalidData("Object type required".to_string()))
                    }
                } else {
                    Err(SecretsError::InvalidData("Payload required".to_string()))
                }
            }
            KmipOperation::Get => {
                if let Some(payload) = payload {
                    if let Some(object_id) = payload.get("unique_identifier").and_then(|v| v.as_str()) {
                        let object = self.get_object(object_id).await?;
                        if let Some(obj) = object {
                            Ok(serde_json::to_value(obj).unwrap())
                        } else {
                            Err(SecretsError::NotFound(format!("Object '{}' not found", object_id)))
                        }
                    } else {
                        Err(SecretsError::InvalidData("Unique identifier required".to_string()))
                    }
                } else {
                    Err(SecretsError::InvalidData("Payload required".to_string()))
                }
            }
            KmipOperation::Destroy => {
                if let Some(payload) = payload {
                    if let Some(object_id) = payload.get("unique_identifier").and_then(|v| v.as_str()) {
                        self.destroy_object(object_id).await?;
                        Ok(serde_json::json!({"unique_identifier": object_id}))
                    } else {
                        Err(SecretsError::InvalidData("Unique identifier required".to_string()))
                    }
                } else {
                    Err(SecretsError::InvalidData("Payload required".to_string()))
                }
            }
            KmipOperation::Query => {
                let max_items = payload
                    .and_then(|p| p.get("max_items").and_then(|v| v.as_u64()).map(|v| v as usize));

                let objects = self.query_objects(None, max_items).await?;
                Ok(serde_json::json!({"unique_identifiers": objects}))
            }
            _ => Err(SecretsError::InvalidData(format!("Operation not yet implemented: {:?}", operation))),
        }
    }
}

#[async_trait]
impl SecretsEngine for KmipSecretsEngine {
    fn engine_type(&self) -> &'static str {
        "kmip"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        match path {
            "keys" => {
                let object_type = data
                    .get("object_type")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| SecretsError::InvalidData("Object type required".to_string()))?;

                let obj_type = match object_type {
                    "SymmetricKey" => KmipObjectType::SymmetricKey,
                    "PublicKey" => KmipObjectType::PublicKey,
                    "PrivateKey" => KmipObjectType::PrivateKey,
                    "Certificate" => KmipObjectType::Certificate,
                    "SecretData" => KmipObjectType::SecretData,
                    "OpaqueObject" => KmipObjectType::OpaqueObject,
                    _ => return Err(SecretsError::InvalidData(format!("Unsupported object type: {}", object_type))),
                };

                let object_id = Uuid::new_v4().to_string();

                let object = match obj_type {
                    KmipObjectType::SymmetricKey => {
                        let algorithm = data
                            .get("algorithm")
                            .and_then(|v| v.as_str())
                            .unwrap_or("AES");
                        let length = data
                            .get("length")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(256) as u32;

                        let alg = match algorithm {
                            "AES" => KmipCryptographicAlgorithm::AES,
                            _ => return Err(SecretsError::InvalidData(format!("Unsupported algorithm: {}", algorithm))),
                        };

                        let key_block = KmipKeyBlock {
                            key_format_type: KmipKeyFormatType::Raw,
                            key_compression_type: None,
                            key_value: KmipKeyValue {
                                key_material: KmipKeyMaterial {
                                    key_data: self.generate_key_material(&alg, length)?,
                                    format_type: KmipKeyFormatType::Raw,
                                },
                            },
                            cryptographic_algorithm: alg,
                            cryptographic_length: KmipCryptographicLength { length },
                            key_wrapping_data: None,
                        };

                        KmipObject::SymmetricKey(KmipSymmetricKey { key_block })
                    }
                    _ => return Err(SecretsError::InvalidData("Only SymmetricKey supported for now".to_string())),
                };

                let attributes = HashMap::new(); // Would parse attributes from data

                self.register_object(&object_id, obj_type, object, attributes).await?;

                let now = Utc::now();
                Ok(Secret {
                    id: Uuid::new_v4(),
                    path: path.to_string(),
                    data: serde_json::json!({"unique_identifier": object_id}),
                    metadata: SecretMetadata {
                        created_at: now,
                        updated_at: now,
                        version: 1,
                        ttl: None,
                        expired_at: None,
                        custom_metadata: None,
                    },
                })
            }
            _ => Err(SecretsError::InvalidData(
                "Unsupported path for create".to_string(),
            )),
        }
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        if let Some(object_id) = path.strip_prefix("objects/") {
            let object = self.get_object(object_id).await?
                .ok_or_else(|| SecretsError::NotFound(format!("Object '{}' not found", object_id)))?;

            let now = Utc::now();
            Ok(Secret {
                id: Uuid::new_v4(),
                path: path.to_string(),
                data: serde_json::to_value(object).unwrap(),
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
            Err(SecretsError::NotFound(format!("Object not found: {}", path)))
        }
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        if let Some(object_id) = path.strip_prefix("objects/") {
            self.destroy_object(object_id).await
        } else {
            Err(SecretsError::NotFound(format!("Object not found: {}", path)))
        }
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError> {
        match path {
            "objects" => {
                let objects = self.objects.read().await;
                Ok(objects.keys().cloned().collect())
            }
            _ => Ok(vec![]),
        }
    }

    async fn collect_metrics(&self) -> Result<super::EngineMetrics, super::SecretsError> {
        let objects = self.objects.read().await;
        Ok(super::EngineMetrics {
            engine_type: self.engine_type().to_string(),
            secrets_created: objects.len() as u64,
            secrets_read: 0,
            secrets_updated: 0,
            secrets_deleted: 0,
            avg_response_time_ms: 0.0,
            error_count: 0,
            active_secrets: objects.len() as u64,
            storage_size_bytes: 0,
        })
    }
}

/// Create a new KMIP secrets engine
pub fn new_kmip_engine(storage: Arc<dyn crate::storage::StorageEngine>) -> BoxedSecretsEngine {
    let config = KmipConfig {
        server_port: 5696, // Standard KMIP port
        server_host: "0.0.0.0".to_string(),
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        authentication_required: false,
        supported_operations: vec![
            KmipOperation::Create,
            KmipOperation::Get,
            KmipOperation::Destroy,
            KmipOperation::Query,
        ],
        supported_object_types: vec![
            KmipObjectType::SymmetricKey,
            KmipObjectType::PublicKey,
            KmipObjectType::PrivateKey,
            KmipObjectType::Certificate,
        ],
        max_message_size: 4096,
    };

    Box::new(KmipSecretsEngine::new(storage, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_storage;

    async fn setup_engine() -> KmipSecretsEngine {
        let storage = create_test_storage().await;
        let config = KmipConfig {
            server_port: 5696,
            server_host: "0.0.0.0".to_string(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            authentication_required: false,
            supported_operations: vec![KmipOperation::Create, KmipOperation::Get],
            supported_object_types: vec![KmipObjectType::SymmetricKey],
            max_message_size: 4096,
        };

        KmipSecretsEngine::new(storage, config)
    }

    #[tokio::test]
    async fn test_create_kmip_key() {
        let engine = setup_engine().await;

        let result = engine.create_key("test-key-1", KmipCryptographicAlgorithm::AES, 256).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-key-1");
    }

    #[tokio::test]
    async fn test_get_kmip_object() {
        let engine = setup_engine().await;

        // Create a key first
        engine.create_key("test-key-2", KmipCryptographicAlgorithm::AES, 256).await.unwrap();

        // Get the object
        let object = engine.get_object("test-key-2").await;
        assert!(object.is_ok());

        let obj = object.unwrap();
        assert!(obj.is_some());
        let managed_obj = obj.unwrap();
        assert_eq!(managed_obj.unique_identifier, "test-key-2");
        assert_eq!(managed_obj.object_type, KmipObjectType::SymmetricKey);
    }

    #[tokio::test]
    async fn test_register_object() {
        let engine = setup_engine().await;

        let key_data = vec![1, 2, 3, 4, 5];
        let key_material = KmipKeyMaterial {
            key_data,
            format_type: KmipKeyFormatType::Raw,
        };

        let key_block = KmipKeyBlock {
            key_format_type: KmipKeyFormatType::Raw,
            key_compression_type: None,
            key_value: KmipKeyValue { key_material },
            cryptographic_algorithm: KmipCryptographicAlgorithm::AES,
            cryptographic_length: KmipCryptographicLength { length: 128 },
            key_wrapping_data: None,
        };

        let symmetric_key = KmipSymmetricKey { key_block };
        let object = KmipObject::SymmetricKey(symmetric_key);
        let attributes = HashMap::new();

        let result = engine.register_object("test-key-3", KmipObjectType::SymmetricKey, object, attributes).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-key-3");
    }

    #[tokio::test]
    async fn test_query_objects() {
        let engine = setup_engine().await;

        // Create a few keys
        engine.create_key("test-key-4", KmipCryptographicAlgorithm::AES, 256).await.unwrap();
        engine.create_key("test-key-5", KmipCryptographicAlgorithm::AES, 128).await.unwrap();

        // Query all objects
        let objects = engine.query_objects(None, None).await;
        assert!(objects.is_ok());

        let object_ids = objects.unwrap();
        assert!(object_ids.contains(&"test-key-4".to_string()));
        assert!(object_ids.contains(&"test-key-5".to_string()));
    }

    #[tokio::test]
    async fn test_secrets_engine_interface() {
        let engine = setup_engine().await;

        // Test create via secrets engine interface
        let create_data = serde_json::json!({
            "object_type": "SymmetricKey",
            "algorithm": "AES",
            "length": 256
        });

        let result = engine.create_secret("keys", create_data, None).await;
        assert!(result.is_ok());

        let secret = result.unwrap();
        assert!(secret.data.get("unique_identifier").is_some());

        // Test read via secrets engine interface
        if let Some(object_id) = secret.data.get("unique_identifier").and_then(|v| v.as_str()) {
            let read_result = engine.read_secret(&format!("objects/{}", object_id)).await;
            assert!(read_result.is_ok());
        }
    }
}
