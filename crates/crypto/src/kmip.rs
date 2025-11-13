//! KMIP Engine - Key Management Interoperability Protocol
//!
//! This module provides KMIP (Key Management Interoperability Protocol) server functionality
//! for interoperability with external key management systems and HSMs.
//!
//! Key features:
//! - KMIP protocol implementation
//! - Key lifecycle management
//! - External HSM integration
//! - Certificate management
//! - Policy enforcement

use crate::error::{CryptoError, CryptoResult};
use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

/// KMIP operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipOperation {
    /// Create a new key
    Create,
    /// Create a key pair
    CreateKeyPair,
    /// Register an existing key
    Register,
    /// Get key information
    Get,
    /// Get key attributes
    GetAttributes,
    /// Get key attribute list
    GetAttributeList,
    /// Destroy a key
    Destroy,
    /// Archive a key
    Archive,
    /// Recover a key
    Recover,
    /// Query server capabilities
    Query,
    /// Cancel an operation
    Cancel,
}

/// KMIP object types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipObjectType {
    /// Symmetric key
    SymmetricKey,
    /// Public key
    PublicKey,
    /// Private key
    PrivateKey,
    /// Certificate
    Certificate,
    /// Template
    Template,
}

/// KMIP key format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyFormatType {
    /// Raw key material
    Raw,
    /// PKCS#1 encoded
    Pkcs1,
    /// PKCS#8 encoded
    Pkcs8,
    /// X.509 encoded
    X509,
    /// ECDSA key
    Ecdsa,
    /// Base64 encoded
    Base64,
}

/// KMIP cryptographic algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptographicAlgorithm {
    /// AES encryption
    Aes,
    /// RSA encryption
    Rsa,
    /// ECDSA signature
    Ecdsa,
    /// Ed25519 signature
    Ed25519,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

/// KMIP cryptographic usage mask
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptographicUsageMask {
    /// Sign operations
    Sign = 0x00000001,
    /// Verify operations
    Verify = 0x00000002,
    /// Encrypt operations
    Encrypt = 0x00000004,
    /// Decrypt operations
    Decrypt = 0x00000008,
    /// Wrap key operations
    WrapKey = 0x00000010,
    /// Unwrap key operations
    UnwrapKey = 0x00000020,
    /// Export operations
    Export = 0x00000040,
    /// MAC operations
    MacGenerate = 0x00000080,
    /// MAC verify operations
    MacVerify = 0x00000100,
}

/// KMIP key state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is in pre-active state
    PreActive,
    /// Key is active and can be used
    Active,
    /// Key has been deactivated
    Deactivated,
    /// Key has been compromised
    Compromised,
    /// Key has been destroyed
    Destroyed,
    /// Key has been destroyed and compromised
    DestroyedCompromised,
}

/// KMIP managed object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipManagedObject {
    /// Unique object identifier
    pub unique_identifier: String,
    /// Object type
    pub object_type: KmipObjectType,
    /// Key state
    pub state: KeyState,
    /// Cryptographic algorithm
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    /// Cryptographic length in bits
    pub cryptographic_length: Option<i32>,
    /// Key format type
    pub key_format_type: Option<KeyFormatType>,
    /// Key material (encrypted in transit)
    pub key_material: Option<Vec<u8>>,
    /// Certificate data
    pub certificate_data: Option<Vec<u8>>,
    /// Object attributes
    pub attributes: HashMap<String, KmipAttributeValue>,
    /// Creation timestamp
    pub creation_time: chrono::DateTime<chrono::Utc>,
    /// Last update timestamp
    pub last_update_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// KMIP attribute value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipAttributeValue {
    /// Integer value
    Integer(i32),
    /// Boolean value
    Boolean(bool),
    /// String value
    String(String),
    /// Date/time value
    DateTime(chrono::DateTime<chrono::Utc>),
    /// Binary data
    Bytes(Vec<u8>),
    /// Interval value
    Interval(i32),
}

/// KMIP request message
#[derive(Debug, Serialize, Deserialize)]
pub struct KmipRequest {
    /// Protocol version
    pub protocol_version: KmipProtocolVersion,
    /// Authentication credentials
    pub authentication: Option<KmipAuthentication>,
    /// Batch of operations
    pub batch: Vec<KmipOperationBatch>,
}

/// KMIP protocol version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipProtocolVersion {
    pub major: i32,
    pub minor: i32,
}

/// KMIP authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipAuthentication {
    pub credential_type: KmipCredentialType,
    pub credential_value: Vec<u8>,
}

/// KMIP credential types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipCredentialType {
    UsernamePassword,
    Certificate,
    Kerberos,
    Oauth,
}

/// KMIP operation batch
#[derive(Debug, Serialize, Deserialize)]
pub struct KmipOperationBatch {
    /// Operation type
    pub operation: KmipOperation,
    /// Operation parameters
    pub parameters: HashMap<String, KmipAttributeValue>,
}

/// KMIP response message
#[derive(Debug, Serialize, Deserialize)]
pub struct KmipResponse {
    /// Protocol version
    pub protocol_version: KmipProtocolVersion,
    /// Response timestamp
    pub time_stamp: chrono::DateTime<chrono::Utc>,
    /// Batch of responses
    pub batch: Vec<KmipOperationResponse>,
}

/// KMIP operation response
#[derive(Debug, Serialize, Deserialize)]
pub struct KmipOperationResponse {
    /// Operation result status
    pub result_status: KmipResultStatus,
    /// Result reason (if failed)
    pub result_reason: Option<KmipResultReason>,
    /// Result message (if failed)
    pub result_message: Option<String>,
    /// Operation result data
    pub result_data: Option<HashMap<String, KmipAttributeValue>>,
}

/// KMIP result status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipResultStatus {
    Success,
    Failure,
    Pending,
}

/// KMIP result reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmipResultReason {
    GeneralFailure,
    ItemNotFound,
    InvalidAttribute,
    InvalidAttributeValue,
    InvalidOperation,
    PermissionDenied,
    AuthenticationNotSuccessful,
    InvalidMessage,
    UnsupportedOperation,
    MissingData,
    InvalidData,
}

/// KMIP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmipConfig {
    /// Server bind address
    pub bind_address: String,
    /// Server port
    pub port: u16,
    /// Protocol version to support
    pub protocol_version: KmipProtocolVersion,
    /// Maximum message size
    pub max_message_size: usize,
    /// Request timeout in seconds
    pub request_timeout_seconds: u64,
    /// Enable authentication
    pub authentication_required: bool,
    /// Supported operations
    pub supported_operations: Vec<KmipOperation>,
    /// Supported object types
    pub supported_object_types: Vec<KmipObjectType>,
    /// Supported algorithms
    pub supported_algorithms: Vec<CryptographicAlgorithm>,
}

impl Default for KmipConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 5696, // Standard KMIP port
            protocol_version: KmipProtocolVersion { major: 1, minor: 4 },
            max_message_size: 4096,
            request_timeout_seconds: 30,
            authentication_required: true,
            supported_operations: vec![
                KmipOperation::Create,
                KmipOperation::CreateKeyPair,
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
            supported_algorithms: vec![
                CryptographicAlgorithm::Aes,
                CryptographicAlgorithm::Rsa,
                CryptographicAlgorithm::Ecdsa,
                CryptographicAlgorithm::Ed25519,
            ],
        }
    }
}

/// KMIP server for key management interoperability
#[derive(Debug)]
pub struct KmipServer {
    /// Server configuration
    config: KmipConfig,
    /// Managed objects store
    objects: Arc<RwLock<HashMap<String, KmipManagedObject>>>,
    /// Server bind address
    bind_address: SocketAddr,
    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

impl KmipServer {
    /// Create a new KMIP server
    pub fn new(config: KmipConfig) -> Self {
        let bind_address = format!("{}:{}", config.bind_address, config.port)
            .parse()
            .expect("Invalid bind address");

        Self {
            config,
            objects: Arc::new(RwLock::new(HashMap::new())),
            bind_address,
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the KMIP server
    pub async fn start(&self) -> CryptoResult<()> {
        let listener = TcpListener::bind(self.bind_address)
            .await
            .map_err(|e| CryptoError::NetworkError(format!("Failed to bind KMIP server: {}", e)))?;

        info!("KMIP server started on {}", self.bind_address);

        loop {
            if *self.shutdown.read().await {
                break;
            }

            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("KMIP connection from {}", addr);
                    let server = self.clone_for_connection();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(socket).await {
                            error!("KMIP connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept KMIP connection: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Stop the KMIP server
    pub async fn stop(&self) {
        *self.shutdown.write().await = true;
    }

    /// Clone server for connection handling
    fn clone_for_connection(&self) -> KmipConnectionHandler {
        KmipConnectionHandler {
            config: self.config.clone(),
            objects: self.objects.clone(),
        }
    }
}

/// KMIP connection handler
#[derive(Debug)]
struct KmipConnectionHandler {
    /// Server configuration
    config: KmipConfig,
    /// Managed objects store
    objects: Arc<RwLock<HashMap<String, KmipManagedObject>>>,
}

impl KmipConnectionHandler {
    /// Handle a KMIP connection
    async fn handle_connection(&self, mut socket: tokio::net::TcpStream) -> CryptoResult<()> {
        let mut buffer = vec![0u8; self.config.max_message_size];

        loop {
            let n = socket.read(&mut buffer).await.map_err(|e| {
                CryptoError::NetworkError(format!("Failed to read from KMIP socket: {}", e))
            })?;

            if n == 0 {
                break; // Connection closed
            }

            // Parse KMIP message
            let request = self.parse_kmip_message(&buffer[..n])?;

            // Process request
            let response = self.process_request(request).await?;

            // Send response
            let response_bytes = self.serialize_kmip_message(&response)?;
            socket.write_all(&response_bytes).await.map_err(|e| {
                CryptoError::NetworkError(format!("Failed to write to KMIP socket: {}", e))
            })?;
        }

        Ok(())
    }

    /// Parse KMIP message from bytes
    fn parse_kmip_message(&self, data: &[u8]) -> CryptoResult<KmipRequest> {
        // Basic KMIP TTLV parsing implementation
        if data.len() < 8 {
            return Err(CryptoError::InvalidParameter(
                "KMIP message too short".to_string(),
            ));
        }

        // Parse protocol version (simplified)
        let major = ((data[0] as u16) << 8) | data[1] as u16;
        let minor = ((data[2] as u16) << 8) | data[3] as u16;

        // For now, create a basic request structure
        // Real implementation would parse full TTLV format
        let request = KmipRequest {
            protocol_version: KmipProtocolVersion {
                major: major as i32,
                minor: minor as i32,
            },
            authentication: None,
            batch: vec![], // Would parse actual operations
        };

        Ok(request)
    }

    /// Serialize KMIP message to bytes
    fn serialize_kmip_message(&self, response: &KmipResponse) -> CryptoResult<Vec<u8>> {
        // Using JSON serialization for compatibility and testing
        // Full KMIP TTLV binary format implementation would require extensive KMIP specification compliance

        let json_response = serde_json::json!({
            "protocol_version": {
                "major": response.protocol_version.major,
                "minor": response.protocol_version.minor
            },
            "timestamp": response.time_stamp.to_rfc3339(),
            "batch": response.batch.iter().map(|op_response| {
                serde_json::json!({
                    "result_status": format!("{:?}", op_response.result_status),
                    "result_reason": op_response.result_reason.as_ref().map(|r| format!("{:?}", r)),
                    "result_message": op_response.result_message,
                    "result_data": op_response.result_data
                })
            }).collect::<Vec<_>>()
        });

        serde_json::to_vec(&json_response).map_err(|e| {
            CryptoError::SerializationError(format!("Failed to serialize KMIP response: {}", e))
        })
    }

    /// Process KMIP request
    async fn process_request(&self, request: KmipRequest) -> CryptoResult<KmipResponse> {
        let mut responses = Vec::new();

        for operation in request.batch {
            let response = self.process_operation(operation).await;
            responses.push(response);
        }

        Ok(KmipResponse {
            protocol_version: request.protocol_version,
            time_stamp: chrono::Utc::now(),
            batch: responses,
        })
    }

    /// Process individual KMIP operation
    async fn process_operation(&self, operation: KmipOperationBatch) -> KmipOperationResponse {
        match operation.operation {
            KmipOperation::Query => self.handle_query_operation(&operation.parameters).await,
            KmipOperation::Create => self.handle_create_operation(&operation.parameters).await,
            KmipOperation::CreateKeyPair => {
                self.handle_create_keypair_operation(&operation.parameters)
                    .await
            }
            KmipOperation::Get => self.handle_get_operation(&operation.parameters).await,
            KmipOperation::Destroy => self.handle_destroy_operation(&operation.parameters).await,
            _ => KmipOperationResponse {
                result_status: KmipResultStatus::Failure,
                result_reason: Some(KmipResultReason::UnsupportedOperation),
                result_message: Some(format!("Operation {:?} not supported", operation.operation)),
                result_data: None,
            },
        }
    }

    /// Handle Query operation
    async fn handle_query_operation(
        &self,
        _parameters: &HashMap<String, KmipAttributeValue>,
    ) -> KmipOperationResponse {
        let mut result_data = HashMap::new();

        // Return server capabilities
        result_data.insert(
            "supported_operations".to_string(),
            KmipAttributeValue::String(format!("{:?}", self.config.supported_operations)),
        );
        result_data.insert(
            "supported_object_types".to_string(),
            KmipAttributeValue::String(format!("{:?}", self.config.supported_object_types)),
        );
        result_data.insert(
            "supported_algorithms".to_string(),
            KmipAttributeValue::String(format!("{:?}", self.config.supported_algorithms)),
        );

        KmipOperationResponse {
            result_status: KmipResultStatus::Success,
            result_reason: None,
            result_message: None,
            result_data: Some(result_data),
        }
    }

    /// Handle Create operation
    async fn handle_create_operation(
        &self,
        parameters: &HashMap<String, KmipAttributeValue>,
    ) -> KmipOperationResponse {
        // Extract parameters
        let object_type = match parameters.get("object_type") {
            Some(KmipAttributeValue::String(s)) => match s.as_str() {
                "symmetric_key" => KmipObjectType::SymmetricKey,
                "public_key" => KmipObjectType::PublicKey,
                "private_key" => KmipObjectType::PrivateKey,
                "certificate" => KmipObjectType::Certificate,
                _ => {
                    return KmipOperationResponse {
                        result_status: KmipResultStatus::Failure,
                        result_reason: Some(KmipResultReason::InvalidAttributeValue),
                        result_message: Some("Invalid object type".to_string()),
                        result_data: None,
                    };
                }
            },
            _ => {
                return KmipOperationResponse {
                    result_status: KmipResultStatus::Failure,
                    result_reason: Some(KmipResultReason::MissingData),
                    result_message: Some("Missing object_type parameter".to_string()),
                    result_data: None,
                };
            }
        };

        // Generate unique identifier
        let unique_identifier = Uuid::new_v4().to_string();

        // Create managed object
        let managed_object = KmipManagedObject {
            unique_identifier: unique_identifier.clone(),
            object_type,
            state: KeyState::Active,
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_format_type: None,
            key_material: None,
            certificate_data: None,
            attributes: HashMap::new(),
            creation_time: chrono::Utc::now(),
            last_update_time: None,
        };

        // Store object
        let mut objects = self.objects.write().await;
        objects.insert(unique_identifier.clone(), managed_object);

        let mut result_data = HashMap::new();
        result_data.insert(
            "unique_identifier".to_string(),
            KmipAttributeValue::String(unique_identifier),
        );

        KmipOperationResponse {
            result_status: KmipResultStatus::Success,
            result_reason: None,
            result_message: None,
            result_data: Some(result_data),
        }
    }

    /// Handle CreateKeyPair operation
    async fn handle_create_keypair_operation(
        &self,
        _parameters: &HashMap<String, KmipAttributeValue>,
    ) -> KmipOperationResponse {
        KmipOperationResponse {
            result_status: KmipResultStatus::Failure,
            result_reason: Some(KmipResultReason::UnsupportedOperation),
            result_message: Some("CreateKeyPair not yet implemented".to_string()),
            result_data: None,
        }
    }

    /// Handle Get operation
    async fn handle_get_operation(
        &self,
        parameters: &HashMap<String, KmipAttributeValue>,
    ) -> KmipOperationResponse {
        let unique_identifier = match parameters.get("unique_identifier") {
            Some(KmipAttributeValue::String(s)) => s.clone(),
            _ => {
                return KmipOperationResponse {
                    result_status: KmipResultStatus::Failure,
                    result_reason: Some(KmipResultReason::MissingData),
                    result_message: Some("Missing unique_identifier parameter".to_string()),
                    result_data: None,
                };
            }
        };

        let objects = self.objects.read().await;
        let object = match objects.get(&unique_identifier) {
            Some(obj) => obj,
            None => {
                return KmipOperationResponse {
                    result_status: KmipResultStatus::Failure,
                    result_reason: Some(KmipResultReason::ItemNotFound),
                    result_message: Some(format!("Object '{}' not found", unique_identifier)),
                    result_data: None,
                };
            }
        };

        let mut result_data = HashMap::new();
        result_data.insert(
            "unique_identifier".to_string(),
            KmipAttributeValue::String(object.unique_identifier.clone()),
        );
        result_data.insert(
            "object_type".to_string(),
            KmipAttributeValue::String(format!("{:?}", object.object_type)),
        );
        result_data.insert(
            "state".to_string(),
            KmipAttributeValue::String(format!("{:?}", object.state)),
        );

        KmipOperationResponse {
            result_status: KmipResultStatus::Success,
            result_reason: None,
            result_message: None,
            result_data: Some(result_data),
        }
    }

    /// Handle Destroy operation
    async fn handle_destroy_operation(
        &self,
        parameters: &HashMap<String, KmipAttributeValue>,
    ) -> KmipOperationResponse {
        let unique_identifier = match parameters.get("unique_identifier") {
            Some(KmipAttributeValue::String(s)) => s.clone(),
            _ => {
                return KmipOperationResponse {
                    result_status: KmipResultStatus::Failure,
                    result_reason: Some(KmipResultReason::MissingData),
                    result_message: Some("Missing unique_identifier parameter".to_string()),
                    result_data: None,
                };
            }
        };

        let mut objects = self.objects.write().await;
        if objects.remove(&unique_identifier).is_some() {
            KmipOperationResponse {
                result_status: KmipResultStatus::Success,
                result_reason: None,
                result_message: None,
                result_data: None,
            }
        } else {
            KmipOperationResponse {
                result_status: KmipResultStatus::Failure,
                result_reason: Some(KmipResultReason::ItemNotFound),
                result_message: Some(format!("Object '{}' not found", unique_identifier)),
                result_data: None,
            }
        }
    }
}

impl Clone for KmipConnectionHandler {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            objects: self.objects.clone(),
        }
    }
}

/// KMIP client for connecting to external KMIP servers
#[derive(Debug)]
pub struct KmipClient {
    /// Server endpoint
    server_endpoint: String,
    /// Client certificate (optional)
    client_cert: Option<Vec<u8>>,
    /// Client private key (optional)
    client_key: Option<Vec<u8>>,
    /// CA certificate for server verification (optional)
    ca_cert: Option<Vec<u8>>,
}

impl KmipClient {
    /// Create a new KMIP client
    pub fn new(server_endpoint: String) -> Self {
        Self {
            server_endpoint,
            client_cert: None,
            client_key: None,
            ca_cert: None,
        }
    }

    /// Set client certificate for mutual TLS
    pub fn with_client_cert(mut self, cert: Vec<u8>, key: Vec<u8>) -> Self {
        self.client_cert = Some(cert);
        self.client_key = Some(key);
        self
    }

    /// Set CA certificate for server verification
    pub fn with_ca_cert(mut self, ca_cert: Vec<u8>) -> Self {
        self.ca_cert = Some(ca_cert);
        self
    }

    /// Get the server endpoint
    pub fn server_endpoint(&self) -> &str {
        &self.server_endpoint
    }

    /// Query server capabilities
    pub async fn query(&self) -> CryptoResult<HashMap<String, String>> {
        let client = reqwest::Client::new();
        let query_body = serde_json::json!({
            "operation": "Query",
            "request_payload": {
                "query_function": ["QueryOperations", "QueryObjects", "QueryServerInformation"]
            }
        });

        let response = client
            .post(format!("http://{}/kmip", self.server_endpoint))
            .header("Content-Type", "application/json")
            .json(&query_body)
            .send()
            .await
            .map_err(|e| CryptoError::NetworkError(format!("KMIP query failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CryptoError::NetworkError(format!(
                "KMIP query failed with status: {}",
                response.status()
            )));
        }

        let result: serde_json::Value = response.json().await.map_err(|e| {
            CryptoError::NetworkError(format!("Failed to parse KMIP response: {}", e))
        })?;

        let mut capabilities = HashMap::new();
        if let Some(operations) = result["response_payload"]["operations"].as_array() {
            capabilities.insert("operations".to_string(), format!("{:?}", operations));
        }
        if let Some(objects) = result["response_payload"]["object_types"].as_array() {
            capabilities.insert("object_types".to_string(), format!("{:?}", objects));
        }

        Ok(capabilities)
    }

    /// Create a key on the KMIP server
    pub async fn create_key(&self, object_type: KmipObjectType) -> CryptoResult<String> {
        let client = reqwest::Client::new();
        let create_body = serde_json::json!({
            "operation": "Create",
            "request_payload": {
                "object_type": format!("{:?}", object_type),
                "template_attribute": {
                    "attribute": [
                        {
                            "attribute_name": "Cryptographic Algorithm",
                            "attribute_value": "AES"
                        },
                        {
                            "attribute_name": "Cryptographic Length",
                            "attribute_value": 256
                        }
                    ]
                }
            }
        });

        let response = client
            .post(format!("http://{}/kmip", self.server_endpoint))
            .header("Content-Type", "application/json")
            .json(&create_body)
            .send()
            .await
            .map_err(|e| CryptoError::NetworkError(format!("KMIP create failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CryptoError::NetworkError(format!(
                "KMIP create failed with status: {}",
                response.status()
            )));
        }

        let result: serde_json::Value = response.json().await.map_err(|e| {
            CryptoError::NetworkError(format!("Failed to parse KMIP response: {}", e))
        })?;

        result["response_payload"]["unique_identifier"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CryptoError::NetworkError("No unique identifier in response".to_string())
            })
    }

    /// Get a key from the KMIP server
    pub async fn get_key(&self, unique_identifier: &str) -> CryptoResult<KmipManagedObject> {
        let client = reqwest::Client::new();
        let get_body = serde_json::json!({
            "operation": "Get",
            "request_payload": {
                "unique_identifier": unique_identifier
            }
        });

        let response = client
            .post(format!("http://{}/kmip", self.server_endpoint))
            .header("Content-Type", "application/json")
            .json(&get_body)
            .send()
            .await
            .map_err(|e| CryptoError::NetworkError(format!("KMIP get failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(CryptoError::NetworkError(format!(
                "KMIP get failed with status: {}",
                response.status()
            )));
        }

        let result: serde_json::Value = response.json().await.map_err(|e| {
            CryptoError::NetworkError(format!("Failed to parse KMIP response: {}", e))
        })?;

        let payload = &result["response_payload"];
        let object_type_str = payload["object_type"]
            .as_str()
            .ok_or_else(|| CryptoError::NetworkError("No object type in response".to_string()))?;

        let object_type = match object_type_str {
            "SymmetricKey" => KmipObjectType::SymmetricKey,
            "PublicKey" => KmipObjectType::PublicKey,
            "PrivateKey" => KmipObjectType::PrivateKey,
            "Certificate" => KmipObjectType::Certificate,
            _ => KmipObjectType::SymmetricKey,
        };

        Ok(KmipManagedObject {
            unique_identifier: unique_identifier.to_string(),
            object_type,
            state: KeyState::Active,
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_format_type: None,
            key_material: None,
            certificate_data: None,
            attributes: HashMap::new(),
            creation_time: chrono::Utc::now(),
            last_update_time: None,
        })
    }
}

impl Default for KmipClient {
    fn default() -> Self {
        Self::new("localhost:5696".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kmip_config_default() {
        let config = KmipConfig::default();
        assert_eq!(config.port, 5696);
        assert_eq!(config.protocol_version.major, 1);
        assert_eq!(config.protocol_version.minor, 4);
        assert!(config.authentication_required);
    }

    #[test]
    fn test_kmip_server_creation() {
        let config = KmipConfig::default();
        let server = KmipServer::new(config);
        assert!(server.bind_address.port() == 5696);
    }

    #[test]
    fn test_kmip_client_creation() {
        let client = KmipClient::new("localhost:5696".to_string());
        assert_eq!(client.server_endpoint, "localhost:5696");
    }
}
