//! Batch operations for high-throughput transit engine operations

use crate::error::{CryptoResult, CryptoError};
use crate::transit::SignatureAlgorithm;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Batch operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOperation {
    /// Unique operation ID
    pub id: String,
    /// Key name to use for the operation
    pub key_name: String,
    /// Type of operation
    pub operation_type: BatchOperationType,
    /// Data to process
    pub data: Vec<u8>,
    /// Optional context for encryption/decryption
    pub context: Option<Vec<u8>>,
    /// Optional key version (defaults to latest)
    pub key_version: Option<u32>,
    /// Optional signature algorithm (for signing operations)
    pub signature_algorithm: Option<SignatureAlgorithm>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
}

impl BatchOperation {
    /// Create new encrypt operation
    pub fn encrypt(key_name: String, plaintext: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            key_name,
            operation_type: BatchOperationType::Encrypt,
            data: plaintext,
            context: None,
            key_version: None,
            signature_algorithm: None,
            timestamp: Utc::now(),
        }
    }
    
    /// Create new decrypt operation
    pub fn decrypt(key_name: String, ciphertext: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            key_name,
            operation_type: BatchOperationType::Decrypt,
            data: ciphertext.into_bytes(),
            context: None,
            key_version: None,
            signature_algorithm: None,
            timestamp: Utc::now(),
        }
    }
    
    /// Create new sign operation
    pub fn sign(key_name: String, data: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            key_name,
            operation_type: BatchOperationType::Sign,
            data,
            context: None,
            key_version: None,
            signature_algorithm: None,
            timestamp: Utc::now(),
        }
    }
    
    /// Set context for the operation
    pub fn with_context(mut self, context: Vec<u8>) -> Self {
        self.context = Some(context);
        self
    }
    
    /// Set key version for the operation
    pub fn with_key_version(mut self, version: u32) -> Self {
        self.key_version = Some(version);
        self
    }
    
    /// Set signature algorithm for signing operations
    pub fn with_signature_algorithm(mut self, algorithm: SignatureAlgorithm) -> Self {
        self.signature_algorithm = Some(algorithm);
        self
    }
    
    /// Set custom operation ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }
}

/// Types of batch operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BatchOperationType {
    Encrypt,
    Decrypt, 
    Sign,
}

/// Result of a batch operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    /// Operation ID
    pub id: String,
    /// Whether the operation succeeded
    pub success: bool,
    /// Result data (ciphertext, plaintext, or signature)
    pub data: Option<Vec<u8>>,
    /// Error message if operation failed
    pub error: Option<String>,
    /// Processing timestamp
    pub timestamp: DateTime<Utc>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

impl BatchResult {
    /// Create successful result
    pub fn success(id: String, data: Vec<u8>) -> Self {
        Self {
            id,
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
            processing_time_ms: 0, // Will be set by processor
        }
    }
    
    /// Create error result
    pub fn error(id: String, error: String) -> Self {
        Self {
            id,
            success: false,
            data: None,
            error: Some(error),
            timestamp: Utc::now(),
            processing_time_ms: 0, // Will be set by processor
        }
    }
    
    /// Set processing time
    pub fn with_processing_time(mut self, processing_time_ms: u64) -> Self {
        self.processing_time_ms = processing_time_ms;
        self
    }
}

/// Batch request containing multiple operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRequest {
    /// Request ID
    pub id: String,
    /// List of operations to perform
    pub operations: Vec<BatchOperation>,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
    /// Optional request metadata
    pub metadata: HashMap<String, String>,
}

impl BatchRequest {
    /// Create new batch request
    pub fn new(operations: Vec<BatchOperation>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            operations,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add metadata to the request
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Set custom request ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id;
        self
    }
}

/// Batch response containing results of all operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponse {
    /// Request ID
    pub request_id: String,
    /// List of operation results
    pub results: Vec<BatchResult>,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
    /// Total processing time in milliseconds
    pub total_processing_time_ms: u64,
    /// Number of successful operations
    pub successful_operations: usize,
    /// Number of failed operations
    pub failed_operations: usize,
    /// Response metadata
    pub metadata: HashMap<String, String>,
}

impl BatchResponse {
    /// Create batch response from request and results
    pub fn new(request_id: String, results: Vec<BatchResult>) -> Self {
        let successful_operations = results.iter().filter(|r| r.success).count();
        let failed_operations = results.len() - successful_operations;
        let total_processing_time_ms = results.iter().map(|r| r.processing_time_ms).sum();
        
        Self {
            request_id,
            results,
            timestamp: Utc::now(),
            total_processing_time_ms,
            successful_operations,
            failed_operations,
            metadata: HashMap::new(),
        }
    }
    
    /// Add metadata to the response
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Batch processor for high-throughput operations
#[derive(Debug)]
pub struct BatchProcessor {
    /// Maximum operations per batch
    max_batch_size: usize,
    /// Maximum processing time per batch (seconds)
    max_processing_time_seconds: u64,
    /// Enable parallel processing
    parallel_processing: bool,
}

impl BatchProcessor {
    /// Create new batch processor
    pub fn new() -> Self {
        Self {
            max_batch_size: 1000,
            max_processing_time_seconds: 300, // 5 minutes
            parallel_processing: true,
        }
    }
    
    /// Set maximum batch size
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }
    
    /// Set maximum processing time
    pub fn with_max_processing_time(mut self, seconds: u64) -> Self {
        self.max_processing_time_seconds = seconds;
        self
    }
    
    /// Enable/disable parallel processing
    pub fn with_parallel_processing(mut self, enabled: bool) -> Self {
        self.parallel_processing = enabled;
        self
    }
    
    /// Validate batch request
    pub fn validate_batch(&self, request: &BatchRequest) -> CryptoResult<()> {
        if request.operations.is_empty() {
            return Err(CryptoError::InvalidParameter("Batch request cannot be empty".to_string()));
        }
        
        if request.operations.len() > self.max_batch_size {
            return Err(CryptoError::InvalidParameter(
                format!("Batch size {} exceeds maximum {}", request.operations.len(), self.max_batch_size)
            ));
        }
        
        // Check for duplicate operation IDs
        let mut ids = std::collections::HashSet::new();
        for operation in &request.operations {
            if !ids.insert(&operation.id) {
                return Err(CryptoError::InvalidParameter(
                    format!("Duplicate operation ID: {}", operation.id)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Split large batch into smaller chunks
    pub fn chunk_batch(&self, request: BatchRequest) -> Vec<BatchRequest> {
        if request.operations.len() <= self.max_batch_size {
            return vec![request];
        }
        
        let mut chunks = Vec::new();
        let operations = request.operations;
        
        for chunk in operations.chunks(self.max_batch_size) {
            let chunk_request = BatchRequest {
                id: Uuid::new_v4().to_string(),
                operations: chunk.to_vec(),
                timestamp: Utc::now(),
                metadata: request.metadata.clone(),
            };
            chunks.push(chunk_request);
        }
        
        chunks
    }
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStats {
    /// Total operations processed
    pub total_operations: u64,
    /// Successful operations
    pub successful_operations: u64,
    /// Failed operations
    pub failed_operations: u64,
    /// Total processing time (milliseconds)
    pub total_processing_time_ms: u64,
    /// Average processing time per operation (milliseconds)
    pub average_processing_time_ms: f64,
    /// Operations per second
    pub operations_per_second: f64,
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

impl BatchStats {
    /// Create new batch statistics
    pub fn new() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            total_processing_time_ms: 0,
            average_processing_time_ms: 0.0,
            operations_per_second: 0.0,
            last_updated: Utc::now(),
        }
    }
    
    /// Update statistics with batch response
    pub fn update(&mut self, response: &BatchResponse) {
        self.total_operations += response.results.len() as u64;
        self.successful_operations += response.successful_operations as u64;
        self.failed_operations += response.failed_operations as u64;
        self.total_processing_time_ms += response.total_processing_time_ms;
        
        // Calculate averages
        if self.total_operations > 0 {
            self.average_processing_time_ms = self.total_processing_time_ms as f64 / self.total_operations as f64;
            
            // Operations per second (convert from milliseconds)
            if self.total_processing_time_ms > 0 {
                self.operations_per_second = (self.total_operations as f64 * 1000.0) / self.total_processing_time_ms as f64;
            }
        }
        
        self.last_updated = Utc::now();
    }
    
    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_operations == 0 {
            return 0.0;
        }
        (self.successful_operations as f64 / self.total_operations as f64) * 100.0
    }
}

impl Default for BatchStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_batch_operation_creation() {
        let encrypt_op = BatchOperation::encrypt("test-key".to_string(), b"test data".to_vec());
        assert_eq!(encrypt_op.operation_type, BatchOperationType::Encrypt);
        assert_eq!(encrypt_op.key_name, "test-key");
        assert_eq!(encrypt_op.data, b"test data");
        
        let decrypt_op = BatchOperation::decrypt("test-key".to_string(), "encrypted-data".to_string());
        assert_eq!(decrypt_op.operation_type, BatchOperationType::Decrypt);
        
        let sign_op = BatchOperation::sign("sign-key".to_string(), b"sign this".to_vec());
        assert_eq!(sign_op.operation_type, BatchOperationType::Sign);
    }
    
    #[test]
    fn test_batch_request() {
        let operations = vec![
            BatchOperation::encrypt("key1".to_string(), b"data1".to_vec()),
            BatchOperation::encrypt("key2".to_string(), b"data2".to_vec()),
        ];
        
        let request = BatchRequest::new(operations.clone())
            .with_metadata("client".to_string(), "test".to_string());
        
        assert_eq!(request.operations.len(), 2);
        assert!(request.metadata.contains_key("client"));
    }
    
    #[test]
    fn test_batch_processor_validation() {
        let processor = BatchProcessor::new().with_max_batch_size(2);
        
        // Valid request
        let valid_request = BatchRequest::new(vec![
            BatchOperation::encrypt("key1".to_string(), b"data1".to_vec()),
        ]);
        assert!(processor.validate_batch(&valid_request).is_ok());
        
        // Empty request
        let empty_request = BatchRequest::new(vec![]);
        assert!(processor.validate_batch(&empty_request).is_err());
        
        // Too large request
        let large_request = BatchRequest::new(vec![
            BatchOperation::encrypt("key1".to_string(), b"data1".to_vec()),
            BatchOperation::encrypt("key2".to_string(), b"data2".to_vec()),
            BatchOperation::encrypt("key3".to_string(), b"data3".to_vec()),
        ]);
        assert!(processor.validate_batch(&large_request).is_err());
    }
    
    #[test]
    fn test_batch_stats() {
        let mut stats = BatchStats::new();
        
        let results = vec![
            BatchResult::success("1".to_string(), b"result1".to_vec()).with_processing_time(100),
            BatchResult::error("2".to_string(), "error".to_string()).with_processing_time(50),
        ];
        
        let response = BatchResponse::new("req1".to_string(), results);
        stats.update(&response);
        
        assert_eq!(stats.total_operations, 2);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.failed_operations, 1);
        assert_eq!(stats.success_rate(), 50.0);
    }
}
