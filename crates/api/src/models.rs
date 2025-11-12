//! Data models and DTOs for the Secreton API.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use secreton_common::ApiResponse;

/// HTTP status codes for responses
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HttpStatus {
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    Conflict = 409,
    UnprocessableEntity = 422,
    TooManyRequests = 429,
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
}

impl HttpStatus {
    /// Get the numeric status code
    pub fn code(&self) -> u16 {
        *self as u16
    }

    /// Check if status is successful (2xx)
    pub fn is_success(&self) -> bool {
        self.code() >= 200 && self.code() < 300
    }

    /// Check if status is client error (4xx)
    pub fn is_client_error(&self) -> bool {
        self.code() >= 400 && self.code() < 500
    }

    /// Check if status is server error (5xx)
    pub fn is_server_error(&self) -> bool {
        self.code() >= 500
    }
}

/// Enhanced API response with HTTP status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpApiResponse<T> {
    /// HTTP status code
    pub status_code: u16,

    /// Response data
    #[serde(flatten)]
    pub response: ApiResponse<T>,

    /// Request ID for tracing
    pub request_id: Option<String>,

    /// Response timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// API version
    pub version: String,
}

impl<T> HttpApiResponse<T> {
    /// Create a success response
    pub fn success(data: T, status_code: HttpStatus) -> Self {
        Self {
            status_code: status_code.code(),
            response: ApiResponse::success(data),
            request_id: None,
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Create an error response
    pub fn error(message: impl Into<String>, status_code: HttpStatus) -> Self {
        Self {
            status_code: status_code.code(),
            response: ApiResponse::error(message),
            request_id: None,
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Create an error response with metadata
    pub fn error_with_metadata(
        message: impl Into<String>,
        status_code: HttpStatus,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            status_code: status_code.code(),
            response: ApiResponse::error_with_metadata(message, metadata),
            request_id: None,
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Set request ID
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

/// Pagination metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    /// Current page number (1-based)
    pub page: usize,

    /// Number of items per page
    pub per_page: usize,

    /// Total number of items
    pub total: usize,

    /// Total number of pages
    pub total_pages: usize,

    /// Whether there are more items
    pub has_more: bool,

    /// Links to other pages
    pub links: Option<PaginationLinks>,
}

/// Pagination links
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationLinks {
    /// Link to first page
    pub first: Option<String>,

    /// Link to previous page
    pub prev: Option<String>,

    /// Link to next page
    pub next: Option<String>,

    /// Link to last page
    pub last: Option<String>,
}

/// Paginated API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedApiResponse<T> {
    /// The response data
    #[serde(flatten)]
    pub response: ApiResponse<Vec<T>>,

    /// Pagination metadata
    pub pagination: PaginationMeta,

    /// Request ID for tracing
    pub request_id: Option<String>,

    /// Response timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// API version
    pub version: String,
}

impl<T> PaginatedApiResponse<T> {
    /// Create a paginated success response
    pub fn success(items: Vec<T>, pagination: PaginationMeta) -> Self {
        Self {
            response: ApiResponse::success(items),
            pagination,
            request_id: None,
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Set request ID
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

/// Pagination parameters for list operations
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
    
    #[serde(default)]
    pub offset: u32,
    
    pub sort: Option<String>,
    pub order: Option<SortOrder>,
    pub filter: Option<String>,
}

/// Sort order options
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    Desc,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Asc
    }
}

fn default_limit() -> u32 {
    50
}

/// Paginated response wrapper
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: PaginationInfo,
}

/// Pagination metadata
#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
    pub has_next: bool,
    pub has_previous: bool,
}

impl<T> PaginatedResponse<T> {
    /// Create new paginated response
    pub fn new(items: Vec<T>, total: u64, limit: u32, offset: u32) -> Self {
        let has_next = offset + limit < total as u32;
        let has_previous = offset > 0;

        Self {
            items,
            pagination: PaginationInfo {
                total,
                limit,
                offset,
                has_next,
                has_previous,
            },
        }
    }
}

/// Generic ID wrapper for request parameters
#[derive(Debug, Deserialize)]
pub struct IdParam {
    pub id: String,
}

/// Generic name wrapper for request parameters
#[derive(Debug, Deserialize)]
pub struct NameParam {
    pub name: String,
}

/// Bulk operation request
#[derive(Debug, Deserialize)]
pub struct BulkOperationRequest<T> {
    pub items: Vec<T>,
    #[serde(default)]
    pub continue_on_error: bool,
}

/// Bulk operation response
#[derive(Debug, Serialize)]
pub struct BulkOperationResponse<T> {
    pub results: Vec<BulkOperationResult<T>>,
    pub summary: BulkOperationSummary,
}

/// Individual bulk operation result
#[derive(Debug, Serialize)]
pub struct BulkOperationResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub index: usize,
}

/// Bulk operation summary
#[derive(Debug, Serialize)]
pub struct BulkOperationSummary {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Search request parameters
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    
    #[serde(default)]
    pub fields: Vec<String>,
    
    #[serde(default = "default_limit")]
    pub limit: u32,
    
    #[serde(default)]
    pub offset: u32,
    
    pub sort: Option<String>,
    
    #[serde(default)]
    pub highlight: bool,
    
    pub filters: Option<HashMap<String, String>>,
}

/// Search response
#[derive(Debug, Serialize)]
pub struct SearchResponse<T> {
    pub results: Vec<SearchResult<T>>,
    pub total: u64,
    pub took_ms: u64,
    pub query: String,
    pub pagination: PaginationInfo,
}

/// Individual search result
#[derive(Debug, Serialize)]
pub struct SearchResult<T> {
    pub item: T,
    pub score: f64,
    pub highlights: Option<HashMap<String, Vec<String>>>,
}

/// Export request parameters
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub format: ExportFormat,
    pub fields: Option<Vec<String>>,
    pub filter: Option<String>,
    pub compression: Option<CompressionType>,
}

/// Export formats
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
    Excel,
    Xml,
    Yaml,
}

/// Compression types
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionType {
    Gzip,
    Zip,
    Bzip2,
}

/// Import request
#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    pub format: ExportFormat,
    pub data: String,
    
    #[serde(default)]
    pub overwrite: bool,
    
    #[serde(default)]
    pub validate_only: bool,
    
    pub mapping: Option<HashMap<String, String>>,
}

/// Import response
#[derive(Debug, Serialize)]
pub struct ImportResponse {
    pub success: bool,
    pub imported: u32,
    pub updated: u32,
    pub skipped: u32,
    pub errors: Vec<ImportError>,
}

/// Import error details
#[derive(Debug, Serialize)]
pub struct ImportError {
    pub row: u32,
    pub field: Option<String>,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// Health check status levels
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Metrics data point
#[derive(Debug, Serialize)]
pub struct MetricDataPoint {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub value: f64,
    pub labels: Option<HashMap<String, String>>,
}

/// Time series metrics
#[derive(Debug, Serialize)]
pub struct TimeSeriesMetric {
    pub name: String,
    pub description: Option<String>,
    pub unit: Option<String>,
    pub data_points: Vec<MetricDataPoint>,
}

/// Metrics query parameters
#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
    pub step: Option<String>,
    pub metrics: Option<Vec<String>>,
    pub labels: Option<HashMap<String, String>>,
}

/// Configuration validation request
#[derive(Debug, Deserialize)]
pub struct ValidateConfigRequest {
    pub config: serde_json::Value,
    pub strict: Option<bool>,
    pub check_connectivity: Option<bool>,
}

/// Configuration validation response
#[derive(Debug, Serialize)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub suggestions: Vec<ConfigSuggestion>,
}

/// Configuration validation error
#[derive(Debug, Serialize)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

/// Configuration validation warning
#[derive(Debug, Serialize)]
pub struct ValidationWarning {
    pub path: String,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Configuration suggestion
#[derive(Debug, Serialize)]
pub struct ConfigSuggestion {
    pub path: String,
    pub current_value: Option<serde_json::Value>,
    pub suggested_value: serde_json::Value,
    pub reason: String,
}

/// Validation severity levels
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

/// Generic status response
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: String,
    pub message: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

/// Operation result
#[derive(Debug, Serialize)]
pub struct OperationResult<T = ()> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
    pub operation_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> OperationResult<T> {
    /// Create successful operation result
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
            operation_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create successful operation result with message
    pub fn success_with_message(data: T, message: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some(message),
            operation_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

impl OperationResult<()> {
    /// Create successful operation result without data
    pub fn success_empty() -> Self {
        Self {
            success: true,
            data: None,
            message: None,
            operation_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create successful operation result with message only
    pub fn success_message(message: String) -> Self {
        Self {
            success: true,
            data: None,
            message: Some(message),
            operation_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create failed operation result
    pub fn failure(message: String) -> Self {
        Self {
            success: false,
            data: None,
            message: Some(message),
            operation_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Audit trail entry
#[derive(Debug, Serialize)]
pub struct AuditTrailEntry {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub resource_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub details: Option<serde_json::Value>,
    pub success: bool,
}

/// Batch processing job status
#[derive(Debug, Serialize)]
pub struct BatchJobStatus {
    pub job_id: String,
    pub status: BatchJobState,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub progress: BatchJobProgress,
    pub result_url: Option<String>,
    pub error: Option<String>,
}

/// Batch job states
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BatchJobState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Batch job progress information
#[derive(Debug, Serialize)]
pub struct BatchJobProgress {
    pub total: u64,
    pub processed: u64,
    pub successful: u64,
    pub failed: u64,
    pub percentage: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paginated_response() {
        let items = vec!["item1".to_string(), "item2".to_string()];
        let response = PaginatedResponse::new(items, 10, 5, 0);
        
        assert_eq!(response.items.len(), 2);
        assert_eq!(response.pagination.total, 10);
        assert_eq!(response.pagination.limit, 5);
        assert_eq!(response.pagination.offset, 0);
        assert!(response.pagination.has_next);
        assert!(!response.pagination.has_previous);
    }

    #[test]
    fn test_operation_result() {
        let result = OperationResult::success("test data".to_string());
        assert!(result.success);
        assert_eq!(result.data, Some("test data".to_string()));
        
        let empty_result = OperationResult::success_empty();
        assert!(empty_result.success);
        assert!(empty_result.data.is_none());
        
        let failure_result = OperationResult::failure("error message".to_string());
        assert!(!failure_result.success);
        assert_eq!(failure_result.message, Some("error message".to_string()));
    }

    #[test]
    fn test_search_query_default() {
        let query = SearchQuery {
            q: "test".to_string(),
            fields: vec![],
            limit: 50,
            offset: 0,
            sort: None,
            highlight: false,
            filters: None,
        };
        
        assert_eq!(query.q, "test");
        assert_eq!(query.limit, 50);
        assert!(!query.highlight);
    }
}
