//! Comprehensive Audit and Compliance System
//! 
//! Implements immutable audit trails, real-time monitoring, and automated
//! compliance reporting for international banking and security standards.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};

use crate::{error::CoreError, ResourceId, SecurityLevel};

/// Security event types for comprehensive audit logging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityEventType {
    /// Authentication events
    AuthenticationSuccess { user: String, method: String },
    AuthenticationFailure { user: String, method: String, reason: String },
    AuthenticationBlocked { user: String, reason: String },
    AuthenticationChallenge { user: String, challenge_type: String },
    SessionCreated { user: String, session_id: String },
    SessionTerminated { user: String, session_id: String, reason: String },
    PasswordChanged { user: String },
    
    /// Authorization events
    AccessGranted { user: String, resource: String, action: String },
    AccessDenied { user: String, resource: String, action: String, reason: String },
    PrivilegeEscalation { user: String, from_role: String, to_role: String },
    PolicyViolation { user: String, policy: String, details: String },
    
    /// Cryptographic operations
    KeyGeneration { key_type: String, key_id: String, algorithm: String },
    KeyRotation { old_key_id: String, new_key_id: String, algorithm: String },
    KeyDeletion { key_id: String, algorithm: String },
    KeyAccess { key_id: String, user: String, operation: String },
    EncryptionOperation { key_id: String, user: String, data_size: u64 },
    DecryptionOperation { key_id: String, user: String, data_size: u64 },
    SigningOperation { key_id: String, user: String, data_hash: String },
    VerificationOperation { key_id: String, user: String, signature_valid: bool },
    
    /// Hardware Security Module operations
    HSMConnection { hsm_type: String, status: String },
    HSMOperation { hsm_type: String, operation: String, success: bool },
    HSMError { hsm_type: String, error: String },
    HSMKeyGeneration { hsm_type: String, key_id: String },
    
    /// Multi-Factor Authentication
    MFAChallenge { user: String, method: String, challenge_id: String },
    MFASuccess { user: String, method: String },
    MFAFailure { user: String, method: String, reason: String },
    MFARegistration { user: String, method: String },
    MFARemoval { user: String, method: String },
    
    /// System administration
    SystemStartup { version: String, config_hash: String },
    SystemShutdown { reason: String, graceful: bool },
    ConfigurationChange { parameter: String, old_value: String, new_value: String, user: String },
    SecretCreation { secret_path: String, user: String },
    SecretAccess { secret_path: String, user: String, operation: String },
    SecretDeletion { secret_path: String, user: String },
    SecretVersionChange { secret_path: String, old_version: u32, new_version: u32, user: String },
    PolicyCreation { policy_name: String, user: String },
    PolicyModification { policy_name: String, user: String },
    PolicyDeletion { policy_name: String, user: String },
    
    /// Security incidents
    FailedAccessAttempt { user: String, resource: String, attempts: u32 },
    SuspiciousActivity { user: String, activity: String },
    SecurityThreat { threat_type: String, source: String, severity: String },
    IntrusionAttempt { source_ip: String, attack_type: String },
    AnomalousUsage { user: String, pattern: String },
    ComplianceViolation { regulation: String, violation: String, user: String },
    DataBreach { scope: String, data_types: String, affected_users: u32 },
    
    /// Network and system security
    NetworkConnection { source_ip: String, destination_port: u16, protocol: String },
    TLSHandshake { client_ip: String, cipher_suite: String, version: String, success: bool },
    RateLimitTriggered { client_ip: String, endpoint: String, limit: u32 },
    IPBlacklisted { ip: String, reason: String },
    CertificateValidation { certificate_subject: String, valid: bool, expiry: DateTime<Utc> },
    
    /// Backup and disaster recovery
    BackupCreated { backup_id: String, size: u64, encrypted: bool },
    BackupRestored { backup_id: String, user: String },
    DisasterRecoveryTriggered { reason: String, user: String },
    
    /// Compliance and reporting
    ComplianceCheck { standard: String, status: String, details: String },
    ReportGenerated { report_type: String, user: String, timespan: String },
    DataRetentionAction { action: String, data_type: String, count: u32 },
    
    /// Post-Quantum Cryptography
    PQCOperation { algorithm: String, operation: String, key_id: String },
    HybridCryptoOperation { classical_alg: String, pqc_alg: String, operation: String },
    QuantumResistanceCheck { algorithm: String, status: String },
    
    /// Custom events for extensibility
    Custom { event_type: String, details: String },
}

/// Compliance standards supported by the audit system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComplianceStandard {
    /// FIPS 140-3 cryptographic standards
    FIPS140_3,
    /// Common Criteria security evaluation
    CommonCriteria,
    /// SOC 2 Type II controls
    SOC2TypeII,
    /// ISO 27001 information security management
    ISO27001,
    /// PCI DSS payment card security
    PCIDSS,
    /// GDPR data protection regulation
    GDPR,
    /// NIST Cybersecurity Framework
    NISTCyberFramework,
    /// Banking regulations (Basel III, etc.)
    BankingRegulations,
    /// HIPAA healthcare data protection
    HIPAA,
    /// Custom compliance framework
    Custom(String),
}

/// Audit retention policies for different event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Event types this policy applies to
    pub event_types: Vec<SecurityEventType>,
    /// Retention period in days
    pub retention_days: u32,
    /// Whether to archive instead of delete
    pub archive: bool,
    /// Encryption required for archived data
    pub encrypt_archive: bool,
}

/// Real-time alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Event types that trigger alerts
    pub trigger_events: Vec<SecurityEventType>,
    /// Alert channels (email, webhook, etc.)
    pub channels: Vec<String>,
    /// Alert severity levels
    pub severity: AlertSeverity,
    /// Rate limiting for alerts
    pub rate_limit: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Immutable audit trail with cryptographic integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableAuditTrail {
    /// Sequential entry number
    pub sequence: u64,
    /// Hash of previous entry for chain integrity
    pub previous_hash: String,
    /// Current entry hash
    pub current_hash: String,
    /// Digital signature of entry
    pub signature: String,
    /// Timestamp with high precision
    pub timestamp: DateTime<Utc>,
    /// Merkle tree root for batch integrity
    pub merkle_root: Option<String>,
}

/// Enhanced audit log entry with comprehensive security context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this audit entry
    pub id: String,
    
    /// Timestamp when the event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Security event type with detailed context
    pub event_type: SecurityEventType,
    
    /// User ID who performed the action (if applicable)
    pub user_id: Option<String>,
    
    /// Session ID associated with the action
    pub session_id: Option<String>,
    
    /// Action that was performed
    pub action: String,
    
    /// Resource that was acted upon
    pub resource: Option<ResourceId>,
    
    /// IP address of the client
    pub client_ip: Option<String>,
    
    /// User agent string
    pub user_agent: Option<String>,
    
    /// Geographical location (ISO 3166 country code)
    pub geo_location: Option<String>,
    
    /// Whether the action was successful
    pub success: bool,
    
    /// Error message if the action failed
    pub error: Option<String>,
    
    /// Risk score calculated for this event (0.0-10.0)
    pub risk_score: f64,
    
    /// Additional context and metadata
    pub metadata: HashMap<String, serde_json::Value>,
    
    /// Security classification of this audit entry
    pub security_level: SecurityLevel,
    
    /// Source component that generated this entry
    pub source: String,
    
    /// Immutable trail information
    pub trail: Option<ImmutableAuditTrail>,
    
    /// Compliance tags for regulatory mapping
    pub compliance_tags: Vec<ComplianceStandard>,
    
    /// Data classification (public, internal, confidential, restricted)
    pub data_classification: String,
    
    /// Correlation ID for linking related events
    pub correlation_id: Option<String>,
    
    /// Request ID for tracing distributed operations
    pub request_id: Option<String>,
    
    /// Performance metrics
    pub duration_ms: Option<u64>,
    
    /// Data size involved in operation (bytes)
    pub data_size: Option<u64>,
    
    /// TLS/encryption information
    pub encryption_info: Option<EncryptionInfo>,
}

/// TLS and encryption context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// TLS version used
    pub tls_version: Option<String>,
    /// Cipher suite used
    pub cipher_suite: Option<String>,
    /// Certificate subject (for client certificates)
    pub certificate_subject: Option<String>,
    /// Encryption algorithm used for data
    pub encryption_algorithm: Option<String>,
    /// Key derivation function
    pub kdf: Option<String>,
    /// Whether post-quantum cryptography was used
    pub post_quantum: bool,
}

/// Compliance report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Report ID
    pub id: String,
    /// Compliance standard
    pub standard: ComplianceStandard,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Reporting period
    pub period: (DateTime<Utc>, DateTime<Utc>),
    /// Compliance score (0.0-100.0)
    pub compliance_score: f64,
    /// Summary statistics
    pub statistics: HashMap<String, u64>,
    /// Findings and violations
    pub findings: Vec<ComplianceFinding>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Individual compliance finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Finding ID
    pub id: String,
    /// Severity level
    pub severity: AlertSeverity,
    /// Control or requirement reference
    pub control_ref: String,
    /// Description of the finding
    pub description: String,
    /// Evidence (audit entry IDs)
    pub evidence: Vec<String>,
    /// Remediation steps
    pub remediation: Vec<String>,
}

/// Security incident detected from audit analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    /// Incident ID
    pub id: String,
    /// Detection timestamp
    pub detected_at: DateTime<Utc>,
    /// Incident type
    pub incident_type: String,
    /// Severity level
    pub severity: AlertSeverity,
    /// Description
    pub description: String,
    /// Related audit entries
    pub audit_entries: Vec<String>,
    /// Risk score
    pub risk_score: f64,
    /// Affected users
    pub affected_users: Vec<String>,
    /// Affected resources
    pub affected_resources: Vec<String>,
    /// Status
    pub status: IncidentStatus,
}

/// Incident status tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    InvestigationInProgress,
    Contained,
    Resolved,
    Closed,
}

/// Export format options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    JSON,
    CSV,
    XML,
    SIEM, // Common Event Format
    CEF,  // ArcSight Common Event Format
    LEEF, // IBM QRadar Log Event Extended Format
}

impl AuditEntry {
    /// Create a new audit entry builder
    pub fn builder() -> AuditEntryBuilder {
        AuditEntryBuilder::new()
    }

    /// Create a successful audit entry
    pub fn success(action: String, event_type: SecurityEventType, resource: Option<ResourceId>) -> Self {
        Self::builder()
            .action(action)
            .event_type(event_type)
            .resource(resource)
            .success(true)
            .build()
    }

    /// Create a failed audit entry
    pub fn failure(action: String, event_type: SecurityEventType, resource: Option<ResourceId>, error: String) -> Self {
        Self::builder()
            .action(action)
            .event_type(event_type)
            .resource(resource)
            .success(false)
            .error(error)
            .build()
    }

    /// Add metadata to the audit entry
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set user context
    pub fn with_user(mut self, user_id: String, session_id: Option<String>) -> Self {
        self.user_id = Some(user_id);
        self.session_id = session_id;
        self
    }

    /// Set client context
    pub fn with_client(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.client_ip = ip;
        self.user_agent = user_agent;
        self
    }
}

/// Builder for creating audit entries
pub struct AuditEntryBuilder {
    entry: AuditEntry,
}

impl AuditEntryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            entry: AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                event_type: SecurityEventType::Custom { 
                    event_type: "unknown".to_string(), 
                    details: "No details available".to_string() 
                },
                user_id: None,
                session_id: None,
                action: String::new(),
                resource: None,
                client_ip: None,
                user_agent: None,
                geo_location: None,
                success: false,
                error: None,
                risk_score: 0.0,
                metadata: HashMap::new(),
                security_level: SecurityLevel::Internal,
                source: "brankas-core".to_string(),
                trail: None,
                compliance_tags: Vec::new(),
                data_classification: "internal".to_string(),
                correlation_id: None,
                request_id: None,
                duration_ms: None,
                data_size: None,
                encryption_info: None,
            },
        }
    }

    /// Set the event type
    pub fn event_type(mut self, event_type: SecurityEventType) -> Self {
        self.entry.event_type = event_type;
        self
    }

    /// Set the action
    pub fn action(mut self, action: String) -> Self {
        self.entry.action = action;
        self
    }

    /// Set the resource
    pub fn resource(mut self, resource: Option<ResourceId>) -> Self {
        self.entry.resource = resource;
        self
    }

    /// Set the user ID
    pub fn user_id(mut self, user_id: String) -> Self {
        self.entry.user_id = Some(user_id);
        self
    }

    /// Set the session ID
    pub fn session_id(mut self, session_id: String) -> Self {
        self.entry.session_id = Some(session_id);
        self
    }

    /// Set success status
    pub fn success(mut self, success: bool) -> Self {
        self.entry.success = success;
        self
    }

    /// Set error message
    pub fn error(mut self, error: String) -> Self {
        self.entry.error = Some(error);
        self
    }

    /// Set client IP
    pub fn client_ip(mut self, ip: String) -> Self {
        self.entry.client_ip = Some(ip);
        self
    }

    /// Set the user agent
    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.entry.user_agent = Some(user_agent);
        self
    }

    /// Set geographical location
    pub fn geo_location(mut self, geo_location: String) -> Self {
        self.entry.geo_location = Some(geo_location);
        self
    }

    /// Set risk score
    pub fn risk_score(mut self, score: f64) -> Self {
        self.entry.risk_score = score;
        self
    }

    /// Add compliance tag
    pub fn compliance_tag(mut self, tag: ComplianceStandard) -> Self {
        self.entry.compliance_tags.push(tag);
        self
    }

    /// Set data classification
    pub fn data_classification(mut self, classification: String) -> Self {
        self.entry.data_classification = classification;
        self
    }

    /// Set correlation ID
    pub fn correlation_id(mut self, id: String) -> Self {
        self.entry.correlation_id = Some(id);
        self
    }

    /// Set request ID
    pub fn request_id(mut self, id: String) -> Self {
        self.entry.request_id = Some(id);
        self
    }

    /// Set operation duration
    pub fn duration_ms(mut self, duration: u64) -> Self {
        self.entry.duration_ms = Some(duration);
        self
    }

    /// Set data size
    pub fn data_size(mut self, size: u64) -> Self {
        self.entry.data_size = Some(size);
        self
    }

    /// Set encryption info
    pub fn encryption_info(mut self, info: EncryptionInfo) -> Self {
        self.entry.encryption_info = Some(info);
        self
    }

    /// Set security level
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.entry.security_level = level;
        self
    }

    /// Set source component
    pub fn source(mut self, source: String) -> Self {
        self.entry.source = source;
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.entry.metadata.insert(key, value);
        self
    }

    /// Build the audit entry
    pub fn build(self) -> AuditEntry {
        self.entry
    }
}

/// Enhanced trait for audit log storage backends with compliance features
#[async_trait::async_trait]
pub trait AuditStorage: Send + Sync {
    /// Store an audit entry with integrity verification
    async fn store(&self, entry: &AuditEntry) -> Result<(), CoreError>;
    
    /// Store multiple entries atomically
    async fn store_batch(&self, entries: &[AuditEntry]) -> Result<(), CoreError>;
    
    /// Retrieve audit entries with optional filtering
    async fn retrieve(
        &self,
        filters: AuditFilters,
    ) -> Result<Vec<AuditEntry>, CoreError>;
    
    /// Count total audit entries matching filters
    async fn count(&self, filters: AuditFilters) -> Result<u64, CoreError>;
    
    /// Delete audit entries older than specified date
    async fn cleanup_before(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, CoreError>;
    
    /// Verify integrity of audit trail
    async fn verify_integrity(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<bool, CoreError>;
    
    /// Generate compliance report
    async fn generate_compliance_report(
        &self,
        standard: ComplianceStandard,
        period: (DateTime<Utc>, DateTime<Utc>),
    ) -> Result<ComplianceReport, CoreError>;
    
    /// Search for security incidents
    async fn search_incidents(
        &self,
        patterns: Vec<String>,
        time_range: (DateTime<Utc>, DateTime<Utc>),
    ) -> Result<Vec<SecurityIncident>, CoreError>;
    
    /// Export audit data for external analysis
    async fn export_data(
        &self,
        format: ExportFormat,
        filters: AuditFilters,
    ) -> Result<Vec<u8>, CoreError>;
    
    /// Archive old audit entries
    async fn archive_entries(
        &self,
        before: DateTime<Utc>,
        encryption_key: Option<&[u8]>,
    ) -> Result<String, CoreError>;
}

/// Filters for querying audit entries
#[derive(Debug, Clone, Default)]
pub struct AuditFilters {
    /// Start time (inclusive)
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    
    /// End time (inclusive)
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    
    /// User ID filter
    pub user_id: Option<String>,
    
    /// Action filter (can use wildcards)
    pub action: Option<String>,
    
    /// Resource filter
    pub resource: Option<ResourceId>,
    
    /// Success status filter
    pub success: Option<bool>,
    
    /// Security level filter (minimum level)
    pub min_security_level: Option<SecurityLevel>,
    
    /// Source component filter
    pub source: Option<String>,
    
    /// Maximum number of results
    pub limit: Option<u32>,
    
    /// Number of results to skip
    pub offset: Option<u32>,
}

impl AuditFilters {
    /// Create a new filter builder
    pub fn builder() -> AuditFiltersBuilder {
        AuditFiltersBuilder::new()
    }
}

/// Builder for audit filters
pub struct AuditFiltersBuilder {
    filters: AuditFilters,
}

impl AuditFiltersBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            filters: AuditFilters::default(),
        }
    }

    /// Set time range
    pub fn time_range(
        mut self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        self.filters.start_time = Some(start);
        self.filters.end_time = Some(end);
        self
    }

    /// Set user ID filter
    pub fn user_id(mut self, user_id: String) -> Self {
        self.filters.user_id = Some(user_id);
        self
    }

    /// Set action filter
    pub fn action(mut self, action: String) -> Self {
        self.filters.action = Some(action);
        self
    }

    /// Set resource filter
    pub fn resource(mut self, resource: ResourceId) -> Self {
        self.filters.resource = Some(resource);
        self
    }

    /// Set success filter
    pub fn success_only(mut self) -> Self {
        self.filters.success = Some(true);
        self
    }

    /// Set failure filter
    pub fn failures_only(mut self) -> Self {
        self.filters.success = Some(false);
        self
    }

    /// Set minimum security level
    pub fn min_security_level(mut self, level: SecurityLevel) -> Self {
        self.filters.min_security_level = Some(level);
        self
    }

    /// Set pagination
    pub fn paginate(mut self, limit: u32, offset: u32) -> Self {
        self.filters.limit = Some(limit);
        self.filters.offset = Some(offset);
        self
    }

    /// Build the filters
    pub fn build(self) -> AuditFilters {
        self.filters
    }
}

/// Enhanced audit logger with real-time monitoring and compliance
pub struct AuditLogger {
    storage: Arc<dyn AuditStorage>,
    source: String,
    alert_configs: Arc<RwLock<Vec<AlertConfig>>>,
    retention_policies: Arc<RwLock<Vec<RetentionPolicy>>>,
    risk_calculator: Arc<RiskCalculator>,
    compliance_monitor: Arc<ComplianceMonitor>,
}

/// Risk calculation engine for audit events
pub struct RiskCalculator {
    rules: HashMap<SecurityEventType, f64>,
    context_factors: HashMap<String, f64>,
}

impl RiskCalculator {
    pub fn new() -> Self {
        let mut rules = HashMap::new();
        
        // High-risk authentication events
        rules.insert(SecurityEventType::AuthenticationFailure { 
            user: String::new(), method: String::new(), reason: String::new() 
        }, 7.0);
        rules.insert(SecurityEventType::AuthenticationBlocked { 
            user: String::new(), reason: String::new() 
        }, 9.0);
        rules.insert(SecurityEventType::PrivilegeEscalation { 
            user: String::new(), from_role: String::new(), to_role: String::new() 
        }, 8.5);
        
        // Critical crypto operations
        rules.insert(SecurityEventType::KeyDeletion { 
            key_id: String::new(), algorithm: String::new() 
        }, 9.5);
        rules.insert(SecurityEventType::HSMError { 
            hsm_type: String::new(), error: String::new() 
        }, 8.0);
        
        // Security incidents
        rules.insert(SecurityEventType::SecurityThreat { 
            threat_type: String::new(), source: String::new(), severity: String::new() 
        }, 9.0);
        rules.insert(SecurityEventType::IntrusionAttempt { 
            source_ip: String::new(), attack_type: String::new() 
        }, 8.5);
        rules.insert(SecurityEventType::DataBreach { 
            scope: String::new(), data_types: String::new(), affected_users: 0 
        }, 10.0);
        
        Self {
            rules,
            context_factors: HashMap::new(),
        }
    }
    
    pub fn calculate_risk(&self, event: &SecurityEventType, context: &HashMap<String, serde_json::Value>) -> f64 {
        let base_risk = self.rules.get(event).copied().unwrap_or(1.0);
        
        // Apply context factors
        let mut risk = base_risk;
        
        // Time-based factors
        if let Some(hour) = context.get("hour") {
            if let Some(h) = hour.as_u64() {
                if h < 6 || h > 22 {
                    risk *= 1.2; // After hours activity is riskier
                }
            }
        }
        
        // Geographic factors
        if let Some(geo) = context.get("geo_location") {
            if let Some(country) = geo.as_str() {
                if ["CN", "RU", "IR", "KP"].contains(&country) {
                    risk *= 1.5; // Higher risk countries
                }
            }
        }
        
        // Failed attempt patterns
        if let Some(attempts) = context.get("failed_attempts") {
            if let Some(count) = attempts.as_u64() {
                if count > 3 {
                    risk *= 1.0 + (count as f64 * 0.2);
                }
            }
        }
        
        risk.min(10.0)
    }
}

/// Compliance monitoring and reporting engine
pub struct ComplianceMonitor {
    standards: HashMap<ComplianceStandard, ComplianceRules>,
}

#[derive(Debug, Clone)]
pub struct ComplianceRules {
    pub required_events: Vec<SecurityEventType>,
    pub retention_days: u32,
    pub encryption_required: bool,
    pub real_time_monitoring: bool,
}

impl ComplianceMonitor {
    pub fn new() -> Self {
        let mut standards = HashMap::new();
        
        // FIPS 140-3 requirements
        standards.insert(ComplianceStandard::FIPS140_3, ComplianceRules {
            required_events: vec![
                SecurityEventType::KeyGeneration { key_type: String::new(), key_id: String::new(), algorithm: String::new() },
                SecurityEventType::KeyRotation { old_key_id: String::new(), new_key_id: String::new(), algorithm: String::new() },
                SecurityEventType::HSMOperation { hsm_type: String::new(), operation: String::new(), success: false },
            ],
            retention_days: 2555, // 7 years
            encryption_required: true,
            real_time_monitoring: true,
        });
        
        // SOC 2 Type II requirements
        standards.insert(ComplianceStandard::SOC2TypeII, ComplianceRules {
            required_events: vec![
                SecurityEventType::AuthenticationSuccess { user: String::new(), method: String::new() },
                SecurityEventType::AccessGranted { user: String::new(), resource: String::new(), action: String::new() },
                SecurityEventType::AccessDenied { user: String::new(), resource: String::new(), action: String::new(), reason: String::new() },
            ],
            retention_days: 365,
            encryption_required: true,
            real_time_monitoring: true,
        });
        
        // PCI DSS requirements
        standards.insert(ComplianceStandard::PCIDSS, ComplianceRules {
            required_events: vec![
                SecurityEventType::AuthenticationSuccess { user: String::new(), method: String::new() },
                SecurityEventType::AuthenticationFailure { user: String::new(), method: String::new(), reason: String::new() },
                SecurityEventType::AccessGranted { user: String::new(), resource: String::new(), action: String::new() },
                SecurityEventType::AccessDenied { user: String::new(), resource: String::new(), action: String::new(), reason: String::new() },
                SecurityEventType::SecretAccess { secret_path: String::new(), user: String::new(), operation: String::new() },
            ],
            retention_days: 365,
            encryption_required: true,
            real_time_monitoring: true,
        });
        
        Self { standards }
    }
    
    pub async fn check_compliance(
        &self,
        standard: &ComplianceStandard,
        entries: &[AuditEntry],
    ) -> ComplianceReport {
        let rules = self.standards.get(standard).cloned().unwrap_or(ComplianceRules {
            required_events: Vec::new(),
            retention_days: 365,
            encryption_required: false,
            real_time_monitoring: false,
        });
        
        let mut findings = Vec::new();
        let mut statistics = HashMap::new();
        let mut compliance_score: f64 = 100.0;
        
        // Check for required events
        for required_event in &rules.required_events {
            let count = entries.iter()
                .filter(|e| std::mem::discriminant(&e.event_type) == std::mem::discriminant(required_event))
                .count();
            
            statistics.insert(format!("{:?}", required_event), count as u64);
            
            if count == 0 {
                findings.push(ComplianceFinding {
                    id: Uuid::new_v4().to_string(),
                    severity: AlertSeverity::High,
                    control_ref: format!("{:?}-event-logging", standard),
                    description: format!("Missing required event type: {:?}", required_event),
                    evidence: Vec::new(),
                    remediation: vec![
                        "Enable logging for this event type".to_string(),
                        "Review system configuration".to_string(),
                    ],
                });
                compliance_score -= 10.0;
            }
        }
        
        ComplianceReport {
            id: Uuid::new_v4().to_string(),
            standard: standard.clone(),
            generated_at: Utc::now(),
            period: (Utc::now() - Duration::days(30), Utc::now()),
            compliance_score: compliance_score.max(0.0),
            statistics,
            findings,
            recommendations: vec![
                "Implement comprehensive audit logging".to_string(),
                "Enable real-time monitoring".to_string(),
                "Review retention policies".to_string(),
            ],
        }
    }
}

impl AuditLogger {
    /// Create a new enhanced audit logger
    pub async fn new(storage: Arc<dyn AuditStorage>) -> Result<Self, CoreError> {
        Ok(Self {
            storage,
            source: "brankas".to_string(),
            alert_configs: Arc::new(RwLock::new(Vec::new())),
            retention_policies: Arc::new(RwLock::new(Vec::new())),
            risk_calculator: Arc::new(RiskCalculator::new()),
            compliance_monitor: Arc::new(ComplianceMonitor::new()),
        })
    }

    /// Create audit logger with custom source
    pub async fn with_source(
        storage: Arc<dyn AuditStorage>,
        source: String,
    ) -> Result<Self, CoreError> {
        let mut logger = Self::new(storage).await?;
        logger.source = source;
        Ok(logger)
    }

    /// Log a security event with full context
    pub async fn log_event(
        &self,
        event_type: SecurityEventType,
        user_id: Option<String>,
        session_id: Option<String>,
        client_ip: Option<String>,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<(), CoreError> {
        let risk_score = self.risk_calculator.calculate_risk(&event_type, &metadata);
        
        let entry = AuditEntry::builder()
            .event_type(event_type.clone())
            .action(format!("{:?}", event_type))
            .user_id(user_id.unwrap_or_default())
            .session_id(session_id.unwrap_or_default())
            .client_ip(client_ip.unwrap_or_default())
            .risk_score(risk_score)
            .success(true)
            .source(self.source.clone())
            .build();

        // Store the event
        self.storage.store(&entry).await?;

        // Check if this event triggers any alerts
        self.check_alerts(&entry).await?;

        Ok(())
    }

    /// Log a successful action
    pub async fn log_success(
        &self,
        action: String,
        event_type: SecurityEventType,
        resource: Option<ResourceId>,
        user_id: Option<String>,
    ) -> Result<(), CoreError> {
        let entry = AuditEntry::builder()
            .action(action)
            .event_type(event_type)
            .resource(resource)
            .user_id(user_id.unwrap_or_default())
            .success(true)
            .source(self.source.clone())
            .build();

        self.storage.store(&entry).await
    }

    /// Log a failed action
    pub async fn log_failure(
        &self,
        action: String,
        event_type: SecurityEventType,
        resource: Option<ResourceId>,
        user_id: Option<String>,
        error: String,
    ) -> Result<(), CoreError> {
        let entry = AuditEntry::builder()
            .action(action)
            .event_type(event_type)
            .resource(resource)
            .user_id(user_id.unwrap_or_default())
            .success(false)
            .error(error)
            .source(self.source.clone())
            .build();

        self.storage.store(&entry).await
    }

    /// Check for alert conditions
    async fn check_alerts(&self, entry: &AuditEntry) -> Result<(), CoreError> {
        let configs = self.alert_configs.read().await;
        
        for config in configs.iter() {
            if config.trigger_events.contains(&entry.event_type) && 
               entry.risk_score >= self.get_severity_threshold(&config.severity) {
                self.send_alert(config, entry).await?;
            }
        }
        
        Ok(())
    }
    
    /// Send alert notification
    async fn send_alert(&self, _config: &AlertConfig, entry: &AuditEntry) -> Result<(), CoreError> {
        info!(
            "SECURITY ALERT: {} - Risk Score: {} - User: {:?} - Event: {:?}",
            entry.action, entry.risk_score, entry.user_id, entry.event_type
        );
        
        // In a real implementation, this would send notifications through
        // configured channels (email, webhook, SIEM, etc.)
        
        Ok(())
    }
    
    /// Get risk threshold for alert severity
    fn get_severity_threshold(&self, severity: &AlertSeverity) -> f64 {
        match severity {
            AlertSeverity::Low => 3.0,
            AlertSeverity::Medium => 5.0,
            AlertSeverity::High => 7.0,
            AlertSeverity::Critical => 8.5,
        }
    }

    /// Generate compliance report
    pub async fn generate_compliance_report(
        &self,
        standard: ComplianceStandard,
        period: (DateTime<Utc>, DateTime<Utc>),
    ) -> Result<ComplianceReport, CoreError> {
        self.storage.generate_compliance_report(standard, period).await
    }

    /// Search for security incidents
    pub async fn search_incidents(
        &self,
        patterns: Vec<String>,
        time_range: (DateTime<Utc>, DateTime<Utc>),
    ) -> Result<Vec<SecurityIncident>, CoreError> {
        self.storage.search_incidents(patterns, time_range).await
    }

    /// Export audit data
    pub async fn export_data(
        &self,
        format: ExportFormat,
        filters: AuditFilters,
    ) -> Result<Vec<u8>, CoreError> {
        self.storage.export_data(format, filters).await
    }

    /// Verify audit trail integrity
    pub async fn verify_integrity(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<bool, CoreError> {
        self.storage.verify_integrity(from, to).await
    }

    /// Log a custom audit entry
    pub async fn log(&self, entry: AuditEntry) -> Result<(), CoreError> {
        self.storage.store(&entry).await
    }

    /// Retrieve audit entries
    pub async fn get_entries(&self, filters: AuditFilters) -> Result<Vec<AuditEntry>, CoreError> {
        self.storage.retrieve(filters).await
    }

    /// Count audit entries
    pub async fn count_entries(&self, filters: AuditFilters) -> Result<u64, CoreError> {
        self.storage.count(filters).await
    }

    /// Cleanup old audit entries
    pub async fn cleanup_before(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, CoreError> {
        self.storage.cleanup_before(before).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_builder() {
        let event_type = SecurityEventType::SecretCreation {
            secret_path: "test/secret".to_string(),
            user: "user123".to_string(),
        };
        
        let entry = AuditEntry::builder()
            .action("create_secret".to_string())
            .event_type(event_type.clone())
            .user_id("user123".to_string())
            .success(true)
            .risk_score(2.5)
            .metadata("key".to_string(), serde_json::Value::String("value".to_string()))
            .build();

        assert_eq!(entry.action, "create_secret");
        assert_eq!(entry.user_id, Some("user123".to_string()));
        assert!(entry.success);
        assert_eq!(entry.risk_score, 2.5);
        assert_eq!(entry.event_type, event_type);
        assert_eq!(
            entry.metadata.get("key"),
            Some(&serde_json::Value::String("value".to_string()))
        );
    }

    #[test]
    fn test_audit_filters_builder() {
        let filters = AuditFilters::builder()
            .user_id("user123".to_string())
            .action("create_*".to_string())
            .success_only()
            .paginate(50, 0)
            .build();

        assert_eq!(filters.user_id, Some("user123".to_string()));
        assert_eq!(filters.action, Some("create_*".to_string()));
        assert_eq!(filters.success, Some(true));
        assert_eq!(filters.limit, Some(50));
        assert_eq!(filters.offset, Some(0));
    }

    #[test]
    fn test_risk_calculator() {
        let calculator = RiskCalculator::new();
        let mut context = HashMap::new();
        context.insert("hour".to_string(), serde_json::Value::from(2));
        context.insert("geo_location".to_string(), serde_json::Value::String("CN".to_string()));
        
        let event = SecurityEventType::AuthenticationFailure {
            user: "test".to_string(),
            method: "password".to_string(),
            reason: "invalid_password".to_string(),
        };
        
        let risk = calculator.calculate_risk(&event, &context);
        assert!(risk > 7.0); // Base risk * time factor * geo factor
    }

    #[tokio::test]
    async fn test_compliance_monitor() {
        let monitor = ComplianceMonitor::new();
        let entries = vec![
            AuditEntry::builder()
                .event_type(SecurityEventType::AuthenticationSuccess {
                    user: "test".to_string(),
                    method: "password".to_string(),
                })
                .action("login".to_string())
                .success(true)
                .build(),
        ];
        
        let report = monitor.check_compliance(&ComplianceStandard::SOC2TypeII, &entries).await;
        assert!(!report.id.is_empty());
        assert_eq!(report.standard, ComplianceStandard::SOC2TypeII);
        assert!(report.compliance_score <= 100.0);
    }
}
