//! Compliance and audit logging for regulatory compliance
//!
//! Provides comprehensive audit trails, compliance reporting, and
//! regulatory compliance features for enterprise deployments.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

/// Compliance frameworks supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComplianceFramework {
    GDPR,
    CCPA,
    SOX,
    PciDss,
    HIPAA,
    ISO27001,
    NIST,
    FedRAMP,
}

impl ComplianceFramework {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComplianceFramework::GDPR => "GDPR",
            ComplianceFramework::CCPA => "CCPA",
            ComplianceFramework::SOX => "SOX",
            ComplianceFramework::PciDss => "PCI_DSS",
            ComplianceFramework::HIPAA => "HIPAA",
            ComplianceFramework::ISO27001 => "ISO27001",
            ComplianceFramework::NIST => "NIST",
            ComplianceFramework::FedRAMP => "FedRAMP",
        }
    }

    /// Get required audit retention period for this framework
    pub fn retention_period_days(&self) -> u32 {
        match self {
            ComplianceFramework::GDPR => 2555,     // 7 years
            ComplianceFramework::CCPA => 365,      // 1 year
            ComplianceFramework::SOX => 2555,      // 7 years
            ComplianceFramework::PciDss => 365,   // 1 year minimum
            ComplianceFramework::HIPAA => 2190,    // 6 years
            ComplianceFramework::ISO27001 => 1095, // 3 years
            ComplianceFramework::NIST => 2555,     // 7 years
            ComplianceFramework::FedRAMP => 2555,  // 7 years
        }
    }
}

/// Audit event types for compliance tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditEventType {
    // Authentication events
    Login,
    Logout,
    LoginFailed,
    PasswordChange,
    TokenRefresh,
    MFAVerification,

    // Authorization events
    AccessGranted,
    AccessDenied,
    PrivilegeEscalation,
    PolicyViolation,

    // Cryptographic events
    KeyGenerated,
    KeyRotated,
    KeyDeleted,
    Encryption,
    Decryption,
    Signing,
    Verification,

    // Data events
    SecretCreated,
    SecretRetrieved,
    SecretModified,
    SecretDeleted,
    SecretShared,
    SecretUnshared,

    // Administrative events
    UserCreated,
    UserModified,
    UserDeleted,
    RoleAssigned,
    RoleRevoked,
    ConfigurationChanged,

    // Security events
    SuspiciousActivity,
    BruteForceAttempt,
    SecurityViolation,
    ComplianceViolation,

    // System events
    BackupCreated,
    BackupRestored,
    SystemMaintenance,
    EmergencyAccess,
}

/// Audit event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Complete audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub severity: AuditSeverity,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub resource: String,
    pub action: String,
    pub details: HashMap<String, String>,
    pub result: String,
    pub compliance_frameworks: Vec<ComplianceFramework>,
    pub retention_required_until: Option<DateTime<Utc>>,
    pub immutable: bool,
}

/// Compliance audit report
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub report_period_start: DateTime<Utc>,
    pub report_period_end: DateTime<Utc>,
    pub total_events: u64,
    pub events_by_type: HashMap<AuditEventType, u64>,
    pub events_by_severity: HashMap<AuditSeverity, u64>,
    pub compliance_status: ComplianceStatus,
    pub violations: Vec<ComplianceViolation>,
    pub recommendations: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

/// Compliance status
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    MinorViolations,
    MajorViolations,
    NonCompliant,
}

/// Compliance violation record
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub violation_type: String,
    pub severity: AuditSeverity,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub remediation: Option<String>,
    pub status: ViolationStatus,
}

/// Violation status
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ViolationStatus {
    Open,
    InProgress,
    Resolved,
    Accepted, // Risk accepted
}

/// Compliance and audit manager
#[derive(Debug)]
pub struct ComplianceManager {
    enabled_frameworks: Vec<ComplianceFramework>,
    audit_log: Arc<RwLock<Vec<AuditLogEntry>>>,
}

impl ComplianceManager {
    pub fn new(frameworks: Vec<ComplianceFramework>) -> Self {
        let mut retention_policies = HashMap::new();
        for framework in &frameworks {
            retention_policies.insert(framework.clone(), framework.retention_period_days());
        }

        Self {
            enabled_frameworks: frameworks,
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Log an audit event
    pub async fn log_event(&self, entry: AuditLogEntry) {
        let mut log = self.audit_log.write().await;

        // Add retention requirement based on enabled frameworks
        let mut entry = entry;
        if !entry.compliance_frameworks.is_empty() {
            let max_retention = self
                .enabled_frameworks
                .iter()
                .map(|f| f.retention_period_days())
                .max()
                .unwrap_or(2555); // Default 7 years

            entry.retention_required_until =
                Some(entry.timestamp + chrono::Duration::days(max_retention as i64));
        }

        log.push(entry.clone());

        // Log to tracing for immediate visibility
        info!(
            "AUDIT [{}] {}: {} by {:?}",
            entry.severity.as_str(),
            entry.event_type.as_str(),
            entry.action,
            entry.user_id
        );

        // Send to external audit systems if configured
        self.send_to_external_audit(&entry).await;
    }

    /// Generate compliance report for a specific framework
    pub async fn generate_compliance_report(
        &self,
        framework: &ComplianceFramework,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> ComplianceReport {
        let log = self.audit_log.read().await;

        let framework_events: Vec<_> = log
            .iter()
            .filter(|entry| {
                entry.compliance_frameworks.contains(framework)
                    && entry.timestamp >= start_date
                    && entry.timestamp <= end_date
            })
            .collect();

        let mut events_by_type = HashMap::new();
        let mut events_by_severity = HashMap::new();
        let mut violations = Vec::new();

        for event in &framework_events {
            *events_by_type.entry(event.event_type.clone()).or_insert(0) += 1;
            *events_by_severity
                .entry(event.severity.clone())
                .or_insert(0) += 1;

            // Check for compliance violations
            if let Some(violation) = self.check_compliance_violation(framework, event) {
                violations.push(violation);
            }
        }

        let compliance_status = self.determine_compliance_status(&violations);

        let mut recommendations = Vec::new();
        if violations.len() > 0 {
            recommendations.push(format!(
                "Address {} compliance violations",
                violations.len()
            ));
        }
        if events_by_severity
            .get(&AuditSeverity::Critical)
            .unwrap_or(&0)
            > &0
        {
            recommendations.push("Review critical security events immediately".to_string());
        }

        ComplianceReport {
            framework: framework.clone(),
            report_period_start: start_date,
            report_period_end: end_date,
            total_events: framework_events.len() as u64,
            events_by_type,
            events_by_severity,
            compliance_status,
            violations,
            recommendations,
            generated_at: Utc::now(),
        }
    }

    /// Check if an audit event represents a compliance violation
    fn check_compliance_violation(
        &self,
        framework: &ComplianceFramework,
        event: &AuditLogEntry,
    ) -> Option<ComplianceViolation> {
        match framework {
            ComplianceFramework::GDPR => {
                // Check for unauthorized data access
                if matches!(
                    event.event_type,
                    AuditEventType::SecretRetrieved | AuditEventType::SecretModified
                ) && event.user_id.is_none()
                {
                    Some(ComplianceViolation {
                        violation_type: "UnauthorizedDataAccess".to_string(),
                        severity: AuditSeverity::High,
                        description: "Data accessed without proper authentication".to_string(),
                        timestamp: event.timestamp,
                        remediation: Some(
                            "Implement mandatory authentication for all data access".to_string(),
                        ),
                        status: ViolationStatus::Open,
                    })
                } else {
                    None
                }
            }
            ComplianceFramework::PciDss => {
                // Check for weak encryption
                if matches!(
                    event.event_type,
                    AuditEventType::Encryption | AuditEventType::Decryption
                ) {
                    Some(ComplianceViolation {
                        violation_type: "EncryptionValidation".to_string(),
                        severity: AuditSeverity::Medium,
                        description: "Verify encryption strength meets PCI DSS requirements"
                            .to_string(),
                        timestamp: event.timestamp,
                        remediation: Some(
                            "Ensure AES-256 or stronger encryption is used".to_string(),
                        ),
                        status: ViolationStatus::Open,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Determine overall compliance status
    fn determine_compliance_status(&self, violations: &[ComplianceViolation]) -> ComplianceStatus {
        let critical_count = violations
            .iter()
            .filter(|v| v.severity == AuditSeverity::Critical)
            .count();

        let high_count = violations
            .iter()
            .filter(|v| v.severity == AuditSeverity::High)
            .count();

        match (critical_count, high_count) {
            (0, 0) => ComplianceStatus::Compliant,
            (_, 0) => ComplianceStatus::MinorViolations,
            (0, _) => ComplianceStatus::MajorViolations,
            _ => ComplianceStatus::NonCompliant,
        }
    }

    /// Send audit events to external systems
    async fn send_to_external_audit(&self, entry: &AuditLogEntry) {
        // Implementation would integrate with external SIEM/SOC systems
        // For now, just log to stdout for demonstration

        if entry.severity == AuditSeverity::Critical {
            warn!("CRITICAL AUDIT EVENT: {:?}", entry);
        }
    }

    /// Get audit log entries
    pub async fn get_audit_log(&self, limit: Option<usize>) -> Vec<AuditLogEntry> {
        let log = self.audit_log.read().await;
        let limit = limit.unwrap_or(100);

        log.iter().rev().take(limit).cloned().collect()
    }

    /// Clean up old audit entries based on retention policies
    pub async fn cleanup_old_entries(&self) {
        let now = Utc::now();
        let mut log = self.audit_log.write().await;

        log.retain(|entry| {
            if let Some(retention_until) = entry.retention_required_until {
                entry.timestamp <= retention_until
            } else {
                // Default retention: 1 year
                let one_year_ago = now - chrono::Duration::days(365);
                entry.timestamp > one_year_ago
            }
        });

        info!(
            "Audit log cleanup completed. {} entries retained.",
            log.len()
        );
    }
}

impl AuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditSeverity::Low => "LOW",
            AuditSeverity::Medium => "MEDIUM",
            AuditSeverity::High => "HIGH",
            AuditSeverity::Critical => "CRITICAL",
        }
    }
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::Login => "LOGIN",
            AuditEventType::Logout => "LOGOUT",
            AuditEventType::LoginFailed => "LOGIN_FAILED",
            AuditEventType::PasswordChange => "PASSWORD_CHANGE",
            AuditEventType::TokenRefresh => "TOKEN_REFRESH",
            AuditEventType::MFAVerification => "MFA_VERIFICATION",
            AuditEventType::AccessGranted => "ACCESS_GRANTED",
            AuditEventType::AccessDenied => "ACCESS_DENIED",
            AuditEventType::PrivilegeEscalation => "PRIVILEGE_ESCALATION",
            AuditEventType::PolicyViolation => "POLICY_VIOLATION",
            AuditEventType::KeyGenerated => "KEY_GENERATED",
            AuditEventType::KeyRotated => "KEY_ROTATED",
            AuditEventType::KeyDeleted => "KEY_DELETED",
            AuditEventType::Encryption => "ENCRYPTION",
            AuditEventType::Decryption => "DECRYPTION",
            AuditEventType::Signing => "SIGNING",
            AuditEventType::Verification => "VERIFICATION",
            AuditEventType::SecretCreated => "SECRET_CREATED",
            AuditEventType::SecretRetrieved => "SECRET_RETRIEVED",
            AuditEventType::SecretModified => "SECRET_MODIFIED",
            AuditEventType::SecretDeleted => "SECRET_DELETED",
            AuditEventType::SecretShared => "SECRET_SHARED",
            AuditEventType::SecretUnshared => "SECRET_UNSHARED",
            AuditEventType::UserCreated => "USER_CREATED",
            AuditEventType::UserModified => "USER_MODIFIED",
            AuditEventType::UserDeleted => "USER_DELETED",
            AuditEventType::RoleAssigned => "ROLE_ASSIGNED",
            AuditEventType::RoleRevoked => "ROLE_REVOKED",
            AuditEventType::ConfigurationChanged => "CONFIGURATION_CHANGED",
            AuditEventType::SuspiciousActivity => "SUSPICIOUS_ACTIVITY",
            AuditEventType::BruteForceAttempt => "BRUTE_FORCE_ATTEMPT",
            AuditEventType::SecurityViolation => "SECURITY_VIOLATION",
            AuditEventType::ComplianceViolation => "COMPLIANCE_VIOLATION",
            AuditEventType::BackupCreated => "BACKUP_CREATED",
            AuditEventType::BackupRestored => "BACKUP_RESTORED",
            AuditEventType::SystemMaintenance => "SYSTEM_MAINTENANCE",
            AuditEventType::EmergencyAccess => "EMERGENCY_ACCESS",
        }
    }
}

/// Create compliance audit entry for authentication events
pub async fn audit_authentication_event(
    compliance_manager: &ComplianceManager,
    event_type: AuditEventType,
    user_id: Option<String>,
    session_id: Option<String>,
    ip_address: Option<String>,
    success: bool,
) {
    let severity = match (&event_type, success) {
        (AuditEventType::LoginFailed, _) => AuditSeverity::Medium,
        (AuditEventType::BruteForceAttempt, _) => AuditSeverity::High,
        (_, false) => AuditSeverity::Medium,
        _ => AuditSeverity::Low,
    };

    let entry = AuditLogEntry {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type,
        severity,
        user_id,
        session_id,
        ip_address,
        user_agent: None,
        resource: "authentication".to_string(),
        action: if success { "success" } else { "failed" }.to_string(),
        details: HashMap::new(),
        result: if success { "success" } else { "failure" }.to_string(),
        compliance_frameworks: vec![ComplianceFramework::GDPR, ComplianceFramework::SOX],
        retention_required_until: None,
        immutable: true,
    };

    compliance_manager.log_event(entry).await;
}

/// Create compliance audit entry for cryptographic operations
pub async fn audit_crypto_operation(
    compliance_manager: &ComplianceManager,
    event_type: AuditEventType,
    user_id: Option<String>,
    resource: String,
    operation_details: HashMap<String, String>,
) {
    let action = event_type.as_str().to_lowercase();
    let entry = AuditLogEntry {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type,
        severity: AuditSeverity::Low,
        user_id,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource,
        action,
        details: operation_details,
        result: "success".to_string(),
        compliance_frameworks: vec![ComplianceFramework::PciDss, ComplianceFramework::HIPAA],
        retention_required_until: None,
        immutable: true,
    };

    compliance_manager.log_event(entry).await;
}

/// Create compliance audit entry for data access
pub async fn audit_data_access(
    compliance_manager: &ComplianceManager,
    event_type: AuditEventType,
    user_id: Option<String>,
    resource: String,
    data_classification: Option<String>,
) {
    let mut details = HashMap::new();
    if let Some(classification) = data_classification {
        details.insert("data_classification".to_string(), classification);
    }

    let action = event_type.as_str().to_lowercase();
    let entry = AuditLogEntry {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type,
        severity: AuditSeverity::Low,
        user_id,
        session_id: None,
        ip_address: None,
        user_agent: None,
        resource,
        action,
        details,
        result: "success".to_string(),
        compliance_frameworks: vec![ComplianceFramework::GDPR, ComplianceFramework::CCPA],
        retention_required_until: None,
        immutable: true,
    };

    compliance_manager.log_event(entry).await;
}

/// Initialize compliance manager with common frameworks
pub async fn init_compliance_manager() -> Arc<ComplianceManager> {
    let frameworks = vec![
        ComplianceFramework::GDPR,
        ComplianceFramework::SOX,
        ComplianceFramework::PciDss,
        ComplianceFramework::HIPAA,
    ];

    let manager = Arc::new(ComplianceManager::new(frameworks));

    // Start cleanup task
    let manager_clone = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Hourly

        loop {
            interval.tick().await;
            manager_clone.cleanup_old_entries().await;
        }
    });

    info!("Compliance and audit logging initialized");
    manager
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compliance_manager_creation() {
        let frameworks = vec![ComplianceFramework::GDPR];
        let manager = ComplianceManager::new(frameworks);

        assert_eq!(manager.enabled_frameworks.len(), 1);
        assert_eq!(manager.enabled_frameworks[0], ComplianceFramework::GDPR);
    }

    #[tokio::test]
    async fn test_audit_event_logging() {
        let frameworks = vec![ComplianceFramework::GDPR];
        let manager = ComplianceManager::new(frameworks);

        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::Login,
            severity: AuditSeverity::Low,
            user_id: Some("test-user".to_string()),
            session_id: Some("test-session".to_string()),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: None,
            resource: "authentication".to_string(),
            action: "login".to_string(),
            details: HashMap::new(),
            result: "success".to_string(),
            compliance_frameworks: vec![ComplianceFramework::GDPR],
            retention_required_until: None,
            immutable: true,
        };

        manager.log_event(entry).await;

        let log = manager.get_audit_log(Some(10)).await;
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].event_type, AuditEventType::Login);
    }
}
