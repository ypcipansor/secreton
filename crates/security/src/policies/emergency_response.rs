//! Emergency Response System
//!
//! Provides incident detection, emergency break-glass access,
//! incident response workflows, and post-incident analysis.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum EmergencyError {
    #[error("Incident not found: {0}")]
    IncidentNotFound(String),
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Invalid _request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, EmergencyError>;

/// Incident severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    P3, // Low
    P2, // Medium
    P1, // High
    P0, // Critical
}

/// Incident type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentType {
    SecurityBreach,
    DataLeak,
    ServiceOutage,
    UnauthorizedAccess,
    ComplianceViolation,
    SystemFailure,
}

/// Incident _status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Detected,
    InProgress,
    Contained,
    Resolved,
    Closed,
}

/// Incident record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub _status: IncidentStatus,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub affected_resources: Vec<String>,
    pub assigned_to: Option<String>,
}

/// Break-glass access _request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakGlassAccess {
    pub access_id: String,
    pub incident_id: String,
    pub _user: String,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Response step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStep {
    pub step_id: String,
    pub _action: String,
    pub assignee: String,
    pub completed: bool,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Incident response workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentWorkflow {
    pub workflow_id: String,
    pub incident_id: String,
    pub steps: Vec<ResponseStep>,
    pub escalation_policy: Option<String>,
    pub started_at: DateTime<Utc>,
}

/// Post-incident report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostIncidentReport {
    pub report_id: String,
    pub incident_id: String,
    pub summary: String,
    pub root_cause: String,
    pub impact: String,
    pub timeline: Vec<TimelineEvent>,
    pub lessons_learned: Vec<String>,
    pub action_items: Vec<ActionItem>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionItem {
    pub description: String,
    pub owner: String,
    pub due_date: Option<DateTime<Utc>>,
    pub completed: bool,
}

/// Emergency response system
pub struct EmergencyResponse {
    incidents: Arc<RwLock<HashMap<String, Incident>>>,
    break_glass: Arc<RwLock<HashMap<String, BreakGlassAccess>>>,
    workflows: Arc<RwLock<HashMap<String, IncidentWorkflow>>>,
    reports: Arc<RwLock<HashMap<String, PostIncidentReport>>>,
}

impl EmergencyResponse {
    pub fn new() -> Self {
        Self {
            incidents: Arc::new(RwLock::new(HashMap::new())),
            break_glass: Arc::new(RwLock::new(HashMap::new())),
            workflows: Arc::new(RwLock::new(HashMap::new())),
            reports: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Detect and create incident
    pub async fn detect_incident(
        &self,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        description: String,
        affected_resources: Vec<String>,
    ) -> Result<Incident> {
        let incident = Incident {
            incident_id: Uuid::new_v4().to_string(),
            incident_type,
            severity,
            _status: IncidentStatus::Detected,
            description,
            detected_at: Utc::now(),
            resolved_at: None,
            affected_resources,
            assigned_to: None,
        };

        let mut incidents = self.incidents.write().await;
        incidents.insert(incident.incident_id.clone(), incident.clone());

        // Auto-create workflow for P0/P1
        if incident.severity <= IncidentSeverity::P1 {
            self.create_response_workflow(&incident).await?;
        }

        Ok(incident)
    }

    /// Create incident response workflow
    async fn create_response_workflow(&self, incident: &Incident) -> Result<IncidentWorkflow> {
        let workflow = IncidentWorkflow {
            workflow_id: Uuid::new_v4().to_string(),
            incident_id: incident.incident_id.clone(),
            steps: vec![
                ResponseStep {
                    step_id: "1".to_string(),
                    _action: "Assess incident scope".to_string(),
                    assignee: "on-call-engineer".to_string(),
                    completed: false,
                    completed_at: None,
                },
                ResponseStep {
                    step_id: "2".to_string(),
                    _action: "Contain incident".to_string(),
                    assignee: "security-team".to_string(),
                    completed: false,
                    completed_at: None,
                },
                ResponseStep {
                    step_id: "3".to_string(),
                    _action: "Notify stakeholders".to_string(),
                    assignee: "incident-manager".to_string(),
                    completed: false,
                    completed_at: None,
                },
            ],
            escalation_policy: Some("security-escalation".to_string()),
            started_at: Utc::now(),
        };

        let mut workflows = self.workflows.write().await;
        workflows.insert(workflow.workflow_id.clone(), workflow.clone());

        Ok(workflow)
    }

    /// Grant emergency break-glass access
    pub async fn grant_emergency_access(
        &self,
        incident_id: String,
        _user: String,
        reason: String,
        duration_hours: u32,
    ) -> Result<BreakGlassAccess> {
        let incidents = self.incidents.read().await;
        if !incidents.contains_key(&incident_id) {
            return Err(EmergencyError::IncidentNotFound(incident_id));
        }

        let access = BreakGlassAccess {
            access_id: Uuid::new_v4().to_string(),
            incident_id,
            _user,
            reason,
            requested_at: Utc::now(),
            approved_by: Some("auto-approved".to_string()),
            approved_at: Some(Utc::now()),
            expires_at: Utc::now() + Duration::hours(duration_hours as i64),
            revoked: false,
        };

        let mut break_glass = self.break_glass.write().await;
        break_glass.insert(access.access_id.clone(), access.clone());

        Ok(access)
    }

    /// Execute response workflow
    pub async fn execute_response(&self, workflow_id: &str) -> Result<()> {
        let mut workflows = self.workflows.write().await;
        let workflow = workflows
            .get_mut(workflow_id)
            .ok_or_else(|| EmergencyError::InvalidRequest("Workflow not found".to_string()))?;

        // Execute steps
        for step in &mut workflow.steps {
            if !step.completed {
                // Mock execution
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                step.completed = true;
                step.completed_at = Some(Utc::now());
            }
        }

        Ok(())
    }

    /// Resolve incident
    pub async fn resolve_incident(&self, incident_id: &str) -> Result<()> {
        let mut incidents = self.incidents.write().await;
        let incident = incidents
            .get_mut(incident_id)
            .ok_or_else(|| EmergencyError::IncidentNotFound(incident_id.to_string()))?;

        incident._status = IncidentStatus::Resolved;
        incident.resolved_at = Some(Utc::now());

        Ok(())
    }

    /// Create post-incident report
    pub async fn create_post_incident_report(
        &self,
        incident_id: String,
        summary: String,
        root_cause: String,
        impact: String,
    ) -> Result<PostIncidentReport> {
        let report = PostIncidentReport {
            report_id: Uuid::new_v4().to_string(),
            incident_id: incident_id.clone(),
            summary,
            root_cause,
            impact,
            timeline: vec![TimelineEvent {
                timestamp: Utc::now(),
                description: "Incident detected".to_string(),
                actor: "system".to_string(),
            }],
            lessons_learned: vec![
                "Improve monitoring coverage".to_string(),
                "Update runbooks".to_string(),
            ],
            action_items: vec![ActionItem {
                description: "Review access controls".to_string(),
                owner: "security-team".to_string(),
                due_date: Some(Utc::now() + Duration::days(7)),
                completed: false,
            }],
            created_at: Utc::now(),
        };

        let mut reports = self.reports.write().await;
        reports.insert(report.report_id.clone(), report.clone());

        Ok(report)
    }

    /// Revoke break-glass access
    pub async fn revoke_access(&self, access_id: &str) -> Result<()> {
        let mut break_glass = self.break_glass.write().await;
        if let Some(access) = break_glass.get_mut(access_id) {
            access.revoked = true;
        }
        Ok(())
    }

    /// Get active incidents
    pub async fn get_active_incidents(&self) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents
            .values()
            .filter(|i| i._status != IncidentStatus::Closed)
            .cloned()
            .collect()
    }

    /// Get incident by ID
    pub async fn get_incident(&self, incident_id: &str) -> Result<Incident> {
        let incidents = self.incidents.read().await;
        incidents
            .get(incident_id)
            .cloned()
            .ok_or_else(|| EmergencyError::IncidentNotFound(incident_id.to_string()))
    }

    /// List break-glass accesses
    pub async fn list_break_glass_accesses(&self) -> Vec<BreakGlassAccess> {
        let break_glass = self.break_glass.read().await;
        break_glass.values().cloned().collect()
    }

    /// Get workflow for incident
    pub async fn get_incident_workflow(&self, incident_id: &str) -> Option<IncidentWorkflow> {
        let workflows = self.workflows.read().await;
        workflows
            .values()
            .find(|w| w.incident_id == incident_id)
            .cloned()
    }
}

impl Default for EmergencyResponse {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detect_incident() {
        let response = EmergencyResponse::new();

        let incident = response
            .detect_incident(
                IncidentType::SecurityBreach,
                IncidentSeverity::P1,
                "Unauthorized access detected".to_string(),
                vec!["/_secret/production".to_string()],
            )
            .await
            .unwrap();

        assert_eq!(incident.severity, IncidentSeverity::P1);
        assert_eq!(incident._status, IncidentStatus::Detected);
    }

    #[tokio::test]
    async fn test_grant_emergency_access() {
        let response = EmergencyResponse::new();

        let incident = response
            .detect_incident(
                IncidentType::ServiceOutage,
                IncidentSeverity::P0,
                "Critical outage".to_string(),
                vec![],
            )
            .await
            .unwrap();

        let access = response
            .grant_emergency_access(
                incident.incident_id.clone(),
                "admin@example.com".to_string(),
                "Emergency recovery".to_string(),
                4,
            )
            .await
            .unwrap();

        assert!(!access.revoked);
        assert!(access.approved_at.is_some());
    }

    #[tokio::test]
    async fn test_execute_response_workflow() {
        let response = EmergencyResponse::new();

        let incident = response
            .detect_incident(
                IncidentType::SecurityBreach,
                IncidentSeverity::P1,
                "Test incident".to_string(),
                vec![],
            )
            .await
            .unwrap();

        let workflow = response
            .get_incident_workflow(&incident.incident_id)
            .await
            .unwrap();

        response
            .execute_response(&workflow.workflow_id)
            .await
            .unwrap();

        let updated = response
            .get_incident_workflow(&incident.incident_id)
            .await
            .unwrap();
        assert!(updated.steps.iter().all(|s| s.completed));
    }

    #[tokio::test]
    async fn test_resolve_incident() {
        let response = EmergencyResponse::new();

        let incident = response
            .detect_incident(
                IncidentType::DataLeak,
                IncidentSeverity::P2,
                "Test".to_string(),
                vec![],
            )
            .await
            .unwrap();

        response
            .resolve_incident(&incident.incident_id)
            .await
            .unwrap();

        let resolved = response.get_incident(&incident.incident_id).await.unwrap();
        assert_eq!(resolved._status, IncidentStatus::Resolved);
        assert!(resolved.resolved_at.is_some());
    }

    #[tokio::test]
    async fn test_post_incident_report() {
        let response = EmergencyResponse::new();

        let incident = response
            .detect_incident(
                IncidentType::ComplianceViolation,
                IncidentSeverity::P3,
                "Test".to_string(),
                vec![],
            )
            .await
            .unwrap();

        let report = response
            .create_post_incident_report(
                incident.incident_id,
                "Summary of incident".to_string(),
                "Root cause analysis".to_string(),
                "Impact assessment".to_string(),
            )
            .await
            .unwrap();

        assert!(!report.lessons_learned.is_empty());
        assert!(!report.action_items.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_access() {
        let response = EmergencyResponse::new();

        let incident = response
            .detect_incident(
                IncidentType::SystemFailure,
                IncidentSeverity::P1,
                "Test".to_string(),
                vec![],
            )
            .await
            .unwrap();

        let access = response
            .grant_emergency_access(
                incident.incident_id,
                "_user@example.com".to_string(),
                "Emergency".to_string(),
                2,
            )
            .await
            .unwrap();

        response.revoke_access(&access.access_id).await.unwrap();

        let accesses = response.list_break_glass_accesses().await;
        let revoked = accesses
            .iter()
            .find(|a| a.access_id == access.access_id)
            .unwrap();
        assert!(revoked.revoked);
    }
}
