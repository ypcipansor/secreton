//! Real-Time Threat Intelligence and Response System
//!
//! Provides comprehensive threat intelligence integration and automated response:
//! - Multi-source threat intelligence feeds (commercial, open source, government)
//! - Real-time threat correlation and analysis
//! - Behavioral anomaly detection and machine learning
//! - Automated incident response and containment
//! - Threat hunting and advanced persistent threat (APT) detection
//! - Integration with external security tools (SIEM, SOAR, EDR)
//! - Threat intelligence sharing and collaboration
//! - Predictive threat modeling and risk assessment

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Threat intelligence sources
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatIntelSource {
    /// Commercial threat intelligence feeds
    Commercial(String), // e.g., "Mandiant", "CrowdStrike", "Recorded Future"

    /// Government and public sector feeds
    Government(String), // e.g., "US-CERT", "NCSC", "CISA"

    /// Open source intelligence
    OpenSource(String), // e.g., "MISP", "AlienVault OTX", "VirusTotal"

    /// Internal threat intelligence
    Internal(String), // e.g., "SOC", "Incident Response", "Threat Hunting"

    /// Industry sharing groups
    IndustrySharing(String), // e.g., "FS-ISAC", "E-ISAC", "H-ISAC"

    /// Dark web monitoring
    DarkWeb(String),

    /// Social media monitoring
    SocialMedia(String),

    /// Custom sources
    Custom(String),
}

/// Threat intelligence indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: ConfidenceLevel,
    pub severity: ThreatSeverity,
    pub source: ThreatIntelSource,
    pub tags: HashSet<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub description: String,
    pub context: ThreatContext,
    pub kill_chain_phases: Vec<KillChainPhase>,
    pub attributed_actors: Vec<ThreatActor>,
    pub related_indicators: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IndicatorType {
    /// Network indicators
    IpAddress,
    Domain,
    Url,
    EmailAddress,
    NetworkSignature,

    /// File indicators
    FileHash(HashType),
    FileName,
    FilePath,
    FileSignature,

    /// Registry indicators
    RegistryKey,
    RegistryValue,

    /// Process indicators
    ProcessName,
    CommandLine,

    /// Email indicators
    EmailSubject,
    EmailSender,
    EmailAttachment,

    /// Behavioral indicators
    UserBehavior,
    NetworkBehavior,
    SystemBehavior,

    /// Cryptocurrency indicators
    BitcoinAddress,
    EthereumAddress,

    /// Certificate indicators
    CertificateHash,
    CertificateSerial,

    /// Custom indicators
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
    SSDEEP,
    IMPHASH,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ConfidenceLevel {
    Low = 25,
    Medium = 50,
    High = 75,
    VeryHigh = 95,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub campaign: Option<String>,
    pub malware_family: Option<String>,
    pub attack_patterns: Vec<String>,
    pub vulnerabilities: Vec<String>,
    pub targeted_sectors: Vec<String>,
    pub targeted_regions: Vec<String>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_activity: Option<DateTime<Utc>>,
    pub additional_context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KillChainPhase {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
    // MITRE ATT&CK phases
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub name: String,
    pub aliases: Vec<String>,
    pub actor_type: ActorType,
    pub motivation: Vec<String>,
    pub sophistication_level: SophisticationLevel,
    pub attributed_campaigns: Vec<String>,
    pub known_tools: Vec<String>,
    pub target_sectors: Vec<String>,
    pub origin: Option<String>,
    pub active_since: Option<DateTime<Utc>>,
    pub last_activity: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActorType {
    NationState,
    CybercriminalGroup,
    HacktivistGroup,
    InsiderThreat,
    ScriptKiddie,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SophisticationLevel {
    Minimal,
    Opportunistic,
    Intermediate,
    Advanced,
    Expert,
}

/// Threat detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub detection_id: String,
    pub matched_indicators: Vec<ThreatIndicator>,
    pub detection_time: DateTime<Utc>,
    pub source_event: SourceEvent,
    pub risk_score: f64,
    pub confidence: f64,
    pub alert_level: AlertLevel,
    pub potential_impact: ImpactAssessment,
    pub recommended_actions: Vec<ResponseAction>,
    pub investigation_priority: InvestigationPriority,
    pub status: DetectionStatus,
    pub assigned_analyst: Option<String>,
    pub false_positive_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub source_system: String,
    pub raw_data: HashMap<String, serde_json::Value>,
    pub normalized_data: HashMap<String, String>,
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum AlertLevel {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub confidentiality_impact: ImpactLevel,
    pub integrity_impact: ImpactLevel,
    pub availability_impact: ImpactLevel,
    pub financial_impact: Option<f64>,
    pub reputational_impact: ImpactLevel,
    pub regulatory_impact: ImpactLevel,
    pub affected_assets: Vec<String>,
    pub affected_users: Vec<String>,
    pub estimated_recovery_time: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvestigationPriority {
    P1, // Critical - Immediate response required
    P2, // High - Response within 4 hours
    P3, // Medium - Response within 24 hours
    P4, // Low - Response within 72 hours
    P5, // Info - Response as resources permit
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionStatus {
    New,
    InProgress,
    Escalated,
    Resolved,
    FalsePositive,
    Closed,
}

/// Automated response actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_id: String,
    pub action_type: ResponseActionType,
    pub description: String,
    pub automation_level: AutomationLevel,
    pub estimated_impact: ActionImpact,
    pub prerequisites: Vec<String>,
    pub execution_time: Option<Duration>,
    pub rollback_procedure: Option<String>,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseActionType {
    /// Network actions
    BlockIpAddress,
    BlockDomain,
    IsolateHost,
    UpdateFirewallRules,

    /// Endpoint actions
    QuarantineFile,
    KillProcess,
    DisableUser,
    ForcePasswordReset,

    /// Email actions
    QuarantineEmail,
    BlockSender,

    /// Access control actions
    RevokeAccess,
    RequireAdditionalAuth,

    /// Monitoring actions
    IncreaseLogging,
    DeployHoneypot,

    /// Communication actions
    NotifySOC,
    NotifyIncidentResponse,
    NotifyManagement,
    NotifyExternal,

    /// Investigation actions
    CollectForensics,
    CreateTicket,
    StartInvestigation,

    /// Custom actions
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AutomationLevel {
    Manual,        // Manual execution only
    SemiAutomatic, // Automatic with approval
    Automatic,     // Fully automatic
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionImpact {
    pub business_impact: ImpactLevel,
    pub user_impact: ImpactLevel,
    pub system_impact: ImpactLevel,
    pub reversibility: bool,
    pub side_effects: Vec<String>,
}

/// Behavioral anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnomaly {
    pub anomaly_id: String,
    pub anomaly_type: AnomalyType,
    pub entity: String, // User, host, application, etc.
    pub baseline_behavior: BehaviorBaseline,
    pub observed_behavior: ObservedBehavior,
    pub anomaly_score: f64, // 0.0 to 1.0
    pub detection_time: DateTime<Utc>,
    pub duration: Duration,
    pub context: HashMap<String, String>,
    pub similar_anomalies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalyType {
    UserBehavior,
    NetworkTraffic,
    SystemResource,
    ApplicationUsage,
    DataAccess,
    LoginPattern,
    FileActivity,
    ProcessBehavior,
    Communication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    pub entity_id: String,
    pub behavior_type: AnomalyType,
    pub baseline_period: (DateTime<Utc>, DateTime<Utc>),
    pub statistical_profile: StatisticalProfile,
    pub temporal_patterns: HashMap<String, f64>, // hourly, daily, weekly patterns
    pub peer_group_comparison: Option<PeerGroupProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalProfile {
    pub mean: f64,
    pub median: f64,
    pub std_deviation: f64,
    pub percentiles: HashMap<String, f64>, // 95th, 99th, etc.
    pub seasonal_adjustments: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGroupProfile {
    pub peer_group: String,
    pub peer_baseline: StatisticalProfile,
    pub deviation_from_peers: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedBehavior {
    pub observation_time: DateTime<Utc>,
    pub metrics: HashMap<String, f64>,
    pub patterns: HashMap<String, f64>,
    pub deviations: HashMap<String, f64>,
    pub contextual_factors: HashMap<String, String>,
}

/// Threat hunting capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHunt {
    pub hunt_id: String,
    pub name: String,
    pub description: String,
    pub hypothesis: String,
    pub hunting_techniques: Vec<HuntingTechnique>,
    pub data_sources: Vec<String>,
    pub search_queries: Vec<SearchQuery>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub status: HuntStatus,
    pub findings: Vec<HuntFinding>,
    pub duration: Option<Duration>,
    pub resources_used: ResourceUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HuntStatus {
    Planning,
    Active,
    Analyzing,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingTechnique {
    pub technique_id: String,
    pub name: String,
    pub description: String,
    pub mitre_technique: Option<String>,
    pub detection_logic: String,
    pub false_positive_filters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query_id: String,
    pub query_language: String, // KQL, SQL, Sigma, etc.
    pub query_text: String,
    pub data_sources: Vec<String>,
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    pub results_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntFinding {
    pub finding_id: String,
    pub severity: ThreatSeverity,
    pub confidence: ConfidenceLevel,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub affected_entities: Vec<String>,
    pub recommended_actions: Vec<ResponseAction>,
    pub false_positive_likelihood: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: String,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub data: HashMap<String, serde_json::Value>,
    pub relevance_score: f64,
    pub chain_of_custody: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_time: Duration,
    pub memory_usage: u64,      // bytes
    pub storage_scanned: u64,   // bytes
    pub network_bandwidth: u64, // bytes
    pub compute_cost: Option<f64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ThreatIntelError {
    #[error("Source connection failed: {0} - {1}")]
    SourceConnectionFailed(String, String),

    #[error("Indicator parsing failed: {0}")]
    IndicatorParsingFailed(String),

    #[error("Detection analysis failed: {0}")]
    DetectionAnalysisFailed(String),

    #[error("Response action failed: {0} - {1}")]
    ResponseActionFailed(String, String),

    #[error("Behavioral analysis failed: {0}")]
    BehavioralAnalysisFailed(String),

    #[error("Threat hunt failed: {0} - {1}")]
    ThreatHuntFailed(String, String),

    #[error("Integration error: {0} - {1}")]
    IntegrationError(String, String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Configuration error: {0} - {1}")]
    ConfigurationError(String, String),
}

/// Trait for threat intelligence sources
#[async_trait]
pub trait ThreatIntelligenceSource: Send + Sync {
    async fn fetch_indicators(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError>;
    async fn query_indicator(
        &self,
        indicator_value: &str,
    ) -> Result<Option<ThreatIndicator>, ThreatIntelError>;
    async fn submit_indicator(&self, indicator: &ThreatIndicator) -> Result<(), ThreatIntelError>;
    fn get_source_info(&self) -> ThreatIntelSource;
    fn get_supported_indicator_types(&self) -> Vec<IndicatorType>;
    async fn test_connection(&self) -> Result<bool, ThreatIntelError>;
}

/// Trait for response action executors
#[async_trait]
pub trait ResponseActionExecutor: Send + Sync {
    async fn execute_action(
        &self,
        action: &ResponseAction,
        context: &HashMap<String, String>,
    ) -> Result<ExecutionResult, ThreatIntelError>;
    async fn rollback_action(
        &self,
        action: &ResponseAction,
        execution_result: &ExecutionResult,
    ) -> Result<(), ThreatIntelError>;
    fn get_supported_actions(&self) -> Vec<ResponseActionType>;
    async fn validate_action(&self, action: &ResponseAction) -> Result<bool, ThreatIntelError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub execution_time: DateTime<Utc>,
    pub duration: Duration,
    pub output: String,
    pub error_message: Option<String>,
    pub rollback_data: Option<HashMap<String, String>>,
}

/// Main Threat Intelligence and Response Engine
pub struct ThreatIntelligenceEngine {
    sources: Arc<RwLock<HashMap<String, Arc<dyn ThreatIntelligenceSource>>>>,
    executors: Arc<RwLock<HashMap<String, Arc<dyn ResponseActionExecutor>>>>,
    indicators: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    detections: Arc<RwLock<HashMap<String, ThreatDetection>>>,
    anomalies: Arc<RwLock<HashMap<String, BehavioralAnomaly>>>,
    threat_hunts: Arc<RwLock<HashMap<String, ThreatHunt>>>,
    behavior_baselines: Arc<RwLock<HashMap<String, BehaviorBaseline>>>,
    config: ThreatIntelConfig,
    metrics: Arc<Mutex<ThreatIntelMetrics>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub indicator_refresh_interval: Duration,
    pub detection_threshold: f64,
    pub auto_response_enabled: bool,
    pub false_positive_threshold: f64,
    pub behavioral_analysis_enabled: bool,
    pub threat_hunting_enabled: bool,
    pub data_retention_period: Duration,
    pub correlation_time_window: Duration,
    pub machine_learning_enabled: bool,
    pub external_sharing_enabled: bool,
    pub notification_settings: ThreatNotificationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatNotificationSettings {
    pub critical_alerts_immediate: bool,
    pub high_alerts_within: Duration,
    pub notification_channels: Vec<String>,
    pub escalation_rules: Vec<EscalationRule>,
    pub alert_suppression: AlertSuppression,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub condition: String,
    pub escalation_target: String,
    pub escalation_delay: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSuppression {
    pub enabled: bool,
    pub suppression_window: Duration,
    pub max_alerts_per_window: usize,
    pub grouping_criteria: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ThreatIntelMetrics {
    pub indicators_processed: u64,
    pub detections_generated: u64,
    pub false_positives: u64,
    pub true_positives: u64,
    pub response_actions_executed: u64,
    pub threat_hunts_completed: u64,
    pub anomalies_detected: u64,
    pub indicators_by_severity: HashMap<ThreatSeverity, u64>,
    pub detections_by_source: HashMap<String, u64>,
    pub response_time_metrics: VecDeque<Duration>,
    pub accuracy_metrics: HashMap<String, f64>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            indicator_refresh_interval: Duration::from_secs(300), // 5 minutes
            detection_threshold: 0.7,                             // 70% confidence threshold
            auto_response_enabled: true,
            false_positive_threshold: 0.1, // 10% false positive threshold
            behavioral_analysis_enabled: true,
            threat_hunting_enabled: true,
            data_retention_period: Duration::from_secs(86400 * 365), // 1 year
            correlation_time_window: Duration::from_secs(3600),      // 1 hour
            machine_learning_enabled: true,
            external_sharing_enabled: false, // Requires careful configuration
            notification_settings: ThreatNotificationSettings {
                critical_alerts_immediate: true,
                high_alerts_within: Duration::from_secs(900), // 15 minutes
                notification_channels: vec![
                    "email".to_string(),
                    "slack".to_string(),
                    "siem".to_string(),
                ],
                escalation_rules: vec![EscalationRule {
                    condition: "critical_unacknowledged_30min".to_string(),
                    escalation_target: "security_manager".to_string(),
                    escalation_delay: Duration::from_secs(1800), // 30 minutes
                }],
                alert_suppression: AlertSuppression {
                    enabled: true,
                    suppression_window: Duration::from_secs(300), // 5 minutes
                    max_alerts_per_window: 10,
                    grouping_criteria: vec!["source_ip".to_string(), "indicator_type".to_string()],
                },
            },
        }
    }
}

impl ThreatIntelligenceEngine {
    pub fn new(config: ThreatIntelConfig) -> Self {
        Self {
            sources: Arc::new(RwLock::new(HashMap::new())),
            executors: Arc::new(RwLock::new(HashMap::new())),
            indicators: Arc::new(RwLock::new(HashMap::new())),
            detections: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(HashMap::new())),
            threat_hunts: Arc::new(RwLock::new(HashMap::new())),
            behavior_baselines: Arc::new(RwLock::new(HashMap::new())),
            config,
            metrics: Arc::new(Mutex::new(ThreatIntelMetrics::default())),
        }
    }

    /// Register a threat intelligence source
    pub fn register_source(&self, name: String, source: Arc<dyn ThreatIntelligenceSource>) {
        let mut sources = self.sources.write().unwrap();
        sources.insert(name, source);
    }

    /// Register a response action executor
    pub fn register_executor(&self, name: String, executor: Arc<dyn ResponseActionExecutor>) {
        let mut executors = self.executors.write().unwrap();
        executors.insert(name, executor);
    }

    /// Ingest threat indicators from all sources
    pub async fn ingest_threat_indicators(&self) -> Result<usize, ThreatIntelError> {
        let sources = self.sources.read().unwrap().clone();
        let mut total_indicators = 0;

        for (source_name, source) in sources {
            match source.fetch_indicators(None).await {
                Ok(indicators) => {
                    for indicator in indicators {
                        self.store_indicator(indicator).await?;
                        total_indicators += 1;
                    }
                    info!("Ingested indicators from source: {}", source_name);
                }
                Err(e) => {
                    error!("Failed to ingest from source {}: {}", source_name, e);
                    continue;
                }
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.indicators_processed += total_indicators as u64;
        }

        info!("Total indicators ingested: {}", total_indicators);
        Ok(total_indicators)
    }

    /// Store threat indicator
    async fn store_indicator(
        &self,
        mut indicator: ThreatIndicator,
    ) -> Result<(), ThreatIntelError> {
        // Check for duplicates and merge if necessary
        {
            let mut indicators = self.indicators.write().unwrap();

            if let Some(existing) = indicators.get(&indicator.id) {
                // Update existing indicator with new information
                indicator = self.merge_indicators(existing, &indicator);
            }

            indicators.insert(indicator.id.clone(), indicator.clone());
        }

        // Update severity metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            *metrics
                .indicators_by_severity
                .entry(indicator.severity)
                .or_insert(0) += 1;
        }

        Ok(())
    }

    /// Merge two indicators
    fn merge_indicators(
        &self,
        existing: &ThreatIndicator,
        new: &ThreatIndicator,
    ) -> ThreatIndicator {
        let mut merged = existing.clone();

        // Take the higher confidence
        if new.confidence > existing.confidence {
            merged.confidence = new.confidence.clone();
        }

        // Take the higher severity
        if new.severity > existing.severity {
            merged.severity = new.severity.clone();
        }

        // Merge tags
        merged.tags.extend(new.tags.clone());

        // Update last seen
        if new.last_seen.is_some() {
            merged.last_seen = new.last_seen;
        }

        // Merge context
        if let Some(new_campaign) = &new.context.campaign {
            merged.context.campaign = Some(new_campaign.clone());
        }

        merged
            .context
            .attack_patterns
            .extend(new.context.attack_patterns.clone());
        merged
            .context
            .vulnerabilities
            .extend(new.context.vulnerabilities.clone());

        merged
    }

    /// Analyze event for threat indicators
    pub async fn analyze_event(
        &self,
        event: &SourceEvent,
    ) -> Result<Option<ThreatDetection>, ThreatIntelError> {
        let indicators = self.indicators.read().unwrap();
        let mut matched_indicators = Vec::new();
        let mut total_risk_score = 0.0;

        // Check event data against all indicators
        for indicator in indicators.values() {
            if self.match_indicator_to_event(indicator, event) {
                matched_indicators.push(indicator.clone());
                total_risk_score += self.calculate_indicator_risk_score(indicator);
            }
        }

        if matched_indicators.is_empty() {
            return Ok(None);
        }

        // Calculate overall confidence and risk
        let confidence = self.calculate_detection_confidence(&matched_indicators, event);
        let risk_score = total_risk_score / matched_indicators.len() as f64;

        // Check if detection meets threshold
        if confidence < self.config.detection_threshold {
            return Ok(None);
        }

        // Create detection
        let detection = ThreatDetection {
            detection_id: Uuid::new_v4().to_string(),
            matched_indicators,
            detection_time: Utc::now(),
            source_event: event.clone(),
            risk_score,
            confidence,
            alert_level: self.calculate_alert_level(risk_score),
            potential_impact: self.assess_potential_impact(event, risk_score),
            recommended_actions: self.generate_response_actions(risk_score, event),
            investigation_priority: self.calculate_investigation_priority(risk_score, confidence),
            status: DetectionStatus::New,
            assigned_analyst: None,
            false_positive_probability: self.estimate_false_positive_probability(event, confidence),
        };

        // Store detection
        {
            let mut detections = self.detections.write().unwrap();
            detections.insert(detection.detection_id.clone(), detection.clone());
        }

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.detections_generated += 1;
            *metrics
                .detections_by_source
                .entry(event.source_system.clone())
                .or_insert(0) += 1;
        }

        info!(
            "Threat detection created: {} (confidence: {:.2}, risk: {:.2})",
            detection.detection_id, confidence, risk_score
        );

        Ok(Some(detection))
    }

    /// Match indicator to event
    fn match_indicator_to_event(&self, indicator: &ThreatIndicator, event: &SourceEvent) -> bool {
        match &indicator.indicator_type {
            IndicatorType::IpAddress => event
                .normalized_data
                .values()
                .any(|value| value == &indicator.value),
            IndicatorType::Domain => event.normalized_data.values().any(|value| {
                value.contains(&indicator.value)
                    || value.ends_with(&format!(".{}", indicator.value))
            }),
            IndicatorType::FileHash(_) => event
                .normalized_data
                .values()
                .any(|value| value.to_lowercase() == indicator.value.to_lowercase()),
            IndicatorType::EmailAddress => event
                .normalized_data
                .values()
                .any(|value| value.to_lowercase() == indicator.value.to_lowercase()),
            IndicatorType::ProcessName => event
                .normalized_data
                .get("process_name")
                .map(|p| p.contains(&indicator.value))
                .unwrap_or(false),
            IndicatorType::CommandLine => event
                .normalized_data
                .get("command_line")
                .map(|cmd| cmd.contains(&indicator.value))
                .unwrap_or(false),
            _ => false, // TODO: Implement other indicator types
        }
    }

    /// Calculate risk score for an indicator
    fn calculate_indicator_risk_score(&self, indicator: &ThreatIndicator) -> f64 {
        let severity_weight = match indicator.severity {
            ThreatSeverity::Critical => 1.0,
            ThreatSeverity::High => 0.8,
            ThreatSeverity::Medium => 0.6,
            ThreatSeverity::Low => 0.4,
            ThreatSeverity::Info => 0.2,
        };

        let confidence_weight = match indicator.confidence {
            ConfidenceLevel::VeryHigh => 1.0,
            ConfidenceLevel::High => 0.8,
            ConfidenceLevel::Medium => 0.6,
            ConfidenceLevel::Low => 0.4,
        };

        // Age factor - newer indicators are generally more relevant
        let age_factor = if let Some(created) = indicator
            .created_at
            .checked_add_signed(chrono::Duration::days(30))
        {
            if Utc::now() < created {
                1.0 // Fresh indicator
            } else {
                0.7 // Older indicator
            }
        } else {
            0.5
        };

        (severity_weight * confidence_weight * age_factor) * 100.0
    }

    /// Calculate detection confidence
    fn calculate_detection_confidence(
        &self,
        indicators: &[ThreatIndicator],
        _event: &SourceEvent,
    ) -> f64 {
        if indicators.is_empty() {
            return 0.0;
        }

        let total_confidence: f64 = indicators
            .iter()
            .map(|i| match i.confidence {
                ConfidenceLevel::VeryHigh => 0.95,
                ConfidenceLevel::High => 0.75,
                ConfidenceLevel::Medium => 0.5,
                ConfidenceLevel::Low => 0.25,
            })
            .sum();

        (total_confidence / indicators.len() as f64).min(1.0)
    }

    /// Calculate alert level
    fn calculate_alert_level(&self, risk_score: f64) -> AlertLevel {
        match risk_score {
            score if score >= 90.0 => AlertLevel::Critical,
            score if score >= 70.0 => AlertLevel::High,
            score if score >= 50.0 => AlertLevel::Medium,
            score if score >= 30.0 => AlertLevel::Low,
            _ => AlertLevel::Info,
        }
    }

    /// Assess potential impact
    fn assess_potential_impact(&self, _event: &SourceEvent, risk_score: f64) -> ImpactAssessment {
        let impact_level = match risk_score {
            score if score >= 90.0 => ImpactLevel::Critical,
            score if score >= 70.0 => ImpactLevel::High,
            score if score >= 50.0 => ImpactLevel::Medium,
            score if score >= 30.0 => ImpactLevel::Low,
            _ => ImpactLevel::None,
        };

        ImpactAssessment {
            confidentiality_impact: impact_level.clone(),
            integrity_impact: impact_level.clone(),
            availability_impact: impact_level.clone(),
            financial_impact: Some(risk_score * 1000.0), // Mock financial impact
            reputational_impact: impact_level.clone(),
            regulatory_impact: impact_level,
            affected_assets: Vec::new(), // TODO: Determine from event
            affected_users: Vec::new(),  // TODO: Determine from event
            estimated_recovery_time: Some(Duration::from_secs(3600)), // 1 hour default
        }
    }

    /// Generate response actions
    fn generate_response_actions(
        &self,
        risk_score: f64,
        event: &SourceEvent,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        // Always create investigation ticket
        actions.push(ResponseAction {
            action_id: Uuid::new_v4().to_string(),
            action_type: ResponseActionType::CreateTicket,
            description: "Create investigation ticket for threat detection".to_string(),
            automation_level: AutomationLevel::Automatic,
            estimated_impact: ActionImpact {
                business_impact: ImpactLevel::None,
                user_impact: ImpactLevel::None,
                system_impact: ImpactLevel::None,
                reversibility: true,
                side_effects: Vec::new(),
            },
            prerequisites: Vec::new(),
            execution_time: Some(Duration::from_secs(30)),
            rollback_procedure: Some("Close ticket".to_string()),
            approval_required: false,
        });

        // High-risk actions
        if risk_score >= 70.0 {
            // Block IP if available
            if let Some(ip) = event.normalized_data.get("source_ip") {
                actions.push(ResponseAction {
                    action_id: Uuid::new_v4().to_string(),
                    action_type: ResponseActionType::BlockIpAddress,
                    description: format!("Block suspicious IP address: {}", ip),
                    automation_level: AutomationLevel::SemiAutomatic,
                    estimated_impact: ActionImpact {
                        business_impact: ImpactLevel::Low,
                        user_impact: ImpactLevel::Medium,
                        system_impact: ImpactLevel::Low,
                        reversibility: true,
                        side_effects: vec!["Legitimate traffic may be blocked".to_string()],
                    },
                    prerequisites: vec!["Firewall access".to_string()],
                    execution_time: Some(Duration::from_secs(60)),
                    rollback_procedure: Some("Remove firewall rule".to_string()),
                    approval_required: true,
                });
            }

            // Isolate host if available
            if let Some(host) = event.normalized_data.get("hostname") {
                actions.push(ResponseAction {
                    action_id: Uuid::new_v4().to_string(),
                    action_type: ResponseActionType::IsolateHost,
                    description: format!("Isolate potentially compromised host: {}", host),
                    automation_level: AutomationLevel::Manual,
                    estimated_impact: ActionImpact {
                        business_impact: ImpactLevel::High,
                        user_impact: ImpactLevel::High,
                        system_impact: ImpactLevel::Medium,
                        reversibility: true,
                        side_effects: vec!["Host will be disconnected from network".to_string()],
                    },
                    prerequisites: vec!["EDR access".to_string(), "Network access".to_string()],
                    execution_time: Some(Duration::from_secs(300)),
                    rollback_procedure: Some("Restore network connectivity".to_string()),
                    approval_required: true,
                });
            }
        }

        // Critical risk actions
        if risk_score >= 90.0 {
            actions.push(ResponseAction {
                action_id: Uuid::new_v4().to_string(),
                action_type: ResponseActionType::NotifyIncidentResponse,
                description: "Notify incident response team of critical threat".to_string(),
                automation_level: AutomationLevel::Automatic,
                estimated_impact: ActionImpact {
                    business_impact: ImpactLevel::None,
                    user_impact: ImpactLevel::None,
                    system_impact: ImpactLevel::None,
                    reversibility: true,
                    side_effects: Vec::new(),
                },
                prerequisites: Vec::new(),
                execution_time: Some(Duration::from_secs(10)),
                rollback_procedure: None,
                approval_required: false,
            });
        }

        actions
    }

    /// Calculate investigation priority
    fn calculate_investigation_priority(
        &self,
        risk_score: f64,
        confidence: f64,
    ) -> InvestigationPriority {
        let combined_score = (risk_score * confidence) / 100.0;

        match combined_score {
            score if score >= 80.0 => InvestigationPriority::P1,
            score if score >= 60.0 => InvestigationPriority::P2,
            score if score >= 40.0 => InvestigationPriority::P3,
            score if score >= 20.0 => InvestigationPriority::P4,
            _ => InvestigationPriority::P5,
        }
    }

    /// Estimate false positive probability
    fn estimate_false_positive_probability(&self, _event: &SourceEvent, confidence: f64) -> f64 {
        // Simple heuristic - higher confidence means lower false positive probability
        (1.0 - confidence).max(0.01).min(0.99)
    }

    /// Execute response actions
    pub async fn execute_response_actions(
        &self,
        detection_id: &str,
    ) -> Result<usize, ThreatIntelError> {
        let detection = {
            let detections = self.detections.read().unwrap();
            detections.get(detection_id).cloned().ok_or_else(|| {
                ThreatIntelError::DetectionAnalysisFailed(format!(
                    "Detection {} not found",
                    detection_id
                ))
            })?
        };

        if !self.config.auto_response_enabled {
            info!(
                "Auto-response disabled, skipping action execution for detection {}",
                detection_id
            );
            return Ok(0);
        }

        let executors = self.executors.read().unwrap().clone();
        let mut executed_count = 0;
        let mut context = HashMap::new();
        context.insert("detection_id".to_string(), detection_id.to_string());

        for action in &detection.recommended_actions {
            // Check if action requires approval
            if action.approval_required && action.automation_level != AutomationLevel::Automatic {
                info!(
                    "Action {} requires approval, skipping automatic execution",
                    action.action_id
                );
                continue;
            }

            // Find appropriate executor
            let mut executor_found = false;
            for (executor_name, executor) in &executors {
                if executor
                    .get_supported_actions()
                    .contains(&action.action_type)
                {
                    match executor.execute_action(action, &context).await {
                        Ok(result) => {
                            if result.success {
                                info!(
                                    "Successfully executed action {} using executor {}",
                                    action.action_id, executor_name
                                );
                                executed_count += 1;
                            } else {
                                warn!(
                                    "Action execution failed: {}",
                                    result.error_message.unwrap_or_default()
                                );
                            }
                            executor_found = true;
                            break;
                        }
                        Err(e) => {
                            error!("Action execution error: {}", e);
                            continue;
                        }
                    }
                }
            }

            if !executor_found {
                warn!(
                    "No executor found for action type: {:?}",
                    action.action_type
                );
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.response_actions_executed += executed_count as u64;
        }

        info!(
            "Executed {} response actions for detection {}",
            executed_count, detection_id
        );
        Ok(executed_count)
    }

    /// Start threat intelligence monitoring  
    pub async fn start_threat_monitoring(self: Arc<Self>) {
        let engine = self;
        let refresh_interval = engine.config.indicator_refresh_interval;

        tokio::spawn(async move {
            let mut interval = interval(refresh_interval);

            loop {
                interval.tick().await;

                info!("Starting threat intelligence refresh");
                if let Err(e) = engine.ingest_threat_indicators().await {
                    error!("Threat intelligence refresh failed: {}", e);
                }
            }
        });

        info!("Threat intelligence monitoring started");
    }

    /// Get threat intelligence metrics
    pub fn get_metrics(&self) -> ThreatIntelMetrics {
        let metrics = self.metrics.lock().unwrap();
        ThreatIntelMetrics {
            indicators_processed: metrics.indicators_processed,
            detections_generated: metrics.detections_generated,
            false_positives: metrics.false_positives,
            true_positives: metrics.true_positives,
            response_actions_executed: metrics.response_actions_executed,
            threat_hunts_completed: metrics.threat_hunts_completed,
            anomalies_detected: metrics.anomalies_detected,
            indicators_by_severity: metrics.indicators_by_severity.clone(),
            detections_by_source: metrics.detections_by_source.clone(),
            response_time_metrics: metrics.response_time_metrics.clone(),
            accuracy_metrics: metrics.accuracy_metrics.clone(),
        }
    }
}

/// Mock threat intelligence source for testing
pub struct MockThreatIntelSource {
    pub source_info: ThreatIntelSource,
}

#[async_trait]
impl ThreatIntelligenceSource for MockThreatIntelSource {
    async fn fetch_indicators(
        &self,
        _since: Option<DateTime<Utc>>,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        // Generate mock indicators
        Ok(vec![ThreatIndicator {
            id: Uuid::new_v4().to_string(),
            indicator_type: IndicatorType::IpAddress,
            value: "192.168.1.100".to_string(),
            confidence: ConfidenceLevel::High,
            severity: ThreatSeverity::High,
            source: self.source_info.clone(),
            tags: HashSet::from(["malware".to_string(), "c2".to_string()]),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + ChronoDuration::days(30)),
            last_seen: Some(Utc::now()),
            description: "Known malware C2 server".to_string(),
            context: ThreatContext {
                campaign: Some("APT-TEST".to_string()),
                malware_family: Some("TestMalware".to_string()),
                attack_patterns: vec!["T1071.001".to_string()],
                vulnerabilities: Vec::new(),
                targeted_sectors: vec!["finance".to_string()],
                targeted_regions: vec!["global".to_string()],
                first_seen: Some(Utc::now() - ChronoDuration::days(7)),
                last_activity: Some(Utc::now()),
                additional_context: HashMap::new(),
            },
            kill_chain_phases: vec![KillChainPhase::CommandAndControl],
            attributed_actors: Vec::new(),
            related_indicators: Vec::new(),
            metadata: HashMap::new(),
        }])
    }

    async fn query_indicator(
        &self,
        indicator_value: &str,
    ) -> Result<Option<ThreatIndicator>, ThreatIntelError> {
        if indicator_value == "192.168.1.100" {
            let indicators = self.fetch_indicators(None).await?;
            Ok(indicators.into_iter().find(|i| i.value == indicator_value))
        } else {
            Ok(None)
        }
    }

    async fn submit_indicator(&self, _indicator: &ThreatIndicator) -> Result<(), ThreatIntelError> {
        Ok(())
    }

    fn get_source_info(&self) -> ThreatIntelSource {
        self.source_info.clone()
    }

    fn get_supported_indicator_types(&self) -> Vec<IndicatorType> {
        vec![
            IndicatorType::IpAddress,
            IndicatorType::Domain,
            IndicatorType::FileHash(HashType::SHA256),
        ]
    }

    async fn test_connection(&self) -> Result<bool, ThreatIntelError> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_intel_engine_creation() {
        let config = ThreatIntelConfig::default();
        let engine = ThreatIntelligenceEngine::new(config);

        assert!(engine.sources.read().unwrap().is_empty());
        assert!(engine.indicators.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_indicator_ingestion() {
        let config = ThreatIntelConfig::default();
        let engine = ThreatIntelligenceEngine::new(config);

        let source = Arc::new(MockThreatIntelSource {
            source_info: ThreatIntelSource::OpenSource("mock".to_string()),
        });

        engine.register_source("mock".to_string(), source);

        let count = engine.ingest_threat_indicators().await.unwrap();
        assert!(count > 0);

        let indicators = engine.indicators.read().unwrap();
        assert!(!indicators.is_empty());
    }

    #[tokio::test]
    async fn test_event_analysis() {
        let config = ThreatIntelConfig::default();
        let engine = ThreatIntelligenceEngine::new(config);

        // Ingest test indicators
        let source = Arc::new(MockThreatIntelSource {
            source_info: ThreatIntelSource::OpenSource("mock".to_string()),
        });
        engine.register_source("mock".to_string(), source);
        engine.ingest_threat_indicators().await.unwrap();

        // Create test event
        let event = SourceEvent {
            event_id: "test-event".to_string(),
            event_type: "network_connection".to_string(),
            timestamp: Utc::now(),
            source_system: "firewall".to_string(),
            raw_data: HashMap::new(),
            normalized_data: HashMap::from([
                ("source_ip".to_string(), "192.168.1.100".to_string()),
                ("destination_port".to_string(), "80".to_string()),
            ]),
            correlation_id: None,
        };

        let detection = engine.analyze_event(&event).await.unwrap();
        assert!(detection.is_some());

        let detection = detection.unwrap();
        assert!(!detection.matched_indicators.is_empty());
        assert!(detection.risk_score > 0.0);
    }

    #[test]
    fn test_risk_score_calculation() {
        let config = ThreatIntelConfig::default();
        let engine = ThreatIntelligenceEngine::new(config);

        let indicator = ThreatIndicator {
            id: "test".to_string(),
            indicator_type: IndicatorType::IpAddress,
            value: "test".to_string(),
            confidence: ConfidenceLevel::High,
            severity: ThreatSeverity::Critical,
            source: ThreatIntelSource::OpenSource("test".to_string()),
            tags: HashSet::new(),
            created_at: Utc::now(),
            expires_at: None,
            last_seen: None,
            description: "Test indicator".to_string(),
            context: ThreatContext {
                campaign: None,
                malware_family: None,
                attack_patterns: Vec::new(),
                vulnerabilities: Vec::new(),
                targeted_sectors: Vec::new(),
                targeted_regions: Vec::new(),
                first_seen: None,
                last_activity: None,
                additional_context: HashMap::new(),
            },
            kill_chain_phases: Vec::new(),
            attributed_actors: Vec::new(),
            related_indicators: Vec::new(),
            metadata: HashMap::new(),
        };

        let risk_score = engine.calculate_indicator_risk_score(&indicator);
        assert!(risk_score > 50.0); // Critical + High confidence should be high risk
    }
}
