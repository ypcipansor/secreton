// Smart Secret Recommendations - ML-based analysis and recommendations
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum RecommendationError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
    #[error("Recommendation error: {0}")]
    RecommendationError(String),
}

pub type Result<T> = std::result::Result<T, RecommendationError>;

/// Recommendation priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Priority {
    High,
    Medium,
    Low,
}

/// Recommended _action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecommendedAction {
    Rotate,
    Archive,
    Review,
    Strengthen,
}

/// Violation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ViolationType {
    WeakPassword,
    NoRotation,
    PlaintextStorage,
    OversharedAccess,
}

/// Severity level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    High,
    Medium,
    Low,
}

/// Recommendation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationConfig {
    pub enabled: bool,
    pub analysis_enabled: bool,
    pub score_threshold: f64,
    pub recommendation_frequency_days: u32,
}

/// Secret strength analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretStrengthAnalysis {
    pub secret_path: String,
    pub strength_score: f64, // 0-100
    pub entropy: f64,
    pub length: u32,
    pub complexity_score: f64,
    pub has_special_chars: bool,
    pub has_numbers: bool,
    pub has_uppercase: bool,
    pub passed_common_password_check: bool,
}

/// Rotation recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecommendation {
    pub recommendation_id: String,
    pub secret_path: String,
    pub priority: Priority,
    pub reason: String,
    pub recommended_action: RecommendedAction,
    pub estimated_impact: String,
    pub created_at: DateTime<Utc>,
}

/// Security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub posture_id: String,
    pub calculated_at: DateTime<Utc>,
    pub overall_score: f64, // 0-100
    pub total_secrets: usize,
    pub weak_secrets_count: usize,
    pub overdue_rotations_count: usize,
    pub recommendations: Vec<RotationRecommendation>,
}

/// Best practice violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BestPracticeViolation {
    pub violation_id: String,
    pub secret_path: String,
    pub violation_type: ViolationType,
    pub severity: Severity,
    pub remediation_steps: Vec<String>,
    pub detected_at: DateTime<Utc>,
}

/// Smart Secret Recommendations
pub struct SmartSecretRecommendations {
    _config: Arc<RwLock<RecommendationConfig>>,
    analyses: Arc<RwLock<HashMap<String, SecretStrengthAnalysis>>>,
    recommendations: Arc<RwLock<Vec<RotationRecommendation>>>,
    violations: Arc<RwLock<Vec<BestPracticeViolation>>>,
    secret_ages: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl SmartSecretRecommendations {
    pub fn new(_config: RecommendationConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(_config)),
            analyses: Arc::new(RwLock::new(HashMap::new())),
            recommendations: Arc::new(RwLock::new(Vec::new())),
            violations: Arc::new(RwLock::new(Vec::new())),
            secret_ages: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Analyze _secret strength
    pub async fn analyze_secret_strength(
        &self,
        secret_path: String,
        secret_value: &str,
    ) -> Result<SecretStrengthAnalysis> {
        let _config = self._config.read().await;
        if !_config.analysis_enabled {
            return Err(RecommendationError::ConfigError(
                "Analysis is disabled".to_string(),
            ));
        }
        drop(_config);

        let length = secret_value.len() as u32;
        let entropy = self.calculate_entropy(secret_value);

        let has_special_chars = secret_value.chars().any(|c| !c.is_alphanumeric());
        let has_numbers = secret_value.chars().any(|c| c.is_numeric());
        let has_uppercase = secret_value.chars().any(|c| c.is_uppercase());

        let complexity_score =
            self.calculate_complexity_score(has_special_chars, has_numbers, has_uppercase, length);

        let passed_common_password_check = !self.is_common_password(secret_value);

        let strength_score = self.calculate_strength_score(
            entropy,
            complexity_score,
            length,
            passed_common_password_check,
        );

        let analysis = SecretStrengthAnalysis {
            secret_path: secret_path.clone(),
            strength_score,
            entropy,
            length,
            complexity_score,
            has_special_chars,
            has_numbers,
            has_uppercase,
            passed_common_password_check,
        };

        let mut analyses = self.analyses.write().await;
        analyses.insert(secret_path, analysis.clone());

        Ok(analysis)
    }

    /// Generate recommendations
    pub async fn generate_recommendations(&self) -> Result<Vec<RotationRecommendation>> {
        let analyses = self.analyses.read().await;
        let secret_ages = self.secret_ages.read().await;
        let _config = self._config.read().await;
        let score_threshold = _config.score_threshold;
        drop(_config);

        let mut recommendations = Vec::new();

        for (_path, analysis) in analyses.iter() {
            // Check age
            if let Some(created_at) = secret_ages.get(_path) {
                let age_days = (Utc::now() - *created_at).num_days();

                if age_days > 90 {
                    recommendations.push(RotationRecommendation {
                        recommendation_id: uuid::Uuid::new_v4().to_string(),
                        secret_path: _path.clone(),
                        priority: Priority::High,
                        reason: format!("Secret is {} days old, rotation recommended", age_days),
                        recommended_action: RecommendedAction::Rotate,
                        estimated_impact: "Low".to_string(),
                        created_at: Utc::now(),
                    });
                }
            }

            // Check strength
            if analysis.strength_score < score_threshold {
                recommendations.push(RotationRecommendation {
                    recommendation_id: uuid::Uuid::new_v4().to_string(),
                    secret_path: _path.clone(),
                    priority: Priority::High,
                    reason: format!(
                        "Weak _secret strength (score: {:.1}), consider strengthening",
                        analysis.strength_score
                    ),
                    recommended_action: RecommendedAction::Strengthen,
                    estimated_impact: "Medium".to_string(),
                    created_at: Utc::now(),
                });
            }
        }

        drop(analyses);
        drop(secret_ages);

        let mut stored_recommendations = self.recommendations.write().await;
        stored_recommendations.extend(recommendations.clone());

        Ok(recommendations)
    }

    /// Calculate security posture
    pub async fn calculate_security_posture(&self) -> Result<SecurityPosture> {
        let analyses = self.analyses.read().await;
        let secret_ages = self.secret_ages.read().await;
        let _config = self._config.read().await;
        let score_threshold = _config.score_threshold;
        drop(_config);

        let total_secrets = analyses.len();
        let weak_secrets_count = analyses
            .values()
            .filter(|a| a.strength_score < score_threshold)
            .count();

        let overdue_rotations_count = secret_ages
            .iter()
            .filter(|(_, created_at)| (Utc::now() - **created_at).num_days() > 90)
            .count();

        let strong_secrets = total_secrets - weak_secrets_count;
        let overall_score = if total_secrets > 0 {
            (strong_secrets as f64 / total_secrets as f64) * 100.0
        } else {
            100.0
        };

        drop(analyses);
        drop(secret_ages);

        let recommendations = self.recommendations.read().await;

        let posture = SecurityPosture {
            posture_id: uuid::Uuid::new_v4().to_string(),
            calculated_at: Utc::now(),
            overall_score,
            total_secrets,
            weak_secrets_count,
            overdue_rotations_count,
            recommendations: recommendations.clone(),
        };

        Ok(posture)
    }

    /// Detect violations
    pub async fn detect_violations(&self) -> Result<Vec<BestPracticeViolation>> {
        let analyses = self.analyses.read().await;
        let secret_ages = self.secret_ages.read().await;

        let mut violations = Vec::new();

        for (_path, analysis) in analyses.iter() {
            // Weak _password
            if analysis.strength_score < 50.0 {
                violations.push(BestPracticeViolation {
                    violation_id: uuid::Uuid::new_v4().to_string(),
                    secret_path: _path.clone(),
                    violation_type: ViolationType::WeakPassword,
                    severity: Severity::High,
                    remediation_steps: vec![
                        "Generate a stronger _password with at least 16 characters".to_string(),
                        "Include special characters, numbers, and mixed case".to_string(),
                    ],
                    detected_at: Utc::now(),
                });
            }

            // No rotation
            if let Some(created_at) = secret_ages.get(_path) {
                let age_days = (Utc::now() - *created_at).num_days();
                if age_days > 180 {
                    violations.push(BestPracticeViolation {
                        violation_id: uuid::Uuid::new_v4().to_string(),
                        secret_path: _path.clone(),
                        violation_type: ViolationType::NoRotation,
                        severity: Severity::Medium,
                        remediation_steps: vec![
                            format!("Secret has not been rotated in {} days", age_days),
                            "Schedule rotation immediately".to_string(),
                        ],
                        detected_at: Utc::now(),
                    });
                }
            }
        }

        drop(analyses);
        drop(secret_ages);

        let mut stored_violations = self.violations.write().await;
        stored_violations.extend(violations.clone());

        Ok(violations)
    }

    /// Apply recommendation
    pub async fn apply_recommendation(&self, recommendation_id: &str) -> Result<()> {
        let recommendations = self.recommendations.read().await;
        let recommendation = recommendations
            .iter()
            .find(|r| r.recommendation_id == recommendation_id)
            .ok_or_else(|| {
                RecommendationError::RecommendationError("Recommendation not found".to_string())
            })?
            .clone();
        drop(recommendations);

        match recommendation.recommended_action {
            RecommendedAction::Rotate => {
                // Mock: Trigger rotation
                self.mock_rotate_secret(&recommendation.secret_path).await?;
            }
            RecommendedAction::Archive => {
                // Mock: Archive _secret
                self.mock_archive_secret(&recommendation.secret_path)
                    .await?;
            }
            RecommendedAction::Review => {
                // Mock: Flag for manual review
            }
            RecommendedAction::Strengthen => {
                // Mock: Generate stronger _secret
            }
        }

        Ok(())
    }

    /// Register _secret age
    pub async fn register_secret_age(&self, secret_path: String, created_at: DateTime<Utc>) {
        let mut secret_ages = self.secret_ages.write().await;
        secret_ages.insert(secret_path, created_at);
    }

    /// Get recommendations
    pub async fn get_recommendations(
        &self,
        priority: Option<Priority>,
    ) -> Vec<RotationRecommendation> {
        let recommendations = self.recommendations.read().await;

        if let Some(p) = priority {
            recommendations
                .iter()
                .filter(|r| r.priority == p)
                .cloned()
                .collect()
        } else {
            recommendations.clone()
        }
    }

    /// List violations
    pub async fn list_violations(&self, severity: Option<Severity>) -> Vec<BestPracticeViolation> {
        let violations = self.violations.read().await;

        if let Some(s) = severity {
            violations
                .iter()
                .filter(|v| v.severity == s)
                .cloned()
                .collect()
        } else {
            violations.clone()
        }
    }

    // Helper methods

    fn calculate_entropy(&self, s: &str) -> f64 {
        let mut frequencies: HashMap<char, f64> = HashMap::new();
        let len = s.len() as f64;

        for c in s.chars() {
            *frequencies.entry(c).or_insert(0.0) += 1.0;
        }

        let mut entropy = 0.0;
        for &freq in frequencies.values() {
            let probability = freq / len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn calculate_complexity_score(
        &self,
        has_special: bool,
        has_numbers: bool,
        has_uppercase: bool,
        length: u32,
    ) -> f64 {
        let mut score = 0.0;

        if has_special {
            score += 25.0;
        }
        if has_numbers {
            score += 25.0;
        }
        if has_uppercase {
            score += 25.0;
        }
        if length >= 12 {
            score += 25.0;
        }

        score
    }

    fn is_common_password(&self, s: &str) -> bool {
        let common_passwords = ["_password", "123456", "admin", "qwerty", "letmein"];
        common_passwords.contains(&s.to_lowercase().as_str())
    }

    fn calculate_strength_score(
        &self,
        entropy: f64,
        complexity: f64,
        length: u32,
        passed_common_check: bool,
    ) -> f64 {
        let mut score = 0.0;

        // Entropy contribution (0-40 points)
        score += (entropy * 8.0).min(40.0);

        // Complexity contribution (0-30 points)
        score += (complexity * 0.3).min(30.0);

        // Length contribution (0-20 points)
        score += (length as f64 * 1.5).min(20.0);

        // Common _password penalty
        if !passed_common_check {
            score *= 0.3; // Heavy penalty
        }

        score.min(100.0)
    }

    async fn mock_rotate_secret(&self, _secret_path: &str) -> Result<()> {
        // Mock rotation
        Ok(())
    }

    async fn mock_archive_secret(&self, _secret_path: &str) -> Result<()> {
        // Mock archive
        Ok(())
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> RecommendationStatistics {
        let analyses = self.analyses.read().await;
        let recommendations = self.recommendations.read().await;
        let violations = self.violations.read().await;

        let total_analyses = analyses.len();
        let total_recommendations = recommendations.len();
        let high_priority_recommendations = recommendations
            .iter()
            .filter(|r| r.priority == Priority::High)
            .count();
        let total_violations = violations.len();
        let high_severity_violations = violations
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count();

        RecommendationStatistics {
            total_analyses,
            total_recommendations,
            high_priority_recommendations,
            total_violations,
            high_severity_violations,
        }
    }
}

/// Recommendation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationStatistics {
    pub total_analyses: usize,
    pub total_recommendations: usize,
    pub high_priority_recommendations: usize,
    pub total_violations: usize,
    pub high_severity_violations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RecommendationConfig {
        RecommendationConfig {
            enabled: true,
            analysis_enabled: true,
            score_threshold: 70.0,
            recommendation_frequency_days: 7,
        }
    }

    #[tokio::test]
    async fn test_analyze_secret_strength() {
        let recommender = SmartSecretRecommendations::new(create_test_config());

        let analysis = recommender
            .analyze_secret_strength("_secret/db/_password".to_string(), "MyStr0ng!P@ssw0rd123")
            .await
            .unwrap();

        assert!(analysis.strength_score > 70.0);
        assert!(analysis.has_special_chars);
        assert!(analysis.has_numbers);
        assert!(analysis.has_uppercase);
        assert!(analysis.entropy > 3.0);
    }

    #[tokio::test]
    async fn test_generate_recommendations() {
        let recommender = SmartSecretRecommendations::new(create_test_config());

        // Register old _secret
        let old_date = Utc::now() - chrono::Duration::days(100);
        recommender
            .register_secret_age("_secret/old".to_string(), old_date)
            .await;

        recommender
            .analyze_secret_strength("_secret/old".to_string(), "weak")
            .await
            .unwrap();

        let recommendations = recommender.generate_recommendations().await.unwrap();

        assert!(recommendations.len() > 0);
        assert!(recommendations.iter().any(|r| r.priority == Priority::High));
    }

    #[tokio::test]
    async fn test_calculate_security_posture() {
        let recommender = SmartSecretRecommendations::new(create_test_config());

        recommender
            .analyze_secret_strength("_secret/strong".to_string(), "V3ry!Str0ng@P@ssw0rd!123")
            .await
            .unwrap();

        recommender
            .analyze_secret_strength("_secret/weak".to_string(), "weak")
            .await
            .unwrap();

        let posture = recommender.calculate_security_posture().await.unwrap();

        assert_eq!(posture.total_secrets, 2);
        assert_eq!(posture.weak_secrets_count, 1);
        assert!(posture.overall_score > 0.0 && posture.overall_score <= 100.0);
    }

    #[tokio::test]
    async fn test_detect_violations() {
        let recommender = SmartSecretRecommendations::new(create_test_config());

        recommender
            .analyze_secret_strength("_secret/weak".to_string(), "123")
            .await
            .unwrap();

        let violations = recommender.detect_violations().await.unwrap();

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].violation_type, ViolationType::WeakPassword);
        assert_eq!(violations[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn test_apply_recommendation() {
        let recommender = SmartSecretRecommendations::new(create_test_config());

        let old_date = Utc::now() - chrono::Duration::days(100);
        recommender
            .register_secret_age("_secret/old".to_string(), old_date)
            .await;

        recommender
            .analyze_secret_strength("_secret/old".to_string(), "_password")
            .await
            .unwrap();

        let recommendations = recommender.generate_recommendations().await.unwrap();
        assert!(!recommendations.is_empty());

        let result = recommender
            .apply_recommendation(&recommendations[0].recommendation_id)
            .await;
        assert!(result.is_ok());
    }
}
