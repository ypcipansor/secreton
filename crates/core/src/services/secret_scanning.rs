// Secret Scanning - Git commit scanning and leak detection
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Scan error: {0}")]
    ScanError(String),
    #[error("Pattern error: {0}")]
    PatternError(String),
}

pub type Result<T> = std::result::Result<T, ScanError>;

/// Alert threshold
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertThreshold {
    High,
    Medium,
    Low,
}

/// Severity level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Secret type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    APIKey,
    Password,
    Token,
    PrivateKey,
    Certificate,
    DatabaseURL,
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub scan_patterns: Vec<ScanPattern>,
    pub excluded_paths: Vec<String>,
    pub alert_threshold: AlertThreshold,
    pub max_file_size_kb: usize,
}

/// Scan pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPattern {
    pub pattern_id: String,
    pub name: String,
    pub regex: String,
    pub secret_type: SecretType,
    pub severity: Severity,
    pub description: String,
}

/// Finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub file_path: String,
    pub line_number: usize,
    pub matched_pattern: String,
    pub matched_text: String, // Masked
    pub secret_type: SecretType,
    pub severity: Severity,
    pub remediation: String,
}

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub repository: String,
    pub commit_hash: Option<String>,
    pub findings: Vec<Finding>,
    pub scanned_files: usize,
    pub scanned_at: DateTime<Utc>,
    pub duration_ms: u64,
}

/// Secret Scanner
pub struct SecretScanner {
    config: Arc<RwLock<ScanConfig>>,
    scan_history: Arc<RwLock<Vec<ScanResult>>>,
}

impl SecretScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            scan_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Scan repository
    pub async fn scan_repository(&self, repository: String, branch: String) -> Result<ScanResult> {
        let start_time = std::time::Instant::now();
        let config = self.config.read().await;

        // Mock repository scanning
        let mut findings = Vec::new();
        let mock_files = vec![
            ("src/config.py", "API_KEY = 'sk-1234567890abcdef'"),
            ("app/database.js", "const password = 'mysecretpass123'"),
            ("deploy/secrets.yaml", "token: ghp_abcdefghijklmnop"),
        ];

        let mut scanned_files = 0;

        for (file_path, content) in &mock_files {
            // Check if excluded
            if self.is_excluded(file_path, &config.excluded_paths) {
                continue;
            }

            scanned_files += 1;

            // Scan content
            let file_findings = self.scan_content(file_path, content, &config.scan_patterns);
            findings.extend(file_findings);
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;

        let scan_result = ScanResult {
            scan_id: uuid::Uuid::new_v4().to_string(),
            repository: format!("{}/tree/{}", repository, branch),
            commit_hash: None,
            findings,
            scanned_files,
            scanned_at: Utc::now(),
            duration_ms,
        };

        let mut history = self.scan_history.write().await;
        history.push(scan_result.clone());

        Ok(scan_result)
    }

    /// Scan commit
    pub async fn scan_commit(
        &self,
        repository: String,
        commit_hash: String,
    ) -> Result<ScanResult> {
        let start_time = std::time::Instant::now();
        let config = self.config.read().await;

        // Mock commit diff scanning
        let findings = self.mock_scan_commit(&commit_hash, &config.scan_patterns);

        let duration_ms = start_time.elapsed().as_millis() as u64;

        let scan_result = ScanResult {
            scan_id: uuid::Uuid::new_v4().to_string(),
            repository,
            commit_hash: Some(commit_hash),
            findings,
            scanned_files: 1,
            scanned_at: Utc::now(),
            duration_ms,
        };

        let mut history = self.scan_history.write().await;
        history.push(scan_result.clone());

        Ok(scan_result)
    }

    /// Scan diff (for PRs/MRs)
    pub async fn scan_diff(&self, diff: String) -> Result<Vec<Finding>> {
        let config = self.config.read().await;

        // Mock diff scanning
        let findings = self.scan_content("diff", &diff, &config.scan_patterns);

        Ok(findings)
    }

    /// Scan content
    fn scan_content(
        &self,
        file_path: &str,
        content: &str,
        patterns: &[ScanPattern],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_number, line) in content.lines().enumerate() {
            for pattern in patterns {
                if self.matches_pattern(line, &pattern.regex) {
                    let finding = Finding {
                        finding_id: uuid::Uuid::new_v4().to_string(),
                        file_path: file_path.to_string(),
                        line_number: line_number + 1,
                        matched_pattern: pattern.name.clone(),
                        matched_text: self.mask_secret(line),
                        secret_type: pattern.secret_type.clone(),
                        severity: pattern.severity.clone(),
                        remediation: self.get_remediation(&pattern.secret_type),
                    };

                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Check if pattern matches
    fn matches_pattern(&self, text: &str, pattern: &str) -> bool {
        // Mock regex matching
        match pattern {
            "API_KEY" => text.contains("API_KEY") || text.contains("api_key"),
            "password" => text.contains("password") || text.contains("PASSWORD"),
            "token" => text.contains("token") || text.contains("TOKEN"),
            _ => false,
        }
    }

    /// Mask secret
    fn mask_secret(&self, text: &str) -> String {
        let parts: Vec<&str> = text.split('=').collect();
        if parts.len() >= 2 {
            format!("{}=****", parts[0].trim())
        } else {
            "****".to_string()
        }
    }

    /// Get remediation advice
    fn get_remediation(&self, secret_type: &SecretType) -> String {
        match secret_type {
            SecretType::APIKey => {
                "Revoke the exposed API key and generate a new one. Store in Vault.".to_string()
            }
            SecretType::Password => {
                "Reset the password immediately. Use environment variables or Vault.".to_string()
            }
            SecretType::Token => {
                "Revoke the token and generate a new one. Never commit tokens to git.".to_string()
            }
            SecretType::PrivateKey => {
                "Rotate the private key immediately. Store in secure key management system."
                    .to_string()
            }
            SecretType::Certificate => "Revoke and reissue the certificate.".to_string(),
            SecretType::DatabaseURL => {
                "Rotate database credentials. Use connection pooling with Vault.".to_string()
            }
        }
    }

    /// Check if path is excluded
    fn is_excluded(&self, path: &str, excluded_paths: &[String]) -> bool {
        excluded_paths.iter().any(|excluded| path.contains(excluded))
    }

    /// Mock commit scanning
    fn mock_scan_commit(&self, _commit_hash: &str, patterns: &[ScanPattern]) -> Vec<Finding> {
        vec![Finding {
            finding_id: uuid::Uuid::new_v4().to_string(),
            file_path: "config/secrets.yaml".to_string(),
            line_number: 15,
            matched_pattern: "API Key Pattern".to_string(),
            matched_text: "api_key: ****".to_string(),
            secret_type: SecretType::APIKey,
            severity: Severity::High,
            remediation: self.get_remediation(&SecretType::APIKey),
        }]
    }

    /// Add custom pattern
    pub async fn add_pattern(&self, pattern: ScanPattern) -> Result<()> {
        let mut config = self.config.write().await;
        config.scan_patterns.push(pattern);
        Ok(())
    }

    /// Exclude path
    pub async fn exclude_path(&self, path: String) -> Result<()> {
        let mut config = self.config.write().await;
        config.excluded_paths.push(path);
        Ok(())
    }

    /// Generate report
    pub async fn generate_report(&self, scan_id: &str) -> Option<String> {
        let history = self.scan_history.read().await;
        let scan = history.iter().find(|s| s.scan_id == scan_id)?;

        let mut report = format!(
            "Scan Report: {}\nRepository: {}\nFindings: {}\n\n",
            scan.scan_id,
            scan.repository,
            scan.findings.len()
        );

        for finding in &scan.findings {
            report.push_str(&format!(
                "- [{}] {} at {}:{}\n  Type: {:?}\n  Remediation: {}\n\n",
                match finding.severity {
                    Severity::Critical => "CRITICAL",
                    Severity::High => "HIGH",
                    Severity::Medium => "MEDIUM",
                    Severity::Low => "LOW",
                },
                finding.matched_pattern,
                finding.file_path,
                finding.line_number,
                finding.secret_type,
                finding.remediation
            ));
        }

        Some(report)
    }

    /// Get scan history
    pub async fn get_scan_history(&self) -> Vec<ScanResult> {
        let history = self.scan_history.read().await;
        history.clone()
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        let config = ScanConfig {
            scan_patterns: vec![
                ScanPattern {
                    pattern_id: "api-key".to_string(),
                    name: "API Key Pattern".to_string(),
                    regex: "API_KEY".to_string(),
                    secret_type: SecretType::APIKey,
                    severity: Severity::High,
                    description: "Detects API keys".to_string(),
                },
                ScanPattern {
                    pattern_id: "password".to_string(),
                    name: "Password Pattern".to_string(),
                    regex: "password".to_string(),
                    secret_type: SecretType::Password,
                    severity: Severity::Critical,
                    description: "Detects passwords".to_string(),
                },
            ],
            excluded_paths: vec!["node_modules/".to_string(), "vendor/".to_string()],
            alert_threshold: AlertThreshold::High,
            max_file_size_kb: 1024,
        };

        Self::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_repository() {
        let scanner = SecretScanner::default();

        let result = scanner
            .scan_repository("example/repo".to_string(), "main".to_string())
            .await
            .unwrap();

        assert!(result.findings.len() > 0);
        assert!(result.scanned_files > 0);
    }

    #[tokio::test]
    async fn test_detect_api_keys() {
        let scanner = SecretScanner::default();

        let result = scanner
            .scan_repository("example/repo".to_string(), "main".to_string())
            .await
            .unwrap();

        let api_key_findings: Vec<&Finding> = result
            .findings
            .iter()
            .filter(|f| f.secret_type == SecretType::APIKey)
            .collect();

        assert!(api_key_findings.len() > 0);
    }

    #[tokio::test]
    async fn test_detect_passwords() {
        let scanner = SecretScanner::default();

        let result = scanner
            .scan_repository("example/repo".to_string(), "main".to_string())
            .await
            .unwrap();

        let password_findings: Vec<&Finding> = result
            .findings
            .iter()
            .filter(|f| f.secret_type == SecretType::Password)
            .collect();

        assert!(password_findings.len() > 0);
        assert!(password_findings[0].severity == Severity::Critical);
    }

    #[tokio::test]
    async fn test_exclude_paths() {
        let scanner = SecretScanner::default();

        scanner.exclude_path("test/".to_string()).await.unwrap();

        // Paths with test/ should be excluded
        let config = scanner.config.read().await;
        assert!(config.excluded_paths.contains(&"test/".to_string()));
    }

    #[tokio::test]
    async fn test_severity_classification() {
        let scanner = SecretScanner::default();

        let result = scanner
            .scan_repository("example/repo".to_string(), "main".to_string())
            .await
            .unwrap();

        // Should have findings with different severities
        let has_critical = result.findings.iter().any(|f| f.severity == Severity::Critical);
        let has_high = result.findings.iter().any(|f| f.severity == Severity::High);

        assert!(has_critical || has_high);
    }
}
