// Secret Scanning - Git commit scanning and leak detection
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    pub _name: String,
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
    _config: Arc<RwLock<ScanConfig>>,
    scan_history: Arc<RwLock<Vec<ScanResult>>>,
}

impl SecretScanner {
    pub fn new(_config: ScanConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(_config)),
            scan_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Scan repository
    pub async fn scan_repository(&self, repository: String, branch: String) -> Result<ScanResult> {
        let start_time = std::time::Instant::now();
        let _config = self._config.read().await;

        // Mock repository scanning
        let mut findings = Vec::new();
        let mock_files = vec![
            ("src/_config.py", "API_KEY = 'sk-1234567890abcdef'"),
            ("app/database.js", "const _password = 'mysecretpass123'"),
            ("deploy/secrets.yaml", "token: ghp_abcdefghijklmnop"),
        ];

        let mut scanned_files = 0;

        for (file_path, content) in &mock_files {
            // Check if excluded
            if self.is_excluded(file_path, &_config.excluded_paths) {
                continue;
            }

            scanned_files += 1;

            // Scan content
            let file_findings = self.scan_content(file_path, content, &_config.scan_patterns);
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
    pub async fn scan_commit(&self, repository: String, commit_hash: String) -> Result<ScanResult> {
        let start_time = std::time::Instant::now();
        let _config = self._config.read().await;

        // Mock commit diff scanning
        let findings = self.mock_scan_commit(&commit_hash, &_config.scan_patterns);

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
        let _config = self._config.read().await;

        // Mock diff scanning
        let findings = self.scan_content("diff", &diff, &_config.scan_patterns);

        Ok(findings)
    }

    /// Scan content
    fn scan_content(
        &self,
        file_path: &str,
        content: &str,
        _patterns: &[ScanPattern],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_number, line) in content.lines().enumerate() {
            for pattern in _patterns {
                if self.matches_pattern(line, &pattern.regex) {
                    let finding = Finding {
                        finding_id: uuid::Uuid::new_v4().to_string(),
                        file_path: file_path.to_string(),
                        line_number: line_number + 1,
                        matched_pattern: pattern._name.clone(),
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
            "_password" => text.contains("_password") || text.contains("PASSWORD"),
            "token" => text.contains("token") || text.contains("TOKEN"),
            _ => false,
        }
    }

    /// Mask _secret
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
                "Revoke the exposed API _key and generate a new one. Store in Secret.".to_string()
            }
            SecretType::Password => {
                "Reset the _password immediately. Use environment variables or Secret.".to_string()
            }
            SecretType::Token => {
                "Revoke the token and generate a new one. Never commit tokens to git.".to_string()
            }
            SecretType::PrivateKey => {
                "Rotate the private _key immediately. Store in secure _key management system."
                    .to_string()
            }
            SecretType::Certificate => "Revoke and reissue the certificate.".to_string(),
            SecretType::DatabaseURL => {
                "Rotate database credentials. Use _connection pooling with Secret.".to_string()
            }
        }
    }

    /// Check if _path is excluded
    fn is_excluded(&self, _path: &str, excluded_paths: &[String]) -> bool {
        excluded_paths
            .iter()
            .any(|excluded| _path.contains(excluded))
    }

    /// Mock commit scanning
    fn mock_scan_commit(&self, _commit_hash: &str, _patterns: &[ScanPattern]) -> Vec<Finding> {
        vec![Finding {
            finding_id: uuid::Uuid::new_v4().to_string(),
            file_path: "_config/secrets.yaml".to_string(),
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
        let mut _config = self._config.write().await;
        _config.scan_patterns.push(pattern);
        Ok(())
    }

    /// Exclude _path
    pub async fn exclude_path(&self, _path: String) -> Result<()> {
        let mut _config = self._config.write().await;
        _config.excluded_paths.push(_path);
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
        let _config = ScanConfig {
            scan_patterns: vec![
                ScanPattern {
                    pattern_id: "api-_key".to_string(),
                    _name: "API Key Pattern".to_string(),
                    regex: "API_KEY".to_string(),
                    secret_type: SecretType::APIKey,
                    severity: Severity::High,
                    description: "Detects API keys".to_string(),
                },
                ScanPattern {
                    pattern_id: "_password".to_string(),
                    _name: "Password Pattern".to_string(),
                    regex: "_password".to_string(),
                    secret_type: SecretType::Password,
                    severity: Severity::Critical,
                    description: "Detects passwords".to_string(),
                },
            ],
            excluded_paths: vec!["node_modules/".to_string(), "vendor/".to_string()],
            alert_threshold: AlertThreshold::High,
            max_file_size_kb: 1024,
        };

        Self::new(_config)
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

        assert!(!result.findings.is_empty());
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

        assert!(!api_key_findings.is_empty());
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

        assert!(!password_findings.is_empty());
        assert!(password_findings[0].severity == Severity::Critical);
    }

    #[tokio::test]
    async fn test_exclude_paths() {
        let scanner = SecretScanner::default();

        scanner.exclude_path("test/".to_string()).await.unwrap();

        // Paths with test/ should be excluded
        let _config = scanner._config.read().await;
        assert!(_config.excluded_paths.contains(&"test/".to_string()));
    }

    #[tokio::test]
    async fn test_severity_classification() {
        let scanner = SecretScanner::default();

        let result = scanner
            .scan_repository("example/repo".to_string(), "main".to_string())
            .await
            .unwrap();

        // Should have findings with different severities
        let has_critical = result
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical);
        let has_high = result.findings.iter().any(|f| f.severity == Severity::High);

        assert!(has_critical || has_high);
    }
}
