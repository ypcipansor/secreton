//! Common types and utilities.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Version information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre_release: Option<String>,
    pub build: Option<String>,
}

impl Version {
    /// Create a new version
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre_release: None,
            build: None,
        }
    }

    /// Create version with pre-release
    pub fn with_pre_release(mut self, pre_release: String) -> Self {
        self.pre_release = Some(pre_release);
        self
    }

    /// Create version with build metadata
    pub fn with_build(mut self, build: String) -> Self {
        self.build = Some(build);
        self
    }

    /// Parse version from string (semver format)
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 3 {
            return Err("Version must have at least major.minor.patch".to_string());
        }

        let major = parts[0].parse::<u32>().map_err(|_| "Invalid major version")?;
        let minor = parts[1].parse::<u32>().map_err(|_| "Invalid minor version")?;
        
        // Handle patch version which might have pre-release or build info
        let patch_full = parts[2];
        let (patch_str, rest) = if let Some(pos) = patch_full.find('-') {
            patch_full.split_at(pos)
        } else if let Some(pos) = patch_full.find('+') {
            patch_full.split_at(pos)
        } else {
            (patch_full, "")
        };

        let patch = patch_str.parse::<u32>().map_err(|_| "Invalid patch version")?;

        let mut version = Self::new(major, minor, patch);

        // Parse pre-release and build info
        if !rest.is_empty() {
            if rest.starts_with('-') {
                let rest = &rest[1..];
                if let Some(pos) = rest.find('+') {
                    let (pre_release, build) = rest.split_at(pos);
                    version.pre_release = Some(pre_release.to_string());
                    version.build = Some(build[1..].to_string());
                } else {
                    version.pre_release = Some(rest.to_string());
                }
            } else if rest.starts_with('+') {
                version.build = Some(rest[1..].to_string());
            }
        }

        Ok(version)
    }

    /// Compare versions (semver compatibility)
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.major == other.major
    }

    /// Check if this version is newer than another
    pub fn is_newer_than(&self, other: &Version) -> bool {
        if self.major != other.major {
            return self.major > other.major;
        }
        if self.minor != other.minor {
            return self.minor > other.minor;
        }
        self.patch > other.patch
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        
        if let Some(ref pre_release) = self.pre_release {
            write!(f, "-{}", pre_release)?;
        }
        
        if let Some(ref build) = self.build {
            write!(f, "+{}", build)?;
        }
        
        Ok(())
    }
}

/// Health status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

impl HealthStatus {
    /// Check if status indicates system is operational
    pub fn is_operational(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }

    /// Get status priority for aggregation (lower is better)
    pub fn priority(&self) -> u8 {
        match self {
            HealthStatus::Healthy => 0,
            HealthStatus::Degraded => 1,
            HealthStatus::Unhealthy => 2,
            HealthStatus::Unknown => 3,
        }
    }

    /// Combine two health statuses (returns worse status)
    pub fn combine(self, other: HealthStatus) -> HealthStatus {
        if self.priority() >= other.priority() {
            self
        } else {
            other
        }
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        HealthStatus::Unknown
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Time range structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

impl TimeRange {
    /// Create a new time range
    pub fn new(
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self, String> {
        if start >= end {
            return Err("Start time must be before end time".to_string());
        }
        Ok(Self { start, end })
    }

    /// Create time range for the last N minutes
    pub fn last_minutes(minutes: u32) -> Self {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::minutes(minutes as i64);
        Self { start, end }
    }

    /// Create time range for the last N hours
    pub fn last_hours(hours: u32) -> Self {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::hours(hours as i64);
        Self { start, end }
    }

    /// Create time range for the last N days
    pub fn last_days(days: u32) -> Self {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::days(days as i64);
        Self { start, end }
    }

    /// Check if a timestamp is within this range
    pub fn contains(&self, timestamp: chrono::DateTime<chrono::Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }

    /// Get the duration of this time range
    pub fn duration(&self) -> chrono::Duration {
        self.end - self.start
    }

    /// Split time range into smaller intervals
    pub fn split_into_intervals(&self, interval_duration: chrono::Duration) -> Vec<TimeRange> {
        let mut intervals = Vec::new();
        let mut current_start = self.start;

        while current_start < self.end {
            let current_end = std::cmp::min(current_start + interval_duration, self.end);
            intervals.push(TimeRange {
                start: current_start,
                end: current_end,
            });
            current_start = current_end;
        }

        intervals
    }
}

/// Pagination helper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub limit: u32,
    pub offset: u32,
    pub total: Option<u64>,
}

impl Pagination {
    /// Create new pagination
    pub fn new(limit: u32, offset: u32) -> Self {
        Self {
            limit,
            offset,
            total: None,
        }
    }

    /// Create pagination with total count
    pub fn with_total(limit: u32, offset: u32, total: u64) -> Self {
        Self {
            limit,
            offset,
            total: Some(total),
        }
    }

    /// Get current page number (0-based)
    pub fn page(&self) -> u32 {
        if self.limit == 0 {
            0
        } else {
            self.offset / self.limit
        }
    }

    /// Get total pages
    pub fn total_pages(&self) -> Option<u32> {
        self.total.map(|total| {
            if self.limit == 0 {
                0
            } else {
                ((total as u32 + self.limit - 1) / self.limit).max(1)
            }
        })
    }

    /// Check if there are more pages
    pub fn has_next_page(&self) -> Option<bool> {
        self.total.map(|total| {
            let next_offset = self.offset + self.limit;
            (next_offset as u64) < total
        })
    }

    /// Check if there are previous pages
    pub fn has_previous_page(&self) -> bool {
        self.offset > 0
    }

    /// Get next page pagination
    pub fn next_page(&self) -> Option<Self> {
        if self.has_next_page().unwrap_or(true) {
            Some(Self {
                limit: self.limit,
                offset: self.offset + self.limit,
                total: self.total,
            })
        } else {
            None
        }
    }

    /// Get previous page pagination
    pub fn previous_page(&self) -> Option<Self> {
        if self.has_previous_page() {
            Some(Self {
                limit: self.limit,
                offset: self.offset.saturating_sub(self.limit),
                total: self.total,
            })
        } else {
            None
        }
    }
}

/// Environment type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Environment {
    /// Parse environment from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dev" | "development" => Some(Environment::Development),
            "stage" | "staging" => Some(Environment::Staging),
            "prod" | "production" => Some(Environment::Production),
            _ => None,
        }
    }

    /// Check if this is a production environment
    pub fn is_production(&self) -> bool {
        matches!(self, Environment::Production)
    }

    /// Check if debug features should be enabled
    pub fn debug_enabled(&self) -> bool {
        matches!(self, Environment::Development | Environment::Staging)
    }
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Development
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Environment::Development => write!(f, "development"),
            Environment::Staging => write!(f, "staging"),
            Environment::Production => write!(f, "production"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v1 = Version::parse("1.2.3").unwrap();
        assert_eq!(v1.major, 1);
        assert_eq!(v1.minor, 2);
        assert_eq!(v1.patch, 3);
        assert!(v1.pre_release.is_none());
        assert!(v1.build.is_none());

        let v2 = Version::parse("1.2.3-alpha.1+build.123").unwrap();
        assert_eq!(v2.major, 1);
        assert_eq!(v2.minor, 2);
        assert_eq!(v2.patch, 3);
        assert_eq!(v2.pre_release, Some("alpha.1".to_string()));
        assert_eq!(v2.build, Some("build.123".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::new(1, 2, 3);
        let v2 = Version::new(1, 2, 4);
        let v3 = Version::new(2, 0, 0);

        assert!(!v1.is_newer_than(&v1));
        assert!(v2.is_newer_than(&v1));
        assert!(v3.is_newer_than(&v2));

        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_operational());
        assert!(HealthStatus::Degraded.is_operational());
        assert!(!HealthStatus::Unhealthy.is_operational());
        assert!(!HealthStatus::Unknown.is_operational());

        assert_eq!(
            HealthStatus::Healthy.combine(HealthStatus::Degraded),
            HealthStatus::Degraded
        );
        assert_eq!(
            HealthStatus::Degraded.combine(HealthStatus::Unhealthy),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn test_time_range() {
        let range = TimeRange::last_hours(1);
        let now = chrono::Utc::now();
        let past = now - chrono::Duration::minutes(30);
        let future = now + chrono::Duration::minutes(30);

        assert!(range.contains(past));
        assert!(!range.contains(future));
        assert!(range.duration() <= chrono::Duration::hours(1));
    }

    #[test]
    fn test_pagination() {
        let pagination = Pagination::with_total(10, 20, 100);
        assert_eq!(pagination.page(), 2);
        assert_eq!(pagination.total_pages(), Some(10));
        assert!(pagination.has_next_page().unwrap());
        assert!(pagination.has_previous_page());

        let next = pagination.next_page().unwrap();
        assert_eq!(next.offset, 30);
    }

    #[test]
    fn test_environment() {
        assert_eq!(Environment::from_str("dev"), Some(Environment::Development));
        assert_eq!(Environment::from_str("production"), Some(Environment::Production));
        assert_eq!(Environment::from_str("invalid"), None);

        assert!(!Environment::Development.is_production());
        assert!(Environment::Production.is_production());
        assert!(Environment::Development.debug_enabled());
        assert!(!Environment::Production.debug_enabled());
    }
}
