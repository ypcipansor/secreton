//! Security vs Performance optimization levels

use serde::{Deserialize, Serialize};

/// Security vs Performance optimization levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum OptimizationLevel {
    /// Maximum security, minimum performance (Production-Critical)
    MaximumSecurity,
    /// High security with good performance (Production-Standard)
    #[default]
    HighSecurity,
    /// Balanced security and performance (Development/Staging)
    Balanced,
    /// Maximum performance, reduced security (Testing Only)
    MaximumPerformance,
}

impl OptimizationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            OptimizationLevel::MaximumSecurity => "max-security",
            OptimizationLevel::HighSecurity => "high-security",
            OptimizationLevel::Balanced => "balanced",
            OptimizationLevel::MaximumPerformance => "max-performance",
        }
    }

    /// Get security score (0.0 = no security, 1.0 = maximum security)
    pub fn security_score(&self) -> f64 {
        match self {
            OptimizationLevel::MaximumSecurity => 1.0,
            OptimizationLevel::HighSecurity => 0.9,
            OptimizationLevel::Balanced => 0.7,
            OptimizationLevel::MaximumPerformance => 0.3,
        }
    }

    /// Get performance score (0.0 = slowest, 1.0 = fastest)
    pub fn performance_score(&self) -> f64 {
        match self {
            OptimizationLevel::MaximumSecurity => 0.3,
            OptimizationLevel::HighSecurity => 0.6,
            OptimizationLevel::Balanced => 0.8,
            OptimizationLevel::MaximumPerformance => 1.0,
        }
    }

    /// Get recommended use case
    pub fn recommended_use(&self) -> &'static str {
        match self {
            OptimizationLevel::MaximumSecurity => {
                "Production systems with highest security requirements (banking, healthcare)"
            }
            OptimizationLevel::HighSecurity => {
                "Standard production deployments (enterprise applications)"
            }
            OptimizationLevel::Balanced => "Development and staging environments",
            OptimizationLevel::MaximumPerformance => "Testing and development (NOT for production)",
        }
    }
}
