//! Secret Marketplace
//!
//! Provides a marketplace for secret templates, sharing, collaboration,
//! versioning, ratings, and usage analytics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum MarketplaceError {
    #[error("Template not found: {0}")]
    TemplateNotFound(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Invalid version: {0}")]
    InvalidVersion(String),
    #[error("Already exists: {0}")]
    AlreadyExists(String),
}

pub type Result<T> = std::result::Result<T, MarketplaceError>;

/// Template category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TemplateCategory {
    Database,
    Cloud,
    API,
    Certificate,
    SSH,
    Custom,
}

/// Template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretTemplate {
    pub template_id: String,
    pub name: String,
    pub description: String,
    pub category: TemplateCategory,
    pub content: String,
    pub version: String,
    pub author: String,
    pub published_at: DateTime<Utc>,
    pub downloads: u64,
    pub rating: f64,
    pub tags: Vec<String>,
}

/// Template version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVersion {
    pub version: String,
    pub template_id: String,
    pub content: String,
    pub changelog: String,
    pub published_at: DateTime<Utc>,
}

/// Shared secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSecret {
    pub share_id: String,
    pub secret_id: String,
    pub owner: String,
    pub shared_with: Vec<String>,
    pub permissions: SharePermissions,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Share permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePermissions {
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
    pub can_share: bool,
}

/// Template rating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRating {
    pub rating_id: String,
    pub template_id: String,
    pub user: String,
    pub rating: u8,
    pub review: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Usage analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateAnalytics {
    pub template_id: String,
    pub total_downloads: u64,
    pub unique_users: usize,
    pub average_rating: f64,
    pub total_ratings: usize,
    pub downloads_last_30d: u64,
}

/// Search filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFilters {
    pub category: Option<TemplateCategory>,
    pub tags: Vec<String>,
    pub min_rating: Option<f64>,
    pub author: Option<String>,
}

/// Secret Marketplace
pub struct SecretMarketplace {
    templates: Arc<RwLock<HashMap<String, SecretTemplate>>>,
    versions: Arc<RwLock<HashMap<String, Vec<TemplateVersion>>>>,
    shared_secrets: Arc<RwLock<HashMap<String, SharedSecret>>>,
    ratings: Arc<RwLock<HashMap<String, Vec<TemplateRating>>>>,
    downloads: Arc<RwLock<HashMap<String, u64>>>,
}

impl SecretMarketplace {
    pub fn new() -> Self {
        Self {
            templates: Arc::new(RwLock::new(HashMap::new())),
            versions: Arc::new(RwLock::new(HashMap::new())),
            shared_secrets: Arc::new(RwLock::new(HashMap::new())),
            ratings: Arc::new(RwLock::new(HashMap::new())),
            downloads: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Publish template
    pub async fn publish_template(&self, template: SecretTemplate) -> Result<String> {
        let mut templates = self.templates.write().await;

        if templates.contains_key(&template.template_id) {
            return Err(MarketplaceError::AlreadyExists(template.template_id));
        }

        let template_id = template.template_id.clone();

        // Create initial version
        let version = TemplateVersion {
            version: template.version.clone(),
            template_id: template_id.clone(),
            content: template.content.clone(),
            changelog: "Initial version".to_string(),
            published_at: template.published_at,
        };

        let mut versions = self.versions.write().await;
        versions.insert(template_id.clone(), vec![version]);

        templates.insert(template_id.clone(), template);
        Ok(template_id)
    }

    /// Get template
    pub async fn get_template(&self, template_id: &str) -> Result<SecretTemplate> {
        let templates = self.templates.read().await;
        templates
            .get(template_id)
            .cloned()
            .ok_or_else(|| MarketplaceError::TemplateNotFound(template_id.to_string()))
    }

    /// Update template version
    pub async fn publish_version(&self, template_id: &str, version: TemplateVersion) -> Result<()> {
        let mut templates = self.templates.write().await;
        let mut versions = self.versions.write().await;

        let template = templates
            .get_mut(template_id)
            .ok_or_else(|| MarketplaceError::TemplateNotFound(template_id.to_string()))?;

        template.version = version.version.clone();
        template.content = version.content.clone();

        versions
            .entry(template_id.to_string())
            .or_default()
            .push(version);

        Ok(())
    }

    /// Get template versions
    pub async fn get_versions(&self, template_id: &str) -> Vec<TemplateVersion> {
        let versions = self.versions.read().await;
        versions.get(template_id).cloned().unwrap_or_default()
    }

    /// Search templates
    pub async fn search_templates(
        &self,
        query: &str,
        filters: SearchFilters,
    ) -> Vec<SecretTemplate> {
        let templates = self.templates.read().await;

        templates
            .values()
            .filter(|t| {
                let matches_query = query.is_empty()
                    || t.name.to_lowercase().contains(&query.to_lowercase())
                    || t.description.to_lowercase().contains(&query.to_lowercase());

                let matches_category =
                    filters.category.is_none() || filters.category.as_ref() == Some(&t.category);

                let matches_tags =
                    filters.tags.is_empty() || filters.tags.iter().any(|tag| t.tags.contains(tag));

                let matches_rating =
                    filters.min_rating.is_none() || t.rating >= filters.min_rating.unwrap();

                let matches_author =
                    filters.author.is_none() || filters.author.as_ref() == Some(&t.author);

                matches_query
                    && matches_category
                    && matches_tags
                    && matches_rating
                    && matches_author
            })
            .cloned()
            .collect()
    }

    /// Download template
    pub async fn download_template(&self, template_id: &str) -> Result<SecretTemplate> {
        let mut downloads = self.downloads.write().await;
        *downloads.entry(template_id.to_string()).or_insert(0) += 1;

        let mut templates = self.templates.write().await;
        let template = templates
            .get_mut(template_id)
            .ok_or_else(|| MarketplaceError::TemplateNotFound(template_id.to_string()))?;

        template.downloads += 1;
        Ok(template.clone())
    }

    /// Share secret
    pub async fn share_secret(&self, shared_secret: SharedSecret) -> Result<String> {
        let mut shares = self.shared_secrets.write().await;
        let share_id = shared_secret.share_id.clone();
        shares.insert(share_id.clone(), shared_secret);
        Ok(share_id)
    }

    /// Get shared secret
    pub async fn get_shared_secret(&self, share_id: &str, user: &str) -> Result<SharedSecret> {
        let shares = self.shared_secrets.read().await;

        let shared = shares
            .get(share_id)
            .ok_or_else(|| MarketplaceError::TemplateNotFound(share_id.to_string()))?;

        // Check permissions
        if shared.owner != user && !shared.shared_with.contains(&user.to_string()) {
            return Err(MarketplaceError::PermissionDenied(
                "Not authorized".to_string(),
            ));
        }

        // Check expiry
        if let Some(expires_at) = shared.expires_at
            && Utc::now() > expires_at {
            return Err(MarketplaceError::PermissionDenied(
                "Share expired".to_string(),
            ));
        }

        Ok(shared.clone())
    }

    /// Revoke share
    pub async fn revoke_share(&self, share_id: &str, user: &str) -> Result<()> {
        let mut shares = self.shared_secrets.write().await;

        let shared = shares
            .get(share_id)
            .ok_or_else(|| MarketplaceError::TemplateNotFound(share_id.to_string()))?;

        if shared.owner != user {
            return Err(MarketplaceError::PermissionDenied(
                "Not the owner".to_string(),
            ));
        }

        shares.remove(share_id);
        Ok(())
    }

    /// Rate template
    pub async fn rate_template(&self, rating: TemplateRating) -> Result<()> {
        let mut ratings = self.ratings.write().await;

        ratings
            .entry(rating.template_id.clone())
            .or_default()
            .push(rating.clone());

        // Update template rating
        let mut templates = self.templates.write().await;
        if let Some(template) = templates.get_mut(&rating.template_id) {
            let all_ratings = &ratings[&rating.template_id];
            let sum: u32 = all_ratings.iter().map(|r| r.rating as u32).sum();
            template.rating = sum as f64 / all_ratings.len() as f64;
        }

        Ok(())
    }

    /// Get analytics
    pub async fn get_analytics(&self, template_id: &str) -> Result<TemplateAnalytics> {
        let templates = self.templates.read().await;
        let ratings = self.ratings.read().await;
        let downloads = self.downloads.read().await;

        let template = templates
            .get(template_id)
            .ok_or_else(|| MarketplaceError::TemplateNotFound(template_id.to_string()))?;

        let template_ratings = ratings.get(template_id).cloned().unwrap_or_default();
        let total_downloads = downloads.get(template_id).cloned().unwrap_or(0);

        Ok(TemplateAnalytics {
            template_id: template_id.to_string(),
            total_downloads,
            unique_users: template_ratings.len(),
            average_rating: template.rating,
            total_ratings: template_ratings.len(),
            downloads_last_30d: total_downloads,
        })
    }

    /// List popular templates
    pub async fn get_popular_templates(&self, limit: usize) -> Vec<SecretTemplate> {
        let templates = self.templates.read().await;

        let mut sorted: Vec<SecretTemplate> = templates.values().cloned().collect();
        sorted.sort_by(|a, b| b.downloads.cmp(&a.downloads));
        sorted.truncate(limit);
        sorted
    }

    /// List by category
    pub async fn list_by_category(&self, category: TemplateCategory) -> Vec<SecretTemplate> {
        let templates = self.templates.read().await;
        templates
            .values()
            .filter(|t| t.category == category)
            .cloned()
            .collect()
    }
}

impl Default for SecretMarketplace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_template() {
        let marketplace = SecretMarketplace::new();

        let template = SecretTemplate {
            template_id: "tmpl1".to_string(),
            name: "Database Secret".to_string(),
            description: "Template for database credentials".to_string(),
            category: TemplateCategory::Database,
            content: "username: {{username}}\npassword: {{password}}".to_string(),
            version: "1.0.0".to_string(),
            author: "alice".to_string(),
            published_at: Utc::now(),
            downloads: 0,
            rating: 0.0,
            tags: vec!["database".to_string(), "credentials".to_string()],
        };

        let template_id = marketplace.publish_template(template).await.unwrap();
        assert_eq!(template_id, "tmpl1");
    }

    #[tokio::test]
    async fn test_download_template() {
        let marketplace = SecretMarketplace::new();

        let template = SecretTemplate {
            template_id: "tmpl1".to_string(),
            name: "Test".to_string(),
            description: "Test template".to_string(),
            category: TemplateCategory::API,
            content: "api_key: {{key}}".to_string(),
            version: "1.0.0".to_string(),
            author: "bob".to_string(),
            published_at: Utc::now(),
            downloads: 0,
            rating: 0.0,
            tags: vec![],
        };

        marketplace.publish_template(template).await.unwrap();

        let downloaded = marketplace.download_template("tmpl1").await.unwrap();
        assert_eq!(downloaded.downloads, 1);
    }

    #[tokio::test]
    async fn test_share_secret() {
        let marketplace = SecretMarketplace::new();

        let shared = SharedSecret {
            share_id: "share1".to_string(),
            secret_id: "secret1".to_string(),
            owner: "alice".to_string(),
            shared_with: vec!["bob".to_string()],
            permissions: SharePermissions {
                can_read: true,
                can_write: false,
                can_delete: false,
                can_share: false,
            },
            expires_at: None,
            created_at: Utc::now(),
        };

        let share_id = marketplace.share_secret(shared).await.unwrap();
        assert_eq!(share_id, "share1");

        let retrieved = marketplace
            .get_shared_secret(&share_id, "bob")
            .await
            .unwrap();
        assert_eq!(retrieved.owner, "alice");
    }

    #[tokio::test]
    async fn test_rate_template() {
        let marketplace = SecretMarketplace::new();

        let template = SecretTemplate {
            template_id: "tmpl1".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            category: TemplateCategory::Custom,
            content: "test".to_string(),
            version: "1.0.0".to_string(),
            author: "alice".to_string(),
            published_at: Utc::now(),
            downloads: 0,
            rating: 0.0,
            tags: vec![],
        };

        marketplace.publish_template(template).await.unwrap();

        let rating = TemplateRating {
            rating_id: uuid::Uuid::new_v4().to_string(),
            template_id: "tmpl1".to_string(),
            user: "bob".to_string(),
            rating: 5,
            review: Some("Great template!".to_string()),
            created_at: Utc::now(),
        };

        marketplace.rate_template(rating).await.unwrap();

        let template = marketplace.get_template("tmpl1").await.unwrap();
        assert_eq!(template.rating, 5.0);
    }

    #[tokio::test]
    async fn test_search_templates() {
        let marketplace = SecretMarketplace::new();

        let template = SecretTemplate {
            template_id: "tmpl1".to_string(),
            name: "AWS Secret".to_string(),
            description: "AWS credentials template".to_string(),
            category: TemplateCategory::Cloud,
            content: "access_key: {{key}}".to_string(),
            version: "1.0.0".to_string(),
            author: "alice".to_string(),
            published_at: Utc::now(),
            downloads: 0,
            rating: 4.5,
            tags: vec!["aws".to_string(), "cloud".to_string()],
        };

        marketplace.publish_template(template).await.unwrap();

        let filters = SearchFilters {
            category: Some(TemplateCategory::Cloud),
            tags: vec![],
            min_rating: Some(4.0),
            author: None,
        };

        let results = marketplace.search_templates("AWS", filters).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "AWS Secret");
    }

    #[tokio::test]
    async fn test_get_analytics() {
        let marketplace = SecretMarketplace::new();

        let template = SecretTemplate {
            template_id: "tmpl1".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            category: TemplateCategory::API,
            content: "test".to_string(),
            version: "1.0.0".to_string(),
            author: "alice".to_string(),
            published_at: Utc::now(),
            downloads: 0,
            rating: 0.0,
            tags: vec![],
        };

        marketplace.publish_template(template).await.unwrap();
        marketplace.download_template("tmpl1").await.unwrap();

        let analytics = marketplace.get_analytics("tmpl1").await.unwrap();
        assert_eq!(analytics.total_downloads, 1);
    }
}
