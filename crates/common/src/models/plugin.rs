use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCatalogEntry {
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub artifact_path: String,
    pub pinned: Option<bool>,
    pub metadata: Option<serde_json::Value>,
}
