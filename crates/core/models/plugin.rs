use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCatalogEntry {
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub artifact_path: String,
    pub pinned: bool,
    pub metadata: Option<serde_json::Value>,
} 