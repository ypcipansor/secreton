use serde::Deserialize;
use anyhow::Result;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct NotifyConfig {
    pub webhook: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub server_url: String,
    pub server_urls: Option<Vec<String>>, // daftar server untuk failover
    pub auth_method: String, // "userpass", "approle", "k8s", dst
    pub auth_config: serde_yaml::Value, // detail auth
    pub templates: Vec<TemplateConfig>,
    pub interval: Option<u64>, // detik
    pub sink: Option<String>, // file,env,child
    pub log_file: Option<String>,
    pub log_format: Option<String>,
    pub audit_file: Option<String>,
    pub run: Option<Vec<String>>, // perintah child process
    pub notify: Option<NotifyConfig>,
    pub restart_child: Option<bool>,
    pub restart_delay: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TemplateConfig {
    pub source: String, // path di vault
    pub dest: String,   // path file lokal
    pub mode: Option<String>, // one-shot/interval
}

impl AgentConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let cfg: AgentConfig = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }
} 