use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrationType {
    AwsSecretsManager,
    AzureKeyVault,
    Kubernetes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub id: String,
    pub name: String,
    pub integration_type: IntegrationType,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HookType {
    PreExpire,
    PostExpire,
    PreArchive,
    PostArchive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleHook {
    #[serde(alias = "hook_id")]
    pub id: String,
    pub hook_type: HookType,
    pub action_url: String,
    pub enabled: bool,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sSecret {
    #[serde(alias = "_name")]
    pub name: String,
    pub namespace: String,
    #[serde(alias = "_secreton_path")]
    pub secreton_path: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InjectionStatus {
    Pending,
    Injected,
    Failed,
    Updating,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInjection {
    pub pod_name: String,
    pub namespace: String,
    pub mount_path: String,
    #[serde(alias = "_status")]
    pub status: InjectionStatus,
}
