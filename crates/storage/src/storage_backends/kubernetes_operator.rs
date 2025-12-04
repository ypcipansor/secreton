#![cfg(feature = "kubernetes")]

// Kubernetes Secrets Operator - CRD-based secret injection and rotation
use chrono::{DateTime, Duration, Utc};
use k8s_openapi::api::core::v1::Pod;
use kube::{Client, api::Api};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum K8sOperatorError {
    #[error("Kubernetes error: {0}")]
    K8sError(String),
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    #[error("Injection error: {0}")]
    InjectionError(String),
}

pub type Result<T> = std::result::Result<T, K8sOperatorError>;

/// Kubernetes configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    pub kubeconfig_path: String,
    pub namespace: String,
    pub context: Option<String>,
    pub annotations: HashMap<String, String>,
}

/// Secret operator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretOperatorConfig {
    pub enable_injection: bool,
    pub rotation_interval_hours: u64,
    pub pod_annotation: String, // e.g., "vault.secreton.io/inject"
    pub mount_path: String,     // e.g., "/vault/secrets"
    pub auto_rotate: bool,
}

/// Kubernetes secret managed by operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sSecret {
    pub name: String,
    pub namespace: String,
    pub data: HashMap<String, String>, // Base64 encoded in real K8s
    pub vault_path: String,
    pub rotation_enabled: bool,
    pub last_rotation: Option<DateTime<Utc>>,
    pub version: u64,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

/// Pod injection record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInjection {
    pub pod_name: String,
    pub namespace: String,
    pub secrets: Vec<String>,
    pub mount_path: String,
    pub injected_at: DateTime<Utc>,
    pub status: InjectionStatus,
}

/// Injection status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InjectionStatus {
    Pending,
    Injected,
    Failed,
    Updating,
}

/// Secret rotation schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSchedule {
    pub secret_name: String,
    pub namespace: String,
    pub interval_hours: u64,
    pub next_rotation: DateTime<Utc>,
    pub last_rotation: Option<DateTime<Utc>>,
}

/// Kubernetes Secrets Operator
pub struct KubernetesOperator {
    _config: Arc<RwLock<KubernetesConfig>>,
    operator_config: Arc<RwLock<SecretOperatorConfig>>,
    secrets: Arc<RwLock<HashMap<String, K8sSecret>>>,
    injections: Arc<RwLock<Vec<PodInjection>>>,
    rotation_schedules: Arc<RwLock<Vec<RotationSchedule>>>,
    client: Client, // K8s API client
}

impl KubernetesOperator {
    /// Create a new operator with async client initialization
    pub async fn new(
        config: KubernetesConfig,
        operator_config: SecretOperatorConfig,
    ) -> Result<Self> {
        let client = Client::try_default().await.map_err(|e| {
            K8sOperatorError::ConfigError(format!("Failed to create K8s client: {}", e))
        })?;

        Ok(Self {
            _config: Arc::new(RwLock::new(config)),
            operator_config: Arc::new(RwLock::new(operator_config)),
            secrets: Arc::new(RwLock::new(HashMap::new())),
            injections: Arc::new(RwLock::new(Vec::new())),
            rotation_schedules: Arc::new(RwLock::new(Vec::new())),
            client,
        })
    }

    /// Create Kubernetes secret from Secret
    pub async fn create_k8s_secret(
        &self,
        name: &str,
        namespace: &str,
        vault_path: &str,
        data: HashMap<String, String>,
    ) -> Result<K8sSecret> {
        let mut labels = HashMap::new();
        labels.insert("managed-by".to_string(), "secreton-operator".to_string());

        let mut annotations = HashMap::new();
        annotations.insert("vault.secreton.io/path".to_string(), vault_path.to_string());

        let secret = K8sSecret {
            name: name.to_string(),
            namespace: namespace.to_string(),
            data,
            vault_path: vault_path.to_string(),
            rotation_enabled: false,
            last_rotation: None,
            version: 1,
            labels,
            annotations,
        };

        // Create Kubernetes secret
        // Real implementation uses kube-rs crate
        self.create_k8s_secret_internal(&secret).await?;

        let mut secrets = self.secrets.write().await;
        let key = format!("{}/{}", namespace, name);
        secrets.insert(key, secret.clone());

        Ok(secret)
    }

    /// Inject secrets into pod via annotations
    pub async fn inject_into_pod(
        &self,
        pod_name: &str,
        namespace: &str,
        secret_names: Vec<String>,
    ) -> Result<PodInjection> {
        let operator_config = self.operator_config.read().await;

        if !operator_config.enable_injection {
            return Err(K8sOperatorError::ConfigError(
                "Secret injection is disabled".to_string(),
            ));
        }

        let mount_path = operator_config.mount_path.clone();
        drop(operator_config);

        // Verify secrets exist
        let secrets = self.secrets.read().await;
        for secret_name in &secret_names {
            let key = format!("{}/{}", namespace, secret_name);
            if !secrets.contains_key(&key) {
                return Err(K8sOperatorError::SecretNotFound(secret_name.clone()));
            }
        }
        drop(secrets);

        let injection = PodInjection {
            pod_name: pod_name.to_string(),
            namespace: namespace.to_string(),
            secrets: secret_names.clone(),
            mount_path: mount_path.clone(),
            injected_at: Utc::now(),
            status: InjectionStatus::Injected,
        };

        // Mock mutation webhook that modifies pod spec
        // Real implementation would use admission webhook
        self.mock_inject_secrets(pod_name, namespace, &secret_names, &mount_path)
            .await?;

        let mut injections = self.injections.write().await;
        injections.push(injection.clone());

        Ok(injection)
    }

    /// Rotate Kubernetes secrets
    pub async fn rotate_k8s_secrets(&self) -> Result<Vec<String>> {
        let mut rotated = Vec::new();
        let now = Utc::now();

        let mut schedules = self.rotation_schedules.write().await;
        let mut secrets = self.secrets.write().await;

        for schedule in schedules.iter_mut() {
            if schedule.next_rotation <= now {
                let key = format!("{}/{}", schedule.namespace, schedule.secret_name);

                if let Some(secret) = secrets.get_mut(&key) {
                    // Mock rotation - in real implementation would fetch from Secret
                    secret.version += 1;
                    secret.last_rotation = Some(now);

                    // Update K8s secret
                    self.update_k8s_secret(secret).await?;

                    schedule.last_rotation = Some(now);
                    schedule.next_rotation = now + Duration::hours(schedule.interval_hours as i64);

                    rotated.push(key.clone());
                }
            }
        }

        Ok(rotated)
    }

    /// Sync secret from Secret to Kubernetes
    pub async fn sync_from_vault(
        &self,
        vault_path: &str,
        k8s_name: &str,
        namespace: &str,
    ) -> Result<()> {
        // Mock fetching from Secret
        // Real implementation would call Secret API
        let vault_data = self.mock_fetch_from_vault(vault_path).await?;

        let key = format!("{}/{}", namespace, k8s_name);
        let mut secrets = self.secrets.write().await;

        if let Some(secret) = secrets.get_mut(&key) {
            secret.data = vault_data;
            secret.version += 1;
            secret.last_rotation = Some(Utc::now());

            // Update K8s secret
            self.update_k8s_secret(secret).await?;
        } else {
            return Err(K8sOperatorError::SecretNotFound(k8s_name.to_string()));
        }

        Ok(())
    }

    /// Watch for pod events with injection annotation
    pub async fn watch_pod_events(&self) -> Result<Vec<String>> {
        // Mock watching K8s pod events
        // Real implementation would use kube-rs watch API
        let operator_config = self.operator_config.read().await;
        let annotation = operator_config.pod_annotation.clone();
        drop(operator_config);

        // List pods that need injection
        let pods_needing_injection = self.list_pods_with_annotation(&annotation).await?;

        Ok(pods_needing_injection)
    }

    /// Enable auto-rotation for secret
    pub async fn enable_rotation(
        &self,
        secret_name: &str,
        namespace: &str,
        interval_hours: u64,
    ) -> Result<()> {
        let key = format!("{}/{}", namespace, secret_name);

        let mut secrets = self.secrets.write().await;
        if let Some(secret) = secrets.get_mut(&key) {
            secret.rotation_enabled = true;
        } else {
            return Err(K8sOperatorError::SecretNotFound(secret_name.to_string()));
        }
        drop(secrets);

        let schedule = RotationSchedule {
            secret_name: secret_name.to_string(),
            namespace: namespace.to_string(),
            interval_hours,
            next_rotation: Utc::now() + Duration::hours(interval_hours as i64),
            last_rotation: None,
        };

        let mut schedules = self.rotation_schedules.write().await;
        schedules.push(schedule);

        Ok(())
    }

    /// List managed secrets
    pub async fn list_managed_secrets(&self, namespace: Option<&str>) -> Vec<K8sSecret> {
        let secrets = self.secrets.read().await;

        secrets
            .values()
            .filter(|s| namespace.map(|ns| s.namespace == ns).unwrap_or(true))
            .cloned()
            .collect()
    }

    /// Get secret by name
    pub async fn get_secret(&self, name: &str, namespace: &str) -> Result<K8sSecret> {
        let key = format!("{}/{}", namespace, name);
        let secrets = self.secrets.read().await;

        secrets
            .get(&key)
            .cloned()
            .ok_or_else(|| K8sOperatorError::SecretNotFound(name.to_string()))
    }

    /// Delete secret
    pub async fn delete_secret(&self, name: &str, namespace: &str) -> Result<()> {
        let key = format!("{}/{}", namespace, name);

        let mut secrets = self.secrets.write().await;
        secrets
            .remove(&key)
            .ok_or_else(|| K8sOperatorError::SecretNotFound(name.to_string()))?;

        // Delete K8s secret
        self.delete_k8s_secret(name, namespace).await?;

        Ok(())
    }

    /// List pod injections
    pub async fn list_injections(&self, namespace: Option<&str>) -> Vec<PodInjection> {
        let injections = self.injections.read().await;

        injections
            .iter()
            .filter(|i| namespace.map(|ns| i.namespace == ns).unwrap_or(true))
            .cloned()
            .collect()
    }

    // Real K8s API methods using kube-rs
    async fn create_k8s_secret_internal(&self, secret: &K8sSecret) -> Result<()> {
        use k8s_openapi::api::core::v1::Secret as K8sSecretType;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        for (key, value) in &secret.data {
            data.insert(
                key.clone(),
                k8s_openapi::ByteString(base64::encode(value).into_bytes()),
            );
        }

        let mut labels = BTreeMap::new();
        for (key, value) in &secret.labels {
            labels.insert(key.clone(), value.clone());
        }

        let mut annotations = BTreeMap::new();
        for (key, value) in &secret.annotations {
            annotations.insert(key.clone(), value.clone());
        }

        let k8s_secret = K8sSecretType {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(secret.name.clone()),
                namespace: Some(secret.namespace.clone()),
                labels: Some(labels),
                annotations: Some(annotations),
                ..Default::default()
            },
            data: Some(data),
            type_: Some("Opaque".to_string()),
            ..Default::default()
        };

        let secrets: Api<K8sSecretType> = Api::namespaced(self.client.clone(), &secret.namespace);
        secrets
            .create(&Default::default(), &k8s_secret)
            .await
            .map_err(|e| K8sOperatorError::K8sError(format!("Failed to create secret: {}", e)))?;

        Ok(())
    }

    async fn update_k8s_secret(&self, secret: &K8sSecret) -> Result<()> {
        use k8s_openapi::api::core::v1::Secret as K8sSecretType;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        for (key, value) in &secret.data {
            data.insert(
                key.clone(),
                k8s_openapi::ByteString(base64::encode(value).into_bytes()),
            );
        }

        let secrets: Api<K8sSecretType> = Api::namespaced(self.client.clone(), &secret.namespace);

        // Get existing secret first
        let existing = secrets
            .get(&secret.name)
            .await
            .map_err(|e| K8sOperatorError::K8sError(format!("Failed to get secret: {}", e)))?;

        let mut labels = BTreeMap::new();
        for (key, value) in &secret.labels {
            labels.insert(key.clone(), value.clone());
        }

        let mut annotations = BTreeMap::new();
        for (key, value) in &secret.annotations {
            annotations.insert(key.clone(), value.clone());
        }

        let updated_secret = K8sSecretType {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(secret.name.clone()),
                namespace: Some(secret.namespace.clone()),
                resource_version: existing.metadata.resource_version,
                labels: Some(labels),
                annotations: Some(annotations),
                ..Default::default()
            },
            data: Some(data),
            type_: Some("Opaque".to_string()),
            ..Default::default()
        };

        secrets
            .replace(&secret.name, &Default::default(), &updated_secret)
            .await
            .map_err(|e| K8sOperatorError::K8sError(format!("Failed to update secret: {}", e)))?;

        Ok(())
    }

    async fn delete_k8s_secret(&self, name: &str, namespace: &str) -> Result<()> {
        use k8s_openapi::api::core::v1::Secret as K8sSecretType;

        let secrets: Api<K8sSecretType> = Api::namespaced(self.client.clone(), namespace);
        secrets
            .delete(name, &Default::default())
            .await
            .map_err(|e| K8sOperatorError::K8sError(format!("Failed to delete secret: {}", e)))?;

        Ok(())
    }

    async fn mock_inject_secrets(
        &self,
        _pod_name: &str,
        _namespace: &str,
        _secrets: &[String],
        _mount_path: &str,
    ) -> Result<()> {
        // Mock injection via admission webhook
        Ok(())
    }

    async fn mock_fetch_from_vault(&self, _path: &str) -> Result<HashMap<String, String>> {
        // Mock fetching from Secret
        let mut data = HashMap::new();
        data.insert("username".to_string(), "updated_user".to_string());
        data.insert("password".to_string(), "updated_pass".to_string());
        Ok(data)
    }

    async fn list_pods_with_annotation(&self, annotation: &str) -> Result<Vec<String>> {
        let pods: Api<Pod> = Api::all(self.client.clone());

        let pod_list = pods
            .list(&Default::default())
            .await
            .map_err(|e| K8sOperatorError::K8sError(format!("Failed to list pods: {}", e)))?;

        let mut pod_names = Vec::new();
        for pod in pod_list.items {
            if let Some(annotations) = &pod.metadata.annotations
                && annotations.contains_key(annotation)
                && let Some(name) = pod.metadata.name
            {
                pod_names.push(name);
            }
        }

        Ok(pod_names)
    }
}

impl Default for KubernetesOperator {
    fn default() -> Self {
        let config = KubernetesConfig {
            kubeconfig_path: "~/.kube/config".to_string(),
            namespace: "default".to_string(),
            context: None,
            annotations: HashMap::new(),
        };

        let operator_config = SecretOperatorConfig {
            enable_injection: true,
            rotation_interval_hours: 24,
            pod_annotation: "vault.secreton.io/inject".to_string(),
            mount_path: "/vault/secrets".to_string(),
            auto_rotate: true,
        };

        // For default, we'll create a basic client - in real usage, async new should be used
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(Self::new(config, operator_config))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_operator() -> KubernetesOperator {
        KubernetesOperator::default()
    }

    #[tokio::test]
    async fn test_create_k8s_secret() {
        let operator = create_test_operator();

        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        data.insert("password".to_string(), "secret123".to_string());

        let secret = operator
            .create_k8s_secret("db-credentials", "default", "/secret/data/db", data)
            .await
            .unwrap();

        assert_eq!(secret.name, "db-credentials");
        assert_eq!(secret.namespace, "default");
        assert_eq!(secret.vault_path, "/secret/data/db");
        assert_eq!(secret.version, 1);
        assert_eq!(
            secret.labels.get("managed-by"),
            Some(&"secreton-operator".to_string())
        );
    }

    #[tokio::test]
    async fn test_inject_secrets_into_pod() {
        let operator = create_test_operator();

        // Create secret first
        let mut data = HashMap::new();
        data.insert("api_key".to_string(), "key123".to_string());

        operator
            .create_k8s_secret("api-secret", "default", "/secret/data/api", data)
            .await
            .unwrap();

        // Inject into pod
        let injection = operator
            .inject_into_pod("my-pod", "default", vec!["api-secret".to_string()])
            .await
            .unwrap();

        assert_eq!(injection.pod_name, "my-pod");
        assert_eq!(injection.namespace, "default");
        assert_eq!(injection.secrets, vec!["api-secret"]);
        assert_eq!(injection.mount_path, "/vault/secrets");
        assert_eq!(injection.status, InjectionStatus::Injected);
    }

    #[tokio::test]
    async fn test_secret_rotation() {
        let operator = create_test_operator();

        let mut data = HashMap::new();
        data.insert("token".to_string(), "old_token".to_string());

        operator
            .create_k8s_secret("app-token", "default", "/secret/data/token", data)
            .await
            .unwrap();

        // Enable rotation
        operator
            .enable_rotation("app-token", "default", 1)
            .await
            .unwrap();

        // Manually trigger rotation
        let mut schedules = operator.rotation_schedules.write().await;
        if let Some(schedule) = schedules.first_mut() {
            schedule.next_rotation = Utc::now() - Duration::hours(1);
        }
        drop(schedules);

        let rotated = operator.rotate_k8s_secrets().await.unwrap();

        assert_eq!(rotated.len(), 1);
        assert_eq!(rotated[0], "default/app-token");

        let secret = operator.get_secret("app-token", "default").await.unwrap();
        assert_eq!(secret.version, 2);
        assert!(secret.last_rotation.is_some());
    }

    #[tokio::test]
    async fn test_sync_from_vault() {
        let operator = create_test_operator();

        let mut data = HashMap::new();
        data.insert("old_key".to_string(), "old_value".to_string());

        operator
            .create_k8s_secret("sync-secret", "default", "/secret/data/sync", data)
            .await
            .unwrap();

        // Sync from Secret (mock will return updated data)
        operator
            .sync_from_vault("/secret/data/sync", "sync-secret", "default")
            .await
            .unwrap();

        let secret = operator.get_secret("sync-secret", "default").await.unwrap();
        assert_eq!(secret.version, 2);
        assert!(secret.data.contains_key("username"));
        assert!(secret.data.contains_key("password"));
    }

    #[tokio::test]
    async fn test_list_managed_secrets() {
        let operator = create_test_operator();

        let mut data1 = HashMap::new();
        data1.insert("key1".to_string(), "value1".to_string());

        let mut data2 = HashMap::new();
        data2.insert("key2".to_string(), "value2".to_string());

        operator
            .create_k8s_secret("secret1", "default", "/secret/data/s1", data1)
            .await
            .unwrap();

        operator
            .create_k8s_secret("secret2", "production", "/secret/data/s2", data2)
            .await
            .unwrap();

        let all_secrets = operator.list_managed_secrets(None).await;
        assert_eq!(all_secrets.len(), 2);

        let default_secrets = operator.list_managed_secrets(Some("default")).await;
        assert_eq!(default_secrets.len(), 1);
        assert_eq!(default_secrets[0].name, "secret1");
    }

    #[tokio::test]
    async fn test_watch_pod_events() {
        let operator = create_test_operator();

        let pods = operator.watch_pod_events().await.unwrap();

        assert_eq!(pods.len(), 2);
        assert!(pods.contains(&"pod-1".to_string()));
        assert!(pods.contains(&"pod-2".to_string()));
    }
}
