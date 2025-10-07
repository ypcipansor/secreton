// Ansible Integration - Playbook execution with secret injection
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum AnsibleError {
    #[error("Playbook error: {0}")]
    PlaybookError(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Secret error: {0}")]
    SecretError(String),
}

pub type Result<T> = std::result::Result<T, AnsibleError>;

/// Connection type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionType {
    SSH,
    WinRM,
    Local,
}

/// Ansible configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleConfig {
    pub vault_path: String,
    pub inventory_path: String,
    pub connection: ConnectionType,
    pub remote_user: String,
    pub become: bool,
}

/// Ansible task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleTask {
    pub task_id: String,
    pub name: String,
    pub module: String, // vault_read, vault_write, shell, copy, etc.
    pub args: HashMap<String, String>,
    pub register: Option<String>, // Variable name to store result
}

/// Ansible playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsiblePlaybook {
    pub playbook_id: String,
    pub name: String,
    pub hosts: String,
    pub tasks: Vec<AnsibleTask>,
    pub variables: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

/// Host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub hostname: String,
    pub ansible_host: String,
    pub ansible_port: u16,
    pub variables: HashMap<String, String>,
}

/// Inventory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleInventory {
    pub hosts: Vec<Host>,
    pub groups: HashMap<String, Vec<String>>, // group_name -> hostnames
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Success,
    Failed,
}

/// Execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub execution_id: String,
    pub playbook_id: String,
    pub status: ExecutionStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub output: String,
    pub task_results: Vec<TaskResult>,
    pub secrets_injected: Vec<String>, // secret paths
}

/// Task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub task_name: String,
    pub status: String, // ok, changed, failed, skipped
    pub output: String,
}

/// Ansible Integration
pub struct AnsibleIntegration {
    config: Arc<RwLock<AnsibleConfig>>,
    playbooks: Arc<RwLock<HashMap<String, AnsiblePlaybook>>>,
    inventory: Arc<RwLock<Option<AnsibleInventory>>>,
    executions: Arc<RwLock<HashMap<String, ExecutionResult>>>,
}

impl AnsibleIntegration {
    pub fn new(config: AnsibleConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            playbooks: Arc::new(RwLock::new(HashMap::new())),
            inventory: Arc::new(RwLock::new(None)),
            executions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register playbook
    pub async fn register_playbook(&self, playbook: AnsiblePlaybook) -> Result<()> {
        if playbook.tasks.is_empty() {
            return Err(AnsibleError::PlaybookError(
                "Playbook must have at least one task".to_string(),
            ));
        }

        let mut playbooks = self.playbooks.write().await;
        playbooks.insert(playbook.playbook_id.clone(), playbook);

        Ok(())
    }

    /// Set inventory
    pub async fn set_inventory(&self, inventory: AnsibleInventory) -> Result<()> {
        let mut inv = self.inventory.write().await;
        *inv = Some(inventory);

        Ok(())
    }

    /// Execute playbook
    pub async fn execute_playbook(
        &self,
        playbook_id: &str,
        extra_vars: HashMap<String, String>,
    ) -> Result<String> {
        let playbooks = self.playbooks.read().await;
        let playbook = playbooks
            .get(playbook_id)
            .ok_or_else(|| AnsibleError::PlaybookError("Playbook not found".to_string()))?;

        let inventory = self.inventory.read().await;
        if inventory.is_none() {
            return Err(AnsibleError::ExecutionError(
                "No inventory configured".to_string(),
            ));
        }

        let execution_id = uuid::Uuid::new_v4().to_string();

        // Inject secrets into variables
        let mut injected_secrets = Vec::new();
        let mut merged_vars = playbook.variables.clone();
        merged_vars.extend(extra_vars);

        // Mock secret injection
        for (key, value) in &merged_vars {
            if value.starts_with("vault:") {
                let secret_path = value.strip_prefix("vault:").unwrap();
                injected_secrets.push(secret_path.to_string());
                // Real implementation would fetch from Vault
            }
        }

        // Mock task execution
        let mut task_results = Vec::new();
        for task in &playbook.tasks {
            let result = self.mock_execute_task(task, &merged_vars).await;
            task_results.push(result);
        }

        let execution_result = ExecutionResult {
            execution_id: execution_id.clone(),
            playbook_id: playbook_id.to_string(),
            status: ExecutionStatus::Success,
            start_time: Utc::now(),
            end_time: Some(Utc::now()),
            output: "Playbook executed successfully".to_string(),
            task_results,
            secrets_injected: injected_secrets,
        };

        drop(playbooks);
        drop(inventory);

        let mut executions = self.executions.write().await;
        executions.insert(execution_id.clone(), execution_result);

        Ok(execution_id)
    }

    /// Mock task execution
    async fn mock_execute_task(
        &self,
        task: &AnsibleTask,
        _variables: &HashMap<String, String>,
    ) -> TaskResult {
        TaskResult {
            task_id: task.task_id.clone(),
            task_name: task.name.clone(),
            status: "ok".to_string(),
            output: format!("Task {} completed", task.name),
        }
    }

    /// Inject secrets
    pub async fn inject_secrets(
        &self,
        playbook_id: &str,
        secret_mappings: HashMap<String, String>, // var_name -> secret_path
    ) -> Result<()> {
        let mut playbooks = self.playbooks.write().await;
        let playbook = playbooks
            .get_mut(playbook_id)
            .ok_or_else(|| AnsibleError::PlaybookError("Playbook not found".to_string()))?;

        for (var_name, secret_path) in secret_mappings {
            playbook
                .variables
                .insert(var_name, format!("vault:{}", secret_path));
        }

        Ok(())
    }

    /// Get execution result
    pub async fn get_execution_result(&self, execution_id: &str) -> Option<ExecutionResult> {
        let executions = self.executions.read().await;
        executions.get(execution_id).cloned()
    }

    /// List playbooks
    pub async fn list_playbooks(&self) -> Vec<String> {
        let playbooks = self.playbooks.read().await;
        playbooks.keys().cloned().collect()
    }

    /// Get playbook
    pub async fn get_playbook(&self, playbook_id: &str) -> Option<AnsiblePlaybook> {
        let playbooks = self.playbooks.read().await;
        playbooks.get(playbook_id).cloned()
    }

    /// Delete playbook
    pub async fn delete_playbook(&self, playbook_id: &str) -> Result<()> {
        let mut playbooks = self.playbooks.write().await;
        playbooks
            .remove(playbook_id)
            .ok_or_else(|| AnsibleError::PlaybookError("Playbook not found".to_string()))?;

        Ok(())
    }

    /// List executions
    pub async fn list_executions(&self) -> Vec<ExecutionResult> {
        let executions = self.executions.read().await;
        executions.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AnsibleConfig {
        AnsibleConfig {
            vault_path: "/vault".to_string(),
            inventory_path: "/etc/ansible/hosts".to_string(),
            connection: ConnectionType::SSH,
            remote_user: "ansible".to_string(),
            become: true,
        }
    }

    fn create_test_playbook() -> AnsiblePlaybook {
        AnsiblePlaybook {
            playbook_id: "deploy-app".to_string(),
            name: "Deploy Application".to_string(),
            hosts: "webservers".to_string(),
            tasks: vec![
                AnsibleTask {
                    task_id: "task1".to_string(),
                    name: "Read secret from Vault".to_string(),
                    module: "vault_read".to_string(),
                    args: {
                        let mut args = HashMap::new();
                        args.insert("path".to_string(), "secret/data/app".to_string());
                        args
                    },
                    register: Some("app_secret".to_string()),
                },
                AnsibleTask {
                    task_id: "task2".to_string(),
                    name: "Deploy application".to_string(),
                    module: "shell".to_string(),
                    args: {
                        let mut args = HashMap::new();
                        args.insert("cmd".to_string(), "deploy.sh".to_string());
                        args
                    },
                    register: None,
                },
            ],
            variables: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    fn create_test_inventory() -> AnsibleInventory {
        AnsibleInventory {
            hosts: vec![
                Host {
                    hostname: "web1".to_string(),
                    ansible_host: "192.168.1.10".to_string(),
                    ansible_port: 22,
                    variables: HashMap::new(),
                },
                Host {
                    hostname: "web2".to_string(),
                    ansible_host: "192.168.1.11".to_string(),
                    ansible_port: 22,
                    variables: HashMap::new(),
                },
            ],
            groups: {
                let mut groups = HashMap::new();
                groups.insert(
                    "webservers".to_string(),
                    vec!["web1".to_string(), "web2".to_string()],
                );
                groups
            },
        }
    }

    #[tokio::test]
    async fn test_register_playbook() {
        let ansible = AnsibleIntegration::new(create_test_config());
        let playbook = create_test_playbook();

        ansible.register_playbook(playbook).await.unwrap();

        let playbooks = ansible.list_playbooks().await;
        assert_eq!(playbooks.len(), 1);
        assert_eq!(playbooks[0], "deploy-app");
    }

    #[tokio::test]
    async fn test_execute_playbook() {
        let ansible = AnsibleIntegration::new(create_test_config());
        let playbook = create_test_playbook();

        ansible.register_playbook(playbook).await.unwrap();
        ansible.set_inventory(create_test_inventory()).await.unwrap();

        let execution_id = ansible
            .execute_playbook("deploy-app", HashMap::new())
            .await
            .unwrap();

        let result = ansible.get_execution_result(&execution_id).await.unwrap();
        assert_eq!(result.status, ExecutionStatus::Success);
        assert_eq!(result.task_results.len(), 2);
    }

    #[tokio::test]
    async fn test_inject_secrets() {
        let ansible = AnsibleIntegration::new(create_test_config());
        let playbook = create_test_playbook();

        ansible.register_playbook(playbook).await.unwrap();

        let mut secret_mappings = HashMap::new();
        secret_mappings.insert("db_password".to_string(), "secret/data/db/password".to_string());
        secret_mappings.insert("api_key".to_string(), "secret/data/api/key".to_string());

        ansible
            .inject_secrets("deploy-app", secret_mappings)
            .await
            .unwrap();

        let playbook = ansible.get_playbook("deploy-app").await.unwrap();
        assert_eq!(playbook.variables.len(), 2);
        assert_eq!(
            playbook.variables.get("db_password"),
            Some(&"vault:secret/data/db/password".to_string())
        );
    }

    #[tokio::test]
    async fn test_inventory_management() {
        let ansible = AnsibleIntegration::new(create_test_config());
        let inventory = create_test_inventory();

        ansible.set_inventory(inventory).await.unwrap();

        // Execute requires inventory
        let playbook = create_test_playbook();
        ansible.register_playbook(playbook).await.unwrap();

        let result = ansible.execute_playbook("deploy-app", HashMap::new()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execution_tracking() {
        let ansible = AnsibleIntegration::new(create_test_config());
        let playbook = create_test_playbook();

        ansible.register_playbook(playbook).await.unwrap();
        ansible.set_inventory(create_test_inventory()).await.unwrap();

        let execution_id = ansible
            .execute_playbook("deploy-app", HashMap::new())
            .await
            .unwrap();

        let executions = ansible.list_executions().await;
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].execution_id, execution_id);
    }
}
