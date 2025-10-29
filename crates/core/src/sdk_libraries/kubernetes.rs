use std::collections::HashMap;

use base64::{engine::general_purpose, Engine as _};


/// Kubernetes operator configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KubernetesOperatorConfig {
    /// Kubernetes namespace
    pub namespace: String,
    /// Secreton server URL
    pub server_url: String,
    /// Authentication token
    pub token: String,
    /// Operator image
    pub image: String,
    /// Resource limits
    pub resources: HashMap<String, String>,
}

/// Kubernetes operator implementation
pub struct KubernetesOperator {
    config: KubernetesOperatorConfig,
}

impl KubernetesOperator {
    /// Create a new Kubernetes operator
    pub fn new(config: KubernetesOperatorConfig) -> Self {
        Self { config }
    }

    /// Generate Kubernetes manifests
    pub fn generate_manifests(&self) -> String {
        format!(
            r#"
---
apiVersion: v1
kind: Namespace
metadata:
  name: {}

---
apiVersion: v1
kind: Secret
metadata:
  name: secreton-credentials
  namespace: {}
type: Opaque
data:
  token: {}

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secreton-operator
  namespace: {}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secreton-operator
  template:
    metadata:
      labels:
        app: secreton-operator
    spec:
      serviceAccountName: secreton-operator
      containers:
      - name: operator
        image: {}
        env:
        - name: SECRETON_SERVER_URL
          value: "{}"
        - name: SECRETON_TOKEN
          valueFrom:
            secretKeyRef:
              name: secreton-credentials
              key: token
        resources:
{}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secreton-operator
  namespace: {}

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secreton-operator
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: secreton-operator
subjects:
- kind: ServiceAccount
  name: secreton-operator
  namespace: {}
roleRef:
  kind: ClusterRole
  name: secreton-operator
  apiGroup: rbac.authorization.k8s.io
"#,
            self.config.namespace,
            self.config.namespace,
            general_purpose::STANDARD.encode(&self.config.token),
            self.config.namespace,
            self.config.image,
            self.config.server_url,
            self.format_resources(),
            self.config.namespace,
            self.config.namespace
        )
    }

    fn format_resources(&self) -> String {
        let mut resources = Vec::new();
        for (key, value) in &self.config.resources {
            resources.push(format!("          {}: {}", key, value));
        }
        resources.join("\n")
    }
}