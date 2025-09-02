# Secreton Enterprise Vault - Deployment Guide

**Version:** 2.1.1
**Last Updated:** August 28, 2025
**Status:** ✅ Production Ready

## 📋 Overview

This guide provides comprehensive instructions for deploying Secreton Enterprise Vault in various environments, from development to production. Secreton supports multiple deployment architectures including standalone, clustered, and cloud-native deployments.

## 🏗️ Deployment Architectures

### 1. Standalone Deployment
Perfect for development, testing, and small-scale production.

```
┌─────────────────┐
│   Secreton      │
│   Standalone    │
│   Server        │
├─────────────────┤
│ • Single Node   │
│ • Local Storage │
│ • Basic HA      │
└─────────────────┘
```

### 2. Clustered Deployment
Enterprise-grade high availability with automatic failover.

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Secreton      │    │   Secreton      │    │   Secreton      │
│   Node 1        │◄──►│   Node 2        │◄──►│   Node 3        │
│   (Leader)      │    │   (Follower)    │    │   (Follower)    │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Raft Consensus│    │ • Raft Consensus│    │ • Raft Consensus│
│ • Auto Failover │    │ • Auto Failover │    │ • Auto Failover │
│ • Load Balancing│    │ • Load Balancing│    │ • Load Balancing│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 3. Cloud-Native Deployment
Kubernetes-native deployment with auto-scaling.

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  Secreton   │    │  Secreton   │    │  Secreton   │     │
│  │  Pod 1      │    │  Pod 2      │    │  Pod 3      │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐                        │
│  │ PostgreSQL  │    │   Redis     │                        │
│  │  Database   │    │   Cache     │                        │
│  └─────────────┘    └─────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start Deployment

### Prerequisites

#### System Requirements
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **CPU**: 4+ cores (8+ recommended)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 50GB SSD minimum (500GB+ recommended)
- **Network**: 1Gbps minimum (10Gbps recommended)

#### Software Dependencies
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
  curl \
  wget \
  git \
  build-essential \
  pkg-config \
  libssl-dev \
  postgresql \
  postgresql-contrib \
  redis-server \
  nginx \
  certbot \
  ufw \
  fail2ban
```

### Single-Node Deployment

#### 1. Download and Build
```bash
# Clone repository
git clone https://github.com/cipherce/secreton.git
cd secreton

# Build release version
cargo build --release

# Create system user
sudo useradd -r -s /bin/false secreton
sudo mkdir -p /opt/secreton/{bin,data,logs,config}
sudo chown -R secreton:secreton /opt/secreton
```

#### 2. Database Setup
```bash
# Configure PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE secreton_db;
CREATE USER secreton_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE secreton_db TO secreton_user;
ALTER USER secreton_user CREATEDB;

# Create extensions
\c secreton_db
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

\q
```

#### 3. Configuration
```toml
# /opt/secreton/config/vault.toml
[server]
host = "0.0.0.0"
port = 8200
tls_enabled = true
tls_cert_path = "/opt/secreton/certs/server.crt"
tls_key_path = "/opt/secreton/certs/server.key"

[database]
type = "postgresql"
host = "localhost"
port = 5432
database = "secreton_db"
username = "secreton_user"
password = "secure_password_here"
max_connections = 20

[storage]
backend = "raft"
data_dir = "/opt/secreton/data"
node_id = "secreton-node-01"

[security]
encryption_key_rotation_days = 30
audit_log_enabled = true
audit_log_path = "/opt/secreton/logs/audit.log"
mfa_required = true

[logging]
level = "info"
file_path = "/opt/secreton/logs/secreton.log"
max_size_mb = 100
max_files = 10
```

#### 4. TLS Certificate Setup
```bash
# Create certificate directory
sudo mkdir -p /opt/secreton/certs
sudo chown secreton:secreton /opt/secreton/certs

# Generate self-signed certificate (for testing)
sudo -u secreton openssl req -x509 -newkey rsa:4096 \
  -keyout /opt/secreton/certs/server.key \
  -out /opt/secreton/certs/server.crt \
  -days 365 \
  -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=vault.example.com"

# Set proper permissions
sudo chmod 600 /opt/secreton/certs/server.key
sudo chmod 644 /opt/secreton/certs/server.crt
```

#### 5. System Service
```bash
# Create systemd service file
sudo tee /etc/systemd/system/secreton.service > /dev/null <<EOF
[Unit]
Description=Secreton Enterprise Vault
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=secreton
Group=secreton
ExecStart=/opt/secreton/bin/secreton server -config /opt/secreton/config/vault.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Copy binary
sudo cp target/release/secreton /opt/secreton/bin/
sudo chown secreton:secreton /opt/secreton/bin/secreton
sudo chmod +x /opt/secreton/bin/secreton

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable secreton
sudo systemctl start secreton
```

#### 6. Verification
```bash
# Check service status
sudo systemctl status secreton

# Check logs
sudo journalctl -u secreton -f

# Test API endpoint
curl -k https://localhost:8200/v1/sys/health

# Initialize vault (first time only)
curl -k -X POST \
  -d '{"secret_shares": 5, "secret_threshold": 3}' \
  https://localhost:8200/v1/sys/init
```

## 🏢 Enterprise Clustered Deployment

### Prerequisites
- 3+ servers with identical specifications
- Shared storage or network-attached storage
- Load balancer (HAProxy, NGINX, or cloud load balancer)
- DNS with round-robin or load balancer endpoint

### Cluster Configuration

#### 1. Node Configuration
```toml
# Node 1: /opt/secreton/config/vault.toml
[server]
host = "0.0.0.0"
port = 8200
cluster_addr = "https://vault-node1.example.com:8201"

[storage]
backend = "raft"
data_dir = "/opt/secreton/data"
node_id = "vault-node1"

[cluster]
enabled = true
bootstrap_expect = 3
retry_join = [
  "vault-node2.example.com:8201",
  "vault-node3.example.com:8201"
]
```

```toml
# Node 2: /opt/secreton/config/vault.toml
[server]
host = "0.0.0.0"
port = 8200
cluster_addr = "https://vault-node2.example.com:8201"

[storage]
backend = "raft"
data_dir = "/opt/secreton/data"
node_id = "vault-node2"

[cluster]
enabled = true
bootstrap_expect = 3
retry_join = [
  "vault-node1.example.com:8201",
  "vault-node3.example.com:8201"
]
```

#### 2. Load Balancer Configuration

**HAProxy Configuration:**
```haproxy
frontend vault_frontend
    bind *:443 ssl crt /etc/ssl/certs/vault.pem
    mode tcp
    default_backend vault_backend

backend vault_backend
    mode tcp
    balance roundrobin
    server vault1 vault-node1.example.com:8200 check ssl verify none
    server vault2 vault-node2.example.com:8200 check ssl verify none
    server vault3 vault-node3.example.com:8200 check ssl verify none
```

**NGINX Configuration:**
```nginx
upstream vault_cluster {
    server vault-node1.example.com:8200;
    server vault-node2.example.com:8200;
    server vault-node3.example.com:8200;
}

server {
    listen 443 ssl http2;
    server_name vault.example.com;

    ssl_certificate /etc/ssl/certs/vault.crt;
    ssl_certificate_key /etc/ssl/private/vault.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    location / {
        proxy_pass https://vault_cluster;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 3. Cluster Initialization
```bash
# Initialize cluster on first node
curl -k -X POST \
  -d '{"secret_shares": 5, "secret_threshold": 3}' \
  https://vault-node1.example.com:8200/v1/sys/init

# Unseal each node with unseal keys
for node in vault-node1 vault-node2 vault-node3; do
  for key in "${unseal_keys[@]}"; do
    curl -k -X POST \
      -d "{\"key\": \"$key\"}" \
      https://$node.example.com:8200/v1/sys/unseal
  done
done

# Verify cluster status
curl -k https://vault.example.com/v1/sys/health
curl -k https://vault.example.com/v1/sys/leader
```

## ☁️ Cloud Deployment

### AWS Deployment

#### 1. Infrastructure Setup
```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# VPC and Networking
resource "aws_vpc" "vault" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "secreton-vault"
  }
}

# Security Groups
resource "aws_security_group" "vault" {
  name_prefix = "secreton-vault-"
  vpc_id      = aws_vpc.vault.id

  ingress {
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8201
    to_port     = 8201
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS PostgreSQL
resource "aws_db_instance" "vault" {
  identifier             = "secreton-vault"
  engine                 = "postgres"
  engine_version         = "14.7"
  instance_class         = "db.t3.medium"
  allocated_storage      = 100
  storage_type           = "gp2"
  username               = "secreton"
  password               = var.db_password
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.vault.name
  skip_final_snapshot    = true
}

# EC2 Instances
resource "aws_instance" "vault" {
  count         = 3
  ami           = "ami-0c55b159cbfafe1d0"  # Ubuntu 20.04
  instance_type = "t3.medium"
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.vault.id]
  subnet_id              = aws_subnet.private[count.index].id

  user_data = templatefile("user_data.sh", {
    db_host     = aws_db_instance.vault.address
    db_password = var.db_password
    node_id     = "vault-node-${count.index + 1}"
  })

  tags = {
    Name = "secreton-vault-node-${count.index + 1}"
  }
}

# Load Balancer
resource "aws_lb" "vault" {
  name               = "secreton-vault-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "vault" {
  name     = "secreton-vault-tg"
  port     = 8200
  protocol = "HTTPS"
  vpc_id   = aws_vpc.vault.id

  health_check {
    path                = "/v1/sys/health"
    protocol            = "HTTPS"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "vault" {
  load_balancer_arn = aws_lb.vault.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate.vault.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vault.arn
  }
}
```

#### 2. User Data Script
```bash
#!/bin/bash
# user_data.sh
set -e

# Install dependencies
apt update
apt install -y curl wget git build-essential postgresql-client redis-tools

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Clone and build Secreton
git clone https://github.com/cipherce/secreton.git
cd secreton
cargo build --release

# Create directories
mkdir -p /opt/secreton/{bin,data,logs,config}

# Install binary
cp target/release/secreton /opt/secreton/bin/

# Create configuration
cat > /opt/secreton/config/vault.toml << EOF
[server]
host = "0.0.0.0"
port = 8200

[database]
type = "postgresql"
host = "${db_host}"
database = "secreton"
username = "secreton"
password = "${db_password}"

[storage]
backend = "raft"
data_dir = "/opt/secreton/data"
node_id = "${node_id}"

[cluster]
enabled = true
retry_join = [
  "vault-node1.example.com:8201",
  "vault-node2.example.com:8201",
  "vault-node3.example.com:8201"
]
EOF

# Create systemd service
cat > /etc/systemd/system/secreton.service << EOF
[Unit]
Description=Secreton Enterprise Vault
After=network.target

[Service]
Type=simple
ExecStart=/opt/secreton/bin/secreton server -config /opt/secreton/config/vault.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable secreton
systemctl start secreton
```

### Azure Deployment

#### 1. ARM Template
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vmCount": {
      "type": "int",
      "defaultValue": 3,
      "metadata": {
        "description": "Number of Secreton nodes"
      }
    },
    "vmSize": {
      "type": "string",
      "defaultValue": "Standard_D4s_v3",
      "metadata": {
        "description": "VM size for Secreton nodes"
      }
    }
  },
  "variables": {
    "vnetName": "secreton-vnet",
    "subnetName": "secreton-subnet",
    "nsgName": "secreton-nsg",
    "lbName": "secreton-lb",
    "dbName": "secreton-db"
  },
  "resources": [
    {
      "type": "Microsoft.Network/virtualNetworks",
      "apiVersion": "2021-02-01",
      "name": "[variables('vnetName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "addressSpace": {
          "addressPrefixes": ["10.0.0.0/16"]
        },
        "subnets": [
          {
            "name": "[variables('subnetName')]",
            "properties": {
              "addressPrefix": "10.0.1.0/24"
            }
          }
        ]
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers",
      "apiVersion": "2017-12-01",
      "name": "[variables('dbName')]",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "GP_Gen5_4",
        "tier": "GeneralPurpose",
        "capacity": 4,
        "size": "51200"
      },
      "properties": {
        "version": "14",
        "administratorLogin": "secreton",
        "storageProfile": {
          "storageMB": 51200,
          "backupRetentionDays": 7
        }
      }
    },
    {
      "type": "Microsoft.Network/loadBalancers",
      "apiVersion": "2021-02-01",
      "name": "[variables('lbName')]",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "Standard"
      },
      "properties": {
        "frontendIPConfigurations": [
          {
            "name": "LoadBalancerFrontEnd",
            "properties": {
              "publicIPAddress": {
                "id": "[resourceId('Microsoft.Network/publicIPAddresses', variables('lbName'))]"
              }
            }
          }
        ],
        "backendAddressPools": [
          {
            "name": "BackendPool1"
          }
        ],
        "loadBalancingRules": [
          {
            "name": "LBRule",
            "properties": {
              "frontendIPConfiguration": {
                "id": "[resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', variables('lbName'), 'LoadBalancerFrontEnd')]"
              },
              "backendAddressPool": {
                "id": "[resourceId('Microsoft.Network/loadBalancers/backendAddressPools', variables('lbName'), 'BackendPool1')]"
              },
              "protocol": "Tcp",
              "frontendPort": 8200,
              "backendPort": 8200,
              "enableFloatingIP": false,
              "idleTimeoutInMinutes": 5,
              "probe": {
                "id": "[resourceId('Microsoft.Network/loadBalancers/probes', variables('lbName'), 'tcpProbe')]"
              }
            }
          }
        ],
        "probes": [
          {
            "name": "tcpProbe",
            "properties": {
              "protocol": "Tcp",
              "port": 8200,
              "intervalInSeconds": 5,
              "numberOfProbes": 2
            }
          }
        ]
      }
    }
  ]
}
```

## 🐳 Docker Deployment

### Single Container
```dockerfile
# Dockerfile
FROM rust:1.70-slim as builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/secreton /usr/local/bin/secreton

EXPOSE 8200

CMD ["secreton", "server", "-config", "/etc/secreton/vault.toml"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  secreton:
    build: .
    ports:
      - "8200:8200"
    volumes:
      - ./config:/etc/secreton:ro
      - ./data:/var/lib/secreton
      - ./logs:/var/log/secreton
    environment:
      - SECRETON_CONFIG=/etc/secreton/vault.toml
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8200/v1/sys/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: secreton
      POSTGRES_USER: secreton
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

### Docker Swarm
```yaml
# docker-compose.swarm.yml
version: '3.8'

services:
  secreton:
    image: secreton:latest
    ports:
      - "8200:8200"
    volumes:
      - secreton_data:/var/lib/secreton
      - secreton_logs:/var/log/secreton
    configs:
      - source: vault_config
        target: /etc/secreton/vault.toml
    secrets:
      - db_password
    deploy:
      mode: replicated
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 120s
      healthcheck:
        test: ["CMD", "curl", "-f", "http://localhost:8200/v1/sys/health"]
        interval: 30s
        timeout: 10s
        retries: 3
    networks:
      - secreton_network

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: secreton
      POSTGRES_USER: secreton
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    deploy:
      mode: replicated
      replicas: 1
    networks:
      - secreton_network

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    deploy:
      mode: replicated
      replicas: 1
    networks:
      - secreton_network

configs:
  vault_config:
    file: ./config/vault.toml

secrets:
  db_password:
    file: ./secrets/db_password.txt

networks:
  secreton_network:
    driver: overlay

volumes:
  secreton_data:
  secreton_logs:
  postgres_data:
  redis_data:
```

## 🚀 Kubernetes Deployment

### Prerequisites
- Kubernetes cluster (v1.19+)
- kubectl configured
- Helm 3.x
- cert-manager (optional, for TLS certificates)

### Basic Deployment
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secreton
  labels:
    app: secreton
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secreton
  template:
    metadata:
      labels:
        app: secreton
    spec:
      containers:
      - name: secreton
        image: secreton:latest
        ports:
        - containerPort: 8200
          name: api
        - containerPort: 8201
          name: cluster
        env:
        - name: SECRETON_CONFIG
          value: "/etc/secreton/vault.toml"
        volumeMounts:
        - name: config
          mountPath: /etc/secreton
        - name: data
          mountPath: /var/lib/secreton
        - name: logs
          mountPath: /var/log/secreton
        livenessProbe:
          httpGet:
            path: /v1/sys/health
            port: 8200
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /v1/sys/health
            port: 8200
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: secreton-config
      - name: data
        persistentVolumeClaim:
          claimName: secreton-data
      - name: logs
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: secreton
spec:
  selector:
    app: secreton
  ports:
  - name: api
    port: 8200
    targetPort: 8200
  - name: cluster
    port: 8201
    targetPort: 8201
  type: ClusterIP

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: secreton-config
data:
  vault.toml: |
    [server]
    host = "0.0.0.0"
    port = 8200
    cluster_addr = "https://secreton-0.secreton.default.svc.cluster.local:8201"

    [database]
    type = "postgresql"
    host = "postgres.default.svc.cluster.local"
    database = "secreton"
    username = "secreton"
    password = "secure_password"

    [storage]
    backend = "raft"
    data_dir = "/var/lib/secreton"
    node_id = "secreton-0"

    [cluster]
    enabled = true
    retry_join = [
      "secreton-1.secreton.default.svc.cluster.local:8201",
      "secreton-2.secreton.default.svc.cluster.local:8201"
    ]

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: secreton-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
```

### Ingress Configuration
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secreton-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - vault.example.com
    secretName: secreton-tls
  rules:
  - host: vault.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: secreton
            port:
              number: 8200
```

### Helm Chart
```yaml
# Chart.yaml
apiVersion: v2
name: secreton
description: Secreton Enterprise Vault Helm Chart
type: application
version: 2.1.1
appVersion: "2.1.1"

# values.yaml
replicaCount: 3

image:
  repository: secreton/secreton
  tag: "2.1.1"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8200
  clusterPort: 8201

ingress:
  enabled: true
  className: ""
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: vault.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: secreton-tls
      hosts:
        - vault.example.com

config:
  server:
    host: "0.0.0.0"
    port: 8200
  database:
    type: postgresql
    host: postgres.default.svc.cluster.local
    database: secreton
    username: secreton
  storage:
    backend: raft
    dataDir: /var/lib/secreton

persistence:
  enabled: true
  size: 100Gi
  accessMode: ReadWriteOnce
```

## 🔧 Post-Deployment Configuration

### 1. Initialize Vault
```bash
# Initialize vault
curl -X POST \
  -d '{"secret_shares": 5, "secret_threshold": 3}' \
  https://vault.example.com/v1/sys/init

# Save the response containing unseal keys and root token
```

### 2. Unseal Vault
```bash
# Unseal with threshold number of keys (3 out of 5)
for key in "${unseal_keys[@]:0:3}"; do
  curl -X POST \
    -d "{\"key\": \"$key\"}" \
    https://vault.example.com/v1/sys/unseal
done
```

### 3. Configure Authentication
```bash
# Enable userpass auth method
curl -X POST \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"type": "userpass"}' \
  https://vault.example.com/v1/sys/auth/userpass

# Create admin user
curl -X POST \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{
    "password": "secure-admin-password",
    "policies": ["admin"]
  }' \
  https://vault.example.com/v1/auth/userpass/users/admin
```

### 4. Configure Secrets Engines
```bash
# Enable KV secrets engine
curl -X POST \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"type": "kv", "config": {"version": "2"}}' \
  https://vault.example.com/v1/sys/mounts/secret

# Enable Transit engine
curl -X POST \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{"type": "transit"}' \
  https://vault.example.com/v1/sys/mounts/transit
```

### 5. Configure Policies
```bash
# Create admin policy
curl -X POST \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{
    "policy": "path \"*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}"
  }' \
  https://vault.example.com/v1/sys/policies/acl/admin

# Create developer policy
curl -X POST \
  -H "X-Vault-Token: $ROOT_TOKEN" \
  -d '{
    "policy": "path \"secret/data/dev/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}\n\npath \"transit/encrypt/my-key\" {\n  capabilities = [\"update\"]\n}\n\npath \"transit/decrypt/my-key\" {\n  capabilities = [\"update\"]\n}"
  }' \
  https://vault.example.com/v1/sys/policies/acl/developer
```

## 📊 Monitoring and Health Checks

### Health Check Endpoints
```bash
# Basic health check
curl https://vault.example.com/v1/sys/health

# Detailed health check
curl https://vault.example.com/v1/sys/health?standbyok=true

# Cluster health
curl https://vault.example.com/v1/sys/leader
curl https://vault.example.com/v1/sys/seal-status
```

### Prometheus Metrics
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'secreton'
    static_configs:
      - targets: ['vault.example.com:8200']
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
    tls_config:
      ca_file: /etc/prometheus/certs/ca.crt
      cert_file: /etc/prometheus/certs/client.crt
      key_file: /etc/prometheus/certs/client.key
```

### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Secreton Enterprise Vault",
    "tags": ["secreton", "vault", "security"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_core_handle_request_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(vault_core_handle_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Active Connections",
        "type": "singlestat",
        "targets": [
          {
            "expr": "vault_core_active_connections"
          }
        ]
      }
    ]
  }
}
```

## 🔧 Troubleshooting Deployment Issues

### Common Issues

#### Database Connection Issues
```bash
# Check database connectivity
psql -h localhost -U secreton -d secreton_db

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log

# Verify connection string
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"connection_url": "postgresql://secreton:password@localhost/secreton_db"}' \
  https://vault.example.com/v1/database/config/postgresql
```

#### TLS Certificate Issues
```bash
# Check certificate validity
openssl x509 -in /opt/secreton/certs/server.crt -text -noout

# Test TLS connection
openssl s_client -connect vault.example.com:8200 -servername vault.example.com

# Check certificate chain
openssl verify -CAfile ca.crt -untrusted intermediate.crt server.crt
```

#### Cluster Formation Issues
```bash
# Check cluster status
curl https://vault.example.com/v1/sys/leader

# Check node status
for node in vault-node1 vault-node2 vault-node3; do
  curl https://$node.example.com:8200/v1/sys/health
done

# Check raft logs
tail -f /opt/secreton/logs/secreton.log | grep raft
```

#### Performance Issues
```bash
# Check system resources
top -p $(pgrep secreton)
iostat -x 1
free -h

# Check vault metrics
curl https://vault.example.com/v1/sys/metrics

# Profile performance
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/sys/profiling/start

# Stop profiling after some time
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/sys/profiling/stop
```

## 📚 Additional Resources

### Documentation Links
- [Configuration Guide](../docs/CONFIGURATION_GUIDE.md)
- [Security Hardening](../docs/SECURITY_HARDENING.md)
- [Monitoring Guide](../docs/MONITORING_GUIDE.md)
- [Troubleshooting Guide](../docs/TROUBLESHOOTING.md)

### Community Resources
- [GitHub Repository](https://github.com/cipherce/secreton)
- [Docker Hub](https://hub.docker.com/r/secreton/secreton)
- [Helm Charts](https://artifacthub.io/packages/helm/secreton/secreton)
- [Terraform Modules](https://registry.terraform.io/modules/cipherce/secreton/aws)

### Professional Services
- Enterprise deployment consulting
- Security assessment and hardening
- Performance optimization
- 24/7 support and maintenance

---

**This deployment guide provides comprehensive instructions for deploying Secreton Enterprise Vault in various environments. For production deployments, consider engaging professional services for security review and optimization.**
