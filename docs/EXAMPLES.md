# Secreton by Cipherce - Contoh Penggunaan Lengkap

**Version:** 2.1.1
**Last Updated:** August 28, 2025
**Status:** ✅ Production Ready

## 🚀 Memulai Aplikasi

### 1. Setup Environment

```bash
# Clone repository
git clone https://github.com/cipherce/secreton.git
cd secreton

# Setup PostgreSQL database
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database
sudo -u postgres psql
CREATE DATABASE secreton;
CREATE USER secreton_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE secreton TO secreton_user;
\q

# Setup environment variables
cp .env.example .env
# Edit .env with your database credentials
```

### 2. Build dan Jalankan

```bash
# Build aplikasi
cargo build --release

# Jalankan dengan konfigurasi default
cargo run --release

# Atau jalankan dengan port custom
cargo run --release -- --port 9090

# Development mode dengan auto-reload
cargo watch -x run
```

### 3. Menggunakan Makefile

```bash
# Build production
make build

# Jalankan
make run

# Development dengan hot reload
make dev

# Test lengkap
make test

# Security audit
make audit

# Code quality check
make check
```

## 🔐 Inisialisasi dan Setup Vault

### 1. Initialize Vault dengan Quantum-Safe Keys

```bash
curl -X POST http://localhost:8080/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{
    "secret_shares": 5,
    "secret_threshold": 3,
    "crypto_algorithm": "kyber768",
    "enable_mfa": true
  }'
```

**Response:**
```json
{
  "keys": ["key1", "key2", "key3", "key4", "key5"],
  "root_token": "hvs.root-token-here",
  "crypto_info": {
    "algorithm": "kyber768",
    "security_level": "quantum_safe",
    "key_id": "quantum_key_001"
  }
}
```

### 2. Unseal Vault

```bash
# Unseal dengan 3 dari 5 keys
curl -X POST http://localhost:8080/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "key1"}'

curl -X POST http://localhost:8080/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "key2"}'

curl -X POST http://localhost:8080/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "key3"}'
```

### 3. Setup Multi-Factor Authentication

```bash
# Enable MFA untuk root token
curl -X POST http://localhost:8080/v1/auth/mfa/setup \
  -H "X-Vault-Token: hvs.root-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "totp",
    "issuer": "Secreton",
    "account_name": "admin@company.com"
  }'
```

## 🔑 Operasi Secret Management

### 1. Menyimpan Secret dengan Quantum Encryption

```bash
# Simpan secret database
curl -X POST http://localhost:8080/v1/secret/database/prod \
  -H "X-Vault-Token: hvs.your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "db_admin",
      "password": "super_secret_password",
      "host": "prod-db.company.com",
      "port": "5432",
      "database": "production"
    },
    "metadata": {
      "environment": "production",
      "team": "backend",
      "rotation_schedule": "30d"
    }
  }'
```

### 2. Mengambil Secret

```bash
# Ambil secret
curl -X GET http://localhost:8080/v1/secret/database/prod \
  -H "X-Vault-Token: hvs.your-token"
```

**Response:**
```json
{
  "data": {
    "username": "db_admin",
    "password": "super_secret_password",
    "host": "prod-db.company.com",
    "port": "5432",
    "database": "production"
  },
  "metadata": {
    "created_time": "2025-08-28T10:30:00Z",
    "deletion_time": "",
    "destroyed": false,
    "version": 1,
    "encryption_algorithm": "kyber768"
  }
}
```

### 3. Update Secret dengan Versioning

```bash
# Update password dengan versioning
curl -X POST http://localhost:8080/v1/secret/database/prod \
  -H "X-Vault-Token: hvs.your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "db_admin",
      "password": "new_super_secret_password_2025",
      "host": "prod-db.company.com",
      "port": "5432",
      "database": "production"
    }
  }'
```

### 4. Melihat History Version

```bash
# Lihat semua versi
curl -X GET http://localhost:8080/v1/secret/database/prod?list=true \
  -H "X-Vault-Token: hvs.your-token"
```

## 🔐 Quantum-Safe Encryption Operations

### 1. Encrypt Data dengan Kyber

```bash
# Encrypt data menggunakan quantum-safe algorithm
curl -X POST http://localhost:8080/v1/transit/encrypt/my-key \
  -H "X-Vault-Token: hvs.your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "SGVsbG8gUXVhbnR1bSBXb3JsZA==",  # Base64 encoded "Hello Quantum World"
    "algorithm": "kyber768"
  }'
```

**Response:**
```json
{
  "data": {
    "ciphertext": "vault:v1:quantum:encrypted_data_here",
    "key_version": 1,
    "algorithm": "kyber768",
    "security_level": "quantum_safe"
  }
}
```

### 2. Decrypt Data

```bash
# Decrypt data
curl -X POST http://localhost:8080/v1/transit/decrypt/my-key \
  -H "X-Vault-Token: hvs.your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "vault:v1:quantum:encrypted_data_here"
  }'
```

### 3. Digital Signature dengan Dilithium

```bash
# Buat signature
curl -X POST http://localhost:8080/v1/transit/sign/my-key \
  -H "X-Vault-Token: hvs.your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "SGVsbG8gUXVhbnR1bSBXb3JsZA==",
    "algorithm": "dilithium3",
    "signature_format": "base64"
  }'
```

## 👥 User Management & Access Control

### 1. Membuat User dengan MFA

```bash
# Buat user baru
curl -X POST http://localhost:8080/v1/auth/userpass/users/developer \
  -H "X-Vault-Token: hvs.root-token" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "secure_password_123",
    "policies": ["developer-policy"],
    "mfa_enabled": true,
    "mfa_methods": ["totp", "recovery_codes"]
  }'
```

### 2. Setup Policy RBAC

```bash
# Buat policy untuk developer
curl -X POST http://localhost:8080/v1/sys/policies/acl/developer-policy \
  -H "X-Vault-Token: hvs.root-token" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": "path \"secret/database/*\" { capabilities = [\"read\", \"list\"] }\\npath \"transit/encrypt/*\" { capabilities = [\"update\"] }"
  }'
```

## 📊 Monitoring & Audit

### 1. Melihat Audit Logs

```bash
# Query audit logs
curl -X GET "http://localhost:8080/v1/audit/logs?start_time=2025-08-28T00:00:00Z&limit=100" \
  -H "X-Vault-Token: hvs.admin-token"
```

### 2. System Health Check

```bash
# Health check
curl -X GET http://localhost:8080/v1/sys/health

# Detailed system status
curl -X GET http://localhost:8080/v1/sys/status \
  -H "X-Vault-Token: hvs.admin-token"
```

## 🚀 Advanced Examples

### 1. Batch Operations

```bash
# Batch encrypt multiple values
curl -X POST http://localhost:8080/v1/transit/encrypt/my-key \
  -H "X-Vault-Token: hvs.your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "batch_input": [
      {"plaintext": "SGVsbG8="},
      {"plaintext": "V29ybGQ="},
      {"plaintext": "UXVhbnR1bQ=="}
    ]
  }'
```

### 2. Key Rotation Automation

```bash
# Rotate encryption key
curl -X POST http://localhost:8080/v1/transit/keys/my-key/rotate \
  -H "X-Vault-Token: hvs.admin-token"

# Verify rotation
curl -X GET http://localhost:8080/v1/transit/keys/my-key \
  -H "X-Vault-Token: hvs.admin-token"
```

### 3. Emergency Access Setup

```bash
# Setup emergency access dengan Shamir's Secret Sharing
curl -X POST http://localhost:8080/v1/sys/emergency-access/setup \
  -H "X-Vault-Token: hvs.root-token" \
  -H "Content-Type: application/json" \
  -d '{
    "shares": 7,
    "threshold": 4,
    "description": "Emergency root access for production"
  }'
```

## 🔧 Troubleshooting

### Common Issues

**Database Connection Error:**
```bash
# Check database status
sudo systemctl status postgresql

# Test connection
psql -h localhost -U secreton_user -d secreton
```

**Authentication Failed:**
```bash
# Verify token
curl -X GET http://localhost:8080/v1/auth/token/lookup-self \
  -H "X-Vault-Token: your-token-here"
```

**MFA Setup Issues:**
```bash
# Reset MFA
curl -X POST http://localhost:8080/v1/auth/mfa/reset \
  -H "X-Vault-Token: hvs.admin-token" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "username"}'
```

---

## 📞 Support & Resources

**Documentation Lengkap:**
- [CLI Guide](CLI_GUIDE.md) - Command-line interface
- [API Documentation](docs/API_REFERENCE.md) - REST API reference
- [Security Guide](docs/SECURITY_REVIEW.md) - Security best practices

**Community & Support:**
- GitHub Issues: https://github.com/cipherce/secreton/issues
- Discord: https://discord.gg/cipherce
- Enterprise Support: enterprise@cipherce.com

---

*Contoh ini menggunakan Secreton v2.1.1 dengan fitur quantum-safe cryptography dan zero-trust architecture.*
  "keys_base64": ["a2V5MQ==", "a2V5Mg==", "a2V5Mw==", "a2V5NA==", "a2V5NQ=="],
  "root_token": "hvs.root.token"
}
```

### 2. Unseal Vault

```bash
curl -X POST http://localhost:8080/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{
    "key": "key1"
  }'
```

Response:
```json
{
  "sealed": false,
  "total": 1,
  "threshold": 1,
  "progress": 1
}
```

## 🔑 Autentikasi

### 1. Login

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 3600
}
```

### 2. Logout

```bash
curl -X POST http://localhost:8080/v1/auth/logout \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🔒 Manajemen Secret

### 1. Menyimpan Secret

```bash
curl -X POST http://localhost:8080/v1/secrets/myapp/database \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "data": {
      "username": "dbuser",
      "password": "dbpass123",
      "host": "localhost",
      "port": 5432,
      "database": "myapp"
    }
  }'
```

### 2. Mengambil Secret

```bash
curl -X GET http://localhost:8080/v1/secrets/myapp/database \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response:
```json
{
  "username": "dbuser",
  "password": "dbpass123",
  "host": "localhost",
  "port": 5432,
  "database": "myapp"
}
```

### 3. Update Secret

```bash
curl -X PUT http://localhost:8080/v1/secrets/myapp/database \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "data": {
      "username": "newuser",
      "password": "newpass123",
      "host": "localhost",
      "port": 5432,
      "database": "myapp"
    }
  }'
```

### 4. Hapus Secret

```bash
curl -X DELETE http://localhost:8080/v1/secrets/myapp/database \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🏥 Health Check

### 1. Cek Status Aplikasi

```bash
curl -X GET http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "name": "vault-adhyaksa"
}
```

## 📝 Contoh Script Bash

### 1. Script Inisialisasi Lengkap

```bash
#!/bin/bash

# Inisialisasi Vault
echo "Initializing Vault..."
INIT_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{
    "secret_shares": 5,
    "secret_threshold": 3
  }')

echo "Vault initialized: $INIT_RESPONSE"

# Unseal Vault
echo "Unsealing Vault..."
UNSEAL_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{
    "key": "key1"
  }')

echo "Vault unsealed: $UNSEAL_RESPONSE"

# Login
echo "Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }')

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.token')
echo "Token: $TOKEN"

# Store secret
echo "Storing secret..."
curl -s -X POST http://localhost:8080/v1/secrets/myapp/database \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "data": {
      "username": "dbuser",
      "password": "dbpass123",
      "host": "localhost"
    }
  }'

echo "Secret stored successfully!"
```

### 2. Script untuk Mengambil Secret

```bash
#!/bin/bash

TOKEN="YOUR_TOKEN_HERE"
SECRET_PATH="myapp/database"

# Get secret
SECRET=$(curl -s -X GET http://localhost:8080/v1/secrets/$SECRET_PATH \
  -H "Authorization: Bearer $TOKEN")

echo "Secret: $SECRET"

# Extract specific values
USERNAME=$(echo $SECRET | jq -r '.username')
PASSWORD=$(echo $SECRET | jq -r '.password')
HOST=$(echo $SECRET | jq -r '.host')

echo "Username: $USERNAME"
echo "Password: $PASSWORD"
echo "Host: $HOST"
```

## 🔧 Konfigurasi Environment Variables

```bash
# Set environment variables
export VAULT_DATABASE_URL="sqlite:vault.db"
export VAULT_JWT_SECRET="your-super-secret-jwt-key"
export VAULT_ENCRYPTION_KEY="your-32-byte-encryption-key"
export VAULT_HOST="127.0.0.1"
export VAULT_PORT="8080"
export VAULT_LOG_LEVEL="info"

# Run with environment variables
cargo run
```

## 🧪 Testing

### 1. Test dengan curl

```bash
# Test health endpoint
curl -X GET http://localhost:8080/health

# Test initialization
curl -X POST http://localhost:8080/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{"secret_shares": 3, "secret_threshold": 2}'

# Test unseal
curl -X POST http://localhost:8080/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{"key": "key1"}'

# Test login
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

### 2. Test dengan Python

```python
import requests
import json

BASE_URL = "http://localhost:8080"

# Health check
response = requests.get(f"{BASE_URL}/health")
print("Health:", response.json())

# Initialize vault
init_data = {"secret_shares": 5, "secret_threshold": 3}
response = requests.post(f"{BASE_URL}/v1/sys/init", json=init_data)
print("Init:", response.json())

# Unseal vault
unseal_data = {"key": "key1"}
response = requests.post(f"{BASE_URL}/v1/sys/unseal", json=unseal_data)
print("Unseal:", response.json())

# Login
login_data = {"username": "admin", "password": "admin"}
response = requests.post(f"{BASE_URL}/v1/auth/login", json=login_data)
token = response.json()["token"]
print("Token:", token)

# Store secret
headers = {"Authorization": f"Bearer {token}"}
secret_data = {"data": {"username": "test", "password": "test123"}}
response = requests.post(f"{BASE_URL}/v1/secrets/test/secret", 
                       json=secret_data, headers=headers)
print("Store:", response.status_code)

# Get secret
response = requests.get(f"{BASE_URL}/v1/secrets/test/secret", headers=headers)
print("Get:", response.json())
```

## ⚠️ Troubleshooting

### 1. Server tidak start
```bash
# Cek port
netstat -tlnp | grep 8080

# Cek log
cargo run 2>&1 | tee vault.log

# Cek konfigurasi
cat config/vault.toml
```

### 2. Database error
```bash
# Cek file database
ls -la vault.db

# Reset database
rm vault.db
cargo run
```

### 3. Authentication error
```bash
# Cek token
echo "YOUR_TOKEN" | base64 -d

# Regenerate token
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

## 📊 Monitoring

### 1. Cek Status Server
```bash
# Health check
curl -X GET http://localhost:8080/health

# Cek proses
ps aux | grep vault-adhyaksa

# Cek port
netstat -tlnp | grep 8080
```

### 2. Log Monitoring
```bash
# Set log level
export RUST_LOG=debug
cargo run

# Monitor logs
tail -f vault.log
``` 