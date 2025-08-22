# Secreton by Cipherce - Contoh Penggunaan

## 🚀 Memulai Aplikasi

### 1. Build dan Jalankan

```bash
# Build aplikasi
cargo build --release

# Jalankan dengan konfigurasi default
cargo run -- --config config/vault.toml --port 8080

# Atau jalankan dengan port custom
cargo run -- --port 9090
```

### 2. Menggunakan Makefile

```bash
# Build
make build

# Jalankan
make run

# Development mode
make dev

# Test
make test
```

## 🔐 Inisialisasi Vault

### 1. Initialize Vault

```bash
curl -X POST http://localhost:8080/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{
    "secret_shares": 5,
    "secret_threshold": 3
  }'
```

Response:
```json
{
  "keys": ["key1", "key2", "key3", "key4", "key5"],
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