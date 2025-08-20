# Vault Adhyaksa

A secure secrets management system inspired by HashiCorp Vault, built with Rust.

## 🚀 Features

- **Secure Secret Storage**: Encrypt and store secrets using AES-GCM
- **JWT Authentication**: Secure API access with JSON Web Tokens
- **SQLite Storage**: Persistent storage with SQLite database
- **RESTful API**: HTTP API for all operations
- **Vault Initialization**: Shamir Secret Sharing for master key management
- **Seal/Unseal**: Vault can be sealed and unsealed for security

## 🏗️ Architecture

```
vault_adhyaksa/
├── src/
│   ├── core/          # Main server logic
│   ├── storage/       # Database operations
│   ├── auth/          # Authentication & JWT
│   ├── secrets/       # Encryption & secret management
│   ├── api/           # HTTP API endpoints
│   └── utils/         # Utilities & configuration
├── config/            # Configuration files
└── Cargo.toml         # Dependencies
```

## 📦 Installation

### Prerequisites

- Rust 1.70+ 
- SQLite

### Build

```bash
# Clone the repository
git clone <repository-url>
cd vault_adhyaksa

# Build the project
cargo build --release

# Run the application
cargo run
```

## 🔧 Configuration

Create a configuration file at `config/vault.toml`:

```toml
[database]
url = "sqlite:vault.db"

[security]
jwt_secret = "your-super-secret-jwt-key-change-this-in-production"
encryption_key = "your-32-byte-encryption-key-here"

[server]
host = "127.0.0.1"
port = 8080

[logging]
level = "info"
```

## 🚀 Usage

### 1. Start the Server

```bash
cargo run -- --config config/vault.toml --port 8080
```

### 2. Initialize Vault

```bash
curl -X POST http://localhost:8080/v1/sys/init \
  -H "Content-Type: application/json" \
  -d '{
    "secret_shares": 5,
    "secret_threshold": 3
  }'
```

### 3. Unseal Vault

```bash
curl -X POST http://localhost:8080/v1/sys/unseal \
  -H "Content-Type: application/json" \
  -d '{
    "key": "your-unseal-key"
  }'
```

### 4. Authenticate

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'
```

### 5. Store Secrets

```bash
curl -X POST http://localhost:8080/v1/secrets/myapp/database \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "data": {
      "username": "dbuser",
      "password": "dbpass",
      "host": "localhost"
    }
  }'
```

### 6. Retrieve Secrets

```bash
curl -X GET http://localhost:8080/v1/secrets/myapp/database \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🔐 Security Features

### Encryption
- AES-GCM encryption for all secrets
- Random nonce generation for each encryption
- Base64 encoding for storage

### Authentication
- JWT-based authentication
- Token expiration (1 hour default)
- Secure password verification

### Vault Security
- Seal/Unseal mechanism
- Master key management
- Shamir Secret Sharing (simplified)

## 📚 API Reference

### System Endpoints

#### Initialize Vault
```
POST /v1/sys/init
```

#### Unseal Vault
```
POST /v1/sys/unseal
```

### Authentication

#### Login
```
POST /v1/auth/login
```

#### Logout
```
POST /v1/auth/logout
```

### Secrets Management

#### Create Secret
```
POST /v1/secrets/{path}
```

#### Get Secret
```
GET /v1/secrets/{path}
```

#### Update Secret
```
PUT /v1/secrets/{path}
```

#### Delete Secret
```
DELETE /v1/secrets/{path}
```

### Sentinel Policy Versioning

#### Upload Sentinel Policy Version
```
POST /admin/sentinel/{namespace}/policy/{name}
Headers: Authorization: Bearer <token>
Body (JSON):
{
  "policy_type": "egp|rgp|wasm|hcl",
  "source_code": "...",
  "egp": true,
  "rgp": false
}
```

#### List Sentinel Policy Versions
```
GET /admin/sentinel/{namespace}/policy/{name}/versions
Headers: Authorization: Bearer <token>
```

#### Delete Sentinel Policy Version
```
DELETE /admin/sentinel/{namespace}/policy/{name}/version/{version}
Headers: Authorization: Bearer <token>
```

### Health Check

#### Health Status
```
GET /health
```

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_encryption_decryption
```

## 🔧 Development

### Project Structure

- **Core**: Main server logic and routing
- **Storage**: Database operations with SQLite
- **Auth**: JWT authentication and token management
- **Secrets**: Encryption/decryption and secret operations
- **Utils**: Configuration and utility functions

### Adding New Features

1. Create new module in `src/`
2. Add routes in `core/mod.rs`
3. Implement business logic
4. Add tests
5. Update documentation

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## ⚠️ Security Notes

- Change default secrets in production
- Use strong encryption keys
- Secure your JWT secret
- Regularly rotate keys
- Monitor access logs

## 🆘 Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Check SQLite file permissions
   - Verify database URL in config

2. **Encryption Key Error**
   - Ensure encryption key is exactly 32 bytes
   - Use strong random keys

3. **Authentication Failed**
   - Verify JWT secret
   - Check token expiration

4. **Vault Sealed**
   - Initialize vault first
   - Provide correct unseal key

## 📞 Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation
- Review the logs for errors 

# Integrasi Kubernetes dengan vault_adhyaksa

## 1. Webhook Mutating Admission Controller

Endpoint: `/v1/k8s/webhook` (POST)
Digunakan sebagai webhook mutasi untuk inject secret ke pod.

### Contoh YAML MutatingWebhookConfiguration
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: vault-adhyaksa-webhook
webhooks:
  - name: vault.adhyaksa
    clientConfig:
      service:
        name: vault-adhyaksa
        namespace: default
        path: /v1/k8s/webhook
      caBundle: <CA_BUNDLE>
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
    admissionReviewVersions: ["v1"]
    sideEffects: None
```

### Contoh Pod dengan Annotation Inject
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo-pod
  annotations:
    vault.adhyaksa/inject: "true"
spec:
  containers:
    - name: app
      image: busybox
      command: ["sleep", "3600"]
```

Jika annotation di atas ada, maka env `VAULT_SECRET` akan diinject ke container pertama.

## 2. CRD VaultSecret

Definisi CRD dan contoh YAML:
```yaml
apiVersion: vault.adhyaksa/v1
kind: VaultSecret
metadata:
  name: mysecret
spec:
  encrypted_data: <base64>
  public_key: <pem>
```

## 3. Sealed Secrets Endpoint

- `/v1/k8s/sealed/encrypt` (POST)
  - Body: `{ "plaintext": "...", "public_key": "..." }`
  - Response: `{ "encrypted": "..." }`
- `/v1/k8s/sealed/decrypt` (POST)
  - Body: `{ "encrypted": "...", "private_key": "..." }`
  - Response: `{ "plaintext": "..." }`

### Contoh curl
```sh
curl -X POST http://localhost:8000/v1/k8s/sealed/encrypt \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"mysecret","public_key":"dummy_pub"}'

curl -X POST http://localhost:8000/v1/k8s/sealed/decrypt \
  -H 'Content-Type: application/json' \
  -d '{"encrypted":"...","private_key":"dummy_priv"}'
```

## 4. Catatan
- Untuk demo, enkripsi sealed secrets masih dummy (base64), bisa diupgrade ke RSA.
- Patch webhook inject env masih dummy (`VAULT_SECRET`), bisa diintegrasikan ke secret dinamis dari Vault. 

## Plugin Eksternal (Dynamic Library)

### Cara Membuat Plugin Eksternal (Rust)

1. Buat crate Rust baru (type = cdylib):
   ```toml
   [lib]
   crate-type = ["cdylib"]
   ```
2. Implementasikan trait `VaultPlugin` untuk struct plugin Anda.
3. Ekspos fungsi entry point berikut:
   ```rust
   #[no_mangle]
   pub extern "C" fn plugin_entry() -> Box<dyn VaultPlugin> {
       Box::new(MyPlugin::default())
   }
   ```
4. Build: `cargo build --release`
   - Hasil: `target/release/libmy_plugin.so`

### Cara Load Plugin ke Vault Adhyaksa

1. Jalankan server Vault Adhyaksa.
2. Panggil endpoint:
   ```bash
   curl -X POST http://localhost:8000/v1/admin/plugins/load_dynamic \
     -H 'Content-Type: application/json' \
     -d '{"path": "/path/to/libmy_plugin.so"}'
   ```
3. Plugin akan terdaftar dan bisa digunakan sesuai interface-nya.

### Catatan
- Plugin harus kompatibel dengan trait `VaultPlugin` yang ada di Vault Adhyaksa.
- Untuk update/unload plugin, gunakan endpoint `/v1/admin/plugins/reload` dan `/v1/admin/plugins/unload`.
- Untuk keamanan, pastikan hanya plugin tepercaya yang di-load. 