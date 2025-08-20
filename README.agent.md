# Vault Adhyaksa Agent

**Vault Adhyaksa Agent** adalah aplikasi pendamping (helper/sidecar) untuk HashiCorp Vault-like server (`vault_adhyaksa`). Agent ini bertugas melakukan auto-auth, perpanjangan token otomatis, rendering template file dari secret Vault, serta sink token ke file, environment, atau menjalankan aplikasi lain dengan token dinamis. Agent ini sangat cocok untuk DevOps, deployment cloud-native, dan kebutuhan compliance/enterprise.

---

## Perbedaan Vault Agent vs vault_adhyaksa (Server)

| Komponen             | vault_adhyaksa (Server)         | vault_adhyaksa_agent (Agent)         |
|---------------------|----------------------------------|--------------------------------------|
| **Fungsi utama**    | Server utama, API, storage, RBAC | Client/sidecar, auto-auth, template  |
| **Proses**          | Service utama, satu per cluster  | Banyak, satu per aplikasi/VM/Pod     |
| **Akses**           | Menyimpan & mengelola secrets    | Mengambil secrets, tidak menyimpan   |
| **Kegunaan**        | Backend, pusat keamanan          | Otomasi aplikasi, DevOps, CI/CD      |
| **Contoh deploy**   | VM, container, Kubernetes        | Sidecar, VM, container, pipeline     |
| **Auto-auth**       | Tidak (hanya API)                | Ya (userpass, approle, k8s)          |
| **Sink token**      | Tidak                            | Ya (file, env, child process)        |
| **Template**        | Tidak                            | Ya (render file dari secret)         |
| **Failover**        | Cluster/HA internal              | Multi-server fallback                |
| **Reload config**   | API/admin                        | SIGHUP/file watcher (hot reload)     |
| **Audit/Notifikasi**| Internal DB/file                 | File audit, webhook, log file        |

**Singkatnya:**
- `vault_adhyaksa` = server utama, pusat API dan storage secret
- `vault_adhyaksa_agent` = client/sidecar untuk aplikasi, mengambil secret/token dari server, siap untuk DevOps/CI/CD

---

## Kegunaan Vault Agent
- Otomatis login ke Vault dan perpanjang token
- Render file konfigurasi dari secret Vault ke file lokal (template)
- Sink token ke file, .env, atau jalankan aplikasi lain dengan token di environment
- Monitoring, audit, notifikasi event penting (webhook)
- Failover ke server backup jika server utama down
- Hot reload config/template tanpa restart
- Restart child process otomatis jika aplikasi crash
- Siap untuk compliance, DevOps, dan cloud-native

---

## Fitur Utama
- **Auto-auth**: userpass, approle, k8s
- **Token renewal**: otomatis
- **Template rendering**: file dari secret ke file lokal
- **Sink**: file, env, child process
- **Failover server**: multi-server
- **Reload config/template**: SIGHUP (Linux), file watcher (Windows)
- **Monitoring**: HTTP health endpoint (`/healthz`)
- **Notifikasi eksternal**: webhook (Slack, Discord, dsb)
- **Audit**: file audit JSONL
- **Logging**: file/stdout, rotation, format JSON (opsional)
- **Restart child process**: otomatis

---

## Contoh Konfigurasi (`agent.yaml`)
```yaml
server_url: "https://vault1:8200"
server_urls:
  - "https://vault1:8200"
  - "https://vault2:8200"
auth_method: userpass         # atau approle, k8s
auth_config:
  username: "myuser"
  password: "mypassword"
  # Untuk approle:
  # role_id: "..."
  # secret_id: "..."
  # Untuk k8s:
  # jwt_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"
  # role: "myrole"
templates:
  - source: "secret/data/myapp/config"
    dest: "/etc/myapp/config.json"
    mode: "interval"         # atau "one-shot"
interval: 60                 # detik, render ulang setiap 60 detik
sink: "file,env,child"       # bisa kombinasi: file, env, child
log_file: "logs/agent.log"
log_format: "json"           # atau "plain"
audit_file: "logs/audit.log"
run:
  - "bash"
  - "start_myapp.sh"
notify:
  webhook: "https://hooks.slack.com/services/xxx"
restart_child: true
restart_delay: 5             # detik
```

---

## Cara Menjalankan
1. **Build**
   ```sh
   cargo build --release -p vault_adhyaksa_agent
   ```
2. **Jalankan**
   ```sh
   ./target/release/vault_adhyaksa_agent --config agent.yaml
   ```
3. **Reload config/template**
   - **Linux/Unix**:  `kill -HUP <pid>`
   - **Windows**: edit & simpan file `agent.yaml`, agent reload otomatis
4. **Health check**
   - Endpoint: `http://localhost:9900/healthz`
   - Response:
     ```json
     {
       "status": "ok",
       "token_valid": true,
       "child_running": true,
       "last_error": null
     }
     ```

---

## Best Practice
- Jalankan agent sebagai sidecar/launcher aplikasi
- Gunakan sink: child untuk aplikasi yang butuh token dinamis
- Aktifkan audit dan notifikasi untuk compliance dan alerting
- Gunakan health endpoint untuk monitoring otomatis
- Gunakan failover server untuk high-availability

---

## Troubleshooting
- Cek log file (`log_file`) dan audit file (`audit_file`) untuk semua event
- Gunakan health endpoint (`/healthz`) untuk status agent
- Pastikan permission file config, log, dan audit sesuai

---

## Kontribusi & Pengembangan
- Modular, mudah dikembangkan (tambah auth method, sink, dsb)
- Siap diintegrasikan ke pipeline CI/CD, monitoring, dan SIEM

---

**Vault Agent = Otomasi, keamanan, dan DevOps Vault Anda!** 