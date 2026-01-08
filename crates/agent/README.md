# Secreton Agent

**Secreton Agent** adalah aplikasi pendamping (helper/sidecar) untuk Secreton server. Agent ini bertugas melakukan auto-auth, perpanjangan token otomatis, rendering template file dari secret Secreton, serta sink token ke file, environment, atau menjalankan aplikasi lain dengan token dinamis. Agent ini sangat cocok untuk DevOps, deployment cloud-native, dan kebutuhan compliance/enterprise.

## Fitur Utama

- **Auto-Auth**: Otentikasi otomatis ke Secreton menggunakan metode yang dikonfigurasi (seperti Kubernetes Service Account, AppRole, AWS IAM, Azure MSI, dll).
- **Token Lifecycle Management**: Memperbarui token (renew) secara otomatis sebelum kadaluarsa.
- **Templating**: Mengambil secret dari Secreton dan menuliskannya ke file konfigurasi menggunakan template engine (seperti Consul Template).
- **Secret Sinking**: Menulis token atau secret ke lokasi file tertentu (sink) agar bisa dibaca aplikasi.
- **Process Supervisor**: Menjalankan dan mengawasi proses aplikasi utama, menyuntikkan environment variable berisi secret.

## Perbedaan Secreton Agent vs Secreton Server

| Komponen             | Secreton (Server)         | Secreton Agent (Agent)         |
|----------------------|------------------------------------|-----------------------------------------|
| **Fungsi Utama**     | Menyimpan & mengelola secret       | Mengambil secret & mengelola token      |
| **Lokasi**           | Server terpusat / Cluster          | Di node aplikasi / Sidecar container    |
| **Otentikasi**       | Memverifikasi identitas client     | Melakukan login atas nama aplikasi      |
| **Koneksi DB**       | Menyimpan data terenkripsi di DB   | Tidak punya database sendiri            |

Secara sederhana:
- `secreton` = server utama, pusat API dan storage secret
- `secreton_agent` = client/sidecar untuk aplikasi, mengambil secret/token dari server, siap untuk DevOps/CI/CD

## Cara Kerja

1. **Startup**: Agent membaca konfigurasi.
2. **Auth**: Agent melakukan login ke Secreton Server.
3. **Token Maintenance**: Agent menjaga token tetap hidup (renew) di background.
4. **Template Rendering**: Agent menarik secret yang diminta di template, merender ke file tujuan.
5. **Sink**: Agent menulis token ke file sink (jika dikonfigurasi).
6. **Exec**: Agent menjalankan perintah aplikasi (jika mode exec digunakan) dengan environment variable rahasia.

## Struktur Project

Project ini adalah crate Rust `secreton-agent`.

- `src/main.rs`: Entry point.
- `src/config.rs`: Definisi konfigurasi (YAML/TOML/JSON).
- `src/agent.rs`: Logika utama agent loop.
- `src/auth/`: Modul-modul otentikasi (Kubernetes, AppRole, dll).
- `src/sink/`: Modul penulisan token/secret ke file.
- `src/template/`: Modul rendering template.

## Cara Menjalankan

### Persiapan
Pastikan Secreton Server sudah berjalan.

### Build
```bash
cargo build --release -p secreton-agent
```

### Run
```bash
./target/release/secreton-agent --config agent.yaml
```

### Contoh Konfigurasi (agent.yaml)

```yaml
secreton:
  address: "http://localhost:8200"
  tls_skip_verify: true

auto_auth:
  method: "approle"
  config:
    role_id: "uuid-role-id"
    secret_id: "uuid-secret-id"
    remove_secret_id_file_after_reading: false
  sink:
    - type: "file"
      config:
        path: "/tmp/secreton-token"

templates:
  - source: "/etc/myapp/config.tpl"
    destination: "/etc/myapp/config.json"
    contents: |
      {
        "db_password": "{{ with secret "secret/data/db" }}{{ .Data.data.password }}{{ end }}"
      }
```
