# Model Data

**Versi:** 2.0
**Terakhir diperbarui:** 2026-09-21
**Referensi:** [01-spesifikasi-teknis.md](01-spesifikasi-teknis.md), [02-model-aplikasi.md](02-model-aplikasi.md)
**Status:** sesuai dengan tipe Rust yang benar-benar ada

> Versi 1.0 dokumen ini memuat DDL PostgreSQL lengkap untuk tabel `users`, `secret_entries`,
> dan `audit_logs`, beserta riwayat enam migrasi. Tidak ada DDL itu di repositori ini, dan
> tidak ada file migrasi. Dokumen ini menggambarkan entitas seperti yang benar-benar
> didefinisikan — sebagai struct Rust yang diserialisasi ke backend yang dipilih.

---

## 1. Cara Data Sebenarnya Disimpan

Secreton tidak memiliki skema relasional tetap. Yang ada adalah **satu trait storage** dan
beberapa backend yang mengimplementasikannya:

```rust
pub trait StorageBackend: std::fmt::Debug + Send + Sync {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()>;
    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>>;
    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>>;
    async fn update(&self, entry: &SecretEntry) -> StorageResult<()>;
    async fn delete_by_path(&self, path: &str) -> StorageResult<bool>;
    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>>;
    async fn count(&self, params: &QueryParams) -> StorageResult<u64>;
    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>>;
    async fn health_check(&self) -> StorageResult<HealthStatus>;
    async fn get_stats(&self) -> StorageResult<StorageStats>;
    async fn migrate(&self) -> StorageResult<()>;
    // ...
}
```

Konsekuensinya untuk pembaca dokumen ini:

- **Tidak ada SQL yang bisa dibaca sebagai "skema".** Backend PostgreSQL menyimpan tipe
  Rust ini; struct-nya adalah definisi skema.
- **Tidak ada riwayat migrasi bernomor.** `migrate()` adalah method pada trait, dipanggil
  oleh `Services::start()`; ia membuat apa yang dibutuhkan backend, bukan menjalankan
  daftar migrasi berversi.
- **Tidak ada transaksi yang diam-diam hilang.** Backend in-memory sebelumnya mengembalikan
  transaksi yang `store`/`update`/`delete`-nya adalah no-op `Ok(())`, sehingga pemanggil
  yang melakukan commit diberi tahu bahwa operasinya berhasil. Sekarang ada test
  `rolled_back_transaction_writes_are_discarded`: apa yang ditulis di dalam transaksi yang
  di-rollback harus tidak terlihat.

---

## 2. Entitas

### 2.1 Ringkasan

| Entitas | Sumber | Peran |
|---------|--------|-------|
| `SecretEntry` | `crates/storage/src/lib.rs` | Unit penyimpanan inti |
| `User` | `crates/auth/src/model.rs` | Akun dan identitas |
| `Policy` | `crates/auth/src/policies/model.rs` | Aturan akses sebagai kode |
| `Token` | `crates/auth/src/token/core.rs` | Token yang diterbitkan |
| `AuditEvent` | `crates/domain/src/audit.rs` | Jejak peristiwa keamanan |
| `OAuthState` | `crates/domain/src/models/oauth_state.rs` | State OIDC jangka pendek |
| `SecurityLevel` | `crates/domain/src/security.rs` | Klasifikasi keamanan |

Semua entitas ini adalah nilai Rust biasa dengan `Serialize`/`Deserialize`. Tidak ada tabel
`roles` atau `permissions` terpisah seperti pada versi 1.0: role dan permission adalah
`Vec<String>` di dalam `User`.

### 2.2 SecretEntry

`crates/storage/src/lib.rs`

| Field | Tipe | Keterangan |
|-------|------|------------|
| `id` | `Uuid` | Identifier unik |
| `path` | `String` | Path hierarkis, mis. `secret/myapp/db` |
| `encrypted_data` | `Vec<u8>` | Payload terenkripsi (barrier) |
| `encryption_metadata` | `EncryptionMetadata` | Info kunci, nonce, auth tag |
| `security_level` | `SecurityLevel` | Klasifikasi |
| `metadata` | `HashMap<String, String>` | Metadata tambahan |
| `tags` | `Vec<String>` | Kategorisasi dan pencarian |
| `version` | `u32` | Nomor versi KV v2 |
| `owner_id` | `Uuid` | Pemilik |
| `created_at` | `DateTime<Utc>` | Waktu pembuatan |
| `updated_at` | `DateTime<Utc>` | Waktu perubahan terakhir |
| `expires_at` | `Option<DateTime<Utc>>` | Kedaluwarsa opsional |

Catatan penting: `encrypted_data` adalah `Vec<u8>` (blob), bukan teks terenkripsi yang bisa
dibaca. Konversi ke dan dari plaintext hanya terjadi di dalam barrier kriptografi.

### 2.3 User

`crates/auth/src/model.rs`

| Field | Tipe | Keterangan |
|-------|------|------------|
| `id` | `String` | Identifier (bukan `Uuid` seperti pada entitas lain) |
| `username` | `String` | Login |
| `email` | `Option<String>` | Opsional |
| `display_name` / `full_name` | `Option<String>` | Nama tampilan |
| `roles` | `Vec<String>` | Role yang dimiliki |
| `permissions` | `Vec<String>` | Permission eksplisit |
| `policies` | `Vec<String>` | Policy yang melekat |
| `metadata` | `HashMap<String, String>` | Metadata |
| `password_hash` | `String` | Hash Argon2id; kosong untuk bootstrap root |
| `password_login_disabled` | `bool` | `true` hanya untuk bootstrap root (default `false` untuk record lama) |
| `mfa_enabled` | `bool` | Status MFA |
| `mfa_secret` | `Option<String>` | Rahasia TOTP |
| `disabled`, `enabled`, `is_active` | `bool` | Flag status |
| `is_superuser` | `bool` | Superuser |
| `failed_login_attempts` | `u32` | Penghitung percobaan gagal |
| `locked_until` | `Option<DateTime<Utc>>` | Akun terkunci sampai waktu ini |
| `created_at`, `updated_at` | `DateTime<Utc>` | Timestamp |
| `last_login` | `Option<DateTime<Utc>>` | Login terakhir |

Root tidak memiliki login password. `init` menerima `root_username` dan membuat akun root
dengan nama tersebut; identitasnya disimpan agar `unseal` menerbitkan token untuk akun itu,
bukan untuk nama tetap `"root"`. Token tersebut berlaku satu jam (TTL bootstrap tetap, tidak
mengikuti session timeout yang dapat dikonfigurasi), dan hanya setelah threshold share
tercapai. Jika penerbitan token gagal setelah barrier terbuka, ulangi panggilan `unseal`
selama proses belum restart; vault tetap terbuka di memori dan tidak perlu share lagi.
Retry ini tidak bertahan melewati restart: root key hanya ada di memori, sehingga setelah
restart vault harus di-unseal kembali dengan share-nya.

`init` bersifat bertahap (staged). Sebuah marker di `sys/init_staging` ditulis sebelum
artefak durabel pertama (`sys/init`, `sys/root_key_enc`, `sys/root_identity`, akun root dan
enrollment TOTP) dan dihapus paling akhir. Selama marker ada, vault dianggap belum
terinisialisasi: `is_initialized()` mengembalikan false walaupun `sys/init` sudah tertulis.
Jika salah satu langkah gagal, `init` menghapus state parsial itu dan mengembalikan error
aslinya, sehingga pemanggilan `init` berikutnya berhasil tanpa restart atau pembersihan
manual — shares tidak pernah diterima operator pada percobaan yang gagal, jadi state
setengah jadi tidak boleh terlihat permanen. Marker tidak menyimpan share, token, password,
JWT secret, atau root key; ia hanya mencatat nama akun root dan id entitas untuk menemukan
record TOTP yang perlu dibersihkan.

Marker dihapus paling akhir dan hanya jika seluruh artefak wajib benar-benar terhapus.
Selama satu delete gagal, marker tetap ada dan `init` mengembalikan error, sehingga percobaan
berikutnya mengulang pembersihan yang sama. Path yang tidak ada dihitung sukses (idempoten);
vault yang sudah committed tidak pernah dihapus artefaknya. Penulisan marker memakai operasi
upsert, bukan insert, karena `init` menulisnya beberapa kali: PostgreSQL menolak insert kedua
ke `path` yang sama pada constraint `UNIQUE`, sedangkan backend memory menerimanya.

Inisialisasi diserialkan dalam satu proses oleh sebuah async mutex yang dipegang untuk
seluruh urutan (recovery, guard `is_initialized`, staging, penulisan, commit, penghapusan
marker, dan cleanup). Dua pemanggilan `init` yang bersamaan karenanya menghasilkan tepat satu
pemenang; pemanggilan lainnya ditolak dengan aman. Batas ini berlaku per proses — untuk
backend yang dipakai bersama, dua proses berbeda tidak diserialkan oleh trait storage saat ini
dan masing-masing harus melakukan inisialisasi secara terkoordinasi.

Vault yang dibuat sebelum `sys/root_identity` ada tetap dapat dipakai. Setelah barrier
terbuka, jika tidak ada record identitas, `unseal` mencari akun legacy bernama `root`,
memverifikasi bahwa akun itu benar-benar ada dan privileged, menandainya
non-password-authenticatable, lalu mem-persist identitas tersebut agar permintaan berikutnya
tidak bergantung pada fallback. Record identitas yang corrupt atau error storage dilaporkan
sebagai error dan tidak pernah berubah menjadi fallback ke akun lain.

Lockout: setelah 5 percobaan gagal, akun non-privileged dikunci selama 15 menit
(`crates/engines/src/services/auth.rs`). Akun privileged sengaja tidak dikunci dengan cara
ini, agar serangan denial-of-service tidak dapat mengunci keluar administrator.

### 2.4 Policy

`crates/auth/src/policies/model.rs`

| Field | Tipe |
|-------|------|
| `id` | `Uuid` |
| `name` | `String` |
| `policy_type` | `PolicyType` |
| `effect` | `PolicyEffect` (allow/deny) |
| `rules` | `Vec<PolicyRule>` |
| `metadata` | `HashMap<String, String>` |
| `created_at`, `updated_at` | `DateTime<Utc>` |

`PolicyRule` diparse oleh grammar Pest di `policies/policy_grammar.pest` — policy adalah
bahasa tersendiri, bukan string yang dicocokkan.

### 2.5 Token

`crates/auth/src/token/core.rs`

| Field | Tipe | Keterangan |
|-------|------|------------|
| `id` | `Uuid` | Identifier |
| `accessor` | `String` | Accessor untuk revoke tanpa mengekspos token |
| `entity_id` | `Option<Uuid>` | Entitas pemilik |
| `token_type` | `TokenType` | Jenis token |
| `policies` | `Vec<String>` | Policy yang berlaku |
| `creation_time`, `expiry_time` | `DateTime<Utc>`, `Option<…>` | Masa berlaku |
| `last_renewal_time` | `Option<DateTime<Utc>>` | Renewal terakhir |
| `status` | `TokenStatus` | Status |
| `renewable` | `bool` | Dapat diperbarui |
| `explicit_max_ttl` | `Option<Duration>` | Batas atas |
| `num_uses`, `remaining_uses` | `Option<u32>` | Kuota pemakaian |

Token disimpan berdasarkan accessor, sehingga revocation tidak memerlukan penyimpanan nilai
token itu sendiri.

### 2.6 AuditEvent

`crates/domain/src/audit.rs`

| Field | Tipe | Keterangan |
|-------|------|------------|
| `id` | `Uuid` | Identifier |
| `timestamp` | `DateTime<Utc>` | Waktu kejadian |
| `event_type` | `String` | Nama bertitik, mis. `secret.read`, `auth.login` |
| `actor` | `String` | Pelaku, atau `"anonymous"` untuk percobaan tanpa autentikasi |
| `resource` | `String` | Sumber daya, mis. path secret |
| `action` | `String` | Aksi |
| `outcome` | `AuditOutcome` | Hasil |
| `client_ip` | `Option<String>` | Alamat klien sesuai konfigurasi trusted proxy |
| `request_id` | `Option<String>` | Mengaitkan dengan `x-request-id` pada request asal |
| `metadata` | `HashMap<String, Value>` | Konteks tambahan |

`request_id` adalah yang menghubungkan baris log server dengan entri audit untuk permintaan
yang sama, dan `actor` bernilai `"anonymous"` pada jalur penolakan — jalur yang justru
paling penting untuk tercatat.

### 2.7 SecurityLevel

`crates/domain/src/security.rs`

| Nilai | Angka | Arti |
|-------|------:|------|
| `Public` | 0 | Tanpa kontrol keamanan |
| `Internal` | 1 | Kontrol akses dasar (default) |
| `Confidential` | 2 | Akses terbatas |
| `Secret` | 3 | Sangat terbatas |
| `TopSecret` | 4 | Kontrol maksimum |

Angka ini adalah nilai ordinal, sehingga perbandingan tingkat dapat dilakukan langsung.

---

## 3. Keterhubungan Antar Entitas

```
        ┌──────────┐
        │  User    │
        │          │
        │ roles[]  │◀──┐ (referensi berdasarkan nama, bukan foreign key)
        │ perms[]  │   │
        └────┬─────┘   │
             │         │
             │ owner_id │ policies[]
             ▼         │
     ┌───────────────┐ │   ┌──────────┐
     │ SecretEntry   │ │   │  Policy  │
     │               │ └───│          │
     │ version       │     │ rules[]  │
     │ encrypted_data│     └──────────┘
     └───────┬───────┘
             │
             │ (setiap operasi memancarkan)
             ▼
     ┌───────────────┐        ┌──────────┐
     │  AuditEvent   │        │  Token   │
     │  actor        │        │ accessor │
     │  request_id   │        │ policies │
     └───────────────┘        └──────────┘
```

Tidak ada foreign key yang dipaksakan oleh database. Relasi dinyatakan sebagai identifier
di dalam nilai, dan integritasnya dijaga oleh service di `secreton-engines`. Backend
in-memory dan file tidak memiliki konsep foreign key sama sekali, jadi mengandalkannya akan
membuat backend tersebut tidak dapat mengimplementasikan trait yang sama.

---

## 4. Aturan Validasi

| Aturan | Di mana |
|--------|---------|
| Password mengikuti `PasswordPolicy` | `crates/domain/src/password.rs`, diterapkan saat pembuatan user |
| Konfigurasi divalidasi saat startup | `ServerConfig::validate()`, sebelum apa pun berjalan |
| Secret JWT minimum 32 byte | `validate()`; proses berhenti jika lebih pendek |
| Origin CORS wildcard ditolak | `validate()` |
| Timeout nol ditolak | `validate()` |
| Transaksi yang di-rollback dibuang | Test `rolled_back_transaction_writes_are_discarded` |
| Bytes cache yang rusak ditolak | Round-trip test `postcard`; bytes yang rusak tidak boleh didekode menjadi entri parsial lalu dikembalikan sebagai cache hit |
| Token hanya HS256 | `Validation::new(Algorithm::HS256)`, dipin oleh `only_hs256_tokens_are_accepted` |

---

## 5. Catatan tentang Versi 1.0 Dokumen Ini

Untuk kejelasan, hal-hal berikut ada di versi 1.0 tetapi **tidak** ada di kode:

- DDL untuk tabel `users`, `secret_entries`, `audit_logs`, `tokens`, `roles`, `permissions`.
- Index (B-Tree, GIN) dan foreign key dengan `ON DELETE CASCADE`.
- Riwayat migrasi 001–006 dengan status "Applied"/"Pending".
- Tabel terpisah untuk `Role` dan `Permission`.
- Enum `user_role` sebagai tipe tertutup dengan nilai `secret_admin`, `key_manager`,
  `crypto_user`, `auditor`, `read_only` — role adalah `Vec<String>` bebas, dan helper seperti
  `is_root()`/`is_admin()` mengenali nama tertentu tapi tidak membatasi daftarnya pada satu
  enum.
- Tipe database `INET` dan `JSONB`.

Jika salah satu dari ini diinginkan, ia harus ditambahkan ke kode terlebih dahulu, lalu
dokumen ini diperbarui.
