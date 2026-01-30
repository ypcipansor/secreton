# Proses Bisnis dan Keamanan Secreton

Dokumen ini menjelaskan alur kerja (workflow) sistem Secreton mulai dari inisialisasi hingga penggunaan operasional, serta menjawab pertanyaan mengenai keamanan dan aksesibilitas data.

## 1. Alur Proses (Business Process Flow)

### Tahap 1: Inisialisasi (`sys/init`)
Proses ini dilakukan pertama kali saat sistem baru dijalankan dan belum memiliki kunci enkripsi utama.
*   **Aktor:** Administrator Awal (Calon Root).
*   **Input:** Menentukan jumlah pecahan kunci (`shares`) dan jumlah minimal pecahan yang dibutuhkan (`threshold`) untuk membuka brankas (vault).
*   **Proses:**
    1.  Sistem menghasilkan Master Key secara acak.
    2.  Master Key dipecah menggunakan **Shamir Secret Sharing** menjadi beberapa bagian (`shares`).
    3.  Sistem mengenkripsi Root Key menggunakan Master Key.
    4.  Sistem membuat user `root` dengan password acak (sehingga login password tidak dimungkinkan).
    5.  Sistem mengaktifkan MFA (TOTP) untuk user `root`.
*   **Output:**
    *   Daftar Shamir Shares (kunci pecahan).
    *   URI/Secret untuk setup TOTP Root.
    *   **Catatan Penting:** Pada tahap ini **Root Token TIDAK muncul**.

### Tahap 2: Unsealing (`sys/unseal`)
Proses membuka brankas (vault) yang terkunci (sealed).
*   **Aktor:** Pemegang Kunci (Key Holders).
*   **Input:** Potongan kunci (shares) dimasukkan satu per satu.
*   **Proses:**
    1.  Setiap kali share dimasukkan, sistem mengecek apakah `threshold` sudah terpenuhi.
    2.  Jika belum, sistem menunggu share berikutnya.
    3.  Jika `threshold` terpenuhi, sistem merekonstruksi Master Key.
    4.  Master Key digunakan untuk mendekripsi Root Key di memori.
*   **Output:**
    *   Jika berhasil terbuka, sistem mengembalikan **Root Token** (JWT) yang berlaku singkat (misal: 1 jam).

### Tahap 3: Login & Operasional
*   **Root:** Login menggunakan **Root Token** yang didapat dari proses Unseal. Root tidak login menggunakan password.
*   **Admin & User Biasa:**
    *   Login melalui endpoint `auth/login` atau antarmuka web.
    *   Memasukkan Username dan Password.
    *   Memasukkan kode OTP (MFA) jika diwajibkan.

---

## 2. Detail Keamanan dan Pertanyaan Spesifik

### Apakah Root Token muncul saat Init?
**Tidak.** Root token tidak dimunculkan saat proses inisialisasi (`init`) demi keamanan. Root token hanya diberikan oleh sistem setelah proses **Unsealing** berhasil diselesaikan. Hal ini memastikan bahwa akses root hanya bisa didapatkan jika pemegang kunci (quorum) menyetujui untuk membuka vault.

### Apakah menggunakan Shamir Secret Sharing?
**Ya.** Sistem menggunakan algoritma Shamir Secret Sharing untuk memecah Master Key menjadi beberapa bagian. Ini mencegah satu orang memiliki kontrol penuh atas kunci enkripsi utama secara fisik/offline.

### Bagaimana penggunaan OTP (MFA)?
Penggunaan OTP diatur berdasarkan peran (role) pengguna:
*   **User Root:** **Wajib.** MFA diaktifkan secara otomatis saat inisialisasi.
*   **User Admin:** **Wajib.** Sistem secara eksplisit mengecek dan menolak login jika user memiliki role `admin` tetapi tidak menyertakan kode MFA yang valid (hard-enforced).
*   **User Biasa:** **Opsional / Tergantung Kebijakan.** Secara default sistem mendukung MFA untuk user biasa, namun tidak diwajibkan secara keras di level kode (kecuali dikonfigurasi lain). Namun, untuk praktik terbaik, MFA sangat disarankan.

### Isolasi Data (Visibility)
Apakah user bisa melihat secret milik orang lain?
*   **User Root & Admin:**
    *   Memiliki hak akses **Superuser**.
    *   Bisa melihat, mengubah, dan menghapus **semua** secret di dalam sistem, terlepas dari siapa pembuatnya.
    *   Digunakan untuk manajemen darurat atau audit.
*   **User Biasa:**
    *   **Terisolasi Penuh.**
    *   Secara default, user biasa hanya bisa melihat secret yang `owner_id`-nya adalah milik mereka sendiri.
    *   Sistem menggunakan pengecekan `check_permission` yang memvalidasi kepemilikan (Ownership) dan kebijakan (Policy/RBAC).
    *   User A **tidak bisa** melihat secret milik User B kecuali ada Policy eksplisit yang mengizinkannya (misal: shared secret untuk tim).

---

## 3. Matriks Kewenangan (Authority Matrix)

| Aksi / Kewenangan | User Root | User Admin | User Biasa |
| :--- | :---: | :---: | :---: |
| **System Init** | Ya | Tidak | Tidak |
| **Unseal Vault** | Ya | Tidak | Tidak |
| **Manage Admins** | Ya | Tidak | Tidak |
| **Manage Users** | Ya | Ya | Tidak |
| **Manage Policies** | Ya | Ya | Tidak |
| **Lihat Semua Secret** | Ya | Ya | Tidak |
| **Buat/Edit Secret Sendiri** | Ya | Ya | Ya |
| **Login via Password** | Tidak (via Token) | Ya | Ya |
| **Wajib MFA** | Ya | Ya | Opsional |
