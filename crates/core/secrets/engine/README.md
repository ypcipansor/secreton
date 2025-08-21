# MemorySecretsEngine: Zero Trust, Maximum Security, Forever Secret

## Fitur Utama
- **Memory-only**: Secret hanya hidup di RAM, tidak pernah ke disk.
- **TTL & Auto-Expire**: Secret otomatis kadaluarsa dan terhapus.
- **Audit Log Immutable**: Semua operasi (create, read, update, delete) dicatat ke audit log.
- **Policy & MFA Enforcement**: Setiap operasi dicek ke policy engine dan MFA sebelum dijalankan.

## Contoh Penggunaan
Lihat file `memory_example.rs` untuk contoh integrasi lengkap dengan audit log dan policy enforcement.

## Integrasi
- Gunakan `MemorySecretsEngine::with_audit_and_policy(audit_logger, policy_set)` untuk mode zero trust.
- Pastikan context MFA (`{"mfa_passed": true}`) diberikan pada setiap operasi jika policy mewajibkan MFA.

## Best Practice
- Gunakan engine ini untuk secret yang benar-benar sensitif dan tidak boleh pernah bocor ke disk.
- Audit log dapat diintegrasikan ke SIEM/log server untuk compliance dan forensik.
- Policy dapat diatur granular (RBAC/ABAC) sesuai kebutuhan organisasi.

---

**Engine ini dirancang untuk keamanan maksimal dan zero trust, cocok untuk kebutuhan compliance, forensik, dan skenario high-security.**
