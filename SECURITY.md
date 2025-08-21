# Security & Compliance Checklist (Brankas)

## Zero Trust & Least Privilege
- [x] Semua akses secret enforce policy (RBAC/ABAC) dan MFA
- [x] Tidak ada root token statis, hanya dynamic auth

## Secret Handling
- [x] Memory-only mode (RAM only) tersedia
- [x] Secret terenkripsi (AES-GCM), TTL, auto-expire, versioning
- [x] Master key tidak pernah di-expose ke aplikasi/user

## Audit & Forensik
- [x] Semua operasi secret dicatat ke audit log immutable
- [ ] Audit log dapat diintegrasikan ke SIEM/log server eksternal

## Cryptography
- [x] AES-GCM, Argon2, RSA, dsb, min 256 bit
- [x] Komunikasi antar service wajib TLS/mTLS
- [x] Key management terpisah

## Compliance & Standar
- [x] Policy granular, audit log, MFA, encryption, key rotation, access review, immutable log
- [ ] Dokumentasi dan SOP sesuai PCI DSS, ISO 27001, NIST, OJK/BI

## Operational Security
- [x] CI/CD pipeline: cargo-audit, clippy, test, fmt
- [ ] Fuzzing dan penetration test berkala

## Impossible to Hack
- [x] Zero trust, memory-only, audit immutable, MFA, policy granular
- [ ] Security review eksternal (pentest, audit) dan update rutin

---

**Catatan:**
- Tidak ada sistem yang benar-benar impossible to hack, tapi dengan checklist ini risiko sudah ditekan ke level minimum sesuai standar internasional dan perbankan.
- Lakukan security review eksternal dan update checklist ini secara berkala.
