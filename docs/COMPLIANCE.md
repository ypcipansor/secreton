# Compliance Mapping: Brankas

## PCI DSS
- Encryption at rest & in transit: AES-GCM, TLS/mTLS
- Access control: RBAC/ABAC, MFA
- Audit log: immutable, append-only, SIEM integration
- Key management: Shamir’s Secret Sharing, envelope encryption

## ISO/IEC 27001
- Policy enforcement: granular, least privilege
- Audit & forensik: log immutable, reviewable
- Secure development: CI/CD security, dependency audit

## NIST SP 800-53
- AC-2, AC-3: Access control, least privilege
- AU-2, AU-6: Audit log, review, alerting
- SC-13, SC-28: Encryption, key management

## OJK/BI (Perbankan Indonesia)
- MFA wajib untuk semua akses sensitif
- Audit log dan monitoring
- Key management dan rotasi

---

**Brankas** sudah memenuhi fitur utama compliance di atas. Untuk audit formal, lakukan review eksternal dan update dokumen ini secara berkala.
