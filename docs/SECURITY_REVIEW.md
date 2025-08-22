# Security Review Checklist (Secreton)

- [ ] Semua akses enforce policy & MFA
- [ ] Tidak ada root token statis
- [ ] Secret hanya di memori (RAM) jika memory-only
- [ ] Audit log immutable, SIEM integration
- [ ] Key management: rotasi, tidak expose master key
- [ ] TLS/mTLS aktif di semua endpoint
- [ ] Dependency audit (cargo-audit)
- [ ] Test coverage & static analysis
- [ ] Fuzzing & penetration test
- [ ] Monitoring & alerting aktif

---

**Review checklist ini setiap 3 bulan atau setiap ada perubahan besar.**
