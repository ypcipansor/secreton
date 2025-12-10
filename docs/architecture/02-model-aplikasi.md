# Model Aplikasi

**Versi:** 1.0
**Tanggal:** December 10, 2025
**Referensi:** 01-spesifikasi-teknis.md

---

## 1. Overview

### 1.1 Tujuan Dokumen
Dokumen ini menjelaskan keterhubungan aplikasi dengan layanan yang didukung, data yang dihasilkan, infrastruktur yang digunakan, dan penerapan keamanan.

### 1.2 Scope
Arsitektur aplikasi Secreton sebagai sistem manajemen secrets dengan zero-trust principles, termasuk semua komponen internal dan integrasi eksternal.

---

## 2. Keterhubungan dengan Layanan

### 2.1 Diagram Konteks
```
┌─────────────────────────────────────────────────────────────┐
│                    External Systems                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Clients   │  │  Services  │  │  Identity Providers │  │
│  │             │  │            │  │                     │  │
│  │ • CLI Tool  │  │ • AWS      │  │ • LDAP/AD          │  │
│  │ • Web UI    │  │ • GCP      │  │ • OAuth2 Providers  │  │
│  │ • REST API  │  │ • K8s      │  │ • RADIUS            │  │
│  │ • Agent     │  │ • Docker   │  │ • MFA Systems       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Secreton System                          │
│  ┌─────────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   API Layer     │  │   Core      │  │  Storage Layer  │  │
│  │                 │  │  Services   │  │                 │  │
│  │ • REST/HTTP     │◄─┤             │◄─┤ • PostgreSQL    │  │
│  │ • gRPC          │  │ • Auth      │  │ • Redis Cache   │  │
│  │ • GraphQL       │  │ • Crypto    │  │ • File Storage  │  │
│  │ • WebSocket     │  │ • Audit     │  │ • Raft          │  │
│  └─────────────────┘  └─────────────┘  └─────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                 Data & Monitoring                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Databases  │  │ Monitoring  │  │     Security        │  │
│  │             │  │             │  │                     │  │
│  │ • Secrets   │  │ • Prometheus│  │ • Audit Logs       │  │
│  │ • Users     │  │ • Grafana   │  │ • Security Events   │  │
│  │ • Policies  │  │ • Metrics   │  │ • Compliance       │  │
│  │ • Tokens    │  │ • Tracing   │  │ • Access Control    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Layanan yang Didukung
| No | Layanan | Deskripsi | Endpoint/Interface |
|----|---------|-----------|-------------------|
| 1 | REST API | Full-featured HTTP API | http://localhost:8080 |
| 2 | CLI Tool | Command-line interface | secreton-cli |
| 3 | Agent | Sidecar auto-auth agent | secreton-agent |
| 4 | Web UI | Web dashboard (optional) | http://localhost:3000 |
| 5 | gRPC API | High-performance RPC (disabled) | grpc://localhost:9090 |
| 6 | GraphQL API | Flexible query interface (disabled) | http://localhost:8080/graphql |

### 2.3 Integrasi Eksternal
| No | Sistem Eksternal | Tipe Integrasi | Protocol |
|----|------------------|----------------|----------|
| 1 | PostgreSQL | Primary storage backend | TCP/IP |
| 2 | Redis | Cache dan session storage | TCP/IP |
| 3 | LDAP/Active Directory | User authentication | LDAP |
| 4 | OAuth2/OIDC | Identity federation | HTTPS |
| 5 | RADIUS | Network authentication | UDP |
| 6 | AWS IAM/STS | Cloud integration | HTTPS |
| 7 | Kubernetes | Container orchestration | API Server |
| 8 | Prometheus | Metrics collection | HTTP |
| 9 | Grafana | Dashboard visualization | HTTP |

---

## 3. Data yang Dihasilkan

### 3.1 Kategori Data
| Kategori | Deskripsi | Sensitivitas |
|----------|-----------|--------------|
| Secrets | Encrypted sensitive data | High |
| User Credentials | Authentication tokens | High |
| Audit Logs | Security event logs | Medium |
| Configuration | System settings | Medium |
| Metrics | Performance data | Low |
| Policies | Access control rules | Medium |

### 3.2 Aliran Data
```
Input Sources
      │
      ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│   API       │────▶│  Auth      │
│  Request    │     │  Gateway    │     │  Service   │
└─────────────┘     └─────────────┘     └─────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Encryption  │     │ Validation  │     │  Audit     │
│  Service    │     │             │     │  Logging   │
└─────────────┘     └─────────────┘     └─────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Storage   │     │   Cache     │     │ Monitoring │
│   Backend   │     │   Layer     │     │   System   │
└─────────────┘     └─────────────┘     └─────────────┘
```

### 3.3 Data Storage
| Tipe Data | Storage | Retensi | Backup |
|-----------|---------|---------|--------|
| Secrets | PostgreSQL + Encryption | Unlimited | Daily |
| Audit Logs | PostgreSQL | 7 years | Weekly |
| User Data | PostgreSQL | Account lifetime | Daily |
| Metrics | Prometheus TSDB | 30 days | None |
| Cache | Redis | TTL-based | None |

---

## 4. Infrastruktur yang Digunakan

### 4.1 Komponen Infrastruktur
| Komponen | Teknologi | Fungsi |
|----------|-----------|--------|
| Application Server | Rust + Axum | Main API server |
| Database | PostgreSQL 15+ | Primary data storage |
| Cache | Redis 7+ | Session dan data caching |
| Reverse Proxy | Nginx | Load balancing dan SSL termination |
| Monitoring | Prometheus + Grafana | Metrics dan visualization |
| Container Runtime | Docker | Application containerization |
| Orchestration | Docker Compose | Multi-service management |

### 4.2 Deployment Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer (Nginx)                    │
│                           │                                 │
│                    ┌──────▼──────┐                          │
│                    │             │                          │
│                    │  Secreton   │                          │
│                    │   API       │                          │
│                    │  Server     │                          │
│                    └──────┬──────┘                          │
│                           │                                 │
│              ┌────────────▼────────────┐                    │
│              │                         │                    │
│         ┌────▼────┐              ┌────▼────┐                │
│         │  Auth   │              │ Crypto  │                │
│         │ Service │              │ Service │                │
│         └─────────┘              └─────────┘                │
│              │                         │                    │
│              └────────────┬────────────┘                    │
│                           │                                 │
│                    ┌──────▼──────┐                          │
│                    │             │                          │
│                    │  Storage    │                          │
│                    │   Layer     │                          │
│                    └──────┬──────┘                          │
│                           │                                 │
│              ┌────────────▼────────────┐                    │
│              │                         │                    │
│         ┌────▼────┐              ┌────▼────┐                │
│         │   DB    │              │  Cache  │                │
│         │(PostgreSQL)│           │ (Redis) │                │
│         └─────────┘              └─────────┘                │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Penerapan Keamanan

### 5.1 Authentication
| Metode | Implementasi | Modul |
|--------|--------------|-------|
| JWT Tokens | Bearer token dengan TTL | secreton-auth |
| OAuth 2.0 / OIDC | Integration dengan Google, GitHub, Okta | secreton-auth |
| LDAP | Active Directory dan OpenLDAP | secreton-auth |
| RADIUS | Network authentication | secreton-auth |
| Multi-Factor Authentication | TOTP, hardware tokens (U2F/FIDO2) | secreton-auth |

### 5.2 Authorization
| Model | Implementasi | Detail |
|-------|--------------|--------|
| Role-Based Access Control | Fine-grained permissions | Admin, SecretAdmin, KeyManager, etc. |
| Policy as Code | Declarative access policies | HCL-based policy language |
| Dynamic Secrets | Just-in-time credential generation | Auto-expiring credentials |
| Token Hierarchy | Parent/child token relationships | Token delegation |
| Granular Revocation | Individual token revocation | Immediate access removal |

### 5.3 Enkripsi
| Tipe | Algorithm | Penggunaan |
|------|-----------|------------|
| At Rest | AES-256-GCM, ChaCha20-Poly1305 | Secret data encryption |
| In Transit | TLS 1.2/1.3 | API communication |
| Key Derivation | PBKDF2, Argon2 | Password hashing |
| Hardware Security | HSM integration | Enterprise key storage |

### 5.4 Audit & Logging
| Tipe Log | Format | Retention |
|----------|--------|-----------|
| Security Events | Structured JSON | 7 years |
| API Access | HTTP logs | 90 days |
| Authentication | Auth events | 1 year |
| System Metrics | Prometheus format | 30 days |
| Error Logs | Structured logs | 30 days |

### 5.5 Secrets Management
| Tipe Secret | Metode | Tool |
|-------------|--------|------|
| API Keys | Encrypted storage | secreton-crypto |
| Database Credentials | Dynamic generation | secreton-secrets-database |
| Certificates | PKI engine | secreton-secrets-pki |
| Cloud Credentials | Integration APIs | secreton-integrations |
| SSH Keys | Key management | secreton-crypto |</content>
<parameter name="filePath">/home/clouduser/secreton/secreton/docs/architecture/02-model-aplikasi.md