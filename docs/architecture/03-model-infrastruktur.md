# Model Infrastruktur

**Versi:** 1.0
**Tanggal:** December 10, 2025
**Referensi:** 01-spesifikasi-teknis.md, 02-model-aplikasi.md

---

## 1. Overview

Dokumen ini menjelaskan kerangka kerja yang mencakup semua komponen teknologi dan sumber daya yang diperlukan untuk mendukung pelaksanaan layanan secara digital.

---

## 2. Model Infrastruktur Pusat Data/Komputasi Awan/Server

### 2.1 Arsitektur Compute

#### 2.1.1 Containerization
| Aspek | Detail |
|-------|--------|
| Container Runtime | Docker |
| Base Image | rust:1.90-slim (build), debian:bookworm-slim (runtime) |
| Registry | Docker Hub (default) |
| Image Size | ~500MB (runtime), ~2GB (build cache) |
| Security | Non-root user, minimal attack surface |

#### 2.1.2 Orchestration
| Aspek | Detail |
|-------|--------|
| Platform | Docker Compose |
| Deployment Strategy | Single-node (development), Rolling update (production) |
| Scaling | Horizontal pod scaling (planned for K8s) |
| Service Discovery | Docker internal networking |
| Configuration | Environment variables, mounted configs |

#### 2.1.3 Server Specifications
| Komponen | Requirement Minimum | Recommended | Production |
|----------|---------------------|-------------|------------|
| CPU | 1 core | 2 cores | 4+ cores |
| Memory | 512MB | 2GB | 8GB+ |
| Storage | 1GB | 10GB | 100GB+ SSD |
| Network | 10Mbps | 100Mbps | 1Gbps |

### 2.2 Diagram Compute Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose Stack                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Nginx (Reverse Proxy)             │    │
│  │  ┌─────────────────────────────────────────────────┐ │    │
│  │  │                                                 │ │    │
│  │  │              Secreton API Server                │ │    │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │ │    │
│  │  │  │   Auth      │  │   Crypto    │  │ Storage │  │ │    │
│  │  │  │  Service    │  │  Service    │  │ Service │  │ │    │
│  │  │  └─────────────┘  └─────────────┘  └─────────┘  │ │    │
│  │  └─────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────┘    │
│           │                        │                        │
│           ▼                        ▼                        ▼
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────┐
│  │   PostgreSQL    │     │      Redis      │     │  Prometheus  │
│  │   (Database)    │     │     (Cache)     │     │ (Monitoring) │
│  └─────────────────┘     └─────────────────┘     └─────────────┘
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                        Grafana                              │ │
│  │                 (Dashboard & Visualization)                 │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Model Infrastruktur Jaringan

### 3.1 Topologi Jaringan
```
Internet
    │
    ▼
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Firewall│────▶│  Nginx  │────▶│Secreton │
│ Rules   │     │ Reverse │     │  API    │
│         │     │  Proxy  │     │ Server  │
└─────────┘     └─────────┘     └─────────┘
    │               │               │
    ▼               ▼               ▼
┌─────────┐     ┌─────────┐     ┌─────────┐
│PostgreSQL│     │  Redis  │     │Prometheus│
│ Database │     │  Cache  │     │ Metrics  │
└─────────┘     └─────────┘     └─────────┘
```

### 3.2 Port Configuration
| Service | Port | Protocol | Direction | Description |
|---------|------|----------|-----------|-------------|
| Secreton API | 8080 | TCP | Inbound | HTTP API endpoint |
| Secreton HTTPS | 8443 | TCP | Inbound | HTTPS API endpoint |
| Secreton Metrics | 9090 | TCP | Internal | Prometheus metrics |
| PostgreSQL | 5432 | TCP | Internal | Database connection |
| Redis | 6379 | TCP | Internal | Cache connection |
| Nginx HTTP | 80 | TCP | Inbound | Web interface |
| Nginx HTTPS | 443 | TCP | Inbound | Secure web interface |
| Grafana | 3000 | TCP | Internal | Dashboard access |
| Prometheus | 9091 | TCP | Internal | Metrics access |

### 3.3 Protocol & API
| Protocol | Version | Penggunaan |
|----------|---------|------------|
| HTTP | 1.1/2 | REST API communication |
| HTTPS | TLS 1.2/1.3 | Secure API communication |
| TCP | - | Database dan cache connections |
| UDP | - | DNS resolution (future) |
| WebSocket | - | Real-time notifications (planned) |

### 3.4 Load Balancing
| Aspek | Detail |
|-------|--------|
| Type | L7 (Application Layer) |
| Algorithm | Round Robin |
| Health Check | HTTP /health endpoint |
| Session Affinity | None (stateless API) |
| SSL Termination | Nginx handles TLS |

### 3.5 DNS Configuration
| Record | Type | Value | Purpose |
|--------|------|-------|---------|
| secreton.local | A | 127.0.0.1 | Development access |
| api.secreton.local | CNAME | secreton.local | API endpoint |
| db.secreton.local | A | 127.0.0.1 | Database access |
| monitor.secreton.local | A | 127.0.0.1 | Monitoring access |

---

## 4. Model Infrastruktur Keamanan

### 4.1 Network Security

#### 4.1.1 Firewall Rules
| Rule | Source | Destination | Port | Action | Purpose |
|------|--------|-------------|------|--------|---------|
| ALLOW | Internal | PostgreSQL | 5432 | Accept | Database access |
| ALLOW | Internal | Redis | 6379 | Accept | Cache access |
| ALLOW | Load Balancer | Secreton API | 8080 | Accept | API traffic |
| ALLOW | External | Nginx | 80,443 | Accept | Web access |
| DENY | External | PostgreSQL | 5432 | Drop | Prevent direct DB access |
| DENY | External | Redis | 6379 | Drop | Prevent direct cache access |

#### 4.1.2 TLS/SSL Configuration
| Aspek | Detail |
|-------|--------|
| TLS Version | 1.2, 1.3 |
| Certificate Type | Let's Encrypt (production), Self-signed (dev) |
| Cipher Suites | ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-CHACHA20-POLY1305 |
| HSTS | max-age=31536000; includeSubDomains |
| Certificate Pinning | HPKP header (optional) |

### 4.2 Application Security

#### 4.2.1 Authentication Flow
```
Client Request
      │
      ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Nginx     │────▶│  JWT Auth   │────▶│  RBAC       │
│ (TLS Term)  │     │ Validation  │     │  Check      │
└─────────────┘     └─────────────┘     └─────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Rate Limit  │     │ MFA Check   │     │  Audit Log  │
│             │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ API Handler │     │  Business  │     │  Response   │
│             │     │   Logic     │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
```

#### 4.2.2 Security Headers
| Header | Value | Purpose |
|--------|-------|---------|
| X-Frame-Options | DENY | Prevent clickjacking |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| X-XSS-Protection | 1; mode=block | XSS protection |
| Strict-Transport-Security | max-age=31536000 | Force HTTPS |
| Content-Security-Policy | default-src 'self' | Prevent XSS |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer |

### 4.3 Data Security

#### 4.3.1 Encryption at Rest
| Data Type | Algorithm | Key Management |
|-----------|-----------|----------------|
| Secrets | AES-256-GCM | Envelope encryption |
| User Data | AES-256-GCM | Database-level encryption |
| Audit Logs | AES-256-GCM | Log encryption |
| Configuration | AES-256-GCM | Config file encryption |

#### 4.3.2 Encryption in Transit
| Connection | Protocol | Encryption |
|------------|----------|------------|
| API Calls | HTTPS | TLS 1.3 |
| Database | TLS | PostgreSQL SSL |
| Cache | TLS | Redis TLS |
| Monitoring | HTTPS | TLS 1.2+ |

### 4.4 Security Monitoring
| Aspect | Tool/Method | Alert |
|--------|-------------|-------|
| Network Traffic | Nginx logs | Unusual patterns |
| Authentication | Audit logs | Failed login attempts |
| API Usage | Prometheus | Rate limit violations |
| System Resources | Monitoring | High CPU/memory usage |
| Security Events | SIEM integration | Suspicious activities |</content>
<parameter name="filePath">/home/clouduser/secreton/secreton/docs/architecture/03-model-infrastruktur.md