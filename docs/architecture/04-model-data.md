# Model Data

**Versi:** 1.0
**Tanggal:** December 10, 2025
**Referensi:** 01-spesifikasi-teknis.md, 02-model-aplikasi.md

---

## 1. Overview

Dokumen ini menjelaskan struktur yang menggambarkan bentuk dan keterhubungan informasi (dimensi/entitas) data dalam aplikasi.

---

## 2. Logical Data Model

### 2.1 Daftar Entitas

| No | Nama Entitas | Deskripsi | Domain |
|----|--------------|-----------|--------|
| 1 | User | User accounts dan authentication data | Security |
| 2 | SecretEntry | Encrypted secrets dengan metadata | Secrets |
| 3 | Policy | Access control policies | Authorization |
| 4 | AuditLog | Security event logs | Audit |
| 5 | Token | Authentication tokens | Security |
| 6 | Role | User roles untuk RBAC | Authorization |
| 7 | Permission | Granular permissions | Authorization |

### 2.2 Entity Relationship Diagram
```
┌─────────────────┐       ┌─────────────────┐
│      User       │       │     Policy      │
│                 │       │                 │
│ • id (PK)       │1:N────│ • id (PK)       │
│ • username      │       │ • name          │
│ • email         │       │ • rules         │
│ • role_id (FK)  │       │ • created_at    │
│ • created_at    │       │ • updated_at    │
│ • updated_at    │       └─────────────────┘
└─────────┬───────┘               │
          │                       │
          │1:N                    │1:N
          │                       │
┌─────────▼───────┐       ┌───────▼─────────┐
│  SecretEntry    │       │   AuditLog      │
│                 │       │                 │
│ • id (PK)       │       │ • id (PK)       │
│ • path          │       │ • user_id (FK)  │
│ • encrypted_data│       │ • action        │
│ • owner_id (FK) │       │ • resource      │
│ • version       │       │ • timestamp     │
│ • created_at    │       │ • ip_address    │
│ • updated_at    │       │ • user_agent    │
│ • expires_at    │       └─────────────────┘
└─────────────────┘               ▲
          │                       │
          │1:N                    │1:N
          │                       │
┌─────────▼───────┐       ┌───────▼─────────┐
│     Token       │       │   Permission    │
│                 │       │                 │
│ • id (PK)       │       │ • id (PK)       │
│ • user_id (FK)  │       │ • role_id (FK)  │
│ • token_hash    │       │ • resource      │
│ • expires_at    │       │ • action        │
│ • created_at    │       │ • created_at    │
└─────────────────┘       └─────────────────┘
          ▲
          │
          │1:N
          │
┌─────────▼───────┐
│      Role       │
│                 │
│ • id (PK)       │
│ • name          │
│ • description   │
│ • created_at    │
└─────────────────┘
```

### 2.3 Detail Entitas

#### 2.3.1 User

**Deskripsi:** Representasi user account dalam sistem dengan informasi authentication.

**Atribut:**
| No | Nama Atribut | Deskripsi | Mandatory |
|----|--------------|-----------|-----------|
| 1 | id | Unique identifier (UUID) | Ya |
| 2 | username | Login username | Ya |
| 3 | email | Email address | Ya |
| 4 | password_hash | Hashed password | Ya |
| 5 | role_id | Reference to user role | Ya |
| 6 | mfa_enabled | MFA status flag | Tidak |
| 7 | last_login | Last login timestamp | Tidak |
| 8 | created_at | Account creation time | Ya |
| 9 | updated_at | Last update time | Ya |

**Relasi:**
| Entitas Terkait | Tipe Relasi | Deskripsi |
|-----------------|-------------|-----------|
| Role | N:1 | User belongs to one role |
| SecretEntry | 1:N | User owns multiple secrets |
| Token | 1:N | User has multiple tokens |
| AuditLog | 1:N | User generates audit events |

#### 2.3.2 SecretEntry

**Deskripsi:** Core entity untuk menyimpan encrypted secrets dengan metadata lengkap.

**Atribut:**
| No | Nama Atribut | Deskripsi | Mandatory |
|----|--------------|-----------|-----------|
| 1 | id | Unique identifier (UUID) | Ya |
| 2 | path | Hierarchical path (e.g., secret/myapp/db) | Ya |
| 3 | encrypted_data | AES-256-GCM encrypted data | Ya |
| 4 | encryption_metadata | Key info, IV, auth tag | Ya |
| 5 | owner_id | Reference to owner user | Ya |
| 6 | security_level | Security classification | Ya |
| 7 | version | Version number for updates | Ya |
| 8 | tags | Searchable tags (JSON array) | Tidak |
| 9 | created_at | Creation timestamp | Ya |
| 10 | updated_at | Last update timestamp | Ya |
| 11 | expires_at | Optional expiration time | Tidak |

**Relasi:**
| Entitas Terkait | Tipe Relasi | Deskripsi |
|-----------------|-------------|-----------|
| User | N:1 | Secret owned by one user |
| AuditLog | 1:N | Secret operations logged |

### 2.4 Keterhubungan Antar Entitas

| No | Entitas Asal | Entitas Tujuan | Kardinalitas | Deskripsi |
|----|--------------|----------------|--------------|-----------|
| 1 | User | Role | N:1 | Multiple users can have same role |
| 2 | User | SecretEntry | 1:N | One user can own multiple secrets |
| 3 | User | Token | 1:N | One user can have multiple active tokens |
| 4 | User | AuditLog | 1:N | One user generates multiple audit events |
| 5 | Role | Permission | 1:N | One role grants multiple permissions |
| 6 | Policy | User | N:1 | Policy applies to multiple users |
| 7 | SecretEntry | AuditLog | 1:N | Secret operations create audit trail |

---

## 3. Physical Data Model

### 3.1 Database Schema

**Database:** secreton
**DBMS:** PostgreSQL 15+
**Character Set:** UTF-8

### 3.2 Tabel/Collection Definitions

#### 3.2.1 users

**Deskripsi:** User account information dan authentication data.
**Source:** `crates/auth/src/models.rs`

| No | Kolom | Tipe Data | Constraints | Default | Deskripsi |
|----|-------|-----------|-------------|---------|-----------|
| 1 | id | UUID | PK, NOT NULL | uuid_generate_v4() | Primary key |
| 2 | username | VARCHAR(255) | UNIQUE, NOT NULL | - | Login username |
| 3 | email | VARCHAR(255) | UNIQUE, NOT NULL | - | Email address |
| 4 | password_hash | TEXT | NOT NULL | - | Argon2 hashed password |
| 5 | role_id | UUID | FK(users.id), NOT NULL | - | Reference to roles table |
| 6 | mfa_enabled | BOOLEAN | NOT NULL | false | MFA status |
| 7 | mfa_secret | TEXT | - | - | TOTP secret (encrypted) |
| 8 | last_login | TIMESTAMP | - | - | Last successful login |
| 9 | login_attempts | INTEGER | NOT NULL | 0 | Failed login counter |
| 10 | locked_until | TIMESTAMP | - | - | Account lock timestamp |
| 11 | created_at | TIMESTAMP | NOT NULL | CURRENT_TIMESTAMP | Creation time |
| 12 | updated_at | TIMESTAMP | NOT NULL | CURRENT_TIMESTAMP | Last update |

**Indexes:**
| Nama Index | Kolom | Tipe | Unique |
|------------|-------|------|--------|
| idx_users_username | username | B-Tree | Ya |
| idx_users_email | email | B-Tree | Ya |
| idx_users_role_id | role_id | B-Tree | Tidak |
| idx_users_created_at | created_at | B-Tree | Tidak |

**Foreign Keys:**
| Kolom | Referensi | On Delete | On Update |
|-------|-----------|-----------|-----------|
| role_id | roles(id) | CASCADE | CASCADE |

#### 3.2.2 secret_entries

**Deskripsi:** Encrypted secrets dengan full metadata.
**Source:** `crates/storage/src/lib.rs`

| No | Kolom | Tipe Data | Constraints | Default | Deskripsi |
|----|-------|-----------|-------------|---------|-----------|
| 1 | id | UUID | PK, NOT NULL | uuid_generate_v4() | Primary key |
| 2 | path | TEXT | NOT NULL | - | Hierarchical path |
| 3 | encrypted_data | BYTEA | NOT NULL | - | Encrypted payload |
| 4 | encryption_metadata | JSONB | NOT NULL | - | Encryption details |
| 5 | owner_id | UUID | FK(users.id), NOT NULL | - | Owner user ID |
| 6 | security_level | VARCHAR(50) | NOT NULL | 'standard' | Security classification |
| 7 | version | INTEGER | NOT NULL | 1 | Version counter |
| 8 | tags | JSONB | - | - | Search tags |
| 9 | metadata | JSONB | - | - | Additional metadata |
| 10 | created_at | TIMESTAMP | NOT NULL | CURRENT_TIMESTAMP | Creation time |
| 11 | updated_at | TIMESTAMP | NOT NULL | CURRENT_TIMESTAMP | Last update |
| 12 | expires_at | TIMESTAMP | - | - | Expiration time |

**Indexes:**
| Nama Index | Kolom | Tipe | Unique |
|------------|-------|------|--------|
| idx_secret_entries_path | path | GIN | Tidak |
| idx_secret_entries_owner_id | owner_id | B-Tree | Tidak |
| idx_secret_entries_created_at | created_at | B-Tree | Tidak |
| idx_secret_entries_expires_at | expires_at | B-Tree | Tidak |
| idx_secret_entries_tags | tags | GIN | Tidak |

**Foreign Keys:**
| Kolom | Referensi | On Delete | On Update |
|-------|-----------|-----------|-----------|
| owner_id | users(id) | CASCADE | CASCADE |

#### 3.2.3 audit_logs

**Deskripsi:** Comprehensive audit trail untuk semua security events.
**Source:** `crates/security/src/audit.rs`

| No | Kolom | Tipe Data | Constraints | Default | Deskripsi |
|----|-------|-----------|-------------|---------|-----------|
| 1 | id | UUID | PK, NOT NULL | uuid_generate_v4() | Primary key |
| 2 | user_id | UUID | FK(users.id) | - | User who performed action |
| 3 | action | VARCHAR(100) | NOT NULL | - | Action performed |
| 4 | resource | TEXT | NOT NULL | - | Resource affected |
| 5 | resource_id | UUID | - | - | Specific resource ID |
| 6 | ip_address | INET | - | - | Client IP address |
| 7 | user_agent | TEXT | - | - | Client user agent |
| 8 | success | BOOLEAN | NOT NULL | true | Action success status |
| 9 | error_message | TEXT | - | - | Error details if failed |
| 10 | metadata | JSONB | - | - | Additional context |
| 11 | timestamp | TIMESTAMP | NOT NULL | CURRENT_TIMESTAMP | Event time |

**Indexes:**
| Nama Index | Kolom | Tipe | Unique |
|------------|-------|------|--------|
| idx_audit_logs_user_id | user_id | B-Tree | Tidak |
| idx_audit_logs_action | action | B-Tree | Tidak |
| idx_audit_logs_timestamp | timestamp | B-Tree | Tidak |
| idx_audit_logs_resource | resource | GIN | Tidak |

**Foreign Keys:**
| Kolom | Referensi | On Delete | On Update |
|-------|-----------|-----------|-----------|
| user_id | users(id) | SET NULL | CASCADE |

### 3.3 Enum/Type Definitions

#### 3.3.1 security_level

**Source:** `crates/core/src/types.rs`

| Value | Deskripsi |
|-------|-----------|
| public | Publicly accessible data |
| internal | Internal system data |
| confidential | Sensitive business data |
| restricted | Highly sensitive data |
| top_secret | Most sensitive data |

#### 3.3.2 user_role

**Source:** `crates/auth/src/lib.rs`

| Value | Deskripsi |
|-------|-----------|
| admin | Full system access |
| secret_admin | Secret management access |
| key_manager | Key management access |
| crypto_user | Cryptography operations |
| auditor | Read-only audit access |
| read_only | Read-only access |

### 3.4 Migration History

| Version | Tanggal | Deskripsi | Status |
|---------|---------|-----------|--------|
| 001 | 2025-01-01 | Initial schema creation | Applied |
| 002 | 2025-02-15 | Add audit logging table | Applied |
| 003 | 2025-03-01 | Add MFA support | Applied |
| 004 | 2025-04-01 | Add secret versioning | Applied |
| 005 | 2025-05-01 | Add policy engine | Applied |
| 006 | 2025-06-01 | Add replication support | Pending |

---

## 4. Data Validation Rules

### 4.1 Business Rules

| No | Rule | Entitas/Kolom | Implementasi |
|----|------|---------------|--------------|
| 1 | Username uniqueness | users.username | UNIQUE constraint |
| 2 | Email format validation | users.email | Application validation |
| 3 | Path hierarchy | secret_entries.path | Application validation |
| 4 | Version increment | secret_entries.version | Trigger function |
| 5 | Token expiration | tokens.expires_at | Background cleanup job |
| 6 | Audit immutability | audit_logs.* | No UPDATE permission |

### 4.2 Constraint Rules

| No | Constraint | Tabel | Kolom | Deskripsi |
|----|------------|-------|-------|-----------|
| 1 | CHECK | users | login_attempts | >= 0 |
| 2 | CHECK | secret_entries | version | > 0 |
| 3 | CHECK | secret_entries | expires_at | > created_at |
| 4 | CHECK | tokens | expires_at | > created_at |
| 5 | UNIQUE | users | (username) | Unique username |
| 6 | UNIQUE | users | (email) | Unique email |</content>
<parameter name="filePath">/home/clouduser/secreton/secreton/docs/architecture/04-model-data.md