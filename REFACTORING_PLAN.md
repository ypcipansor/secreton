# Secreton Comprehensive Refactoring Plan

## Identified Issues

### 1. Duplicate Module Structures
- **`crates/storage/src/secrets/`** and **`crates/storage/src/storage_backends/secrets/`** contain identical files
  - cubbyhole.rs, database.rs, kmip.rs, kvv2.rs, pki_engine.rs, ssh.rs, transform.rs, transit.rs
  - Minor differences (underscore prefixes, import changes)
  - **Action**: Consolidate into single location under `crates/storage/src/secrets/`

### 2. Duplicate Secret Dependency Graph
- **`crates/storage/src/storage_backends/secret_dependency_graph.rs`**
- **`crates/integrations/src/integrations/secret_dependency_graph.rs`**
- **Action**: Move to dedicated crate `crates/secret-graph`

### 3. Multiple Implementations of Same Functionality
- Secret operations scattered across:
  - `crates/api/src/handlers/vault.rs`
  - `crates/api/src/services/vault.rs`
  - `crates/api/src/kv.rs`
  - `crates/api/src/transit.rs`
  - `crates/secrets/src/service.rs`
  - `crates/secrets/src/backend/vault.rs`
  - `crates/crypto/src/kv_engine.rs`
  - `crates/storage/src/secrets/`

### 4. Overlapping Concerns Between Crates
- Storage and secrets are mixed
- Core has secret implementations that should be in secrets crate
- Auth functionality split between auth and auth-methods

## Refactoring Strategy

### Phase 1: Eliminate Duplicate Files (Immediate)
1. Remove `crates/storage/src/storage_backends/secrets/` directory
2. Update all imports to use `crates/storage/src/secrets/`
3. Remove `crates/storage/src/storage_backends/secret_dependency_graph.rs`
4. Remove duplicate from integrations

### Phase 2: Create New Specialized Crates
1. **`crates/secret-graph`** - Dependency tracking and impact analysis
2. **`crates/handlers`** - HTTP handlers (extracted from api)
3. **`crates/services`** - Business logic services (extracted from api)

### Phase 3: Consolidate Secret Operations
1. Move all secret engine implementations to `crates/secrets`
2. Ensure single source of truth for each secret type
3. Clean up cross-dependencies

### Phase 4: Improve Separation of Concerns
1. API crate should only contain HTTP layer and routing
2. Services crate contains business logic
3. Handlers crate contains request/response handling
4. Each secret engine in secrets crate

## Implementation Order

1. ✅ Phase 1: Remove duplicate directories (safe, high impact)
2. Phase 2: Extract secret-graph crate
3. Phase 3: Consolidate secret implementations
4. Phase 4: Split api crate into handlers and services
