# Authentication Consolidation Plan

## Goal
Consolidate all authentication functionality into `crates/auth-methods` and deprecate `crates/auth`.

## Current State

### `crates/auth/` (To be deprecated)
- `authentication/` - Auth method implementations (duplicates auth-methods)
- `agent_auth.rs` - Agent authentication
- `agent_templating.rs` - Agent templates
- `identity.rs` - Identity management
- `mfa.rs` - MFA implementation
- `revocation/` - Token/cert revocation
- `token.rs` - Token management

### `crates/auth-methods/` (Keep and enhance)
- `method/` - Auth method implementations (cleaner design)
- `agent/` - Agent authentication (already present)
- `identity/` - Identity management (already present)
- `mfa/` - MFA implementation (already present)
- `revocation/` - Revocation management (already present)
- `token/` - Token management (already present)
- `service.rs` - Orchestration service

## Migration Steps

### 1. Content Analysis ✅ COMPLETE
- Identified overlapping modules
- Found unique content in auth crate:
  - `authentication/advanced_mfa.rs` - FIDO2/WebAuthn
  - `authentication/rbac.rs` - Should move to security/policies
  - `authentication/authenticated_key_operations.rs` - Crypto integration

### 2. Migrate Unique Features
- [ ] Move `advanced_mfa.rs` content to `auth-methods/src/mfa/`
  - Add FIDO2 support
  - Add WebAuthn support
  - Add Push notification support
  - Add Biometric support
  
- [ ] Move `authenticated_key_operations.rs` to appropriate location
  - Likely belongs in crypto crate or as auth-methods feature

- [ ] Move RBAC functionality to `security/policies` crate
  - `authentication/rbac.rs` → `security/src/policies/rbac.rs`

### 3. Update Dependencies
- [ ] Update `crates/core/Cargo.toml` to use only `auth-methods`
- [ ] Update `crates/security/Cargo.toml` (already commented out)
- [ ] Add migration guide in CHANGELOG

### 4. Remove Old Crate
- [ ] Archive `crates/auth/` directory
- [ ] Remove from workspace members
- [ ] Update documentation

## Compatibility Strategy

To ensure smooth transition:
1. Keep both crates temporarily with deprecation warnings
2. Add re-exports in `auth` that point to `auth-methods`
3. Update internal usage first
4. Provide migration period before removal

## Benefits

- **Single Source of Truth**: All auth in one place
- **Better Organization**: auth-methods has cleaner module structure
- **Reduced Maintenance**: Only one codebase to maintain
- **Clearer Dependencies**: Simpler dependency graph
- **Better Testing**: Consolidated test suite

## Timeline

- Phase 1: Migrate unique features (1-2 days)
- Phase 2: Update dependencies (1 day)
- Phase 3: Deprecation warnings (1 day)
- Phase 4: Remove old crate (after migration period)
