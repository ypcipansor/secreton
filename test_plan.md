I need to address several bugs in the PR:

1. **Bug 1, 3, 4:** Backup handlers lack admin role authorization checks. I tried to fix this before but somehow the commit didn't include the right code or it was lost. I need to add `if !user.is_superuser && !user.roles.contains(&"admin".to_string()) && !user.roles.contains(&"root".to_string())` to all 5 handler functions.
2. **Bug 2:** `restore_backup` doesn't verify the SHA-256 checksum before restoring. I need to add checksum validation logic in `restore_backup` inside `AdminService`.
3. **Bug 5:** `.filter(|e| !e.path.starts_with("backups/"))` is scattered or incomplete. Actually, wait. I added it to `create_backup` but apparently not correctly or maybe it is redundantly in other places? Let me check where this filter is. Wait, the reviewer says "Several AdminService methods now add .filter...". I only added it to `create_backup`. Let me check `crates/api/src/services/admin.rs`.
