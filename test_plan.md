I need to address 2 bugs mentioned in the PR comments:

**Bug 1: create_backup stores full backup data in metadata field, creating exponential growth risk**
- In `crates/api/src/services/admin.rs:269-300`, `create_backup` fetches all entries, including previous backups. We need to filter out backup entries during creation.
- Specifically, in `create_backup` (around line 269), we can filter the `entries` list before serializing it:
  `let entries: Vec<_> = self.storage.list(&query_params).await?.into_iter().filter(|e| !e.path.starts_with("backups/")).collect();`
- Wait, where exactly is this? Let's check `crates/api/src/services/admin.rs`.

**Bug 2: Backup handlers in admin.rs require AuthenticatedUser but lack admin/root role check**
- In `crates/api/src/handlers/admin.rs`, the new backup endpoints (e.g. `create_backup`, `list_backups`, etc.) need an authorization check to ensure the user is an admin.
- Usually, admin.rs functions check this, like `!user.is_superuser && !user.roles.contains("admin")`.
- Alternatively, maybe the admin router applies an admin-only middleware? If not, we should manually check it inside the handlers, like this:
  ```rust
  if !user.is_superuser && !user.roles.iter().any(|r| r == "admin") {
      return Err(crate::ApiError::Authorization("Admin privileges required".to_string()));
  }
  ```
