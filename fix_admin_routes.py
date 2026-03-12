import re

with open('crates/api/src/handlers/admin.rs', 'r') as f:
    code = f.read()

# Add backup routes to admin
backup_routes = """
        // Backup operations
        .route("/backups", post(create_backup))
        .route("/backups", get(list_backups))
        .route("/backups/:backup_id", get(get_backup))
        .route("/backups/:backup_id/restore", post(restore_backup))
        .route("/backups/:backup_id", delete(delete_backup))
"""

if "route(\"/backups\"" not in code:
    code = code.replace(".route(\"/maintenance/vacuum\", post(vacuum_database))", ".route(\"/maintenance/vacuum\", post(vacuum_database))" + backup_routes)

with open('crates/api/src/handlers/admin.rs', 'w') as f:
    f.write(code)
