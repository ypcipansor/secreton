import re

with open('crates/api/src/handlers/secret.rs', 'r') as f:
    code = f.read()

# Remove backup routes
code = re.sub(r'\s*\.route\("/backup", post\(create_backup\)\)', '', code)
code = re.sub(r'\s*\.route\("/backup", get\(list_backups\)\)', '', code)
code = re.sub(r'\s*\.route\("/backup/\{backup_id\}", get\(get_backup\)\)', '', code)
code = re.sub(r'\s*\.route\("/backup/\{backup_id\}/restore", post\(restore_backup\)\)', '', code)
code = re.sub(r'\s*\.route\("/backup/\{backup_id\}", delete\(delete_backup\)\)', '', code)

# Remove the Backup operations from the end
parts = re.split(r"/// Backup operations\n", code)
if len(parts) == 2:
    code = parts[0]

with open('crates/api/src/handlers/secret.rs', 'w') as f:
    f.write(code)
