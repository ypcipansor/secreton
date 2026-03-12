I need to fix two bugs in `crates/api/src/services/admin.rs`:
1. Checksum verification in `restore_backup`. The reviewer mentioned I missed this.
2. Filter out "data" key from metadata in `get_backup` and `list_backups` to avoid returning the entire backup payload in list/get responses.
