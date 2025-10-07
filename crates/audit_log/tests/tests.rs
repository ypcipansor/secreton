use audit_log::*;

#[test]
fn test_append_and_load_event() {
    let file_path = "/tmp/secreton_audit_test.log";
    let _ = std::fs::remove_file(file_path); // Clean up before test
    let mut log = AuditLog::new(file_path);
    let event = AuditEvent::new(
        "evt-1".to_string(),
        "put_secret".to_string(),
        "alice".to_string(),
        "bank-api-key".to_string(),
        "created new secret".to_string(),
        None,
        "hash1".to_string(),
    );
    log.append_event(event).unwrap();
    let mut log2 = AuditLog::new(file_path);
    log2.load_events().unwrap();
    assert_eq!(log2.events.len(), 1);
    assert_eq!(log2.events[0].event_type, "put_secret");
    let _ = std::fs::remove_file(file_path); // Clean up after test
}
