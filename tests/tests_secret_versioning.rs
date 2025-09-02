//! Tests for Secret Versioning & Audit Trail

use secret_versioning::*;

#[test]
fn test_put_and_get_secret() {
    let mut history = SecretHistory::new("bank-api-key");
    let v1 = history.put_secret("secret1".to_string(), "alice".to_string(), None, "audit1".to_string());
    let v2 = history.put_secret("secret2".to_string(), "bob".to_string(), Some("changed value".to_string()), "audit2".to_string());
    assert_eq!(history.get_secret(Some(v1)).unwrap().value, "secret1");
    assert_eq!(history.get_secret(Some(v2)).unwrap().value, "secret2");
    assert_eq!(history.list_versions(), vec![1,2]);
}

#[test]
fn test_rollback() {
    let mut history = SecretHistory::new("bank-api-key");
    history.put_secret("secret1".to_string(), "alice".to_string(), None, "audit1".to_string());
    let v2 = history.put_secret("secret2".to_string(), "bob".to_string(), Some("changed value".to_string()), "audit2".to_string());
    let v3 = history.rollback(1, "carol".to_string(), "audit3".to_string()).unwrap();
    assert_eq!(history.get_secret(Some(v3)).unwrap().value, "secret1");
}
