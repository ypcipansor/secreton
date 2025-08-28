use granular_revocation::*;

#[test]
fn test_revoke_and_check() {
    let mut registry = RevocationRegistry::new();
    let scope = RevocationScope::Secret("api-key-1".to_string());
    registry.revoke(scope.clone(), "compromised".to_string(), "alice".to_string(), "audit-1".to_string());
    assert!(registry.is_revoked(&scope));
    assert_eq!(registry.list_events().len(), 1);
}

#[test]
fn test_multiple_scopes() {
    let mut registry = RevocationRegistry::new();
    let s1 = RevocationScope::Secret("api-key-1".to_string());
    let s2 = RevocationScope::User("bob".to_string());
    registry.revoke(s1.clone(), "rotation".to_string(), "system".to_string(), "audit-2".to_string());
    registry.revoke(s2.clone(), "offboarding".to_string(), "admin".to_string(), "audit-3".to_string());
    assert!(registry.is_revoked(&s1));
    assert!(registry.is_revoked(&s2));
    assert_eq!(registry.list_events().len(), 2);
}
