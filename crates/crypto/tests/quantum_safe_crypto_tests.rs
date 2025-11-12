// Test quantum-safe algorithms using real PQC implementations

use secreton_crypto::quantum_safe_crypto::*;

#[test]
fn test_quantum_safe_algorithms() {
    // Test algorithm detection
    assert!(is_quantum_safe("xmss-sha256"));
    assert!(is_quantum_safe("dilithium3"));
    assert!(is_quantum_safe("falcon-512"));
    assert!(!is_quantum_safe("rsa-2048"));
    assert!(!is_quantum_safe("ecdsa-p256"));
}

#[test]
fn test_xmss_sha256() {
    let algorithm = QuantumSafeAlgorithm::XmssSha256;
    // Ensure data is at least 32 bytes for XMSS signing
    let data = b"this is a test message that is at least 32 bytes long";

    // Test key generation
    let (public_key, private_key) = generate_key_pair(algorithm).unwrap();
    assert!(!public_key.is_empty());
    assert!(!private_key.is_empty());

    // Test signing and verification
    let signature = sign(&private_key, data, algorithm).unwrap();
    assert!(!signature.is_empty());

    let is_valid = verify(&public_key, data, &signature, algorithm).unwrap();
    assert!(is_valid);
}

#[test]
fn test_dilithium3() {
    let algorithm = QuantumSafeAlgorithm::Dilithium3;
    let data = b"test message for dilithium";

    // Test key generation
    let (public_key, private_key) = generate_key_pair(algorithm).unwrap();
    assert!(!public_key.is_empty());
    assert!(!private_key.is_empty());

    // Test signing and verification
    let signature = sign(&private_key, data, algorithm).unwrap();
    assert!(!signature.is_empty());

    let is_valid = verify(&public_key, data, &signature, algorithm).unwrap();
    assert!(is_valid);

    // Test with tampered data
    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0xFF;
    let is_valid_tampered = verify(&public_key, &tampered_data, &signature, algorithm).unwrap();
    assert!(!is_valid_tampered);
}

#[test]
fn test_falcon512() {
    let algorithm = QuantumSafeAlgorithm::Falcon512;
    let data = b"test message for falcon";

    // Test key generation
    let (public_key, private_key) = generate_key_pair(algorithm).unwrap();
    assert!(!public_key.is_empty());
    assert!(!private_key.is_empty());

    // Test signing and verification
    let signature = sign(&private_key, data, algorithm).unwrap();
    assert!(!signature.is_empty());

    let is_valid = verify(&public_key, data, &signature, algorithm).unwrap();
    assert!(is_valid);
}
