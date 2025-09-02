use secreton_crypto::quantum_safe_crypto::*;
use secreton_crypto::error::CryptoError;

#[test]
fn test_quantum_safe_algorithms() {
    // Test algorithm detection
    assert!(is_quantum_safe("xmss-sha256"));
    assert!(is_quantum_safe("dilithium3"));
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
    
    // Test with tampered data
    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 0xFF;
    let is_valid_tampered = verify(&public_key, &tampered_data, &signature, algorithm).unwrap();
    assert!(!is_valid_tampered);
}

#[test]
fn test_unsupported_algorithm() {
    // Test unsupported algorithm handling
    let result = generate_key_pair(QuantumSafeAlgorithm::Dilithium3);
    assert!(matches!(result, Err(CryptoError::KeyGenerationFailed(_))));
    
    let data = b"test";
    let result = sign(&[0u8; 10], data, QuantumSafeAlgorithm::Dilithium3);
    assert!(matches!(result, Err(CryptoError::SigningFailed(_))));
    
    let result = verify(&[0u8; 10], data, &[0u8; 10], QuantumSafeAlgorithm::Dilithium3);
    assert!(matches!(result, Err(CryptoError::VerificationFailed(_))));
}
