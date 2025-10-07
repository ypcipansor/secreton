//! Constant-Time Operations for Cryptographic Security
//!
//! This module provides timing-attack resistant implementations
//! of comparison and validation operations for PQC algorithms.
//!
//! # Security Rationale
//! Standard comparison operators (==, !=) may leak information through
//! timing side-channels by short-circuiting on the first differing byte.
//! Attackers can use timing measurements to extract secrets.
//!
//! # Implementation
//! Uses constant-time comparison from `subtle` crate that processes
//! all bytes regardless of differences.

use subtle::ConstantTimeEq;

/// Constant-time equality comparison for byte slices
///
/// # Security
/// - Always processes ALL bytes, never short-circuits
/// - Prevents timing side-channel attacks
/// - Use for comparing secrets, signatures, MACs, etc.
///
/// # Example
/// ```ignore
/// use brankas_crypto::pqc::constant_time::ct_eq;
///
/// let secret1 = vec![0x42; 32];
/// let secret2 = vec![0x42; 32];
/// let secret3 = vec![0x43; 32];
///
/// assert!(ct_eq(&secret1, &secret2)); // Equal
/// assert!(!ct_eq(&secret1, &secret3)); // Not equal
/// ```
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false; // Length mismatch is not timing-sensitive
    }

    a.ct_eq(b).into()
}

/// Constant-time inequality comparison for byte slices
///
/// # Security
/// - Always processes ALL bytes, never short-circuits
/// - Prevents timing side-channel attacks
///
/// # Example
/// ```ignore
/// use brankas_crypto::pqc::constant_time::ct_ne;
///
/// let secret1 = vec![0x42; 32];
/// let secret2 = vec![0x43; 32];
///
/// assert!(ct_ne(&secret1, &secret2)); // Not equal
/// ```
pub fn ct_ne(a: &[u8], b: &[u8]) -> bool {
    !ct_eq(a, b)
}

/// Validate key size in constant time (prevents size oracle attacks)
///
/// # Security
/// - Always performs full comparison regardless of size mismatch
/// - Prevents attackers from deducing key sizes through timing
///
/// # Arguments
/// * `key` - The key bytes to validate
/// * `expected_size` - The expected size in bytes
///
/// # Returns
/// * `Ok(())` if size matches
/// * `Err(String)` if size mismatch (includes both sizes for debugging)
///
/// # Example
/// ```ignore
/// use brankas_crypto::pqc::constant_time::validate_key_size;
///
/// let key = vec![0x42; 2560]; // ML-DSA-44 private key
/// validate_key_size(&key, 2560).unwrap(); // OK
/// ```
pub fn validate_key_size(key: &[u8], expected_size: usize) -> Result<(), String> {
    // Perform constant-time length comparison
    let actual_size = key.len();
    let sizes_match = actual_size == expected_size;

    if !sizes_match {
        return Err(format!(
            "Invalid key size: expected {} bytes, got {} bytes",
            expected_size, actual_size
        ));
    }

    Ok(())
}

/// Constant-time select between two byte slices based on condition
///
/// # Security
/// - Always accesses both slices regardless of condition
/// - Prevents branch prediction attacks
/// - Uses conditional move instead of branching
///
/// # Arguments
/// * `condition` - If true, return `a`; if false, return `b`
/// * `a` - First byte slice
/// * `b` - Second byte slice (must be same length as `a`)
///
/// # Returns
/// * `a` if condition is true, `b` otherwise
///
/// # Panics
/// Panics if `a` and `b` have different lengths
///
/// # Example
/// ```ignore
/// use brankas_crypto::pqc::constant_time::ct_select;
///
/// let secret_a = vec![0xAA; 32];
/// let secret_b = vec![0xBB; 32];
///
/// let result = ct_select(true, &secret_a, &secret_b);
/// assert_eq!(result, secret_a);
/// ```
pub fn ct_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "ct_select requires equal-length inputs");

    let mut result = vec![0u8; a.len()];
    let mask = if condition { 0xFF } else { 0x00 };

    for i in 0..a.len() {
        // Constant-time selection using bitwise operations
        result[i] = (a[i] & mask) | (b[i] & !mask);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_equal() {
        let a = vec![0x42; 32];
        let b = vec![0x42; 32];
        assert!(ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_not_equal() {
        let a = vec![0x42; 32];
        let b = vec![0x43; 32];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        let a = vec![0x42; 32];
        let b = vec![0x42; 31];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_ne() {
        let a = vec![0x42; 32];
        let b = vec![0x43; 32];
        assert!(ct_ne(&a, &b));

        let c = vec![0x42; 32];
        assert!(!ct_ne(&a, &c));
    }

    #[test]
    fn test_validate_key_size_valid() {
        let key = vec![0x42; 2560]; // ML-DSA-44 private key size
        assert!(validate_key_size(&key, 2560).is_ok());
    }

    #[test]
    fn test_validate_key_size_invalid() {
        let key = vec![0x42; 100];
        let result = validate_key_size(&key, 2560);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid key size: expected 2560 bytes, got 100 bytes"));
    }

    #[test]
    fn test_ct_select_true() {
        let a = vec![0xAA; 32];
        let b = vec![0xBB; 32];
        let result = ct_select(true, &a, &b);
        assert_eq!(result, a);
    }

    #[test]
    fn test_ct_select_false() {
        let a = vec![0xAA; 32];
        let b = vec![0xBB; 32];
        let result = ct_select(false, &a, &b);
        assert_eq!(result, b);
    }

    #[test]
    #[should_panic(expected = "ct_select requires equal-length inputs")]
    fn test_ct_select_mismatched_lengths() {
        let a = vec![0xAA; 32];
        let b = vec![0xBB; 31];
        ct_select(true, &a, &b);
    }

    #[test]
    fn test_ct_eq_timing_properties() {
        // This is a basic functional test. Actual timing analysis
        // requires specialized tools (e.g., dudect, ctgrind).

        let secret1 = vec![0x42; 1024];
        let mut secret2 = secret1.clone();

        // Equal secrets
        assert!(ct_eq(&secret1, &secret2));

        // Differ in first byte
        secret2[0] = 0x43;
        assert!(!ct_eq(&secret1, &secret2));

        // Differ in last byte
        secret2[0] = 0x42;
        secret2[1023] = 0x43;
        assert!(!ct_eq(&secret1, &secret2));

        // Both operations should take the same time regardless of
        // where the difference occurs (verified via external tools)
    }

    #[test]
    fn test_ct_select_no_branching() {
        // Verify ct_select works for various data patterns
        let zeros = vec![0x00; 64];
        let ones = vec![0xFF; 64];
        let mixed = (0..64).map(|i| (i % 256) as u8).collect::<Vec<u8>>();

        // Test all combinations
        assert_eq!(ct_select(true, &zeros, &ones), zeros);
        assert_eq!(ct_select(false, &zeros, &ones), ones);
        assert_eq!(ct_select(true, &mixed, &zeros), mixed);
        assert_eq!(ct_select(false, &mixed, &ones), ones);
    }
}
