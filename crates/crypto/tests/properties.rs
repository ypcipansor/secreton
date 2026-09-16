//! Property-based tests for the cryptographic primitives.
//!
//! Example-based tests pin down the cases someone thought of. These pin down the
//! invariants that must hold for *every* input: an AEAD must round-trip any plaintext
//! and reject any tampering, and Shamir sharing must reconstruct from any sufficient
//! subset of shares while an insufficient subset must not recover the secret.

use proptest::prelude::*;
use rand::rngs::OsRng;
use secreton_crypto::encryption::{Aes256GcmCipher, ChaCha20Poly1305Cipher, SymmetricCipher};
use secreton_crypto::shamir;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every AEAD must return exactly the plaintext it was given, for any input
    /// including the empty message.
    #[test]
    fn aes_gcm_round_trips_any_plaintext(
        plaintext in prop::collection::vec(any::<u8>(), 0..2048),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let cipher = Aes256GcmCipher;
        let encrypted = cipher.encrypt(&plaintext, &key).expect("encrypt");
        let recovered = cipher.decrypt(&encrypted, &key).expect("decrypt");
        prop_assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chacha20_poly1305_round_trips_any_plaintext(
        plaintext in prop::collection::vec(any::<u8>(), 0..2048),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let cipher = ChaCha20Poly1305Cipher;
        let encrypted = cipher.encrypt(&plaintext, &key).expect("encrypt");
        let recovered = cipher.decrypt(&encrypted, &key).expect("decrypt");
        prop_assert_eq!(recovered, plaintext);
    }

    /// Encryption must be randomised: the same plaintext under the same key must not
    /// produce the same ciphertext twice, otherwise equal secrets become linkable at rest.
    #[test]
    fn encryption_is_randomised(
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        key in prop::array::uniform32(any::<u8>()),
    ) {
        let cipher = Aes256GcmCipher;
        let a = cipher.encrypt(&plaintext, &key).expect("encrypt");
        let b = cipher.encrypt(&plaintext, &key).expect("encrypt");
        prop_assert_ne!(
            a.ciphertext, b.ciphertext,
            "nonce reuse: identical plaintexts produced identical ciphertexts"
        );
    }

    /// Flipping any single bit of the ciphertext must make authentication fail. This is
    /// the property that separates an AEAD from plain encryption.
    #[test]
    fn tampering_is_always_detected(
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        key in prop::array::uniform32(any::<u8>()),
        selector in any::<u16>(),
    ) {
        let cipher = Aes256GcmCipher;
        let mut encrypted = cipher.encrypt(&plaintext, &key).expect("encrypt");
        let idx = (selector as usize) % encrypted.ciphertext.len();
        encrypted.ciphertext[idx] ^= 1 << (selector % 8);
        prop_assert!(
            cipher.decrypt(&encrypted, &key).is_err(),
            "a tampered ciphertext decrypted successfully"
        );
    }

    /// Tampering with the nonce must also be detected, not silently produce garbage.
    #[test]
    fn nonce_tampering_is_detected(
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        key in prop::array::uniform32(any::<u8>()),
        selector in any::<u16>(),
    ) {
        let cipher = Aes256GcmCipher;
        let mut encrypted = cipher.encrypt(&plaintext, &key).expect("encrypt");
        let idx = (selector as usize) % encrypted.nonce.len();
        encrypted.nonce[idx] ^= 1 << (selector % 8);
        prop_assert!(cipher.decrypt(&encrypted, &key).is_err());
    }

    /// Decrypting with the wrong key must fail rather than return garbage.
    #[test]
    fn wrong_key_never_decrypts(
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        key in prop::array::uniform32(any::<u8>()),
        other in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(key != other);
        let cipher = Aes256GcmCipher;
        let encrypted = cipher.encrypt(&plaintext, &key).expect("encrypt");
        prop_assert!(cipher.decrypt(&encrypted, &other).is_err());
    }

    /// Any `threshold`-sized subset of the shares must reconstruct the secret. The unseal
    /// flow depends on operators being able to present *any* quorum, not a fixed one.
    #[test]
    fn shamir_reconstructs_from_any_quorum(
        secret in prop::collection::vec(any::<u8>(), 1..128),
        threshold in 2usize..5,
        extra in 0usize..3,
    ) {
        let total = threshold + extra;
        let shares = shamir::split(&secret, threshold, total, &mut OsRng).expect("split");

        // Slide a window across the shares so different quorums are exercised.
        for start in 0..=(total - threshold) {
            let quorum = &shares[start..start + threshold];
            let recovered = shamir::combine(quorum).expect("combine");
            prop_assert_eq!(&recovered, &secret);
        }
    }

    /// Fewer shares than the threshold must not recover the secret.
    #[test]
    fn shamir_rejects_sub_threshold_quorums(
        secret in prop::collection::vec(any::<u8>(), 1..128),
        threshold in 3usize..6,
    ) {
        let shares = shamir::split(&secret, threshold, threshold, &mut OsRng).expect("split");
        let insufficient = &shares[..threshold - 1];
        match shamir::combine(insufficient) {
            Err(_) => {}
            Ok(recovered) => prop_assert_ne!(
                recovered, secret,
                "sub-threshold shares reconstructed the secret"
            ),
        }
    }
}
