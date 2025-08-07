//! Cryptographic utilities for DarkMint
//!
//! This module provides cryptographic functions used throughout the DarkMint system,
//! including Poseidon hashing, Keccak-256 hashing, and address derivation.

use alloy_primitives::B256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use tiny_keccak::{Hasher, Keccak};

/// Security parameter for address prefix length
pub const SECURITY_PARAMETER: usize = 20;

/// Ethereum address length in bytes
pub const ADDRESS_LENGTH: usize = 20;

/// Hash length in bytes (32 bytes for both Keccak-256 and Poseidon)
pub const HASH_LENGTH: usize = 32;

/// Compute Poseidon hash of two field elements
///
/// This is the primary hash function used in DarkMint circuits,
/// replacing MiMC7 for better efficiency and security.
///
/// # Arguments
/// * `left` - Left input field element
/// * `right` - Right input field element
///
/// # Returns
/// * Poseidon hash as a field element
pub fn poseidon_hash(left: Fr, right: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let left_bytes = left.into_bigint().to_bytes_be();
    let right_bytes = right.into_bigint().to_bytes_be();
    let hash_bytes = poseidon
        .hash_bytes_be(&[&left_bytes, &right_bytes])
        .unwrap();
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

/// Compute Keccak-256 hash of input data
///
/// Used for Ethereum-compatible hashing operations.
///
/// # Arguments
/// * `input` - Input data to hash
///
/// # Returns
/// * Keccak-256 hash as B256
pub fn keccak256<T: AsRef<[u8]>>(input: T) -> B256 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(input.as_ref());
    hasher.finalize(&mut output);

    B256::from(output)
}

/// Derive Ethereum address from 20-byte input
///
/// Computes the Keccak-256 hash of the input address bytes.
///
/// # Arguments
/// * `address` - 20-byte Ethereum address
///
/// # Returns
/// * 32-byte hash of the address
pub fn hash_ethereum_address(address: &[u8; ADDRESS_LENGTH]) -> [u8; HASH_LENGTH] {
    keccak256(address).0
}

/// Hash arbitrary bytes using Poseidon (simplified version for circuit use)
///
/// Converts byte array to field element for use in Poseidon hash.
/// Takes first 32 bytes or pads with zeros if shorter.
///
/// # Arguments
/// * `bytes` - Input bytes to hash
///
/// # Returns
/// * Field element representation of the bytes
pub fn bytes_to_field_element(bytes: &[u8]) -> Fr {
    if bytes.is_empty() {
        return Fr::from(0u64);
    }

    // Take first 32 bytes or pad with zeros
    let mut hash_input = [0u8; HASH_LENGTH];
    let copy_len = bytes.len().min(HASH_LENGTH);
    hash_input[..copy_len].copy_from_slice(&bytes[..copy_len]);

    Fr::from_le_bytes_mod_order(&hash_input)
}

/// Generate burn address from preimage
///
/// This function derives an Ethereum address from a field element preimage
/// by hashing the preimage with itself using Poseidon and taking the first 20 bytes.
///
/// # Arguments
/// * `preimage` - Field element preimage
///
/// # Returns
/// * 20-byte Ethereum address derived from preimage
pub fn derive_burn_address(preimage: Fr) -> [u8; ADDRESS_LENGTH] {
    let burn_hash = poseidon_hash(preimage, preimage);
    let burn_bytes = burn_hash.into_bigint().to_bytes_be();

    let mut address = [0u8; ADDRESS_LENGTH];
    for (i, byte) in address.iter_mut().enumerate() {
        *byte = burn_bytes.get(i).copied().unwrap_or(0);
    }

    address
}

/// Generate nullifier from preimage
///
/// Creates a unique nullifier to prevent double-spending by hashing
/// the preimage with zero.
///
/// # Arguments
/// * `preimage` - Field element preimage
///
/// # Returns
/// * Nullifier as field element
pub fn generate_nullifier(preimage: Fr) -> Fr {
    poseidon_hash(preimage, Fr::from(0u64))
}

/// Process balance with optional encryption
///
/// If encrypted is true, applies Poseidon hash with salt for privacy.
/// If false, returns the original balance.
///
/// # Arguments
/// * `balance` - Account balance as field element
/// * `salt` - Salt for encryption
/// * `encrypted` - Whether to encrypt the balance
///
/// # Returns
/// * Processed balance (encrypted or plaintext)
pub fn process_balance(balance: Fr, salt: Fr, encrypted: bool) -> Fr {
    if encrypted {
        poseidon_hash(balance, salt)
    } else {
        balance
    }
}

/// Check if a substring exists within a larger byte array
///
/// Performs a linear search to find if the substring appears anywhere
/// within the main string. This is used to verify that lower layer hashes
/// are properly embedded in upper layer data.
///
/// # Arguments
/// * `substring` - Bytes to search for
/// * `main_string` - Bytes to search within
///
/// # Returns
/// * `true` if substring is found, `false` otherwise
pub fn contains_substring(substring: &[u8], main_string: &[u8]) -> bool {
    if substring.len() > main_string.len() {
        return false;
    }

    // Use constant-time comparison to prevent timing attacks
    for i in 0..=main_string.len() - substring.len() {
        if constant_time_eq(&main_string[i..i + substring.len()], substring) {
            return true;
        }
    }
    false
}

/// Constant-time byte array comparison
///
/// Compares two byte arrays in constant time to prevent timing attacks.
/// This is important for security when comparing cryptographic hashes.
///
/// # Arguments
/// * `a` - First byte array
/// * `b` - Second byte array
///
/// # Returns
/// * `true` if arrays are equal, `false` otherwise
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash_basic() {
        let left = Fr::from(123u64);
        let right = Fr::from(456u64);
        let hash = poseidon_hash(left, right);

        // Hash should be different from inputs
        assert_ne!(hash, Fr::from(0u64));
        assert_ne!(hash, left);
        assert_ne!(hash, right);
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        let left = Fr::from(789u64);
        let right = Fr::from(101112u64);
        let hash1 = poseidon_hash(left, right);
        let hash2 = poseidon_hash(left, right);

        // Same inputs should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_keccak256_basic() {
        let data = b"test data";
        let hash = keccak256(data);
        assert_eq!(hash.len(), HASH_LENGTH);
        assert_ne!(hash.0, [0u8; HASH_LENGTH]);
    }

    #[test]
    fn test_hash_ethereum_address() {
        let address = [1u8; ADDRESS_LENGTH];
        let hash = hash_ethereum_address(&address);
        assert_eq!(hash.len(), HASH_LENGTH);
        assert_ne!(hash, [0u8; HASH_LENGTH]);
    }

    #[test]
    fn test_bytes_to_field_element() {
        let bytes = vec![1u8, 2u8, 3u8, 4u8];
        let field_element = bytes_to_field_element(&bytes);
        assert_ne!(field_element, Fr::from(0u64));

        // Empty bytes should return zero
        let empty_field = bytes_to_field_element(&[]);
        assert_eq!(empty_field, Fr::from(0u64));
    }

    #[test]
    fn test_derive_burn_address() {
        let preimage = Fr::from(12345u64);
        let address = derive_burn_address(preimage);
        assert_eq!(address.len(), ADDRESS_LENGTH);
        assert_ne!(address, [0u8; ADDRESS_LENGTH]);
    }

    #[test]
    fn test_generate_nullifier() {
        let preimage = Fr::from(67890u64);
        let nullifier = generate_nullifier(preimage);
        assert_ne!(nullifier, Fr::from(0u64));
        assert_ne!(nullifier, preimage);
    }

    #[test]
    fn test_process_balance_encrypted() {
        let balance = Fr::from(100u64);
        let salt = Fr::from(42u64);
        let encrypted = process_balance(balance, salt, true);
        assert_ne!(encrypted, balance);
    }

    #[test]
    fn test_contains_substring_found() {
        let main_string = b"hello world";
        let substring = b"world";
        assert!(contains_substring(substring, main_string));
    }

    #[test]
    fn test_contains_substring_not_found() {
        let main_string = b"hello world";
        let substring = b"xyz";
        assert!(!contains_substring(substring, main_string));
    }

    #[test]
    fn test_contains_substring_edge_cases() {
        // Empty substring should be found
        assert!(contains_substring(b"", b"hello"));

        // Substring longer than main string should not be found
        assert!(!contains_substring(b"hello world", b"hello"));

        // Exact match should be found
        assert!(contains_substring(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq() {
        // Test equal arrays
        assert!(constant_time_eq(b"hello", b"hello"));

        // Test different arrays
        assert!(!constant_time_eq(b"hello", b"world"));

        // Test different lengths
        assert!(!constant_time_eq(b"hello", b"hell"));

        // Test empty arrays
        assert!(constant_time_eq(b"", b""));

        // Test one empty array
        assert!(!constant_time_eq(b"hello", b""));
    }
}
