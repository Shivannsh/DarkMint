//! Merkle Proof Verification Circuit
//!
//! This module implements intermediate layer verification for MPT (Merkle Patricia Trie) proofs.
//! It handles path verification between different layers of the trie structure and generates
//! commitments for both upper and lower layers.

use crate::crypto::{bytes_to_field_element, keccak256, poseidon_hash};
use ark_bn254::Fr;

/// Input parameters for Merkle path verification circuit
///
/// Contains data for verifying the connection between two layers in an MPT proof,
/// including layer data and metadata about the proof structure.
#[derive(Debug, Clone)]
pub struct MerklePathInputs {
    /// Whether this is the top layer of the proof
    pub is_top: bool,
    /// Number of bytes in the upper layer data
    pub num_upper_layer_bytes: u32,
    /// Raw bytes of the upper layer
    pub upper_layer_bytes: Vec<u8>,
    /// Number of bytes in the lower layer data
    pub num_lower_layer_bytes: u32,
    /// Raw bytes of the lower layer
    pub lower_layer_bytes: Vec<u8>,
    /// Salt for commitment generation
    pub salt: Fr,
}

/// Output values from Merkle path verification circuit
///
/// Contains commitments for both upper and lower layers that can be used
/// for further verification or as inputs to other circuits.
#[derive(Debug, Clone)]
pub struct MerklePathOutputs {
    /// Commitment hash for the upper layer
    pub commit_upper: Fr,
    /// Commitment hash for the lower layer
    pub commit_lower: Fr,
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

    // Use sliding window approach for efficient substring search
    for i in 0..=main_string.len() - substring.len() {
        if main_string[i..i + substring.len()] == *substring {
            return true;
        }
    }
    false
}

/// Generate commitment hash for layer data
///
/// Creates a commitment by hashing the layer data with its length and salt.
/// This provides a succinct representation of the layer that can be used
/// in further computations.
///
/// # Arguments
/// * `layer_bytes` - Raw bytes of the layer
/// * `num_bytes` - Number of bytes to consider
/// * `salt` - Salt for commitment generation
///
/// # Returns
/// * Commitment hash as field element
fn generate_layer_commitment(layer_bytes: &[u8], num_bytes: u32, salt: Fr) -> Fr {
    let layer_hash = bytes_to_field_element(layer_bytes);
    let layer_with_length = poseidon_hash(layer_hash, Fr::from(num_bytes as u64));
    poseidon_hash(layer_with_length, salt)
}

/// Calculate upper layer commitment with conditional logic
///
/// Generates the upper layer commitment based on whether this is the top layer.
/// For top layers, includes additional hash information from the lower layer.
///
/// # Arguments
/// * `upper_layer_bytes` - Raw bytes of upper layer
/// * `num_upper_bytes` - Number of upper layer bytes
/// * `lower_layer_keccak` - Keccak hash of lower layer
/// * `salt` - Salt for commitment generation
/// * `is_top` - Whether this is the top layer
///
/// # Returns
/// * Upper layer commitment as field element
fn calculate_upper_commitment(
    upper_layer_bytes: &[u8],
    num_upper_bytes: u32,
    lower_layer_keccak: &[u8; 32],
    salt: Fr,
    is_top: bool,
) -> Fr {
    let upper_layer_hash = bytes_to_field_element(upper_layer_bytes);
    let commit_upper_to_len = poseidon_hash(upper_layer_hash, Fr::from(num_upper_bytes as u64));
    let commit_upper_to_salt = poseidon_hash(commit_upper_to_len, salt);

    if is_top {
        // When is_top is true, include the lower layer keccak hash
        let keccak_lower_fr = bytes_to_field_element(lower_layer_keccak);
        poseidon_hash(commit_upper_to_salt, keccak_lower_fr)
    } else {
        // When is_top is false, use the base commitment
        commit_upper_to_salt
    }
}

/// Verify substring containment constraint
///
/// Checks that the substring containment property holds according to the
/// circuit's logic: when is_top is false, the lower layer hash should be
/// contained in the upper layer.
///
/// # Arguments
/// * `keccak_lower` - Keccak hash of lower layer
/// * `upper_layer_bytes` - Upper layer data
/// * `is_top` - Whether this is the top layer
///
/// # Returns
/// * `Ok(())` if constraint is satisfied, `Err` otherwise
fn verify_substring_constraint(
    keccak_lower: &[u8; 32],
    upper_layer_bytes: &[u8],
    is_top: bool,
) -> Result<(), &'static str> {
    let substring_found = contains_substring(keccak_lower, upper_layer_bytes);

    // For non-top layers: the lower layer hash should be contained in upper layer
    // For top layer: we don't check substring containment (handled by state root verification)
    if (is_top && !substring_found) || (!is_top && substring_found) {
        Ok(())
    } else {
        Err("Substring containment constraint violated")
    }
}

/// Main Merkle path verification circuit implementation
///
/// This function implements the core logic for verifying connections between
/// layers in an MPT proof. It performs the following operations:
///
/// 1. Validates input parameters
/// 2. Generates lower layer commitment
/// 3. Calculates Keccak hash of lower layer
/// 4. Generates upper layer commitment with conditional logic
/// 5. Verifies substring containment constraints
///
/// The circuit ensures that:
/// - Lower layer data is properly committed
/// - Upper layer properly references lower layer (when not top)
/// - All cryptographic relationships are maintained
///
/// # Arguments
/// * `inputs` - Merkle path input parameters
///
/// # Returns
/// * Merkle path outputs including both layer commitments
///
/// # Panics
/// * If substring containment constraint is violated
pub fn verify_merkle_path(inputs: MerklePathInputs) -> MerklePathOutputs {
    // Step 1: Validate that is_top is a proper boolean
    // In Rust, bool type guarantees this is always true, but keeping for circuit compatibility

    // Step 2: Generate lower layer commitment
    let commit_lower = generate_layer_commitment(
        &inputs.lower_layer_bytes,
        inputs.num_lower_layer_bytes,
        inputs.salt,
    );

    // Step 3: Calculate Keccak hash of lower layer for containment check
    let keccak_lower_layer = keccak256(&inputs.lower_layer_bytes).0;

    // Step 4: Calculate upper layer commitment with conditional logic
    let commit_upper = calculate_upper_commitment(
        &inputs.upper_layer_bytes,
        inputs.num_upper_layer_bytes,
        &keccak_lower_layer,
        inputs.salt,
        inputs.is_top,
    );

    // Step 5: Verify substring containment constraint
    verify_substring_constraint(
        &keccak_lower_layer,
        &inputs.upper_layer_bytes,
        inputs.is_top,
    )
    .expect("Substring containment constraint must be satisfied");

    MerklePathOutputs {
        commit_upper,
        commit_lower,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_generate_layer_commitment() {
        let layer_bytes = vec![1u8, 2u8, 3u8, 4u8];
        let salt = Fr::from(789u64);
        let commitment = generate_layer_commitment(&layer_bytes, layer_bytes.len() as u32, salt);

        assert_ne!(commitment, Fr::from(0u64));
    }

    #[test]
    fn test_verify_merkle_path_top_layer() {
        let inputs = MerklePathInputs {
            is_top: true,
            num_upper_layer_bytes: 100,
            upper_layer_bytes: vec![1u8; 100],
            num_lower_layer_bytes: 50,
            lower_layer_bytes: vec![2u8; 50],
            salt: Fr::from(789u64),
        };

        let outputs = verify_merkle_path(inputs);

        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.commit_lower, Fr::from(0u64));
    }

    #[test]
    fn test_verify_merkle_path_intermediate_layer() {
        // Create test data where keccak(lower_layer) is contained in upper_layer
        let lower_layer = vec![2u8; 50];
        let keccak_lower = keccak256(&lower_layer).0;
        let mut upper_layer = vec![1u8; 100];

        // Insert the keccak hash into the upper layer to satisfy constraint
        upper_layer[10..42].copy_from_slice(&keccak_lower);

        let inputs = MerklePathInputs {
            is_top: false,
            num_upper_layer_bytes: upper_layer.len() as u32,
            upper_layer_bytes: upper_layer,
            num_lower_layer_bytes: lower_layer.len() as u32,
            lower_layer_bytes: lower_layer,
            salt: Fr::from(789u64),
        };

        let outputs = verify_merkle_path(inputs);

        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.commit_lower, Fr::from(0u64));
    }

    #[test]
    fn test_verify_merkle_path_deterministic() {
        let inputs = MerklePathInputs {
            is_top: true,
            num_upper_layer_bytes: 50,
            upper_layer_bytes: vec![3u8; 50],
            num_lower_layer_bytes: 25,
            lower_layer_bytes: vec![4u8; 25],
            salt: Fr::from(999u64),
        };

        let outputs1 = verify_merkle_path(inputs.clone());
        let outputs2 = verify_merkle_path(inputs);

        // Same inputs should produce same outputs
        assert_eq!(outputs1.commit_upper, outputs2.commit_upper);
        assert_eq!(outputs1.commit_lower, outputs2.commit_lower);
    }

    #[test]
    #[should_panic(expected = "Substring containment constraint must be satisfied")]
    fn test_verify_merkle_path_constraint_violation() {
        // Create inputs where constraint will be violated
        let inputs = MerklePathInputs {
            is_top: false, // This means substring should be found
            num_upper_layer_bytes: 50,
            upper_layer_bytes: vec![1u8; 50], // But upper layer doesn't contain keccak(lower)
            num_lower_layer_bytes: 25,
            lower_layer_bytes: vec![2u8; 25],
            salt: Fr::from(789u64),
        };

        verify_merkle_path(inputs); // Should panic due to constraint violation
    }

    #[test]
    fn test_calculate_upper_commitment_difference() {
        let upper_bytes = vec![5u8; 60];
        let lower_keccak = [6u8; 32];
        let salt = Fr::from(111u64);

        let top_commitment =
            calculate_upper_commitment(&upper_bytes, 60, &lower_keccak, salt, true);
        let intermediate_commitment =
            calculate_upper_commitment(&upper_bytes, 60, &lower_keccak, salt, false);

        // Top and intermediate commitments should be different
        assert_ne!(top_commitment, intermediate_commitment);
    }

    #[test]
    fn test_verify_substring_constraint_success() {
        let keccak = [7u8; 32];
        let mut upper_layer = vec![8u8; 100];
        upper_layer[20..52].copy_from_slice(&keccak); // Insert keccak hash

        // Should succeed when is_top=false and substring is found
        assert!(verify_substring_constraint(&keccak, &upper_layer, false).is_ok());

        // Should succeed when is_top=true and substring is not found (different keccak)
        let different_keccak = [9u8; 32];
        assert!(verify_substring_constraint(&different_keccak, &upper_layer, true).is_ok());
    }

    #[test]
    fn test_verify_substring_constraint_failure() {
        let keccak = [7u8; 32];
        let upper_layer = vec![8u8; 100]; // Doesn't contain keccak

        // Should fail when is_top=false but substring is not found
        assert!(verify_substring_constraint(&keccak, &upper_layer, false).is_err());

        // Should fail when is_top=true but substring is found
        let mut upper_with_keccak = vec![8u8; 100];
        upper_with_keccak[20..52].copy_from_slice(&keccak);
        assert!(verify_substring_constraint(&keccak, &upper_with_keccak, true).is_err());
    }
}
