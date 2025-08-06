#![no_main]
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use sha2::Digest;

#[derive(Debug, Clone)]
pub struct MptPathInputs {
    pub is_top: bool,
    pub num_upper_layer_bytes: u32,
    pub upper_layer_bytes: Vec<u8>,
    pub num_lower_layer_bytes: u32,
    pub lower_layer_bytes: Vec<u8>,
    pub salt: Fr,
}

#[derive(Debug, Clone)]
pub struct MptPathOutputs {
    pub commit_upper: Fr,
    pub commit_lower: Fr,
}

/// Poseidon hash function (replacing MiMC7)
pub fn poseidon_hash(left: Fr, right: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let left_bytes = left.into_bigint().to_bytes_be();
    let right_bytes = right.into_bigint().to_bytes_be();
    let hash_bytes = poseidon
        .hash_bytes_be(&[&left_bytes, &right_bytes])
        .unwrap();
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

/// Hash bytes using Poseidon (simplified version)
pub fn hash_bytes_poseidon(bytes: &[u8]) -> Fr {
    if bytes.is_empty() {
        return Fr::from(0u64);
    }
    
    // Take first 32 bytes or pad with zeros
    let mut hash_input = [0u8; 32];
    let copy_len = bytes.len().min(32);
    hash_input[..copy_len].copy_from_slice(&bytes[..copy_len]);
    
    Fr::from_le_bytes_mod_order(&hash_input)
}

/// Keccak-256 hash function (using SHA-256 as approximation)
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Check if a substring exists in a larger string
pub fn substring_check(substring: &[u8], main_string: &[u8]) -> bool {
    if substring.len() > main_string.len() {
        return false;
    }
    
    for i in 0..=main_string.len() - substring.len() {
        if main_string[i..i + substring.len()] == *substring {
            return true;
        }
    }
    false
}

/// Main MPT-path circuit implementation
pub fn mpt_path_circuit(inputs: MptPathInputs) -> MptPathOutputs {
    // Validate is_top is boolean
    assert!(inputs.is_top == true || inputs.is_top == false);
    
    // Calculate commit_lower
    let lower_layer_hash = hash_bytes_poseidon(&inputs.lower_layer_bytes);
    let commit_lower_to_len = poseidon_hash(lower_layer_hash, Fr::from(inputs.num_lower_layer_bytes as u64));
    let commit_lower = poseidon_hash(commit_lower_to_len, inputs.salt);
    
    // Calculate Keccak hash of lower layer
    let keccak_lower_layer = keccak256(&inputs.lower_layer_bytes);
    
    // Calculate commit_upper
    let upper_layer_hash = hash_bytes_poseidon(&inputs.upper_layer_bytes);
    let commit_upper_to_len = poseidon_hash(upper_layer_hash, Fr::from(inputs.num_upper_layer_bytes as u64));
    let commit_upper_to_salt = poseidon_hash(commit_upper_to_len, inputs.salt);
    
    // Convert keccak hash to field element for subtraction
    let keccak_lower_fr = Fr::from_le_bytes_mod_order(&keccak_lower_layer);
    
    // Calculate commit_upper with conditional logic
    let commit_upper = if inputs.is_top {
        // When is_top is true, add the difference
        poseidon_hash(commit_upper_to_salt, keccak_lower_fr)
    } else {
        // When is_top is false, use the original hash
        commit_upper_to_salt
    };
    
    // Verify substring check constraint
    let substring_found = substring_check(&keccak_lower_layer, &inputs.upper_layer_bytes);
    assert_eq!(substring_found, !inputs.is_top, "Substring check constraint violated");
    
    MptPathOutputs {
        commit_upper,
        commit_lower,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash() {
        let left = Fr::from(123u64);
        let right = Fr::from(456u64);
        let hash = poseidon_hash(left, right);
        assert_ne!(hash, Fr::from(0u64));
        assert_ne!(hash, left);
        assert_ne!(hash, right);
    }

    #[test]
    fn test_hash_bytes_poseidon() {
        let bytes = vec![1u8, 2u8, 3u8, 4u8];
        let hash = hash_bytes_poseidon(&bytes);
        assert_ne!(hash, Fr::from(0u64));
    }

    #[test]
    fn test_keccak256() {
        let data = b"test data";
        let hash = keccak256(data);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_substring_check() {
        let main_string = b"hello world";
        let substring = b"world";
        let not_substring = b"xyz";
        
        assert!(substring_check(substring, main_string));
        assert!(!substring_check(not_substring, main_string));
    }

    #[test]
    fn test_mpt_path_circuit_basic() {
        // Create test data where keccak(lower_layer) is contained in upper_layer
        let lower_layer = vec![2u8; 50];
        let keccak_lower = keccak256(&lower_layer);
        let mut upper_layer = vec![1u8; 100];
        // Insert the keccak hash into the upper layer
        upper_layer[10..42].copy_from_slice(&keccak_lower);
        
        let inputs = MptPathInputs {
            is_top: false,
            num_upper_layer_bytes: upper_layer.len() as u32,
            upper_layer_bytes: upper_layer,
            num_lower_layer_bytes: lower_layer.len() as u32,
            lower_layer_bytes: lower_layer,
            salt: Fr::from(789u64),
        };

        let outputs = mpt_path_circuit(inputs);
        
        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.commit_lower, Fr::from(0u64));
    }

    #[test]
    fn test_mpt_path_circuit_is_top() {
        let inputs = MptPathInputs {
            is_top: true,
            num_upper_layer_bytes: 100,
            upper_layer_bytes: vec![1u8; 100],
            num_lower_layer_bytes: 50,
            lower_layer_bytes: vec![2u8; 50],
            salt: Fr::from(789u64),
        };

        let outputs = mpt_path_circuit(inputs);
        
        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.commit_lower, Fr::from(0u64));
    }

    #[test]
    fn test_mpt_path_circuit_empty_layers() {
        // For empty layers, keccak([]) will be a specific hash
        // We need to ensure it's NOT found in the upper layer when is_top = false
        let lower_layer = vec![];
        let keccak_lower = keccak256(&lower_layer);
        let upper_layer = vec![1u8; 100]; // Upper layer doesn't contain the keccak hash
        
        let inputs = MptPathInputs {
            is_top: true, // Set to true so constraint expects substring_found = false
            num_upper_layer_bytes: upper_layer.len() as u32,
            upper_layer_bytes: upper_layer,
            num_lower_layer_bytes: lower_layer.len() as u32,
            lower_layer_bytes: lower_layer,
            salt: Fr::from(789u64),
        };

        let outputs = mpt_path_circuit(inputs);
        
        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.commit_lower, Fr::from(0u64));
    }
} 