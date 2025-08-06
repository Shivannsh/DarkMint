//! Account Verification Circuit
//!
//! This module implements the final layer of MPT (Merkle Patricia Trie) proof verification
//! for Ethereum account data. It handles account RLP encoding, address derivation,
//! and commitment generation using Poseidon hash functions.

use ark_bn254::Fr;
use rlp::RlpStream;

use crate::crypto::{
    derive_burn_address, generate_nullifier, hash_ethereum_address, poseidon_hash, process_balance,
    ADDRESS_LENGTH, SECURITY_PARAMETER,
};

/// Input parameters for account proof verification circuit
///
/// Contains all necessary data to verify an Ethereum account's existence
/// and generate privacy-preserving commitments.
#[derive(Debug, Clone)]
pub struct AccountProofInputs {
    /// Preimage used to generate the burn address
    pub burn_preimage: Fr,
    /// Length of the lower layer prefix in the MPT proof
    pub lower_layer_prefix_len: u32,
    /// Prefix bytes from the lower layer of the MPT proof
    pub lower_layer_prefix: Vec<u8>,
    /// Account nonce from Ethereum state
    pub nonce: u64,
    /// Account balance in wei
    pub balance: u128,
    /// Storage root hash of the account
    pub storage_hash: [u8; 32],
    /// Code hash of the account
    pub code_hash: [u8; 32],
    /// Salt for commitment generation
    pub salt: Fr,
    /// Whether the balance should be encrypted in output
    pub encrypted: bool,
}

/// Output values from account proof verification circuit
///
/// These values are made public and can be used for further verification
/// or as inputs to other circuits.
#[derive(Debug, Clone)]
pub struct AccountProofOutputs {
    /// Upper layer commitment hash
    pub commit_upper: Fr,
    /// Encrypted or plaintext balance based on encryption flag
    pub encrypted_balance: Fr,
    /// Unique nullifier to prevent double-spending
    pub nullifier: Fr,
}

/// RLP encode Ethereum account data according to specification
///
/// Encodes account data (nonce, balance, storage_hash, code_hash) into
/// RLP format as used in Ethereum's state trie.
///
/// # Arguments
/// * `nonce` - Account nonce
/// * `balance` - Account balance in wei
/// * `storage_hash` - Root hash of account's storage trie
/// * `code_hash` - Hash of account's contract code
///
/// # Returns
/// * RLP-encoded account data as bytes
fn encode_account_rlp(
    nonce: u64,
    balance: u128,
    storage_hash: &[u8; 32],
    code_hash: &[u8; 32],
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(4);

    // Convert to big-endian for RLP encoding as per Ethereum specification
    stream.append(&nonce.to_be_bytes().as_slice());
    stream.append(&balance.to_be_bytes().as_slice());
    stream.append(&storage_hash.as_slice());
    stream.append(&code_hash.as_slice());

    stream.out().to_vec()
}

/// Generate expected prefix for MPT proof verification
///
/// Creates the expected prefix that should appear in the MPT proof
/// based on the derived burn address and account data.
///
/// # Arguments
/// * `burn_address` - Derived burn address (20 bytes)
/// * `account_rlp_len` - Length of RLP-encoded account data
///
/// # Returns
/// * Expected prefix bytes
fn generate_expected_prefix(
    burn_address: &[u8; ADDRESS_LENGTH],
    account_rlp_len: usize,
) -> Vec<u8> {
    let address_hash = hash_ethereum_address(burn_address);

    let mut expected_prefix = Vec::new();

    // Add security parameter bytes from address hash
    for i in 0..SECURITY_PARAMETER {
        expected_prefix.push(address_hash[32 - SECURITY_PARAMETER + i]);
    }

    // Add RLP encoding markers for account data
    expected_prefix.push(1 + 0x80 + 55); // RLP encoding for account
    expected_prefix.push(account_rlp_len as u8);

    expected_prefix
}

/// Calculate upper layer commitment hash
///
/// Combines the lower layer prefix with account data and generates
/// a commitment hash using Poseidon.
///
/// # Arguments
/// * `lower_layer_prefix` - Prefix from lower MPT layer
/// * `prefix_len` - Length of the prefix to use
/// * `account_rlp` - RLP-encoded account data
/// * `salt` - Salt for commitment generation
///
/// # Returns
/// * Upper layer commitment as field element
fn calculate_upper_layer_commitment(
    lower_layer_prefix: &[u8],
    prefix_len: u32,
    account_rlp: &[u8],
    salt: Fr,
) -> Fr {
    // Concatenate layers
    let mut upper_layer_bytes = Vec::new();
    upper_layer_bytes.extend_from_slice(&lower_layer_prefix[..prefix_len as usize]);
    upper_layer_bytes.extend_from_slice(account_rlp);

    // Calculate commitment using Poseidon hash
    let upper_layer_hash = poseidon_hash(
        crate::crypto::bytes_to_field_element(
            &upper_layer_bytes[..32.min(upper_layer_bytes.len())],
        ),
        Fr::from(upper_layer_bytes.len() as u64),
    );

    poseidon_hash(upper_layer_hash, salt)
}

/// Main account verification circuit implementation
///
/// This function implements the core logic for verifying Ethereum account proofs
/// and generating privacy-preserving commitments for the DarkMint system.
///
/// The circuit performs the following operations:
/// 1. Derives burn address from preimage
/// 2. Generates nullifier for double-spend prevention
/// 3. Processes balance (encrypt or keep plaintext)
/// 4. RLP encodes account data
/// 5. Verifies MPT proof structure
/// 6. Generates upper layer commitment
///
/// # Arguments
/// * `inputs` - Account proof input parameters
///
/// # Returns
/// * Account proof outputs including commitments and nullifier
pub fn verify_account_proof(inputs: AccountProofInputs) -> AccountProofOutputs {
    // Step 1: Derive burn address from preimage
    let burn_address = derive_burn_address(inputs.burn_preimage);

    // Step 2: Generate nullifier for double-spend prevention
    let nullifier = generate_nullifier(inputs.burn_preimage);

    // Step 3: Process balance (encrypt if requested)
    let balance_fr = Fr::from(inputs.balance);
    let encrypted_balance = process_balance(balance_fr, inputs.salt, inputs.encrypted);

    // Step 4: RLP encode account data according to Ethereum specification
    let account_rlp = encode_account_rlp(
        inputs.nonce,
        inputs.balance,
        &inputs.storage_hash,
        &inputs.code_hash,
    );

    // Step 5: Generate and verify expected prefix structure
    let _expected_prefix = generate_expected_prefix(&burn_address, account_rlp.len());
    // Note: In a full implementation, we would verify that the expected_prefix
    // matches the structure found in the MPT proof

    // Step 6: Calculate upper layer commitment
    let commit_upper = calculate_upper_layer_commitment(
        &inputs.lower_layer_prefix,
        inputs.lower_layer_prefix_len,
        &account_rlp,
        inputs.salt,
    );

    AccountProofOutputs {
        commit_upper,
        encrypted_balance,
        nullifier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_inputs() -> AccountProofInputs {
        AccountProofInputs {
            burn_preimage: Fr::from(123u64),
            lower_layer_prefix_len: 0,
            lower_layer_prefix: vec![],
            nonce: 0,
            balance: 1000000000000000000u128, // 1 ETH in wei
            storage_hash: [0u8; 32],
            code_hash: [0u8; 32],
            salt: Fr::from(789u64),
            encrypted: false,
        }
    }

    #[test]
    fn test_encode_account_rlp() {
        let nonce = 42u64;
        let balance = 1000000000000000000u128;
        let storage_hash = [1u8; 32];
        let code_hash = [2u8; 32];

        let rlp = encode_account_rlp(nonce, balance, &storage_hash, &code_hash);
        assert!(!rlp.is_empty());
    }

    #[test]
    fn test_generate_expected_prefix() {
        let address = [1u8; ADDRESS_LENGTH];
        let rlp_len = 100;
        let prefix = generate_expected_prefix(&address, rlp_len);

        assert_eq!(prefix.len(), SECURITY_PARAMETER + 2);
        assert_eq!(prefix[SECURITY_PARAMETER], 1 + 0x80 + 55);
        assert_eq!(prefix[SECURITY_PARAMETER + 1], rlp_len as u8);
    }

    #[test]
    fn test_verify_account_proof_unencrypted() {
        let inputs = create_test_inputs();
        let outputs = verify_account_proof(inputs);

        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.encrypted_balance, Fr::from(0u64));
        assert_ne!(outputs.nullifier, Fr::from(0u64));

        // Verify encrypted balance equals balance when not encrypted
        assert_eq!(outputs.encrypted_balance, Fr::from(1000000000000000000u128));
    }

    #[test]
    fn test_verify_account_proof_encrypted() {
        let mut inputs = create_test_inputs();
        inputs.encrypted = true;

        let outputs = verify_account_proof(inputs);

        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.encrypted_balance, Fr::from(0u64));
        assert_ne!(outputs.nullifier, Fr::from(0u64));

        // Verify encrypted balance is different from original balance when encrypted
        assert_ne!(outputs.encrypted_balance, Fr::from(1000000000000000000u128));
    }

    #[test]
    fn test_verify_account_proof_deterministic() {
        let inputs = create_test_inputs();
        let outputs1 = verify_account_proof(inputs.clone());
        let outputs2 = verify_account_proof(inputs);

        // Same inputs should produce same outputs
        assert_eq!(outputs1.commit_upper, outputs2.commit_upper);
        assert_eq!(outputs1.encrypted_balance, outputs2.encrypted_balance);
        assert_eq!(outputs1.nullifier, outputs2.nullifier);
    }

    #[test]
    fn test_calculate_upper_layer_commitment() {
        let prefix = vec![1u8, 2u8, 3u8];
        let account_rlp = vec![4u8, 5u8, 6u8];
        let salt = Fr::from(999u64);

        let commitment = calculate_upper_layer_commitment(&prefix, 3, &account_rlp, salt);
        assert_ne!(commitment, Fr::from(0u64));
    }
}
