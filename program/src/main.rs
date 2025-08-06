//! DarkMint Zero-Knowledge Proof Program
//!
//! This program implements the core zero-knowledge proof logic for the DarkMint system.
//! It verifies Ethereum account proofs and generates privacy-preserving commitments
//! using Modified Merkle Patricia Trie (MPT) verification with Poseidon hash functions.
//!
//! The program performs:
//! 1. Account proof verification (final MPT layer)
//! 2. Path proof verification (intermediate MPT layers)
//! 3. State root validation against Ethereum blockchain
//! 4. Generation of privacy-preserving commitments

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use alloy_sol_types::SolType;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use fibonacci_lib::PublicValuesStruct;
use fibonacci_lib::{mpt_last_circuit, mpt_path_circuit, MptLastInputs, MptPathInputs};
use hex;
use tiny_keccak::{Hasher, Keccak};

/// Check if a substring exists within a larger byte array
///
/// This function is used to verify that lower layer hashes are properly
/// embedded within upper layer MPT proof data.
///
/// # Arguments
/// * `substring` - Bytes to search for
/// * `main_string` - Bytes to search within
///
/// # Returns
/// * `true` if substring is found, `false` otherwise
fn contains_substring(substring: &[u8], main_string: &[u8]) -> bool {
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

/// Compute Keccak-256 hash of input data
///
/// Used for Ethereum-compatible hashing operations in MPT proof verification.
///
/// # Arguments
/// * `input` - Input data to hash
///
/// # Returns
/// * Keccak-256 hash as B256
pub fn compute_keccak256<T: AsRef<[u8]>>(input: T) -> B256 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(input.as_ref());
    hasher.finalize(&mut output);

    B256::from(output)
}

/// Convert field element to u32 for public values
///
/// Extracts the last 4 bytes of the field element as a u32 value.
/// This is used to convert circuit outputs to the format expected by Solidity.
///
/// # Arguments
/// * `field_element` - Field element to convert
///
/// # Returns
/// * u32 representation of the field element
fn field_element_to_u32(field_element: Fr) -> u32 {
    let bytes = field_element.into_bigint().to_bytes_be();
    u32::from_be_bytes([
        bytes.get(28).copied().unwrap_or(0),
        bytes.get(29).copied().unwrap_or(0),
        bytes.get(30).copied().unwrap_or(0),
        bytes.get(31).copied().unwrap_or(0),
    ])
}

/// Input parameters for the DarkMint proof system
///
/// Contains all necessary data read from the zkVM input stream
/// for generating the zero-knowledge proof.
#[derive(Debug)]
struct ProofInputs {
    burn_preimage: Vec<u8>,
    lower_layer_prefix_len: u32,
    lower_layer_prefix: Vec<u8>,
    nonce: u64,
    balance: u128,
    storage_hash: [u8; 32],
    code_hash: [u8; 32],
    account_proof: Vec<Vec<u8>>,
    state_root: [u8; 32],
    salt: u32,
    encrypted: bool,
}

/// Read all input parameters from the zkVM input stream
///
/// # Returns
/// * Structured input parameters for proof generation
fn read_proof_inputs() -> ProofInputs {
    ProofInputs {
        burn_preimage: sp1_zkvm::io::read::<Vec<u8>>(),
        lower_layer_prefix_len: sp1_zkvm::io::read::<u32>(),
        lower_layer_prefix: sp1_zkvm::io::read::<Vec<u8>>(),
        nonce: sp1_zkvm::io::read::<u64>(),
        balance: sp1_zkvm::io::read::<u128>(),
        storage_hash: sp1_zkvm::io::read::<[u8; 32]>(),
        code_hash: sp1_zkvm::io::read::<[u8; 32]>(),
        account_proof: sp1_zkvm::io::read::<Vec<Vec<u8>>>(),
        state_root: sp1_zkvm::io::read::<[u8; 32]>(),
        salt: sp1_zkvm::io::read::<u32>(),
        encrypted: sp1_zkvm::io::read::<bool>(),
    }
}

/// Print debug information about input parameters
///
/// # Arguments
/// * `inputs` - Input parameters to log
fn log_input_parameters(inputs: &ProofInputs, burn_preimage_fr: Fr) {
    println!("burn_preimage: {:?}", burn_preimage_fr);
    println!("lower_layer_prefix_len: {}", inputs.lower_layer_prefix_len);
    println!("lower_layer_prefix: {:?}", inputs.lower_layer_prefix);
    println!("nonce: {}", inputs.nonce);
    println!("balance: {}", inputs.balance);
    println!("storage_hash: 0x{}", hex::encode(inputs.storage_hash));
    println!("code_hash: 0x{}", hex::encode(inputs.code_hash));
}

/// Process MPT path proofs for all layers
///
/// This function handles the verification of all intermediate and top layers
/// in the MPT proof chain, generating commitments for each layer and verifying
/// the final state root.
///
/// # Arguments
/// * `account_proof` - Vector of proof layers from bottom to top
/// * `state_root` - Expected Ethereum state root hash
/// * `salt` - Salt for commitment generation
///
/// # Returns
/// * Tuple of (path_proofs, layers, root_proof) as u32 vectors/option
///
/// # Panics
/// * If state root verification fails
/// * If any intermediate layer verification fails
fn process_mpt_path_proofs(
    account_proof: Vec<Vec<u8>>,
    state_root: [u8; 32],
    salt_fr: Fr,
) -> (Vec<u32>, Vec<u32>, Option<u32>) {
    let mut layers: Vec<u32> = vec![];
    let mut path_proofs: Vec<u32> = vec![];
    let mut rev_proof = account_proof;
    rev_proof.reverse();
    let mut root_proof: Option<u32> = None;

    // Process each layer in the reversed proof (bottom to top)
    for (index, level) in rev_proof.iter().enumerate() {
        if index == rev_proof.len() - 1 {
            // Top layer - verify against state root
            verify_state_root(level, &state_root);
            root_proof = Some(generate_root_proof(level, salt_fr));
        } else {
            // Intermediate layer - verify against next level
            let next_level = &rev_proof[index + 1];
            verify_intermediate_layer(level, next_level, index);

            let (path_proof, layer_commitment) = generate_path_proof(level, next_level, salt_fr);
            path_proofs.push(path_proof);
            layers.push(layer_commitment);
        }
    }

    (path_proofs, layers, root_proof)
}

/// Verify that the top layer matches the expected state root
///
/// # Arguments
/// * `level` - Top layer data
/// * `state_root` - Expected state root
///
/// # Panics
/// * If state root verification fails
fn verify_state_root(level: &[u8], state_root: &[u8; 32]) {
    let level_hash = compute_keccak256(level);
    let level_hash_bytes = level_hash.as_slice();
    let state_root_bytes = state_root.as_slice();

    if level_hash_bytes != state_root_bytes {
        panic!("State root verification failed!");
    }
}

/// Generate root proof for the top layer
///
/// # Arguments
/// * `level` - Top layer data
/// * `salt_fr` - Salt for commitment generation
///
/// # Returns
/// * Root proof as u32
fn generate_root_proof(level: &[u8], salt_fr: Fr) -> u32 {
    let root_proof_inputs = MptPathInputs {
        is_top: true,
        num_upper_layer_bytes: 1, // When is_top is true, use minimal size
        upper_layer_bytes: vec![0; 136], // Use zeros when is_top is true
        num_lower_layer_bytes: level.len() as u32,
        lower_layer_bytes: level.to_vec(),
        salt: salt_fr,
    };

    let root_proof_outputs = mpt_path_circuit(root_proof_inputs);
    field_element_to_u32(root_proof_outputs.commit_upper)
}

/// Verify intermediate layer against the next layer
///
/// # Arguments
/// * `level` - Current layer data
/// * `next_level` - Next layer data
/// * `index` - Layer index for error reporting
///
/// # Panics
/// * If layer verification fails
fn verify_intermediate_layer(level: &[u8], next_level: &[u8], index: usize) {
    let level_hash = compute_keccak256(level);

    if !contains_substring(level_hash.as_slice(), next_level) {
        panic!("MPT path verification failed at level {}!", index);
    }
}

/// Generate path proof for intermediate layer
///
/// # Arguments
/// * `level` - Current layer data
/// * `next_level` - Next layer data
/// * `salt_fr` - Salt for commitment generation
///
/// # Returns
/// * Tuple of (path_proof, layer_commitment) as u32 values
fn generate_path_proof(level: &[u8], next_level: &[u8], salt_fr: Fr) -> (u32, u32) {
    let path_proof_inputs = MptPathInputs {
        is_top: false,
        num_upper_layer_bytes: next_level.len() as u32,
        upper_layer_bytes: next_level.to_vec(),
        num_lower_layer_bytes: level.len() as u32,
        lower_layer_bytes: level.to_vec(),
        salt: salt_fr,
    };

    let path_proof_outputs = mpt_path_circuit(path_proof_inputs);
    let path_proof = field_element_to_u32(path_proof_outputs.commit_upper);
    let layer_commitment = field_element_to_u32(path_proof_outputs.commit_lower);

    (path_proof, layer_commitment)
}

/// Generate and commit the final proof outputs
///
/// This function encodes the public values and proof data, then commits them
/// to the zkVM output stream for verification by external parties.
///
/// # Arguments
/// * `burn_preimage` - Original burn preimage bytes
/// * `commit_upper` - Upper layer commitment
/// * `encrypted_balance` - Processed balance value
/// * `nullifier` - Unique nullifier for double-spend prevention
/// * `encrypted` - Whether balance is encrypted
/// * `path_proofs` - Path proof commitments for intermediate layers
/// * `layers` - Layer commitments
/// * `root_proof` - Optional root proof commitment
fn commit_proof_outputs(
    burn_preimage: &[u8],
    commit_upper: u32,
    encrypted_balance: u32,
    nullifier: u32,
    encrypted: bool,
    path_proofs: &[u32],
    layers: &[u32],
    root_proof: Option<u32>,
) {
    // Encode the main public values
    let public_values = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        burn_preimage: burn_preimage.to_vec().into(),
        commit_upper,
        encrypted_balance,
        nullifier,
        encrypted,
    });

    // Encode the MPT path proof data
    let proof_data = encode_proof_data(path_proofs, layers, root_proof);

    // Commit both sets of data to the zkVM output
    sp1_zkvm::io::commit_slice(&public_values);
    sp1_zkvm::io::commit_slice(&proof_data);
}

/// Encode MPT path proof data into a byte array
///
/// # Arguments
/// * `path_proofs` - Path proof commitments
/// * `layers` - Layer commitments  
/// * `root_proof` - Optional root proof commitment
///
/// # Returns
/// * Encoded proof data as bytes
fn encode_proof_data(path_proofs: &[u32], layers: &[u32], root_proof: Option<u32>) -> Vec<u8> {
    let mut proof_data = Vec::new();

    // Encode path proofs
    proof_data.extend_from_slice(&(path_proofs.len() as u32).to_be_bytes());
    for proof in path_proofs {
        proof_data.extend_from_slice(&proof.to_be_bytes());
    }

    // Encode layer commitments
    proof_data.extend_from_slice(&(layers.len() as u32).to_be_bytes());
    for layer in layers {
        proof_data.extend_from_slice(&layer.to_be_bytes());
    }

    // Encode root proof if present
    if let Some(root_proof_val) = root_proof {
        proof_data.extend_from_slice(&root_proof_val.to_be_bytes());
    }

    proof_data
}

pub fn main() {
    // Step 1: Read all input parameters from zkVM
    let inputs = read_proof_inputs();

    // Step 2: Convert inputs to appropriate types for circuit
    let burn_preimage_fr = Fr::from_be_bytes_mod_order(inputs.burn_preimage.as_slice());
    let salt_fr = Fr::from(inputs.salt);

    // Step 3: Log input parameters for debugging
    log_input_parameters(&inputs, burn_preimage_fr);

    // Step 4: Execute account verification circuit
    let circuit_inputs = MptLastInputs {
        burn_preimage: burn_preimage_fr,
        lower_layer_prefix_len: inputs.lower_layer_prefix_len,
        lower_layer_prefix: inputs.lower_layer_prefix.clone(),
        nonce: inputs.nonce,
        balance: inputs.balance,
        storage_hash: inputs.storage_hash,
        code_hash: inputs.code_hash,
        salt: salt_fr,
        encrypted: inputs.encrypted,
    };

    let circuit_outputs = mpt_last_circuit(circuit_inputs);

    // Step 5: Convert circuit outputs to u32 format for public values
    let commit_upper_u32 = field_element_to_u32(circuit_outputs.commit_upper);
    let encrypted_balance_u32 = field_element_to_u32(circuit_outputs.encrypted_balance);
    let nullifier_u32 = field_element_to_u32(circuit_outputs.nullifier);

    // Step 6: Process MPT path proofs for all layers
    let (path_proofs, layers, root_proof) =
        process_mpt_path_proofs(inputs.account_proof, inputs.state_root, salt_fr);

    // Step 7: Generate and commit public values and proof data
    commit_proof_outputs(
        &inputs.burn_preimage,
        commit_upper_u32,
        encrypted_balance_u32,
        nullifier_u32,
        inputs.encrypted,
        &path_proofs,
        &layers,
        root_proof,
    );
}
