//! MPT-last circuit implementation for SP1 zkVM
//! This implements the Modified-Merkle-Patricia-Trie-Proof-Verifier
//! Based on the circom circuit but using Poseidon hash instead of MiMC7

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use fibonacci_lib::PublicValuesStruct;
use sha2::{digest::consts::U256, Digest};
use fibonacci_lib::{mpt_last_circuit, MptLastInputs, MptPathInputs, mpt_path_circuit};

/// Keccak-256 hash function (using SHA-256 as approximation)
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Check if a substring exists in a larger string
fn substring_check(substring: &[u8], main_string: &[u8]) -> bool {
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

pub fn main() {
    // Read inputs for the MPT-last circuit
    let burn_preimage = sp1_zkvm::io::read::<Vec<u8>>();
    let lower_layer_prefix_len = sp1_zkvm::io::read::<u32>();
    let lower_layer_prefix = sp1_zkvm::io::read::<Vec<u8>>();
    let nonce = sp1_zkvm::io::read::<u64>();
    let balance = sp1_zkvm::io::read::<u128>();
    let storage_hash = sp1_zkvm::io::read::<[u8; 32]>();
    let code_hash = sp1_zkvm::io::read::<[u8; 32]>();
    let account_proof = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let state_root = sp1_zkvm::io::read::<[u8; 32]>();
    let salt = sp1_zkvm::io::read::<u32>();
    let encrypted = sp1_zkvm::io::read::<bool>();

    // Convert inputs to the appropriate types for the circuit
    let burn_preimage_fr = Fr::from_le_bytes_mod_order(burn_preimage.as_slice());
    let salt_fr = Fr::from(salt);

    println!("burn_preimage: {:?}", burn_preimage_fr);
    println!("lower_layer_prefix_len: {}", lower_layer_prefix_len);
    println!("lower_layer_prefix: {:?}", lower_layer_prefix);
    println!("nonce: {}", nonce);
    println!("balance: {}", balance);
    println!("storage_hash: {:?}", storage_hash);
    println!("code_hash: {:?}", code_hash);

        // Create the circuit inputs
        let inputs = MptLastInputs {
            burn_preimage: burn_preimage_fr,
            lower_layer_prefix_len,
            lower_layer_prefix,
            nonce,
            balance,
            storage_hash,
            code_hash,
            salt: salt_fr,
            encrypted,
        };

    let outputs = mpt_last_circuit(inputs);

        // Convert outputs to u32 for the public values struct
    // Use the first 4 bytes of the field element as u32
    let commit_upper_bytes = outputs.commit_upper.into_bigint().to_bytes_be();
    let encrypted_balance_bytes = outputs.encrypted_balance.into_bigint().to_bytes_be();
    let nullifier_bytes = outputs.nullifier.into_bigint().to_bytes_be();
    
    let commit_upper_u32 = u32::from_be_bytes([
        commit_upper_bytes.get(28).copied().unwrap_or(0),
        commit_upper_bytes.get(29).copied().unwrap_or(0),
        commit_upper_bytes.get(30).copied().unwrap_or(0),
        commit_upper_bytes.get(31).copied().unwrap_or(0),
    ]);
    
    let encrypted_balance_u32 = u32::from_be_bytes([
        encrypted_balance_bytes.get(28).copied().unwrap_or(0),
        encrypted_balance_bytes.get(29).copied().unwrap_or(0),
        encrypted_balance_bytes.get(30).copied().unwrap_or(0),
        encrypted_balance_bytes.get(31).copied().unwrap_or(0),
    ]);
    
    let nullifier_u32 = u32::from_be_bytes([
        nullifier_bytes.get(28).copied().unwrap_or(0),
        nullifier_bytes.get(29).copied().unwrap_or(0),
        nullifier_bytes.get(30).copied().unwrap_or(0),
        nullifier_bytes.get(31).copied().unwrap_or(0),
    ]);


    let mut layers: Vec<u32> = vec![];
    let mut path_proofs: Vec<u32> = vec![];
    let mut rev_proof = account_proof;
    rev_proof.reverse();
    let mut root_proof: Option<u32> = None;

        // Process MPT path proofs for each level in the reversed proof
        for (index, level) in rev_proof.iter().enumerate() {
            if index == rev_proof.len() - 1 {
                // Last level - verify against state root
                let level_hash = keccak256(level);
                if level_hash != state_root {
                    panic!("State root verification failed!");
                }
                
                // Generate root proof using MPT path circuit
                let root_proof_inputs = MptPathInputs {
                    is_top: true,
                    num_upper_layer_bytes: state_root.len() as u32,
                    upper_layer_bytes: state_root.to_vec(),
                    num_lower_layer_bytes: level.len() as u32,
                    lower_layer_bytes: level.clone(),
                    salt: salt_fr,
                };
                
                let root_proof_outputs = mpt_path_circuit(root_proof_inputs);
                let root_proof_bytes = root_proof_outputs.commit_upper.into_bigint().to_bytes_be();
                root_proof = Some(u32::from_be_bytes([
                    root_proof_bytes.get(28).copied().unwrap_or(0),
                    root_proof_bytes.get(29).copied().unwrap_or(0),
                    root_proof_bytes.get(30).copied().unwrap_or(0),
                    root_proof_bytes.get(31).copied().unwrap_or(0),
                ]));
            } else {
                // Middle levels - verify against next level
                let level_hash = keccak256(level);
                let next_level = &rev_proof[index + 1];
                
                if !substring_check(&level_hash, next_level) {
                    panic!("MPT path verification failed at level {}!", index);
                }
                
                // Generate path proof using MPT path circuit
                let path_proof_inputs = MptPathInputs {
                    is_top: false,
                    num_upper_layer_bytes: next_level.len() as u32,
                    upper_layer_bytes: next_level.clone(),
                    num_lower_layer_bytes: level.len() as u32,
                    lower_layer_bytes: level.clone(),
                    salt: salt_fr,
                };
                
                let path_proof_outputs = mpt_path_circuit(path_proof_inputs);
                let path_proof_bytes = path_proof_outputs.commit_upper.into_bigint().to_bytes_be();
                let layer_bytes = path_proof_outputs.commit_lower.into_bigint().to_bytes_be();
                
                path_proofs.push(u32::from_be_bytes([
                    path_proof_bytes.get(28).copied().unwrap_or(0),
                    path_proof_bytes.get(29).copied().unwrap_or(0),
                    path_proof_bytes.get(30).copied().unwrap_or(0),
                    path_proof_bytes.get(31).copied().unwrap_or(0),
                ]));
                
                layers.push(u32::from_be_bytes([
                    layer_bytes.get(28).copied().unwrap_or(0),
                    layer_bytes.get(29).copied().unwrap_or(0),
                    layer_bytes.get(30).copied().unwrap_or(0),
                    layer_bytes.get(31).copied().unwrap_or(0),
                ]));
            }
        }



    // Encode the public values of the program.
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        burn_preimage: burn_preimage.into(),
        commit_upper: commit_upper_u32,
        encrypted_balance: encrypted_balance_u32,
        nullifier: nullifier_u32,
        encrypted,
    });
      // Also commit the MPT path proof data
      let mut proof_data = Vec::new();
      proof_data.extend_from_slice(&(path_proofs.len() as u32).to_be_bytes());
      for proof in &path_proofs {
          proof_data.extend_from_slice(&proof.to_be_bytes());
      }
      proof_data.extend_from_slice(&(layers.len() as u32).to_be_bytes());
      for layer in &layers {
          proof_data.extend_from_slice(&layer.to_be_bytes());
      }
      if let Some(root_proof_val) = root_proof {
          proof_data.extend_from_slice(&root_proof_val.to_be_bytes());
      }

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);

    sp1_zkvm::io::commit_slice(&proof_data);
}