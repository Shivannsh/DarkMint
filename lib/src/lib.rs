//! DarkMint Library
//!
//! A zero-knowledge privacy system for Ethereum that implements Modified Merkle Patricia Trie
//! proof verification using Poseidon hash functions instead of MiMC7.
//!
//! This library provides two main circuit implementations:
//! - MPT Last Circuit: Handles the final layer of MPT proofs for account verification
//! - MPT Path Circuit: Handles intermediate layers of MPT proofs for path verification

#![no_main]

pub mod account_verification;
pub mod crypto;
pub mod merkle_proof;

use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    /// These values represent the zero-knowledge proof outputs for the DarkMint system.
    struct PublicValuesStruct {
        bytes burn_preimage;        // Original preimage used to generate burn address
        uint32 commit_upper;        // Upper layer commitment hash
        uint32 encrypted_balance;   // Balance (encrypted or plaintext based on flag)
        uint32 nullifier;           // Unique nullifier to prevent double-spending
        bool encrypted;             // Whether the balance is encrypted
    }
}

// Re-export the main circuit functions for convenience
pub use account_verification::{
    verify_account_proof as mpt_last_circuit, AccountProofInputs as MptLastInputs,
    AccountProofOutputs as MptLastOutputs,
};
pub use merkle_proof::{
    verify_merkle_path as mpt_path_circuit, MerklePathInputs as MptPathInputs,
    MerklePathOutputs as MptPathOutputs,
};
