#![no_main]

pub mod mpt_last;
pub mod mpt_path;

use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes burn_preimage;
        uint32 commit_upper;
        uint32 encrypted_balance;
        uint32 nullifier;
        bool encrypted;
    }
}


// Re-export the main functions for convenience
pub use mpt_last::{mpt_last_circuit, MptLastInputs, MptLastOutputs};
pub use mpt_path::{mpt_path_circuit, MptPathInputs, MptPathOutputs};

