use alloy_sol_types::sol;
pub mod note;
pub mod mint;
pub mod burn;
pub mod mpt_last;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 burn_preimage;
        uint32 commit_upper;
        uint32 encrypted_balance;
        uint32 nullifier;
        bool encrypted;
    }
}

// Re-export the main function for convenience
pub use mpt_last::{mpt_last_circuit, MptLastInputs, MptLastOutputs};


