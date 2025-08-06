# MPT-Last Circuit Implementation for SP1 zkVM

This implementation explains the Modified-Merkle-Patricia-Trie-Proof-Verifier into the SP1 zkVM environment, using Poseidon hash.

## Overview

The MPT-last circuit implements the following functionality:

1. **Burn Address Calculation**: Derives a burn address from a preimage using Poseidon hash
2. **Nullifier Generation**: Creates a nullifier using Poseidon hash of the preimage and zero
3. **Balance Encryption**: Optionally encrypts account balances using Poseidon hash with salt
4. **RLP Encoding**: Encodes account data (nonce, balance, storage hash, code hash) using RLP
5. **Layer Commitment**: Calculates commitment to the upper layer using Poseidon hash

## Key Features

- **Poseidon Hash**: Replaces MiMC7 with Poseidon hash for better performance and security
- **SP1 zkVM Compatible**: Runs in the SP1 zkVM environment for zero-knowledge proof generation
- **Modular Design**: Clean separation between circuit logic and I/O handling
- **Comprehensive Testing**: Includes unit tests and integration tests

## Circuit Inputs

```rust
pub struct MptLastInputs {
    pub burn_preimage: Fr,           // Preimage for burn address generation
    pub lower_layer_prefix_len: u32, // Length of lower layer prefix
    pub lower_layer_prefix: Vec<u8>, // Lower layer prefix bytes
    pub nonce: u64,                  // Account nonce
    pub balance: u128,               // Account balance
    pub storage_hash: [u8; 32],     // Account storage hash
    pub code_hash: [u8; 32],        // Account code hash
    pub salt: Fr,                    // Random salt for encryption
    pub encrypted: bool,             // Whether balance is encrypted
}
```

## Circuit Outputs

```rust
pub struct MptLastOutputs {
    pub commit_upper: Fr,        // Commitment to upper layer
    pub encrypted_balance: Fr,   // Encrypted or plain balance
    pub nullifier: Fr,           // Nullifier for the burn address
}
```

## Usage

### In SP1 zkVM Program

```rust
// Read inputs from the prover
let burn_preimage = sp1_zkvm::io::read::<u32>();
let lower_layer_prefix_len = sp1_zkvm::io::read::<u32>();
let lower_layer_prefix = sp1_zkvm::io::read::<Vec<u8>>();
let nonce = sp1_zkvm::io::read::<u64>();
let balance = sp1_zkvm::io::read::<u128>();
let storage_hash = sp1_zkvm::io::read::<[u8; 32]>();
let code_hash = sp1_zkvm::io::read::<[u8; 32]>();
let salt = sp1_zkvm::io::read::<u32>();
let encrypted = sp1_zkvm::io::read::<bool>();

// Create circuit inputs
let inputs = MptLastInputs {
    burn_preimage: Fr::from(burn_preimage),
    lower_layer_prefix_len,
    lower_layer_prefix,
    nonce,
    balance,
    storage_hash,
    code_hash,
    salt: Fr::from(salt),
    encrypted,
};

// Execute circuit
let outputs = mpt_last_circuit(inputs);

// Commit public values
let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
    burn_preimage,
    commit_upper: outputs.commit_upper.into_bigint().to_u32().unwrap_or(0),
    encrypted_balance: outputs.encrypted_balance.into_bigint().to_u32().unwrap_or(0),
    nullifier: outputs.nullifier.into_bigint().to_u32().unwrap_or(0),
    encrypted,
});

sp1_zkvm::io::commit_slice(&bytes);
```

## Building and Proving

To build the SP1 program:
```bash
cd program
cargo prove build
```

To generate a proof:
```bash
cargo prove prove
```

## Dependencies

- `ark-bn254`: BN254 curve implementation
- `ark-ff`: Finite field arithmetic
- `light-poseidon`: Poseidon hash function
- `rlp`: RLP encoding/decoding
- `sha2`: SHA-256 for address hashing
- `sp1-zkvm`: SP1 zkVM runtime

## Security Considerations

1. **Poseidon Hash**: Uses the Poseidon hash function which is SNARK-friendly and secure
2. **Salt Usage**: Random salt prevents rainbow table attacks on encrypted balances
3. **Nullifier Generation**: Unique nullifiers prevent double-spending
4. **Field Arithmetic**: All operations are performed in the BN254 scalar field

