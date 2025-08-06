#![no_main]
use alloy_primitives::B256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Clone)]
pub struct MptLastInputs {
    pub burn_preimage: Fr,
    pub lower_layer_prefix_len: u32,
    pub lower_layer_prefix: Vec<u8>,
    pub nonce: u64,
    pub balance: u128,
    pub storage_hash: [u8; 32],
    pub code_hash: [u8; 32],
    pub salt: Fr,
    pub encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct MptLastOutputs {
    pub commit_upper: Fr,
    pub encrypted_balance: Fr,
    pub nullifier: Fr,
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

pub fn keccak256<T: AsRef<[u8]>>(input: T) -> B256 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(input.as_ref());
    hasher.finalize(&mut output);

    B256::from(output)
}

/// Hash address using Keccak-256
pub fn hash_address(address: &[u8; 20]) -> [u8; 32] {
    keccak256(address).0
}

/// RLP encoding for account data
pub fn rlp_encode_account(nonce: u64, balance: u128, storage_hash: &[u8; 32], code_hash: &[u8; 32]) -> Vec<u8> {
    use rlp::RlpStream;
    
    let mut stream = RlpStream::new_list(4);
    // Convert to big-endian for RLP encoding
    stream.append(&nonce.to_be_bytes().as_slice());
    stream.append(&balance.to_be_bytes().as_slice());
    stream.append(&storage_hash.as_slice());
    stream.append(&code_hash.as_slice());
    stream.out().to_vec()
}

/// Main MPT-last circuit implementation
pub fn mpt_last_circuit(inputs: MptLastInputs) -> MptLastOutputs {
    // 1. Calculate burn address from preimage
    let burn_hash = poseidon_hash(inputs.burn_preimage, inputs.burn_preimage);
    let burn_bytes = burn_hash.into_bigint().to_bytes_be();
    let mut address = [0u8; 20];
    for i in 0..20 {
        address[i] = burn_bytes.get(i).copied().unwrap_or(0);
    }

    // 2. Calculate nullifier
    let nullifier = poseidon_hash(inputs.burn_preimage, Fr::from(0u64));

    // 3. Calculate encrypted balance
    let balance_fr = Fr::from(inputs.balance);
    let balance_enc_hash = poseidon_hash(balance_fr, inputs.salt);
    let encrypted_balance = if inputs.encrypted {
        balance_enc_hash
    } else {
        balance_fr
    };

    // 4. RLP encode account data
    let account_rlp = rlp_encode_account(
        inputs.nonce,
        inputs.balance,
        &inputs.storage_hash,
        &inputs.code_hash
    );

    // 5. Hash address for prefix calculation
    let hash_address = hash_address(&address);

    // 6. Calculate expected prefix
    let security = 20;
    let mut expected_prefix = Vec::new();
    for i in 0..security {
        expected_prefix.push(hash_address[32 - security + i]);
    }
    expected_prefix.push(1 + 0x80 + 55); // RLP encoding for account
    expected_prefix.push(account_rlp.len() as u8);

    // 7. Concatenate layers
    let mut upper_layer_bytes = Vec::new();
    upper_layer_bytes.extend_from_slice(&inputs.lower_layer_prefix[..inputs.lower_layer_prefix_len as usize]);
    upper_layer_bytes.extend_from_slice(&account_rlp);

    // 8. Calculate commit_upper using Poseidon
    let upper_layer_hash = poseidon_hash(
        Fr::from_le_bytes_mod_order(&upper_layer_bytes[..32.min(upper_layer_bytes.len())]),
        Fr::from(upper_layer_bytes.len() as u64)
    );
    let commit_upper = poseidon_hash(upper_layer_hash, inputs.salt);

    MptLastOutputs {
        commit_upper,
        encrypted_balance,
        nullifier,
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
    fn test_mpt_last_circuit_basic() {
        let inputs = MptLastInputs {
            burn_preimage: Fr::from(123u64),
            lower_layer_prefix_len: 0,
            lower_layer_prefix: vec![],
            nonce: 0,
            balance: 1000000000000000000u128, // 1 ETH
            storage_hash: [0u8; 32],
            code_hash: [0u8; 32],
            salt: Fr::from(789u64),
            encrypted: false,
        };

        let outputs = mpt_last_circuit(inputs);
        
        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.encrypted_balance, Fr::from(0u64));
        assert_ne!(outputs.nullifier, Fr::from(0u64));
        
        // Verify encrypted balance equals balance when not encrypted
        assert_eq!(outputs.encrypted_balance, Fr::from(1000000000000000000u128));
    }

    #[test]
    fn test_mpt_last_circuit_encrypted() {
        let inputs = MptLastInputs {
            burn_preimage: Fr::from(123u64),
            lower_layer_prefix_len: 0,
            lower_layer_prefix: vec![],
            nonce: 0,
            balance: 1000000000000000000u128, // 1 ETH
            storage_hash: [0u8; 32],
            code_hash: [0u8; 32],
            salt: Fr::from(789u64),
            encrypted: true,
        };

        let outputs = mpt_last_circuit(inputs);
        
        // Verify outputs are not zero
        assert_ne!(outputs.commit_upper, Fr::from(0u64));
        assert_ne!(outputs.encrypted_balance, Fr::from(0u64));
        assert_ne!(outputs.nullifier, Fr::from(0u64));
        
        // Verify encrypted balance is different from original balance when encrypted
        assert_ne!(outputs.encrypted_balance, Fr::from(1000000000000000000u128));
    }

    #[test]
    fn test_hash_address() {
        let address = [1u8; 20];
        let hash = hash_address(&address);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_rlp_encode_account() {
        let nonce = 42u64;
        let balance = 1000000000000000000u128;
        let storage_hash = [1u8; 32];
        let code_hash = [2u8; 32];
        
        let rlp = rlp_encode_account(nonce, balance, &storage_hash, &code_hash);
        assert!(!rlp.is_empty());
    }
} 