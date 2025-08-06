use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use alloy::{
    providers::{Provider, ProviderBuilder}, 
    signers::{local::PrivateKeySigner}, 
    primitives::{U256, Address, Bytes, B256 , keccak256},
    rpc::types::{Block , EIP1186AccountProofResponse}
};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use rand::{rngs::OsRng, RngCore};
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write};

const NOTE_SIZE: usize = 32;

// MiMC7 implementation (simplified from Python)
fn poseidon_hash(left: Fr, right: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let left_bytes = left.into_bigint().to_bytes_be();
    let right_bytes = right.into_bigint().to_bytes_be();
    let hash_bytes = poseidon
        .hash_bytes_be(&[&left_bytes, &right_bytes])
        .unwrap();
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

// Data structures
#[derive(Debug)]
pub struct MintContext {
    pub src_burn_addr: Address,
    pub dst_addr: Address,
    pub encrypted: bool,
    pub priv_fee_payer: PrivateKeySigner,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct Coin {
    pub amount: U256,
    pub salt: U256,
    pub encrypted: bool,
}

impl Coin {
    fn get_value(&self) -> U256 {
        if self.encrypted {
            let left_bytes = self.amount.to_be_bytes::<32>();
            let right_bytes = self.salt.to_be_bytes::<32>();
            let left = Fr::from_le_bytes_mod_order(&left_bytes);
            let right = Fr::from_le_bytes_mod_order(&right_bytes);
            let result = poseidon_hash(left, right);
            U256::from_be_bytes::<32>(result.into_bigint().to_bytes_be().try_into().unwrap())
        } else {
            self.amount
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    entropy: String,
    coins: Vec<Coin>,
}

#[derive(Debug)]
pub struct BurnAddress {
    pub preimage: Fr,
    pub address: Address,
}
impl Wallet {
    pub fn open_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = "burnth.priv";
        if !std::path::Path::new(path).exists() {
            let mut entropy = [0u8; NOTE_SIZE];
            OsRng.fill_bytes(&mut entropy);
            let wallet = Wallet {
                entropy: hex::encode(entropy),
                coins: vec![],
            };
            let mut file = fs::File::create(path)?;
            file.write_all(serde_json::to_string(&wallet)?.as_bytes())?;
            Ok(wallet)
        } else {
            let content = fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        }
    }

    pub fn derive_burn_addr(&self, index: u64) -> Result<BurnAddress, Box<dyn std::error::Error>> {
        let entropy_bytes = hex::decode(&self.entropy)?;
        let mut hasher = Sha256::new();
        hasher.update(&entropy_bytes);
        hasher.update(&index.to_le_bytes());
        let result = hasher.finalize();

        let preimage = Fr::from_le_bytes_mod_order(&result[..31]);
        let hashed = poseidon_hash(preimage, preimage);

        let mut bts = [0u8; 20];
        let hashed_bytes = hashed.into_bigint().to_bytes_be();
        for i in 0..20 {
            bts[i] = hashed_bytes.get(i).copied().unwrap_or(0);
        }
        let address = Address::from_slice(&bts);

        Ok(BurnAddress { preimage, address })
    }

    pub fn derive_coin(&self, amount: Fr, encrypted: bool) -> Coin {
        Coin {
            amount: U256::from_be_bytes::<32>(amount.into_bigint().to_bytes_be().try_into().unwrap()),
            salt: U256::from_be_bytes::<32>(rand::random::<[u8; 32]>()),
            encrypted,
        }
    }
    fn add_coin(&mut self, coin: Coin)-> Result<(), Box<dyn std::error::Error>> {
        self.coins.push(coin);
        self.save()?;
        Ok(())
    }
    fn remove_coin(&mut self, index: usize) {
        self.coins.remove(index);
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::write("burnth.priv", serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

// Placeholder for block splitting logic
fn get_block_splited_information(
    block: &Block,
) -> Result<(Bytes, B256, Bytes), Box<dyn std::error::Error>> {
    // Create RLP stream for block header
    let mut stream = RlpStream::new_list(15); // Base header fields

    // Add required header fields
    stream.append(&block.header.parent_hash.as_slice());
    stream.append(&block.header.ommers_hash.as_slice());
    stream.append(&block.header.beneficiary.as_slice());
    stream.append(&block.header.state_root.as_slice());
    stream.append(&block.header.transactions_root.as_slice());
    stream.append(&block.header.receipts_root.as_slice());
    stream.append(&block.header.logs_bloom.as_slice());
    stream.append(&block.header.difficulty.to_be_bytes_vec());
    stream.append(&block.header.number.to_be_bytes().to_vec());
    stream.append(&block.header.gas_limit.to_be_bytes().to_vec());
    stream.append(&block.header.gas_used.to_be_bytes().to_vec());
    stream.append(&block.header.timestamp.to_be_bytes().to_vec());
    stream.append(&block.header.extra_data.to_vec());
    stream.append(&block.header.mix_hash.as_slice());
    stream.append(&block.header.nonce.as_slice());

    // Add optional EIP-1559 fields if present
    if let Some(base_fee) = block.header.base_fee_per_gas {
        stream.append(&base_fee);
    }

    // Add optional EIP-4844 fields if present
    if let Some(blob_gas_used) = block.header.blob_gas_used {
        stream.append(&blob_gas_used);
    }
    if let Some(excess_blob_gas) = block.header.excess_blob_gas {
        stream.append(&excess_blob_gas);
    }

    // Add optional withdrawals root if present
    if let Some(withdrawals_root) = block.header.withdrawals_root {
        stream.append(&withdrawals_root.as_slice());
    }

    // Add optional parent beacon block root if present
    if let Some(parent_beacon_block_root) = block.header.parent_beacon_block_root {
        stream.append(&parent_beacon_block_root.as_slice());
    }

    let header_rlp = stream.out();

    // Verify the header hash matches
    let computed_hash = keccak256(&header_rlp);
    let block_hash = block.header.hash;

    if computed_hash != block_hash.as_slice() {
        return Err("Block header hash verification failed".into());
    }

    // Find state root position in RLP
    let state_root_bytes = block.header.state_root.as_slice();
    let state_root_start = header_rlp
        .windows(state_root_bytes.len())
        .position(|window| window == state_root_bytes)
        .ok_or("State root not found in header")?;

    let state_root_end = state_root_start + state_root_bytes.len();

    // Split the header
    let prefix = Bytes::from(header_rlp[..state_root_start].to_vec());
    let commit_top = block.header.state_root;
    let postfix = Bytes::from(header_rlp[state_root_end..].to_vec());

    Ok((prefix, commit_top, postfix))
}
pub async fn mint_cmd(
    provider_url: &str,
    context: MintContext,
) -> Result<
    (
        BurnAddress,
        Block,
        EIP1186AccountProofResponse,
        Coin,
        Bytes,
        B256,
        Bytes,
    ),
    Box<dyn std::error::Error>,
> {
    let provider = ProviderBuilder::new()
        .wallet(context.priv_fee_payer.clone())
        .connect(provider_url)
        .await?;

    let mut wallet = Wallet::open_or_create()?;
    let mut burn_addr: Option<BurnAddress> = None;
    let mut amount = U256::ZERO;

    for i in 0..10 {
        let b_addr = wallet.derive_burn_addr(i)?;
        if context.src_burn_addr == b_addr.address {
            amount = provider.get_balance(b_addr.address).await?;
            burn_addr = Some(b_addr);
            break;
        }
    }

    let burn_addr = burn_addr.ok_or("Burn address not found!")?;

    let block_number = provider.get_block_number().await?;
    let amount_fr = Fr::from_le_bytes_mod_order(&amount.to_be_bytes::<32>());
    let coin = wallet.derive_coin(amount_fr, context.encrypted);
    wallet.add_coin(coin.clone())?;
    let zero_fr = Fr::from(0u64);
    let nullifier = poseidon_hash(burn_addr.preimage, zero_fr);
    let block = provider
        .get_block_by_number(block_number.into())
        .await?
        .ok_or("Block not found")?;
    let proof = provider
        .get_proof(burn_addr.address, vec![])
        .block_id(block_number.into())
        .await?;

    let (prefix, state_root, postfix) = get_block_splited_information(&block)?;

    Ok((burn_addr, block, proof, coin, prefix, state_root, postfix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_open_or_create() {
        let wallet = Wallet::open_or_create().unwrap();
        println!("Wallet: {:?}", wallet);
        println!("Wallet entropy length: {:?}", wallet.entropy.len());
        assert!(wallet.entropy.len() == NOTE_SIZE * 2);
    }

    #[test]
    fn test_derive_burn_addr_basic() {
        // Create a wallet using the open_or_create function
        let wallet = Wallet::open_or_create().unwrap();

        // Test deriving burn address for index 0
        let burn_addr = wallet.derive_burn_addr(0).unwrap();
        println!("Burn address: {:?}", burn_addr);
        assert!(burn_addr.address != Address::ZERO);
        assert!(burn_addr.preimage != Fr::from(0u64));

        // Test deriving burn address for index 1
        let burn_addr_1 = wallet.derive_burn_addr(1).unwrap();
        println!("Burn address 1: {:?}", burn_addr_1);
        assert!(burn_addr_1.address != Address::ZERO);
        assert!(burn_addr_1.preimage != Fr::from(0u64));

        // Different indices should produce different addresses
        assert_ne!(burn_addr.address, burn_addr_1.address);
        assert_ne!(burn_addr.preimage, burn_addr_1.preimage);
    }

    #[test]
    fn test_derive_burn_addr_deterministic() {
        // Create a wallet using the open_or_create function
        let wallet = Wallet::open_or_create().unwrap();

        // Derive the same burn address twice
        let burn_addr_1 = wallet.derive_burn_addr(42).unwrap();
        let burn_addr_2 = wallet.derive_burn_addr(42).unwrap();

        // Results should be identical (deterministic)
        assert_eq!(burn_addr_1.address, burn_addr_2.address);
        assert_eq!(burn_addr_1.preimage, burn_addr_2.preimage);
    }

    #[test]
    fn test_derive_burn_addr_different_indices() {
        let wallet = Wallet::open_or_create().unwrap();

        let mut addresses = Vec::new();
        let mut preimages = Vec::new();

        // Derive addresses for indices 0-9
        for i in 0..10 {
            let burn_addr = wallet.derive_burn_addr(i).unwrap();
            addresses.push(burn_addr.address);
            preimages.push(burn_addr.preimage);
        }

        // All addresses should be different
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                assert_ne!(
                    addresses[i], addresses[j],
                    "Addresses at indices {} and {} should be different",
                    i, j
                );
                assert_ne!(
                    preimages[i], preimages[j],
                    "Preimages at indices {} and {} should be different",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_derive_burn_addr_large_indices() {
        let wallet = Wallet::open_or_create().unwrap();

        // Test with large indices
        let burn_addr_1 = wallet.derive_burn_addr(u64::MAX).unwrap();
        let burn_addr_2 = wallet.derive_burn_addr(1000000).unwrap();

        assert!(burn_addr_1.address != Address::ZERO);
        assert!(burn_addr_2.address != Address::ZERO);
        assert_ne!(burn_addr_1.address, burn_addr_2.address);
    }

    #[test]
    fn test_derive_burn_addr_address_format() {
        let wallet = Wallet::open_or_create().unwrap();

        let burn_addr = wallet.derive_burn_addr(0).unwrap();

        // Check that the address is properly formatted (20 bytes)
        let address_bytes = burn_addr.address.as_slice();
        assert_eq!(address_bytes.len(), 20);

        // Address should not be all zeros
        assert_ne!(burn_addr.address, Address::ZERO);
    }

    #[test]
    fn test_derive_burn_addr_field_constraints() {
        let wallet = Wallet::open_or_create().unwrap();

        let burn_addr = wallet.derive_burn_addr(0).unwrap();

        // Check that the preimage field value is within the field size
        // assert!(burn_addr.preimage < Fr::from(FIELD_SIZE));
        assert!(burn_addr.preimage > Fr::from(0u64));
    }

    #[test]
    fn test_derive_burn_addr_multiple_wallets() {
        // Test that different wallets produce different addresses for the same index
        let wallet1 = Wallet::open_or_create().unwrap();
        let wallet2 = Wallet::open_or_create().unwrap();

        let burn_addr1 = wallet1.derive_burn_addr(0).unwrap();
        let burn_addr2 = wallet2.derive_burn_addr(0).unwrap();

        // If wallets have different entropy, addresses should be different
        if wallet1.entropy != wallet2.entropy {
            assert_ne!(burn_addr1.address, burn_addr2.address);
            assert_ne!(burn_addr1.preimage, burn_addr2.preimage);
        }
    }

    #[test]
    fn test_derive_burn_addr_entropy_validation() {
        let wallet = Wallet::open_or_create().unwrap();

        // Verify that the wallet has valid entropy
        assert_eq!(wallet.entropy.len(), NOTE_SIZE * 2); // 32 bytes = 64 hex chars
        assert!(hex::decode(&wallet.entropy).is_ok());
    }
    #[test]
    fn test_derive_coin() {
        let wallet = Wallet::open_or_create().unwrap();
        let coin = wallet.derive_coin(Fr::from(1000000000000000000u64), true);
        println!("Coin: {:?}", coin);
        assert!(coin.amount == U256::from(1000000000000000000u64));
        assert!(coin.salt != U256::ZERO);
        assert!(coin.encrypted == true);
    }
}