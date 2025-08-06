use ark_bn254::Fr;
use ark_ff::PrimeField;

use alloy::{
    primitives::{keccak256, Address, Bytes, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Block, EIP1186AccountProofResponse},
    signers::local::PrivateKeySigner,
};

use rlp::RlpStream;

use crate::{Coin, Wallet, BurnAddress};

/// Context for minting operations
/// 
/// Contains all necessary parameters for converting burned ETH
/// into privacy-preserving coins.
#[derive(Debug)]
pub struct MintContext {
    /// Source burn address to mint from
    pub src_burn_addr: Address,
    /// Destination address for the minting transaction
    pub dst_addr: Address,
    /// Whether the resulting coin should be encrypted
    pub encrypted: bool,
    /// Private key signer for paying transaction fees
    pub priv_fee_payer: PrivateKeySigner,
}

// Placeholder for block splitting logic
fn get_block_splited_information(
    block: &Block,
) -> Result<(Bytes, B256, Bytes), Box<dyn std::error::Error>> {
    // Count fields dynamically
    let mut field_count = 15;
    if block.header.base_fee_per_gas.is_some() {
        field_count += 1;
    }
    if block.header.withdrawals_root.is_some() {
        field_count += 1;
    }
    if block.header.blob_gas_used.is_some() {
        field_count += 1;
    }
    if block.header.excess_blob_gas.is_some() {
        field_count += 1;
    }
    if block.header.parent_beacon_block_root.is_some() {
        field_count += 1;
    }
    if block.header.requests_hash.is_some() {
        field_count += 1;
    }

    let mut stream = RlpStream::new();
    stream.begin_list(field_count);

    // Add fields in exact order with proper encoding
    stream.append(&block.header.parent_hash.as_slice());
    stream.append(&block.header.ommers_hash.as_slice());
    stream.append(&block.header.beneficiary.as_slice());
    stream.append(&block.header.state_root.as_slice());
    stream.append(&block.header.transactions_root.as_slice());
    stream.append(&block.header.receipts_root.as_slice());
    stream.append(&block.header.logs_bloom.as_slice());

    // Handle integers with minimal encoding (remove leading zeros)
    let difficulty_bytes = if block.header.difficulty == U256::ZERO {
        Vec::new()
    } else {
        remove_leading_zeros(&block.header.difficulty.to_be_bytes_vec())
    };
    stream.append(&difficulty_bytes);

    let number_bytes = if block.header.number == 0 {
        Vec::new()
    } else {
        remove_leading_zeros(&block.header.number.to_be_bytes())
    };
    stream.append(&number_bytes);

    let gas_limit_bytes = remove_leading_zeros(&block.header.gas_limit.to_be_bytes());
    stream.append(&gas_limit_bytes);

    let gas_used_bytes = remove_leading_zeros(&block.header.gas_used.to_be_bytes());
    stream.append(&gas_used_bytes);

    let timestamp_bytes = remove_leading_zeros(&block.header.timestamp.to_be_bytes());
    stream.append(&timestamp_bytes);

    stream.append(&block.header.extra_data.to_vec());
    stream.append(&block.header.mix_hash.as_slice());
    stream.append(&block.header.nonce.as_slice());

    // Add optional fields only if they exist
    if let Some(base_fee) = block.header.base_fee_per_gas {
        let base_fee_bytes = if base_fee == 0 {
            Vec::new()
        } else {
            remove_leading_zeros(&base_fee.to_be_bytes())
        };
        stream.append(&base_fee_bytes);
    }

    if let Some(withdrawals_root) = block.header.withdrawals_root {
        stream.append(&withdrawals_root.as_slice());
    }

    if let Some(blob_gas_used) = block.header.blob_gas_used {
        let blob_gas_used_bytes = if blob_gas_used == 0 {
            Vec::new()
        } else {
            remove_leading_zeros(&blob_gas_used.to_be_bytes())
        };
        stream.append(&blob_gas_used_bytes);
    }

    if let Some(excess_blob_gas) = block.header.excess_blob_gas {
        let excess_blob_gas_bytes = if excess_blob_gas == 0 {
            Vec::new()
        } else {
            remove_leading_zeros(&excess_blob_gas.to_be_bytes())
        };
        stream.append(&excess_blob_gas_bytes);
    }

    if let Some(parent_beacon_block_root) = block.header.parent_beacon_block_root {
        stream.append(&parent_beacon_block_root.as_slice());
    }

    if let Some(requests_hash) = block.header.requests_hash {
        stream.append(&requests_hash.as_slice());
    }

    let header_rlp = stream.out();

    // CORRECT: Direct keccak256 hash of RLP
    let computed_hash = keccak256(&header_rlp);
    let block_hash = block.header.hash;

    
    if computed_hash.as_slice() != block_hash.as_slice() {
        println!(
            "Hash mismatch! Expected: {:?}, Got: {:?}",
            block_hash.as_slice(),
            computed_hash.as_slice()
        );
        return Err("Block header hash verification failed".into());
    } else {
        println!("Hash matches!");
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

// Helper function to remove leading zeros
fn remove_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().skip_while(|&&x| x == 0).copied().collect()
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
        let b_addr = wallet.derive_burn_address(i)?;
        if context.src_burn_addr == b_addr.address {
            amount = provider.get_balance(b_addr.address).await?;
            burn_addr = Some(b_addr);
            break;
        }
    }

    let burn_addr = burn_addr.ok_or("Burn address not found!")?;

    let block_number = provider.get_block_number().await?;
    let amount_fr = Fr::from_le_bytes_mod_order(&amount.to_be_bytes::<32>());
    let coin = wallet.create_coin(amount_fr, context.encrypted);
    wallet.add_coin(coin.clone())?;
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

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_wallet_open_or_create() {
//         let wallet = Wallet::open_or_create().unwrap();
//         println!("Wallet: {:?}", wallet);
//         println!("Wallet entropy length: {:?}", wallet.entropy.len());
//         assert!(wallet.entropy.len() == NOTE_SIZE * 2);
//     }

//     #[test]
//     fn test_derive_burn_addr_basic() {
//         // Create a wallet using the open_or_create function
//         let wallet = Wallet::open_or_create().unwrap();

//         // Test deriving burn address for index 0
//         let burn_addr = wallet.derive_burn_address(0).unwrap();
//         println!("Burn address: {:?}", burn_addr);
//         assert!(burn_addr.address != Address::ZERO);
//         assert!(burn_addr.preimage != Fr::from(0u64));

//         // Test deriving burn address for index 1
//         let burn_addr_1 = wallet.derive_burn_address(1).unwrap();
//         println!("Burn address 1: {:?}", burn_addr_1);
//         assert!(burn_addr_1.address != Address::ZERO);
//         assert!(burn_addr_1.preimage != Fr::from(0u64));

//         // Different indices should produce different addresses
//         assert_ne!(burn_addr.address, burn_addr_1.address);
//         assert_ne!(burn_addr.preimage, burn_addr_1.preimage);
//     }

//     #[test]
//     fn test_derive_burn_addr_deterministic() {
//         // Create a wallet using the open_or_create function
//         let wallet = Wallet::open_or_create().unwrap();

//         // Derive the same burn address twice
//         let burn_addr_1 = wallet.derive_burn_address(42).unwrap();
//         let burn_addr_2 = wallet.derive_burn_address(42).unwrap();

//         // Results should be identical (deterministic)
//         assert_eq!(burn_addr_1.address, burn_addr_2.address);
//         assert_eq!(burn_addr_1.preimage, burn_addr_2.preimage);
//     }

//     #[test]
//     fn test_derive_burn_addr_different_indices() {
//         let wallet = Wallet::open_or_create().unwrap();

//         let mut addresses = Vec::new();
//         let mut preimages = Vec::new();

//         // Derive addresses for indices 0-9
//         for i in 0..10 {
//             let burn_addr = wallet.derive_burn_address(i).unwrap();
//             addresses.push(burn_addr.address);
//             preimages.push(burn_addr.preimage);
//         }

//         // All addresses should be different
//         for i in 0..addresses.len() {
//             for j in (i + 1)..addresses.len() {
//                 assert_ne!(
//                     addresses[i], addresses[j],
//                     "Addresses at indices {} and {} should be different",
//                     i, j
//                 );
//                 assert_ne!(
//                     preimages[i], preimages[j],
//                     "Preimages at indices {} and {} should be different",
//                     i, j
//                 );
//             }
//         }
//     }

//     #[test]
//     fn test_derive_burn_addr_large_indices() {
//         let wallet = Wallet::open_or_create().unwrap();

//         // Test with large indices
//         let burn_addr_1 = wallet.derive_burn_address(u64::MAX).unwrap();
//         let burn_addr_2 = wallet.derive_burn_address(1000000).unwrap();

//         assert!(burn_addr_1.address != Address::ZERO);
//         assert!(burn_addr_2.address != Address::ZERO);
//         assert_ne!(burn_addr_1.address, burn_addr_2.address);
//     }

//     #[test]
//     fn test_derive_burn_addr_address_format() {
//         let wallet = Wallet::open_or_create().unwrap();

//         let burn_addr = wallet.derive_burn_address(0).unwrap();

//         // Check that the address is properly formatted (20 bytes)
//         let address_bytes = burn_addr.address.as_slice();
//         assert_eq!(address_bytes.len(), 20);

//         // Address should not be all zeros
//         assert_ne!(burn_addr.address, Address::ZERO);
//     }

//     #[test]
//     fn test_derive_burn_addr_field_constraints() {
//         let wallet = Wallet::open_or_create().unwrap();

//         let burn_addr = wallet.derive_burn_address(0).unwrap();

//         // Check that the preimage field value is within the field size
//         // assert!(burn_addr.preimage < Fr::from(FIELD_SIZE));
//         assert!(burn_addr.preimage > Fr::from(0u64));
//     }

//     #[test]
//     fn test_derive_burn_addr_multiple_wallets() {
//         // Test that different wallets produce different addresses for the same index
//         let wallet1 = Wallet::open_or_create().unwrap();
//         let wallet2 = Wallet::open_or_create().unwrap();

//         let burn_addr1 = wallet1.derive_burn_addr(0).unwrap();
//         let burn_addr2 = wallet2.derive_burn_addr(0).unwrap();

//         // If wallets have different entropy, addresses should be different
//         if wallet1.entropy != wallet2.entropy {
//             assert_ne!(burn_addr1.address, burn_addr2.address);
//             assert_ne!(burn_addr1.preimage, burn_addr2.preimage);
//         }
//     }

//     #[test]
//     fn test_derive_burn_addr_entropy_validation() {
//         let wallet = Wallet::open_or_create().unwrap();

        // Verify that the wallet has valid entropy
//         assert_eq!(wallet.entropy.len(), NOTE_SIZE * 2); // 32 bytes = 64 hex chars
//         assert!(hex::decode(&wallet.entropy).is_ok());
//     }
//     #[test]
//     fn test_derive_coin() {
//         let wallet = Wallet::open_or_create().unwrap();
//         let coin = wallet.create_coin(Fr::from(1000000000000000000u64), true);
//         println!("Coin: {:?}", coin);
//         assert!(coin.amount == U256::from(1000000000000000000u64));
//         assert!(coin.salt != U256::ZERO);
//         assert!(coin.encrypted == true);
//     }
// }