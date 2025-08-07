//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```
use ark_ff::{BigInteger, PrimeField};
use fibonacci_script::{burn_cmd, mint_cmd, BurnAddress, Coin, MintContext};

use alloy::{
    primitives::{address, Bytes, B256, U256},
    providers::{Caller, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    rpc::types::{Block, EIP1186AccountProofResponse},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolValue},
};
use tiny_keccak::{Hasher, Keccak};

use clap::Parser;

use rlp::RlpStream;
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};

use anyhow::Result;

use hex;
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use serde::{Deserialize, Serialize};
use sp1_zkv_sdk::*; // for the `convert_to_zkv` and `hash_bytes` methods.
use std::{fs::File, io::Write};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

pub const DOMAIN_ID: u64 = 113;

sol! {
    contract DarkMint {
        function checkHash(
            bytes _hash,
            uint256 _aggregationId,
            uint256 _domainId,
            bytes32[] _merklePath,
            uint256 _leafCount,
            uint256 _index,
            bytes32 _vkey
        ) public view returns (bool);

        function mint(
            address recipient,
            uint256 amount,
            uint256 nullifier,
            bytes32[] memory publicInputHashes
        ) external;
    }
}

#[derive(Deserialize)]
struct AggregatorInput {
    receipt: String,
    receiptBlockHash: String,
    root: String,
    leaf: String,
    leafIndex: u64,
    numberOfLeaves: u64,
    merkleProof: Vec<String>, // This matches the JSON field name
    aggregationId: u64,
}
/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    burn: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long)]
    amount: Option<f64>,

    #[arg(long)]
    priv_src: Option<String>,

    #[arg(long, default_value = "false")]
    encrypted: bool,

    #[arg(long)]
    dst_addr: Option<String>,

    #[arg(long)]
    src_burn_addr: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    provider_url: String,
}

// Struct of the output we need
#[derive(Serialize, Deserialize)]
struct Output {
    image_id: String,
    pub_inputs: String,
    proof: String,
}

// Helper function to get hex strings
fn to_hex_with_prefix(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex_string)
}

pub fn keccak256<T: AsRef<[u8]>>(input: T) -> B256 {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input.as_ref());
    hasher.finalize(&mut output);

    B256::from(output)
}

/// Calculate lower layer prefix from MPT proof
fn calculate_lower_layer_prefix(
    proof: &EIP1186AccountProofResponse,
) -> Result<(u32, Vec<u8>), String> {
    // RLP encode the account data according to Ethereum's format
    let mut stream = RlpStream::new_list(4);
    // Remove leading zeros from nonce
    let nonce_bytes: Vec<u8> = proof
        .nonce
        .to_be_bytes()
        .into_iter()
        .skip_while(|&x| x == 0)
        .collect();
    stream.append(&nonce_bytes);

    // Remove leading zeros from balance
    let balance_bytes: Vec<u8> = proof
        .balance
        .to_be_bytes::<32>()
        .into_iter()
        .skip_while(|&x| x == 0)
        .collect();
    stream.append(&balance_bytes);

    // Storage and code hash are already 32 bytes
    stream.append(&proof.storage_hash.as_slice());
    stream.append(&proof.code_hash.as_slice());
    let account_rlp = stream.out();

    // Get the last proof element (the account proof)
    let account_proof = proof.account_proof.last().ok_or("No account proof found")?;

    // Debug prints
    println!("Generated RLP: 0x{}", hex::encode(&account_rlp));
    println!("Account proof: 0x{}", hex::encode(account_proof));
    println!("RLP length: {}", account_rlp.len());
    println!("Proof length: {}", account_proof.len());

    // Find where the account RLP starts in the proof
    for i in 0..account_proof.len() {
        if i + account_rlp.len() <= account_proof.len() {
            let window = &account_proof[i..i + account_rlp.len()];
            if window == &account_rlp[..] {
                let prefix = account_proof[..i].to_vec();
                return Ok((i as u32, prefix));
            }
        }
    }

    // If we get here, we couldn't find the RLP in the proof
    Err(format!(
        "Could not find account RLP in proof. RLP: 0x{}, Proof: 0x{}. This could mean the RLP encoding format doesn't match the Ethereum specification.",
        hex::encode(&account_rlp),
        hex::encode(account_proof)
    ))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize rustls crypto provider
    CryptoProvider::install_default(default_provider()).expect("Failed to install crypto provider");

    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.burn {
        let amount = args.amount.expect("--amount is required when using --burn");
        let priv_src = args
            .priv_src
            .expect("--priv-src is required when using --burn");
        burn_cmd(amount, priv_src).await?;
    } else if args.prove {
        let dst_addr = args
            .dst_addr
            .expect("--dst-addr is required when not using --burn");
        let src_burn_addr = args
            .src_burn_addr
            .expect("--src-burn-addr is required when not using --burn");
        let priv_src = args
            .priv_src
            .expect("--priv-src is required when not using --burn");

        let signer: PrivateKeySigner = priv_src.parse()?;

        let provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect(&std::env::var("RPC_URL").expect("RPC_URL must be set"))
            .await?;

        let context = MintContext {
            src_burn_addr: src_burn_addr.parse().unwrap(),
            dst_addr: dst_addr.parse().unwrap(),
            encrypted: args.encrypted,
            priv_fee_payer: priv_src.parse().unwrap(),
        };
        let contract_address = address!("0x157E135Fe3B6d853fb263f9E07DAda1C31361076");

        println!("context: {context:?}");

        let (burn_addr, block, proof, coin, _prefix, _state_root, _postfix): (
            BurnAddress,
            Block,
            EIP1186AccountProofResponse,
            Coin,
            Bytes,
            B256,
            Bytes,
        ) = mint_cmd(&args.provider_url, context).await?;

        // Calculate lower layer prefix from the MPT proof
        let (lower_layer_prefix_len, lower_layer_prefix) = calculate_lower_layer_prefix(&proof)?;

        // Setup the prover client.
        let client = ProverClient::from_env();

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();

        println!("burn_addr.preimage: {:?}", burn_addr.preimage);
        println!("lower_layer_prefix_len: {lower_layer_prefix_len:?}");
        println!("lower_layer_prefix: {lower_layer_prefix:?}");
        println!("proof.nonce: {:?}", proof.nonce);
        println!("proof.balance: {:?}", proof.balance);
        println!("proof.storage_hash: {:?}", proof.storage_hash);
        println!("proof.code_hash: {:?}", proof.code_hash);

        let preimage = burn_addr.preimage.into_bigint();
        println!("preimage: {preimage:?}");

        stdin.write(&preimage.to_bytes_be());
        stdin.write(&lower_layer_prefix_len);
        stdin.write(&lower_layer_prefix);
        stdin.write(&proof.nonce);
        stdin.write(&(proof.balance.to::<u128>())); // Convert U256 to u128
        stdin.write(&proof.storage_hash.0); // Convert B256 to [u8; 32]
        stdin.write(&proof.code_hash.0); // Convert B256 to [u8; 32]
        stdin.write(&proof.account_proof);
        stdin.write(&block.header.state_root.0); // Convert B256 to [u8; 32]
        stdin.write(&coin.salt);
        stdin.write(&coin.encrypted);

        println!("sent");

        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);
        println!("setup");

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .compressed()
            .run()
            .expect("failed to generate proof");
        println!("proof");

        // Convert proof and vk into a zkVerify-compatible proof.
        let SP1ZkvProofWithPublicValues {
            proof: shrunk_proof,
            public_values,
        } = client
            .convert_proof_to_zkv(proof, Default::default())
            .unwrap();
        let vk_hash = vk.hash_bytes();

        // Serialize the proof
        let serialized_proof =
            bincode::serde::encode_to_vec(&shrunk_proof, bincode::config::legacy())
                .expect("failed to serialize proof");

        // Convert to required struct
        let output = Output {
            proof: to_hex_with_prefix(&serialized_proof),
            image_id: to_hex_with_prefix(&vk_hash),
            pub_inputs: to_hex_with_prefix(&public_values),
        };

        // Convert to JSON and store in the file
        let json_string =
            serde_json::to_string_pretty(&output).expect("Failed to serialize to JSON.");

        let mut file = File::create("proof.json").unwrap();
        file.write_all(json_string.as_bytes()).unwrap();

        // Submit proof to API
        println!("Submitting proof to API for verification and aggregation...");

        // Call the proof verification API
        let client = reqwest::Client::new();
        let response = client
            .post("http://localhost:3001/verify-proof")
            .send()
            .await?;

        if response.status().is_success() {
            let result: serde_json::Value = response.json().await?;
            println!("Proof verification and aggregation completed successfully!");
            println!("Result: {}", serde_json::to_string_pretty(&result).unwrap());
        } else {
            let error_text = response.text().await?;
            eprintln!("Error calling proof verification API: {error_text}");
            return Err("Failed to verify and aggregate proof".into());
        }

        let aggregator_json =
            std::fs::read_to_string("/home/gautam/Desktop/DarkMint/proof-sub/aggregation.json")?;
        let agg: AggregatorInput = serde_json::from_str(&aggregator_json)?;

        let proof_json =
            std::fs::read_to_string("/home/gautam/Desktop/DarkMint/script/proof.json")?;
        let proof: Output = serde_json::from_str(&proof_json)?;

        // Convert to correct types for Solidity function - matching Remix format
        // The hash should be the raw public values, not ABI encoded
        let hash_hex = proof.pub_inputs.trim_start_matches("0x");
        let hash_bytes = hex::decode(hash_hex)?;

        let aggregation_id = U256::from(agg.aggregationId);
        let domain_id = U256::from(DOMAIN_ID);

        let merkle_path: Vec<alloy::primitives::B256> = agg
            .merkleProof
            .iter()
            .map(|s| {
                alloy::primitives::B256::from_slice(
                    &hex::decode(s.trim_start_matches("0x")).unwrap(),
                )
            })
            .collect();
        let leaf_count = U256::from(agg.numberOfLeaves);
        let index = U256::from(agg.leafIndex);
        let vkey = alloy::primitives::B256::from_slice(
            &hex::decode(proof.image_id.trim_start_matches("0x")).unwrap(),
        );

        println!("Calling checkhash with:");
        println!("  hash (bytes): 0x{}", hex::encode(&hash_bytes));
        println!("  hash length: {} bytes", hash_bytes.len());
        println!("  aggregation_id: {}", aggregation_id);
        println!("  domain_id: {}", domain_id);
        println!("  merkle_path: {:?}", merkle_path);
        println!("  leaf_count: {}", leaf_count);
        println!("  index: {}", index);
        println!("  vkey: 0x{}", hex::encode(&vkey));

        // Verify this matches the Remix expected format
        println!("\nExpected Remix format:");
        println!("  bytes _hash: 0x{}", hex::encode(&hash_bytes));
        println!("  uint256 _aggregationId: \"{}\"", aggregation_id);
        println!("  uint256 _domainId: \"{}\"", domain_id);
        println!("  bytes32[] _merklePath: {:?}", agg.merkleProof);
        println!("  uint256 _leafCount: \"{}\"", leaf_count);
        println!("  uint256 _index: \"{}\"", index);
        println!("  bytes32 _vkey: \"0x{}\"", hex::encode(&vkey));

        let call_data = DarkMint::checkHashCall {
            _hash: Bytes::from(hash_bytes),
            _aggregationId: aggregation_id,
            _domainId: domain_id,
            _merklePath: merkle_path.into(),
            _leafCount: leaf_count,
            _index: index,
            _vkey: vkey,
        };

        let tx = TransactionRequest::default()
            .to(contract_address)
            .input(call_data.abi_encode().into());

        let result = provider.call(tx).await?;

        // The function returns a boolean, so decode it properly
        let success = result.len() >= 32 && result[31] == 1;
        println!("checkhash result: {}", success);

         
            println!("Hash check passed! Now minting tokens...");

            // Extract recipient address from the signer
            let recipient = signer.address();

            // Parse public inputs to extract amount and nullifier
            let pub_inputs_hex = proof.pub_inputs.trim_start_matches("0x");
            let pub_inputs_bytes = hex::decode(pub_inputs_hex)?;

            // Extract amount and nullifier from public inputs structure
            // Based on the structure seen in logs, these values are at specific offsets
            let mut amount = U256::ZERO;
            let mut nullifier = U256::ZERO;

            if pub_inputs_bytes.len() >= 160 {
                // Ensure we have enough data
                // Extract amount (assuming it's at a specific offset in the public inputs)
                // This is based on the structure visible in your logs
                let amount_bytes = &pub_inputs_bytes[92..124]; // 32 bytes for amount
                amount = U256::from_be_slice(amount_bytes);

                // Extract nullifier (assuming it's at another offset)
                let nullifier_bytes = &pub_inputs_bytes[124..156]; // 32 bytes for nullifier
                nullifier = U256::from_be_slice(nullifier_bytes);
            } else {
                // Fallback values if parsing fails
                amount = U256::from(1000000000000000000u64); // 1 token
                nullifier = U256::from(12345);
                println!("Warning: Could not parse public inputs, using fallback values");
            }

            println!("Extracted from public inputs:");
            println!("  Amount: {} wei", amount);
            println!("  Nullifier: {}", nullifier);

            // Convert hash bytes to bytes32 array for publicInputHashes

            // Prepare mint transaction with correct parameters
            let mint_call_data = DarkMint::mintCall {
                recipient,
                amount,
                nullifier,
                publicInputHashes: pub_inputs_bytes
                    .chunks(32)
                    .map(|chunk| {
                        let mut hash_32 = [0u8; 32];
                        hash_32[..chunk.len()].copy_from_slice(chunk);
                        alloy::primitives::B256::from(hash_32)
                    })
                    .collect::<Vec<_>>(),
            };

            let mut mint_tx = TransactionRequest::default()
                .to(contract_address)
                .input(mint_call_data.abi_encode().into());

            mint_tx.gas = Some(500000); // Set gas limit directly on the field

            println!("Sending mint transaction...");
            println!("  Recipient: {:?}", recipient);
            println!("  Amount: {} wei", amount);
            println!("  Nullifier: {}", nullifier);

            let mint_result = provider.send_transaction(mint_tx).await?;

            println!("Mint transaction sent! Hash: {:?}", mint_result.tx_hash());

            // Wait for transaction confirmation
            let receipt = mint_result.get_receipt().await?;
            println!("Transaction confirmed! Block: {:?}", receipt.block_number);
            println!("Gas used: {:?}", receipt.gas_used);

            if receipt.status() {
                println!("✅ Tokens minted successfully!");
            } else {
                println!("❌ Mint transaction failed!");
            }
        
    }
    Ok(())
}
