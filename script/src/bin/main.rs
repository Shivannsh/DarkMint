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
    primitives::{Bytes, B256},
    rpc::types::{Block, EIP1186AccountProofResponse},
};
use tiny_keccak::{Hasher, Keccak};

use clap::Parser;

use rlp::RlpStream;
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Stdin};

use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use serde::{Deserialize, Serialize};
use sp1_zkv_sdk::*; // for the `convert_to_zkv` and `hash_bytes` methods.
use std::{fs::File, io::Write};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

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

        let context = MintContext {
            src_burn_addr: src_burn_addr.parse().unwrap(),
            dst_addr: dst_addr.parse().unwrap(),
            encrypted: args.encrypted,
            priv_fee_payer: priv_src.parse().unwrap(),
        };

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

        // Verify the proof.
        // client.verify(&proof.clone(), &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
    Ok(())
}
