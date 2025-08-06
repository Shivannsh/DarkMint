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
mod burn;
mod mint;
use ark_ff::{BigInteger, PrimeField};
use burn::burn_cmd;
use mint::{mint_cmd, BurnAddress, Coin, MintContext};

use alloy::{
    primitives::{Address, Bytes, B256},
    rpc::types::{Block, EIP1186AccountProofResponse},
};
use alloy_sol_types::SolType;
use clap::Parser;
use fibonacci_lib::PublicValuesStruct;
use rlp::RlpStream;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::str::FromStr;
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;


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

/// Calculate lower layer prefix from MPT proof
fn calculate_lower_layer_prefix(proof: &EIP1186AccountProofResponse) -> (u32, Vec<u8>) {
    // RLP encode the account data
    let mut stream = RlpStream::new_list(4);
    stream.append(&proof.nonce);
    stream.append(&proof.balance.to_be_bytes_vec());
    stream.append(&proof.storage_hash.as_slice());
    stream.append(&proof.code_hash.as_slice());
    let account_rlp = stream.out();

    // Get the last proof element (the account proof)
    let account_proof = proof.account_proof.last().unwrap();

    // Calculate the prefix by removing the account RLP from the end
    let prefix_len = account_proof.len() - account_rlp.len();
    let lower_layer_prefix = account_proof[..prefix_len].to_vec();

    (prefix_len as u32, lower_layer_prefix)
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

        println!("context: {:?}", context);

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
        let (lower_layer_prefix_len, lower_layer_prefix) = calculate_lower_layer_prefix(&proof);

        // Setup the prover client.
        let client = ProverClient::from_env();

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();

        println!("burn_addr.preimage: {:?}", burn_addr.preimage);
        println!("lower_layer_prefix_len: {:?}", lower_layer_prefix_len);
        println!("lower_layer_prefix: {:?}", lower_layer_prefix);
        println!("proof.nonce: {:?}", proof.nonce);
        println!("proof.balance: {:?}", proof.balance);
        println!("proof.storage_hash: {:?}", proof.storage_hash);
        println!("proof.code_hash: {:?}", proof.code_hash);

        let preimage = burn_addr.preimage.into_bigint();
        println!("preimage: {:?}", preimage);

        stdin.write(&preimage.to_bytes_be());
        stdin.write(&lower_layer_prefix_len);
        stdin.write(&lower_layer_prefix);
        stdin.write(&proof.nonce);
        stdin.write(&proof.balance);
        stdin.write(&proof.storage_hash);
        stdin.write(&proof.code_hash);
        stdin.write(&proof.account_proof);
        stdin.write(&block.header.state_root);
        stdin.write(&coin.salt);
        stdin.write(&coin.encrypted);

        println!("sent");

        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);
        println!("setup");

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .expect("failed to generate proof");
        println!("proof");
        
        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
    Ok(())
}