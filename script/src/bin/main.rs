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

use alloy_sol_types::SolType;
use clap::Parser;
use alloy::{
    primitives::{Address, Bytes, B256},
    rpc::types::{Block, EIP1186AccountProofResponse},
};
use fibonacci_lib::{
    burn,
    mint::{mint_cmd, BurnAddress, Coin, MintContext},
    PublicValuesStruct,
};
use rlp::RlpStream;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "20")]
    encrypted: bool,

    #[arg(long)]
    priv_src: String,

    #[arg(long)]
    dst_addr: String,

    #[arg(long)]
    src_burn_addr: String,

    #[arg(long, default_value = "http://127.0.0.1:8545")]
    provider_url: String,
}

/// Calculate lower layer prefix from MPT proof
fn calculate_lower_layer_prefix(proof: &EIP1186AccountProofResponse) -> (u32, Vec<u8>) {
    // RLP encode the account data
    let mut stream = RlpStream::new_list(4);
    stream.append(&proof.nonce);
    stream.append(&proof.balance);
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

async fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let context = MintContext::new(
        args.src_burn_addr,
        args.dst_addr,
        args.encrypted,
        args.priv_src,
    );

    let (burn_addr, block, proof, coin, prefix, state_root, postfix): (
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
    println!("lower_layer_prefix_len: {}", lower_layer_prefix_len);
    println!("lower_layer_prefix: {:?}", lower_layer_prefix);
    println!("proof.nonce: {:?}", proof.nonce);
    println!("proof.balance: {:?}", proof.balance);
    println!("proof.storage_hash: {:?}", proof.storage_hash);
    println!("proof.code_hash: {:?}", proof.code_hash);

    stdin.write(&burn_addr.preimage);
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

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(FIBONACCI_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct {
            burn_preimage,
            commit_upper,
            encrypted_balance,
            nullifier,
            encrypted,
        } = decoded;
        println!("burn_preimage: {}", burn_preimage);
        println!("commit_upper: {}", commit_upper);
        println!("encrypted_balance: {}", encrypted_balance);
        println!("nullifier: {}", nullifier);
        println!("encrypted: {}", encrypted);

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}