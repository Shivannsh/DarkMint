use crate::mint::Wallet;

use alloy::{
    providers::{Provider, ProviderBuilder}, 
    rpc::types::TransactionRequest, 
    signers::{local::PrivateKeySigner}, 
    primitives::{U256},
};
use std::io::{self, Write};
use clap::Parser;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    amount: f64,
    #[arg(long)]
    priv_src: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    provider_url: String,
}

pub struct BurnContext {
    amount: f64,
    priv_src: String,
}

impl BurnContext {
    pub fn new(amount: f64, priv_src: String) -> Self {
        Self { amount, priv_src }
    }
}

pub async fn burn_cmd(
) -> Result<(), Box<dyn std::error::Error>> {

    let args = Args::parse();
    let signer: PrivateKeySigner = args.priv_src.parse()?;
    let context = BurnContext::new(args.amount, args.priv_src.clone());
    
    let provider = ProviderBuilder::new().wallet(signer.clone()).connect(args.provider_url.as_str()).await?; 
    let wallet = Wallet::open_or_create()?;

    // Find a burn address with zero balance
    let mut burn_addr = None;
    for i in 0..10 {
        let burn_address = wallet.derive_burn_addr(i)?;
        let balance = provider.get_balance(burn_address.address).await?;
        if balance == U256::ZERO {
            burn_addr = Some(burn_address);
            break;
        }
    }

    let burn_addr = burn_addr.ok_or("No available burn address found")?;

    // Ask for user confirmation
    print!(
        "Burning {} ETH by sending them to {}. Are you sure? (Y/n): ",
        context.amount, burn_addr.address
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() == "y" {
        // Convert ETH to Wei
        let amount_wei = U256::from((context.amount * 1e18) as u64);

        let account = signer.address();

        // Get gas price
        let _gas_price = provider.get_gas_price().await?;

        // Get nonce
        let nonce = provider
            .get_transaction_count(account)
            .await?;

        // Create transaction
        let tx = TransactionRequest::default()
            .from(account)
            .to(burn_addr.address)
            .value(amount_wei)
            .nonce(nonce)
            .gas_limit(21000);

        // Send transaction (provider handles signing automatically)
        let pending_tx = provider.send_transaction(tx).await?;

        println!("Pending transaction... {}", pending_tx.tx_hash());

        let receipt = pending_tx.get_receipt().await?;

        println!("Transaction sent! Hash: {:?}", receipt.transaction_hash);
    } else {
        println!("Burn cancelled.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_context_creation() {
        let context = BurnContext::new(1.5, "0x1234567890abcdef".to_string());
        assert_eq!(context.amount, 1.5);
        assert_eq!(context.priv_src, "0x1234567890abcdef");
    }

    #[test]
    fn test_burn_context_new() {
        let amount = 2.5;
        let priv_src = "0xabcdef1234567890".to_string();
        let context = BurnContext::new(amount, priv_src.clone());

        assert_eq!(context.amount, amount);
        assert_eq!(context.priv_src, priv_src);
    }
}