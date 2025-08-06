use crate::mint::{Coin, Wallet};
use clap::Parser;
use ethers::{
    core::types::TransactionRequest,
    prelude::*,
    providers::{Http, Provider},
    types::{Address, U256},
};
use std::io::{self, Write};
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct BurnArgs {
    #[arg(long, default_value = "20")]
    amount: f64,

    #[arg(long)]
    priv_src: String,
}

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = BurnArgs::parse();
    let context = BurnContext::new(args.amount, args.priv_src);
    let provider = Provider::<Http>::try_from(provider_url)?;
    burn_cmd(provider_url, context).await?;
    Ok(())
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
    provider_url: &str,
    context: BurnContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::<Http>::try_from(provider_url)?;
    let wallet = Wallet::open_or_create()?;

    // Find a burn address with zero balance
    let mut burn_addr = None;
    for i in 0..10 {
        let burn_address = wallet.derive_burn_addr(i)?;
        let balance = provider.get_balance(burn_address.address, None).await?;
        if balance == U256::zero() {
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

        // Create account from private key
        let account = LocalWallet::from_str(&context.priv_src)?;

        // Get gas price
        let gas_price = provider.get_gas_price().await?;

        // Get nonce
        let nonce = provider
            .get_transaction_count(account.address(), None)
            .await?;

        // Create transaction
        let tx = TransactionRequest::new()
            .from(account.address())
            .to(burn_addr.address)
            .value(amount_wei)
            .nonce(nonce)
            .gas(21000);

        // Sign and send transaction
        let client = SignerMiddleware::new(provider, account);
        let pending_tx = client.send_transaction(tx, None).await?;
        let receipt = pending_tx.await?;

        if let Some(receipt) = receipt {
            println!("Transaction sent! Hash: {:?}", receipt.transaction_hash);
        } else {
            println!("Transaction sent but no receipt received.");
        }
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