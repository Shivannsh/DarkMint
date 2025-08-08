use crate::Wallet;
use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use std::io::{self, Write};

pub async fn burn_cmd(amount: f64, priv_src: String) -> Result<(), Box<dyn std::error::Error>> {
    let signer: PrivateKeySigner = priv_src.parse()?;

    let provider = ProviderBuilder::new()
        .wallet(signer.clone())
        .connect("https://horizen-rpc-testnet.appchain.base.org/")
        .await?;
    println!("Provider connected");
    let wallet = Wallet::open_or_create()?;
    println!("Wallet opened");

    // Find a burn address with zero balance
    let mut burn_addr = None;
    for i in 0..10 {
        let burn_address = wallet.derive_burn_address(i)?;
        let balance = provider.get_balance(burn_address.address).await?;
        if balance == U256::ZERO {
            burn_addr = Some(burn_address);
            break;
        }
    }
    println!("Burn address found");
    let burn_addr = burn_addr.ok_or("No available burn address found")?;
    println!("Burn address: {}", burn_addr.address);
    println!(
        "Burning {} ETH by sending them to {}",
        amount, burn_addr.address
    );
    // Convert ETH to Wei
    let amount_wei = U256::from((amount * 1_000_000_000_000_000_000.0) as u128);

    let account = signer.address();

    // Check account balance
    let account_balance = provider.get_balance(account).await?;
    println!("Account balance: {} wei", account_balance);

    if account_balance < amount_wei {
        return Err(format!(
            "Insufficient balance. Need {} wei, have {} wei",
            amount_wei, account_balance
        )
        .into());
    }

    // Get gas price
    let gas_price = provider.get_gas_price().await?;
    println!("Gas price: {} wei", gas_price);

    // Get nonce
    let nonce = provider.get_transaction_count(account).await?;

    // Create transaction
    let mut tx = TransactionRequest::default()
        .from(account)
        .to(burn_addr.address)
        .value(amount_wei)
        .nonce(nonce)
        .gas_price(gas_price);

    // Estimate gas
  

    println!("Transaction created");

    // Send transaction (provider handles signing automatically)
    match provider.send_transaction(tx).await {
        Ok(pending_tx) => {
            println!("Pending transaction... {}", pending_tx.tx_hash());

            match pending_tx.get_receipt().await {
                Ok(receipt) => {
                    println!("Transaction sent! Hash: {:?}", receipt.transaction_hash);
                    println!("✅ Burn successful!");
                }
                Err(e) => {
                    println!("❌ Failed to get receipt: {}", e);
                    return Err(e.into());
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to send transaction: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
