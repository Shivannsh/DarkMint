use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use crate::Wallet;
use std::io::{self, Write};

pub async fn burn_cmd(amount: f64, priv_src: String) -> Result<(), Box<dyn std::error::Error>> {
    let signer: PrivateKeySigner = priv_src.parse()?;

    let provider = ProviderBuilder::new()
        .wallet(signer.clone())
        .connect("https://eth-sepolia.g.alchemy.com/v2/4G8SnWtpGGbMLwoolbtiXu99TKMw6vMs")
        .await?;
    let wallet = Wallet::open_or_create()?;

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

    let burn_addr = burn_addr.ok_or("No available burn address found")?;

    // Ask for user confirmation
    print!(
        "Burning {} ETH by sending them to {}. Are you sure? (Y/n): ",
        amount, burn_addr.address
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() == "y" {
        // Convert ETH to Wei
        let amount_wei = U256::from((amount * 1e18) as u64);

        let account = signer.address();

        // Get gas price
        let _gas_price = provider.get_gas_price().await?;

        // Get nonce
        let nonce = provider.get_transaction_count(account).await?;

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



