use clap::Args;
use colored::*;

use dialoguer::{Confirm, Input, Password};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use tokio::time::sleep;

use std::env;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

/// Expand environment variables in a string (e.g., "$PRIVATE_KEY" -> actual value)
fn expand_env_vars(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    if input.starts_with('$') {
        let var_name = &input[1..]; // Remove the '$' prefix
        match env::var(var_name) {
            Ok(value) => {
                println!(
                    "{} Expanded {} to environment variable value",
                    "🔧".bright_green(),
                    input
                );
                Ok(value)
            }
            Err(_) => {
                eprintln!(
                    "{} Environment variable {} not found",
                    "❌".bright_red(),
                    var_name
                );
                Err(format!("Environment variable {} not found", var_name).into())
            }
        }
    } else {
        Ok(input.to_string())
    }
}

/// Burn private coins by sending ETH to a burn address
#[derive(Args, Debug)]
pub struct BurnCommand {
    /// Amount of ETH to burn
    #[arg(long, short = 'a')]
    pub amount: Option<f64>,

    /// Private key for the source account (will prompt if not provided)
    #[arg(long, short = 'p')]
    pub priv_src: Option<String>,

    /// RPC provider URL
    #[arg(
        long,
        short = 'r',
        default_value = "https://horizen-rpc-testnet.appchain.base.org/"
    )]
    pub provider_url: String,

    /// Skip confirmation prompts
    #[arg(long, short = 'y')]
    pub yes: bool,
}

impl BurnCommand {
    pub async fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Print beautiful header
        println!("{}", "🔥 DarkMint - Burn Command".bright_red().bold());
        println!("{}", "═".repeat(50).bright_black());
        println!();

        // Get amount interactively if not provided
        let amount = match self.amount {
            Some(amt) => amt,
            None => {
                let amount: f64 = Input::new()
                    .with_prompt(&format!("{} Amount of ETH to burn", "💰".bright_yellow()))
                    .interact()?;
                amount
            }
        };

        // Validate amount
        if amount <= 0.0 {
            eprintln!("{} Amount must be greater than 0", "❌".bright_red());
            return Err("Invalid amount".into());
        }

        // Get private key interactively if not provided
        let priv_src_raw = match &self.priv_src {
            Some(key) => key.clone(),
            None => {
                println!(
                    "{} {}",
                    "🔐".bright_blue(),
                    "Private key required for burning".bright_cyan()
                );
                let key = Input::new()
                    .with_prompt("Enter your private key")
                    .interact()?;
                key
            }
        };

        // Expand environment variables if needed (e.g., "$PRIVATE_KEY" -> actual value)
        let priv_src = expand_env_vars(&priv_src_raw)?;

        // Validate private key format
        if !priv_src.starts_with("0x") || priv_src.len() != 66 {
            eprintln!(
                "{} Private key must be a valid hex string starting with 0x",
                "❌".bright_red()
            );
            return Err("Invalid private key format".into());
        }

        // Display transaction details
        println!();
        println!("{}", "📋 Transaction Details".bright_green().bold());
        println!("{}", "─".repeat(30).bright_black());
        println!("{} {:.6} ETH", "Amount:".bright_white(), amount);
        println!(
            "{} {}",
            "Provider:".bright_white(),
            self.provider_url.bright_cyan()
        );
        println!(
            "{} {}...{}",
            "Private Key:".bright_white(),
            &priv_src[0..8].bright_yellow(),
            &priv_src[priv_src.len() - 6..].bright_yellow()
        );

        // Confirmation unless --yes flag is used
        if !self.yes {
            println!();
            let confirmed = Confirm::new()
                .with_prompt(&format!(
                    "{} Do you want to proceed with burning {} ETH?",
                    "⚠️".bright_yellow(),
                    amount.to_string().bright_red().bold()
                ))
                .default(false)
                .interact()?;

            if !confirmed {
                println!("{} Operation cancelled by user", "🚫".bright_red());
                return Ok(());
            }
        }

        // Show progress bar during burn operation
        println!();
        println!(
            "{} {}",
            "🔥".bright_red(),
            "Initiating burn operation...".bright_white()
        );

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.red} {msg}")
                .unwrap(),
        );
        pb.set_message("Finding available burn address...");
        pb.enable_steady_tick(Duration::from_millis(100));

        // Simulate some processing time for better UX
        sleep(Duration::from_millis(500)).await;

        pb.set_message("Preparing transaction...");
        sleep(Duration::from_millis(800)).await;

        pb.set_message("Sending transaction to network...");

        // Call the actual main.rs binary with burn arguments
        let mut cmd = Command::new("cargo");
        cmd.args(&["run", "--bin", "fibonacci", "--release", "--"])
            .arg("--burn")
            .arg("--amount")
            .arg(&amount.to_string())
            .arg("--priv-src")
            .arg(&priv_src)
            .arg("--provider-url")
            .arg(&self.provider_url);

        // Set up command to show real-time output
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        // Execute the command with real-time output streaming
        match cmd.spawn() {
            Ok(mut child) => {
                // Stop the spinner to show real-time output
                pb.finish_with_message("🔄 Running burn operation...");
                println!();
                println!(
                    "{}",
                    "📊 Real-time Burn Operation Output".bright_blue().bold()
                );
                println!("{}", "─".repeat(50).bright_black());
                println!();

                // Stream stdout in real-time
                if let Some(stdout) = child.stdout.take() {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        match line {
                            Ok(line) => {
                                // Print each line as it comes with a prefix
                                println!("{} {}", "stdout:".bright_blue(), line.bright_white());
                            }
                            Err(e) => {
                                eprintln!("{} Error reading stdout: {}", "⚠️".bright_yellow(), e);
                                break;
                            }
                        }
                    }
                }

                // Wait for the process to complete
                match child.wait() {
                    Ok(status) => {
                        if status.success() {
                            println!();
                            println!(
                                "{} {}",
                                "🎉".bright_green(),
                                "ETH has been successfully burned!".bright_green().bold()
                            );
                            println!();
                            println!(
                                "{} The burn address and transaction details have been recorded.",
                                "ℹ️".bright_blue()
                            );
                            println!(
                                "{} You can now use the burn address for minting proofs.",
                                "💡".bright_yellow()
                            );
                        } else {
                            println!();
                            eprintln!(
                                "{} {}",
                                "🚨".bright_red(),
                                "Burn operation failed:".bright_red().bold()
                            );
                            return Err(format!(
                                "Command failed with exit code: {:?}",
                                status.code()
                            )
                            .into());
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{} {}",
                            "🚨".bright_red(),
                            "Failed to wait for burn process:".bright_red().bold()
                        );
                        return Err(e.into());
                    }
                }
            }
            Err(e) => {
                pb.finish_with_message("❌ Failed to execute burn command");
                println!();
                eprintln!(
                    "{} {}",
                    "🚨".bright_red(),
                    "Failed to execute burn command:".bright_red().bold()
                );
                eprintln!("{} {}", "   ".repeat(1), e.to_string().bright_red());
                return Err(e.into());
            }
        }

        Ok(())
    }
}
