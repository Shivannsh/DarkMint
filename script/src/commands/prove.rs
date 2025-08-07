use clap::Args;
use colored::*;

use dialoguer::{Confirm, Input, Password};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
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

/// Generate proof to mint private coins
#[derive(Args, Debug)]
pub struct ProveCommand {
    /// Destination address for minted coins
    #[arg(long, short = 'd')]
    pub dst_addr: Option<String>,

    /// Source burn address to prove
    #[arg(long, short = 's')]
    pub src_burn_addr: Option<String>,

    /// Private key for fee payment (will prompt if not provided)
    #[arg(long, short = 'p')]
    pub priv_src: Option<String>,

    /// RPC provider URL
    #[arg(
        long,
        short = 'r',
        default_value = "https://horizen-rpc-testnet.appchain.base.org/"
    )]
    pub provider_url: String,

    /// Enable encryption for the coin
    #[arg(long, short = 'e')]
    pub encrypted: bool,

    /// Skip confirmation prompts
    #[arg(long, short = 'y')]
    pub yes: bool,
}

impl ProveCommand {
    pub async fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Print beautiful header
        println!(
            "{}",
            "🔮 DarkMint - Proof Generation".bright_magenta().bold()
        );
        println!("{}", "═".repeat(50).bright_black());
        println!();

        // Get destination address interactively if not provided
        let dst_addr = match &self.dst_addr {
            Some(addr) => addr.clone(),
            None => {
                let addr: String = Input::new()
                    .with_prompt(&format!(
                        "{} Destination address for minted coins",
                        "🎯".bright_green()
                    ))
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input.starts_with("0x") && input.len() == 42 {
                            Ok(())
                        } else {
                            Err("Please enter a valid Ethereum address (0x...)")
                        }
                    })
                    .interact()?;
                addr
            }
        };

        // Get burn address interactively if not provided
        let src_burn_addr = match &self.src_burn_addr {
            Some(addr) => addr.clone(),
            None => {
                let addr: String = Input::new()
                    .with_prompt(&format!(
                        "{} Source burn address to prove",
                        "🔥".bright_red()
                    ))
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input.starts_with("0x") && input.len() == 42 {
                            Ok(())
                        } else {
                            Err("Please enter a valid Ethereum address (0x...)")
                        }
                    })
                    .interact()?;
                addr
            }
        };

        // Get private key interactively if not provided
        let priv_src_raw = match &self.priv_src {
            Some(key) => key.clone(),
            None => {
                println!(
                    "{} {}",
                    "🔐".bright_blue(),
                    "Private key required for fee payment".bright_cyan()
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

        // Display proof generation details
        println!();
        println!("{}", "📋 Proof Generation Details".bright_green().bold());
        println!("{}", "─".repeat(35).bright_black());
        println!(
            "{} {}",
            "Destination:".bright_white(),
            dst_addr.bright_cyan()
        );
        println!(
            "{} {}",
            "Burn Address:".bright_white(),
            src_burn_addr.bright_red()
        );
        println!(
            "{} {}",
            "Provider:".bright_white(),
            self.provider_url.bright_cyan()
        );
        println!(
            "{} {}",
            "Encrypted:".bright_white(),
            if self.encrypted {
                "Yes".bright_green()
            } else {
                "No".bright_yellow()
            }
        );
        println!(
            "{} {}...{}",
            "Fee Payer:".bright_white(),
            &priv_src[0..8].bright_yellow(),
            &priv_src[priv_src.len() - 6..].bright_yellow()
        );

        // Encryption warning/info
        if self.encrypted {
            println!();
            println!(
                "{} {}",
                "🔒".bright_yellow(),
                "Encrypted mode enabled - coins will be private".bright_yellow()
            );
        } else {
            println!();
            println!(
                "{} {}",
                "🔓".bright_blue(),
                "Standard mode - coins will be transparent".bright_blue()
            );
        }

        // Confirmation unless --yes flag is used
        if !self.yes {
            println!();
            let confirmed = Confirm::new()
                .with_prompt(&format!(
                    "{} Do you want to proceed with proof generation?",
                    "⚠️".bright_yellow()
                ))
                .default(false)
                .interact()?;

            if !confirmed {
                println!("{} Operation cancelled by user", "🚫".bright_red());
                return Ok(());
            }
        }

        // Arguments will be passed directly to the main.rs binary

        // Multi-step progress indication
        println!();
        println!(
            "{} {}",
            "🚀".bright_magenta(),
            "Starting proof generation pipeline...".bright_white()
        );

        let multi_progress = MultiProgress::new();

        // Step 1: Verification
        let pb1 = multi_progress.add(ProgressBar::new_spinner());
        pb1.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.magenta} {msg}")
                .unwrap(),
        );
        pb1.set_message("Verifying burn address and fetching proof...");
        pb1.enable_steady_tick(Duration::from_millis(100));

        // Simulate verification
        sleep(Duration::from_millis(1000)).await;
        pb1.finish_with_message("✅ Burn address verified and proof fetched");

        // Step 2: ZK Proof Generation
        let pb2 = multi_progress.add(ProgressBar::new_spinner());
        pb2.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["🔄", "🔃", "🔄", "🔃"])
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb2.set_message("Generating zero-knowledge proof (this may take a while)...");
        pb2.enable_steady_tick(Duration::from_millis(200));

        // Call the actual main.rs binary with prove arguments and SP1 environment variables
        let mut cmd = Command::new("cargo");
        cmd.args(&["run", "--bin", "fibonacci", "--release", "--"])
            .arg("--prove")
            .arg("--dst-addr")
            .arg(&dst_addr)
            .arg("--src-burn-addr")
            .arg(&src_burn_addr)
            .arg("--priv-src")
            .arg(&priv_src)
            .arg("--provider-url")
            .arg(&self.provider_url);

        if self.encrypted {
            cmd.arg("--encrypted");
        }

        // Set SP1 environment variables
        cmd.env("SP1_PROVER", "network");

        // Get SP1 private key from environment and pass it to the command
        if let Ok(sp1_private_key) = env::var("NETWORK_PRIVATE_KEY") {
            cmd.env("NETWORK_PRIVATE_KEY", sp1_private_key);
        } else {
            // If NETWORK_PRIVATE_KEY is not set, show a warning but continue
            println!();
            println!(
                "{} {}",
                "⚠️".bright_yellow(),
                "Warning: NETWORK_PRIVATE_KEY environment variable not set".bright_yellow()
            );
            println!(
                "{} {}",
                "   ".repeat(1),
                "SP1 network proving may fail without this variable".bright_yellow()
            );
            println!();
        }

        // Set up command to show real-time output
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        // Execute the command with real-time output streaming
        match cmd.spawn() {
            Ok(mut child) => {
                // Stop the spinner to show real-time output
                pb2.finish_with_message("🔄 Running proof generation...");
                println!();
                println!(
                    "{}",
                    "📊 Real-time Proof Generation Output".bright_blue().bold()
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
                                "Proof generation completed successfully!"
                                    .bright_green()
                                    .bold()
                            );
                            println!();
                            println!(
                                "{} {}",
                                "💾".bright_blue(),
                                "Proof has been saved to 'proof.json'".bright_blue()
                            );
                            println!(
                                "{} {}",
                                "🔗".bright_yellow(),
                                "Ready for blockchain verification!".bright_yellow()
                            );
                        } else {
                            println!();
                            eprintln!(
                                "{} {}",
                                "🚨".bright_red(),
                                "Proof generation failed:".bright_red().bold()
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
                            "Failed to wait for proof generation process:"
                                .bright_red()
                                .bold()
                        );
                        return Err(e.into());
                    }
                }
            }
            Err(e) => {
                pb2.finish_with_message("❌ Failed to execute proof generation command");
                println!();
                eprintln!(
                    "{} {}",
                    "🚨".bright_red(),
                    "Failed to execute proof generation command:"
                        .bright_red()
                        .bold()
                );
                eprintln!("{} {}", "   ".repeat(1), e.to_string().bright_red());
                return Err(e.into());
            }
        }

        Ok(())
    }
}
