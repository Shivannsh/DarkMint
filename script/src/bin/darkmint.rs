//! DarkMint CLI - A beautiful interface for Ethereum private coin operations
//!
//! This tool allows you to:
//! - Burn ETH to create private burn addresses
//! - Generate zero-knowledge proofs for minting private coins
//!
//! Usage:
//! ```shell
//! # Burn coins
//! cargo run --bin darkmint -- burn --amount 0.1 --priv-src $PRIVATE_KEY
//!
//! # Generate minting proof
//! cargo run --bin darkmint -- prove --dst-addr $DEST --src-burn-addr $BURN_ADDR --priv-src $PRIVATE_KEY
//! ```

use clap::{Parser, Subcommand};
use colored::*;
use console::Term;
use std::process;

// Import CLI command modules
use fibonacci_script::commands::{BurnCommand, ProveCommand};

#[derive(Parser)]
#[command(

    name = "darkmint",
    about = "🌑 DarkMint - Private Ethereum Transactions Made Beautiful",
    long_about = "DarkMint is a CLI tool for creating private Ethereum transactions using zero-knowledge proofs.\n\nFeatures:\n• Burn ETH to create private burn addresses\n• Generate ZK proofs for minting private coins\n• Beautiful terminal interface with progress indicators\n• Interactive prompts for secure input",
    version = "1.0.0",
    author = "DarkMint Team"

)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(long, short = 'v', global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    
    /// 🔥 Burn ETH to create a private burn address
    Burn(BurnCommand),
    /// 🔮 Generate zero-knowledge proof for minting private coins
    Prove(ProveCommand),
}

fn print_banner() {
    let term = Term::stdout();
    let _ = term.clear_screen();

    println!(
        "{}",
        r#"
    ██████╗  █████╗ ██████╗ ██╗  ██╗███╗   ███╗██╗███╗   ██╗████████╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝████╗ ████║██║████╗  ██║╚══██╔══╝
    ██║  ██║███████║██████╔╝█████╔╝ ██╔████╔██║██║██╔██╗ ██║   ██║   
    ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██║╚██╔╝██║██║██║╚██╗██║   ██║   
    ██████╔╝██║  ██║██║  ██║██║  ██╗██║ ╚═╝ ██║██║██║ ╚████║   ██║   
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   
    "#
        .bright_green()
        .bold()
    );

    println!(
        "{}",
        "    Private Ethereum Transactions Made Beautiful"
            .bright_cyan()
            .italic()
    );
    println!(
        "{}",
        "    ═════════════════════════════════════════════".bright_black()
    );
    println!();
}

fn setup_logging(verbose: bool) {
    if verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }

    // Setup SP1 logger
    sp1_sdk::utils::setup_logger();
}

#[tokio::main]
async fn main() {
    // Initialize rustls crypto provider
    use rustls::crypto::ring::default_provider;
    use rustls::crypto::CryptoProvider;
    CryptoProvider::install_default(default_provider()).expect("Failed to install crypto provider");

    // Load environment variables
    dotenv::dotenv().ok();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Setup logging
    setup_logging(cli.verbose);

    // Print banner for all commands
    print_banner();

    // Execute the command
    let result = match cli.command {
        Commands::Burn(burn_cmd) => burn_cmd.execute().await,
        Commands::Prove(prove_cmd) => prove_cmd.execute().await,
    };

    // Handle results with beautiful error messages
    match result {
        Ok(_) => {
            println!();
            println!(
                "{} {}",
                "✨".bright_green(),
                "Operation completed successfully!".bright_green().bold()
            );
            println!(
                "{} {}",
                "🙏".bright_blue(),
                "Thank you for using DarkMint!".bright_blue()
            );
        }
        Err(e) => {
            println!();
            eprintln!(
                "{} {}",
                "💥".bright_red(),
                "Operation failed!".bright_red().bold()
            );
            eprintln!(
                "{} {}",
                "📋".bright_yellow(),
                "Error details:".bright_yellow()
            );
            eprintln!("   {}", e.to_string().bright_red());
            println!();
            eprintln!("{} {}", "💡".bright_blue(), "Tips:".bright_blue().bold());
            eprintln!("   • Check your private key format (should start with 0x)");
            eprintln!("   • Ensure your RPC provider is accessible");
            eprintln!("   • Verify you have sufficient ETH for transactions");
            eprintln!("   • Run with --verbose for detailed logs");

            process::exit(1);
        }
    }
}
