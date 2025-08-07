# 🌑 DarkMint CLI - Beautiful Private Ethereum Transactions

A stunning command-line interface for DarkMint's private Ethereum transaction system. Built with Rust for performance and beauty.

## ✨ Features

- 🔥 **Burn ETH** - Convert ETH to private burn addresses with beautiful progress indicators
- 🔮 **Generate Proofs** - Create zero-knowledge proofs for minting private coins
- 🎨 **Beautiful Interface** - Colorful, interactive terminal experience
- 🛡️ **Input Validation** - Comprehensive validation with friendly error messages
- 🔐 **Secure Prompts** - Hidden password input for private keys
- 📊 **Progress Tracking** - Multi-step progress bars for long operations
- 💬 **Interactive Mode** - Smart prompts when arguments aren't provided

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
cd DarkMint/script

# Build the CLI
cargo build --release --bin darkmint
```

### Basic Usage

#### 🔥 Burn ETH to Create Private Burn Address

```bash
# Interactive mode (will prompt for missing values)
cargo run --bin darkmint -- burn

# With all arguments
cargo run --bin darkmint -- burn \
  --amount 0.1 \
  --priv-src 0x1234567890abcdef... \
  --provider-url http://127.0.0.1:8545
```

#### 🔮 Generate Zero-Knowledge Proof for Minting

```bash
# Interactive mode (SP1_PROVER automatically set)
NETWORK_PRIVATE_KEY=$SP1_PRIVATE_KEY cargo run --bin darkmint -- prove

# With all arguments (SP1_PROVER automatically set)
NETWORK_PRIVATE_KEY=$SP1_PRIVATE_KEY \
cargo run --release --bin darkmint -- prove \
  --dst-addr 0x742d35Cc6634C0532925a3b8D1B9e7c7E2B3F1A2 \
  --src-burn-addr 0x1234567890abcdef1234567890abcdef12345678 \
  --priv-src 0x1234567890abcdef... \
  --provider-url http://127.0.0.1:8545 \
  --encrypted
```

## 🎯 Command Reference

### Global Options

- `--verbose, -v` - Enable verbose logging for debugging
- `--help, -h` - Show help information
- `--version, -V` - Show version information

### Burn Command

Burns ETH to create a private burn address that can be used for generating minting proofs.

```bash
cargo run --bin darkmint -- burn [OPTIONS]
```

**Options:**
- `--amount, -a <AMOUNT>` - Amount of ETH to burn (will prompt if not provided)
- `--priv-src, -p <PRIVATE_KEY>` - Private key for source account (will prompt securely if not provided)
- `--provider-url, -r <URL>` - RPC provider URL (default: http://127.0.0.1:8545)
- `--yes, -y` - Skip confirmation prompts

**Example:**
```bash
cargo run --bin darkmint -- burn --amount 0.05 --yes
```

### Prove Command

Generates a zero-knowledge proof for minting private coins from a burn address.

```bash
cargo run --bin darkmint -- prove [OPTIONS]
```

**Options:**
- `--dst-addr, -d <ADDRESS>` - Destination address for minted coins (will prompt if not provided)
- `--src-burn-addr, -s <ADDRESS>` - Source burn address to prove (will prompt if not provided)  
- `--priv-src, -p <PRIVATE_KEY>` - Private key for fee payment (will prompt securely if not provided)
- `--provider-url, -r <URL>` - RPC provider URL (default: http://127.0.0.1:8545)
- `--encrypted, -e` - Enable encryption for the coin (creates private coins)
- `--yes, -y` - Skip confirmation prompts

**Example:**
```bash
SP1_PROVER=network NETWORK_PRIVATE_KEY=$SP1_PRIVATE_KEY \
cargo run --release --bin darkmint -- prove \
  --dst-addr 0x742d35Cc6634C0532925a3b8D1B9e7c7E2B3F1A2 \
  --encrypted \
  --yes
```

## 🎨 Interface Features

### Beautiful Output

The CLI features:
- 🎭 **ASCII Art Banner** - Eye-catching startup banner
- 🌈 **Colored Output** - Success (green), warnings (yellow), errors (red)
- 📊 **Progress Indicators** - Spinners and progress bars for operations
- 📋 **Formatted Tables** - Clean display of transaction details
- ✨ **Icons and Emojis** - Visual cues for different operations

### Interactive Prompts

When arguments are missing, the CLI will intelligently prompt for:
- 💰 **Amount Input** - With validation for positive numbers
- 🎯 **Address Input** - With Ethereum address format validation
- 🔐 **Private Key Input** - Hidden input for security
- ✅ **Confirmations** - Safety prompts before executing operations

### Error Handling

- 🚨 **Clear Error Messages** - Human-readable error descriptions
- 💡 **Helpful Tips** - Suggestions for fixing common issues
- 🔍 **Detailed Logging** - Use `--verbose` for debugging information

## 🛠️ Development

### Dependencies Used

- **clap** - Command-line argument parsing with derive macros
- **indicatif** - Beautiful progress bars and spinners
- **colored** - Terminal color output
- **dialoguer** - Interactive prompts and confirmations
- **console** - Advanced terminal control
- **tokio** - Async runtime for network operations

### Project Structure

```
script/
├── src/
│   ├── bin/
│   │   ├── darkmint.rs    # New beautiful CLI
│   │   ├── main.rs        # Original CLI
│   │   └── vkey.rs        # Verification key utility
│   ├── commands/
│   │   ├── mod.rs         # Commands module
│   │   ├── burn.rs        # Burn command implementation
│   │   └── prove.rs       # Prove command implementation
│   ├── burn.rs            # Core burn functionality
│   ├── mint.rs            # Core mint functionality
│   └── lib.rs             # Library exports
└── Cargo.toml             # Dependencies and binaries
```

## 🔧 Environment Variables

For proof generation, you'll need SP1 network configuration:

```bash
export NETWORK_PRIVATE_KEY=your_sp1_private_key
export RPC_URL=your_ethereum_rpc_url  # Optional, can use --provider-url instead
```

**✨ Automatic Configuration**: The CLI automatically sets `SP1_PROVER=network` when running proof generation. You only need to set your `NETWORK_PRIVATE_KEY`.

## 🎯 Examples

### Complete Workflow

1. **Burn ETH to create a private burn address:**
```bash
cargo run --bin darkmint -- burn --amount 0.1
```

2. **Note the burn address from the output, then generate a proof:**
```bash
# SP1_PROVER automatically set by the CLI
SP1_PROVER=network NETWORK_PRIVATE_KEY=$SP1_PRIVATE_KEY \
cargo run --release --bin darkmint -- prove \
  --src-burn-addr 0x1234... \
  --dst-addr 0x5678... \
  --encrypted
```

### Testing Mode

For local testing with a development chain:

```bash
# Start your local Ethereum node (e.g., Hardhat, Ganache)
# Then use the CLI with local provider
cargo run --bin darkmint -- burn \
  --amount 1.0 \
  --provider-url http://127.0.0.1:8545
```

## 🚨 Security Notes

- Private keys are prompted securely (hidden input) when not provided as arguments
- Never commit private keys to version control
- Use environment variables for sensitive configuration
- The CLI validates all input formats before processing

## 🤝 Contributing

This CLI tool is built on top of the existing DarkMint functionality. To contribute:

1. The core logic remains in `burn.rs` and `mint.rs`
2. CLI enhancements go in the `commands/` module
3. Follow the existing patterns for progress indicators and user interaction
4. Test thoroughly with both interactive and non-interactive modes

---

**Made with ❤️ by the DarkMint Team**
