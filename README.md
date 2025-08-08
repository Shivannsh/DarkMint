# DarkMint: Zero-Knowledge Privacy System for Ethereum

DarkMint is a cutting-edge privacy solution for Ethereum that enables confidential and verifiable transactions using zero-knowledge proofs. Built on the SP1 zkVM, it allows users to privately transfer ETH while maintaining full compatibility with the Ethereum network.

## ✨ Features

- **Zero-Knowledge Proofs**: Proves Ethereum account and state transitions without revealing sensitive data
- **Merkle Patricia Trie Verification**: Verifies both final and intermediate layers of Ethereum’s MPT for robust account/state proofs.
- **Private Transactions**: Send ETH without revealing transaction amounts or participant identities
- **Ethereum Compatible**: Uses RLP encoding and Alloy primitives/providers to work seamlessly with existing Ethereum infrastructure
- **Account Privacy**: Implements Modified Merkle Patricia Trie (MPT) verification for Ethereum accounts
- **Flexible Privacy**: Optional balance encryption for enhanced privacy
- **Secure Design**: Uses Poseidon hash for efficient ZK-friendly cryptographic operations
- **Wallet & Coin Management**: Securely manage encrypted and unencrypted coins, derive burn addresses, and handle wallet files.
- **CLI Interface**: Command-line tools for minting, burning, and proof generation.

## 📁 Project Structure

```
lib/src/
├── lib.rs                  # Core library exports and documentation
├── crypto.rs              # All cryptographic functions
├── account_verification.rs # Final MPT (Merkle Patricia Tree) layer verification
└── merkle_proof.rs        # Intermediate MPT layer verification logic

program/src/
└── main.rs                # Main zkVM program for proof generation`

script/src/
├── lib.rs                 # Wallet and coin management utilities
├── mint.rs                # Implementation of minting operations
├── burn.rs                # Implementation of burning operations
└── bin/
    ├── main.rs            # CLI interface for user interactions
    └── vkey.rs            # Verification key utility
```

## Directory & File Purpose

### `lib/src/`

- **`lib.rs`**  
  Central entry point. Re-exports circuits and structs, and provides documentation.

- **`crypto.rs`**  
  Houses all cryptographic primitives, including Poseidon, Keccak, address derivation, and more.

- **`account_verification.rs`**  
  Implements the final Merkle Patricia Tree (MPT) layer and account proof verification logic.

- **`merkle_proof.rs`**  
  Handles intermediate MPT path verification and related constraints.

---

### `program/src/`

- **`main.rs`**  
  Main Zero-Knowledge (ZK) program logic. Orchestrates input reading, circuit execution, and output commitment.

---

### `script/src/`

- **`lib.rs`**  
  Core wallet and coin management logic, including file I/O and encryption.

- **`mint.rs`**  
  Implements minting operations and contextual logic.

- **`burn.rs`**  
  Implements burning operations and logic.

#### `bin/`

- **`main.rs`**  
  Command-line interface (CLI) entry point for user interaction — includes operations like mint, burn, and prove.

- **`vkey.rs`**  
  Utility for printing the verification key hash.

## 🧠 Technical Concepts

### Modified Merkle Patricia Trie (MPT)

- Used for verifying Ethereum account proofs
- Ethereum’s data structure for storing account and state information, enabling efficient and secure proofs
- Implements both final layer (account) and intermediate layer verification
- Ensures state root consistency with Ethereum blockchain

### Cryptographic Functions

- **Poseidon Hash**: Primary hash function, optimized for ZK-SNARKs
- **Keccak-256**: Used for Ethereum address generation and verification
- **RLP Encoding**: Ethereum's recursive length prefix encoding for account and state data

### Zero-Knowledge Proofs

- Built on SP1 zkVM for efficient SNARK generation
- Proves account existence and balance correctness
- Maintains transaction privacy while ensuring validity

## 🧩 Modified Merkle Patricia Trie Proof Verifier

DarkMint's core privacy and proof system is built on three Rank-1 Constraint System (R1CS) circuits, which together enable efficient and private verification of Ethereum state using a modified Merkle Patricia Trie (MPT). These circuits are:

### 1. MPT-Middle Circuit (merkle_proof.rs)

This circuit verifies the relationship between two consecutive layers in the MPT proof:

- **Layer Commitment:** For a layer $l_i$, we compute a SNARK-friendly commitment $h(l_i \mid s)$, where $h$ is a hash function (e.g., Poseidon) and $s$ is a random salt. The salt ensures that the commitment is hiding, so the verifier cannot guess the layer contents.
- **Keccak Substring Constraint:** The circuit enforces that $keccak(l_i)$ (the Ethereum-compatible hash of $l_i$) appears as a substring within the previous layer $l_{i-1}$.
- **Previous Layer Commitment:** The previous layer $l_{i-1}$ is also committed as $h(l_{i-1} \mid s)$.



This ensures the integrity of the path from the account leaf up to the root in the MPT.

### 2. MPT-Last Circuit (account_verification.rs)

This circuit verifies the final (leaf) layer of the MPT, which contains the Ethereum account:

- **Account Existence:** Proves that there exists an account within the final layer $l_{last}$, with commitment $h(l_{last} \mid s)$.
- **Public Key Constraint:** The account's public key is the poseidon hash of some preimage $p$:
  - $pk = poseidon(p, p)$
- **Nullifier Generation:** The nullifier is computed as $poseidon(p, 0)$, which is used to prevent double-spending in privacy protocols.



This circuit ties the cryptographic identity (public key and nullifier) to the committed account data in the MPT.

### 3. Nullifier and Account Logic

- **Nullifier:** $nullifier = poseidon(p, 0)$
- **Public Key:** $pk = poseidon(p, p)$
- **Purpose:** The nullifier is a unique value derived from the secret preimage $p$, ensuring that each spend can be detected (to prevent double-spending) without revealing $p$ itself.

---

## Wallet Management

- Securely derives burn addresses, manages encrypted/unencrypted coins, and persists wallet state

## ⚙️ Installation & Setup

1. Install Rust and required tools:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

2. Install SP1:

```bash
curl -L https://docs.succinct.xyz/install | bash
```

3. Clone and build the project:

```bash
git clone https://github.com/shivannsh/darkmint
cd darkmint/program
cargo build --release
```

4. Install Dependencies

```bash
cd script
cargo build --release
```

## 🚀 Usage

### Setting up Environment

Create a `.env` file in the project root:

```bash
RPC_URL=
PRIVATE_KEY=
SP1_PRIVATE_KEY=
API_KEY=
```

### Basic Commands

Navigate to the script directory and run:

1. **Burn Private Coins**:
The burn command is used to burn a specific amount of ETH from the provided private key and creates a burn address that proves the burnt amount

```bash
cargo run -- --burn --amount AMOUNT --priv-src $PRIVATE_KEY --provider-url $RPC_URL
```

2. **Generate Proof to Mint Private Coins**:
The mint command is used to mint the ETH amount related to a burnt address. to mint the total burnt amount run the mint command without --encrypted, but to mint the burnt amount partially add the --encrypted tag
````bash
 NETWORK_PRIVATE_KEY=$SP1_PRIVATE_KEY cargo run --release -- --prove --dst-addr $RECEIVING_WALLER_ADDRESS --src-burn-addr $BURN_ADDRESS_DERVIED --priv-src $PRIVATE_KEY --provider-SP1_PROVER=networkurl $RPC_URL
````

3. **Generate Verification Key**:

```bash
cargo run --release --bin vkey
```

### Output

- Proofs and public inputs are written to `proof.json` in script directory

### Future Scope 

- This code can be natively integrated into the wallets and the process can eased out 
- This code Can also used as a foundation for Dark Pools and Dark Pools can easily  be created on top of it 

### 📝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 📬 Contact
For questions and support, please open an issue in the GitHub repository.
