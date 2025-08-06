//! DarkMint Script Library
//!
//! This library provides wallet management, coin handling, and cryptographic utilities
//! for the DarkMint privacy system. It includes functionality for:
//!
//! - Wallet creation and management
//! - Burn address derivation
//! - Coin creation and encryption
//! - Poseidon hash computations

use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;

/// Size of cryptographic notes and entropy in bytes
pub const NOTE_SIZE: usize = 32;

/// Wallet file name for persistent storage
pub const WALLET_FILENAME: &str = "burnth.priv";

/// Compute Poseidon hash of two field elements
///
/// This is the primary hash function used in DarkMint for privacy-preserving
/// operations, replacing MiMC7 for better efficiency.
///
/// # Arguments
/// * `left` - Left input field element
/// * `right` - Right input field element
///
/// # Returns
/// * Poseidon hash as a field element
pub fn compute_poseidon_hash(left: Fr, right: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let left_bytes = left.into_bigint().to_bytes_be();
    let right_bytes = right.into_bigint().to_bytes_be();
    let hash_bytes = poseidon
        .hash_bytes_be(&[&left_bytes, &right_bytes])
        .unwrap();
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

/// Represents a privacy-preserving coin in the DarkMint system
///
/// Coins can be either encrypted (for privacy) or plaintext (for transparency).
/// The value computation differs based on the encryption flag.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Coin {
    /// The coin amount in wei
    pub amount: U256,
    /// Salt used for encryption/commitment generation
    pub salt: U256,
    /// Whether the coin value should be encrypted
    pub encrypted: bool,
}

impl Coin {
    /// Create a new coin with the specified parameters
    ///
    /// # Arguments
    /// * `amount` - Coin amount in wei
    /// * `salt` - Salt for encryption/commitment
    /// * `encrypted` - Whether to encrypt the coin value
    ///
    /// # Returns
    /// * New Coin instance
    pub fn new(amount: U256, salt: U256, encrypted: bool) -> Self {
        Self {
            amount,
            salt,
            encrypted,
        }
    }

    /// Get the effective value of the coin
    ///
    /// For encrypted coins, returns the Poseidon hash of (amount, salt).
    /// For unencrypted coins, returns the amount directly.
    ///
    /// # Returns
    /// * Effective coin value as U256
    pub fn get_effective_value(&self) -> U256 {
        if self.encrypted {
            self.compute_encrypted_value()
        } else {
            self.amount
        }
    }

    /// Compute the encrypted value using Poseidon hash
    ///
    /// # Returns
    /// * Poseidon hash of (amount, salt) as U256
    fn compute_encrypted_value(&self) -> U256 {
        let left_bytes = self.amount.to_be_bytes::<32>();
        let right_bytes = self.salt.to_be_bytes::<32>();
        let left = Fr::from_le_bytes_mod_order(&left_bytes);
        let right = Fr::from_le_bytes_mod_order(&right_bytes);
        let result = compute_poseidon_hash(left, right);
        U256::from_be_bytes::<32>(result.into_bigint().to_bytes_be().try_into().unwrap())
    }

    /// Check if the coin is encrypted
    ///
    /// # Returns
    /// * true if encrypted, false otherwise
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}

/// Represents a DarkMint wallet containing entropy and coins
///
/// The wallet manages user's privacy-preserving coins and derives
/// burn addresses deterministically from entropy.
#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    /// Hex-encoded entropy for address derivation
    entropy: String,
    /// Collection of privacy-preserving coins
    coins: Vec<Coin>,
}

/// Represents a burn address with its preimage
///
/// Burn addresses are derived from entropy and used to receive
/// ETH that will be converted to privacy-preserving coins.
#[derive(Debug, Clone)]
pub struct BurnAddress {
    /// Field element preimage used to generate the address
    pub preimage: Fr,
    /// Derived Ethereum address
    pub address: Address,
}

impl BurnAddress {
    /// Create a new burn address from preimage and address
    ///
    /// # Arguments
    /// * `preimage` - Field element preimage
    /// * `address` - Derived Ethereum address
    ///
    /// # Returns
    /// * New BurnAddress instance
    pub fn new(preimage: Fr, address: Address) -> Self {
        Self { preimage, address }
    }
}

impl Wallet {
    /// Open existing wallet or create a new one
    ///
    /// If the wallet file doesn't exist, creates a new wallet with random entropy.
    /// Otherwise, loads the existing wallet from the file.
    ///
    /// # Returns
    /// * Result containing the wallet or an error
    pub fn open_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        if !std::path::Path::new(WALLET_FILENAME).exists() {
            Self::create_new_wallet()
        } else {
            Self::load_existing_wallet()
        }
    }

    /// Create a new wallet with random entropy
    ///
    /// # Returns
    /// * Result containing the new wallet or an error
    fn create_new_wallet() -> Result<Self, Box<dyn std::error::Error>> {
        let mut entropy = [0u8; NOTE_SIZE];
        OsRng.fill_bytes(&mut entropy);

        let wallet = Wallet {
            entropy: hex::encode(entropy),
            coins: vec![],
        };

        wallet.save_to_file()?;
        Ok(wallet)
    }

    /// Load existing wallet from file
    ///
    /// # Returns
    /// * Result containing the loaded wallet or an error
    fn load_existing_wallet() -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(WALLET_FILENAME)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Derive a burn address from wallet entropy and index
    ///
    /// Uses SHA-256 to hash entropy + index, then Poseidon to derive the address.
    /// This provides deterministic address generation while maintaining privacy.
    ///
    /// # Arguments
    /// * `index` - Index for address derivation (allows multiple addresses per wallet)
    ///
    /// # Returns
    /// * Result containing the derived burn address or an error
    pub fn derive_burn_address(
        &self,
        index: u64,
    ) -> Result<BurnAddress, Box<dyn std::error::Error>> {
        // Decode entropy and create hash input
        let entropy_bytes = hex::decode(&self.entropy)?;
        let preimage = self.compute_address_preimage(&entropy_bytes, index);
        let address = self.derive_ethereum_address_from_preimage(preimage);

        Ok(BurnAddress::new(preimage, address))
    }

    /// Compute the preimage for address derivation
    ///
    /// # Arguments
    /// * `entropy_bytes` - Decoded entropy bytes
    /// * `index` - Address index
    ///
    /// # Returns
    /// * Field element preimage
    fn compute_address_preimage(&self, entropy_bytes: &[u8], index: u64) -> Fr {
        let mut hasher = Sha256::new();
        hasher.update(entropy_bytes);
        hasher.update(&index.to_le_bytes());
        let result = hasher.finalize();

        // Take first 31 bytes to ensure we stay within field size
        Fr::from_le_bytes_mod_order(&result[..31])
    }

    /// Derive Ethereum address from preimage using Poseidon hash
    ///
    /// # Arguments
    /// * `preimage` - Field element preimage
    ///
    /// # Returns
    /// * Derived Ethereum address
    fn derive_ethereum_address_from_preimage(&self, preimage: Fr) -> Address {
        let hashed = compute_poseidon_hash(preimage, preimage);
        let hashed_bytes = hashed.into_bigint().to_bytes_be();

        let mut address_bytes = [0u8; 20];
        for (i, byte) in address_bytes.iter_mut().enumerate() {
            *byte = hashed_bytes.get(i).copied().unwrap_or(0);
        }

        Address::from_slice(&address_bytes)
    }

    /// Create a new coin from a field element amount
    ///
    /// # Arguments
    /// * `amount` - Coin amount as field element
    /// * `encrypted` - Whether the coin should be encrypted
    ///
    /// # Returns
    /// * New Coin instance with random salt
    pub fn create_coin(&self, amount: Fr, encrypted: bool) -> Coin {
        let amount_u256 =
            U256::from_be_bytes::<32>(amount.into_bigint().to_bytes_be().try_into().unwrap());
        let salt = U256::from_be_bytes::<32>(rand::random::<[u8; 32]>());

        Coin::new(amount_u256, salt, encrypted)
    }

    /// Add a coin to the wallet and persist to disk
    ///
    /// # Arguments
    /// * `coin` - Coin to add to the wallet
    ///
    /// # Returns
    /// * Result indicating success or error
    pub fn add_coin(&mut self, coin: Coin) -> Result<(), Box<dyn std::error::Error>> {
        self.coins.push(coin);
        self.save_to_file()?;
        Ok(())
    }

    /// Remove a coin from the wallet by index
    ///
    /// # Arguments
    /// * `index` - Index of coin to remove
    ///
    /// # Panics
    /// * If index is out of bounds
    pub fn remove_coin(&mut self, index: usize) {
        if index < self.coins.len() {
            self.coins.remove(index);
        }
    }

    /// Get a reference to all coins in the wallet
    ///
    /// # Returns
    /// * Slice of coins
    pub fn get_coins(&self) -> &[Coin] {
        &self.coins
    }

    /// Get the number of coins in the wallet
    ///
    /// # Returns
    /// * Number of coins
    pub fn coin_count(&self) -> usize {
        self.coins.len()
    }

    /// Save wallet to file
    ///
    /// # Returns
    /// * Result indicating success or error
    fn save_to_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = fs::File::create(WALLET_FILENAME)?;
        let json_data = serde_json::to_string_pretty(self)?;
        file.write_all(json_data.as_bytes())?;
        Ok(())
    }
}

// Re-export modules for external use
pub mod burn;
pub mod mint;

// Re-export commonly used functions and types
pub use burn::burn_cmd;
pub use mint::{mint_cmd, MintContext};
