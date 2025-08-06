use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;

const NOTE_SIZE: usize = 32;

// MiMC7 implementation (simplified from Python)
pub fn poseidon_hash(left: Fr, right: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let left_bytes = left.into_bigint().to_bytes_be();
    let right_bytes = right.into_bigint().to_bytes_be();
    let hash_bytes = poseidon
        .hash_bytes_be(&[&left_bytes, &right_bytes])
        .unwrap();
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Coin {
    pub amount: U256,
    pub salt: U256,
    pub encrypted: bool,
}

impl Coin {
    pub fn get_value(&self) -> U256 {
        if self.encrypted {
            let left_bytes = self.amount.to_be_bytes::<32>();
            let right_bytes = self.salt.to_be_bytes::<32>();
            let left = Fr::from_le_bytes_mod_order(&left_bytes);
            let right = Fr::from_le_bytes_mod_order(&right_bytes);
            let result = poseidon_hash(left, right);
            U256::from_be_bytes::<32>(result.into_bigint().to_bytes_be().try_into().unwrap())
        } else {
            self.amount
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    entropy: String,
    coins: Vec<Coin>,
}

#[derive(Debug)]
pub struct BurnAddress {
    pub preimage: Fr,
    pub address: Address,
}

impl Wallet {
    pub fn open_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = "burnth.priv";
        if !std::path::Path::new(path).exists() {
            let mut entropy = [0u8; NOTE_SIZE];
            OsRng.fill_bytes(&mut entropy);
            let wallet = Wallet {
                entropy: hex::encode(entropy),
                coins: vec![],
            };
            let mut file = fs::File::create(path)?;
            file.write_all(serde_json::to_string(&wallet)?.as_bytes())?;
            Ok(wallet)
        } else {
            let content = fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        }
    }

    pub fn derive_burn_addr(&self, index: u64) -> Result<BurnAddress, Box<dyn std::error::Error>> {
        let entropy_bytes = hex::decode(&self.entropy)?;
        let mut hasher = Sha256::new();
        hasher.update(&entropy_bytes);
        hasher.update(&index.to_le_bytes());
        let result = hasher.finalize();

        let preimage = Fr::from_le_bytes_mod_order(&result[..31]);
        let hashed = poseidon_hash(preimage, preimage);

        let mut bts = [0u8; 20];
        let hashed_bytes = hashed.into_bigint().to_bytes_be();
        for i in 0..20 {
            bts[i] = hashed_bytes.get(i).copied().unwrap_or(0);
        }
        let address = Address::from_slice(&bts);

        Ok(BurnAddress { preimage, address })
    }

    pub fn derive_coin(&self, amount: Fr, encrypted: bool) -> Coin {
        Coin {
            amount: U256::from_be_bytes::<32>(
                amount.into_bigint().to_bytes_be().try_into().unwrap(),
            ),
            salt: U256::from_be_bytes::<32>(rand::random::<[u8; 32]>()),
            encrypted,
        }
    }

    pub fn add_coin(&mut self, coin: Coin) -> Result<(), Box<dyn std::error::Error>> {
        self.coins.push(coin);
        self.save()?;
        Ok(())
    }

    pub fn remove_coin(&mut self, index: usize) {
        self.coins.remove(index);
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = "burnth.priv";
        let mut file = fs::File::create(path)?;
        file.write_all(serde_json::to_string(self)?.as_bytes())?;
        Ok(())
    }
}