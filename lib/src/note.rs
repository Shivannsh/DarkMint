use rand::{RngCore, rngs::OsRng};
use std::fmt;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use ark_bn254::Fr;

// The size of our secret and nullifier in bytes.
// 31 bytes is common for 254-bit fields like in BN254 to 
// avoid modulo bias.
const NOTE_SIZE: usize = 31;

/// Represents a deposit note, containing the core 
/// cryptographic secrets.
/// The `secret` provides ownership, and the `nullifier` 
/// prevents double-spending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub secret: [u8; NOTE_SIZE],
    pub nullifier: [u8; NOTE_SIZE],
}

impl Note {
    /// Creates a new Note with a cryptographically secure 
    /// random secret and nullifier.
    /// This is the standard way to create a note for a new 
    /// deposit.
    pub fn new() -> Self {
        let mut secret = [0u8; NOTE_SIZE];
        let mut nullifier = [0u8; NOTE_SIZE];

        // OsRng is a cryptographically secure random number
        // generator that pulls
        // from the operating system's entropy source. This 
        // is critical for security.
        OsRng.fill_bytes(&mut secret);
        OsRng.fill_bytes(&mut nullifier);

        Self { secret, nullifier }
    }

    /// Calculates the commitment for this note.
    /// The commitment is the public identifier of the 
    /// deposit that gets stored on-chain.
    pub fn commitment(&self) -> [u8; 32] {
        // Pad secret and nullifier to 32 bytes (big-endian, pad with leading zero)
        let mut secret_padded = [0u8; 32];
        let mut nullifier_padded = [0u8; 32];
        secret_padded[32 - NOTE_SIZE..].copy_from_slice(&self.secret);
        nullifier_padded[32 - NOTE_SIZE..].copy_from_slice(&self.nullifier);

        // Poseidon hash over the two 32-byte slices
        let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
        poseidon.hash_bytes_be(&[&secret_padded, &nullifier_padded]).unwrap()
    }

    /// Calculates the nullifier hash for this note.
    /// This value is revealed during a spend to prevent the
    /// note from being used again.
    pub fn nullifier_hash(&self) -> [u8; 32] {
        // Pad nullifier to 32 bytes (big-endian, pad with leading zero)
        let mut nullifier_padded = [0u8; 32];
        nullifier_padded[32 - NOTE_SIZE..].copy_from_slice(&self.nullifier);

        // Poseidon hash over the single 32-byte slice
        let mut poseidon = Poseidon::<Fr>::new_circom(1).unwrap();
        poseidon.hash_bytes_be(&[&nullifier_padded]).unwrap()
    }
}

/// Provides a user-friendly, partial hex representation for
/// display.
/// IMPORTANT: In a real app, you would be more careful 
/// about logging secrets.
impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Note(secret: 0x{}..., nullifier: 0x{}...)",
            hex::encode(&self.secret[0..4]),
            hex::encode(&self.nullifier[0..4])
        )
    }
}

// Implement Default trait for convenience in other parts of
// the code.
impl Default for Note {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_and_nullifier_hash_are_different_for_different_notes() {
        let note1 = Note::new();
        let note2 = Note::new();

        // Commitment and nullifier_hash should be 32 bytes
        assert_eq!(note1.commitment().len(), 32);

        assert_eq!(note1.nullifier_hash().len(), 32);

        // Different notes should have different commitments and nullifier hashes
        assert_ne!(note1.commitment(), note2.commitment());
        assert_ne!(note1.nullifier_hash(), note2.nullifier_hash());
    }

    #[test]
    fn test_commitment_and_nullifier_hash_are_consistent() {
        let note = Note::new();
        let commitment1 = note.commitment();
        let commitment2 = note.commitment();
        let nullifier_hash1 = note.nullifier_hash();
        let nullifier_hash2 = note.nullifier_hash();

        // The same note should always produce the same hash
        assert_eq!(commitment1, commitment2);
        assert_eq!(nullifier_hash1, nullifier_hash2);
    }
}