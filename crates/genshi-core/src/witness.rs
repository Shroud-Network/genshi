//! JSON-friendly witness primitives for CLI and WASM.
//!
//! Arkworks types (`Fr`, `Fq`, `GrumpkinAffine`, `MerklePath`) don't derive
//! serde. This module provides hex-encoded proxies that do, plus conversion
//! helpers. App crates compose these into their own circuit-specific witness
//! JSON types.
//!
//! # Typical usage
//!
//! Hex-encoded scalars round-trip losslessly:
//!
//! ```
//! use genshi_core::witness::{fr_to_hex, fr_from_hex};
//! use ark_bn254::Fr;
//!
//! let val = Fr::from(12345678u64);
//! let hex = fr_to_hex(&val);
//! assert!(hex.starts_with("0x"));
//! assert_eq!(fr_from_hex(&hex).unwrap(), val);
//! ```
//!
//! App crates compose `NoteJson` and `MerklePathJson` into circuit-specific
//! witness structs and derive `serde::{Serialize, Deserialize}` on them.
//! The derives are behind genshi-core's `serde` feature so verifier-only
//! targets (Solana BPF, embedded) don't pull serde in.

use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Affine as GrumpkinAffine;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::gadgets::merkle::{MerklePath, MERKLE_DEPTH};
use crate::note::Note;

type GrumpkinScalar = ark_bn254::Fq;

/// Grumpkin base field = BN254 scalar field Fr.
/// Used for Grumpkin point coordinates.
type GrumpkinBase = ark_bn254::Fr;

/// Witness conversion error.
#[derive(Debug)]
pub enum WitnessError {
    InvalidHex(String),
    InvalidFieldElement(String),
    InvalidPoint(String),
    InvalidMerklePath(String),
}

// ============================================================================
// JSON proxy types
// ============================================================================

/// JSON-serializable note.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NoteJson {
    pub amount: u64,
    pub blinding: String,
    pub secret: String,
    pub nullifier_preimage: String,
    pub owner_public_key_x: String,
    pub owner_public_key_y: String,
    pub leaf_index: u64,
}

/// JSON-serializable Merkle path.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MerklePathJson {
    pub siblings: Vec<Vec<String>>,
    pub indices: Vec<u8>,
}

// ============================================================================
// Note <-> NoteJson
// ============================================================================

impl NoteJson {
    /// Convert from a native `Note` to a JSON-friendly representation.
    pub fn from_note(note: &Note) -> Self {
        let pk_x: GrumpkinBase = note
            .owner_public_key
            .x()
            .expect("public key must not be identity");
        let pk_y: GrumpkinBase = note
            .owner_public_key
            .y()
            .expect("public key must not be identity");
        NoteJson {
            amount: note.amount,
            blinding: fq_to_hex(&note.blinding),
            secret: fq_to_hex(&note.secret),
            nullifier_preimage: fq_to_hex(&note.nullifier_preimage),
            owner_public_key_x: grumpkin_base_to_hex(&pk_x),
            owner_public_key_y: grumpkin_base_to_hex(&pk_y),
            leaf_index: note.leaf_index,
        }
    }

    /// Convert to a native `Note`.
    pub fn to_note(&self) -> Result<Note, WitnessError> {
        let blinding = fq_from_hex(&self.blinding)?;
        let secret = fq_from_hex(&self.secret)?;
        let nullifier_preimage = fq_from_hex(&self.nullifier_preimage)?;
        let pk_x = grumpkin_base_from_hex(&self.owner_public_key_x)?;
        let pk_y = grumpkin_base_from_hex(&self.owner_public_key_y)?;

        let owner_public_key = GrumpkinAffine::new(pk_x, pk_y);

        Ok(Note::new(
            self.amount,
            blinding,
            secret,
            nullifier_preimage,
            owner_public_key,
            self.leaf_index,
        ))
    }
}

// ============================================================================
// MerklePath <-> MerklePathJson
// ============================================================================

impl MerklePathJson {
    /// Convert from a native `MerklePath`.
    pub fn from_path(path: &MerklePath) -> Self {
        let siblings = path
            .siblings
            .iter()
            .map(|level| level.iter().map(fr_to_hex).collect())
            .collect();
        let indices = path.indices.to_vec();
        MerklePathJson { siblings, indices }
    }

    /// Convert to a native `MerklePath`.
    pub fn to_path(&self) -> Result<MerklePath, WitnessError> {
        if self.siblings.len() != MERKLE_DEPTH || self.indices.len() != MERKLE_DEPTH {
            return Err(WitnessError::InvalidMerklePath(format!(
                "expected {} levels, got siblings={} indices={}",
                MERKLE_DEPTH,
                self.siblings.len(),
                self.indices.len()
            )));
        }

        let mut siblings = [[Fr::default(); 3]; MERKLE_DEPTH];
        for (i, level) in self.siblings.iter().enumerate() {
            if level.len() != 3 {
                return Err(WitnessError::InvalidMerklePath(format!(
                    "level {} has {} siblings, expected 3",
                    i,
                    level.len()
                )));
            }
            for (j, s) in level.iter().enumerate() {
                siblings[i][j] = fr_from_hex(s)?;
            }
        }

        let mut indices = [0u8; MERKLE_DEPTH];
        indices.copy_from_slice(&self.indices);

        Ok(MerklePath { siblings, indices })
    }
}

// ============================================================================
// Hex encoding helpers (public — used by app crates building custom witnesses)
// ============================================================================

/// Hex-encode bytes with a `0x` prefix (little-endian for field elements).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a `0x`-prefixed hex string to bytes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, WitnessError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(WitnessError::InvalidHex(format!("odd length: {}", s.len())));
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| WitnessError::InvalidHex(format!("{e}")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Hex-encode a BN254 scalar (Fr) as little-endian `0x…`.
pub fn fr_to_hex(val: &Fr) -> String {
    hex_encode(&val.into_bigint().to_bytes_le())
}

/// Parse a hex-encoded BN254 scalar. Reduces mod Fr order.
pub fn fr_from_hex(s: &str) -> Result<Fr, WitnessError> {
    let bytes = hex_decode(s)?;
    Ok(Fr::from_le_bytes_mod_order(&bytes))
}

/// Alias retained for compatibility with `register!` closures.
pub fn fr_from_hex_pub(s: &str) -> Result<Fr, WitnessError> {
    fr_from_hex(s)
}

/// Hex-encode a Grumpkin scalar (= BN254 Fq).
pub fn fq_to_hex(val: &GrumpkinScalar) -> String {
    hex_encode(&val.into_bigint().to_bytes_le())
}

/// Parse a hex-encoded Grumpkin scalar. Reduces mod Fq order.
pub fn fq_from_hex(s: &str) -> Result<GrumpkinScalar, WitnessError> {
    let bytes = hex_decode(s)?;
    Ok(GrumpkinScalar::from_le_bytes_mod_order(&bytes))
}

/// Hex-encode a Grumpkin base field element (= BN254 Fr).
pub fn grumpkin_base_to_hex(val: &GrumpkinBase) -> String {
    hex_encode(&val.into_bigint().to_bytes_le())
}

/// Parse a hex-encoded Grumpkin base field element.
pub fn grumpkin_base_from_hex(s: &str) -> Result<GrumpkinBase, WitnessError> {
    let bytes = hex_decode(s)?;
    Ok(GrumpkinBase::from_le_bytes_mod_order(&bytes))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen;

    fn test_note() -> Note {
        let g = pedersen::generator_g();
        Note::new(
            100,
            GrumpkinScalar::from(42u64),
            GrumpkinScalar::from(123u64),
            GrumpkinScalar::from(456u64),
            g,
            7,
        )
    }

    #[test]
    fn test_note_json_roundtrip() {
        let note = test_note();
        let json = NoteJson::from_note(&note);
        let note2 = json.to_note().expect("conversion should succeed");

        assert_eq!(note.amount, note2.amount);
        assert_eq!(note.blinding, note2.blinding);
        assert_eq!(note.secret, note2.secret);
        assert_eq!(note.nullifier_preimage, note2.nullifier_preimage);
        assert_eq!(note.owner_public_key, note2.owner_public_key);
        assert_eq!(note.leaf_index, note2.leaf_index);
        assert_eq!(note.commitment(), note2.commitment());
        assert_eq!(note.nullifier(), note2.nullifier());
    }

    #[test]
    fn test_merkle_path_json_roundtrip() {
        let path = MerklePath {
            siblings: core::array::from_fn(|i| {
                [
                    Fr::from((i * 3) as u64),
                    Fr::from((i * 3 + 1) as u64),
                    Fr::from((i * 3 + 2) as u64),
                ]
            }),
            indices: [0, 1, 2, 3, 0, 1, 2, 3, 0, 1],
        };
        let json = MerklePathJson::from_path(&path);
        let path2 = json.to_path().expect("conversion should succeed");
        assert_eq!(path.siblings, path2.siblings);
        assert_eq!(path.indices, path2.indices);
    }

    #[test]
    fn test_fr_hex_roundtrip() {
        let val = Fr::from(12345678u64);
        assert_eq!(val, fr_from_hex(&fr_to_hex(&val)).unwrap());
    }

    #[test]
    fn test_fq_hex_roundtrip() {
        let val = GrumpkinScalar::from(987654321u64);
        assert_eq!(val, fq_from_hex(&fq_to_hex(&val)).unwrap());
    }

    #[test]
    fn test_invalid_hex_fails() {
        assert!(fr_from_hex("0xZZZZ").is_err());
    }
}
