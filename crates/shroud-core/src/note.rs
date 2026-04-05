//! Note data structure, commitment, and nullifier derivation.
//!
//! Implements the note format specified in Technical_Req.md §4.
//!
//! # Note Structure (Technical_Req.md §4.1)
//!
//! ```text
//! Note {
//!     amount: u64
//!     blinding: GrumpkinScalar             // random, Pedersen hiding factor
//!     secret: GrumpkinScalar               // random, owner-only knowledge
//!     nullifier_preimage: GrumpkinScalar   // random, never appears on-chain
//!     owner_public_key: GrumpkinPoint      // owner's public key on Grumpkin
//!     leaf_index: u64                      // position in Merkle tree
//! }
//! ```
//!
//! # Note Commitment (Two-Layer) (Technical_Req.md §4.2)
//!
//! ```text
//! Layer 1 — Grumpkin Pedersen (native in BN254 UltraHonk):
//!     C = amount * G + blinding * H    (on Grumpkin curve)
//!
//! Layer 2 — Poseidon2 hash (goes into 4-ary Merkle tree):
//!     commitment = Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x)
//! ```
//!
//! # Nullifier Derivation (Technical_Req.md §4.3)
//!
//! ```text
//! nullifier = Poseidon2(nullifier_preimage, secret, leaf_index)
//! ```
//!
//! **GUARDRAIL G1**: Amount is NEVER a public input in private transfer.
//! **GUARDRAIL G2**: Nullifier is deterministic — same note always produces same nullifier.

use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Affine as GrumpkinAffine;

use crate::crypto::pedersen;
use crate::crypto::poseidon2;

/// Grumpkin scalar type (= BN254 base field Fq).
type GrumpkinScalar = ark_bn254::Fq;

/// BN254 scalar field type.
type Fr = ark_bn254::Fr;

/// A private note in the Shroud protocol.
///
/// Notes are the fundamental unit of value in the shielded pool.
/// Each note represents an amount of tokens owned by a specific public key,
/// with cryptographic blinding for privacy.
#[derive(Clone, Debug)]
pub struct Note {
    /// The token amount stored in this note.
    pub amount: u64,

    /// Random blinding factor for the Pedersen commitment hiding property.
    pub blinding: GrumpkinScalar,

    /// Random secret known only to the note owner.
    /// Used in both commitment and nullifier derivation.
    pub secret: GrumpkinScalar,

    /// Random preimage for nullifier derivation.
    /// Never appears on-chain in any form except as part of the nullifier hash.
    pub nullifier_preimage: GrumpkinScalar,

    /// Owner's public key on the Grumpkin curve.
    pub owner_public_key: GrumpkinAffine,

    /// Position in the Merkle tree (assigned when the note is inserted).
    pub leaf_index: u64,
}

impl Note {
    /// Create a new note with the given parameters.
    pub fn new(
        amount: u64,
        blinding: GrumpkinScalar,
        secret: GrumpkinScalar,
        nullifier_preimage: GrumpkinScalar,
        owner_public_key: GrumpkinAffine,
        leaf_index: u64,
    ) -> Self {
        Self {
            amount,
            blinding,
            secret,
            nullifier_preimage,
            owner_public_key,
            leaf_index,
        }
    }

    /// Compute the Layer 1 Pedersen commitment on Grumpkin.
    ///
    /// `C = amount * G + blinding * H`
    ///
    /// Returns the commitment as a Grumpkin affine point.
    pub fn pedersen_commitment(&self) -> GrumpkinAffine {
        pedersen::commit(self.amount, self.blinding)
    }

    /// Compute the full two-layer note commitment (Technical_Req.md §4.2).
    ///
    /// Layer 1: Pedersen commitment `C = amount * G + blinding * H` on Grumpkin
    /// Layer 2: `Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x)`
    ///
    /// The output is a BN254 scalar field element that goes into the 4-ary Merkle tree.
    ///
    /// # Note on Field Conversion
    ///
    /// The Grumpkin Pedersen commitment coordinates (C.x, C.y) are in Grumpkin's
    /// base field (= BN254 scalar field Fr). The secret and nullifier_preimage are
    /// in Grumpkin's scalar field (= BN254 base field Fq). For Poseidon2 hashing,
    /// all inputs must be in the same field (BN254 Fr). The Grumpkin scalar values
    /// are converted to BN254 Fr by interpreting their byte representation.
    pub fn commitment(&self) -> Fr {
        let pedersen = self.pedersen_commitment();
        
        // C.x and C.y are in GrumpkinBase = BN254 Fr (already correct field)
        let cx: Fr = pedersen.x()
            .expect("commitment should not be identity");
        let cy: Fr = pedersen.y()
            .expect("commitment should not be identity");
        
        // Convert GrumpkinScalar (= BN254 Fq) values to BN254 Fr for Poseidon2
        // We use the byte representation mod Fr order
        let secret_fr = grumpkin_scalar_to_fr(self.secret);
        let nullifier_preimage_fr = grumpkin_scalar_to_fr(self.nullifier_preimage);
        
        // pk.x is in GrumpkinBase = BN254 Fr (already correct field)
        let pk_x: Fr = self.owner_public_key.x()
            .expect("owner public key should not be identity");
        
        // commitment = Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x)
        poseidon2::poseidon2_hash_5(cx, cy, secret_fr, nullifier_preimage_fr, pk_x)
    }

    /// Compute the nullifier for this note (Technical_Req.md §4.3).
    ///
    /// `nullifier = Poseidon2(nullifier_preimage, secret, leaf_index)`
    ///
    /// **GUARDRAIL G2**: This derivation is deterministic — the same note
    /// always produces the same nullifier. The nullifier set is append-only
    /// and permanent.
    ///
    /// The nullifier reveals that a specific note has been spent, but does not
    /// reveal which note it was (since nullifier_preimage and secret are private).
    pub fn nullifier(&self) -> Fr {
        let nullifier_preimage_fr = grumpkin_scalar_to_fr(self.nullifier_preimage);
        let secret_fr = grumpkin_scalar_to_fr(self.secret);
        let leaf_index_fr = Fr::from(self.leaf_index);
        
        poseidon2::poseidon2_hash_3(nullifier_preimage_fr, secret_fr, leaf_index_fr)
    }
}

/// Convert a Grumpkin scalar (BN254 Fq) to a BN254 scalar (Fr).
///
/// Since both fields have similar (but not identical) orders, we convert
/// via the canonical byte representation, reducing mod Fr's order.
pub fn grumpkin_scalar_to_fr(val: GrumpkinScalar) -> Fr {
    let bytes = val.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero, One};
    use ark_ec::CurveGroup;

    /// Create a test note with deterministic values.
    fn test_note() -> Note {
        let g = pedersen::generator_g();
        // Use G as the "public key" for testing (not secure, just for testing)
        Note::new(
            100,                              // amount
            GrumpkinScalar::from(42u64),      // blinding
            GrumpkinScalar::from(123u64),     // secret
            GrumpkinScalar::from(456u64),     // nullifier_preimage
            g,                                // owner_public_key
            7,                                // leaf_index
        )
    }

    #[test]
    fn test_note_commitment_deterministic() {
        let note = test_note();
        let c1 = note.commitment();
        let c2 = note.commitment();
        assert_eq!(c1, c2, "Note commitment must be deterministic");
    }

    #[test]
    fn test_note_nullifier_deterministic() {
        // GUARDRAIL G2: same note must always produce same nullifier
        let note = test_note();
        let n1 = note.nullifier();
        let n2 = note.nullifier();
        assert_eq!(n1, n2, "Nullifier must be deterministic (G2)");
    }

    #[test]
    fn test_different_amounts_different_commitments() {
        let note1 = test_note();
        let mut note2 = test_note();
        note2.amount = 200;
        
        assert_ne!(
            note1.commitment(), note2.commitment(),
            "Different amounts must produce different commitments"
        );
    }

    #[test]
    fn test_different_secrets_different_commitments() {
        let note1 = test_note();
        let mut note2 = test_note();
        note2.secret = GrumpkinScalar::from(999u64);
        
        assert_ne!(
            note1.commitment(), note2.commitment(),
            "Different secrets must produce different commitments"
        );
    }

    #[test]
    fn test_different_leaf_index_different_nullifier() {
        let note1 = test_note();
        let mut note2 = test_note();
        note2.leaf_index = 8;
        
        assert_ne!(
            note1.nullifier(), note2.nullifier(),
            "Different leaf indices must produce different nullifiers"
        );
    }

    #[test]
    fn test_same_note_different_leaf_same_commitment() {
        // Changing leaf_index should NOT change the commitment
        // (leaf_index is not part of the commitment formula)
        let note1 = test_note();
        let mut note2 = test_note();
        note2.leaf_index = 8;
        
        assert_eq!(
            note1.commitment(), note2.commitment(),
            "Leaf index should not affect commitment (only nullifier)"
        );
    }

    #[test]
    fn test_commitment_not_zero() {
        let note = test_note();
        assert_ne!(note.commitment(), Fr::zero(), "Commitment should not be zero");
    }

    #[test]
    fn test_nullifier_not_zero() {
        let note = test_note();
        assert_ne!(note.nullifier(), Fr::zero(), "Nullifier should not be zero");
    }

    #[test]
    fn test_pedersen_commitment_on_curve() {
        let note = test_note();
        let pc = note.pedersen_commitment();
        assert!(pc.is_on_curve(), "Pedersen commitment must be on Grumpkin curve");
    }

    #[test]
    fn test_pedersen_verify_opening() {
        let note = test_note();
        let pc = note.pedersen_commitment();
        assert!(
            pedersen::verify_opening(pc, note.amount, note.blinding),
            "Pedersen commitment must open correctly"
        );
    }
}
