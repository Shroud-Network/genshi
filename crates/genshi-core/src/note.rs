//! Note data structure, commitment, and nullifier derivation.
//!
//! A `Note` is the fundamental unit of value in a shielded pool: an amount
//! bound to an owner public key, hidden by a Pedersen commitment and made
//! spendable via a deterministic nullifier.
//!
//! # Note structure
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
//! # Note commitment (two-layer)
//!
//! ```text
//! Layer 1 — Grumpkin Pedersen (native in BN254 UltraHonk):
//!     C = amount * G + blinding * H    (on Grumpkin curve)
//!
//! Layer 2 — Poseidon2 hash (goes into Merkle tree):
//!     commitment = Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x)
//! ```
//!
//! # Nullifier derivation
//!
//! ```text
//! nullifier = Poseidon2(nullifier_preimage, secret, leaf_index)
//! ```
//!
//! The nullifier reveals that a specific note has been spent, but not which
//! one — `nullifier_preimage` and `secret` stay private.

use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Affine as GrumpkinAffine;

use crate::crypto::pedersen;
use crate::crypto::poseidon2;

/// Grumpkin scalar type (= BN254 base field Fq).
type GrumpkinScalar = ark_bn254::Fq;

/// BN254 scalar field type.
type Fr = ark_bn254::Fr;

/// A private note.
#[derive(Clone, Debug)]
pub struct Note {
    /// Token amount stored in this note.
    pub amount: u64,

    /// Random blinding factor for the Pedersen commitment hiding property.
    pub blinding: GrumpkinScalar,

    /// Random secret known only to the note owner.
    /// Used in both commitment and nullifier derivation.
    pub secret: GrumpkinScalar,

    /// Random preimage for nullifier derivation.
    /// Never appears on-chain except as part of the nullifier hash.
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
    pub fn pedersen_commitment(&self) -> GrumpkinAffine {
        pedersen::commit(self.amount, self.blinding)
    }

    /// Compute the full two-layer note commitment.
    ///
    /// Layer 1: Pedersen commitment `C = amount * G + blinding * H` on Grumpkin.
    /// Layer 2: `Poseidon2(C.x, C.y, secret, nullifier_preimage, pk.x)`.
    pub fn commitment(&self) -> Fr {
        let pedersen = self.pedersen_commitment();

        let cx: Fr = pedersen.x().expect("commitment should not be identity");
        let cy: Fr = pedersen.y().expect("commitment should not be identity");

        let secret_fr = grumpkin_scalar_to_fr(self.secret);
        let nullifier_preimage_fr = grumpkin_scalar_to_fr(self.nullifier_preimage);

        let pk_x: Fr = self
            .owner_public_key
            .x()
            .expect("owner public key should not be identity");

        poseidon2::poseidon2_hash(&[cx, cy, secret_fr, nullifier_preimage_fr, pk_x])
    }

    /// Compute the nullifier for this note.
    ///
    /// `nullifier = Poseidon2(nullifier_preimage, secret, leaf_index)`
    ///
    /// Deterministic: the same note always produces the same nullifier.
    pub fn nullifier(&self) -> Fr {
        let nullifier_preimage_fr = grumpkin_scalar_to_fr(self.nullifier_preimage);
        let secret_fr = grumpkin_scalar_to_fr(self.secret);
        let leaf_index_fr = Fr::from(self.leaf_index);

        poseidon2::poseidon2_hash(&[nullifier_preimage_fr, secret_fr, leaf_index_fr])
    }
}

/// Convert a Grumpkin scalar (BN254 Fq) to a BN254 scalar (Fr).
///
/// The two fields have similar but not identical orders, so we convert via
/// the canonical byte representation, reducing mod Fr's order.
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
    use ark_ff::Zero;

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
    fn test_note_commitment_deterministic() {
        let note = test_note();
        assert_eq!(note.commitment(), note.commitment());
    }

    #[test]
    fn test_note_nullifier_deterministic() {
        let note = test_note();
        assert_eq!(note.nullifier(), note.nullifier());
    }

    #[test]
    fn test_different_amounts_different_commitments() {
        let n1 = test_note();
        let mut n2 = test_note();
        n2.amount = 200;
        assert_ne!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn test_different_leaf_index_different_nullifier() {
        let n1 = test_note();
        let mut n2 = test_note();
        n2.leaf_index = 8;
        assert_ne!(n1.nullifier(), n2.nullifier());
    }

    #[test]
    fn test_leaf_index_does_not_affect_commitment() {
        let n1 = test_note();
        let mut n2 = test_note();
        n2.leaf_index = 8;
        assert_eq!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn test_commitment_not_zero() {
        assert_ne!(test_note().commitment(), Fr::zero());
    }

    #[test]
    fn test_pedersen_commitment_on_curve() {
        assert!(test_note().pedersen_commitment().is_on_curve());
    }

    #[test]
    fn test_pedersen_verify_opening() {
        let note = test_note();
        let pc = note.pedersen_commitment();
        assert!(pedersen::verify_opening(pc, note.amount, note.blinding));
    }
}
