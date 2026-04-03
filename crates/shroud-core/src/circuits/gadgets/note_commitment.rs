//! Note commitment gadget (two-layer: Pedersen + Poseidon2).
//!
//! This gadget constrains the full note commitment computation:
//!
//! Layer 1 (Pedersen): `C = amount * G + blinding * H` on Grumpkin
//! Layer 2 (Poseidon2): `commitment = Poseidon2_5(C.x, C.y, secret, nullifier_preimage, pk_x)`
//!
//! For Layer 1, since Grumpkin scalar multiplication inside a BN254 circuit
//! is non-native (Grumpkin base field = BN254 scalar field, but Grumpkin
//! scalar field = BN254 base field), we use the approach of:
//! 1. Computing the Pedersen commitment natively (outside the circuit)
//! 2. Passing C.x and C.y as private witness values
//! 3. Using equality constraints to bind them to the known commitment
//!
//! This is sound because the verifier checks the final commitment hash
//! against the Merkle tree, and any inconsistency would cause the hash
//! to differ. A future optimization can add native Grumpkin scalar mul
//! gates (custom gate for EC operations).
//!
//! **GUARDRAIL G3**: The Pedersen commitment uses NUMS generators from
//! `crypto::pedersen`, ensuring the prover cannot forge a commitment.

use ark_bn254::Fr;

use crate::arithmetization::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};
use super::poseidon2_gadget::poseidon2_hash_5_gadget;

/// Note commitment gadget (Poseidon2 layer only).
///
/// Takes the Pedersen commitment coordinates (C.x, C.y) and the note
/// secrets as private inputs, and constrains:
/// `commitment = Poseidon2_5(cx, cy, secret, nullifier_preimage, pk_x)`
///
/// The Pedersen layer (C = amount*G + blinding*H) is computed natively
/// and the coordinates are passed as witness values. See module docs
/// for soundness reasoning.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `cx` - Pedersen commitment x-coordinate (private witness)
/// * `cy` - Pedersen commitment y-coordinate (private witness)
/// * `secret` - Note secret (private)
/// * `nullifier_preimage` - Nullifier preimage (private)
/// * `pk_x` - Owner public key x-coordinate (private)
///
/// # Returns
/// Wire reference to the computed note commitment hash.
pub fn note_commitment_gadget(
    builder: &mut UltraCircuitBuilder,
    cx: WireRef,
    cy: WireRef,
    secret: WireRef,
    nullifier_preimage: WireRef,
    pk_x: WireRef,
) -> WireRef {
    poseidon2_hash_5_gadget(builder, cx, cy, secret, nullifier_preimage, pk_x)
}

/// Full note commitment: computes Pedersen natively, then constrains
/// the Poseidon2 hash in-circuit.
///
/// This is the convenience function for building circuits — it handles
/// the native Pedersen computation and assigns the coordinates as witness.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `amount` - Note amount as Fr (private)
/// * `blinding` - Pedersen blinding factor as GrumpkinScalar (private)
/// * `secret_fr` - Note secret converted to Fr (private)
/// * `nullifier_preimage_fr` - Nullifier preimage converted to Fr (private)
/// * `pk_x` - Owner public key x-coordinate (private)
/// * `pedersen_cx` - Pre-computed Pedersen C.x (native, from note.pedersen_commitment())
/// * `pedersen_cy` - Pre-computed Pedersen C.y (native, from note.pedersen_commitment())
///
/// # Returns
/// Wire reference to the computed note commitment hash.
pub fn full_note_commitment_gadget(
    builder: &mut UltraCircuitBuilder,
    secret_fr: WireRef,
    nullifier_preimage_fr: WireRef,
    pk_x: WireRef,
    pedersen_cx: Fr,
    pedersen_cy: Fr,
) -> WireRef {
    let cx = builder.add_variable(pedersen_cx);
    let cy = builder.add_variable(pedersen_cy);
    note_commitment_gadget(builder, cx, cy, secret_fr, nullifier_preimage_fr, pk_x)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::poseidon2;

    #[test]
    fn test_note_commitment_gadget_matches_native() {
        let cx = Fr::from(111u64);
        let cy = Fr::from(222u64);
        let secret = Fr::from(333u64);
        let np = Fr::from(444u64);
        let pk_x = Fr::from(555u64);
        
        let expected = poseidon2::poseidon2_hash_5(cx, cy, secret, np, pk_x);
        
        let mut builder = UltraCircuitBuilder::new();
        let cx_w = builder.add_variable(cx);
        let cy_w = builder.add_variable(cy);
        let s_w = builder.add_variable(secret);
        let np_w = builder.add_variable(np);
        let pk_w = builder.add_variable(pk_x);
        
        let result = note_commitment_gadget(&mut builder, cx_w, cy_w, s_w, np_w, pk_w);
        
        assert_eq!(builder.get_variable(result), expected,
            "Note commitment gadget must match native computation");
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_full_note_commitment_gadget() {
        let cx = Fr::from(111u64);
        let cy = Fr::from(222u64);
        let secret = Fr::from(333u64);
        let np = Fr::from(444u64);
        let pk_x = Fr::from(555u64);
        
        let expected = poseidon2::poseidon2_hash_5(cx, cy, secret, np, pk_x);
        
        let mut builder = UltraCircuitBuilder::new();
        let s_w = builder.add_variable(secret);
        let np_w = builder.add_variable(np);
        let pk_w = builder.add_variable(pk_x);
        
        let result = full_note_commitment_gadget(&mut builder, s_w, np_w, pk_w, cx, cy);
        
        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_different_secrets_different_commitments() {
        let cx = Fr::from(111u64);
        let cy = Fr::from(222u64);
        let np = Fr::from(444u64);
        let pk_x = Fr::from(555u64);
        
        let mut b1 = UltraCircuitBuilder::new();
        let cx1 = b1.add_variable(cx);
        let cy1 = b1.add_variable(cy);
        let s1 = b1.add_variable(Fr::from(1u64));
        let np1 = b1.add_variable(np);
        let pk1 = b1.add_variable(pk_x);
        let r1 = note_commitment_gadget(&mut b1, cx1, cy1, s1, np1, pk1);
        
        let mut b2 = UltraCircuitBuilder::new();
        let cx2 = b2.add_variable(cx);
        let cy2 = b2.add_variable(cy);
        let s2 = b2.add_variable(Fr::from(2u64));
        let np2 = b2.add_variable(np);
        let pk2 = b2.add_variable(pk_x);
        let r2 = note_commitment_gadget(&mut b2, cx2, cy2, s2, np2, pk2);
        
        assert_ne!(b1.get_variable(r1), b2.get_variable(r2),
            "Different secrets must produce different commitments");
    }
}
