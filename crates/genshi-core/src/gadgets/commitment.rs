//! Note commitment gadget (generic, variable-field).
//!
//! A commitment binds private data into a single public hash that can be
//! stored on-chain (e.g. in a Merkle tree) without revealing the underlying
//! values. The commitment is hiding (the prover controls the inputs) and
//! binding (changing any input changes the hash).
//!
//! This gadget is generic — it hashes an arbitrary number of field elements
//! via Poseidon2. Applications choose which fields to commit to:
//!
//! ```text
//! // 3-field: amount, secret, owner
//! commitment_gadget(builder, &[amount, secret, owner])
//!
//! // 5-field: Pedersen coords + secrets (shroud-pool pattern)
//! commitment_gadget(builder, &[cx, cy, secret, nullifier_preimage, pk_x])
//!
//! // 4-field: amount, secret, owner, asset_id (multi-token)
//! commitment_gadget(builder, &[amount, secret, owner, asset_id])
//! ```
//!
//! For protocols that use a two-layer scheme (Pedersen commitment + Poseidon2
//! hash), the [`commitment_with_pedersen_gadget`] convenience function handles
//! injecting pre-computed Pedersen coordinates as witness values.

use alloc::vec::Vec;
use ark_bn254::Fr;

use crate::arithmetization::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};
use crate::gadgets::poseidon2_gadget::poseidon2_hash_gadget;
use crate::crypto::poseidon2::poseidon2_hash;

/// In-circuit commitment over arbitrary fields.
///
/// Constrains `commitment = Poseidon2(fields[0], fields[1], ...)`.
///
/// # Panics
/// Panics if `fields` is empty.
pub fn commitment_gadget(
    builder: &mut UltraCircuitBuilder,
    fields: &[WireRef],
) -> WireRef {
    poseidon2_hash_gadget(builder, fields)
}

/// Native commitment computation (outside the circuit).
///
/// Computes `commitment = Poseidon2(fields[0], fields[1], ...)`.
/// Use this for witness generation, Merkle leaf computation, or verification.
///
/// # Panics
/// Panics if `fields` is empty.
pub fn commitment_native(fields: &[Fr]) -> Fr {
    poseidon2_hash(fields)
}

/// In-circuit commitment with pre-computed Pedersen coordinates.
///
/// This is a convenience for the two-layer commitment scheme:
///   Layer 1 (native): `C = amount * G + blinding * H` (Pedersen on Grumpkin)
///   Layer 2 (in-circuit): `commitment = Poseidon2(C.x, C.y, extra_fields...)`
///
/// The Pedersen coordinates are injected as witness values and hashed
/// together with any additional private fields.
///
/// # Arguments
/// * `builder` — circuit builder
/// * `pedersen_cx` — pre-computed Pedersen commitment x-coordinate (native value)
/// * `pedersen_cy` — pre-computed Pedersen commitment y-coordinate (native value)
/// * `extra_fields` — additional private witness wires (e.g. secret, nullifier_preimage, pk_x)
///
/// # Returns
/// Wire reference to the commitment hash.
pub fn commitment_with_pedersen_gadget(
    builder: &mut UltraCircuitBuilder,
    pedersen_cx: Fr,
    pedersen_cy: Fr,
    extra_fields: &[WireRef],
) -> WireRef {
    let cx = builder.add_variable(pedersen_cx);
    let cy = builder.add_variable(pedersen_cy);

    let mut all_fields = Vec::with_capacity(2 + extra_fields.len());
    all_fields.push(cx);
    all_fields.push(cy);
    all_fields.extend_from_slice(extra_fields);

    commitment_gadget(builder, &all_fields)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gadget_matches_native_3_fields() {
        let amount = Fr::from(100u64);
        let secret = Fr::from(42u64);
        let owner = Fr::from(999u64);

        let expected = commitment_native(&[amount, secret, owner]);

        let mut builder = UltraCircuitBuilder::new();
        let a_w = builder.add_variable(amount);
        let s_w = builder.add_variable(secret);
        let o_w = builder.add_variable(owner);
        let result = commitment_gadget(&mut builder, &[a_w, s_w, o_w]);

        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn gadget_matches_native_5_fields() {
        let vals = [
            Fr::from(111u64),
            Fr::from(222u64),
            Fr::from(333u64),
            Fr::from(444u64),
            Fr::from(555u64),
        ];

        let expected = commitment_native(&vals);

        let mut builder = UltraCircuitBuilder::new();
        let wires: Vec<_> = vals.iter().map(|&v| builder.add_variable(v)).collect();
        let result = commitment_gadget(&mut builder, &wires);

        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn pedersen_convenience_matches_manual() {
        let cx = Fr::from(111u64);
        let cy = Fr::from(222u64);
        let secret = Fr::from(333u64);
        let np = Fr::from(444u64);
        let pk_x = Fr::from(555u64);

        // Manual: hash all 5 fields
        let expected = commitment_native(&[cx, cy, secret, np, pk_x]);

        // Via convenience function
        let mut builder = UltraCircuitBuilder::new();
        let s_w = builder.add_variable(secret);
        let np_w = builder.add_variable(np);
        let pk_w = builder.add_variable(pk_x);
        let result = commitment_with_pedersen_gadget(
            &mut builder,
            cx,
            cy,
            &[s_w, np_w, pk_w],
        );

        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn different_fields_different_commitments() {
        let c1 = commitment_native(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        let c2 = commitment_native(&[Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn works_with_many_fields() {
        // 8 fields — exercises multi-chunk sponge
        let vals: Vec<Fr> = (1..=8).map(|i| Fr::from(i as u64)).collect();
        let expected = commitment_native(&vals);

        let mut builder = UltraCircuitBuilder::new();
        let wires: Vec<_> = vals.iter().map(|&v| builder.add_variable(v)).collect();
        let result = commitment_gadget(&mut builder, &wires);

        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }
}
