//! Nullifier derivation gadget.
//!
//! A nullifier is a deterministic, public tag derived from private note data.
//! Publishing a nullifier marks a note as "spent" without revealing which note
//! it corresponds to. The same note always produces the same nullifier,
//! preventing double-spending.
//!
//! This gadget is generic — it hashes an arbitrary set of private fields
//! via Poseidon2. The canonical pattern is `nullifier = Poseidon2(secret, leaf_index, ...)`
//! but applications can include additional fields (e.g. nullifier preimage,
//! domain separators).

use crate::arithmetization::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};
use crate::gadgets::poseidon2_gadget::poseidon2_hash_gadget;
use crate::crypto::poseidon2::poseidon2_hash;
use ark_bn254::Fr;

/// In-circuit nullifier derivation over arbitrary private fields.
///
/// Constrains `nullifier = Poseidon2(fields[0], fields[1], ...)`.
///
/// # Common patterns
/// ```text
/// nullifier_gadget(builder, &[secret, leaf_index])              // 2-field
/// nullifier_gadget(builder, &[preimage, secret, leaf_index])    // 3-field (shroud-pool)
/// ```
///
/// # Panics
/// Panics if `fields` is empty.
pub fn nullifier_gadget(
    builder: &mut UltraCircuitBuilder,
    fields: &[WireRef],
) -> WireRef {
    poseidon2_hash_gadget(builder, fields)
}

/// Native nullifier derivation (outside the circuit).
///
/// Computes `nullifier = Poseidon2(fields[0], fields[1], ...)`.
/// Use this to compute expected nullifier values for witness generation
/// or verification.
///
/// # Panics
/// Panics if `fields` is empty.
pub fn nullifier_native(fields: &[Fr]) -> Fr {
    poseidon2_hash(fields)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gadget_matches_native_3_fields() {
        let preimage = Fr::from(42u64);
        let secret = Fr::from(100u64);
        let leaf_idx = Fr::from(7u64);

        let expected = nullifier_native(&[preimage, secret, leaf_idx]);

        let mut builder = UltraCircuitBuilder::new();
        let np_w = builder.add_variable(preimage);
        let s_w = builder.add_variable(secret);
        let li_w = builder.add_variable(leaf_idx);
        let result = nullifier_gadget(&mut builder, &[np_w, s_w, li_w]);

        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn gadget_matches_native_2_fields() {
        let secret = Fr::from(100u64);
        let leaf_idx = Fr::from(7u64);

        let expected = nullifier_native(&[secret, leaf_idx]);

        let mut builder = UltraCircuitBuilder::new();
        let s_w = builder.add_variable(secret);
        let li_w = builder.add_variable(leaf_idx);
        let result = nullifier_gadget(&mut builder, &[s_w, li_w]);

        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn deterministic() {
        let fields = [Fr::from(42u64), Fr::from(100u64), Fr::from(7u64)];

        let mut b1 = UltraCircuitBuilder::new();
        let w1: Vec<_> = fields.iter().map(|&f| b1.add_variable(f)).collect();
        let r1 = nullifier_gadget(&mut b1, &w1);

        let mut b2 = UltraCircuitBuilder::new();
        let w2: Vec<_> = fields.iter().map(|&f| b2.add_variable(f)).collect();
        let r2 = nullifier_gadget(&mut b2, &w2);

        assert_eq!(b1.get_variable(r1), b2.get_variable(r2));
    }

    #[test]
    fn different_inputs_different_nullifiers() {
        let n1 = nullifier_native(&[Fr::from(1u64), Fr::from(0u64)]);
        let n2 = nullifier_native(&[Fr::from(1u64), Fr::from(1u64)]);
        assert_ne!(n1, n2);
    }
}
