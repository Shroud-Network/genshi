//! Nullifier derivation gadget.
//!
//! Constrains: `nullifier = Poseidon2(nullifier_preimage, secret, leaf_index)`
//!
//! **GUARDRAIL G2**: The nullifier is deterministic — the circuit enforces
//! that the same note always produces the same nullifier, preventing
//! double-spending by making nullifiers publicly checkable.



use crate::arithmetization::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};
use super::poseidon2_gadget::poseidon2_hash_3_gadget;

/// Nullifier derivation gadget.
///
/// Constrains `nullifier = Poseidon2_hash_3(nullifier_preimage, secret, leaf_index)`.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `nullifier_preimage` - Random preimage known to note owner (private)
/// * `secret` - Note secret (private)
/// * `leaf_index` - Position in the Merkle tree (private)
///
/// # Returns
/// Wire reference to the computed nullifier (will be made public by the circuit).
pub fn nullifier_gadget(
    builder: &mut UltraCircuitBuilder,
    nullifier_preimage: WireRef,
    secret: WireRef,
    leaf_index: WireRef,
) -> WireRef {
    poseidon2_hash_3_gadget(builder, nullifier_preimage, secret, leaf_index)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use crate::crypto::poseidon2;

    #[test]
    fn test_nullifier_gadget_matches_native() {
        let np = Fr::from(42u64);
        let secret = Fr::from(100u64);
        let leaf_idx = Fr::from(7u64);
        
        let expected = poseidon2::poseidon2_hash_3(np, secret, leaf_idx);
        
        let mut builder = UltraCircuitBuilder::new();
        let np_w = builder.add_variable(np);
        let s_w = builder.add_variable(secret);
        let li_w = builder.add_variable(leaf_idx);
        let result = nullifier_gadget(&mut builder, np_w, s_w, li_w);
        
        assert_eq!(builder.get_variable(result), expected,
            "Nullifier gadget must match native derivation (G2)");
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_nullifier_deterministic() {
        let np = Fr::from(42u64);
        let secret = Fr::from(100u64);
        let leaf_idx = Fr::from(7u64);
        
        let mut b1 = UltraCircuitBuilder::new();
        let np1 = b1.add_variable(np);
        let s1 = b1.add_variable(secret);
        let li1 = b1.add_variable(leaf_idx);
        let r1 = nullifier_gadget(&mut b1, np1, s1, li1);
        
        let mut b2 = UltraCircuitBuilder::new();
        let np2 = b2.add_variable(np);
        let s2 = b2.add_variable(secret);
        let li2 = b2.add_variable(leaf_idx);
        let r2 = nullifier_gadget(&mut b2, np2, s2, li2);
        
        assert_eq!(b1.get_variable(r1), b2.get_variable(r2),
            "Same inputs must produce same nullifier (G2)");
    }

    #[test]
    fn test_different_leaf_different_nullifier() {
        let np = Fr::from(42u64);
        let secret = Fr::from(100u64);
        
        let mut b1 = UltraCircuitBuilder::new();
        let np1 = b1.add_variable(np);
        let s1 = b1.add_variable(secret);
        let li1 = b1.add_variable(Fr::from(0u64));
        let r1 = nullifier_gadget(&mut b1, np1, s1, li1);
        
        let mut b2 = UltraCircuitBuilder::new();
        let np2 = b2.add_variable(np);
        let s2 = b2.add_variable(secret);
        let li2 = b2.add_variable(Fr::from(1u64));
        let r2 = nullifier_gadget(&mut b2, np2, s2, li2);
        
        assert_ne!(b1.get_variable(r1), b2.get_variable(r2),
            "Different leaf indices must produce different nullifiers");
    }
}
