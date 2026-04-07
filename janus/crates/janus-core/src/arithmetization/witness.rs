//! Witness generation helpers.
//!
//! Thin wrappers for assigning native values (u64s, field elements) to circuit
//! wires through [`UltraCircuitBuilder`]. Applications typically call these
//! from inside their own `Circuit::synthesize` implementations.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use alloc::vec::Vec;

use super::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};

/// Assign a u64 value as a field element in the circuit.
pub fn assign_u64(builder: &mut UltraCircuitBuilder, val: u64) -> WireRef {
    builder.add_variable(Fr::from(val))
}

/// Assign a field element in the circuit.
pub fn assign_field(builder: &mut UltraCircuitBuilder, val: Fr) -> WireRef {
    builder.add_variable(val)
}

/// Assign a vector of field elements and return wire references.
pub fn assign_field_vec(builder: &mut UltraCircuitBuilder, vals: &[Fr]) -> Vec<WireRef> {
    vals.iter().map(|v| builder.add_variable(*v)).collect()
}

/// Extract a u64 from a field element (assumes value fits in 64 bits).
pub fn fr_to_u64(val: Fr) -> u64 {
    let bigint = val.into_bigint();
    let limbs = bigint.as_ref();
    limbs[0]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_assign_u64() {
        let mut builder = UltraCircuitBuilder::new();
        let w = assign_u64(&mut builder, 42);
        assert_eq!(builder.get_variable(w), Fr::from(42u64));
    }

    #[test]
    fn test_assign_field_vec() {
        let mut builder = UltraCircuitBuilder::new();
        let vals = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let wires = assign_field_vec(&mut builder, &vals);
        assert_eq!(wires.len(), 3);
        assert_eq!(builder.get_variable(wires[2]), Fr::from(3u64));
    }

    #[test]
    fn test_fr_to_u64() {
        assert_eq!(fr_to_u64(Fr::from(12345u64)), 12345);
        assert_eq!(fr_to_u64(Fr::zero()), 0);
    }
}
