//! Range proof gadget.
//!
//! Wraps the 64-bit range proof from `arithmetization::lookup_tables`
//! into the gadget API for use in transfer and withdraw circuits.
//!
//! # Strategy
//!
//! Decompose value into 8 × 8-bit limbs, each looked up in a 256-entry table.
//! Reconstruct via Horner's method and constrain equality.
//! Total cost: ~50 constraints (8 lookups + 8 reconstruction gates).

use crate::arithmetization::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};
use crate::arithmetization::lookup_tables::{self, LookupTable};

/// Constrain a value to be in [0, 2^64).
///
/// If no range table has been registered yet, this function will
/// automatically register the 8-bit range table.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `value` - Wire reference to the value to range-check
/// * `range_table_id` - ID of the pre-registered 8-bit range table
pub fn range_check_64bit(
    builder: &mut UltraCircuitBuilder,
    value: WireRef,
    range_table_id: usize,
) {
    lookup_tables::range_proof_64bit(builder, value, range_table_id);
}

/// Register the 8-bit range table and return its ID.
///
/// Call this once per circuit before any range checks.
pub fn register_range_table(builder: &mut UltraCircuitBuilder) -> usize {
    builder.add_lookup_table(LookupTable::range_8bit())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::Zero;

    #[test]
    fn test_range_check_valid() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = register_range_table(&mut builder);
        let val = builder.add_variable(Fr::from(42u64));
        range_check_64bit(&mut builder, val, table_id);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_range_check_zero() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = register_range_table(&mut builder);
        let val = builder.add_variable(Fr::zero());
        range_check_64bit(&mut builder, val, table_id);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_range_check_max_u64() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = register_range_table(&mut builder);
        let val = builder.add_variable(Fr::from(u64::MAX));
        range_check_64bit(&mut builder, val, table_id);
        assert!(builder.check_circuit_correctness());
    }
}
