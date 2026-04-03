//! Plookup lookup table construction.
//!
//! Lookup tables define sets of valid tuples `(a, b, c)` that can be
//! referenced by lookup gates. The plookup argument proves (during
//! verification) that every lookup gate's wire values exist in the table.
//!
//! **GUARDRAIL G10**: Every looked-up value must exist in the table.
//! No extra entries that enable range bypass. The 8-bit range table
//! contains exactly `{0, 1, ..., 255}` and nothing else.
//!
//! # 64-bit Range Proof Strategy
//!
//! Instead of a massive 2^64 table, decompose value into 8 × 8-bit limbs:
//! `value = Σ limb_i · 2^(8i)` for i ∈ [0, 8)
//!
//! Each limb is looked up in the 8-bit range table (256 entries).
//! Total cost: ~50 constraints (8 lookups + 8 decomposition gates).

use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use alloc::vec::Vec;

/// A 3-column lookup table for the plookup argument.
///
/// Each entry is a tuple `(col_1, col_2, col_3)`.
/// Lookup gates assert that `(w1, w2, w3)` at a given gate row
/// exists as one of the entries in this table.
#[derive(Clone, Debug)]
pub struct LookupTable {
    /// Unique identifier for this table.
    pub id: usize,
    /// Table entries: column 1.
    pub col_1: Vec<Fr>,
    /// Table entries: column 2.
    pub col_2: Vec<Fr>,
    /// Table entries: column 3.
    pub col_3: Vec<Fr>,
}

impl LookupTable {
    /// Create a new empty lookup table with the given ID.
    pub fn new(id: usize) -> Self {
        Self {
            id,
            col_1: Vec::new(),
            col_2: Vec::new(),
            col_3: Vec::new(),
        }
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.col_1.len()
    }

    /// Is the table empty?
    pub fn is_empty(&self) -> bool {
        self.col_1.is_empty()
    }

    /// Add an entry to the table.
    pub fn add_entry(&mut self, a: Fr, b: Fr, c: Fr) {
        self.col_1.push(a);
        self.col_2.push(b);
        self.col_3.push(c);
    }

    /// Check if the table contains the given tuple.
    ///
    /// Used by `UltraCircuitBuilder::check_circuit_correctness()` to validate
    /// lookup gates against the table during witness checking.
    pub fn contains(&self, a: Fr, b: Fr, c: Fr) -> bool {
        for i in 0..self.col_1.len() {
            if self.col_1[i] == a && self.col_2[i] == b && self.col_3[i] == c {
                return true;
            }
        }
        false
    }

    // ========================================================================
    // Pre-built Tables
    // ========================================================================

    /// Create the 8-bit range table: `{(i, 0, 0) for i in 0..256}`.
    ///
    /// Used for 64-bit range proofs by decomposing values into 8-bit limbs.
    /// Each limb is looked up against this table to prove it's in [0, 255].
    ///
    /// **GUARDRAIL G10**: This table contains exactly 256 entries.
    /// No extra entries that could bypass the range check.
    pub fn range_8bit() -> Self {
        let mut table = Self::new(0);
        for i in 0u64..256 {
            table.add_entry(Fr::from(i), Fr::zero(), Fr::zero());
        }
        assert_eq!(table.len(), 256, "G10: range table must have exactly 256 entries");
        table
    }

    /// Create the XOR-8bit table: `{(a, b, a XOR b) for a,b in 0..16}`.
    ///
    /// Used for bitwise operations. 4-bit XOR table (256 entries: 16×16).
    /// Future optimization for custom gates.
    #[allow(dead_code)]
    pub fn xor_4bit() -> Self {
        let mut table = Self::new(1);
        for a in 0u64..16 {
            for b in 0u64..16 {
                table.add_entry(Fr::from(a), Fr::from(b), Fr::from(a ^ b));
            }
        }
        table
    }
}

// ============================================================================
// Range Proof Helper
// ============================================================================

use super::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};

/// Constrain a value to be in [0, 2^64) using 8-bit limb decomposition + lookup.
///
/// Decomposes `value` into 8 bytes: `value = b0 + b1·256 + b2·256² + ... + b7·256⁷`
/// Each byte `b_i` is looked up in the 8-bit range table.
/// The reconstruction is constrained: `Σ b_i · 2^(8i) = value`.
///
/// # Arguments
/// * `builder` - The circuit builder
/// * `value` - Wire reference to the value to range-check
/// * `range_table_id` - The lookup table ID for the 8-bit range table
pub fn range_proof_64bit(
    builder: &mut UltraCircuitBuilder,
    value: WireRef,
    range_table_id: usize,
) {
    let val = builder.get_variable(value);
    
    // Extract the value as a u64 for limb decomposition
    // We need to convert Fr to u64 — this only works for values < 2^64
    let val_bytes = {
        let bigint = val.into_bigint();
        let limbs = bigint.as_ref(); // [u64; 4] for BN254
        // For a valid 64-bit value, limbs[1..] should all be 0
        limbs[0]
    };
    
    // Decompose into 8 × 8-bit limbs
    let mut limb_wires = Vec::with_capacity(8);
    let mut reconstructed = Fr::zero();
    let mut power = Fr::one();
    let base = Fr::from(256u64);
    
    for i in 0..8u32 {
        let limb_val = ((val_bytes >> (8 * i)) & 0xFF) as u64;
        let limb_wire = builder.add_variable(Fr::from(limb_val));
        limb_wires.push(limb_wire);
        
        // Lookup: each limb must be in [0, 255]
        let zero = builder.zero_var();
        builder.create_lookup_gate(limb_wire, zero, zero, range_table_id);
        
        reconstructed += Fr::from(limb_val) * power;
        power *= base;
    }
    
    // Constrain: Σ limb_i · 2^(8i) = value
    // We do this by building up the sum incrementally
    let b256 = Fr::from(256u64);
    
    // partial_sum = l7·256 + l6
    // partial_sum = partial_sum·256 + l5
    // ... etc (Horner's method, big-endian)
    let mut accum = limb_wires[7]; // start with most significant limb
    let b256_var = builder.add_constant(b256);
    for i in (0..7).rev() {
        // accum = accum * 256 + limb[i]
        let scaled = builder.mul(accum, b256_var);
        accum = builder.add(scaled, limb_wires[i]);
    }
    
    // accum should equal value
    builder.assert_equal(accum, value);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_8bit_table() {
        let table = LookupTable::range_8bit();
        assert_eq!(table.len(), 256);
        
        // Valid entries
        assert!(table.contains(Fr::from(0u64), Fr::zero(), Fr::zero()));
        assert!(table.contains(Fr::from(127u64), Fr::zero(), Fr::zero()));
        assert!(table.contains(Fr::from(255u64), Fr::zero(), Fr::zero()));
        
        // Invalid entries
        assert!(!table.contains(Fr::from(256u64), Fr::zero(), Fr::zero()));
        assert!(!table.contains(Fr::from(1000u64), Fr::zero(), Fr::zero()));
    }

    #[test]
    fn test_xor_4bit_table() {
        let table = LookupTable::xor_4bit();
        assert_eq!(table.len(), 256); // 16×16
        
        // 5 XOR 3 = 6
        assert!(table.contains(Fr::from(5u64), Fr::from(3u64), Fr::from(6u64)));
        // 15 XOR 0 = 15
        assert!(table.contains(Fr::from(15u64), Fr::from(0u64), Fr::from(15u64)));
        // Invalid
        assert!(!table.contains(Fr::from(16u64), Fr::from(0u64), Fr::from(16u64)));
    }

    #[test]
    fn test_lookup_gate_valid() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = builder.add_lookup_table(LookupTable::range_8bit());
        
        let val = builder.add_variable(Fr::from(42u64));
        let zero = builder.zero_var();
        builder.create_lookup_gate(val, zero, zero, table_id);
        
        assert!(builder.check_circuit_correctness(), "42 is in [0,255]");
    }

    #[test]
    fn test_lookup_gate_invalid() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = builder.add_lookup_table(LookupTable::range_8bit());
        
        let val = builder.add_variable(Fr::from(256u64));
        let zero = builder.zero_var();
        builder.create_lookup_gate(val, zero, zero, table_id);
        
        assert!(!builder.check_circuit_correctness(), "256 is NOT in [0,255]");
    }

    #[test]
    fn test_lookup_gate_boundary() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = builder.add_lookup_table(LookupTable::range_8bit());
        
        // Test boundary: 255 (max valid)
        let val = builder.add_variable(Fr::from(255u64));
        let zero = builder.zero_var();
        builder.create_lookup_gate(val, zero, zero, table_id);
        assert!(builder.check_circuit_correctness(), "255 is last valid entry");
    }

    #[test]
    fn test_range_proof_64bit_valid() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = builder.add_lookup_table(LookupTable::range_8bit());
        
        let val = builder.add_variable(Fr::from(1000u64));
        range_proof_64bit(&mut builder, val, table_id);
        
        assert!(builder.check_circuit_correctness(), "1000 is in [0, 2^64)");
    }

    #[test]
    fn test_range_proof_64bit_max() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = builder.add_lookup_table(LookupTable::range_8bit());
        
        let val = builder.add_variable(Fr::from(u64::MAX));
        range_proof_64bit(&mut builder, val, table_id);
        
        assert!(builder.check_circuit_correctness(), "u64::MAX is in [0, 2^64)");
    }

    #[test]
    fn test_range_proof_64bit_zero() {
        let mut builder = UltraCircuitBuilder::new();
        let table_id = builder.add_lookup_table(LookupTable::range_8bit());
        
        let val = builder.add_variable(Fr::zero());
        range_proof_64bit(&mut builder, val, table_id);
        
        assert!(builder.check_circuit_correctness(), "0 is in [0, 2^64)");
    }

    #[test]
    fn test_custom_table() {
        let mut table = LookupTable::new(99);
        table.add_entry(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        table.add_entry(Fr::from(4u64), Fr::from(5u64), Fr::from(6u64));
        
        assert_eq!(table.len(), 2);
        assert!(table.contains(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)));
        assert!(!table.contains(Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)));
    }
}
