//! UltraHonk circuit builder.
//!
//! The `UltraCircuitBuilder` implements PLONKish arithmetization with:
//! - 4 wire columns (w1, w2, w3, w4)
//! - Selector columns for gate activation (q_m, q_1, q_2, q_3, q_4, q_c, q_arith, q_lookup)
//! - Copy constraints via permutation argument
//! - Plookup lookup gates for range proofs
//!
//! # Gate Equation (Arithmetic)
//!
//! When `q_arith = 1`:
//! ```text
//! q_m·(w1·w2) + q_1·w1 + q_2·w2 + q_3·w3 + q_4·w4 + q_c = 0
//! ```
//!
//! # Usage
//!
//! ```
//! use ark_bn254::Fr;
//! use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
//!
//! let mut builder = UltraCircuitBuilder::new();
//! let a = builder.add_variable(Fr::from(3u64));
//! let b = builder.add_variable(Fr::from(4u64));
//! let c = builder.add_variable(Fr::from(7u64));
//! builder.create_add_gate(a, b, c); // constrain: a + b - c = 0
//! assert!(builder.check_circuit_correctness());
//! ```

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use alloc::vec;
use alloc::vec::Vec;

use super::lookup_tables::LookupTable;

// ============================================================================
// Wire Reference
// ============================================================================

/// A reference to a variable (witness value) in the circuit.
///
/// Internally this is an index into the variable storage. Multiple gates
/// can reference the same variable, and copy constraints enforce equality
/// between variables at different wire positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WireRef(pub(crate) u32);

impl WireRef {
    /// The zero variable (always exists at index 0).
    pub const ZERO: WireRef = WireRef(0);
}

/// Identifies a specific cell in the execution trace: (gate_index, wire_column).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellRef {
    pub gate: u32,
    pub wire: u8, // 0-3 for w1-w4
}

// ============================================================================
// Gate Record
// ============================================================================

/// A single gate (row in the execution trace).
#[derive(Clone, Debug)]
pub struct Gate {
    /// Wire variable references (w1, w2, w3, w4)
    pub wires: [WireRef; 4],
    /// Selector values for this gate
    pub q_m: Fr,     // multiplication selector
    pub q_1: Fr,     // w1 linear
    pub q_2: Fr,     // w2 linear
    pub q_3: Fr,     // w3 linear
    pub q_4: Fr,     // w4 linear
    pub q_c: Fr,     // constant
    pub q_arith: Fr, // arithmetic gate flag
    pub q_lookup: Fr, // lookup gate flag
}

impl Gate {
    /// Create a zero gate (no constraints).
    #[allow(dead_code)]
    fn zero() -> Self {
        Self {
            wires: [WireRef::ZERO; 4],
            q_m: Fr::zero(),
            q_1: Fr::zero(),
            q_2: Fr::zero(),
            q_3: Fr::zero(),
            q_4: Fr::zero(),
            q_c: Fr::zero(),
            q_arith: Fr::zero(),
            q_lookup: Fr::zero(),
        }
    }
}

// ============================================================================
// UltraCircuit Builder
// ============================================================================

/// UltraHonk circuit builder for PLONKish arithmetization.
///
/// The builder collects:
/// - Variables (witness values assigned by the prover)
/// - Gates (rows in the execution trace with selector values)
/// - Copy constraints (variable equality across positions)
/// - Lookup table references (for plookup range proofs)
/// - Public input designations
pub struct UltraCircuitBuilder {
    /// Stored variable values. Index 0 is always the zero variable.
    variables: Vec<Fr>,

    /// All gates (rows in the execution trace).
    gates: Vec<Gate>,

    /// Copy constraints: pairs of variable indices that must be equal.
    copy_constraints: Vec<(WireRef, WireRef)>,

    /// Lookup tables available to the circuit.
    lookup_tables: Vec<LookupTable>,

    /// Lookup entries: (gate_index, table_id) for gates that use lookups.
    lookup_entries: Vec<(usize, usize)>,

    /// Variable indices that are public inputs.
    public_input_indices: Vec<WireRef>,
}

impl UltraCircuitBuilder {
    /// Create a new empty circuit builder.
    ///
    /// The zero variable (index 0, value 0) is automatically allocated.
    pub fn new() -> Self {
        Self {
            variables: vec![Fr::zero()], // Index 0 = zero variable
            gates: Vec::new(),
            copy_constraints: Vec::new(),
            lookup_tables: Vec::new(),
            lookup_entries: Vec::new(),
            public_input_indices: Vec::new(),
        }
    }

    // ========================================================================
    // Variable Management
    // ========================================================================

    /// Allocate a new witness variable with the given value.
    ///
    /// Returns a `WireRef` that can be used in gate definitions.
    /// The value is the "assignment" — what the prover knows.
    pub fn add_variable(&mut self, value: Fr) -> WireRef {
        let idx = self.variables.len() as u32;
        self.variables.push(value);
        WireRef(idx)
    }

    /// Get the value of a variable.
    pub fn get_variable(&self, wire: WireRef) -> Fr {
        self.variables[wire.0 as usize]
    }

    /// Set/update the value of an existing variable.
    pub fn set_variable(&mut self, wire: WireRef, value: Fr) {
        self.variables[wire.0 as usize] = value;
    }

    /// Add a constant value as a variable.
    pub fn add_constant(&mut self, value: Fr) -> WireRef {
        self.add_variable(value)
    }

    /// Get the zero variable reference.
    pub fn zero_var(&self) -> WireRef {
        WireRef::ZERO
    }

    /// Number of variables allocated.
    pub fn num_variables(&self) -> usize {
        self.variables.len()
    }

    // ========================================================================
    // Gate Creation
    // ========================================================================

    /// Add a raw gate with explicit selector values.
    ///
    /// The gate constrains:
    /// `q_arith · (q_m·(w1·w2) + q_1·w1 + q_2·w2 + q_3·w3 + q_4·w4 + q_c) = 0`
    pub fn create_gate(&mut self, gate: Gate) {
        self.gates.push(gate);
    }

    /// Number of gates in the circuit.
    pub fn num_gates(&self) -> usize {
        self.gates.len()
    }

    /// Create an addition gate: `a + b - c = 0` (i.e., `c = a + b`).
    ///
    /// Constrains: `1·w1 + 1·w2 + (-1)·w3 + 0·w4 + 0 = 0`
    pub fn create_add_gate(&mut self, a: WireRef, b: WireRef, c: WireRef) {
        self.gates.push(Gate {
            wires: [a, b, c, WireRef::ZERO],
            q_m: Fr::zero(),
            q_1: Fr::one(),
            q_2: Fr::one(),
            q_3: -Fr::one(),
            q_4: Fr::zero(),
            q_c: Fr::zero(),
            q_arith: Fr::one(),
            q_lookup: Fr::zero(),
        });
    }

    /// Create a multiplication gate: `a * b - c = 0` (i.e., `c = a * b`).
    ///
    /// Constrains: `1·(w1·w2) + 0·w1 + 0·w2 + (-1)·w3 + 0·w4 + 0 = 0`
    pub fn create_mul_gate(&mut self, a: WireRef, b: WireRef, c: WireRef) {
        self.gates.push(Gate {
            wires: [a, b, c, WireRef::ZERO],
            q_m: Fr::one(),
            q_1: Fr::zero(),
            q_2: Fr::zero(),
            q_3: -Fr::one(),
            q_4: Fr::zero(),
            q_c: Fr::zero(),
            q_arith: Fr::one(),
            q_lookup: Fr::zero(),
        });
    }

    /// Create a boolean gate: `a * (1 - a) = 0` (i.e., `a ∈ {0, 1}`).
    ///
    /// Expands to: `a·a - a = 0`, or equivalently `q_m·(w1·w2) + q_1·w1 = 0`
    /// with w1 = w2 = a, q_m = 1, q_1 = -1.
    pub fn create_bool_gate(&mut self, a: WireRef) {
        self.gates.push(Gate {
            wires: [a, a, WireRef::ZERO, WireRef::ZERO],
            q_m: Fr::one(),
            q_1: -Fr::one(),
            q_2: Fr::zero(),
            q_3: Fr::zero(),
            q_4: Fr::zero(),
            q_c: Fr::zero(),
            q_arith: Fr::one(),
            q_lookup: Fr::zero(),
        });
    }

    /// Create a constant gate: `a - constant = 0` (i.e., `a = constant`).
    pub fn create_constant_gate(&mut self, a: WireRef, constant: Fr) {
        self.gates.push(Gate {
            wires: [a, WireRef::ZERO, WireRef::ZERO, WireRef::ZERO],
            q_m: Fr::zero(),
            q_1: Fr::one(),
            q_2: Fr::zero(),
            q_3: Fr::zero(),
            q_4: Fr::zero(),
            q_c: -constant,
            q_arith: Fr::one(),
            q_lookup: Fr::zero(),
        });
    }

    /// Create a linear combination gate: `c1·a + c2·b + c3·c + c4·d + constant = 0`.
    pub fn create_linear_combination(
        &mut self,
        a: WireRef, c1: Fr,
        b: WireRef, c2: Fr,
        c: WireRef, c3: Fr,
        d: WireRef, c4: Fr,
        constant: Fr,
    ) {
        self.gates.push(Gate {
            wires: [a, b, c, d],
            q_m: Fr::zero(),
            q_1: c1,
            q_2: c2,
            q_3: c3,
            q_4: c4,
            q_c: constant,
            q_arith: Fr::one(),
            q_lookup: Fr::zero(),
        });
    }

    /// Helper: allocate `a + b` and constrain it.
    pub fn add(&mut self, a: WireRef, b: WireRef) -> WireRef {
        let sum_val = self.get_variable(a) + self.get_variable(b);
        let sum = self.add_variable(sum_val);
        self.create_add_gate(a, b, sum);
        sum
    }

    /// Helper: allocate `a * b` and constrain it.
    pub fn mul(&mut self, a: WireRef, b: WireRef) -> WireRef {
        let prod_val = self.get_variable(a) * self.get_variable(b);
        let prod = self.add_variable(prod_val);
        self.create_mul_gate(a, b, prod);
        prod
    }

    /// Helper: allocate `a - b` and constrain it.
    pub fn sub(&mut self, a: WireRef, b: WireRef) -> WireRef {
        let diff_val = self.get_variable(a) - self.get_variable(b);
        let diff = self.add_variable(diff_val);
        // a - b - diff = 0  =>  1·a + (-1)·b + (-1)·diff = 0
        self.gates.push(Gate {
            wires: [a, b, diff, WireRef::ZERO],
            q_m: Fr::zero(),
            q_1: Fr::one(),
            q_2: -Fr::one(),
            q_3: -Fr::one(),
            q_4: Fr::zero(),
            q_c: Fr::zero(),
            q_arith: Fr::one(),
            q_lookup: Fr::zero(),
        });
        diff
    }

    // ========================================================================
    // Copy Constraints
    // ========================================================================

    /// Assert that two variables are equal (copy constraint).
    ///
    /// This adds a permutation constraint that will be enforced by
    /// the permutation argument in the UltraHonk prover.
    pub fn assert_equal(&mut self, a: WireRef, b: WireRef) {
        self.copy_constraints.push((a, b));
    }

    /// Get all copy constraints.
    pub fn get_copy_constraints(&self) -> &[(WireRef, WireRef)] {
        &self.copy_constraints
    }

    // ========================================================================
    // Public Inputs
    // ========================================================================

    /// Mark a variable as a public input.
    ///
    /// Public inputs are known to both the prover and verifier. The circuit
    /// author chooses which wires are exposed; genshi is agnostic to their
    /// semantics.
    pub fn set_public(&mut self, wire: WireRef) {
        self.public_input_indices.push(wire);
    }

    /// Get public input wire references.
    pub fn get_public_inputs(&self) -> &[WireRef] {
        &self.public_input_indices
    }

    /// Get public input values.
    pub fn get_public_input_values(&self) -> Vec<Fr> {
        self.public_input_indices
            .iter()
            .map(|w| self.get_variable(*w))
            .collect()
    }

    // ========================================================================
    // Lookup Tables
    // ========================================================================

    /// Register a lookup table and return its index.
    pub fn add_lookup_table(&mut self, table: LookupTable) -> usize {
        let idx = self.lookup_tables.len();
        self.lookup_tables.push(table);
        idx
    }

    /// Create a lookup gate: assert that `(w1, w2, w3)` exists in the given table.
    ///
    /// The plookup argument will verify that the tuple is contained in the table
    /// during proof verification.
    pub fn create_lookup_gate(
        &mut self,
        a: WireRef,
        b: WireRef,
        c: WireRef,
        table_id: usize,
    ) {
        let gate_idx = self.gates.len();
        self.gates.push(Gate {
            wires: [a, b, c, WireRef::ZERO],
            q_m: Fr::zero(),
            q_1: Fr::zero(),
            q_2: Fr::zero(),
            q_3: Fr::zero(),
            q_4: Fr::zero(),
            q_c: Fr::zero(),
            q_arith: Fr::zero(),
            q_lookup: Fr::one(),
        });
        self.lookup_entries.push((gate_idx, table_id));
    }

    /// Get all lookup tables.
    pub fn get_lookup_tables(&self) -> &[LookupTable] {
        &self.lookup_tables
    }

    /// Get all lookup entries (gate_index, table_id).
    pub fn get_lookup_entries(&self) -> &[(usize, usize)] {
        &self.lookup_entries
    }

    // ========================================================================
    // Circuit Validation
    // ========================================================================

    /// Check if the current witness satisfies all circuit constraints.
    ///
    /// This performs a gate-by-gate evaluation using the assigned variable values.
    /// Returns `true` if all gates are satisfied, `false` otherwise.
    ///
    /// This is a critical debugging tool: it catches witness generation bugs
    /// before the expensive proving step.
    pub fn check_circuit_correctness(&self) -> bool {
        // Check arithmetic gates
        for (i, gate) in self.gates.iter().enumerate() {
            if gate.q_arith != Fr::zero() {
                let w1 = self.get_variable(gate.wires[0]);
                let w2 = self.get_variable(gate.wires[1]);
                let w3 = self.get_variable(gate.wires[2]);
                let w4 = self.get_variable(gate.wires[3]);

                let result = gate.q_m * (w1 * w2)
                    + gate.q_1 * w1
                    + gate.q_2 * w2
                    + gate.q_3 * w3
                    + gate.q_4 * w4
                    + gate.q_c;

                if result != Fr::zero() {
                    #[cfg(feature = "std")]
                    eprintln!(
                        "Gate {} failed: q_m={:?}·(w1·w2) + q_1={:?}·w1={:?} + q_2={:?}·w2={:?} + q_3={:?}·w3={:?} + q_4={:?}·w4={:?} + q_c={:?} = {:?} ≠ 0",
                        i, gate.q_m, gate.q_1, w1, gate.q_2, w2, gate.q_3, w3, gate.q_4, w4, gate.q_c, result
                    );
                    return false;
                }
            }
        }

        // Check copy constraints
        for (a, b) in &self.copy_constraints {
            let va = self.get_variable(*a);
            let vb = self.get_variable(*b);
            if va != vb {
                #[cfg(feature = "std")]
                eprintln!(
                    "Copy constraint failed: var {} = {:?}, var {} = {:?}",
                    a.0, va, b.0, vb
                );
                return false;
            }
        }

        // Check lookup gates
        for &(gate_idx, table_id) in &self.lookup_entries {
            let gate = &self.gates[gate_idx];
            let w1 = self.get_variable(gate.wires[0]);
            let w2 = self.get_variable(gate.wires[1]);
            let w3 = self.get_variable(gate.wires[2]);

            if table_id >= self.lookup_tables.len() {
                #[cfg(feature = "std")]
                eprintln!("Lookup gate {}: table_id {} out of range", gate_idx, table_id);
                return false;
            }

            let table = &self.lookup_tables[table_id];
            if !table.contains(w1, w2, w3) {
                #[cfg(feature = "std")]
                eprintln!(
                    "Lookup gate {}: ({:?}, {:?}, {:?}) not in table {}",
                    gate_idx, w1, w2, w3, table_id
                );
                return false;
            }
        }

        true
    }

    // ========================================================================
    // Accessors for the proving system (Phase 4)
    // ========================================================================

    /// Get all gates.
    pub fn get_gates(&self) -> &[Gate] {
        &self.gates
    }

    /// Get all variable values.
    pub fn get_variables(&self) -> &[Fr] {
        &self.variables
    }
}

impl Default for UltraCircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_variable() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(42u64));
        assert_eq!(builder.get_variable(a), Fr::from(42u64));
    }

    #[test]
    fn test_zero_variable_exists() {
        let builder = UltraCircuitBuilder::new();
        assert_eq!(builder.get_variable(WireRef::ZERO), Fr::zero());
    }

    #[test]
    fn test_add_gate_satisfied() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(4u64));
        let c = builder.add_variable(Fr::from(7u64));
        builder.create_add_gate(a, b, c);
        assert!(builder.check_circuit_correctness(), "3 + 4 = 7 should satisfy");
    }

    #[test]
    fn test_add_gate_unsatisfied() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(4u64));
        let c = builder.add_variable(Fr::from(8u64)); // wrong: should be 7
        builder.create_add_gate(a, b, c);
        assert!(!builder.check_circuit_correctness(), "3 + 4 ≠ 8 should fail");
    }

    #[test]
    fn test_mul_gate_satisfied() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(4u64));
        let c = builder.add_variable(Fr::from(12u64));
        builder.create_mul_gate(a, b, c);
        assert!(builder.check_circuit_correctness(), "3 * 4 = 12 should satisfy");
    }

    #[test]
    fn test_mul_gate_unsatisfied() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(4u64));
        let c = builder.add_variable(Fr::from(13u64)); // wrong
        builder.create_mul_gate(a, b, c);
        assert!(!builder.check_circuit_correctness(), "3 * 4 ≠ 13 should fail");
    }

    #[test]
    fn test_bool_gate_zero() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::zero());
        builder.create_bool_gate(a);
        assert!(builder.check_circuit_correctness(), "0 is boolean");
    }

    #[test]
    fn test_bool_gate_one() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::one());
        builder.create_bool_gate(a);
        assert!(builder.check_circuit_correctness(), "1 is boolean");
    }

    #[test]
    fn test_bool_gate_non_boolean() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(2u64));
        builder.create_bool_gate(a);
        assert!(!builder.check_circuit_correctness(), "2 is not boolean");
    }

    #[test]
    fn test_constant_gate() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(42u64));
        builder.create_constant_gate(a, Fr::from(42u64));
        assert!(builder.check_circuit_correctness(), "a = 42 should satisfy");
    }

    #[test]
    fn test_constant_gate_wrong() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(41u64));
        builder.create_constant_gate(a, Fr::from(42u64));
        assert!(!builder.check_circuit_correctness(), "41 ≠ 42 should fail");
    }

    #[test]
    fn test_copy_constraint_satisfied() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(7u64));
        let b = builder.add_variable(Fr::from(7u64));
        builder.assert_equal(a, b);
        assert!(builder.check_circuit_correctness(), "Same values should pass");
    }

    #[test]
    fn test_copy_constraint_unsatisfied() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(7u64));
        let b = builder.add_variable(Fr::from(8u64));
        builder.assert_equal(a, b);
        assert!(!builder.check_circuit_correctness(), "7 ≠ 8 should fail copy constraint");
    }

    #[test]
    fn test_public_inputs() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(10u64));
        let b = builder.add_variable(Fr::from(20u64));
        builder.set_public(a);
        builder.set_public(b);
        
        let public_vals = builder.get_public_input_values();
        assert_eq!(public_vals.len(), 2);
        assert_eq!(public_vals[0], Fr::from(10u64));
        assert_eq!(public_vals[1], Fr::from(20u64));
    }

    #[test]
    fn test_add_helper() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(10u64));
        let b = builder.add_variable(Fr::from(20u64));
        let c = builder.add(a, b);
        assert_eq!(builder.get_variable(c), Fr::from(30u64));
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_mul_helper() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(5u64));
        let b = builder.add_variable(Fr::from(6u64));
        let c = builder.mul(a, b);
        assert_eq!(builder.get_variable(c), Fr::from(30u64));
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_sub_helper() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(20u64));
        let b = builder.add_variable(Fr::from(8u64));
        let c = builder.sub(a, b);
        assert_eq!(builder.get_variable(c), Fr::from(12u64));
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_complex_circuit() {
        // Test: c = a*b + d, where a=3, b=4, d=5, c=17
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(4u64));
        let d = builder.add_variable(Fr::from(5u64));
        
        let ab = builder.mul(a, b);     // ab = 12
        let c = builder.add(ab, d);     // c = 17
        
        assert_eq!(builder.get_variable(c), Fr::from(17u64));
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_linear_combination() {
        // 2a + 3b - c + 1 = 0  =>  c = 2*3 + 3*4 + 1 = 19
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(4u64));
        let c = builder.add_variable(Fr::from(19u64));
        
        builder.create_linear_combination(
            a, Fr::from(2u64),
            b, Fr::from(3u64),
            c, -Fr::one(),
            WireRef::ZERO, Fr::zero(),
            Fr::one(),
        );
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_gate_count() {
        let mut builder = UltraCircuitBuilder::new();
        assert_eq!(builder.num_gates(), 0);
        
        let a = builder.add_variable(Fr::from(1u64));
        let b = builder.add_variable(Fr::from(2u64));
        let _ = builder.add(a, b);
        assert_eq!(builder.num_gates(), 1);
        
        let _ = builder.mul(a, b);
        assert_eq!(builder.num_gates(), 2);
    }

    #[test]
    fn test_chained_operations() {
        // result = ((a + b) * c) - d
        // a=2, b=3, c=4, d=5 => (2+3)*4 - 5 = 15
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(2u64));
        let b = builder.add_variable(Fr::from(3u64));
        let c = builder.add_variable(Fr::from(4u64));
        let d = builder.add_variable(Fr::from(5u64));
        
        let ab = builder.add(a, b);     // 5
        let abc = builder.mul(ab, c);    // 20
        let result = builder.sub(abc, d); // 15
        
        assert_eq!(builder.get_variable(result), Fr::from(15u64));
        assert!(builder.check_circuit_correctness());
    }
}
