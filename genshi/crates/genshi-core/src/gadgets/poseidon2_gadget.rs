//! Poseidon2 in-circuit gadget.
//!
//! Mirrors the native Poseidon2 permutation from `crypto::poseidon2`
//! using UltraCircuitBuilder gates. Every round constant and linear
//! layer operation is constrained, producing the same output as the
//! native computation.
//!
//! **Invariant J4**: Uses the SAME `generate_round_constants` and parameters
//! as the native implementation — guaranteeing identical outputs for identical
//! inputs across native, WASM, and Solana BPF targets.
//!
//! # Design
//!
//! The S-box `x^5` is implemented as:
//! ```text
//! x2 = x * x        (1 mul gate)
//! x4 = x2 * x2      (1 mul gate)
//! x5 = x4 * x       (1 mul gate)
//! ```
//! = 3 multiplication gates per S-box application.
//!
//! Cost per state width:
//! - Full round:  t × 3 mul gates (S-box) + ~t add gates (linear layer)
//! - Partial round: 3 mul gates (S-box on state[0] only) + ~t add gates
//! - Total for t=4: 8 × (4×3 + ~8) + 56 × (3 + ~8) ≈ ~712 gates per hash

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::arithmetization::ultra_circuit_builder::{UltraCircuitBuilder, WireRef};
use crate::crypto::poseidon2::{
    generate_round_constants, partial_rounds, RF, RF_HALF, RF_HALF_END,
};

// ============================================================================
// S-box Gadget: x → x^5
// ============================================================================

/// Constrain `output = input^5` using 3 multiplication gates.
///
/// Returns the wire reference for x^5.
fn sbox_gadget(builder: &mut UltraCircuitBuilder, x: WireRef) -> WireRef {
    let x2 = builder.mul(x, x);      // x^2
    let x4 = builder.mul(x2, x2);    // x^4
    builder.mul(x4, x)               // x^5
}

// ============================================================================
// Add Round Constant Gadget
// ============================================================================

/// Constrain `output = input + constant`.
fn add_constant_gadget(
    builder: &mut UltraCircuitBuilder,
    x: WireRef,
    c: Fr,
) -> WireRef {
    if c == Fr::zero() {
        return x; // no-op optimization
    }
    let c_var = builder.add_constant(c);
    builder.add(x, c_var)
}

// ============================================================================
// External Linear Layer Gadgets (Full Rounds)
// ============================================================================

/// External linear layer for t=3 in-circuit.
/// `si = si + sum` for all i.
fn external_linear_layer_t3_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 3],
) {
    let sum = builder.add(state[0], state[1]);
    let sum = builder.add(sum, state[2]);
    state[0] = builder.add(state[0], sum);
    state[1] = builder.add(state[1], sum);
    state[2] = builder.add(state[2], sum);
}

/// External linear layer for t=4 in-circuit (M4 construction).
/// `si = 2*si + sum` for all i.
fn external_linear_layer_t4_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 4],
) {
    let t01 = builder.add(state[0], state[1]);
    let t23 = builder.add(state[2], state[3]);
    let t0123 = builder.add(t01, t23);
    
    // si_new = 2*si + sum = si + si + sum
    state[0] = {
        let doubled = builder.add(state[0], state[0]);
        builder.add(doubled, t0123)
    };
    state[1] = {
        let doubled = builder.add(state[1], state[1]);
        builder.add(doubled, t0123)
    };
    state[2] = {
        let doubled = builder.add(state[2], state[2]);
        builder.add(doubled, t0123)
    };
    state[3] = {
        let doubled = builder.add(state[3], state[3]);
        builder.add(doubled, t0123)
    };
}

/// External linear layer for t=5 in-circuit.
/// `si = si + sum` for all i.
fn external_linear_layer_t5_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 5],
) {
    let s01 = builder.add(state[0], state[1]);
    let s23 = builder.add(state[2], state[3]);
    let s0123 = builder.add(s01, s23);
    let sum = builder.add(s0123, state[4]);
    
    state[0] = builder.add(state[0], sum);
    state[1] = builder.add(state[1], sum);
    state[2] = builder.add(state[2], sum);
    state[3] = builder.add(state[3], sum);
    state[4] = builder.add(state[4], sum);
}

// ============================================================================
// Internal Linear Layer Gadgets (Partial Rounds)
// ============================================================================

/// Internal linear layer for t=3 in-circuit.
/// diag = [1, 1, 2]: state[i] = state[i] * (diag[i]-1) + sum
fn internal_linear_layer_t3_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 3],
) {
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let sum = builder.add(s0, s1);
    let sum = builder.add(sum, s2);
    
    state[0] = sum;                         // 0*s0 + sum
    state[1] = sum;                         // 0*s1 + sum
    state[2] = builder.add(s2, sum);        // 1*s2 + sum
}

/// Internal linear layer for t=4 in-circuit.
/// diag = [1, 1, 2, 3]: state[i] = state[i] * (diag[i]-1) + sum
fn internal_linear_layer_t4_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 4],
) {
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let s3 = state[3];
    let sum01 = builder.add(s0, s1);
    let sum23 = builder.add(s2, s3);
    let sum = builder.add(sum01, sum23);
    
    state[0] = sum;                         // 0*s0 + sum
    state[1] = sum;                         // 0*s1 + sum
    state[2] = builder.add(s2, sum);        // 1*s2 + sum
    // 2*s3 + sum
    let s3_doubled = builder.add(s3, s3);
    state[3] = builder.add(s3_doubled, sum);
}

/// Internal linear layer for t=5 in-circuit.
/// diag = [1, 1, 2, 3, 4]: state[i] = state[i] * (diag[i]-1) + sum
fn internal_linear_layer_t5_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 5],
) {
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let s3 = state[3];
    let s4 = state[4];
    let sum01 = builder.add(s0, s1);
    let sum23 = builder.add(s2, s3);
    let sum0123 = builder.add(sum01, sum23);
    let sum = builder.add(sum0123, s4);
    
    state[0] = sum;                            // 0*s0 + sum
    state[1] = sum;                            // 0*s1 + sum
    state[2] = builder.add(s2, sum);           // 1*s2 + sum
    let s3_doubled = builder.add(s3, s3);
    state[3] = builder.add(s3_doubled, sum);   // 2*s3 + sum
    let s4_doubled = builder.add(s4, s4);
    let s4_tripled = builder.add(s4_doubled, s4);
    state[4] = builder.add(s4_tripled, sum);   // 3*s4 + sum
}

// ============================================================================
// Full Poseidon2 Permutation Gadgets
// ============================================================================

/// Poseidon2 permutation gadget for t=3 (state width 3).
fn poseidon2_permutation_t3_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 3],
) {
    let rp = partial_rounds(3);
    let total_constants = 3 * RF + rp;
    let rc = generate_round_constants(b"genshi_poseidon2_bn254_t3", total_constants);
    let mut rc_idx = 0;
    
    // Initial full rounds
    for _ in 0..RF_HALF {
        for j in 0..3 {
            state[j] = add_constant_gadget(builder, state[j], rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..3 {
            state[j] = sbox_gadget(builder, state[j]);
        }
        external_linear_layer_t3_gadget(builder, state);
    }
    
    // Partial rounds
    for _ in 0..rp {
        state[0] = add_constant_gadget(builder, state[0], rc[rc_idx]);
        rc_idx += 1;
        state[0] = sbox_gadget(builder, state[0]);
        internal_linear_layer_t3_gadget(builder, state);
    }
    
    // Final full rounds
    for _ in 0..RF_HALF_END {
        for j in 0..3 {
            state[j] = add_constant_gadget(builder, state[j], rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..3 {
            state[j] = sbox_gadget(builder, state[j]);
        }
        external_linear_layer_t3_gadget(builder, state);
    }
}

/// Poseidon2 permutation gadget for t=4 (state width 4).
fn poseidon2_permutation_t4_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 4],
) {
    let rp = partial_rounds(4);
    let total_constants = 4 * RF + rp;
    let rc = generate_round_constants(b"genshi_poseidon2_bn254_t4", total_constants);
    let mut rc_idx = 0;
    
    for _ in 0..RF_HALF {
        for j in 0..4 {
            state[j] = add_constant_gadget(builder, state[j], rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..4 {
            state[j] = sbox_gadget(builder, state[j]);
        }
        external_linear_layer_t4_gadget(builder, state);
    }
    
    for _ in 0..rp {
        state[0] = add_constant_gadget(builder, state[0], rc[rc_idx]);
        rc_idx += 1;
        state[0] = sbox_gadget(builder, state[0]);
        internal_linear_layer_t4_gadget(builder, state);
    }
    
    for _ in 0..RF_HALF_END {
        for j in 0..4 {
            state[j] = add_constant_gadget(builder, state[j], rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..4 {
            state[j] = sbox_gadget(builder, state[j]);
        }
        external_linear_layer_t4_gadget(builder, state);
    }
}

/// Poseidon2 permutation gadget for t=5 (state width 5).
fn poseidon2_permutation_t5_gadget(
    builder: &mut UltraCircuitBuilder,
    state: &mut [WireRef; 5],
) {
    let rp = partial_rounds(5);
    let total_constants = 5 * RF + rp;
    let rc = generate_round_constants(b"genshi_poseidon2_bn254_t5", total_constants);
    let mut rc_idx = 0;
    
    for _ in 0..RF_HALF {
        for j in 0..5 {
            state[j] = add_constant_gadget(builder, state[j], rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..5 {
            state[j] = sbox_gadget(builder, state[j]);
        }
        external_linear_layer_t5_gadget(builder, state);
    }
    
    for _ in 0..rp {
        state[0] = add_constant_gadget(builder, state[0], rc[rc_idx]);
        rc_idx += 1;
        state[0] = sbox_gadget(builder, state[0]);
        internal_linear_layer_t5_gadget(builder, state);
    }
    
    for _ in 0..RF_HALF_END {
        for j in 0..5 {
            state[j] = add_constant_gadget(builder, state[j], rc[rc_idx]);
            rc_idx += 1;
        }
        for j in 0..5 {
            state[j] = sbox_gadget(builder, state[j]);
        }
        external_linear_layer_t5_gadget(builder, state);
    }
}

// ============================================================================
// Public Sponge Hash Gadgets
// ============================================================================

/// In-circuit Poseidon2 hash of 2 elements → 1 (t=3 sponge).
///
/// Used for binary Merkle compatibility during testing.
pub fn poseidon2_hash_2_gadget(
    builder: &mut UltraCircuitBuilder,
    a: WireRef,
    b: WireRef,
) -> WireRef {
    let zero = builder.zero_var();
    let mut state = [a, b, zero];
    poseidon2_permutation_t3_gadget(builder, &mut state);
    state[0]
}

/// In-circuit Poseidon2 hash of 3 elements → 1 (t=4 sponge).
pub fn poseidon2_hash_3_gadget(
    builder: &mut UltraCircuitBuilder,
    a: WireRef,
    b: WireRef,
    c: WireRef,
) -> WireRef {
    let zero = builder.zero_var();
    let mut state = [a, b, c, zero];
    poseidon2_permutation_t4_gadget(builder, &mut state);
    state[0]
}

/// In-circuit Poseidon2 hash of 4 elements → 1 (t=5 sponge).
///
/// Used for 4-ary Merkle tree nodes: `Poseidon2(child0, child1, child2, child3)`
pub fn poseidon2_hash_4_gadget(
    builder: &mut UltraCircuitBuilder,
    a: WireRef,
    b: WireRef,
    c: WireRef,
    d: WireRef,
) -> WireRef {
    let zero = builder.zero_var();
    let mut state = [a, b, c, d, zero];
    poseidon2_permutation_t5_gadget(builder, &mut state);
    state[0]
}

/// In-circuit Poseidon2 hash of 5 elements → 1 (two-pass t=5 sponge).
pub fn poseidon2_hash_5_gadget(
    builder: &mut UltraCircuitBuilder,
    a: WireRef,
    b: WireRef,
    c: WireRef,
    d: WireRef,
    e: WireRef,
) -> WireRef {
    let zero = builder.zero_var();
    // First absorption
    let mut state = [a, b, c, d, zero];
    poseidon2_permutation_t5_gadget(builder, &mut state);
    // Second absorption
    state[0] = builder.add(state[0], e);
    poseidon2_permutation_t5_gadget(builder, &mut state);
    state[0]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::poseidon2;

    #[test]
    fn test_poseidon2_hash_2_gadget_matches_native() {
        let a_val = Fr::from(1u64);
        let b_val = Fr::from(2u64);
        
        // Native computation
        let expected = poseidon2::poseidon2_hash_2(a_val, b_val);
        
        // In-circuit computation
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(a_val);
        let b = builder.add_variable(b_val);
        let result = poseidon2_hash_2_gadget(&mut builder, a, b);
        
        assert_eq!(builder.get_variable(result), expected, 
            "Gadget output must match native Poseidon2 hash_2");
        assert!(builder.check_circuit_correctness(),
            "Circuit must be satisfiable");
    }

    #[test]
    fn test_poseidon2_hash_3_gadget_matches_native() {
        let a_val = Fr::from(42u64);
        let b_val = Fr::from(100u64);
        let c_val = Fr::from(7u64);
        
        let expected = poseidon2::poseidon2_hash_3(a_val, b_val, c_val);
        
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(a_val);
        let b = builder.add_variable(b_val);
        let c = builder.add_variable(c_val);
        let result = poseidon2_hash_3_gadget(&mut builder, a, b, c);
        
        assert_eq!(builder.get_variable(result), expected,
            "Gadget output must match native Poseidon2 hash_3");
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_poseidon2_hash_4_gadget_matches_native() {
        let vals = [Fr::from(10u64), Fr::from(20u64), Fr::from(30u64), Fr::from(40u64)];

        let expected = poseidon2::poseidon2_hash_4(vals[0], vals[1], vals[2], vals[3]);

        let mut builder = UltraCircuitBuilder::new();
        let wires: Vec<_> = vals.iter().map(|v| builder.add_variable(*v)).collect();
        let result = poseidon2_hash_4_gadget(&mut builder, wires[0], wires[1], wires[2], wires[3]);

        assert_eq!(builder.get_variable(result), expected,
            "Gadget output must match native Poseidon2 hash_4");
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_poseidon2_hash_5_gadget_matches_native() {
        let vals = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), 
                    Fr::from(4u64), Fr::from(5u64)];
        
        let expected = poseidon2::poseidon2_hash_5(vals[0], vals[1], vals[2], vals[3], vals[4]);
        
        let mut builder = UltraCircuitBuilder::new();
        let wires: Vec<_> = vals.iter().map(|v| builder.add_variable(*v)).collect();
        let result = poseidon2_hash_5_gadget(
            &mut builder, wires[0], wires[1], wires[2], wires[3], wires[4]
        );
        
        assert_eq!(builder.get_variable(result), expected, 
            "Gadget output must match native Poseidon2 hash_5 (commitment)");
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_poseidon2_hash_2_gadget_zero_input() {
        let expected = poseidon2::poseidon2_hash_2(Fr::zero(), Fr::zero());
        
        let mut builder = UltraCircuitBuilder::new();
        let z = builder.zero_var();
        let result = poseidon2_hash_2_gadget(&mut builder, z, z);
        
        assert_eq!(builder.get_variable(result), expected);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_sbox_gadget() {
        // x=3, x^5 = 243
        let mut builder = UltraCircuitBuilder::new();
        let x = builder.add_variable(Fr::from(3u64));
        let x5 = sbox_gadget(&mut builder, x);
        
        assert_eq!(builder.get_variable(x5), Fr::from(243u64));
        assert!(builder.check_circuit_correctness());
        assert_eq!(builder.num_gates(), 3, "S-box should use 3 mul gates");
    }

    #[test]
    fn test_poseidon2_gate_count() {
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(Fr::from(1u64));
        let b = builder.add_variable(Fr::from(2u64));
        let _ = poseidon2_hash_2_gadget(&mut builder, a, b);
        
        // Log gate count for constraint analysis
        let count = builder.num_gates();
        // S-box: 3 mul gates × (3 full rounds × 3 elements + 56 partial × 1) = 3×(24+56) = 240
        // Linear layer + add constant overhead
        // Expected: ~500-900 gates for t=3 with 8 full + 56 partial rounds
        assert!(count > 100, "Poseidon2 t=3 should have significant gate count, got {}", count);
        assert!(count < 2000, "Poseidon2 t=3 should not exceed 2000 gates, got {}", count);
    }
}
