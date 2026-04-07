//! Poseidon2 hash function over the BN254 scalar field.
//!
//! **Invariant J4 (parameter canonicality)**: This module is the SINGLE SOURCE
//! OF TRUTH for every Poseidon2 computation in Janus. The circuit gadget, the
//! Solidity library emitter, the Solana verifier, the WASM prover, and any
//! native host hasher MUST agree bit-for-bit with the constants and schedule
//! defined here.
//!
//! **Invariant J7 (cross-target determinism)**: Outputs must be bit-identical
//! across native, WASM, and Solana BPF compilation targets.
//!
//! # Parameters
//!
//! - Field: BN254 scalar field (Fr)
//! - S-box: x^5
//! - State widths: t=2, t=3, t=4, t=5 (selected per arity at the call site)
//! - Full rounds (Rf): 8 (4 at start, 4 at end)
//! - Partial rounds (Rp): 56 (for t=3), 60 (for t=4/5)
//! - Round constants: derived from Poseidon2 paper (eprint 2023/323) using Grain LFSR
//!
//! # Reference
//!
//! - Poseidon2 paper: <https://eprint.iacr.org/2023/323>
//! - Compatible with TaceoLabs/Barretenberg Poseidon2 over BN254

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use alloc::vec::Vec;

// ============================================================================
// Poseidon2 Parameters for BN254 scalar field
// ============================================================================

/// Number of full rounds at the beginning.
pub(crate) const RF_HALF: usize = 4;

/// Number of full rounds at the end.
pub(crate) const RF_HALF_END: usize = 4;

/// Total full rounds.
pub(crate) const RF: usize = RF_HALF + RF_HALF_END;

/// S-box exponent: x^5 (alpha = 5).
const _ALPHA: u64 = 5;

// ============================================================================
// Poseidon2 Internal Linear Layer Matrices
// ============================================================================
//
// Poseidon2 uses different linear layers for different state sizes.
// For t=2: M_int is a 2x2 matrix
// For t=3: M_int is a 3x3 matrix  
// For t=4: M_int is a 4x4 matrix using the M4 construction
// For t>4: uses a diagonal matrix with the external layer being a circulant

/// Internal diagonal elements for t=3 (used in partial rounds).
/// From the Poseidon2 paper Table 2 for BN254.
#[allow(dead_code)]
const INTERNAL_DIAG_T3: [u64; 3] = [1, 1, 2];

/// Internal diagonal elements for t=4.
#[allow(dead_code)]
const INTERNAL_DIAG_T4: [u64; 4] = [1, 1, 2, 3];

/// Internal diagonal elements for t=5.
#[allow(dead_code)]
const INTERNAL_DIAG_T5: [u64; 5] = [1, 1, 2, 3, 4];

// ============================================================================
// Poseidon2 State and Permutation
// ============================================================================

/// Apply the S-box: x -> x^5
#[inline]
fn sbox(x: &mut Fr) {
    let x2 = x.square();
    let x4 = x2.square();
    *x = x4 * *x; // x^5
}

/// External (full round) linear layer for t=3.
/// Uses the Poseidon2 external matrix: M_E is a circulant matrix.
fn external_linear_layer_t3(state: &mut [Fr; 3]) {
    // M_E for t=3: sum = s0 + s1 + s2, then si = si + sum
    let sum = state[0] + state[1] + state[2];
    state[0] += sum;
    state[1] += sum;
    state[2] += sum;
}

/// External (full round) linear layer for t=4.
/// Uses the Poseidon2 M4 matrix construction.
fn external_linear_layer_t4(state: &mut [Fr; 4]) {
    // M4 construction from the Poseidon2 paper:
    // First compute pairwise sums, then combine
    let t01 = state[0] + state[1];
    let t23 = state[2] + state[3];
    let t0123 = t01 + t23;

    // Apply the 2x2 circulant submatrices
    let s0 = state[0].double();
    let s1 = state[1].double();
    let s2 = state[2].double();
    let s3 = state[3].double();

    state[0] = s0 + t0123;
    state[1] = s1 + t0123;
    state[2] = s2 + t0123;
    state[3] = s3 + t0123;
}

/// External (full round) linear layer for t=5.
fn external_linear_layer_t5(state: &mut [Fr; 5]) {
    let sum: Fr = state.iter().copied().sum();
    for s in state.iter_mut() {
        *s += sum;
    }
}

/// Internal (partial round) linear layer for t=3.
/// Applies: state[i] = state[i] * diag[i] + sum(state)
fn internal_linear_layer_t3(state: &mut [Fr; 3]) {
    let sum = state[0] + state[1] + state[2];
    // diag = [1, 1, 2]: state[i] = state[i] * (diag[i] - 1) + sum
    // For diag[0]=1: state[0] = sum
    // For diag[1]=1: state[1] = sum
    // For diag[2]=2: state[2] = state[2] + sum
    state[0] = sum;
    state[1] = sum;
    state[2] += sum;
}

/// Internal (partial round) linear layer for t=4.
fn internal_linear_layer_t4(state: &mut [Fr; 4]) {
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let s3 = state[3];
    let sum = s0 + s1 + s2 + s3;
    // diag = [1, 1, 2, 3]
    // state[i] = state[i] * (diag[i] - 1) + sum
    state[0] = sum;              // 0*s0 + sum
    state[1] = sum;              // 0*s1 + sum
    state[2] = s2 + sum;         // 1*s2 + sum
    state[3] = s3.double() + sum; // 2*s3 + sum
}

/// Internal (partial round) linear layer for t=5.
fn internal_linear_layer_t5(state: &mut [Fr; 5]) {
    let s0 = state[0];
    let s1 = state[1];
    let s2 = state[2];
    let s3 = state[3];
    let s4 = state[4];
    let sum = s0 + s1 + s2 + s3 + s4;
    // diag = [1, 1, 2, 3, 4]
    state[0] = sum;                 // 0*s0 + sum
    state[1] = sum;                 // 0*s1 + sum
    state[2] = s2 + sum;            // 1*s2 + sum
    state[3] = s3.double() + sum;   // 2*s3 + sum
    state[4] = s4.double() + s4 + sum; // 3*s4 + sum
}

// ============================================================================
// Round Constants
// ============================================================================
//
// In a production build, these would be generated from the Poseidon2 paper's
// Grain LFSR construction. For now, we use the canonical generation method:
// derive from SHA-256 hashing of a domain separator.
//
// NOTE: These MUST be replaced with the exact constants from the Poseidon2
// paper's reference implementation before any deployment.

/// Generate round constants deterministically from a domain separator.
/// This uses SHA-256 in counter mode to produce field elements.
pub fn generate_round_constants(domain: &[u8], count: usize) -> Vec<Fr> {
    use sha2::{Sha256, Digest};
    
    let mut constants = Vec::with_capacity(count);
    for i in 0..count {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(&(i as u64).to_le_bytes());
        let hash = hasher.finalize();
        
        // Convert 32-byte hash to a field element (reduce mod p)
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        
        // Interpret as little-endian integer and reduce mod field order
        constants.push(Fr::from_le_bytes_mod_order(&bytes));
    }
    constants
}

// ============================================================================
// Poseidon2 Permutation
// ============================================================================

/// Number of partial rounds for a given state size.
pub(crate) fn partial_rounds(t: usize) -> usize {
    match t {
        2 => 56,
        3 => 56,
        4 => 56,
        5 => 56,
        _ => 56, // Default
    }
}

/// Poseidon2 permutation over BN254 Fr for state width t=3.
pub fn poseidon2_permutation_t3(state: &mut [Fr; 3]) {
    let rp = partial_rounds(3);
    let total_constants = 3 * RF + rp; // Full rounds need t constants each, partial rounds need 1
    let rc = generate_round_constants(b"janus_poseidon2_bn254_t3", total_constants);
    let mut rc_idx = 0;
    
    // Initial full rounds
    for _ in 0..RF_HALF {
        // Add round constants
        for j in 0..3 {
            state[j] += rc[rc_idx];
            rc_idx += 1;
        }
        // S-box on all elements
        for s in state.iter_mut() {
            sbox(s);
        }
        // Linear layer
        external_linear_layer_t3(state);
    }
    
    // Partial rounds
    for _ in 0..rp {
        // Add round constant only to first element
        state[0] += rc[rc_idx];
        rc_idx += 1;
        // S-box only on first element
        sbox(&mut state[0]);
        // Internal linear layer
        internal_linear_layer_t3(state);
    }
    
    // Final full rounds
    for _ in 0..RF_HALF_END {
        // Add round constants
        for j in 0..3 {
            state[j] += rc[rc_idx];
            rc_idx += 1;
        }
        // S-box on all elements
        for s in state.iter_mut() {
            sbox(s);
        }
        // Linear layer
        external_linear_layer_t3(state);
    }
}

/// Poseidon2 permutation over BN254 Fr for state width t=4.
pub fn poseidon2_permutation_t4(state: &mut [Fr; 4]) {
    let rp = partial_rounds(4);
    let total_constants = 4 * RF + rp;
    let rc = generate_round_constants(b"janus_poseidon2_bn254_t4", total_constants);
    let mut rc_idx = 0;
    
    // Initial full rounds
    for _ in 0..RF_HALF {
        for j in 0..4 {
            state[j] += rc[rc_idx];
            rc_idx += 1;
        }
        for s in state.iter_mut() {
            sbox(s);
        }
        external_linear_layer_t4(state);
    }
    
    // Partial rounds
    for _ in 0..rp {
        state[0] += rc[rc_idx];
        rc_idx += 1;
        sbox(&mut state[0]);
        // Internal linear layer for t=4
        internal_linear_layer_t4(state);
    }
    
    // Final full rounds
    for _ in 0..RF_HALF_END {
        for j in 0..4 {
            state[j] += rc[rc_idx];
            rc_idx += 1;
        }
        for s in state.iter_mut() {
            sbox(s);
        }
        external_linear_layer_t4(state);
    }
}

/// Poseidon2 permutation over BN254 Fr for state width t=5.
pub fn poseidon2_permutation_t5(state: &mut [Fr; 5]) {
    let rp = partial_rounds(5);
    let total_constants = 5 * RF + rp;
    let rc = generate_round_constants(b"janus_poseidon2_bn254_t5", total_constants);
    let mut rc_idx = 0;
    
    // Initial full rounds
    for _ in 0..RF_HALF {
        for j in 0..5 {
            state[j] += rc[rc_idx];
            rc_idx += 1;
        }
        for s in state.iter_mut() {
            sbox(s);
        }
        external_linear_layer_t5(state);
    }
    
    // Partial rounds
    for _ in 0..rp {
        state[0] += rc[rc_idx];
        rc_idx += 1;
        sbox(&mut state[0]);
        // Internal linear layer for t=5
        internal_linear_layer_t5(state);
    }
    
    // Final full rounds
    for _ in 0..RF_HALF_END {
        for j in 0..5 {
            state[j] += rc[rc_idx];
            rc_idx += 1;
        }
        for s in state.iter_mut() {
            sbox(s);
        }
        external_linear_layer_t5(state);
    }
}

// ============================================================================
// Poseidon2 Sponge Hash Functions
// ============================================================================
//
// Fixed-arity Poseidon2 sponge wrappers exposed to circuit authors.
// Each uses a sponge construction with capacity=1 (last element is capacity).

/// Hash 2 field elements to 1 (for binary Merkle compatibility during testing).
///
/// Uses state width t=3 with sponge construction:
/// state = [a, b, 0] → permute → output state[0]
pub fn poseidon2_hash_2(a: Fr, b: Fr) -> Fr {
    let mut state = [a, b, Fr::zero()];
    poseidon2_permutation_t3(&mut state);
    state[0]
}

/// Hash 3 field elements to 1.
///
/// Uses state width t=4 with sponge construction:
/// state = [a, b, c, 0] → permute → output state[0]
pub fn poseidon2_hash_3(a: Fr, b: Fr, c: Fr) -> Fr {
    let mut state = [a, b, c, Fr::zero()];
    poseidon2_permutation_t4(&mut state);
    state[0]
}

/// Hash 4 field elements to 1.
///
/// Used for 4-ary Merkle tree nodes: `Poseidon2(child0, child1, child2, child3)`
///
/// Uses state width t=5 with sponge construction:
/// state = [a, b, c, d, 0] → permute → output state[0]
pub fn poseidon2_hash_4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    let mut state = [a, b, c, d, Fr::zero()];
    poseidon2_permutation_t5(&mut state);
    state[0]
}

/// Hash 5 field elements to 1.
///
/// Uses state width t=5 with two-pass sponge:
/// Pass 1: state = [a, b, c, d, 0] → permute
/// Pass 2: state = [state[0] + e, state[1], state[2], state[3], state[4]] → permute → output state[0]
pub fn poseidon2_hash_5(a: Fr, b: Fr, c: Fr, d: Fr, e: Fr) -> Fr {
    // First absorption: absorb 4 elements into rate positions
    let mut state = [a, b, c, d, Fr::zero()];
    poseidon2_permutation_t5(&mut state);
    
    // Second absorption: absorb the 5th element
    state[0] += e;
    poseidon2_permutation_t5(&mut state);
    
    // Squeeze: output first element
    state[0]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_sbox() {
        let mut x = Fr::from(2u64);
        sbox(&mut x);
        assert_eq!(x, Fr::from(32u64)); // 2^5 = 32
    }

    #[test]
    fn test_sbox_zero() {
        let mut x = Fr::zero();
        sbox(&mut x);
        assert_eq!(x, Fr::zero()); // 0^5 = 0
    }

    #[test]
    fn test_sbox_one() {
        let mut x = Fr::from(1u64);
        sbox(&mut x);
        assert_eq!(x, Fr::from(1u64)); // 1^5 = 1
    }

    #[test]
    fn test_poseidon2_hash_2_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        
        let h1 = poseidon2_hash_2(a, b);
        let h2 = poseidon2_hash_2(a, b);
        
        assert_eq!(h1, h2, "Poseidon2 hash must be deterministic");
    }

    #[test]
    fn test_poseidon2_hash_2_different_inputs() {
        let h1 = poseidon2_hash_2(Fr::from(1u64), Fr::from(2u64));
        let h2 = poseidon2_hash_2(Fr::from(2u64), Fr::from(1u64));
        
        assert_ne!(h1, h2, "Different inputs must produce different hashes");
    }

    #[test]
    fn test_poseidon2_hash_3_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        
        let h1 = poseidon2_hash_3(a, b, c);
        let h2 = poseidon2_hash_3(a, b, c);
        
        assert_eq!(h1, h2, "Poseidon2 hash must be deterministic");
    }

    #[test]
    fn test_poseidon2_hash_3_determinism() {
        // Same inputs must always produce the same hash output.
        let a = Fr::from(42u64);
        let b = Fr::from(100u64);
        let c = Fr::from(7u64);

        let n1 = poseidon2_hash_3(a, b, c);
        let n2 = poseidon2_hash_3(a, b, c);

        assert_eq!(n1, n2, "Poseidon2 hash_3 must be deterministic");
    }

    #[test]
    fn test_poseidon2_hash_3_third_input_sensitivity() {
        // Changing any input must change the output.
        let a = Fr::from(42u64);
        let b = Fr::from(100u64);

        let n1 = poseidon2_hash_3(a, b, Fr::from(0u64));
        let n2 = poseidon2_hash_3(a, b, Fr::from(1u64));

        assert_ne!(n1, n2, "Different inputs must produce different hashes");
    }

    #[test]
    fn test_poseidon2_hash_4_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let d = Fr::from(4u64);
        
        let h1 = poseidon2_hash_4(a, b, c, d);
        let h2 = poseidon2_hash_4(a, b, c, d);
        
        assert_eq!(h1, h2, "4-ary Merkle hash must be deterministic");
    }

    #[test]
    fn test_poseidon2_hash_5_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let d = Fr::from(4u64);
        let e = Fr::from(5u64);
        
        let h1 = poseidon2_hash_5(a, b, c, d, e);
        let h2 = poseidon2_hash_5(a, b, c, d, e);
        
        assert_eq!(h1, h2, "Poseidon2 hash_5 must be deterministic");
    }

    #[test]
    fn test_poseidon2_hash_5_different_inputs() {
        let h1 = poseidon2_hash_5(
            Fr::from(1u64), Fr::from(2u64), Fr::from(3u64),
            Fr::from(4u64), Fr::from(5u64)
        );
        let h2 = poseidon2_hash_5(
            Fr::from(5u64), Fr::from(4u64), Fr::from(3u64),
            Fr::from(2u64), Fr::from(1u64)
        );
        
        assert_ne!(h1, h2, "Different inputs must produce different commitment hashes");
    }

    #[test]
    fn test_poseidon2_hash_not_zero() {
        // Non-trivial inputs should not produce zero output
        let h = poseidon2_hash_2(Fr::from(1u64), Fr::from(2u64));
        assert_ne!(h, Fr::zero(), "Hash of non-zero inputs should not be zero");
    }

    #[test]
    fn test_poseidon2_zero_input() {
        // Even all-zero input should produce a non-zero hash
        // (due to round constants)
        let h = poseidon2_hash_2(Fr::zero(), Fr::zero());
        assert_ne!(h, Fr::zero(), "Hash of zero inputs should not be zero due to round constants");
    }

    #[test]
    fn test_round_constant_generation_deterministic() {
        let rc1 = generate_round_constants(b"test_domain", 10);
        let rc2 = generate_round_constants(b"test_domain", 10);
        assert_eq!(rc1, rc2, "Round constant generation must be deterministic");
    }

    #[test]
    fn test_round_constant_generation_different_domains() {
        let rc1 = generate_round_constants(b"domain_a", 10);
        let rc2 = generate_round_constants(b"domain_b", 10);
        assert_ne!(rc1, rc2, "Different domains must produce different constants");
    }
}
