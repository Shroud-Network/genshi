//! `Proof` and `VerificationKey` — the two structs that travel between prover
//! and verifier.
//!
//! These live outside `prover.rs` so the verifier path (and BPF builds that
//! gate the prover behind a feature flag) can resolve them without pulling in
//! arithmetization code.
//!
//! The field types come from `genshi-math`, not `ark_bn254`, so that the
//! emitted Solana Anchor program — which compiles `genshi-math` with the
//! `bpf` backend instead of arkworks — sees the same struct layout and field
//! types. On native/WASM the backend is arkworks; on BPF it's Solana
//! syscalls + a hand-rolled Montgomery Fr. Either way, this file does not
//! change.

use genshi_math::{Fr, G1Affine};
use alloc::vec::Vec;

/// PLONK proof for UltraHonk.
#[derive(Clone, Debug)]
pub struct Proof {
    // Round 1: Wire commitments
    pub w_comms: [G1Affine; 4],

    // Round 2: Permutation grand product
    pub z_comm: G1Affine,

    // Round 3: Quotient polynomial parts
    pub t_comms: Vec<G1Affine>,

    // Round 4: Evaluations at ζ
    pub w_evals: [Fr; 4],
    pub sigma_evals: [Fr; 4], // σ₁(ζ), σ₂(ζ), σ₃(ζ), σ₄(ζ)
    pub z_eval: Fr,           // z(ζ)
    pub z_omega_eval: Fr,     // z(ζω)
    pub selector_evals: [Fr; 7], // q_m, q_1, q_2, q_3, q_4, q_c, q_arith at ζ
    pub t_eval: Fr,           // t(ζ) = Σ t_i(ζ) · ζ^(i·n)

    // Round 5: Opening witnesses
    pub w_zeta: G1Affine,       // batch opening at ζ
    pub w_zeta_omega: G1Affine, // opening of z at ζω
}

/// Verification key: commitments to preprocessed polynomials.
#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub q_m_comm: G1Affine,
    pub q_1_comm: G1Affine,
    pub q_2_comm: G1Affine,
    pub q_3_comm: G1Affine,
    pub q_4_comm: G1Affine,
    pub q_c_comm: G1Affine,
    pub q_arith_comm: G1Affine,
    pub sigma_comms: [G1Affine; 4],

    pub domain_size: usize,
    pub num_public_inputs: usize,
    pub omega: Fr,
    pub k: [Fr; 4],
}
