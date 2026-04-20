//! genshi PLONK proof verification — pure Rust, no_std compatible.
//!
//! This module MUST remain no_std compatible because it compiles to:
//! - Solana BPF (on-chain verifier using sol_alt_bn128_* syscalls)
//! - Browser WASM (client-side verification)
//! - Native (server-side)
//!
//! **Invariant J1**: One proof format, both VMs. The same proof bytes must
//! verify bytewise-identically on both EVM and Solana.
//!
//! # Verification Steps
//!
//! 1. Reconstruct Fiat-Shamir transcript (same challenges as prover)
//! 2. Verify constraint equation: t(ζ)·Z_H(ζ) = gate + α·perm + α²·boundary
//! 3. Batch KZG verification of opening proofs at ζ
//! 4. KZG verification of z opening at ζω
//!
//! All field and curve operations go through `genshi-math`, which routes to
//! arkworks on native/WASM and to Solana syscalls + hand-rolled Fr on BPF.
//! The verifier never imports `ark_*` directly.

use genshi_math::{pairing_check, Fr, G1Affine, G1Projective};

use super::types::{Proof, VerificationKey};
use super::srs::SRS;
use super::transcript::Transcript;

// ============================================================================
// Verifier
// ============================================================================

/// Verify an UltraHonk proof against a verification key and public inputs.
///
/// Returns `true` if the proof is valid, `false` otherwise.
pub fn verify(
    proof: &Proof,
    vk: &VerificationKey,
    public_inputs: &[Fr],
    srs: &SRS,
) -> bool {
    assert_eq!(
        public_inputs.len(),
        vk.num_public_inputs,
        "Public input count mismatch"
    );

    let n = vk.domain_size;
    let omega = vk.omega;

    // ================================================================
    // Step 1: Reconstruct Fiat-Shamir challenges
    // ================================================================
    let mut transcript = Transcript::new(b"genshi_plonk");

    for c in &proof.w_comms {
        transcript.absorb_point(b"w", c);
    }
    let beta = transcript.squeeze_challenge(b"beta");
    let gamma = transcript.squeeze_challenge(b"gamma");

    transcript.absorb_point(b"z", &proof.z_comm);
    let alpha = transcript.squeeze_challenge(b"alpha");

    for c in &proof.t_comms {
        transcript.absorb_point(b"t", c);
    }
    let zeta = transcript.squeeze_challenge(b"zeta");
    let zeta_omega = zeta * omega;

    for e in &proof.w_evals {
        transcript.absorb_scalar(b"we", e);
    }
    for e in &proof.sigma_evals {
        transcript.absorb_scalar(b"se", e);
    }
    transcript.absorb_scalar(b"ze", &proof.z_eval);
    transcript.absorb_scalar(b"zw", &proof.z_omega_eval);
    for e in &proof.selector_evals {
        transcript.absorb_scalar(b"qe", e);
    }
    transcript.absorb_scalar(b"te", &proof.t_eval);

    let nu = transcript.squeeze_challenge(b"nu");

    // ================================================================
    // Step 2: Verify constraint equation at ζ
    // t(ζ) · Z_H(ζ) = gate(ζ) + α·perm(ζ) + α²·boundary(ζ)
    // ================================================================
    let zeta_n = zeta.pow(&[n as u64]);
    let zh_zeta = zeta_n - Fr::one();

    // Lagrange L₁(ζ)
    let n_fr = Fr::from(n as u64);
    let l1_zeta = if (zeta - Fr::one()).is_zero() {
        Fr::one()
    } else {
        zh_zeta / (n_fr * (zeta - Fr::one()))
    };

    // Public input polynomial PI(ζ) = -Σ pi_i · L_i(ζ)
    let mut pi_zeta = Fr::zero();
    for (i, &pi_val) in public_inputs.iter().enumerate() {
        let omega_i = omega.pow(&[i as u64]);
        if (zeta - omega_i).is_zero() {
            pi_zeta -= pi_val;
        } else {
            let li = omega_i * zh_zeta / (n_fr * (zeta - omega_i));
            pi_zeta -= pi_val * li;
        }
    }

    let w1 = proof.w_evals[0];
    let w2 = proof.w_evals[1];
    let w3 = proof.w_evals[2];
    let w4 = proof.w_evals[3];

    let qm = proof.selector_evals[0];
    let q1 = proof.selector_evals[1];
    let q2 = proof.selector_evals[2];
    let q3 = proof.selector_evals[3];
    let q4 = proof.selector_evals[4];
    let qc = proof.selector_evals[5];
    let qa = proof.selector_evals[6];

    let gate = qa * (qm * w1 * w2 + q1 * w1 + q2 * w2 + q3 * w3 + q4 * w4 + qc) + pi_zeta;

    let k = &vk.k;
    let perm_num = proof.z_eval
        * (w1 + beta * k[0] * zeta + gamma)
        * (w2 + beta * k[1] * zeta + gamma)
        * (w3 + beta * k[2] * zeta + gamma)
        * (w4 + beta * k[3] * zeta + gamma);

    let perm_den = proof.z_omega_eval
        * (w1 + beta * proof.sigma_evals[0] + gamma)
        * (w2 + beta * proof.sigma_evals[1] + gamma)
        * (w3 + beta * proof.sigma_evals[2] + gamma)
        * (w4 + beta * proof.sigma_evals[3] + gamma);

    let perm = perm_num - perm_den;
    let boundary = l1_zeta * (proof.z_eval - Fr::one());

    let lhs = proof.t_eval * zh_zeta;
    let rhs = gate + alpha * perm + alpha * alpha * boundary;

    if lhs != rhs {
        return false;
    }

    // ================================================================
    // Step 3: Batch KZG verification at ζ
    // ================================================================
    let mut f = G1Projective::zero();
    let mut v = Fr::zero();
    let mut nu_pow = Fr::one();

    for i in 0..4 {
        f += proof.w_comms[i].into_group() * nu_pow;
        v += proof.w_evals[i] * nu_pow;
        nu_pow *= nu;
    }

    for i in 0..4 {
        f += vk.sigma_comms[i].into_group() * nu_pow;
        v += proof.sigma_evals[i] * nu_pow;
        nu_pow *= nu;
    }

    let selector_comms = alloc::boxed::Box::new([
        vk.q_m_comm, vk.q_1_comm, vk.q_2_comm, vk.q_3_comm,
        vk.q_4_comm, vk.q_c_comm, vk.q_arith_comm,
    ]);
    for i in 0..7 {
        f += selector_comms[i].into_group() * nu_pow;
        v += proof.selector_evals[i] * nu_pow;
        nu_pow *= nu;
    }

    f += proof.z_comm.into_group() * nu_pow;
    v += proof.z_eval * nu_pow;

    // Batch pairing: e(F - v·G₁, G₂) · e(-W_ζ, τ·G₂ - ζ·G₂) == 1
    let v_g1 = G1Affine::generator() * v;
    let lhs_g1 = (f - v_g1).into_affine();

    let zeta_g2 = srs.g2 * zeta;
    let rhs_g2 = (srs.g2_tau.into_group() - zeta_g2).into_affine();
    let neg_w_zeta = (-proof.w_zeta.into_group()).into_affine();

    if !pairing_check(lhs_g1, srs.g2, neg_w_zeta, rhs_g2) {
        return false;
    }

    // ================================================================
    // Step 4: KZG verification of z at ζω
    // ================================================================
    let z_v_g1 = G1Affine::generator() * proof.z_omega_eval;
    let z_lhs = (proof.z_comm.into_group() - z_v_g1).into_affine();

    let zeta_omega_g2 = srs.g2 * zeta_omega;
    let z_rhs_g2 = (srs.g2_tau.into_group() - zeta_omega_g2).into_affine();
    let neg_w_zeta_omega = (-proof.w_zeta_omega.into_group()).into_affine();

    pairing_check(z_lhs, srs.g2, neg_w_zeta_omega, z_rhs_g2)
}

// ============================================================================
// Verification intermediates for external pairing (Solana syscalls)
// ============================================================================

/// Intermediate values from verification Steps 1-3, ready for pairing.
///
/// Legacy shape used by the v1 `genshi-solana` runtime crate, which drove the
/// pairing via Solana syscalls manually. The v2 codegen path routes the
/// pairing through `genshi-math::pairing_check` directly and does not need
/// this — but we keep the helper so v1 callers don't break.
#[derive(Clone, Debug)]
pub struct VerificationIntermediates {
    pub batch_lhs: G1Affine,
    pub batch_neg_w: G1Affine,
    pub z_lhs: G1Affine,
    pub z_neg_w: G1Affine,
    pub zeta: Fr,
    pub zeta_omega: Fr,
}

/// Compute verification intermediates without performing pairing checks.
///
/// Returns `Some(intermediates)` if the constraint equation passes,
/// `None` if the constraint equation fails.
pub fn verify_prepare(
    proof: &Proof,
    vk: &VerificationKey,
    public_inputs: &[Fr],
) -> Option<VerificationIntermediates> {
    assert_eq!(public_inputs.len(), vk.num_public_inputs);

    let n = vk.domain_size;
    let omega = vk.omega;

    let mut transcript = Transcript::new(b"genshi_plonk");
    for c in &proof.w_comms {
        transcript.absorb_point(b"w", c);
    }
    let beta = transcript.squeeze_challenge(b"beta");
    let gamma = transcript.squeeze_challenge(b"gamma");
    transcript.absorb_point(b"z", &proof.z_comm);
    let alpha = transcript.squeeze_challenge(b"alpha");
    for c in &proof.t_comms {
        transcript.absorb_point(b"t", c);
    }
    let zeta = transcript.squeeze_challenge(b"zeta");
    let zeta_omega = zeta * omega;

    for e in &proof.w_evals { transcript.absorb_scalar(b"we", e); }
    for e in &proof.sigma_evals { transcript.absorb_scalar(b"se", e); }
    transcript.absorb_scalar(b"ze", &proof.z_eval);
    transcript.absorb_scalar(b"zw", &proof.z_omega_eval);
    for e in &proof.selector_evals { transcript.absorb_scalar(b"qe", e); }
    transcript.absorb_scalar(b"te", &proof.t_eval);
    let nu = transcript.squeeze_challenge(b"nu");

    let zeta_n = zeta.pow(&[n as u64]);
    let zh_zeta = zeta_n - Fr::one();
    let n_fr = Fr::from(n as u64);
    let l1_zeta = if (zeta - Fr::one()).is_zero() {
        Fr::one()
    } else {
        zh_zeta / (n_fr * (zeta - Fr::one()))
    };

    let mut pi_zeta = Fr::zero();
    for (i, &pi_val) in public_inputs.iter().enumerate() {
        let omega_i = omega.pow(&[i as u64]);
        if (zeta - omega_i).is_zero() {
            pi_zeta -= pi_val;
        } else {
            let li = omega_i * zh_zeta / (n_fr * (zeta - omega_i));
            pi_zeta -= pi_val * li;
        }
    }

    let (w1, w2, w3, w4) = (proof.w_evals[0], proof.w_evals[1], proof.w_evals[2], proof.w_evals[3]);
    let (qm, q1, q2, q3, q4, qc, qa) = (
        proof.selector_evals[0], proof.selector_evals[1], proof.selector_evals[2],
        proof.selector_evals[3], proof.selector_evals[4], proof.selector_evals[5],
        proof.selector_evals[6],
    );

    let gate = qa * (qm * w1 * w2 + q1 * w1 + q2 * w2 + q3 * w3 + q4 * w4 + qc) + pi_zeta;

    let k = &vk.k;
    let perm_num = proof.z_eval
        * (w1 + beta * k[0] * zeta + gamma)
        * (w2 + beta * k[1] * zeta + gamma)
        * (w3 + beta * k[2] * zeta + gamma)
        * (w4 + beta * k[3] * zeta + gamma);
    let perm_den = proof.z_omega_eval
        * (w1 + beta * proof.sigma_evals[0] + gamma)
        * (w2 + beta * proof.sigma_evals[1] + gamma)
        * (w3 + beta * proof.sigma_evals[2] + gamma)
        * (w4 + beta * proof.sigma_evals[3] + gamma);
    let perm = perm_num - perm_den;
    let boundary = l1_zeta * (proof.z_eval - Fr::one());

    let lhs_eq = proof.t_eval * zh_zeta;
    let rhs_eq = gate + alpha * perm + alpha * alpha * boundary;
    if lhs_eq != rhs_eq {
        return None;
    }

    let mut f = G1Projective::zero();
    let mut v = Fr::zero();
    let mut nu_pow = Fr::one();

    for i in 0..4 {
        f += proof.w_comms[i].into_group() * nu_pow;
        v += proof.w_evals[i] * nu_pow;
        nu_pow *= nu;
    }
    for i in 0..4 {
        f += vk.sigma_comms[i].into_group() * nu_pow;
        v += proof.sigma_evals[i] * nu_pow;
        nu_pow *= nu;
    }
    let selector_comms = alloc::boxed::Box::new([
        vk.q_m_comm, vk.q_1_comm, vk.q_2_comm, vk.q_3_comm,
        vk.q_4_comm, vk.q_c_comm, vk.q_arith_comm,
    ]);
    for i in 0..7 {
        f += selector_comms[i].into_group() * nu_pow;
        v += proof.selector_evals[i] * nu_pow;
        nu_pow *= nu;
    }
    f += proof.z_comm.into_group() * nu_pow;
    v += proof.z_eval * nu_pow;

    let v_g1 = G1Affine::generator() * v;
    let batch_lhs = (f - v_g1).into_affine();
    let batch_neg_w = (-proof.w_zeta.into_group()).into_affine();

    let z_v_g1 = G1Affine::generator() * proof.z_omega_eval;
    let z_lhs = (proof.z_comm.into_group() - z_v_g1).into_affine();
    let z_neg_w = (-proof.w_zeta_omega.into_group()).into_affine();

    Some(VerificationIntermediates {
        batch_lhs,
        batch_neg_w,
        z_lhs,
        z_neg_w,
        zeta,
        zeta_omega,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
    use crate::proving::prover;
    use crate::proving::srs::SRS;
    use ark_bn254::Fr as ArkFr;

    fn test_srs() -> SRS {
        SRS::insecure_for_testing(128)
    }

    fn f(v: u64) -> Fr {
        Fr::from(v)
    }

    #[test]
    fn test_end_to_end_simple_addition() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();

        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        assert!(builder.check_circuit_correctness());
        let (proof, vk) = prover::prove(&builder, &srs);
        assert!(verify(&proof, &vk, &[], &srs), "Valid addition proof should verify");
    }

    #[test]
    fn test_end_to_end_multiplication() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();

        let a = builder.add_variable(ArkFr::from(5u64));
        let b = builder.add_variable(ArkFr::from(6u64));
        let c = builder.add_variable(ArkFr::from(30u64));
        builder.create_mul_gate(a, b, c);

        assert!(builder.check_circuit_correctness());
        let (proof, vk) = prover::prove(&builder, &srs);
        assert!(verify(&proof, &vk, &[], &srs), "Valid multiplication proof should verify");
    }

    #[test]
    fn test_end_to_end_with_public_inputs() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();

        let a = builder.add_variable(ArkFr::from(10u64));
        let b = builder.add_variable(ArkFr::from(20u64));
        let c = builder.add_variable(ArkFr::from(30u64));
        builder.create_add_gate(a, b, c);
        builder.set_public(c);

        assert!(builder.check_circuit_correctness());
        let (proof, vk) = prover::prove(&builder, &srs);
        assert!(verify(&proof, &vk, &[f(30)], &srs), "Public input proof should verify");
    }

    #[test]
    fn test_tampered_proof_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();

        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.w_evals[0] = f(999);

        assert!(!verify(&proof, &vk, &[], &srs), "Tampered proof should not verify");
    }

    #[test]
    fn test_wrong_public_inputs_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();

        let a = builder.add_variable(ArkFr::from(10u64));
        let b = builder.add_variable(ArkFr::from(20u64));
        let c = builder.add_variable(ArkFr::from(30u64));
        builder.create_add_gate(a, b, c);
        builder.set_public(c);

        let (proof, vk) = prover::prove(&builder, &srs);
        assert!(!verify(&proof, &vk, &[f(31)], &srs), "Wrong PI should fail");
    }

    #[test]
    fn test_multi_gate_circuit() {
        let srs = SRS::insecure_for_testing(256);
        let mut builder = UltraCircuitBuilder::new();

        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let d = builder.add_variable(ArkFr::from(5u64));

        let ab = builder.mul(a, b);
        let c = builder.add(ab, d);
        builder.set_public(c);

        assert!(builder.check_circuit_correctness());
        let (proof, vk) = prover::prove(&builder, &srs);
        assert!(verify(&proof, &vk, &[f(17)], &srs), "Multi-gate should verify");
    }

    #[test]
    fn test_tampered_z_comm_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.z_comm = G1Affine::generator();
        assert!(!verify(&proof, &vk, &[], &srs), "Tampered z_comm should fail");
    }

    #[test]
    fn test_tampered_sigma_evals_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.sigma_evals[0] += Fr::one();
        assert!(!verify(&proof, &vk, &[], &srs), "Tampered sigma eval should fail");
    }

    #[test]
    fn test_tampered_selector_evals_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.selector_evals[2] = f(9999);
        assert!(!verify(&proof, &vk, &[], &srs), "Tampered selector eval should fail");
    }

    #[test]
    fn test_tampered_t_eval_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.t_eval += Fr::one();
        assert!(!verify(&proof, &vk, &[], &srs), "Tampered t_eval should fail");
    }

    #[test]
    fn test_tampered_w_zeta_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.w_zeta = G1Affine::generator();
        assert!(!verify(&proof, &vk, &[], &srs), "Tampered w_zeta should fail");
    }

    #[test]
    fn test_tampered_w_zeta_omega_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.w_zeta_omega = G1Affine::generator();
        assert!(!verify(&proof, &vk, &[], &srs), "Tampered w_zeta_omega should fail");
    }

    #[test]
    fn test_tampered_z_omega_eval_fails() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.z_omega_eval += f(42);
        assert!(!verify(&proof, &vk, &[], &srs), "Tampered z_omega_eval should fail");
    }

    #[test]
    #[should_panic(expected = "Public input count mismatch")]
    fn test_wrong_public_input_count_panics() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(10u64));
        let b = builder.add_variable(ArkFr::from(20u64));
        let c = builder.add_variable(ArkFr::from(30u64));
        builder.create_add_gate(a, b, c);
        builder.set_public(c);

        let (proof, vk) = prover::prove(&builder, &srs);
        verify(&proof, &vk, &[f(30), f(1)], &srs);
    }

    #[test]
    fn test_proof_from_different_circuit_fails() {
        let srs = SRS::insecure_for_testing(256);

        let mut b1 = UltraCircuitBuilder::new();
        let a1 = b1.add_variable(ArkFr::from(3u64));
        let b1v = b1.add_variable(ArkFr::from(4u64));
        let c1 = b1.add_variable(ArkFr::from(7u64));
        b1.create_add_gate(a1, b1v, c1);
        let (proof1, _) = prover::prove(&b1, &srs);

        let mut b2 = UltraCircuitBuilder::new();
        let a2 = b2.add_variable(ArkFr::from(3u64));
        let b2v = b2.add_variable(ArkFr::from(4u64));
        let c2 = b2.add_variable(ArkFr::from(12u64));
        b2.create_mul_gate(a2, b2v, c2);
        let (_, vk2) = prover::prove(&b2, &srs);

        assert!(
            !verify(&proof1, &vk2, &[], &srs),
            "Proof from a different circuit should not verify"
        );
    }

    #[test]
    fn test_verify_prepare_valid() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (proof, vk) = prover::prove(&builder, &srs);
        let intermediates = verify_prepare(&proof, &vk, &[]);
        assert!(intermediates.is_some(), "verify_prepare should succeed for valid proof");
    }

    #[test]
    fn test_verify_prepare_invalid_returns_none() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(4u64));
        let c = builder.add_variable(ArkFr::from(7u64));
        builder.create_add_gate(a, b, c);

        let (mut proof, vk) = prover::prove(&builder, &srs);
        proof.t_eval += Fr::one();
        assert!(
            verify_prepare(&proof, &vk, &[]).is_none(),
            "verify_prepare should return None for tampered proof"
        );
    }

    #[test]
    fn test_verify_prepare_intermediates_pairing() {
        let srs = test_srs();
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(10u64));
        let b = builder.add_variable(ArkFr::from(20u64));
        let c = builder.add_variable(ArkFr::from(30u64));
        builder.create_add_gate(a, b, c);
        builder.set_public(c);

        let (proof, vk) = prover::prove(&builder, &srs);
        let pi = &[f(30)];

        let full_ok = verify(&proof, &vk, pi, &srs);
        let intermediates = verify_prepare(&proof, &vk, pi);

        assert_eq!(full_ok, intermediates.is_some(),
            "verify and verify_prepare must agree on validity");

        if let Some(inter) = intermediates {
            let zeta_g2 = srs.g2 * inter.zeta;
            let rhs_g2 = (srs.g2_tau.into_group() - zeta_g2).into_affine();
            assert!(pairing_check(inter.batch_lhs, srs.g2, inter.batch_neg_w, rhs_g2),
                "Batch pairing from intermediates should pass");

            let zw_g2 = srs.g2 * inter.zeta_omega;
            let z_rhs = (srs.g2_tau.into_group() - zw_g2).into_affine();
            assert!(pairing_check(inter.z_lhs, srs.g2, inter.z_neg_w, z_rhs),
                "z opening pairing from intermediates should pass");
        }
    }
}
