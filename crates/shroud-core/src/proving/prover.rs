//! UltraHonk proof generation.
//!
//! Implements a PLONK-style proving system with 4 wire columns and
//! KZG polynomial commitments over BN254.
//!
//! # Protocol Rounds
//!
//! 1. Commit to wire polynomials w₁, w₂, w₃, w₄
//! 2. Compute permutation grand product z(X), commit
//! 3. Compute quotient polynomial t(X), split and commit
//! 4. Evaluate polynomials at challenge ζ
//! 5. Compute opening proofs at ζ and ζω
//!
//! Cross-verify against TaceoLabs/Barretenberg reference (Risk R1 mitigation).

use ark_bn254::{Fr, G1Affine};
use ark_ff::{FftField, Field, One, Zero, PrimeField};
use alloc::vec;
use alloc::vec::Vec;

use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use super::kzg;
use super::srs::SRS;
use super::transcript::Transcript;

// ============================================================================
// Coset generators for permutation argument
// ============================================================================

/// Coset generators k₀, k₁, k₂, k₃ for the 4-wire permutation argument.
/// These must generate disjoint cosets of the evaluation domain H.
/// k₀ = 1 (identity coset), k₁..k₃ chosen as small non-roots-of-unity.
fn coset_generators() -> [Fr; 4] {
    [
        Fr::one(),
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(7u64),
    ]
}

// ============================================================================
// Data Structures
// ============================================================================

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
    pub sigma_evals: [Fr; 3], // σ₁(ζ), σ₂(ζ), σ₃(ζ) (σ₄ not needed)
    pub z_omega_eval: Fr,     // z(ζω)

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

/// Computed during preprocessing: full polynomial data for prover.
struct ProvingData {
    // Selector polynomials (coefficient form)
    q_m: Vec<Fr>,
    q_1: Vec<Fr>,
    q_2: Vec<Fr>,
    q_3: Vec<Fr>,
    q_4: Vec<Fr>,
    q_c: Vec<Fr>,
    q_arith: Vec<Fr>,

    // Permutation polynomials (coefficient form)
    sigmas: [Vec<Fr>; 4],

    // Wire evaluations on the domain (evaluation form)
    wire_evals: [Vec<Fr>; 4],

    // Domain parameters
    domain_size: usize,
    omega: Fr,
    k: [Fr; 4],

    num_public_inputs: usize,
}

// ============================================================================
// Domain Utilities (minimal NTT-free for correctness)
// ============================================================================

/// Compute the n-th roots of unity: [1, ω, ω², ..., ω^(n-1)].
fn roots_of_unity(n: usize) -> Vec<Fr> {
    let omega = compute_omega(n);
    let mut roots = Vec::with_capacity(n);
    let mut w = Fr::one();
    for _ in 0..n {
        roots.push(w);
        w *= omega;
    }
    roots
}

/// Compute a primitive n-th root of unity for BN254 scalar field.
/// n must be a power of 2.
fn compute_omega(n: usize) -> Fr {
    assert!(n.is_power_of_two(), "Domain size must be power of 2");
    // BN254 Fr supports 2-adicity of 28 (2^28 | r-1).
    // Get the 2^28-th root of unity and square down.
    let two_adic_root = Fr::TWO_ADIC_ROOT_OF_UNITY;
    let log_n = n.trailing_zeros();
    assert!(log_n <= 28, "Domain size exceeds BN254 2-adicity");
    let mut omega = two_adic_root;
    for _ in log_n..28 {
        omega = omega * omega;
    }
    // Verify: ω^n = 1
    debug_assert_eq!(omega.pow([n as u64]), Fr::one());
    omega
}

/// Interpolate: given evaluations at roots of unity, compute coefficients.
/// This is a simple O(n²) iFFT for correctness.
fn ifft(evals: &[Fr], omega: Fr, n: usize) -> Vec<Fr> {
    let omega_inv = omega.inverse().expect("omega must be invertible");
    let n_inv = Fr::from(n as u64).inverse().expect("n must be invertible");

    let mut coeffs = vec![Fr::zero(); n];
    for j in 0..n {
        let mut sum = Fr::zero();
        let mut omega_inv_pow = Fr::one(); // ω^(-ij)
        for i in 0..n {
            sum += evals[i] * omega_inv_pow;
            omega_inv_pow *= omega_inv.pow([j as u64]);
        }
        coeffs[j] = sum * n_inv;
    }

    // Fix: use the standard DFT formula
    let mut coeffs2 = vec![Fr::zero(); n];
    for j in 0..n {
        let mut sum = Fr::zero();
        let mut w = Fr::one();
        let omega_inv_j = omega_inv.pow([j as u64]);
        for i in 0..n {
            sum += evals[i] * w;
            w *= omega_inv_j;
        }
        coeffs2[j] = sum * n_inv;
    }
    coeffs2
}

/// Evaluate polynomial (coefficient form) at all roots of unity.
/// O(n²) DFT for correctness.
fn fft(coeffs: &[Fr], omega: Fr, n: usize) -> Vec<Fr> {
    let mut padded = coeffs.to_vec();
    padded.resize(n, Fr::zero());

    let mut evals = vec![Fr::zero(); n];
    for i in 0..n {
        let x = omega.pow([i as u64]);
        evals[i] = kzg::evaluate_poly(&padded, x);
    }
    evals
}

/// Compute the i-th Lagrange basis polynomial evaluated at x:
/// L_i(x) = ω^i/n · (x^n - 1) / (x - ω^i)
fn lagrange_eval(i: usize, x: Fr, omega: Fr, n: usize) -> Fr {
    let omega_i = omega.pow([i as u64]);
    let x_n = x.pow([n as u64]);

    if (x - omega_i).is_zero() {
        return Fr::one();
    }

    let n_fr = Fr::from(n as u64);
    omega_i * (x_n - Fr::one()) / (n_fr * (x - omega_i))
}

// ============================================================================
// Preprocessing
// ============================================================================

/// Preprocess a circuit into proving data and verification key.
fn preprocess(
    builder: &UltraCircuitBuilder,
    srs: &SRS,
) -> (ProvingData, VerificationKey) {
    let num_public = builder.get_public_inputs().len();
    let num_gates = builder.num_gates();
    let total = num_public + num_gates;

    // Pad to next power of 2 (minimum 4 for safety)
    let n = total.next_power_of_two().max(4);
    let omega = compute_omega(n);
    let k = coset_generators();

    // Build execution trace
    let mut wire_evals: [Vec<Fr>; 4] = [
        vec![Fr::zero(); n],
        vec![Fr::zero(); n],
        vec![Fr::zero(); n],
        vec![Fr::zero(); n],
    ];
    let mut q_m_evals = vec![Fr::zero(); n];
    let mut q_1_evals = vec![Fr::zero(); n];
    let mut q_2_evals = vec![Fr::zero(); n];
    let mut q_3_evals = vec![Fr::zero(); n];
    let mut q_4_evals = vec![Fr::zero(); n];
    let mut q_c_evals = vec![Fr::zero(); n];
    let mut q_arith_evals = vec![Fr::zero(); n];

    // Track wire->variable mapping for permutation
    let mut wire_var_ids: Vec<[u32; 4]> = vec![[0; 4]; n];

    // Fill public input rows (rows 0..num_public)
    // Each PI row: q_1 = 1, w_1 = PI value, everything else 0
    // Gate equation: 1·w_1 + q_c = 0, so q_c = -PI value
    for (row, &pi_wire) in builder.get_public_inputs().iter().enumerate() {
        let pi_val = builder.get_variable(pi_wire);
        wire_evals[0][row] = pi_val;
        q_1_evals[row] = Fr::one();
        q_c_evals[row] = -pi_val;
        q_arith_evals[row] = Fr::one();
        wire_var_ids[row][0] = pi_wire.0;
    }

    // Fill circuit gate rows (rows num_public..num_public+num_gates)
    let gates = builder.get_gates();
    for (gi, gate) in gates.iter().enumerate() {
        let row = num_public + gi;
        for col in 0..4 {
            wire_evals[col][row] = builder.get_variable(gate.wires[col]);
            wire_var_ids[row][col] = gate.wires[col].0;
        }
        q_m_evals[row] = gate.q_m;
        q_1_evals[row] = gate.q_1;
        q_2_evals[row] = gate.q_2;
        q_3_evals[row] = gate.q_3;
        q_4_evals[row] = gate.q_4;
        q_c_evals[row] = gate.q_c;
        q_arith_evals[row] = gate.q_arith;
    }

    // Build permutation polynomials
    let sigmas_evals = build_permutation(&wire_var_ids, n, omega, &k);

    // Convert all to coefficient form via iFFT
    let q_m = ifft(&q_m_evals, omega, n);
    let q_1 = ifft(&q_1_evals, omega, n);
    let q_2 = ifft(&q_2_evals, omega, n);
    let q_3 = ifft(&q_3_evals, omega, n);
    let q_4 = ifft(&q_4_evals, omega, n);
    let q_c = ifft(&q_c_evals, omega, n);
    let q_arith = ifft(&q_arith_evals, omega, n);

    let sigmas: [Vec<Fr>; 4] = [
        ifft(&sigmas_evals[0], omega, n),
        ifft(&sigmas_evals[1], omega, n),
        ifft(&sigmas_evals[2], omega, n),
        ifft(&sigmas_evals[3], omega, n),
    ];

    // Commit to preprocessed polynomials
    let vk = VerificationKey {
        q_m_comm: kzg::commit(&q_m, srs),
        q_1_comm: kzg::commit(&q_1, srs),
        q_2_comm: kzg::commit(&q_2, srs),
        q_3_comm: kzg::commit(&q_3, srs),
        q_4_comm: kzg::commit(&q_4, srs),
        q_c_comm: kzg::commit(&q_c, srs),
        q_arith_comm: kzg::commit(&q_arith, srs),
        sigma_comms: [
            kzg::commit(&sigmas[0], srs),
            kzg::commit(&sigmas[1], srs),
            kzg::commit(&sigmas[2], srs),
            kzg::commit(&sigmas[3], srs),
        ],
        domain_size: n,
        num_public_inputs: num_public,
        omega,
        k,
    };

    let pd = ProvingData {
        q_m, q_1, q_2, q_3, q_4, q_c, q_arith,
        sigmas,
        wire_evals,
        domain_size: n,
        omega, k,
        num_public_inputs: num_public,
    };

    (pd, vk)
}

/// Build permutation polynomials from wire-variable assignments.
///
/// For each variable, all positions referencing it form a cycle.
/// The permutation maps each position to the next in the cycle.
fn build_permutation(
    wire_var_ids: &[[u32; 4]],
    n: usize,
    omega: Fr,
    k: &[Fr; 4],
) -> [Vec<Fr>; 4] {
    use alloc::collections::BTreeMap;

    // Initialize with identity permutation
    let mut sigma_evals: [Vec<Fr>; 4] = [
        vec![Fr::zero(); n],
        vec![Fr::zero(); n],
        vec![Fr::zero(); n],
        vec![Fr::zero(); n],
    ];

    for i in 0..n {
        let omega_i = omega.pow([i as u64]);
        for j in 0..4 {
            sigma_evals[j][i] = omega_i * k[j];
        }
    }

    // Build variable → positions map
    let mut var_positions: BTreeMap<u32, Vec<(usize, usize)>> = BTreeMap::new();
    for i in 0..n {
        for j in 0..4 {
            var_positions
                .entry(wire_var_ids[i][j])
                .or_default()
                .push((j, i));
        }
    }

    // Create cycles
    for (_, positions) in &var_positions {
        if positions.len() <= 1 {
            continue;
        }
        for idx in 0..positions.len() {
            let next = (idx + 1) % positions.len();
            let (cur_col, cur_row) = positions[idx];
            let (next_col, next_row) = positions[next];
            sigma_evals[cur_col][cur_row] =
                omega.pow([next_row as u64]) * k[next_col];
        }
    }

    sigma_evals
}

// ============================================================================
// Prover
// ============================================================================

/// Generate a PLONK proof for a satisfied circuit.
///
/// # Panics
/// Panics if the circuit is not satisfied (call `check_circuit_correctness()` first).
pub fn prove(builder: &UltraCircuitBuilder, srs: &SRS) -> (Proof, VerificationKey) {
    debug_assert!(
        builder.check_circuit_correctness(),
        "Circuit must be satisfied before proving"
    );

    let (pd, vk) = preprocess(builder, srs);
    let n = pd.domain_size;
    let omega = pd.omega;

    // ================================================================
    // Round 1: Wire polynomial commitments
    // ================================================================
    let w_coeffs: [Vec<Fr>; 4] = [
        ifft(&pd.wire_evals[0], omega, n),
        ifft(&pd.wire_evals[1], omega, n),
        ifft(&pd.wire_evals[2], omega, n),
        ifft(&pd.wire_evals[3], omega, n),
    ];

    let w_comms = [
        kzg::commit(&w_coeffs[0], srs),
        kzg::commit(&w_coeffs[1], srs),
        kzg::commit(&w_coeffs[2], srs),
        kzg::commit(&w_coeffs[3], srs),
    ];

    let mut transcript = Transcript::new(b"shroud_ultrahonk");
    for c in &w_comms {
        transcript.absorb_point(b"w", c);
    }

    // ================================================================
    // Round 2: Permutation grand product z(X)
    // ================================================================
    let beta = transcript.squeeze_challenge(b"beta");
    let gamma = transcript.squeeze_challenge(b"gamma");

    let z_evals = compute_grand_product(
        &pd.wire_evals, &pd.sigmas, omega, n, &pd.k, beta, gamma,
    );
    let z_coeffs = ifft(&z_evals, omega, n);
    let z_comm = kzg::commit(&z_coeffs, srs);

    transcript.absorb_point(b"z", &z_comm);

    // ================================================================
    // Round 3: Quotient polynomial t(X)
    // ================================================================
    let alpha = transcript.squeeze_challenge(b"alpha");

    let t_coeffs = compute_quotient(
        &w_coeffs, &pd, &z_coeffs, &z_evals,
        alpha, beta, gamma, omega, n,
    );

    // Split quotient into degree < n parts
    let num_parts = (t_coeffs.len() + n - 1) / n;
    let mut t_parts: Vec<Vec<Fr>> = Vec::new();
    for i in 0..num_parts {
        let start = i * n;
        let end = ((i + 1) * n).min(t_coeffs.len());
        let mut part = t_coeffs[start..end].to_vec();
        part.resize(n, Fr::zero());
        t_parts.push(part);
    }
    // Ensure we have at least 3 parts
    while t_parts.len() < 3 {
        t_parts.push(vec![Fr::zero(); n]);
    }

    let t_comms: Vec<G1Affine> = t_parts.iter().map(|p| kzg::commit(p, srs)).collect();
    for c in &t_comms {
        transcript.absorb_point(b"t", c);
    }

    // ================================================================
    // Round 4: Evaluations at challenge ζ
    // ================================================================
    let zeta = transcript.squeeze_challenge(b"zeta");
    let zeta_omega = zeta * omega;

    let w_evals = [
        kzg::evaluate_poly(&w_coeffs[0], zeta),
        kzg::evaluate_poly(&w_coeffs[1], zeta),
        kzg::evaluate_poly(&w_coeffs[2], zeta),
        kzg::evaluate_poly(&w_coeffs[3], zeta),
    ];

    let sigma_evals = [
        kzg::evaluate_poly(&pd.sigmas[0], zeta),
        kzg::evaluate_poly(&pd.sigmas[1], zeta),
        kzg::evaluate_poly(&pd.sigmas[2], zeta),
    ];

    let z_omega_eval = kzg::evaluate_poly(&z_coeffs, zeta_omega);

    // Absorb evaluations
    for e in &w_evals {
        transcript.absorb_scalar(b"we", e);
    }
    for e in &sigma_evals {
        transcript.absorb_scalar(b"se", e);
    }
    transcript.absorb_scalar(b"zw", &z_omega_eval);

    // ================================================================
    // Round 5: Opening proofs
    // ================================================================
    let nu = transcript.squeeze_challenge(b"nu");

    // Collect all polynomials to open at ζ
    let polys_at_zeta: Vec<&[Fr]> = vec![
        &w_coeffs[0], &w_coeffs[1], &w_coeffs[2], &w_coeffs[3],
        &pd.sigmas[0], &pd.sigmas[1], &pd.sigmas[2],
        &pd.q_m, &pd.q_1, &pd.q_2, &pd.q_3, &pd.q_4, &pd.q_c, &pd.q_arith,
        &z_coeffs,
    ];

    let (_, w_zeta) = kzg::batch_open(&polys_at_zeta, zeta, nu, srs);

    // Open z at ζω
    let z_opening = kzg::open(&z_coeffs, zeta_omega, srs);
    let w_zeta_omega = z_opening.witness;

    let proof = Proof {
        w_comms,
        z_comm,
        t_comms,
        w_evals,
        sigma_evals,
        z_omega_eval,
        w_zeta,
        w_zeta_omega,
    };

    (proof, vk)
}

/// Compute the permutation grand product z evaluations.
///
/// z(1) = 1
/// z(ω^{i+1}) = z(ω^i) · ∏_j (w_j(ω^i) + β·ω^i·k_j + γ) / (w_j(ω^i) + β·σ_j(ω^i) + γ)
fn compute_grand_product(
    wire_evals: &[Vec<Fr>; 4],
    sigma_coeffs: &[Vec<Fr>; 4],
    omega: Fr,
    n: usize,
    k: &[Fr; 4],
    beta: Fr,
    gamma: Fr,
) -> Vec<Fr> {
    // Evaluate σ on the domain
    let sigma_evals: [Vec<Fr>; 4] = [
        fft(&sigma_coeffs[0], omega, n),
        fft(&sigma_coeffs[1], omega, n),
        fft(&sigma_coeffs[2], omega, n),
        fft(&sigma_coeffs[3], omega, n),
    ];

    let mut z = vec![Fr::zero(); n];
    z[0] = Fr::one();

    for i in 0..n - 1 {
        let omega_i = omega.pow([i as u64]);
        let mut num = Fr::one();
        let mut den = Fr::one();

        for j in 0..4 {
            num *= wire_evals[j][i] + beta * omega_i * k[j] + gamma;
            den *= wire_evals[j][i] + beta * sigma_evals[j][i] + gamma;
        }

        z[i + 1] = z[i] * num * den.inverse().expect("denominator must be non-zero");
    }

    // Verify: z(ω^{n-1}) should complete the cycle → z times last ratio should = 1
    // This is equivalent to the permutation being correctly constructed
    z
}

/// Compute the quotient polynomial t(X) = numerator(X) / Z_H(X).
///
/// numerator = gate_identity + α·perm_identity + α²·boundary_identity
fn compute_quotient(
    w_coeffs: &[Vec<Fr>; 4],
    pd: &ProvingData,
    z_coeffs: &[Fr],
    z_evals: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    omega: Fr,
    n: usize,
) -> Vec<Fr> {
    let alpha_sq = alpha * alpha;

    // We'll compute the numerator at 4n evaluation points (a coset)
    // to handle degree overflow, then divide by Z_H.
    let big_n = 4 * n;
    let big_omega = compute_omega(big_n);
    // Use a coset offset
    let coset_offset = Fr::from(3u64); // arbitrary non-root-of-unity

    // Evaluate all polynomials at coset points: {offset · big_ω^i}
    let mut numerator_evals = vec![Fr::zero(); big_n];

    for i in 0..big_n {
        let x = coset_offset * big_omega.pow([i as u64]);
        let x_n = x.pow([n as u64]);
        let zh = x_n - Fr::one(); // Z_H(x)

        // Evaluate all base polynomials at x
        let w1 = kzg::evaluate_poly(&w_coeffs[0], x);
        let w2 = kzg::evaluate_poly(&w_coeffs[1], x);
        let w3 = kzg::evaluate_poly(&w_coeffs[2], x);
        let w4 = kzg::evaluate_poly(&w_coeffs[3], x);

        let qm = kzg::evaluate_poly(&pd.q_m, x);
        let q1 = kzg::evaluate_poly(&pd.q_1, x);
        let q2 = kzg::evaluate_poly(&pd.q_2, x);
        let q3 = kzg::evaluate_poly(&pd.q_3, x);
        let q4 = kzg::evaluate_poly(&pd.q_4, x);
        let qc = kzg::evaluate_poly(&pd.q_c, x);
        let qa = kzg::evaluate_poly(&pd.q_arith, x);

        let z_x = kzg::evaluate_poly(z_coeffs, x);
        let z_wx = kzg::evaluate_poly(z_coeffs, x * omega);

        let s1 = kzg::evaluate_poly(&pd.sigmas[0], x);
        let s2 = kzg::evaluate_poly(&pd.sigmas[1], x);
        let s3 = kzg::evaluate_poly(&pd.sigmas[2], x);
        let s4 = kzg::evaluate_poly(&pd.sigmas[3], x);

        // Public input polynomial PI(x) - handled via q_c in preprocessing
        // (PI values are baked into q_c for public input rows)

        // Gate identity
        let gate = qa * (qm * w1 * w2 + q1 * w1 + q2 * w2 + q3 * w3 + q4 * w4 + qc);

        // Permutation identity
        let k = &pd.k;
        let perm_num =
            z_x * (w1 + beta * k[0] * x + gamma)
                * (w2 + beta * k[1] * x + gamma)
                * (w3 + beta * k[2] * x + gamma)
                * (w4 + beta * k[3] * x + gamma);

        let perm_den =
            z_wx * (w1 + beta * s1 + gamma)
                * (w2 + beta * s2 + gamma)
                * (w3 + beta * s3 + gamma)
                * (w4 + beta * s4 + gamma);

        let perm = perm_num - perm_den;

        // Boundary: L₁(x) · (z(x) - 1)
        let l1 = lagrange_eval(0, x, omega, n);
        let boundary = l1 * (z_x - Fr::one());

        // Full numerator
        let num_x = gate + alpha * perm + alpha_sq * boundary;

        // Quotient at this point
        numerator_evals[i] = num_x * zh.inverse().expect("Z_H should not vanish on coset");
    }

    // iFFT the quotient evaluations from the coset back to coefficient form
    // t(coset_offset · big_ω^i) = numerator_evals[i]
    // So t(X) can be recovered by shifting: let Y = X/coset_offset,
    // t(coset_offset · Y) evaluated at Y = big_ω^i
    // This means: t'(Y) = t(coset_offset·Y), and t'_coeffs from iFFT,
    // then t_coeffs[j] = t'_coeffs[j] / coset_offset^j

    let t_shifted = ifft(&numerator_evals, big_omega, big_n);

    let mut t_coeffs = vec![Fr::zero(); big_n];
    let coset_inv = coset_offset.inverse().expect("coset offset invertible");
    let mut coset_pow = Fr::one();
    for j in 0..big_n {
        t_coeffs[j] = t_shifted[j] * coset_pow;
        coset_pow *= coset_inv;
    }

    // Trim trailing zeros
    while t_coeffs.last() == Some(&Fr::zero()) && t_coeffs.len() > 1 {
        t_coeffs.pop();
    }

    t_coeffs
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;

    #[test]
    fn test_compute_omega() {
        let n = 8;
        let omega = compute_omega(n);
        assert_eq!(omega.pow([n as u64]), Fr::one(), "ω^n must be 1");
        assert_ne!(omega.pow([(n / 2) as u64]), Fr::one(), "ω^(n/2) must not be 1");
    }

    #[test]
    fn test_fft_ifft_roundtrip() {
        let n = 4;
        let omega = compute_omega(n);
        let coeffs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let evals = fft(&coeffs, omega, n);
        let recovered = ifft(&evals, omega, n);
        for i in 0..n {
            assert_eq!(coeffs[i], recovered[i], "FFT/iFFT roundtrip failed at {}", i);
        }
    }

    #[test]
    fn test_prove_trivial_circuit() {
        let srs = SRS::insecure_for_testing(128);
        let mut builder = UltraCircuitBuilder::new();

        // Simple circuit: a + b = c
        let a = builder.add_variable(Fr::from(3u64));
        let b = builder.add_variable(Fr::from(4u64));
        let c = builder.add_variable(Fr::from(7u64));
        builder.create_add_gate(a, b, c);

        assert!(builder.check_circuit_correctness());
        let (proof, vk) = prove(&builder, &srs);

        // Basic sanity checks on proof structure
        assert!(!proof.w_comms[0].is_zero());
        assert_eq!(vk.domain_size.count_ones(), 1); // power of 2
    }

    #[test]
    fn test_prove_with_public_inputs() {
        let srs = SRS::insecure_for_testing(128);
        let mut builder = UltraCircuitBuilder::new();

        let a = builder.add_variable(Fr::from(10u64));
        let b = builder.add_variable(Fr::from(20u64));
        let c = builder.add_variable(Fr::from(30u64));
        builder.create_add_gate(a, b, c);
        builder.set_public(c);

        assert!(builder.check_circuit_correctness());
        let (proof, vk) = prove(&builder, &srs);
        assert_eq!(vk.num_public_inputs, 1);
        assert!(!proof.z_comm.is_zero());
    }
}
