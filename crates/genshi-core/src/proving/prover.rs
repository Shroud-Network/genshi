//! genshi PLONK proof generation.
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
use ark_ff::{FftField, Field, One, Zero};
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
// Domain Utilities — Radix-2 FFT (Cooley-Tukey), O(n log n)
// ============================================================================

/// Compute a primitive n-th root of unity for BN254 scalar field.
/// n must be a power of 2.
fn compute_omega(n: usize) -> Fr {
    assert!(n.is_power_of_two(), "Domain size must be power of 2");
    let two_adic_root = Fr::TWO_ADIC_ROOT_OF_UNITY;
    let log_n = n.trailing_zeros();
    assert!(log_n <= 28, "Domain size exceeds BN254 2-adicity");
    let mut omega = two_adic_root;
    for _ in log_n..28 {
        omega = omega * omega;
    }
    debug_assert_eq!(omega.pow([n as u64]), Fr::one());
    omega
}

/// Radix-2 Cooley-Tukey FFT. O(n log n).
///
/// Evaluates polynomial (coefficient form) at all n-th roots of unity.
fn fft(coeffs: &[Fr], omega: Fr, n: usize) -> Vec<Fr> {
    assert!(n.is_power_of_two());
    let mut a = coeffs.to_vec();
    a.resize(n, Fr::zero());

    // Bit-reversal permutation
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }

    // Butterfly stages
    let mut len = 2;
    while len <= n {
        let w_len = omega.pow([(n / len) as u64]);
        let half = len / 2;
        let mut i = 0;
        while i < n {
            let mut w = Fr::one();
            for k in 0..half {
                let u = a[i + k];
                let v = a[i + k + half] * w;
                a[i + k] = u + v;
                a[i + k + half] = u - v;
                w *= w_len;
            }
            i += len;
        }
        len <<= 1;
    }
    a
}

/// Inverse FFT. O(n log n).
fn ifft(evals: &[Fr], omega: Fr, n: usize) -> Vec<Fr> {
    let omega_inv = omega.inverse().expect("omega invertible");
    let mut coeffs = fft(evals, omega_inv, n);
    let n_inv = Fr::from(n as u64).inverse().expect("n invertible");
    for c in &mut coeffs {
        *c *= n_inv;
    }
    coeffs
}

/// Evaluate polynomial on coset `{g · ω^i}`. O(n log n).
fn coset_fft(coeffs: &[Fr], omega: Fr, n: usize, g: Fr) -> Vec<Fr> {
    let mut shifted = coeffs.to_vec();
    shifted.resize(n, Fr::zero());
    let mut g_pow = Fr::one();
    for c in &mut shifted {
        *c *= g_pow;
        g_pow *= g;
    }
    fft(&shifted, omega, n)
}

/// Recover coefficients from evaluations on coset `{g · ω^i}`. O(n log n).
fn coset_ifft(evals: &[Fr], omega: Fr, n: usize, g: Fr) -> Vec<Fr> {
    let mut coeffs = ifft(evals, omega, n);
    let g_inv = g.inverse().expect("coset offset invertible");
    let mut g_pow = Fr::one();
    for c in &mut coeffs {
        *c *= g_pow;
        g_pow *= g_inv;
    }
    coeffs
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
    // Gate equation at PI rows: q_1·w_1 + PI(X) = 0
    // PI(X) is computed by the verifier as -Σ pi_i·L_i(X)
    // So the gate becomes: w_1 - pi_value = 0 (verified by constraint check)
    for (row, &pi_wire) in builder.get_public_inputs().iter().enumerate() {
        let pi_val = builder.get_variable(pi_wire);
        wire_evals[0][row] = pi_val;
        q_1_evals[row] = Fr::one();
        // q_c stays 0 — PI contribution added by verifier
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

/// Extract just the verification key for a circuit shape.
///
/// Runs the same preprocessing pipeline as [`prove`] but discards the
/// witness-dependent proving data. Used by [`crate::proving::api::extract_vk`]
/// to derive the VK at setup time before any real witnesses exist.
pub fn extract_vk_from_builder(
    builder: &UltraCircuitBuilder,
    srs: &SRS,
) -> VerificationKey {
    let (_pd, vk) = preprocess(builder, srs);
    vk
}

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

    let mut transcript = Transcript::new(b"genshi_plonk");
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
        kzg::evaluate_poly(&pd.sigmas[3], zeta),
    ];

    let z_eval = kzg::evaluate_poly(&z_coeffs, zeta);
    let z_omega_eval = kzg::evaluate_poly(&z_coeffs, zeta_omega);

    let selector_evals = [
        kzg::evaluate_poly(&pd.q_m, zeta),
        kzg::evaluate_poly(&pd.q_1, zeta),
        kzg::evaluate_poly(&pd.q_2, zeta),
        kzg::evaluate_poly(&pd.q_3, zeta),
        kzg::evaluate_poly(&pd.q_4, zeta),
        kzg::evaluate_poly(&pd.q_c, zeta),
        kzg::evaluate_poly(&pd.q_arith, zeta),
    ];

    // Compute t(ζ) = Σ t_i(ζ) · ζ^(i·n)
    let n = pd.domain_size;
    let zeta_n = zeta.pow([n as u64]);
    let mut t_eval = Fr::zero();
    let mut zeta_pow = Fr::one();
    for part in &t_parts {
        t_eval += kzg::evaluate_poly(part, zeta) * zeta_pow;
        zeta_pow *= zeta_n;
    }

    // Absorb evaluations
    for e in &w_evals {
        transcript.absorb_scalar(b"we", e);
    }
    for e in &sigma_evals {
        transcript.absorb_scalar(b"se", e);
    }
    transcript.absorb_scalar(b"ze", &z_eval);
    transcript.absorb_scalar(b"zw", &z_omega_eval);
    for e in &selector_evals {
        transcript.absorb_scalar(b"qe", e);
    }
    transcript.absorb_scalar(b"te", &t_eval);

    // ================================================================
    // Round 5: Opening proofs
    // ================================================================
    let nu = transcript.squeeze_challenge(b"nu");

    // Collect all polynomials to open at ζ
    let polys_at_zeta: Vec<&[Fr]> = vec![
        &w_coeffs[0], &w_coeffs[1], &w_coeffs[2], &w_coeffs[3],
        &pd.sigmas[0], &pd.sigmas[1], &pd.sigmas[2], &pd.sigmas[3],
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
        z_eval,
        z_omega_eval,
        selector_evals,
        t_eval,
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
/// Uses coset FFT for O(n log n) performance:
/// 1. Evaluate all polynomials on a 4n coset via coset_fft
/// 2. Compute numerator in evaluation form (element-wise)
/// 3. Divide by Z_H pointwise
/// 4. Recover t(X) via coset_ifft
fn compute_quotient(
    w_coeffs: &[Vec<Fr>; 4],
    pd: &ProvingData,
    z_coeffs: &[Fr],
    _z_evals: &[Fr],
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    omega: Fr,
    n: usize,
) -> Vec<Fr> {
    let alpha_sq = alpha * alpha;
    let big_n = 4 * n;
    let big_omega = compute_omega(big_n);
    let g = Fr::from(3u64); // coset offset (non-root-of-unity)

    // Step 1: Evaluate all polynomials on the 4n coset via coset_fft
    let w1_c = coset_fft(&w_coeffs[0], big_omega, big_n, g);
    let w2_c = coset_fft(&w_coeffs[1], big_omega, big_n, g);
    let w3_c = coset_fft(&w_coeffs[2], big_omega, big_n, g);
    let w4_c = coset_fft(&w_coeffs[3], big_omega, big_n, g);

    let qm_c = coset_fft(&pd.q_m, big_omega, big_n, g);
    let q1_c = coset_fft(&pd.q_1, big_omega, big_n, g);
    let q2_c = coset_fft(&pd.q_2, big_omega, big_n, g);
    let q3_c = coset_fft(&pd.q_3, big_omega, big_n, g);
    let q4_c = coset_fft(&pd.q_4, big_omega, big_n, g);
    let qc_c = coset_fft(&pd.q_c, big_omega, big_n, g);
    let qa_c = coset_fft(&pd.q_arith, big_omega, big_n, g);

    let z_c = coset_fft(z_coeffs, big_omega, big_n, g);

    let s1_c = coset_fft(&pd.sigmas[0], big_omega, big_n, g);
    let s2_c = coset_fft(&pd.sigmas[1], big_omega, big_n, g);
    let s3_c = coset_fft(&pd.sigmas[2], big_omega, big_n, g);
    let s4_c = coset_fft(&pd.sigmas[3], big_omega, big_n, g);

    // z(ω·x) on the coset: since ω = big_omega^4, evaluating z at
    // g·big_omega^(i+4) = rotating the coset evaluations by 4
    let mut z_omega_c = vec![Fr::zero(); big_n];
    for i in 0..big_n {
        z_omega_c[i] = z_c[(i + 4) % big_n];
    }

    // PI(X) = -Σ pi_val_i · L_i(X): build via iFFT then coset_fft
    let mut pi_domain_evals = vec![Fr::zero(); n];
    for i in 0..pd.num_public_inputs {
        pi_domain_evals[i] = -pd.wire_evals[0][i];
    }
    let pi_coeffs = ifft(&pi_domain_evals, omega, n);
    let pi_c = coset_fft(&pi_coeffs, big_omega, big_n, g);

    // L_1(X) = (X^n - 1) / (n · (X - 1)): build from its domain evals
    // L_1(ω^i) = 1 if i=0, else 0
    let mut l1_domain_evals = vec![Fr::zero(); n];
    l1_domain_evals[0] = Fr::one();
    let l1_coeffs = ifft(&l1_domain_evals, omega, n);
    let l1_c = coset_fft(&l1_coeffs, big_omega, big_n, g);

    // Precompute coset x-values: x_i = g · big_omega^i
    // and Z_H(x_i) = x_i^n - 1
    // Also need x_i for the permutation numerator: β·k_j·x
    let mut x_c = vec![Fr::zero(); big_n];
    let mut zh_c = vec![Fr::zero(); big_n];
    {
        let mut x_val = g; // g · big_omega^0 = g
        for i in 0..big_n {
            x_c[i] = x_val;
            zh_c[i] = x_val.pow([n as u64]) - Fr::one();
            x_val *= big_omega;
        }
    }

    // Step 2: Compute quotient in evaluation form
    let k = &pd.k;
    let mut t_evals = vec![Fr::zero(); big_n];
    for i in 0..big_n {
        let x = x_c[i];

        // Gate identity
        let gate = qa_c[i]
            * (qm_c[i] * w1_c[i] * w2_c[i]
                + q1_c[i] * w1_c[i]
                + q2_c[i] * w2_c[i]
                + q3_c[i] * w3_c[i]
                + q4_c[i] * w4_c[i]
                + qc_c[i])
            + pi_c[i];

        // Permutation identity
        let perm_num = z_c[i]
            * (w1_c[i] + beta * k[0] * x + gamma)
            * (w2_c[i] + beta * k[1] * x + gamma)
            * (w3_c[i] + beta * k[2] * x + gamma)
            * (w4_c[i] + beta * k[3] * x + gamma);

        let perm_den = z_omega_c[i]
            * (w1_c[i] + beta * s1_c[i] + gamma)
            * (w2_c[i] + beta * s2_c[i] + gamma)
            * (w3_c[i] + beta * s3_c[i] + gamma)
            * (w4_c[i] + beta * s4_c[i] + gamma);

        // Boundary
        let boundary = l1_c[i] * (z_c[i] - Fr::one());

        let numerator = gate + alpha * (perm_num - perm_den) + alpha_sq * boundary;
        t_evals[i] = numerator * zh_c[i].inverse().expect("Z_H non-zero on coset");
    }

    // Step 3: Recover t(X) in coefficient form via coset iFFT
    let mut t_coeffs = coset_ifft(&t_evals, big_omega, big_n, g);

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
    use ark_ec::AffineRepr;

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
