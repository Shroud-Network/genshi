//! KZG polynomial commitment scheme over BN254.
//!
//! Provides commit, open, and verify operations using the BN254 pairing.
//! Used by the UltraHonk prover/verifier for polynomial commitments.
//!
//! **Verification equation**:
//! ```text
//! e(C - v·G₁, G₂) == e(π, τ·G₂ - z·G₂)
//! ```
//! Rearranged as multi-pairing check:
//! ```text
//! e(C - v·G₁, G₂) · e(-π, τ·G₂ - z·G₂) == 1
//! ```

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{One, Zero};
use alloc::vec;
use alloc::vec::Vec;

use super::srs::SRS;

/// Result of opening a polynomial commitment at a point.
#[derive(Clone, Debug)]
pub struct KZGOpening {
    /// The evaluation p(z).
    pub evaluation: Fr,
    /// The witness commitment: [q(τ)]₁ where q(X) = (p(X) - p(z)) / (X - z).
    pub witness: G1Affine,
}

// ============================================================================
// Core Operations
// ============================================================================

/// Commit to a polynomial given its coefficients.
///
/// Computes `C = Σ coeffs[i] · [τ^i]₁` via multi-scalar multiplication.
///
/// # Panics
/// Panics if the polynomial degree exceeds the SRS capacity.
pub fn commit(coeffs: &[Fr], srs: &SRS) -> G1Affine {
    if coeffs.is_empty() {
        return G1Affine::zero();
    }
    assert!(
        coeffs.len() <= srs.size(),
        "Polynomial degree {} exceeds SRS capacity {}",
        coeffs.len() - 1,
        srs.max_degree()
    );
    G1Projective::msm(&srs.g1_powers[..coeffs.len()], coeffs)
        .expect("MSM should not fail")
        .into_affine()
}

/// Evaluate a polynomial (in coefficient form) at point `z`.
///
/// Uses Horner's method: `p(z) = c₀ + z·(c₁ + z·(c₂ + ...))`
pub fn evaluate_poly(coeffs: &[Fr], z: Fr) -> Fr {
    if coeffs.is_empty() {
        return Fr::zero();
    }
    let mut result = Fr::zero();
    for c in coeffs.iter().rev() {
        result = result * z + c;
    }
    result
}

/// Open a polynomial commitment at point `z`.
///
/// Computes the witness polynomial `q(X) = (p(X) - p(z)) / (X - z)`
/// and returns `(p(z), [q(τ)]₁)`.
pub fn open(coeffs: &[Fr], z: Fr, srs: &SRS) -> KZGOpening {
    let evaluation = evaluate_poly(coeffs, z);
    let quotient = compute_quotient_poly(coeffs, z, evaluation);
    let witness = commit(&quotient, srs);
    KZGOpening { evaluation, witness }
}

/// Verify a KZG opening proof.
///
/// Checks: `e(C - v·G₁, G₂) · e(-π, τ·G₂ - z·G₂) == 1`
///
/// Where C = commitment, v = claimed evaluation, π = witness,
/// z = evaluation point.
pub fn verify(
    commitment: G1Affine,
    z: Fr,
    evaluation: Fr,
    witness: G1Affine,
    srs: &SRS,
) -> bool {
    // LHS of pairing: C - v·G₁
    let v_g1 = G1Affine::generator() * evaluation;
    let lhs_g1 = (commitment.into_group() - v_g1).into_affine();

    // RHS G2 element: τ·G₂ - z·G₂
    let z_g2 = srs.g2 * z;
    let rhs_g2 = (srs.g2_tau.into_group() - z_g2).into_affine();

    // Multi-pairing check: e(lhs, G₂) · e(-π, rhs_g2) == 1
    let neg_witness = (-witness.into_group()).into_affine();
    Bn254::multi_pairing(
        [lhs_g1, neg_witness],
        [srs.g2, rhs_g2],
    )
    .is_zero()
}

/// Batch open multiple polynomials at the same point `z`.
///
/// Uses random linear combination with powers of `nu` to batch
/// multiple opening proofs into one.
///
/// Returns evaluations and a single batched witness.
pub fn batch_open(
    polys: &[&[Fr]],
    z: Fr,
    nu: Fr,
    srs: &SRS,
) -> (Vec<Fr>, G1Affine) {
    let mut evaluations = Vec::with_capacity(polys.len());
    let mut combined_quotient = Vec::new();
    let mut nu_power = Fr::one();

    for poly in polys {
        let eval = evaluate_poly(poly, z);
        evaluations.push(eval);

        let q = compute_quotient_poly(poly, z, eval);
        // Accumulate: combined += nu^i · q_i
        if combined_quotient.is_empty() {
            combined_quotient = q.iter().map(|&c| c * nu_power).collect();
        } else {
            let max_len = combined_quotient.len().max(q.len());
            combined_quotient.resize(max_len, Fr::zero());
            for (j, &c) in q.iter().enumerate() {
                combined_quotient[j] += c * nu_power;
            }
        }
        nu_power *= nu;
    }

    let witness = commit(&combined_quotient, srs);
    (evaluations, witness)
}

/// Batch verify: verify a batched opening proof.
///
/// Checks that the batch witness is consistent with all claimed evaluations.
pub fn batch_verify(
    commitments: &[G1Affine],
    z: Fr,
    evaluations: &[Fr],
    nu: Fr,
    batch_witness: G1Affine,
    srs: &SRS,
) -> bool {
    assert_eq!(commitments.len(), evaluations.len());

    // Compute batched commitment: C_batch = Σ nu^i · C_i
    // Compute batched evaluation: v_batch = Σ nu^i · v_i
    let mut combined_comm = G1Projective::zero();
    let mut combined_eval = Fr::zero();
    let mut nu_power = Fr::one();

    for (c, &v) in commitments.iter().zip(evaluations.iter()) {
        combined_comm += c.into_group() * nu_power;
        combined_eval += v * nu_power;
        nu_power *= nu;
    }

    verify(combined_comm.into_affine(), z, combined_eval, batch_witness, srs)
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute quotient polynomial q(X) = (p(X) - v) / (X - z).
///
/// Uses synthetic division. The polynomial p(X) - v must be divisible
/// by (X - z) when v = p(z).
fn compute_quotient_poly(coeffs: &[Fr], z: Fr, evaluation: Fr) -> Vec<Fr> {
    if coeffs.is_empty() {
        return vec![];
    }

    // p(X) - v: subtract evaluation from constant term
    let mut dividend = coeffs.to_vec();
    dividend[0] -= evaluation;

    // Synthetic division by (X - z)
    let n = dividend.len();
    if n <= 1 {
        return vec![];
    }

    let mut quotient = vec![Fr::zero(); n - 1];
    quotient[n - 2] = dividend[n - 1];
    for i in (0..n - 2).rev() {
        quotient[i] = dividend[i + 1] + z * quotient[i + 1];
    }

    // Verify: remainder should be zero (dividend[0] + z * quotient[0] == 0)
    debug_assert!(
        (dividend[0] + z * quotient[0]).is_zero(),
        "Non-zero remainder in quotient polynomial computation"
    );

    quotient
}

/// Add two coefficient vectors, returning a new vector.
pub fn poly_add(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let max_len = a.len().max(b.len());
    let mut result = vec![Fr::zero(); max_len];
    for (i, &v) in a.iter().enumerate() {
        result[i] += v;
    }
    for (i, &v) in b.iter().enumerate() {
        result[i] += v;
    }
    result
}

/// Scale a polynomial by a scalar.
pub fn poly_scale(coeffs: &[Fr], scalar: Fr) -> Vec<Fr> {
    coeffs.iter().map(|&c| c * scalar).collect()
}

/// Multiply two polynomials (schoolbook, O(n²)).
pub fn poly_mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut result = vec![Fr::zero(); a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            result[i + j] += ai * bj;
        }
    }
    result
}

/// Subtract polynomial b from a.
pub fn poly_sub(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let max_len = a.len().max(b.len());
    let mut result = vec![Fr::zero(); max_len];
    for (i, &v) in a.iter().enumerate() {
        result[i] += v;
    }
    for (i, &v) in b.iter().enumerate() {
        result[i] -= v;
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proving::srs::SRS;

    fn test_srs() -> SRS {
        SRS::insecure_for_testing(64)
    }

    #[test]
    fn test_commit_constant_polynomial() {
        let srs = test_srs();
        let coeffs = vec![Fr::from(5u64)]; // p(X) = 5
        let comm = commit(&coeffs, &srs);
        // Should be 5 * G1
        let expected = (G1Affine::generator() * Fr::from(5u64)).into_affine();
        assert_eq!(comm, expected);
    }

    #[test]
    fn test_evaluate_poly() {
        // p(X) = 3 + 2X + X²
        let coeffs = vec![Fr::from(3u64), Fr::from(2u64), Fr::one()];
        // p(2) = 3 + 4 + 4 = 11
        assert_eq!(evaluate_poly(&coeffs, Fr::from(2u64)), Fr::from(11u64));
        // p(0) = 3
        assert_eq!(evaluate_poly(&coeffs, Fr::zero()), Fr::from(3u64));
    }

    #[test]
    fn test_open_and_verify() {
        let srs = test_srs();
        // p(X) = 1 + 2X + 3X²
        let coeffs = vec![Fr::one(), Fr::from(2u64), Fr::from(3u64)];
        let commitment = commit(&coeffs, &srs);

        let z = Fr::from(5u64);
        let opening = open(&coeffs, z, &srs);

        // p(5) = 1 + 10 + 75 = 86
        assert_eq!(opening.evaluation, Fr::from(86u64));
        assert!(verify(commitment, z, opening.evaluation, opening.witness, &srs));
    }

    #[test]
    fn test_verify_wrong_evaluation_fails() {
        let srs = test_srs();
        let coeffs = vec![Fr::one(), Fr::from(2u64), Fr::from(3u64)];
        let commitment = commit(&coeffs, &srs);

        let z = Fr::from(5u64);
        let opening = open(&coeffs, z, &srs);

        // Wrong evaluation
        let wrong_eval = opening.evaluation + Fr::one();
        assert!(!verify(commitment, z, wrong_eval, opening.witness, &srs));
    }

    #[test]
    fn test_verify_wrong_point_fails() {
        let srs = test_srs();
        let coeffs = vec![Fr::one(), Fr::from(2u64)];
        let commitment = commit(&coeffs, &srs);

        let z = Fr::from(3u64);
        let opening = open(&coeffs, z, &srs);

        // Verify at wrong point
        let wrong_z = Fr::from(4u64);
        assert!(!verify(commitment, wrong_z, opening.evaluation, opening.witness, &srs));
    }

    #[test]
    fn test_batch_open_and_verify() {
        let srs = test_srs();
        let p1 = vec![Fr::from(1u64), Fr::from(2u64)]; // 1 + 2X
        let p2 = vec![Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)]; // 3 + 4X + 5X²

        let c1 = commit(&p1, &srs);
        let c2 = commit(&p2, &srs);

        let z = Fr::from(7u64);
        let nu = Fr::from(42u64);

        let (evals, witness) = batch_open(&[&p1, &p2], z, nu, &srs);
        assert!(batch_verify(&[c1, c2], z, &evals, nu, witness, &srs));
    }

    #[test]
    fn test_polynomial_operations() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)]; // 1 + 2X
        let b = vec![Fr::from(3u64), Fr::from(1u64)]; // 3 + X

        // (1 + 2X)(3 + X) = 3 + 7X + 2X²
        let product = poly_mul(&a, &b);
        assert_eq!(product, vec![Fr::from(3u64), Fr::from(7u64), Fr::from(2u64)]);

        // (1 + 2X) + (3 + X) = 4 + 3X
        let sum = poly_add(&a, &b);
        assert_eq!(sum, vec![Fr::from(4u64), Fr::from(3u64)]);
    }

    #[test]
    fn test_quotient_polynomial() {
        // p(X) = X² - 1 = (X-1)(X+1), z = 1, p(1) = 0
        let coeffs = vec![-Fr::one(), Fr::zero(), Fr::one()];
        let z = Fr::one();
        let eval = evaluate_poly(&coeffs, z);
        assert_eq!(eval, Fr::zero());

        let q = compute_quotient_poly(&coeffs, z, eval);
        // q(X) = X + 1
        assert_eq!(q, vec![Fr::one(), Fr::one()]);
    }

    // ====================================================================
    // Negative / edge-case tests
    // ====================================================================

    #[test]
    fn test_commit_empty_polynomial() {
        let srs = test_srs();
        let comm = commit(&[], &srs);
        assert!(comm.is_zero(), "Empty poly should commit to identity");
    }

    #[test]
    fn test_evaluate_empty_polynomial() {
        assert_eq!(evaluate_poly(&[], Fr::from(5u64)), Fr::zero());
    }

    #[test]
    fn test_evaluate_poly_at_zero() {
        let coeffs = vec![Fr::from(7u64), Fr::from(3u64), Fr::from(2u64)];
        assert_eq!(evaluate_poly(&coeffs, Fr::zero()), Fr::from(7u64));
    }

    #[test]
    fn test_verify_wrong_commitment_fails() {
        let srs = test_srs();
        let coeffs = vec![Fr::one(), Fr::from(2u64)];
        let _correct_comm = commit(&coeffs, &srs);

        let z = Fr::from(3u64);
        let opening = open(&coeffs, z, &srs);

        // Use a different commitment (generator instead of correct one)
        assert!(
            !verify(G1Affine::generator(), z, opening.evaluation, opening.witness, &srs),
            "Wrong commitment should fail verification"
        );
    }

    #[test]
    fn test_verify_wrong_witness_fails() {
        let srs = test_srs();
        let coeffs = vec![Fr::one(), Fr::from(2u64), Fr::from(3u64)];
        let commitment = commit(&coeffs, &srs);

        let z = Fr::from(5u64);
        let opening = open(&coeffs, z, &srs);

        // Replace witness with generator
        assert!(
            !verify(commitment, z, opening.evaluation, G1Affine::generator(), &srs),
            "Wrong witness should fail verification"
        );
    }

    #[test]
    fn test_batch_verify_wrong_eval_fails() {
        let srs = test_srs();
        let p1 = vec![Fr::from(1u64), Fr::from(2u64)];
        let p2 = vec![Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)];

        let c1 = commit(&p1, &srs);
        let c2 = commit(&p2, &srs);

        let z = Fr::from(7u64);
        let nu = Fr::from(42u64);

        let (mut evals, witness) = batch_open(&[&p1, &p2], z, nu, &srs);
        evals[0] += Fr::one(); // corrupt first evaluation
        assert!(
            !batch_verify(&[c1, c2], z, &evals, nu, witness, &srs),
            "Batch verify with wrong eval should fail"
        );
    }

    #[test]
    fn test_batch_verify_wrong_nu_fails() {
        let srs = test_srs();
        let p1 = vec![Fr::from(1u64), Fr::from(2u64)];
        let p2 = vec![Fr::from(3u64), Fr::from(4u64)];

        let c1 = commit(&p1, &srs);
        let c2 = commit(&p2, &srs);

        let z = Fr::from(7u64);
        let nu = Fr::from(42u64);
        let wrong_nu = Fr::from(99u64);

        let (evals, witness) = batch_open(&[&p1, &p2], z, nu, &srs);
        assert!(
            !batch_verify(&[c1, c2], z, &evals, wrong_nu, witness, &srs),
            "Batch verify with wrong nu should fail"
        );
    }

    #[test]
    fn test_poly_sub() {
        let a = vec![Fr::from(5u64), Fr::from(3u64)];
        let b = vec![Fr::from(2u64), Fr::from(1u64)];
        let result = poly_sub(&a, &b);
        assert_eq!(result, vec![Fr::from(3u64), Fr::from(2u64)]);
    }

    #[test]
    fn test_poly_sub_different_lengths() {
        let a = vec![Fr::from(5u64), Fr::from(3u64), Fr::from(1u64)];
        let b = vec![Fr::from(2u64)];
        let result = poly_sub(&a, &b);
        assert_eq!(result, vec![Fr::from(3u64), Fr::from(3u64), Fr::from(1u64)]);
    }

    #[test]
    fn test_poly_scale() {
        let coeffs = vec![Fr::from(2u64), Fr::from(3u64)];
        let scaled = poly_scale(&coeffs, Fr::from(4u64));
        assert_eq!(scaled, vec![Fr::from(8u64), Fr::from(12u64)]);
    }

    #[test]
    fn test_poly_scale_by_zero() {
        let coeffs = vec![Fr::from(2u64), Fr::from(3u64)];
        let scaled = poly_scale(&coeffs, Fr::zero());
        assert!(scaled.iter().all(|c| c.is_zero()));
    }

    #[test]
    fn test_poly_mul_empty() {
        let result = poly_mul(&[], &[Fr::one()]);
        assert!(result.is_empty());
        let result2 = poly_mul(&[Fr::one()], &[]);
        assert!(result2.is_empty());
    }

    #[test]
    fn test_poly_add_different_lengths() {
        let a = vec![Fr::from(1u64)];
        let b = vec![Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let result = poly_add(&a, &b);
        assert_eq!(result, vec![Fr::from(3u64), Fr::from(3u64), Fr::from(4u64)]);
    }

    #[test]
    fn test_open_at_zero() {
        let srs = test_srs();
        let coeffs = vec![Fr::from(7u64), Fr::from(3u64)]; // 7 + 3X
        let commitment = commit(&coeffs, &srs);
        let opening = open(&coeffs, Fr::zero(), &srs);
        assert_eq!(opening.evaluation, Fr::from(7u64));
        assert!(verify(commitment, Fr::zero(), opening.evaluation, opening.witness, &srs));
    }

    #[test]
    fn test_commit_single_coefficient() {
        let srs = test_srs();
        // p(X) = 1 (constant)
        let coeffs = vec![Fr::one()];
        let comm = commit(&coeffs, &srs);
        let expected = G1Affine::generator();
        assert_eq!(comm, expected, "Constant 1 poly should commit to generator");
    }

    #[test]
    fn test_batch_open_single_poly() {
        let srs = test_srs();
        let p = vec![Fr::from(5u64), Fr::from(3u64)];
        let c = commit(&p, &srs);

        let z = Fr::from(2u64);
        let nu = Fr::from(1u64); // nu=1 for single poly

        let (evals, witness) = batch_open(&[&p], z, nu, &srs);
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], evaluate_poly(&p, z));
        assert!(batch_verify(&[c], z, &evals, nu, witness, &srs));
    }
}
