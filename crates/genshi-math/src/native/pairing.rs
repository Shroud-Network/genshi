//! Native BN254 pairing check. Thin wrapper over `ark_bn254`'s multi-pairing
//! so the verifier can call a single `pairing_check(...)` regardless of backend.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::One as _;

use super::curve::{G1Affine, G2Affine};

/// Returns `true` iff `e(g1a, g2a) · e(g1b, g2b) == 1` in GT.
///
/// This is the only pairing shape the verifier needs. Every KZG equation the
/// verifier checks is first rewritten as `e(A,B) == e(C,D)` → `e(A,B) · e(-C,D) == 1`,
/// which this function implements as a single `multi_pairing` call.
pub fn pairing_check(
    g1a: G1Affine,
    g2a: G2Affine,
    g1b: G1Affine,
    g2b: G2Affine,
) -> bool {
    Bn254::multi_pairing([g1a.0, g1b.0], [g2a.0, g2b.0]).0.is_one()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fr::Fr;
    use super::super::curve::G1Projective;

    /// Build a tiny ad-hoc KZG-style "check": e(a·G1, G2) · e(-G1, a·G2) == 1.
    ///
    /// This mirrors what the verifier does after rewriting its pairing equation.
    #[test]
    fn pairing_check_passes_on_balanced_pairs() {
        let a = Fr::from(42u64);
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let a_g1 = (g1.into_group() * a).into_affine();
        let a_g2 = (g2.into_group() * a).into_affine();
        let neg_g1 = G1Affine(-g1.0);

        // e(a·G1, G2) · e(-G1, a·G2) = e(G1,G2)^a · e(G1,G2)^{-a} = 1
        assert!(pairing_check(a_g1, g2, neg_g1, a_g2));
    }

    #[test]
    fn pairing_check_fails_on_unbalanced_pairs() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        // e(G1, G2) · e(G1, G2) = e(G1,G2)^2 ≠ 1
        assert!(!pairing_check(g1, g2, g1, g2));
    }

    #[test]
    fn pairing_check_identity_inputs() {
        let g2 = G2Affine::generator();
        // e(O, G2) · e(O, G2) = 1 · 1 = 1
        assert!(pairing_check(
            G1Affine::zero(),
            g2,
            G1Affine::zero(),
            g2,
        ));
    }

    // Ensure we don't accidentally drop CurveGroup import after refactors.
    #[allow(dead_code)]
    fn _keeps_projective_in_scope(_: G1Projective) {}
}
