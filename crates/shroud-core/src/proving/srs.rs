//! Structured Reference String (SRS) for KZG commitments.
//!
//! The SRS contains `[τ^0·G1, τ^1·G1, ..., τ^n·G1]` and `τ·G2` from a
//! trusted setup ceremony (Powers of Tau / Aztec ceremony).
//!
//! **GUARDRAIL G9**: SRS must come from a verifiable ceremony.
//! For development/testing, we use a deterministic "insecure" SRS
//! derived from a known secret. NEVER use this in production.
//!
//! For WASM: lazy loading + IndexedDB caching (Phase 6).
//! Download only the SRS points needed for actual circuit size.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField};
use alloc::vec::Vec;

/// Structured Reference String for KZG polynomial commitments.
///
/// Contains the G1 powers `{τ^i · G1}` for committing to polynomials,
/// and `τ · G2` for the pairing verification equation.
#[derive(Clone, Debug)]
pub struct SRS {
    /// G1 powers: `[G1, τ·G1, τ²·G1, ..., τ^n·G1]`
    /// Length = max polynomial degree + 1
    pub g1_powers: Vec<G1Affine>,

    /// `G2` generator
    pub g2: G2Affine,

    /// `τ · G2` (for pairing check: `e(C - v·G1, G2) = e(π, τ·G2 - z·G2)`)
    pub g2_tau: G2Affine,
}

impl SRS {
    /// Generate an insecure SRS for testing purposes.
    ///
    /// ⚠️ **WARNING**: This uses a known secret `τ`. The SRS is deterministic
    /// and reproducible, but NOT secure. Use only for development and testing.
    ///
    /// **GUARDRAIL G9**: Production deployment MUST use ceremony-derived SRS.
    ///
    /// # Arguments
    /// * `max_degree` - Maximum polynomial degree supported (number of G1 points = max_degree + 1)
    pub fn insecure_for_testing(max_degree: usize) -> Self {
        // Use a deterministic "secret" tau derived from domain separator
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(b"shroud_insecure_srs_tau_DO_NOT_USE_IN_PRODUCTION");
        let tau = Fr::from_be_bytes_mod_order(&hash);

        let g1_gen = G1Affine::generator();
        let g2_gen = G2Affine::generator();

        // Compute G1 powers: [G1, τ·G1, τ²·G1, ..., τ^n·G1]
        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        let mut tau_pow = Fr::one();
        for _ in 0..=max_degree {
            let point = (g1_gen * tau_pow).into_affine();
            g1_powers.push(point);
            tau_pow *= tau;
        }

        // Compute τ·G2
        let g2_tau = (g2_gen * tau).into_affine();

        Self {
            g1_powers,
            g2: g2_gen,
            g2_tau,
        }
    }

    /// Maximum polynomial degree this SRS supports.
    pub fn max_degree(&self) -> usize {
        self.g1_powers.len().saturating_sub(1)
    }

    /// Number of G1 points in the SRS.
    pub fn size(&self) -> usize {
        self.g1_powers.len()
    }

    /// Get a G1 power at index `i`: `τ^i · G1`.
    ///
    /// # Panics
    /// Panics if `i > max_degree()`.
    pub fn g1_power(&self, i: usize) -> G1Affine {
        self.g1_powers[i]
    }

    /// Trim the SRS to a smaller degree (for sub-circuits).
    pub fn trim(&self, max_degree: usize) -> Self {
        assert!(max_degree <= self.max_degree(),
            "Cannot trim to degree {} > SRS degree {}", max_degree, self.max_degree());
        Self {
            g1_powers: self.g1_powers[..=max_degree].to_vec(),
            g2: self.g2,
            g2_tau: self.g2_tau,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srs_generation() {
        let srs = SRS::insecure_for_testing(16);
        assert_eq!(srs.size(), 17); // 0..=16
        assert_eq!(srs.max_degree(), 16);
    }

    #[test]
    fn test_srs_first_point_is_generator() {
        let srs = SRS::insecure_for_testing(4);
        // τ^0 · G1 = G1
        assert_eq!(srs.g1_power(0), G1Affine::generator());
    }

    #[test]
    fn test_srs_deterministic() {
        let srs1 = SRS::insecure_for_testing(8);
        let srs2 = SRS::insecure_for_testing(8);
        assert_eq!(srs1.g1_powers, srs2.g1_powers, "SRS must be deterministic");
        assert_eq!(srs1.g2_tau, srs2.g2_tau);
    }

    #[test]
    fn test_srs_points_on_curve() {
        let srs = SRS::insecure_for_testing(8);
        for (i, p) in srs.g1_powers.iter().enumerate() {
            assert!(p.is_on_curve(), "G1 power {} not on curve", i);
        }
        assert!(srs.g2.is_on_curve(), "G2 not on curve");
        assert!(srs.g2_tau.is_on_curve(), "G2·τ not on curve");
    }

    #[test]
    fn test_srs_trim() {
        let srs = SRS::insecure_for_testing(16);
        let trimmed = srs.trim(4);
        assert_eq!(trimmed.max_degree(), 4);
        assert_eq!(trimmed.g1_power(0), srs.g1_power(0));
        assert_eq!(trimmed.g1_power(4), srs.g1_power(4));
    }

    #[test]
    fn test_srs_powers_not_identity() {
        let srs = SRS::insecure_for_testing(4);
        for p in &srs.g1_powers {
            assert!(!p.is_zero(), "SRS point should not be identity");
        }
    }
}
