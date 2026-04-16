//! Structured Reference String (SRS) for KZG commitments.
//!
//! The SRS contains `[τ^0·G1, τ^1·G1, ..., τ^n·G1]` and `τ·G2` from a
//! trusted setup ceremony (Powers of Tau — genshi uses Aztec's ceremony).
//!
//! **Invariant J6**: In production, SRS must come from a verifiable ceremony.
//! For development/testing, we expose a deterministic "insecure" SRS derived
//! from a known secret — NEVER use this in production.
//!
//! The struct stores points as `genshi_math::{G1Affine, G2Affine}` so the
//! same struct layout is reachable from the BPF backend (which hand-rolls the
//! point types over Solana syscalls).

use genshi_math::{Fr, G1Affine, G2Affine};
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
    /// **WARNING**: This uses a known secret `τ`. The SRS is deterministic and
    /// reproducible, but NOT secure. Use only for development and testing.
    ///
    /// **Invariant J6**: Production deployment MUST use ceremony-derived SRS.
    ///
    /// # Arguments
    /// * `max_degree` - Maximum polynomial degree supported (number of G1 points = max_degree + 1)
    #[cfg(feature = "math-native")]
    pub fn insecure_for_testing(max_degree: usize) -> Self {
        use ark_bn254::{Fr as ArkFr, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
        use ark_ec::{AffineRepr, CurveGroup};
        use ark_ff::{One, PrimeField};
        use sha2::{Digest, Sha256};

        let hash = Sha256::digest(b"genshi_insecure_srs_tau_DO_NOT_USE_IN_PRODUCTION");
        let tau = ArkFr::from_be_bytes_mod_order(&hash);

        let g1_gen = ArkG1Affine::generator();
        let g2_gen = ArkG2Affine::generator();

        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        let mut tau_pow = ArkFr::one();
        for _ in 0..=max_degree {
            let point = (g1_gen * tau_pow).into_affine();
            g1_powers.push(G1Affine::from_ark(point));
            tau_pow *= tau;
        }

        let g2_tau = G2Affine::from_ark((g2_gen * tau).into_affine());

        Self {
            g1_powers,
            g2: G2Affine::from_ark(g2_gen),
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

    /// Serialize the SRS to bytes.
    ///
    /// Layout:
    /// - `num_g1_points`: 4 bytes (u32 LE)
    /// - `g1_powers`: num_g1_points × uncompressed G1 size
    /// - `g2`: uncompressed G2 size
    /// - `g2_tau`: uncompressed G2 size
    #[cfg(feature = "math-native")]
    pub fn save_to_bytes(&self) -> Vec<u8> {
        let g1_size = G1Affine::serialized_size();
        let g2_size = G2Affine::serialized_size();
        let n = self.g1_powers.len();
        let mut buf = Vec::with_capacity(4 + n * g1_size + 2 * g2_size);

        buf.extend_from_slice(&(n as u32).to_le_bytes());
        for p in &self.g1_powers {
            let mut point_buf = Vec::new();
            p.serialize_uncompressed(&mut point_buf);
            buf.extend_from_slice(&point_buf);
        }

        let mut g2_buf = Vec::new();
        self.g2.serialize_uncompressed(&mut g2_buf);
        buf.extend_from_slice(&g2_buf);

        let mut g2_tau_buf = Vec::new();
        self.g2_tau.serialize_uncompressed(&mut g2_tau_buf);
        buf.extend_from_slice(&g2_tau_buf);

        buf
    }

    /// Deserialize the SRS from bytes. Runs on both host (native backend) and
    /// inside emitted Anchor programs (bpf backend), so the byte layout is
    /// identical across backends.
    pub fn load_from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 4, "SRS bytes too short");
        let n = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut offset = 4;

        let g1_size = G1Affine::serialized_size();
        let g2_size = G2Affine::serialized_size();

        let mut g1_powers = Vec::with_capacity(n);
        for _ in 0..n {
            let p = G1Affine::deserialize_uncompressed(&bytes[offset..offset + g1_size]);
            g1_powers.push(p);
            offset += g1_size;
        }

        let g2 = G2Affine::deserialize_uncompressed(&bytes[offset..offset + g2_size]);
        offset += g2_size;

        let g2_tau = G2Affine::deserialize_uncompressed(&bytes[offset..offset + g2_size]);

        Self { g1_powers, g2, g2_tau }
    }

    /// Pre-reserved for backend-agnostic "empty" construction (tests that want
    /// to build a dummy SRS without running the insecure ceremony). Not used
    /// yet; stub retained to silence `Fr` unused-import linters in no_std.
    #[allow(dead_code)]
    fn _phantom_fr_use() -> Fr {
        Fr::zero()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "math-native"))]
mod tests {
    use super::*;

    #[test]
    fn test_srs_generation() {
        let srs = SRS::insecure_for_testing(16);
        assert_eq!(srs.size(), 17);
        assert_eq!(srs.max_degree(), 16);
    }

    #[test]
    fn test_srs_first_point_is_generator() {
        let srs = SRS::insecure_for_testing(4);
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

    #[test]
    fn test_srs_save_load_roundtrip() {
        let srs = SRS::insecure_for_testing(16);
        let bytes = srs.save_to_bytes();
        let srs2 = SRS::load_from_bytes(&bytes);

        assert_eq!(srs.g1_powers, srs2.g1_powers, "G1 powers must match");
        assert_eq!(srs.g2, srs2.g2, "G2 must match");
        assert_eq!(srs.g2_tau, srs2.g2_tau, "G2 tau must match");
    }

    #[test]
    fn test_srs_bytes_deterministic() {
        let srs = SRS::insecure_for_testing(8);
        let bytes1 = srs.save_to_bytes();
        let bytes2 = srs.save_to_bytes();
        assert_eq!(bytes1, bytes2, "Same SRS must produce same bytes");
    }
}
