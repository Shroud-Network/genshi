//! Grumpkin Pedersen commitment scheme.
//!
//! **GUARDRAIL G3**: The commitment scheme must be both computationally binding
//! and computationally hiding. This requires that the discrete log relationship
//! between generator points G and H is unknown.
//!
//! # Generator Derivation
//!
//! Generators are derived via a Nothing-Up-My-Sleeve (NUMS) construction:
//! 1. Hash a domain separator using SHA-256
//! 2. Use try-and-increment to map the hash to a valid Grumpkin curve point
//! 3. The discrete log between G and H is unknown because both are derived
//!    from hash outputs (random oracle model)
//!
//! ## Generator Seeds
//! - G: `SHA256("shroud_pedersen_generator_G")` → try-and-increment → Grumpkin point
//! - H: `SHA256("shroud_pedersen_generator_H")` → try-and-increment → Grumpkin point
//!
//! # Commitment
//!
//! `C = amount * G + blinding * H` on the Grumpkin curve.
//!
//! This is a standard Pedersen commitment providing:
//! - **Hiding**: The blinding factor randomizes the commitment
//! - **Binding**: Opening to two different (amount, blinding) pairs requires
//!   knowing the discrete log of G relative to H

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_grumpkin::Affine as GrumpkinAffine;

/// Grumpkin scalar type (= BN254 base field Fq).
type GrumpkinScalar = ark_bn254::Fq;

/// Domain separator for generator G.
const GENERATOR_G_DOMAIN: &[u8] = b"shroud_pedersen_generator_G";

/// Domain separator for generator H.
const GENERATOR_H_DOMAIN: &[u8] = b"shroud_pedersen_generator_H";

/// Derive a Grumpkin curve point from a domain separator using try-and-increment.
///
/// Process:
/// 1. Hash `domain || counter` with SHA-256 to get a candidate x-coordinate
/// 2. Check if x^3 + b (Grumpkin: b = -17) has a square root (valid y)
/// 3. If not, increment counter and try again
/// 4. Return the resulting affine point
///
/// This is deterministic and produces a verifiably random point with unknown
/// discrete log relative to any independently derived point.
fn hash_to_grumpkin_point(domain: &[u8]) -> GrumpkinAffine {
    use sha2::{Sha256, Digest};
    
    // Grumpkin curve equation: y^2 = x^3 - 17 (short Weierstrass form)
    // a = 0, b = -17 over the Grumpkin base field (= BN254 scalar field Fr)
    type GrumpkinBase = ark_bn254::Fr;
    
    for counter in 0u64.. {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        
        // Interpret hash as a candidate x-coordinate in Grumpkin's base field
        let x = GrumpkinBase::from_le_bytes_mod_order(&bytes);
        
        // Try to construct a point with this x-coordinate
        // Grumpkin uses short Weierstrass: y^2 = x^3 + ax + b
        // For Grumpkin: a = 0, b = -17
        if let Some(point) = GrumpkinAffine::get_point_from_x_unchecked(x, false) {
            // Verify the point is on the curve and in the correct subgroup
            if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
                return point;
            }
        }
        
        // Also try with the other y (negate)
        if let Some(point) = GrumpkinAffine::get_point_from_x_unchecked(x, true) {
            if point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
                return point;
            }
        }
    }
    
    unreachable!("Try-and-increment must find a valid point")
}

/// Pedersen generator G for the amount component.
///
/// Derived from: `SHA256("shroud_pedersen_generator_G")` via try-and-increment.
/// This is deterministic and reproducible by anyone.
pub fn generator_g() -> GrumpkinAffine {
    hash_to_grumpkin_point(GENERATOR_G_DOMAIN)
}

/// Pedersen generator H for the blinding factor.
///
/// Derived from: `SHA256("shroud_pedersen_generator_H")` via try-and-increment.
/// The discrete log relationship between G and H is unknown (NUMS property).
pub fn generator_h() -> GrumpkinAffine {
    hash_to_grumpkin_point(GENERATOR_H_DOMAIN)
}

/// Compute a Pedersen commitment: `C = amount * G + blinding * H`
///
/// # Arguments
/// * `amount` - The value being committed to (u64, converted to scalar)
/// * `blinding` - Random blinding factor for hiding property
///
/// # Returns
/// The commitment point on the Grumpkin curve (affine coordinates).
///
/// # Security Properties
/// - **Hiding**: Different blinding factors produce different commitments for the same amount
/// - **Binding**: Cannot open to two different (amount, blinding) pairs without breaking DL
pub fn commit(amount: u64, blinding: GrumpkinScalar) -> GrumpkinAffine {
    let g = generator_g();
    let h = generator_h();
    
    let amount_scalar = GrumpkinScalar::from(amount);
    
    // C = amount * G + blinding * H
    let commitment = g.mul_bigint(amount_scalar.into_bigint())
        + h.mul_bigint(blinding.into_bigint());
    
    commitment.into_affine()
}

/// Verify that a commitment opens to the given (amount, blinding) pair.
///
/// Recomputes `amount * G + blinding * H` and checks equality.
///
/// # Returns
/// `true` if the commitment matches, `false` otherwise.
pub fn verify_opening(
    commitment: GrumpkinAffine,
    amount: u64,
    blinding: GrumpkinScalar,
) -> bool {
    let recomputed = commit(amount, blinding);
    commitment == recomputed
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero, One};
    
    #[test]
    fn test_generator_derivation_deterministic() {
        let g1 = generator_g();
        let g2 = generator_g();
        assert_eq!(g1, g2, "Generator G derivation must be deterministic");
        
        let h1 = generator_h();
        let h2 = generator_h();
        assert_eq!(h1, h2, "Generator H derivation must be deterministic");
    }

    #[test]
    fn test_generators_are_different() {
        let g = generator_g();
        let h = generator_h();
        assert_ne!(g, h, "Generators G and H must be different points");
    }

    #[test]
    fn test_generators_on_curve() {
        let g = generator_g();
        let h = generator_h();
        assert!(g.is_on_curve(), "Generator G must be on the Grumpkin curve");
        assert!(h.is_on_curve(), "Generator H must be on the Grumpkin curve");
    }

    #[test]
    fn test_generators_not_identity() {
        let g = generator_g();
        let h = generator_h();
        assert!(!g.is_zero(), "Generator G must not be the identity point");
        assert!(!h.is_zero(), "Generator H must not be the identity point");
    }

    #[test]
    fn test_commitment_deterministic() {
        let blinding = GrumpkinScalar::from(42u64);
        let c1 = commit(100, blinding);
        let c2 = commit(100, blinding);
        assert_eq!(c1, c2, "Same inputs must produce same commitment");
    }

    #[test]
    fn test_verify_opening_correct() {
        let blinding = GrumpkinScalar::from(12345u64);
        let amount = 500u64;
        let c = commit(amount, blinding);
        assert!(verify_opening(c, amount, blinding), "Valid opening must verify");
    }

    #[test]
    fn test_verify_opening_wrong_amount() {
        let blinding = GrumpkinScalar::from(12345u64);
        let c = commit(500, blinding);
        assert!(!verify_opening(c, 501, blinding), "Wrong amount must not verify");
    }

    #[test]
    fn test_verify_opening_wrong_blinding() {
        let blinding = GrumpkinScalar::from(12345u64);
        let wrong_blinding = GrumpkinScalar::from(12346u64);
        let c = commit(500, blinding);
        assert!(!verify_opening(c, 500, wrong_blinding), "Wrong blinding must not verify");
    }

    #[test]
    fn test_hiding_property() {
        // Different blindings produce different commitments for same amount
        let b1 = GrumpkinScalar::from(1u64);
        let b2 = GrumpkinScalar::from(2u64);
        let c1 = commit(100, b1);
        let c2 = commit(100, b2);
        assert_ne!(c1, c2, "Hiding: different blindings must produce different commitments");
    }

    #[test]
    fn test_different_amounts_different_commitments() {
        let blinding = GrumpkinScalar::from(42u64);
        let c1 = commit(100, blinding);
        let c2 = commit(200, blinding);
        assert_ne!(c1, c2, "Different amounts must produce different commitments");
    }

    #[test]
    fn test_commitment_on_curve() {
        let blinding = GrumpkinScalar::from(42u64);
        let c = commit(100, blinding);
        assert!(c.is_on_curve(), "Commitment must be a valid curve point");
    }

    #[test]
    fn test_zero_amount_commitment() {
        let blinding = GrumpkinScalar::from(999u64);
        let c = commit(0, blinding);
        // C = 0*G + blinding*H = blinding*H
        let h = generator_h();
        let expected = h.mul_bigint(blinding.into_bigint()).into_affine();
        assert_eq!(c, expected, "Zero amount commitment should equal blinding*H");
    }

    #[test]
    fn test_zero_blinding_commitment() {
        let blinding = GrumpkinScalar::zero();
        let c = commit(100, blinding);
        // C = amount*G + 0*H = amount*G
        let g = generator_g();
        let amount_scalar = GrumpkinScalar::from(100u64);
        let expected = g.mul_bigint(amount_scalar.into_bigint()).into_affine();
        assert_eq!(c, expected, "Zero blinding commitment should equal amount*G");
    }
}
