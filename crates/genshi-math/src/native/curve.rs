//! Native BN254 G1 and G2 curve types. Newtypes over the `ark_bn254`
//! representations that expose only the operations the verifier actually
//! uses, so the BPF backend has a finite surface to mirror.

use ark_bn254::{
    G1Affine as ArkG1Affine, G1Projective as ArkG1Projective, G2Affine as ArkG2Affine,
    G2Projective as ArkG2Projective,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero as _};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use super::fr::Fr;

// ============================================================================
// G1Affine
// ============================================================================

/// G1 affine point (the form used on the wire and in commitments).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct G1Affine(pub(crate) ArkG1Affine);

impl G1Affine {
    /// The curve generator `G1`.
    #[inline]
    pub fn generator() -> Self {
        Self(ArkG1Affine::generator())
    }

    /// The identity element (`O`).
    #[inline]
    pub fn zero() -> Self {
        Self(ArkG1Affine::zero())
    }

    /// `true` iff this is the identity.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Lift to a projective representation for mixed arithmetic.
    #[inline]
    pub fn into_group(self) -> G1Projective {
        G1Projective(self.0.into_group())
    }

    /// 64-byte uncompressed big-endian encoding: `x_be (32) || y_be (32)`.
    ///
    /// The identity element encodes as 64 zero bytes. Matches the EVM precompile
    /// wire format (EIP-197) and `sol_alt_bn128_*` instruction data, so the
    /// transcript can absorb the same bytes that are fed to the host pairing
    /// syscall.
    pub fn to_uncompressed_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        if !self.0.is_zero() {
            let x: ark_bn254::Fq = self.0.x().expect("non-identity G1 has x");
            let y: ark_bn254::Fq = self.0.y().expect("non-identity G1 has y");
            out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
            out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
        }
        out
    }

    /// Decode a 64-byte `x_be || y_be` uncompressed encoding, with full curve +
    /// subgroup membership checks. `None` on any validation failure.
    ///
    /// All-zero input decodes to the identity element.
    pub fn from_uncompressed_bytes(bytes: &[u8; 64]) -> Option<Self> {
        if bytes.iter().all(|&b| b == 0) {
            return Some(Self(ArkG1Affine::zero()));
        }
        let x = ark_bn254::Fq::from_be_bytes_mod_order(&bytes[..32]);
        let y = ark_bn254::Fq::from_be_bytes_mod_order(&bytes[32..]);
        // Reject representatives that are not canonical (field element
        // encoded above the modulus) so the decode is a bijection on valid
        // encodings.
        if x.into_bigint().to_bytes_be() != bytes[..32] {
            return None;
        }
        if y.into_bigint().to_bytes_be() != bytes[32..] {
            return None;
        }
        let point = ArkG1Affine::new_unchecked(x, y);
        if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
            return None;
        }
        Some(Self(point))
    }

    /// arkworks-native serialization length in bytes (for SRS buffers).
    pub fn serialized_size() -> usize {
        ArkG1Affine::generator()
            .serialized_size(ark_serialize::Compress::No)
    }

    /// Serialize (uncompressed) via arkworks. Used only by the host SRS loader.
    pub fn serialize_uncompressed(&self, buf: &mut impl ark_serialize::Write) {
        self.0
            .serialize_uncompressed(buf)
            .expect("G1 serialization is infallible for on-curve points");
    }

    /// Deserialize (uncompressed) via arkworks. Used only by the host SRS loader.
    pub fn deserialize_uncompressed(bytes: &[u8]) -> Self {
        Self(
            ArkG1Affine::deserialize_uncompressed(bytes)
                .expect("G1 deserialization failure — SRS is malformed"),
        )
    }

    /// **Native-backend-only.** Wrap an `ark_bn254::G1Affine`.
    #[inline]
    pub fn from_ark(inner: ArkG1Affine) -> Self {
        Self(inner)
    }

    /// **Native-backend-only.** Unwrap to `ark_bn254::G1Affine`.
    #[inline]
    pub fn to_ark(self) -> ArkG1Affine {
        self.0
    }
}

impl Mul<Fr> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: Fr) -> G1Projective {
        G1Projective(self.0 * rhs.0)
    }
}

impl Mul<&Fr> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: &Fr) -> G1Projective {
        G1Projective(self.0 * rhs.0)
    }
}

// ============================================================================
// G1Projective
// ============================================================================

/// G1 projective point (used for in-verifier additive accumulation).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct G1Projective(pub(crate) ArkG1Projective);

impl G1Projective {
    /// Additive identity (point at infinity).
    #[inline]
    pub fn zero() -> Self {
        Self(ArkG1Projective::zero())
    }

    /// Normalize to affine for the pairing call.
    #[inline]
    pub fn into_affine(self) -> G1Affine {
        G1Affine(self.0.into_affine())
    }

    /// **Native-backend-only.** Wrap an `ark_bn254::G1Projective`.
    #[inline]
    pub fn from_ark(inner: ArkG1Projective) -> Self {
        Self(inner)
    }

    /// **Native-backend-only.** Unwrap to `ark_bn254::G1Projective`.
    #[inline]
    pub fn to_ark(self) -> ArkG1Projective {
        self.0
    }
}

impl Add for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: G1Projective) -> G1Projective {
        G1Projective(self.0 + rhs.0)
    }
}

impl Sub for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: G1Projective) -> G1Projective {
        G1Projective(self.0 - rhs.0)
    }
}

impl AddAssign<G1Projective> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: G1Projective) {
        self.0 += rhs.0;
    }
}

impl SubAssign<G1Projective> for G1Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: G1Projective) {
        self.0 -= rhs.0;
    }
}

impl Neg for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn neg(self) -> G1Projective {
        G1Projective(-self.0)
    }
}

impl Mul<Fr> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: Fr) -> G1Projective {
        G1Projective(self.0 * rhs.0)
    }
}

impl Mul<&Fr> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: &Fr) -> G1Projective {
        G1Projective(self.0 * rhs.0)
    }
}

// ============================================================================
// G2Affine
// ============================================================================

/// G2 affine point. Used in the pairing check and inside the SRS; emitted
/// Anchor programs hardcode the two specific G2 values they need and never
/// materialize a `G2Affine` at runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct G2Affine(pub(crate) ArkG2Affine);

impl G2Affine {
    #[inline]
    pub fn generator() -> Self {
        Self(ArkG2Affine::generator())
    }

    /// Lift to projective form for scalar multiplication.
    #[inline]
    pub fn into_group(self) -> G2Projective {
        G2Projective(self.0.into_group())
    }

    pub fn serialized_size() -> usize {
        ArkG2Affine::generator()
            .serialized_size(ark_serialize::Compress::No)
    }

    pub fn serialize_uncompressed(&self, buf: &mut impl ark_serialize::Write) {
        self.0
            .serialize_uncompressed(buf)
            .expect("G2 serialization is infallible for on-curve points");
    }

    pub fn deserialize_uncompressed(bytes: &[u8]) -> Self {
        Self(
            ArkG2Affine::deserialize_uncompressed(bytes)
                .expect("G2 deserialization failure — SRS is malformed"),
        )
    }

    /// **Native-backend-only.** Wrap an `ark_bn254::G2Affine`.
    #[inline]
    pub fn from_ark(inner: ArkG2Affine) -> Self {
        Self(inner)
    }

    /// **Native-backend-only.** Unwrap to `ark_bn254::G2Affine`.
    #[inline]
    pub fn to_ark(self) -> ArkG2Affine {
        self.0
    }
}

impl Mul<Fr> for G2Affine {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: Fr) -> G2Projective {
        G2Projective(self.0 * rhs.0)
    }
}

// ============================================================================
// G2Projective (internal use — only needed for `τ·G2 − ζ·G2` in verifier)
// ============================================================================

/// G2 projective point. Only appears in the verifier as the temporary
/// `τ·G2 − ζ·G2` before re-affining for the pairing call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct G2Projective(pub(crate) ArkG2Projective);

impl G2Projective {
    #[inline]
    pub fn into_affine(self) -> G2Affine {
        G2Affine(self.0.into_affine())
    }

    /// **Native-backend-only.** Wrap an `ark_bn254::G2Projective`.
    #[inline]
    pub fn from_ark(inner: ArkG2Projective) -> Self {
        Self(inner)
    }
}

impl Add for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: G2Projective) -> G2Projective {
        G2Projective(self.0 + rhs.0)
    }
}

impl Mul<Fr> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: Fr) -> G2Projective {
        G2Projective(self.0 * rhs.0)
    }
}

impl Sub for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: G2Projective) -> G2Projective {
        G2Projective(self.0 - rhs.0)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let o = G1Affine::zero();
        assert!(o.is_zero());
        assert!(o.into_group().into_affine().is_zero());
    }

    #[test]
    fn generator_is_not_identity() {
        assert!(!G1Affine::generator().is_zero());
        assert_ne!(G1Affine::generator(), G1Affine::zero());
    }

    #[test]
    fn scalar_mul_matches_repeated_add() {
        let g = G1Affine::generator().into_group();
        let three = Fr::from(3u64);
        // 3·G = G + G + G
        let by_scalar = g * three;
        let by_add = g + g + g;
        assert_eq!(by_scalar, by_add);
    }

    #[test]
    fn negation_cancels() {
        let g = G1Affine::generator().into_group();
        let g_neg = -g;
        assert!((g + g_neg).into_affine().is_zero());
    }

    #[test]
    fn subtraction_is_add_negate() {
        let a = G1Affine::generator().into_group() * Fr::from(7u64);
        let b = G1Affine::generator().into_group() * Fr::from(3u64);
        assert_eq!(a - b, a + (-b));
    }

    #[test]
    fn g1_affine_uncompressed_bytes_length() {
        let g = G1Affine::generator();
        let bytes = g.to_uncompressed_bytes();
        assert_eq!(bytes.len(), 64);
        // First byte should be nonzero (generator.x is not zero).
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn g1_affine_uncompressed_identity_is_zeroes() {
        let bytes = G1Affine::zero().to_uncompressed_bytes();
        assert_eq!(bytes, [0u8; 64]);
    }

    #[test]
    fn g2_scalar_mul_matches_generator_add() {
        let two = Fr::from(2u64);
        let g2 = G2Affine::generator();
        let by_scalar = (g2 * two).into_affine();
        let by_add = (g2.into_group() + g2.into_group()).into_affine();
        assert_eq!(by_scalar, by_add);
    }

    #[test]
    fn msm_accumulation_loop() {
        // Mirrors the KZG batch-verify shape: f = Σ nu^i · C_i
        let mut f = G1Projective::zero();
        let g = G1Affine::generator();
        let nu = Fr::from(11u64);
        let mut nu_pow = Fr::one();
        for _ in 0..5 {
            f += g.into_group() * nu_pow;
            nu_pow *= nu;
        }
        // f should equal (1 + ν + ν² + ν³ + ν⁴)·G
        let coefficient = Fr::one()
            + nu
            + nu * nu
            + nu * nu * nu
            + nu * nu * nu * nu;
        let expected = g.into_group() * coefficient;
        assert_eq!(f, expected);
    }
}
