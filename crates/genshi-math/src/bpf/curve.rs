//! BPF-compatible G1/G2 curve types.
//!
//! Points are stored as opaque big-endian byte buffers matching the EIP-197 /
//! Solana syscall wire format. On `target_os = "solana"`, arithmetic routes
//! through `sol_alt_bn128_{addition,multiplication}`; on host builds with the
//! `host-test` feature (or `native` for `#[path]`-included parity tests),
//! it falls back to arkworks.

extern crate alloc;

use super::fr::Fr;
use core::ops::{Add, AddAssign, Mul, Neg, Sub};

// ============================================================================
// G1Affine — 64 bytes: x_be (32) || y_be (32)
// ============================================================================

#[derive(Clone, Debug)]
pub struct G1Affine(pub(crate) [u8; 64]);

impl Copy for G1Affine {}

impl PartialEq for G1Affine {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G1Affine {}

impl G1Affine {
    pub const fn from_raw(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn generator() -> Self {
        let mut buf = [0u8; 64];
        buf[31] = 1; // x = 1
        buf[63] = 2; // y = 2
        Self(buf)
    }

    pub fn zero() -> Self {
        Self([0u8; 64])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 64]
    }

    pub fn to_uncompressed_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn from_uncompressed_bytes(bytes: &[u8; 64]) -> Option<Self> {
        if bytes.iter().all(|&b| b == 0) {
            return Some(Self(*bytes));
        }
        #[cfg(any(feature = "native", feature = "host-test"))]
        {
            use ark_bn254::{Fq, G1Affine as ArkG1};
            use ark_ec::AffineRepr;
            use ark_ff::PrimeField;
            let x = Fq::from_be_bytes_mod_order(&bytes[0..32]);
            let y = Fq::from_be_bytes_mod_order(&bytes[32..64]);
            let p = ArkG1::new_unchecked(x, y);
            if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
                return None;
            }
        }
        Some(Self(*bytes))
    }

    pub fn into_group(self) -> G1Projective {
        G1Projective(self.0)
    }

    pub fn serialized_size() -> usize {
        64
    }

    pub fn serialize_uncompressed(&self, buf: &mut alloc::vec::Vec<u8>) {
        #[cfg(any(feature = "native", feature = "host-test"))]
        {
            use ark_serialize::CanonicalSerialize;
            let ark = self.to_ark();
            ark.serialize_uncompressed(buf)
                .expect("G1 serialization is infallible for on-curve points");
        }
        #[cfg(not(any(feature = "native", feature = "host-test")))]
        {
            buf.extend_from_slice(&self.0);
        }
    }

    pub fn deserialize_uncompressed(bytes: &[u8]) -> Self {
        #[cfg(any(feature = "native", feature = "host-test"))]
        {
            use ark_serialize::CanonicalDeserialize;
            let ark = ark_bn254::G1Affine::deserialize_uncompressed(&bytes[..64])
                .expect("G1 deserialization failure — SRS is malformed");
            Self::from_ark(ark)
        }
        #[cfg(not(any(feature = "native", feature = "host-test")))]
        {
            let mut b = [0u8; 64];
            b.copy_from_slice(&bytes[..64]);
            Self(b)
        }
    }

    #[cfg(any(feature = "native", feature = "host-test"))]
    pub fn from_ark(ark_point: ark_bn254::G1Affine) -> Self {
        Self(encode_ark_g1(&ark_point))
    }

    #[cfg(any(feature = "native", feature = "host-test"))]
    pub fn to_ark(&self) -> ark_bn254::G1Affine {
        decode_ark_g1(&self.0)
    }
}

impl Mul<Fr> for G1Affine {
    type Output = G1Projective;
    fn mul(self, scalar: Fr) -> G1Projective {
        let result = g1_scalar_mul(&self.0, &scalar.to_be_bytes());
        G1Projective(result)
    }
}

// ============================================================================
// G1Projective — internally same 64-byte layout (affine); arithmetic via
// syscalls produces affine output for addition/scalar-mul.
// ============================================================================

#[derive(Clone, Debug)]
pub struct G1Projective(pub(crate) [u8; 64]);

impl Copy for G1Projective {}

impl PartialEq for G1Projective {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G1Projective {}

impl G1Projective {
    pub fn zero() -> Self {
        Self([0u8; 64])
    }

    pub fn into_affine(self) -> G1Affine {
        G1Affine(self.0)
    }

    #[cfg(any(feature = "native", feature = "host-test"))]
    pub fn from_ark(ark_point: ark_bn254::G1Projective) -> Self {
        use ark_ec::CurveGroup;
        Self(encode_ark_g1(&ark_point.into_affine()))
    }
}

impl Add for G1Projective {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(g1_add(&self.0, &rhs.0))
    }
}

impl AddAssign for G1Projective {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for G1Projective {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl Neg for G1Projective {
    type Output = Self;
    fn neg(self) -> Self {
        if self.0 == [0u8; 64] {
            return self;
        }
        let mut result = self.0;
        let y_bytes = &self.0[32..64];
        let neg_y = fq_negate(y_bytes);
        result[32..64].copy_from_slice(&neg_y);
        Self(result)
    }
}

impl Mul<Fr> for G1Projective {
    type Output = Self;
    fn mul(self, scalar: Fr) -> Self {
        Self(g1_scalar_mul(&self.0, &scalar.to_be_bytes()))
    }
}

// ============================================================================
// G2Affine — 128 bytes: x1_be (32) || x0_be (32) || y1_be (32) || y0_be (32)
// ============================================================================

#[derive(Clone, Debug)]
pub struct G2Affine(pub(crate) [u8; 128]);

impl Copy for G2Affine {}

impl PartialEq for G2Affine {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G2Affine {}

const G2_GENERATOR_BYTES: [u8; 128] = [
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a,
    0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12,
    0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76,
    0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd,
    0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb,
    0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b,
    0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75,
    0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3,
    0x55, 0xac, 0xdd, 0xb9, 0xe5, 0x57, 0xb7, 0xbb,
];

impl G2Affine {
    pub const fn from_raw(bytes: [u8; 128]) -> Self {
        Self(bytes)
    }

    pub fn generator() -> Self {
        Self(G2_GENERATOR_BYTES)
    }

    pub fn zero() -> Self {
        Self([0u8; 128])
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 128]
    }

    pub fn into_group(self) -> G2Projective {
        G2Projective(self.0)
    }

    pub fn serialized_size() -> usize {
        128
    }

    pub fn serialize_uncompressed(&self, buf: &mut alloc::vec::Vec<u8>) {
        #[cfg(any(feature = "native", feature = "host-test"))]
        {
            use ark_serialize::CanonicalSerialize;
            let ark = self.to_ark();
            ark.serialize_uncompressed(buf)
                .expect("G2 serialization is infallible for on-curve points");
        }
        #[cfg(not(any(feature = "native", feature = "host-test")))]
        {
            buf.extend_from_slice(&self.0);
        }
    }

    pub fn deserialize_uncompressed(bytes: &[u8]) -> Self {
        #[cfg(any(feature = "native", feature = "host-test"))]
        {
            use ark_serialize::CanonicalDeserialize;
            let ark = ark_bn254::G2Affine::deserialize_uncompressed(&bytes[..128])
                .expect("G2 deserialization failure — SRS is malformed");
            Self::from_ark(ark)
        }
        #[cfg(not(any(feature = "native", feature = "host-test")))]
        {
            let mut b = [0u8; 128];
            b.copy_from_slice(&bytes[..128]);
            Self(b)
        }
    }

    #[cfg(any(feature = "native", feature = "host-test"))]
    pub fn from_ark(ark_point: ark_bn254::G2Affine) -> Self {
        Self(encode_ark_g2(&ark_point))
    }

    #[cfg(any(feature = "native", feature = "host-test"))]
    pub fn to_ark(&self) -> ark_bn254::G2Affine {
        decode_ark_g2(&self.0)
    }
}

impl Mul<Fr> for G2Affine {
    type Output = G2Projective;
    fn mul(self, scalar: Fr) -> G2Projective {
        #[cfg(target_os = "solana")]
        {
            let _ = scalar;
            unimplemented!("G2 scalar mul not available on BPF; restructure to avoid it")
        }
        #[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
        {
            use ark_bn254::{Fr as ArkFr, G2Affine as ArkG2, G2Projective as ArkG2P};
            use ark_ec::CurveGroup;
            use ark_ff::PrimeField;

            let g2 = decode_ark_g2(&self.0);
            let s = ArkFr::from_be_bytes_mod_order(&scalar.to_be_bytes());
            let result: ArkG2 = (ArkG2P::from(g2) * s).into_affine();
            G2Projective(encode_ark_g2(&result))
        }
        #[cfg(all(not(target_os = "solana"), not(any(feature = "native", feature = "host-test"))))]
        {
            let _ = scalar;
            unimplemented!("G2 scalar mul requires Solana target or host-test feature")
        }
    }
}

// ============================================================================
// G2Projective
// ============================================================================

#[derive(Clone, Debug)]
pub struct G2Projective(pub(crate) [u8; 128]);

impl Copy for G2Projective {}

impl PartialEq for G2Projective {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G2Projective {}

impl G2Projective {
    pub fn into_affine(self) -> G2Affine {
        G2Affine(self.0)
    }
}

impl Sub for G2Projective {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        #[cfg(target_os = "solana")]
        {
            let _ = rhs;
            unimplemented!("G2 projective sub not available on BPF; restructure pairing equation")
        }
        #[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
        {
            use ark_bn254::{G2Affine as ArkG2, G2Projective as ArkG2P};
            use ark_ec::CurveGroup;

            let a = ArkG2P::from(decode_ark_g2(&self.0));
            let b = ArkG2P::from(decode_ark_g2(&rhs.0));
            let result: ArkG2 = (a - b).into_affine();
            Self(encode_ark_g2(&result))
        }
        #[cfg(all(not(target_os = "solana"), not(any(feature = "native", feature = "host-test"))))]
        {
            let _ = rhs;
            unimplemented!("G2 projective sub requires Solana target or host-test feature")
        }
    }
}

// ============================================================================
// BN254 Fq modulus (for G1 point negation)
// ============================================================================

const FQ_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

fn fq_negate(y_be: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (FQ_MODULUS[i] as u16).wrapping_sub(y_be[i] as u16).wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }
    result
}

// ============================================================================
// Syscall dispatchers
// ============================================================================

#[cfg(target_os = "solana")]
fn g1_add(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(a);
    input[64..].copy_from_slice(b);
    // solana-bn254 3.x renamed `alt_bn128_addition` to `alt_bn128_g1_addition_be`
    // to disambiguate from the new G2 variants. The old alias still works but
    // emits a deprecation warning; prefer the explicit big-endian form.
    let result = solana_bn254::prelude::alt_bn128_g1_addition_be(&input)
        .expect("sol_alt_bn128_g1_addition_be failed");
    let mut output = [0u8; 64];
    output.copy_from_slice(&result[..64]);
    output
}

#[cfg(target_os = "solana")]
fn g1_scalar_mul(point: &[u8; 64], scalar_be: &[u8; 32]) -> [u8; 64] {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(scalar_be);
    let result = solana_bn254::prelude::alt_bn128_g1_multiplication_be(&input)
        .expect("sol_alt_bn128_g1_multiplication_be failed");
    let mut output = [0u8; 64];
    output.copy_from_slice(&result[..64]);
    output
}

// Host fallback: arkworks (available when native or host-test feature is on)
#[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
fn g1_add(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    use ark_bn254::{G1Affine as ArkG1, G1Projective as ArkG1P};
    use ark_ec::CurveGroup;

    let pa = decode_ark_g1(a);
    let pb = decode_ark_g1(b);
    let sum: ArkG1 = (ArkG1P::from(pa) + ArkG1P::from(pb)).into_affine();
    encode_ark_g1(&sum)
}

#[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
fn g1_scalar_mul(point: &[u8; 64], scalar_be: &[u8; 32]) -> [u8; 64] {
    use ark_bn254::{Fr as ArkFr, G1Affine as ArkG1, G1Projective as ArkG1P};
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;

    let p = decode_ark_g1(point);
    let s = ArkFr::from_be_bytes_mod_order(scalar_be);
    let result: ArkG1 = (ArkG1P::from(p) * s).into_affine();
    encode_ark_g1(&result)
}

// Panic stubs when neither syscalls nor arkworks are available
#[cfg(all(not(target_os = "solana"), not(any(feature = "native", feature = "host-test"))))]
fn g1_add(_a: &[u8; 64], _b: &[u8; 64]) -> [u8; 64] {
    unimplemented!("BPF G1 add requires Solana target or host-test feature")
}

#[cfg(all(not(target_os = "solana"), not(any(feature = "native", feature = "host-test"))))]
fn g1_scalar_mul(_point: &[u8; 64], _scalar_be: &[u8; 32]) -> [u8; 64] {
    unimplemented!("BPF G1 scalar mul requires Solana target or host-test feature")
}

// ============================================================================
// Arkworks codec helpers (host-only)
// ============================================================================

#[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
fn decode_ark_g1(bytes: &[u8; 64]) -> ark_bn254::G1Affine {
    use ark_bn254::{Fq, G1Affine as ArkG1};
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    if bytes == &[0u8; 64] {
        return ArkG1::zero();
    }
    let x = Fq::from_be_bytes_mod_order(&bytes[0..32]);
    let y = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    ArkG1::new_unchecked(x, y)
}

#[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
fn encode_ark_g1(p: &ark_bn254::G1Affine) -> [u8; 64] {
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};

    if p.is_zero() {
        return [0u8; 64];
    }
    let mut out = [0u8; 64];
    let x = p.x().unwrap();
    let y = p.y().unwrap();
    out[0..32].copy_from_slice(&x.into_bigint().to_bytes_be());
    out[32..64].copy_from_slice(&y.into_bigint().to_bytes_be());
    out
}

#[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
fn decode_ark_g2(bytes: &[u8; 128]) -> ark_bn254::G2Affine {
    use ark_bn254::{Fq, Fq2, G2Affine as ArkG2};
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    if bytes == &[0u8; 128] {
        return ArkG2::zero();
    }
    let x1 = Fq::from_be_bytes_mod_order(&bytes[0..32]);
    let x0 = Fq::from_be_bytes_mod_order(&bytes[32..64]);
    let y1 = Fq::from_be_bytes_mod_order(&bytes[64..96]);
    let y0 = Fq::from_be_bytes_mod_order(&bytes[96..128]);
    ArkG2::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1))
}

#[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
fn encode_ark_g2(p: &ark_bn254::G2Affine) -> [u8; 128] {
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};

    if p.is_zero() {
        return [0u8; 128];
    }
    let mut out = [0u8; 128];
    let x = p.x().unwrap();
    let y = p.y().unwrap();
    out[0..32].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
    out[32..64].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
    out[64..96].copy_from_slice(&y.c1.into_bigint().to_bytes_be());
    out[96..128].copy_from_slice(&y.c0.into_bigint().to_bytes_be());
    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g1_generator_is_not_identity() {
        assert!(!G1Affine::generator().is_zero());
    }

    #[test]
    fn g1_identity_is_identity() {
        assert!(G1Affine::zero().is_zero());
    }

    #[test]
    fn g1_add_identity() {
        let g = G1Affine::generator().into_group();
        let z = G1Projective::zero();
        assert_eq!(g + z, g);
    }

    #[test]
    fn g1_double() {
        let g = G1Affine::generator().into_group();
        let two_g = g + g;
        let scalar_2 = Fr::from(2u64);
        let two_g_mul = G1Affine::generator() * scalar_2;
        assert_eq!(two_g, two_g_mul);
    }

    #[test]
    fn g1_negate_cancels() {
        let g = G1Affine::generator().into_group();
        let neg_g = -g;
        let sum = g + neg_g;
        assert!(sum.into_affine().is_zero());
    }

    #[test]
    fn g1_scalar_mul_one() {
        let g = G1Affine::generator();
        let one = Fr::one();
        let result = g * one;
        assert_eq!(result.into_affine(), g);
    }

    #[test]
    fn g1_scalar_mul_zero() {
        let g = G1Affine::generator();
        let zero = Fr::zero();
        let result = g * zero;
        assert!(result.into_affine().is_zero());
    }
}
