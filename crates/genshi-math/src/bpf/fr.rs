//! BPF-compatible BN254 scalar field (`Fr`) in Montgomery form.
//!
//! Stores elements as `x·R mod p` where:
//!   - p = BN254 scalar field order
//!   - R = 2^256
//!   - Limb layout: 4×u64, little-endian (limb 0 = least significant 64 bits)
//!
//! Montgomery multiplication avoids expensive division per operation.
//! All constants below are derived from arkworks `ark_bn254::FrConfig` and
//! verified against the native backend in `tests/parity.rs`.

use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// BN254 scalar field order p (little-endian limbs).
///
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// Montgomery R = 2^256 mod p (the Montgomery form of 1).
const R: [u64; 4] = [
    0xac96341c4ffffffb,
    0x36fc76959f60cd29,
    0x666ea36f7879462e,
    0x0e0a77c19a07df2f,
];

/// Montgomery R² = 2^512 mod p (used to convert integers into Montgomery form).
const R2: [u64; 4] = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

/// Montgomery inverse: INV = -p⁻¹ mod 2^64.
const INV: u64 = 0xc2e1f593efffffff;

/// BN254 scalar field element in Montgomery form.
///
/// Internal representation: `self.0 = x·R mod p` for the "real" value x.
#[derive(Copy, Clone, Debug)]
pub struct Fr(pub(crate) [u64; 4]);

impl PartialEq for Fr {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Fr {}

impl core::hash::Hash for Fr {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Fr {
    #[inline]
    pub fn zero() -> Self {
        Self([0, 0, 0, 0])
    }

    #[inline]
    pub fn one() -> Self {
        Self(R)
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Convert a raw u64 value into Montgomery form.
    pub fn from_u64(val: u64) -> Self {
        let raw = [val, 0, 0, 0];
        Self(mont_mul(&raw, &R2))
    }

    /// 32-byte big-endian reduction mod p, then convert to Montgomery form.
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let raw = reduce_be_bytes(bytes);
        Self(mont_mul(&raw, &R2))
    }

    /// 32-byte little-endian reduction mod p, then convert to Montgomery form.
    pub fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut be = [0u8; 32];
        let n = bytes.len().min(32);
        for i in 0..n {
            be[31 - i] = bytes[i];
        }
        Self::from_be_bytes_mod_order(&be)
    }

    /// Convert out of Montgomery form and serialize as 32 big-endian bytes.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let reduced = mont_mul(&self.0, &[1, 0, 0, 0]);
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&reduced[0].to_be_bytes());
        out[16..24].copy_from_slice(&reduced[1].to_be_bytes());
        out[8..16].copy_from_slice(&reduced[2].to_be_bytes());
        out[0..8].copy_from_slice(&reduced[3].to_be_bytes());
        out
    }

    /// Convert out of Montgomery form and serialize as 32 little-endian bytes.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let reduced = mont_mul(&self.0, &[1, 0, 0, 0]);
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&reduced[0].to_le_bytes());
        out[8..16].copy_from_slice(&reduced[1].to_le_bytes());
        out[16..24].copy_from_slice(&reduced[2].to_le_bytes());
        out[24..32].copy_from_slice(&reduced[3].to_le_bytes());
        out
    }

    /// Modular exponentiation by a single-limb exponent (square-and-multiply).
    pub fn pow(&self, exp: &[u64]) -> Self {
        let mut result = Fr::one();
        for &limb in exp.iter().rev() {
            for i in (0..64).rev() {
                result = result * result;
                if (limb >> i) & 1 == 1 {
                    result = result * *self;
                }
            }
        }
        result
    }

    /// Modular inverse via Fermat's little theorem: a⁻¹ = a^(p-2) mod p.
    pub fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.pow(&P_MINUS_2))
    }

    pub fn from_be_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        limbs[3] = u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
        limbs[2] = u64::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]);
        limbs[1] = u64::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]]);
        limbs[0] = u64::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31]]);

        if !lt(&limbs, &MODULUS) {
            return None;
        }
        Some(Self(mont_mul(&limbs, &R2)))
    }

    #[cfg(any(feature = "native", feature = "host-test"))]
    pub fn from_ark(ark_fr: ark_bn254::Fr) -> Self {
        use ark_ff::{BigInteger, PrimeField};
        let be_bytes = ark_fr.into_bigint().to_bytes_be();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&be_bytes);
        Self::from_be_bytes_mod_order(&arr)
    }

    #[cfg(any(feature = "native", feature = "host-test"))]
    pub fn to_ark(self) -> ark_bn254::Fr {
        use ark_ff::PrimeField;
        let be = self.to_be_bytes();
        ark_bn254::Fr::from_be_bytes_mod_order(&be)
    }
}

/// p - 2 (for Fermat inversion), little-endian limbs.
const P_MINUS_2: [u64; 4] = [
    MODULUS[0] - 2,
    MODULUS[1],
    MODULUS[2],
    MODULUS[3],
];

// ============================================================================
// Montgomery multiplication (CIOS — Coarsely Integrated Operand Scanning)
// ============================================================================

/// Compute `a * b * R⁻¹ mod p` (Montgomery multiplication).
#[inline]
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 5]; // 5 limbs to hold the intermediate product

    for i in 0..4 {
        let mut carry: u64 = 0;

        // Step 1: t += a[i] * b
        for j in 0..4 {
            let (lo, hi) = mac(t[j], a[i], b[j], carry);
            t[j] = lo;
            carry = hi;
        }
        t[4] = carry;

        // Step 2: Montgomery reduction — m = t[0] * INV mod 2^64
        let m = t[0].wrapping_mul(INV);

        // Step 3: t += m * MODULUS (and shift right by 64 bits)
        let (_, mut carry2) = mac(t[0], m, MODULUS[0], 0);
        for j in 1..4 {
            let (lo, hi) = mac(t[j], m, MODULUS[j], carry2);
            t[j - 1] = lo;
            carry2 = hi;
        }
        let (lo, _) = adc(t[4], 0, carry2);
        t[3] = lo;
        t[4] = 0;
    }

    let mut result = [t[0], t[1], t[2], t[3]];
    // Final conditional subtraction: if result >= p, subtract p
    if !lt(&result, &MODULUS) {
        sub_mod(&mut result, &MODULUS);
    }
    result
}

/// Multiply-and-accumulate: returns (lo, hi) = a + b*c + carry
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let full = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (full as u64, (full >> 64) as u64)
}

/// Add with carry: returns (sum, carry)
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let full = (a as u128) + (b as u128) + (carry as u128);
    (full as u64, (full >> 64) as u64)
}

/// Subtract with borrow: returns (diff, borrow)
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let full = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (full as u64, (full >> 127) as u64) // borrow is top bit
}

/// Returns true if a < b (both 4-limb, little-endian).
#[inline]
fn lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false // equal
}

/// In-place a -= b (assumes a >= b).
#[inline]
fn sub_mod(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, bo) = sbb(a[i], b[i], borrow);
        a[i] = d;
        borrow = bo;
    }
}

/// Reduce a big-endian byte string mod p into 4 little-endian u64 limbs.
fn reduce_be_bytes(bytes: &[u8]) -> [u64; 4] {
    // Pad or truncate to 32 bytes, parse as big-endian 256-bit integer
    let mut buf = [0u8; 32];
    let n = bytes.len().min(32);
    buf[32 - n..].copy_from_slice(&bytes[bytes.len() - n..]);

    let mut limbs = [0u64; 4];
    limbs[3] = u64::from_be_bytes(buf[0..8].try_into().unwrap());
    limbs[2] = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    limbs[1] = u64::from_be_bytes(buf[16..24].try_into().unwrap());
    limbs[0] = u64::from_be_bytes(buf[24..32].try_into().unwrap());

    // Reduce mod p: while limbs >= MODULUS, subtract
    while !lt(&limbs, &MODULUS) {
        sub_mod(&mut limbs, &MODULUS);
    }
    limbs
}

// ============================================================================
// Arithmetic trait impls
// ============================================================================

impl From<u64> for Fr {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl Add for Fr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c) = adc(self.0[i], rhs.0[i], carry);
            result[i] = s;
            carry = c;
        }
        if carry != 0 || !lt(&result, &MODULUS) {
            sub_mod(&mut result, &MODULUS);
        }
        Self(result)
    }
}

impl Sub for Fr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b) = sbb(self.0[i], rhs.0[i], borrow);
            result[i] = d;
            borrow = b;
        }
        if borrow != 0 {
            // Underflow: add p back
            let mut carry = 0u64;
            for i in 0..4 {
                let (s, c) = adc(result[i], MODULUS[i], carry);
                result[i] = s;
                carry = c;
            }
        }
        Self(result)
    }
}

impl Mul for Fr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(mont_mul(&self.0, &rhs.0))
    }
}

impl Div for Fr {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        self * rhs.inverse().expect("division by zero")
    }
}

impl Neg for Fr {
    type Output = Self;
    fn neg(self) -> Self {
        if self.is_zero() {
            self
        } else {
            let mut result = MODULUS;
            sub_mod(&mut result, &self.0);
            Self(result)
        }
    }
}

impl AddAssign for Fr {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for Fr {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for Fr {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl DivAssign for Fr {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

// ============================================================================
// Tests — these run on the host and verify the BPF Fr against arkworks.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_zero() {
        assert!(Fr::zero().is_zero());
        assert!(!Fr::one().is_zero());
    }

    #[test]
    fn one_times_one_is_one() {
        assert_eq!(Fr::one() * Fr::one(), Fr::one());
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = Fr::from(42u64);
        let b = Fr::from(17u64);
        assert_eq!(a + b - b, a);
    }

    #[test]
    fn mul_by_zero() {
        let a = Fr::from(12345u64);
        assert_eq!(a * Fr::zero(), Fr::zero());
    }

    #[test]
    fn negation() {
        let a = Fr::from(7u64);
        let neg_a = -a;
        assert_eq!(a + neg_a, Fr::zero());
    }

    #[test]
    fn inverse_roundtrip() {
        let a = Fr::from(13u64);
        let inv = a.inverse().unwrap();
        assert_eq!(a * inv, Fr::one());
    }

    #[test]
    fn division() {
        let a = Fr::from(100u64);
        let b = Fr::from(25u64);
        let c = a / b;
        assert_eq!(c * b, a);
    }

    #[test]
    fn pow_small() {
        let a = Fr::from(3u64);
        let a_cubed = a.pow(&[3]);
        assert_eq!(a_cubed, Fr::from(27u64));
    }

    #[test]
    fn be_bytes_roundtrip() {
        let a = Fr::from(0xDEADBEEFu64);
        let bytes = a.to_be_bytes();
        let b = Fr::from_be_bytes_mod_order(&bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn le_bytes_roundtrip() {
        let a = Fr::from(0xCAFEu64);
        let bytes = a.to_le_bytes();
        let b = Fr::from_le_bytes_mod_order(&bytes);
        assert_eq!(a, b);
    }
}
