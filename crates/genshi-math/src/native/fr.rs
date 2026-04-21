//! Native BN254 scalar field (`Fr`). Newtype over `ark_bn254::Fr` that exposes
//! only the operations the verifier actually uses, so the BPF backend only has
//! to reproduce this surface.

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, One as _, PrimeField, Zero as _};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// BN254 scalar field element.
///
/// `Copy` because the underlying limb representation is 4×u64 = 32 bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fr(pub(crate) ArkFr);

impl Fr {
    /// Additive identity.
    #[inline]
    pub fn zero() -> Self {
        Self(ArkFr::zero())
    }

    /// Multiplicative identity.
    #[inline]
    pub fn one() -> Self {
        Self(ArkFr::one())
    }

    /// Return `true` iff `self == 0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Reduce a big-endian byte string modulo the BN254 scalar order.
    ///
    /// Used to turn 32-byte Keccak outputs into challenge scalars. Accepts any
    /// length; excess bits are reduced.
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        Self(ArkFr::from_be_bytes_mod_order(bytes))
    }

    /// Reduce a little-endian byte string modulo the BN254 scalar order.
    ///
    /// Matches the Solana instruction-data convention where public inputs are
    /// passed as 32-byte LE chunks. Accepts any length; excess bits are reduced.
    pub fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        Self(ArkFr::from_le_bytes_mod_order(bytes))
    }

    /// 32-byte big-endian encoding of this scalar.
    ///
    /// Matches the on-chain `uint256` layout so a Solidity verifier can absorb
    /// `abi.encodePacked(scalar)` directly into its Keccak transcript.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let repr = self.0.into_bigint().to_bytes_be();
        debug_assert_eq!(repr.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&repr);
        out
    }

    /// 32-byte little-endian encoding of this scalar.
    ///
    /// Matches the Solana instruction-data convention used by
    /// `genshi-solana`'s public-input encoder and `Fr::from_le_bytes_mod_order`.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let repr = self.0.into_bigint().to_bytes_le();
        debug_assert_eq!(repr.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&repr);
        out
    }

    /// Strict canonical decode from 32 big-endian bytes.
    ///
    /// Returns `None` if the integer encoded in `bytes` is >= the Fr modulus.
    /// This is the verifier-side counterpart of `to_be_bytes`: a successful
    /// decode followed by re-encoding produces the exact same bytes, so proofs
    /// and VKs round-trip deterministically.
    pub fn from_be_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let reduced = Self::from_be_bytes_mod_order(bytes);
        if reduced.to_be_bytes() == *bytes {
            Some(reduced)
        } else {
            None
        }
    }

    /// Strict canonical decode from 32 little-endian bytes.
    ///
    /// Returns `None` if the integer encoded in `bytes` is >= the Fr modulus.
    /// Verifier-side counterpart of `to_le_bytes` and the CLI's
    /// `public_inputs.bin` format (LE per-element, written by
    /// `public_inputs_to_bytes_le`).
    pub fn from_le_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let reduced = Self::from_le_bytes_mod_order(bytes);
        if reduced.to_le_bytes() == *bytes {
            Some(reduced)
        } else {
            None
        }
    }

    /// `self^exp`, with `exp` given as little-endian u64 limbs.
    ///
    /// Matches `ark_ff::Field::pow`'s semantics so `zeta.pow(&[n as u64])`
    /// means `zeta^n` regardless of backend.
    pub fn pow(&self, exp: &[u64]) -> Self {
        Self(<ArkFr as ark_ff::Field>::pow(&self.0, exp))
    }

    /// Multiplicative inverse; `None` when `self` is zero.
    ///
    /// The verifier never calls `inverse()` directly — it uses `/`, which is
    /// implemented on top of this. Exposed separately because the BPF backend
    /// implements `inverse` via Fermat's little theorem and reuses it.
    pub fn inverse(&self) -> Option<Self> {
        <ArkFr as ark_ff::Field>::inverse(&self.0).map(Self)
    }

    /// Invert every element of `values` in place using Montgomery's trick.
    ///
    /// One field inversion for the whole batch; zeros are left untouched
    /// (invariant: `values[i].is_zero()` implies `values[i]` stays zero).
    ///
    /// Used by the verifier to collapse 5+ Fermat-style inversions in the
    /// public-input Lagrange loop into a single inversion — the single biggest
    /// CU reduction on the BPF backend.
    pub fn batch_inverse(values: &mut [Self]) {
        use ark_ff::fields::batch_inversion;
        let mut ark_values: Vec<ArkFr> = values.iter().map(|v| v.0).collect();
        batch_inversion(&mut ark_values);
        for (slot, inv) in values.iter_mut().zip(ark_values.into_iter()) {
            slot.0 = inv;
        }
    }

    /// Lift a small non-negative integer.
    #[inline]
    pub fn from_u64(v: u64) -> Self {
        Self(ArkFr::from(v))
    }

    /// **Native-backend-only.** Wrap an `ark_bn254::Fr` value.
    ///
    /// The prover computes in ark-world; this is how it packages results into
    /// a `Proof`/`VerificationKey` that the backend-agnostic verifier can read.
    /// This method does not exist on the BPF backend, which is fine because
    /// the prover never runs on BPF.
    #[inline]
    pub fn from_ark(inner: ArkFr) -> Self {
        Self(inner)
    }

    /// **Native-backend-only.** Unwrap to `ark_bn254::Fr`.
    #[inline]
    pub fn to_ark(self) -> ArkFr {
        self.0
    }

    /// Access the inner `ark_bn254::Fr` by reference. Native-only escape hatch
    /// for code paths that aren't worth converting (e.g. one-off `ark_ff`
    /// utilities used during test setup).
    #[inline]
    pub fn as_ark(&self) -> &ArkFr {
        &self.0
    }
}

impl From<u64> for Fr {
    #[inline]
    fn from(v: u64) -> Self {
        Self::from_u64(v)
    }
}

// ----------------------------------------------------------------------------
// Operator impls. Each one forwards to the underlying ark_bn254::Fr and
// re-wraps the result. Covers every operator the verifier uses.
// ----------------------------------------------------------------------------

macro_rules! binop {
    ($trait:ident, $method:ident, $op:tt) => {
        impl $trait for Fr {
            type Output = Fr;
            #[inline]
            fn $method(self, rhs: Fr) -> Fr {
                Fr(self.0 $op rhs.0)
            }
        }
        impl $trait<&Fr> for Fr {
            type Output = Fr;
            #[inline]
            fn $method(self, rhs: &Fr) -> Fr {
                Fr(self.0 $op rhs.0)
            }
        }
        impl $trait<Fr> for &Fr {
            type Output = Fr;
            #[inline]
            fn $method(self, rhs: Fr) -> Fr {
                Fr(self.0 $op rhs.0)
            }
        }
        impl $trait<&Fr> for &Fr {
            type Output = Fr;
            #[inline]
            fn $method(self, rhs: &Fr) -> Fr {
                Fr(self.0 $op rhs.0)
            }
        }
    };
}

binop!(Add, add, +);
binop!(Sub, sub, -);
binop!(Mul, mul, *);
binop!(Div, div, /);

impl Neg for Fr {
    type Output = Fr;
    #[inline]
    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}

impl Neg for &Fr {
    type Output = Fr;
    #[inline]
    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}

macro_rules! binop_assign {
    ($trait:ident, $method:ident, $op:tt) => {
        impl $trait for Fr {
            #[inline]
            fn $method(&mut self, rhs: Fr) {
                self.0 $op rhs.0;
            }
        }
        impl $trait<&Fr> for Fr {
            #[inline]
            fn $method(&mut self, rhs: &Fr) {
                self.0 $op rhs.0;
            }
        }
    };
}

binop_assign!(AddAssign, add_assign, +=);
binop_assign!(SubAssign, sub_assign, -=);
binop_assign!(MulAssign, mul_assign, *=);
binop_assign!(DivAssign, div_assign, /=);

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_one_distinct() {
        assert!(Fr::zero().is_zero());
        assert!(!Fr::one().is_zero());
        assert_ne!(Fr::zero(), Fr::one());
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = Fr::from(42u64);
        let b = Fr::from(7u64);
        assert_eq!((a + b) - b, a);
        assert_eq!(a - a, Fr::zero());
    }

    #[test]
    fn mul_div_roundtrip() {
        let a = Fr::from(13u64);
        let b = Fr::from(99u64);
        assert_eq!((a * b) / b, a);
        assert_eq!(a * Fr::one(), a);
        assert_eq!(a * Fr::zero(), Fr::zero());
    }

    #[test]
    fn neg_matches_subtraction() {
        let a = Fr::from(5u64);
        assert_eq!(-a, Fr::zero() - a);
        assert_eq!(a + (-a), Fr::zero());
    }

    #[test]
    fn assign_ops() {
        let mut a = Fr::from(10u64);
        a += Fr::from(5u64);
        assert_eq!(a, Fr::from(15u64));
        a -= Fr::from(3u64);
        assert_eq!(a, Fr::from(12u64));
        a *= Fr::from(2u64);
        assert_eq!(a, Fr::from(24u64));
        a /= Fr::from(4u64);
        assert_eq!(a, Fr::from(6u64));
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let a = Fr::from(3u64);
        // 3^5 = 243
        assert_eq!(a.pow(&[5u64]), Fr::from(243u64));
        // 3^0 = 1
        assert_eq!(a.pow(&[0u64]), Fr::one());
    }

    #[test]
    fn inverse_times_self_is_one() {
        let a = Fr::from(7u64);
        let inv = a.inverse().expect("7 is nonzero");
        assert_eq!(a * inv, Fr::one());
        assert!(Fr::zero().inverse().is_none());
    }

    #[test]
    fn be_bytes_roundtrip_for_small_values() {
        let a = Fr::from(0x1234_5678_9abc_def0u64);
        let bytes = a.to_be_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(Fr::from_be_bytes_mod_order(&bytes), a);
    }

    #[test]
    fn be_bytes_zero_is_all_zero() {
        assert_eq!(Fr::zero().to_be_bytes(), [0u8; 32]);
    }

    #[test]
    fn from_be_bytes_reduces_modulo_order() {
        // All-ones is > modulus; confirm reduction produces a valid scalar.
        let reduced = Fr::from_be_bytes_mod_order(&[0xffu8; 32]);
        // No panic is the guarantee we care about here; also check it round-trips.
        let bytes = reduced.to_be_bytes();
        assert_eq!(Fr::from_be_bytes_mod_order(&bytes), reduced);
    }
}
