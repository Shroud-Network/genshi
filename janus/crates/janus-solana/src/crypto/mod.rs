//! Cryptographic verification module for Solana BPF target.
//!
//! Provides wrappers around BN254 operations. On the actual Solana BPF
//! target, `pairing_check_2` routes through `sol_alt_bn128_pairing` via the
//! `solana-program` crate (~280K CU per 2-pair check). On native targets
//! (used for tests, CLI, and host-side verification), it falls back to the
//! arkworks pairing engine.
//!
//! Solana BN254 syscalls (available since v1.16):
//! - `sol_alt_bn128_addition`:       ~1K CU
//! - `sol_alt_bn128_multiplication`: ~14K CU
//! - `sol_alt_bn128_pairing`:        ~280K CU per 2-pair check

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInteger, PrimeField, Zero};

/// Length of a serialized pairing element (G1 || G2) on Solana, in bytes.
const PAIRING_ELEMENT_LEN: usize = 192;

/// Encode a G1Affine point as 64 bytes for Solana syscall input.
///
/// Format: [x: 32 bytes BE] [y: 32 bytes BE]
/// Solana's `sol_alt_bn128_pairing` syscall expects big-endian encoding,
/// matching the EIP-197 wire format.
pub fn g1_to_be_bytes(point: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if point.is_zero() {
        return out;
    }
    let x: ark_bn254::Fq = point.x().unwrap();
    let y: ark_bn254::Fq = point.y().unwrap();
    out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
    out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
    out
}

/// Encode a G2Affine point as 128 bytes for Solana syscall input.
///
/// Format: `[x1: 32 BE] [x0: 32 BE] [y1: 32 BE] [y0: 32 BE]`
/// (Fp2 encoded as c1 || c0, matching EIP-197 / Solana convention.)
pub fn g2_to_be_bytes(point: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if point.is_zero() {
        return out;
    }
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    out[0..32].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
    out[32..64].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
    out[64..96].copy_from_slice(&y.c1.into_bigint().to_bytes_be());
    out[96..128].copy_from_slice(&y.c0.into_bigint().to_bytes_be());
    out
}

/// Serialize a (G1, G2) pair into the 192-byte layout the Solana pairing
/// syscall consumes.
pub fn pairing_pair_to_be_bytes(g1: &G1Affine, g2: &G2Affine) -> [u8; PAIRING_ELEMENT_LEN] {
    let mut out = [0u8; PAIRING_ELEMENT_LEN];
    out[0..64].copy_from_slice(&g1_to_be_bytes(g1));
    out[64..192].copy_from_slice(&g2_to_be_bytes(g2));
    out
}

/// Perform a 2-pair pairing check: `e(A1, B1) * e(A2, B2) == 1`.
///
/// On Solana BPF (`target_os = "solana"`), this calls `sol_alt_bn128_pairing`
/// via the `solana-program` crate, costing ~280K CU. On native, it falls
/// back to arkworks `Bn254::multi_pairing`, used by the host-side tests and
/// any off-chain verification path (CLI, server).
pub fn pairing_check_2(
    a1: &G1Affine,
    b1: &G2Affine,
    a2: &G1Affine,
    b2: &G2Affine,
) -> bool {
    #[cfg(target_os = "solana")]
    {
        // 384-byte input = two 192-byte (G1 || G2) pairs in big-endian.
        let mut input = [0u8; 2 * PAIRING_ELEMENT_LEN];
        input[..PAIRING_ELEMENT_LEN].copy_from_slice(&pairing_pair_to_be_bytes(a1, b1));
        input[PAIRING_ELEMENT_LEN..].copy_from_slice(&pairing_pair_to_be_bytes(a2, b2));

        // `alt_bn128_pairing` returns a 32-byte result where the final byte
        // is `1` if the product of pairings equals the identity element in
        // GT (i.e., the pairing check passes) and `0` otherwise.
        match solana_program::alt_bn128::prelude::alt_bn128_pairing(&input) {
            Ok(result) => result.len() == 32 && result[31] == 1,
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "solana"))]
    {
        // Native / host-side path: use the arkworks pairing engine.
        Bn254::multi_pairing([*a1, *a2], [*b1, *b2]).is_zero()
    }
}

/// Compute G2 point: `tau*G2 - scalar*G2`. Used for the KZG pairing RHS.
pub fn compute_g2_rhs(g2: &G2Affine, g2_tau: &G2Affine, scalar: &Fr) -> G2Affine {
    let scaled = g2.into_group() * scalar;
    (g2_tau.into_group() - scaled).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_encoding() {
        let g1_gen = G1Affine::generator();
        let bytes = g1_to_be_bytes(&g1_gen);
        // G1 generator: x=1, y=2
        assert_eq!(bytes[31], 1); // Last byte of x
        assert_eq!(bytes[63], 2); // Last byte of y
    }

    #[test]
    fn test_g1_encoding_identity_is_zero() {
        let identity = G1Affine::zero();
        assert_eq!(g1_to_be_bytes(&identity), [0u8; 64]);
    }

    #[test]
    fn test_g2_encoding_nonzero() {
        let g2_gen = G2Affine::generator();
        let bytes = g2_to_be_bytes(&g2_gen);
        assert_ne!(&bytes[..32], &[0u8; 32], "G2 x1 should not be zero");
    }

    #[test]
    fn test_pairing_pair_layout() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let pair = pairing_pair_to_be_bytes(&g1, &g2);
        assert_eq!(&pair[..64], &g1_to_be_bytes(&g1));
        assert_eq!(&pair[64..], &g2_to_be_bytes(&g2));
    }

    #[test]
    fn test_pairing_check_identity() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let neg_g1 = (-g1.into_group()).into_affine();
        // e(G1, G2) * e(-G1, G2) = 1
        assert!(pairing_check_2(&g1, &g2, &neg_g1, &g2));
    }

    #[test]
    fn test_pairing_check_fails_for_nontrivial_inputs() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        // e(G1, G2) * e(G1, G2) = e(G1, G2)^2 != 1
        assert!(!pairing_check_2(&g1, &g2, &g1, &g2));
    }
}
