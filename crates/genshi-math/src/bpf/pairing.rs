
//! BPF pairing check via `sol_alt_bn128_pairing`.
//!
//! The verifier calls `pairing_check(a1, b1, a2, b2)` which returns true iff
//! `e(a1, b1) · e(a2, b2) == 1` in GT. On BPF this routes through the Solana
//! syscall; on host builds it falls back to arkworks for testing.

use super::curve::{G1Affine, G2Affine};

/// 2-pair pairing check: `e(a1, b1) · e(a2, b2) == 1`.
pub fn pairing_check(a1: G1Affine, b1: G2Affine, a2: G1Affine, b2: G2Affine) -> bool {
    // Build the 384-byte input: [G1(64) || G2(128)] × 2
    let mut input = [0u8; 384];
    input[0..64].copy_from_slice(&a1.0);
    input[64..192].copy_from_slice(&b1.0);
    input[192..256].copy_from_slice(&a2.0);
    input[256..384].copy_from_slice(&b2.0);
    pairing_check_raw(&input)
}

#[cfg(target_os = "solana")]
fn pairing_check_raw(input: &[u8; 384]) -> bool {
    // solana-bn254 3.x renamed `alt_bn128_pairing` → `alt_bn128_pairing_be`.
    // The deprecated alias forwards to the BE form unchanged.
    let result = solana_bn254::prelude::alt_bn128_pairing_be(input)
        .expect("sol_alt_bn128_pairing_be failed");
    result[31] == 1 && result[..31].iter().all(|&b| b == 0)
}

#[cfg(all(not(target_os = "solana"), any(feature = "native", feature = "host-test")))]
fn pairing_check_raw(input: &[u8; 384]) -> bool {
    use ark_bn254::{Bn254, Fq, Fq2, G1Affine as ArkG1, G2Affine as ArkG2};
    use ark_ec::{pairing::Pairing, AffineRepr};
    use ark_ff::{PrimeField, Zero};

    fn decode_g1(bytes: &[u8]) -> ArkG1 {
        if bytes.iter().all(|&b| b == 0) {
            return ArkG1::zero();
        }
        let x = Fq::from_be_bytes_mod_order(&bytes[0..32]);
        let y = Fq::from_be_bytes_mod_order(&bytes[32..64]);
        ArkG1::new_unchecked(x, y)
    }

    fn decode_g2(bytes: &[u8]) -> ArkG2 {
        if bytes.iter().all(|&b| b == 0) {
            return ArkG2::zero();
        }
        let x1 = Fq::from_be_bytes_mod_order(&bytes[0..32]);
        let x0 = Fq::from_be_bytes_mod_order(&bytes[32..64]);
        let y1 = Fq::from_be_bytes_mod_order(&bytes[64..96]);
        let y0 = Fq::from_be_bytes_mod_order(&bytes[96..128]);
        ArkG2::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1))
    }

    let a1 = decode_g1(&input[0..64]);
    let b1 = decode_g2(&input[64..192]);
    let a2 = decode_g1(&input[192..256]);
    let b2 = decode_g2(&input[256..384]);

    let lhs = Bn254::pairing(a1, b1);
    let rhs = Bn254::pairing(a2, b2);
    (lhs + rhs).is_zero()
}

#[cfg(all(not(target_os = "solana"), not(any(feature = "native", feature = "host-test"))))]
fn pairing_check_raw(_input: &[u8; 384]) -> bool {
    unimplemented!("BPF pairing requires Solana target or host-test feature")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_identity() {
        // e(G1, G2) * e(-G1, G2) = 1
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let neg_g1 = (-g1.into_group()).into_affine();
        assert!(pairing_check(g1, g2, neg_g1, g2));
    }

    #[test]
    fn pairing_fails_for_nonidentity() {
        // e(G1, G2) * e(G1, G2) = e(G1, G2)^2 != 1
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        assert!(!pairing_check(g1, g2, g1, g2));
    }
}
