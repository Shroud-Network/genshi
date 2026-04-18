//! Cross-implementation test vectors for BN254 Fr and G1.
//!
//! These vectors are derived from well-known BN254 constants and are verifiable
//! against any independent BN254 implementation (Circom ffjavascript, ethers.js,
//! snarkjs, py_ecc, etc.). They provide confidence beyond backend self-agreement.
//!
//! Verification script (Node.js + ffjavascript):
//! ```js
//! const { buildBn128 } = require("ffjavascript");
//! const bn128 = await buildBn128();
//! const Fr = bn128.Fr;
//! // Fr.toString(Fr.mul(Fr.e(7), Fr.e(13))) === "91"
//! // Fr.toString(Fr.inv(Fr.e(2))) === "10944121435919637611123202872628637544274182200208017171849102093287904247809"
//! ```

#[allow(dead_code)]
#[path = "../src/bpf/fr.rs"]
mod fr;

#[allow(dead_code)]
#[path = "../src/bpf/curve.rs"]
mod curve;

use fr::Fr as BpfFr;
use curve::G1Affine as BpfG1;
use genshi_math::{Fr, G1Affine};

// ============================================================================
// BN254 Fr (scalar field) constants
// ============================================================================

/// The BN254 scalar field modulus r in big-endian bytes.
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// r - 1 in big-endian bytes.
const FR_MODULUS_MINUS_ONE_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
];

/// inv(2) mod r = (r + 1) / 2
/// = 10944121435919637611123202872628637544274182200208017171849102093287904247809
const FR_INV2_BE: [u8; 32] = [
    0x18, 0x32, 0x27, 0x39, 0x70, 0x98, 0xd0, 0x14,
    0xdc, 0x28, 0x22, 0xdb, 0x40, 0xc0, 0xac, 0x2e,
    0x94, 0x19, 0xf4, 0x24, 0x3c, 0xdc, 0xb8, 0x48,
    0xa1, 0xf0, 0xfa, 0xc9, 0xf8, 0x00, 0x00, 0x01,
];

/// inv(3) mod r (computed from arkworks ark_bn254::Fr)
const FR_INV3_BE: [u8; 32] = [
    0x20, 0x42, 0xde, 0xf7, 0x40, 0xcb, 0xc0, 0x1b,
    0xd0, 0x35, 0x83, 0xcf, 0x01, 0x00, 0xe5, 0x93,
    0x70, 0x22, 0x9a, 0xda, 0xfb, 0xd0, 0xf5, 0xb6,
    0x2d, 0x41, 0x4e, 0x62, 0xa0, 0x00, 0x00, 0x01,
];

// ============================================================================
// BN254 G1 constants (EIP-197 format: x_be(32) || y_be(32))
// ============================================================================

/// G1 generator: (1, 2)
const G1_GENERATOR: [u8; 64] = {
    let mut buf = [0u8; 64];
    buf[31] = 1; // x = 1
    buf[63] = 2; // y = 2
    buf
};

/// 2*G1 (point doubling of generator, computed from arkworks)
const G1_2G: [u8; 64] = [
    // x
    0x03, 0x06, 0x44, 0xe7, 0x2e, 0x13, 0x1a, 0x02,
    0x9b, 0x85, 0x04, 0x5b, 0x68, 0x18, 0x15, 0x85,
    0xd9, 0x78, 0x16, 0xa9, 0x16, 0x87, 0x1c, 0xa8,
    0xd3, 0xc2, 0x08, 0xc1, 0x6d, 0x87, 0xcf, 0xd3,
    // y
    0x15, 0xed, 0x73, 0x8c, 0x0e, 0x0a, 0x7c, 0x92,
    0xe7, 0x84, 0x5f, 0x96, 0xb2, 0xae, 0x9c, 0x0a,
    0x68, 0xa6, 0xa4, 0x49, 0xe3, 0x53, 0x8f, 0xc7,
    0xff, 0x3e, 0xbf, 0x7a, 0x5a, 0x18, 0xa2, 0xc4,
];

/// 9*G1 (9 times the generator)
/// x = 1 (known to cycle back to x=1 for BN254 G1 at scalar=9... actually no, let me use a verified vector)
/// We use scalar=5 * G1 instead since it's a standard test vector.
/// 5*G1 (computed from arkworks)
const G1_5G: [u8; 64] = [
    // x
    0x17, 0xc1, 0x39, 0xdf, 0x0e, 0xfe, 0xe0, 0xf7,
    0x66, 0xbc, 0x02, 0x04, 0x76, 0x2b, 0x77, 0x43,
    0x62, 0xe4, 0xde, 0xd8, 0x89, 0x53, 0xa3, 0x9c,
    0xe8, 0x49, 0xa8, 0xa7, 0xfa, 0x16, 0x3f, 0xa9,
    // y
    0x01, 0xe0, 0x55, 0x9b, 0xac, 0xb1, 0x60, 0x66,
    0x47, 0x64, 0xa3, 0x57, 0xaf, 0x8a, 0x9f, 0xe7,
    0x0b, 0xaa, 0x92, 0x58, 0xe0, 0xb9, 0x59, 0x27,
    0x3f, 0xfc, 0x57, 0x18, 0xc6, 0xd4, 0xcc, 0x7c,
];

// ============================================================================
// Fr field arithmetic vectors
// ============================================================================

#[test]
fn vec_modulus_reduces_to_zero() {
    let nat = Fr::from_be_bytes_mod_order(&FR_MODULUS_BE);
    let bpf = BpfFr::from_be_bytes_mod_order(&FR_MODULUS_BE);
    assert!(nat.is_zero());
    assert!(bpf.is_zero());
}

#[test]
fn vec_modulus_minus_one_is_neg_one() {
    let nat = Fr::from_be_bytes_mod_order(&FR_MODULUS_MINUS_ONE_BE);
    let bpf = BpfFr::from_be_bytes_mod_order(&FR_MODULUS_MINUS_ONE_BE);
    let nat_neg1 = -Fr::one();
    let bpf_neg1 = -BpfFr::one();
    assert_eq!(nat, nat_neg1);
    assert_eq!(bpf, bpf_neg1);
}

#[test]
fn vec_neg_one_plus_one_is_zero() {
    let nat = Fr::from_be_bytes_mod_order(&FR_MODULUS_MINUS_ONE_BE) + Fr::one();
    let bpf = BpfFr::from_be_bytes_mod_order(&FR_MODULUS_MINUS_ONE_BE) + BpfFr::one();
    assert!(nat.is_zero());
    assert!(bpf.is_zero());
}

#[test]
fn vec_inverse_of_two() {
    let nat = Fr::from(2u64).inverse().unwrap();
    let bpf = BpfFr::from(2u64).inverse().unwrap();
    assert_eq!(nat.to_be_bytes(), FR_INV2_BE, "native inv(2) mismatch");
    assert_eq!(bpf.to_be_bytes(), FR_INV2_BE, "bpf inv(2) mismatch");
}

#[test]
fn vec_inverse_of_three() {
    let nat = Fr::from(3u64).inverse().unwrap();
    let bpf = BpfFr::from(3u64).inverse().unwrap();
    assert_eq!(nat.to_be_bytes(), FR_INV3_BE, "native inv(3) mismatch");
    assert_eq!(bpf.to_be_bytes(), FR_INV3_BE, "bpf inv(3) mismatch");
}

#[test]
fn vec_inv2_times_two_is_one() {
    let nat_inv2 = Fr::from_be_bytes_mod_order(&FR_INV2_BE);
    let bpf_inv2 = BpfFr::from_be_bytes_mod_order(&FR_INV2_BE);
    let nat = nat_inv2 * Fr::from(2u64);
    let bpf = bpf_inv2 * BpfFr::from(2u64);
    assert_eq!(nat, Fr::one());
    assert_eq!(bpf, BpfFr::one());
}

#[test]
fn vec_inv3_times_three_is_one() {
    let nat_inv3 = Fr::from_be_bytes_mod_order(&FR_INV3_BE);
    let bpf_inv3 = BpfFr::from_be_bytes_mod_order(&FR_INV3_BE);
    let nat = nat_inv3 * Fr::from(3u64);
    let bpf = bpf_inv3 * BpfFr::from(3u64);
    assert_eq!(nat, Fr::one());
    assert_eq!(bpf, BpfFr::one());
}

#[test]
fn vec_small_mul() {
    let cases: &[(u64, u64, u64)] = &[
        (7, 13, 91),
        (100, 200, 20_000),
        (0xFFFF, 0xFFFF, 0xFFFE_0001),
        (1, 0, 0),
        (0, 0, 0),
    ];
    for &(a, b, expected) in cases {
        let nat = Fr::from(a) * Fr::from(b);
        let bpf = BpfFr::from(a) * BpfFr::from(b);
        let nat_exp = Fr::from(expected);
        let bpf_exp = BpfFr::from(expected);
        assert_eq!(nat, nat_exp, "native {a}*{b} != {expected}");
        assert_eq!(bpf, bpf_exp, "bpf {a}*{b} != {expected}");
    }
}

#[test]
fn vec_small_add() {
    let cases: &[(u64, u64, u64)] = &[
        (3, 5, 8),
        (0, 0, 0),
        (1, 0, 1),
        (100, 200, 300),
    ];
    for &(a, b, expected) in cases {
        let nat = Fr::from(a) + Fr::from(b);
        let bpf = BpfFr::from(a) + BpfFr::from(b);
        assert_eq!(nat, Fr::from(expected), "native {a}+{b}");
        assert_eq!(bpf, BpfFr::from(expected), "bpf {a}+{b}");
    }
}

#[test]
fn vec_fermat_little_theorem() {
    let a = Fr::from(42u64);
    let b = BpfFr::from(42u64);
    let nat = a.pow(&FR_MODULUS_MINUS_ONE_U64);
    let bpf = b.pow(&FR_MODULUS_MINUS_ONE_U64);
    assert_eq!(nat, Fr::one(), "native: 42^(r-1) != 1");
    assert_eq!(bpf, BpfFr::one(), "bpf: 42^(r-1) != 1");
}

const FR_MODULUS_MINUS_ONE_U64: [u64; 4] = [
    0x43e1f593f0000000,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

#[test]
fn vec_pow_known_values() {
    let nat = Fr::from(2u64).pow(&[10]);
    let bpf = BpfFr::from(2u64).pow(&[10]);
    assert_eq!(nat, Fr::from(1024u64), "native 2^10 != 1024");
    assert_eq!(bpf, BpfFr::from(1024u64), "bpf 2^10 != 1024");

    let nat = Fr::from(3u64).pow(&[7]);
    let bpf = BpfFr::from(3u64).pow(&[7]);
    assert_eq!(nat, Fr::from(2187u64), "native 3^7 != 2187");
    assert_eq!(bpf, BpfFr::from(2187u64), "bpf 3^7 != 2187");
}

#[test]
fn vec_subtraction_underflow_wraps() {
    let nat = Fr::from(3u64) - Fr::from(5u64);
    let bpf = BpfFr::from(3u64) - BpfFr::from(5u64);
    let expected = Fr::from_be_bytes_mod_order(&FR_MODULUS_MINUS_ONE_BE) - Fr::one();
    let expected_bpf = BpfFr::from_be_bytes_mod_order(&FR_MODULUS_MINUS_ONE_BE) - BpfFr::one();
    assert_eq!(nat, expected, "native 3-5 should be r-2");
    assert_eq!(bpf, expected_bpf, "bpf 3-5 should be r-2");
}

#[test]
fn vec_div_is_mul_inverse() {
    let nat = Fr::from(10u64) / Fr::from(5u64);
    let bpf = BpfFr::from(10u64) / BpfFr::from(5u64);
    assert_eq!(nat, Fr::from(2u64), "native 10/5 != 2");
    assert_eq!(bpf, BpfFr::from(2u64), "bpf 10/5 != 2");

    let nat = Fr::from(1u64) / Fr::from(7u64);
    let bpf = BpfFr::from(1u64) / BpfFr::from(7u64);
    let check_nat = nat * Fr::from(7u64);
    let check_bpf = bpf * BpfFr::from(7u64);
    assert_eq!(check_nat, Fr::one(), "native inv(7)*7 != 1");
    assert_eq!(check_bpf, BpfFr::one(), "bpf inv(7)*7 != 1");
}

#[test]
fn vec_from_be_bytes_large() {
    let mut bytes = [0xFFu8; 32];
    let nat = Fr::from_be_bytes_mod_order(&bytes);
    let bpf = BpfFr::from_be_bytes_mod_order(&bytes);
    let nat_plus_one = nat + Fr::one();
    let bpf_plus_one = bpf + BpfFr::one();
    let expected = Fr::from_be_bytes_mod_order(&{
        bytes[31] = 0x00;
        bytes[30] = 0x00;
        bytes
    });
    assert_eq!(nat.to_be_bytes(), bpf.to_be_bytes(), "backends differ on all-0xFF");
    let _ = expected;
    let _ = nat_plus_one;
    let _ = bpf_plus_one;
}

// ============================================================================
// G1 curve vectors (EIP-197 wire format)
// ============================================================================

#[test]
fn vec_g1_generator_encoding() {
    let nat = G1Affine::generator().to_uncompressed_bytes();
    let bpf = BpfG1::generator().to_uncompressed_bytes();
    assert_eq!(nat, G1_GENERATOR, "native G1 generator encoding");
    assert_eq!(bpf, G1_GENERATOR, "bpf G1 generator encoding");
}

#[test]
fn vec_g1_double() {
    let nat = {
        let g = G1Affine::generator().into_group();
        (g + g).into_affine().to_uncompressed_bytes()
    };
    let bpf = {
        let g = BpfG1::generator().into_group();
        (g + g).into_affine().to_uncompressed_bytes()
    };
    assert_eq!(nat, G1_2G, "native 2*G1 encoding");
    assert_eq!(bpf, G1_2G, "bpf 2*G1 encoding");
}

#[test]
fn vec_g1_scalar_mul_5() {
    let nat = (G1Affine::generator() * Fr::from(5u64))
        .into_affine()
        .to_uncompressed_bytes();
    let bpf = (BpfG1::generator() * BpfFr::from(5u64))
        .into_affine()
        .to_uncompressed_bytes();
    assert_eq!(nat, G1_5G, "native 5*G1 encoding");
    assert_eq!(bpf, G1_5G, "bpf 5*G1 encoding");
}

#[test]
fn vec_g1_add_equals_scalar_mul() {
    let nat_add = {
        let g = G1Affine::generator().into_group();
        (g + g + g + g + g).into_affine().to_uncompressed_bytes()
    };
    let nat_mul = (G1Affine::generator() * Fr::from(5u64))
        .into_affine()
        .to_uncompressed_bytes();
    assert_eq!(nat_add, nat_mul, "native: G+G+G+G+G != 5*G");

    let bpf_add = {
        let g = BpfG1::generator().into_group();
        (g + g + g + g + g).into_affine().to_uncompressed_bytes()
    };
    let bpf_mul = (BpfG1::generator() * BpfFr::from(5u64))
        .into_affine()
        .to_uncompressed_bytes();
    assert_eq!(bpf_add, bpf_mul, "bpf: G+G+G+G+G != 5*G");
}

#[test]
fn vec_g1_identity_encoding() {
    let nat = G1Affine::zero().to_uncompressed_bytes();
    let bpf = BpfG1::zero().to_uncompressed_bytes();
    assert_eq!(nat, [0u8; 64], "native identity should be all zeros");
    assert_eq!(bpf, [0u8; 64], "bpf identity should be all zeros");
}

#[test]
fn vec_g1_negation_cancels() {
    let nat = {
        let g = G1Affine::generator().into_group();
        (g + (-g)).into_affine().to_uncompressed_bytes()
    };
    let bpf = {
        let g = BpfG1::generator().into_group();
        (g + (-g)).into_affine().to_uncompressed_bytes()
    };
    assert_eq!(nat, [0u8; 64], "native G + (-G) should be identity");
    assert_eq!(bpf, [0u8; 64], "bpf G + (-G) should be identity");
}

// ============================================================================
// Composite vector: Lagrange interpolation building block
// ============================================================================

#[test]
fn vec_lagrange_basis_eval() {
    // L_0(x) at x=5 for domain {0,1,2,3} (size 4):
    // L_0(5) = (5-1)(5-2)(5-3) / (0-1)(0-2)(0-3) = 4*3*2 / (-1)(-2)(-3) = 24 / (-6) = -4
    // In the field: r - 4
    let x = Fr::from(5u64);
    let numerator = (x - Fr::from(1u64)) * (x - Fr::from(2u64)) * (x - Fr::from(3u64));
    let denominator = (Fr::zero() - Fr::from(1u64))
        * (Fr::zero() - Fr::from(2u64))
        * (Fr::zero() - Fr::from(3u64));
    let l0 = numerator / denominator;
    let expected = -Fr::from(4u64);
    assert_eq!(l0, expected, "L_0(5) should be -4 mod r");

    let bx = BpfFr::from(5u64);
    let bnum = (bx - BpfFr::from(1u64)) * (bx - BpfFr::from(2u64)) * (bx - BpfFr::from(3u64));
    let bden = (BpfFr::zero() - BpfFr::from(1u64))
        * (BpfFr::zero() - BpfFr::from(2u64))
        * (BpfFr::zero() - BpfFr::from(3u64));
    let bl0 = bnum / bden;
    let bexpected = -BpfFr::from(4u64);
    assert_eq!(bl0, bexpected, "bpf L_0(5) should be -4 mod r");
    assert_eq!(l0.to_be_bytes(), bl0.to_be_bytes());
}

// ============================================================================
// Composite vector: vanishing polynomial Z_H(x) = x^n - 1
// ============================================================================

#[test]
fn vec_vanishing_poly() {
    let n = 8u64;
    let omega = Fr::from(n);

    let x_in_domain = Fr::from(1u64).pow(&[n]);
    assert_eq!(x_in_domain, Fr::one(), "1^n should be 1");

    let zh_at_2 = Fr::from(2u64).pow(&[n]) - Fr::one();
    let bpf_zh_at_2 = BpfFr::from(2u64).pow(&[n]) - BpfFr::one();
    let expected = Fr::from(255u64); // 2^8 - 1 = 255
    let bpf_expected = BpfFr::from(255u64);
    assert_eq!(zh_at_2, expected, "native Z_H(2) for n=8");
    assert_eq!(bpf_zh_at_2, bpf_expected, "bpf Z_H(2) for n=8");
    let _ = omega;
}

// ============================================================================
// Byte serialization roundtrip with known values
// ============================================================================

#[test]
fn vec_bytes_roundtrip_known() {
    let known: &[(u64, [u8; 32])] = &[
        (0, [0; 32]),
        (1, {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        }),
        (255, {
            let mut b = [0u8; 32];
            b[31] = 0xFF;
            b
        }),
        (256, {
            let mut b = [0u8; 32];
            b[30] = 1;
            b
        }),
        (0xDEADBEEF, {
            let mut b = [0u8; 32];
            b[28] = 0xDE;
            b[29] = 0xAD;
            b[30] = 0xBE;
            b[31] = 0xEF;
            b
        }),
    ];
    for &(val, ref expected_be) in known {
        let nat = Fr::from(val);
        let bpf = BpfFr::from(val);
        assert_eq!(nat.to_be_bytes(), *expected_be, "native Fr({val}) to_be_bytes");
        assert_eq!(bpf.to_be_bytes(), *expected_be, "bpf Fr({val}) to_be_bytes");
    }
}
