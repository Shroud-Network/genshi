//! Cross-backend parity tests for Fr.
//!
//! Runs BPF Fr against arkworks Fr on the same inputs and asserts byte-
//! identical outputs. This is the contract that keeps the verifier correct
//! across backends.
//!
//! These tests compile BOTH backends in the same binary (the bpf module is
//! imported directly by path, the native backend through arkworks). They
//! always run under `--features native` (the default) so arkworks is
//! available.

#![cfg(feature = "native")]

#[path = "../src/bpf/fr.rs"]
mod bpf_fr;

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

fn bpf_from_ark(ark: ArkFr) -> bpf_fr::Fr {
    let bytes = ark.into_bigint().to_bytes_be();
    bpf_fr::Fr::from_be_bytes_mod_order(&bytes)
}

fn assert_parity(ark: ArkFr, bpf: bpf_fr::Fr) {
    let ark_bytes = ark.into_bigint().to_bytes_be();
    let bpf_bytes = bpf.to_be_bytes();
    assert_eq!(ark_bytes, bpf_bytes, "parity violation");
}

// ============================================================================
// Basic identity tests
// ============================================================================

#[test]
fn parity_zero() {
    assert_parity(ArkFr::zero(), bpf_fr::Fr::zero());
}

#[test]
fn parity_one() {
    assert_parity(ArkFr::one(), bpf_fr::Fr::one());
}

#[test]
fn parity_from_u64() {
    for &v in &[0u64, 1, 2, 42, 255, 1000, u64::MAX] {
        assert_parity(ArkFr::from(v), bpf_fr::Fr::from(v));
    }
}

// ============================================================================
// Small-set targeted tests
// ============================================================================

#[test]
fn parity_add() {
    let pairs: Vec<(u64, u64)> = vec![
        (0, 0), (1, 1), (42, 58), (u64::MAX, 1), (u64::MAX, u64::MAX),
    ];
    for (a, b) in pairs {
        let ark = ArkFr::from(a) + ArkFr::from(b);
        let bpf = bpf_fr::Fr::from(a) + bpf_fr::Fr::from(b);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_sub() {
    let pairs: Vec<(u64, u64)> = vec![
        (100, 42), (0, 0), (1, 1), (42, 100),
    ];
    for (a, b) in pairs {
        let ark = ArkFr::from(a) - ArkFr::from(b);
        let bpf = bpf_fr::Fr::from(a) - bpf_fr::Fr::from(b);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_mul() {
    let pairs: Vec<(u64, u64)> = vec![
        (0, 42), (1, 1), (3, 7), (12345, 67890), (u64::MAX, u64::MAX),
    ];
    for (a, b) in pairs {
        let ark = ArkFr::from(a) * ArkFr::from(b);
        let bpf = bpf_fr::Fr::from(a) * bpf_fr::Fr::from(b);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_neg() {
    for &v in &[0u64, 1, 42, u64::MAX] {
        let ark = -ArkFr::from(v);
        let bpf = -bpf_fr::Fr::from(v);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_inverse() {
    for &v in &[1u64, 2, 7, 42, 12345, u64::MAX] {
        let ark = ArkFr::from(v).inverse().unwrap();
        let bpf = bpf_fr::Fr::from(v).inverse().unwrap();
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_pow() {
    let a_ark = ArkFr::from(3u64);
    let a_bpf = bpf_fr::Fr::from(3u64);
    for &exp in &[0u64, 1, 2, 10, 100, 1000] {
        let ark = a_ark.pow([exp]);
        let bpf = a_bpf.pow(&[exp]);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_from_be_bytes() {
    let cases: &[&[u8]] = &[
        &[0; 32],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        &[0xFF; 32],
    ];
    for &bytes in cases {
        let ark = ArkFr::from_be_bytes_mod_order(bytes);
        let bpf = bpf_fr::Fr::from_be_bytes_mod_order(bytes);
        assert_parity(ark, bpf);
    }
}

// ============================================================================
// Large-scale Fr parity: 10 000 chained operations
// ============================================================================

/// Deterministic PRNG: xorshift64 seeded from a step counter.
/// Not cryptographic — just gives us reproducible, well-distributed u64s.
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn parity_10k_add() {
    let mut rng = 0xDEAD_BEEF_CAFE_BABEu64;
    for _ in 0..10_000 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);
        let ark = ArkFr::from(a) + ArkFr::from(b);
        let bpf = bpf_fr::Fr::from(a) + bpf_fr::Fr::from(b);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_10k_sub() {
    let mut rng = 0x1234_5678_9ABC_DEF0u64;
    for _ in 0..10_000 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);
        let ark = ArkFr::from(a) - ArkFr::from(b);
        let bpf = bpf_fr::Fr::from(a) - bpf_fr::Fr::from(b);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_10k_mul() {
    let mut rng = 0xAAAA_BBBB_CCCC_DDDDu64;
    for _ in 0..10_000 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);
        let ark = ArkFr::from(a) * ArkFr::from(b);
        let bpf = bpf_fr::Fr::from(a) * bpf_fr::Fr::from(b);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_10k_chained_mul_add_sub() {
    let mut ark_acc = ArkFr::from(1u64);
    let mut bpf_acc = bpf_fr::Fr::from(1u64);
    let mut rng = 0xFEED_FACE_0BAD_F00Du64;

    for i in 0..10_000u64 {
        let v = xorshift(&mut rng);
        match i % 3 {
            0 => {
                ark_acc = ark_acc + ArkFr::from(v);
                bpf_acc = bpf_acc + bpf_fr::Fr::from(v);
            }
            1 => {
                ark_acc = ark_acc * ArkFr::from(v);
                bpf_acc = bpf_acc * bpf_fr::Fr::from(v);
            }
            _ => {
                ark_acc = ark_acc - ArkFr::from(v);
                bpf_acc = bpf_acc - bpf_fr::Fr::from(v);
            }
        }
    }
    assert_parity(ark_acc, bpf_acc);
}

#[test]
fn parity_10k_neg() {
    let mut rng = 0x0011_2233_4455_6677u64;
    for _ in 0..10_000 {
        let v = xorshift(&mut rng);
        let ark = -ArkFr::from(v);
        let bpf = -bpf_fr::Fr::from(v);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_1k_inverse() {
    let mut rng = 0xBAD0_CAFE_1337_BEEFu64;
    for _ in 0..1_000 {
        let v = xorshift(&mut rng);
        if v == 0 { continue; }
        let ark = ArkFr::from(v).inverse().unwrap();
        let bpf = bpf_fr::Fr::from(v).inverse().unwrap();
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_1k_pow() {
    let mut rng = 0x7777_8888_9999_AAAAu64;
    for _ in 0..1_000 {
        let base = xorshift(&mut rng);
        let exp = xorshift(&mut rng) % 256;
        let ark = ArkFr::from(base).pow([exp]);
        let bpf = bpf_fr::Fr::from(base).pow(&[exp]);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_1k_from_be_bytes() {
    let mut rng = 0xC0DE_D00D_FACE_B00Cu64;
    for _ in 0..1_000 {
        let mut bytes = [0u8; 32];
        for b in bytes.iter_mut() {
            *b = (xorshift(&mut rng) & 0xFF) as u8;
        }
        let ark = ArkFr::from_be_bytes_mod_order(&bytes);
        let bpf = bpf_fr::Fr::from_be_bytes_mod_order(&bytes);
        assert_parity(ark, bpf);
    }
}

#[test]
fn parity_1k_be_le_roundtrip() {
    let mut rng = 0xABCD_EF01_2345_6789u64;
    for _ in 0..1_000 {
        let v = xorshift(&mut rng);
        let bpf_val = bpf_fr::Fr::from(v);
        let be = bpf_val.to_be_bytes();
        let le = bpf_val.to_le_bytes();
        let from_be = bpf_fr::Fr::from_be_bytes_mod_order(&be);
        let from_le = bpf_fr::Fr::from_le_bytes_mod_order(&le);
        assert_eq!(bpf_val, from_be, "BE roundtrip failed for {v}");
        assert_eq!(bpf_val, from_le, "LE roundtrip failed for {v}");
    }
}

// ============================================================================
// Large-value Fr parity (multi-limb scalars near the modulus)
// ============================================================================

#[test]
fn parity_near_modulus_ops() {
    // p-1, p-2, and values that exercise carry/borrow across limbs
    let near_p: &[&[u8]] = &[
        // p - 1
        &[0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
          0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
          0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
          0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00],
        // p - 2
        &[0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
          0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
          0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x90,
          0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00],
        // (2^128 - 1) — crosses a limb boundary
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    ];

    for &a_bytes in near_p {
        for &b_bytes in near_p {
            let ark_a = ArkFr::from_be_bytes_mod_order(a_bytes);
            let ark_b = ArkFr::from_be_bytes_mod_order(b_bytes);
            let bpf_a = bpf_fr::Fr::from_be_bytes_mod_order(a_bytes);
            let bpf_b = bpf_fr::Fr::from_be_bytes_mod_order(b_bytes);

            assert_parity(ark_a + ark_b, bpf_a + bpf_b);
            assert_parity(ark_a - ark_b, bpf_a - bpf_b);
            assert_parity(ark_a * ark_b, bpf_a * bpf_b);
            assert_parity(-ark_a, -bpf_a);

            if !ark_a.is_zero() {
                assert_parity(ark_a.inverse().unwrap(), bpf_a.inverse().unwrap());
            }
        }
    }
}

// ============================================================================
// Transcript-simulation parity (what the verifier actually does)
// ============================================================================

#[test]
fn parity_transcript_challenge_simulation() {
    // Simulates the Fiat-Shamir pattern: absorb 32-byte "hash output",
    // squeeze into Fr, do field ops, repeat. This is the hottest Fr path
    // in the verifier.
    let mut ark_acc = ArkFr::one();
    let mut bpf_acc = bpf_fr::Fr::one();
    let mut rng = 0x5EED_0000_0000_0001u64;

    for _ in 0..500 {
        // Simulate a 32-byte Keccak squeeze
        let mut challenge = [0u8; 32];
        for b in challenge.iter_mut() {
            *b = (xorshift(&mut rng) & 0xFF) as u8;
        }

        let ark_ch = ArkFr::from_be_bytes_mod_order(&challenge);
        let bpf_ch = bpf_fr::Fr::from_be_bytes_mod_order(&challenge);

        // Typical verifier ops: accumulate with powers of challenge
        ark_acc = ark_acc * ark_ch + ark_ch;
        bpf_acc = bpf_acc * bpf_ch + bpf_ch;
    }
    assert_parity(ark_acc, bpf_acc);
}

#[test]
fn parity_vanishing_poly_eval() {
    // z_H(zeta) = zeta^n - 1, the pattern used in every PLONK verifier
    let mut rng = 0xAAAA_0000_BBBB_1111u64;
    for _ in 0..100 {
        let mut zeta_bytes = [0u8; 32];
        for b in zeta_bytes.iter_mut() {
            *b = (xorshift(&mut rng) & 0xFF) as u8;
        }
        let n = (xorshift(&mut rng) % 1024 + 8) as u64;

        let ark_z = ArkFr::from_be_bytes_mod_order(&zeta_bytes);
        let bpf_z = bpf_fr::Fr::from_be_bytes_mod_order(&zeta_bytes);

        let ark_zh = ark_z.pow([n]) - ArkFr::one();
        let bpf_zh = bpf_z.pow(&[n]) - bpf_fr::Fr::one();

        assert_parity(ark_zh, bpf_zh);
    }
}

// ============================================================================
// Division parity (mul by inverse)
// ============================================================================

#[test]
fn parity_1k_div() {
    let mut rng = 0xD1D1_D3D0_CAFE_BABEu64;
    for _ in 0..1_000 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);
        if b == 0 { continue; }
        let ark = ArkFr::from(a) / ArkFr::from(b);
        let bpf = bpf_fr::Fr::from(a) / bpf_fr::Fr::from(b);
        assert_parity(ark, bpf);
    }
}

// ============================================================================
// from_ark helper parity
// ============================================================================

#[test]
fn parity_1k_from_ark_roundtrip() {
    let mut rng = 0xF00D_0000_1234_ABCDu64;
    for _ in 0..1_000 {
        let v = xorshift(&mut rng);
        let ark_val = ArkFr::from(v) * ArkFr::from(v);
        let bpf_val = bpf_from_ark(ark_val);
        assert_parity(ark_val, bpf_val);
    }
}
