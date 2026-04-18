//! Cross-backend G1 parity: BPF curve ops (host fallback) vs native (arkworks).
//!
//! Every test performs the same G1 operation on both backends and asserts
//! byte-identical affine encodings.

#[allow(dead_code)]
#[path = "../src/bpf/fr.rs"]
mod fr;

#[allow(dead_code)]
#[path = "../src/bpf/curve.rs"]
mod curve;

use curve::{G1Affine as BpfG1, G1Projective as BpfG1P};
use fr::Fr as BpfFr;
use genshi_math::{Fr, G1Affine, G1Projective};

fn xorshift(state: &mut u64) -> u64 {
    let mut s = *state;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *state = s;
    s
}

fn assert_g1_eq(native: G1Affine, bpf: BpfG1) {
    let nb = native.to_uncompressed_bytes();
    let bb = bpf.to_uncompressed_bytes();
    assert_eq!(nb, bb, "G1 byte mismatch");
}

fn assert_g1p_eq(native: G1Projective, bpf: BpfG1P) {
    assert_g1_eq(native.into_affine(), bpf.into_affine());
}

// ---- Basic parity -----------------------------------------------------------

#[test]
fn parity_generator() {
    assert_g1_eq(G1Affine::generator(), BpfG1::generator());
}

#[test]
fn parity_zero() {
    assert_g1_eq(G1Affine::zero(), BpfG1::zero());
}

#[test]
fn parity_scalar_mul_one() {
    let nat = G1Affine::generator() * Fr::one();
    let bpf = BpfG1::generator() * BpfFr::one();
    assert_g1p_eq(nat, bpf);
}

#[test]
fn parity_scalar_mul_zero() {
    let nat = G1Affine::generator() * Fr::zero();
    let bpf = BpfG1::generator() * BpfFr::zero();
    assert_g1p_eq(nat, bpf);
}

#[test]
fn parity_double() {
    let nat = {
        let g = G1Affine::generator().into_group();
        g + g
    };
    let bpf = {
        let g = BpfG1::generator().into_group();
        g + g
    };
    assert_g1p_eq(nat, bpf);
}

#[test]
fn parity_negate() {
    let nat = (-G1Affine::generator().into_group()).into_affine();
    let bpf = (-BpfG1::generator().into_group()).into_affine();
    assert_g1_eq(nat, bpf);
}

#[test]
fn parity_sub_cancel() {
    let nat = {
        let g = G1Affine::generator().into_group();
        (g - g).into_affine()
    };
    let bpf = {
        let g = BpfG1::generator().into_group();
        (g - g).into_affine()
    };
    assert_g1_eq(nat, bpf);
    assert!(nat.is_zero());
    assert!(bpf.is_zero());
}

// ---- 1k scalar mul ----------------------------------------------------------

#[test]
fn parity_1k_scalar_mul() {
    let mut rng = 0xBEEF_CAFE_DEAD_F00Du64;
    for _ in 0..1_000 {
        let s = xorshift(&mut rng);
        let nat = (G1Affine::generator() * Fr::from(s)).into_affine();
        let bpf = (BpfG1::generator() * BpfFr::from(s)).into_affine();
        assert_g1_eq(nat, bpf);
    }
}

// ---- 1k add (accumulate s_i * G) -------------------------------------------

#[test]
fn parity_1k_add() {
    let mut rng = 0xCAFE_BABE_1234_5678u64;
    let mut nat_acc = G1Projective::zero();
    let mut bpf_acc = BpfG1P::zero();

    for _ in 0..1_000 {
        let s = xorshift(&mut rng);
        nat_acc = nat_acc + (G1Affine::generator() * Fr::from(s));
        bpf_acc = bpf_acc + (BpfG1::generator() * BpfFr::from(s));
    }
    assert_g1p_eq(nat_acc, bpf_acc);
}

// ---- 1k negate --------------------------------------------------------------

#[test]
fn parity_1k_negate() {
    let mut rng = 0xFACE_FEED_0123_4567u64;
    for _ in 0..1_000 {
        let s = xorshift(&mut rng);
        let nat = (-(G1Affine::generator() * Fr::from(s))).into_affine();
        let bpf = (-(BpfG1::generator() * BpfFr::from(s))).into_affine();
        assert_g1_eq(nat, bpf);
    }
}

// ---- 1k sub -----------------------------------------------------------------

#[test]
fn parity_1k_sub() {
    let mut rng = 0xABCD_EF01_2345_6789u64;
    for _ in 0..1_000 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);
        let nat = {
            let pa = G1Affine::generator() * Fr::from(a);
            let pb = G1Affine::generator() * Fr::from(b);
            (pa - pb).into_affine()
        };
        let bpf = {
            let pa = BpfG1::generator() * BpfFr::from(a);
            let pb = BpfG1::generator() * BpfFr::from(b);
            (pa - pb).into_affine()
        };
        assert_g1_eq(nat, bpf);
    }
}

// ---- Chained mul-add (mirrors KZG batch accumulation) -----------------------

#[test]
fn parity_500_msm_accumulation() {
    let mut rng = 0x1337_C0DE_BEEF_CAFEu64;
    let mut nat_f = G1Projective::zero();
    let mut bpf_f = BpfG1P::zero();

    let nu_val = xorshift(&mut rng);
    let nat_nu = Fr::from(nu_val);
    let bpf_nu = BpfFr::from(nu_val);
    let mut nat_nu_pow = Fr::one();
    let mut bpf_nu_pow = BpfFr::one();

    for _ in 0..500 {
        let c_val = xorshift(&mut rng);
        let nat_c = G1Affine::generator() * Fr::from(c_val);
        let bpf_c = BpfG1::generator() * BpfFr::from(c_val);

        nat_f = nat_f + nat_c * nat_nu_pow;
        bpf_f = bpf_f + bpf_c * bpf_nu_pow;

        nat_nu_pow = nat_nu_pow * nat_nu;
        bpf_nu_pow = bpf_nu_pow * bpf_nu;
    }
    assert_g1p_eq(nat_f, bpf_f);
}

// ---- Verifier-style: commitment linear combination --------------------------

#[test]
fn parity_100_commitment_lincomb() {
    let mut rng = 0xDEAD_BEEF_FACE_FEEDu64;

    for _ in 0..100 {
        let a_val = xorshift(&mut rng);
        let b_val = xorshift(&mut rng);
        let c_val = xorshift(&mut rng);

        let nat = {
            let a = Fr::from(a_val);
            let b = Fr::from(b_val);
            let c = Fr::from(c_val);
            let g = G1Affine::generator();
            let p1 = g * a;
            let p2 = g * b;
            let p3 = g * c;
            (p1 + p2 - p3).into_affine()
        };
        let bpf = {
            let a = BpfFr::from(a_val);
            let b = BpfFr::from(b_val);
            let c = BpfFr::from(c_val);
            let g = BpfG1::generator();
            let p1 = g * a;
            let p2 = g * b;
            let p3 = g * c;
            (p1 + p2 - p3).into_affine()
        };
        assert_g1_eq(nat, bpf);
    }
}

// ---- Edge cases: large scalars ----------------------------------------------

#[test]
fn parity_large_scalars() {
    let scalars: &[u64] = &[
        u64::MAX,
        u64::MAX - 1,
        0x43e1f593f0000000,
        1,
        2,
        0xFFFF_FFFF_FFFF_FFFE,
    ];
    for &s in scalars {
        let nat = (G1Affine::generator() * Fr::from(s)).into_affine();
        let bpf = (BpfG1::generator() * BpfFr::from(s)).into_affine();
        assert_g1_eq(nat, bpf);
    }
}

// ---- AddAssign accumulation -------------------------------------------------

#[test]
fn parity_500_add_assign() {
    let mut rng = 0x0BAD_F00D_1234_ABCDu64;
    let mut nat_acc = G1Projective::zero();
    let mut bpf_acc = BpfG1P::zero();

    for _ in 0..500 {
        let s = xorshift(&mut rng);
        let nat_p = G1Affine::generator() * Fr::from(s);
        let bpf_p = BpfG1::generator() * BpfFr::from(s);
        nat_acc += nat_p;
        bpf_acc += bpf_p;
    }
    assert_g1p_eq(nat_acc, bpf_acc);
}

// ---- Double-and-add pattern -------------------------------------------------

#[test]
fn parity_double_and_add_chain() {
    let mut nat = G1Affine::generator().into_group();
    let mut bpf = BpfG1::generator().into_group();

    for _ in 0..200 {
        nat = nat + nat;
        bpf = bpf + bpf;
    }
    assert_g1p_eq(nat, bpf);
}

// ---- Identity arithmetic edge cases -----------------------------------------

#[test]
fn parity_identity_ops() {
    let nat_z = G1Projective::zero();
    let bpf_z = BpfG1P::zero();
    let nat_g = G1Affine::generator().into_group();
    let bpf_g = BpfG1::generator().into_group();

    assert_g1p_eq(nat_z + nat_g, bpf_z + bpf_g);
    assert_g1p_eq(nat_g + nat_z, bpf_g + bpf_z);
    assert_g1p_eq(nat_z + nat_z, bpf_z + bpf_z);
    assert_g1p_eq(nat_g - nat_z, bpf_g - bpf_z);
}

// ---- Projective scalar mul --------------------------------------------------

#[test]
fn parity_500_projective_scalar_mul() {
    let mut rng = 0x7777_8888_9999_AAAAu64;
    for _ in 0..500 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);
        let nat = {
            let p = G1Affine::generator() * Fr::from(a);
            (p * Fr::from(b)).into_affine()
        };
        let bpf = {
            let p = BpfG1::generator() * BpfFr::from(a);
            (p * BpfFr::from(b)).into_affine()
        };
        assert_g1_eq(nat, bpf);
    }
}
