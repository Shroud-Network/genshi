//! Cross-backend pairing parity: BPF pairing_check (host fallback) vs
//! native (arkworks). Both backends must agree on e(A,B)·e(C,D)==1.

#[allow(dead_code)]
#[path = "../src/bpf/fr.rs"]
mod fr;

#[allow(dead_code)]
#[path = "../src/bpf/curve.rs"]
mod curve;

#[allow(dead_code)]
#[path = "../src/bpf/pairing.rs"]
mod pairing;

use curve::{G1Affine as BpfG1, G2Affine as BpfG2};
use fr::Fr as BpfFr;
use pairing::pairing_check as bpf_pairing_check;
use genshi_math::{pairing_check as native_pairing_check, Fr, G1Affine, G2Affine};

fn xorshift(state: &mut u64) -> u64 {
    let mut s = *state;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *state = s;
    s
}

// ---- Basic identity checks --------------------------------------------------

#[test]
fn parity_identity_pair() {
    let nat = native_pairing_check(
        G1Affine::zero(),
        G2Affine::generator(),
        G1Affine::zero(),
        G2Affine::generator(),
    );
    let bpf = bpf_pairing_check(
        BpfG1::zero(),
        BpfG2::generator(),
        BpfG1::zero(),
        BpfG2::generator(),
    );
    assert_eq!(nat, bpf);
    assert!(nat);
}

#[test]
fn parity_generator_cancel() {
    let nat = {
        let g1 = G1Affine::generator();
        let neg_g1 = (-g1.into_group()).into_affine();
        let g2 = G2Affine::generator();
        native_pairing_check(g1, g2, neg_g1, g2)
    };
    let bpf = {
        let g1 = BpfG1::generator();
        let neg_g1 = (-g1.into_group()).into_affine();
        let g2 = BpfG2::generator();
        bpf_pairing_check(g1, g2, neg_g1, g2)
    };
    assert_eq!(nat, bpf);
    assert!(nat);
}

#[test]
fn parity_unbalanced_fails() {
    let nat = {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        native_pairing_check(g1, g2, g1, g2)
    };
    let bpf = {
        let g1 = BpfG1::generator();
        let g2 = BpfG2::generator();
        bpf_pairing_check(g1, g2, g1, g2)
    };
    assert_eq!(nat, bpf);
    assert!(!nat);
}

// ---- 100 random balanced pairs: e(a*G1, G2) · e(-a*G1, G2) = 1 ------------

#[test]
fn parity_100_random_balanced() {
    let mut rng = 0xCAFE_DEAD_BEEF_1234u64;
    for i in 0..100 {
        let s = xorshift(&mut rng);
        if s == 0 {
            continue;
        }

        let nat = {
            let a_g1 = (G1Affine::generator() * Fr::from(s)).into_affine();
            let neg_a_g1 = (-a_g1.into_group()).into_affine();
            let g2 = G2Affine::generator();
            native_pairing_check(a_g1, g2, neg_a_g1, g2)
        };
        let bpf = {
            let a_g1 = (BpfG1::generator() * BpfFr::from(s)).into_affine();
            let neg_a_g1 = (-a_g1.into_group()).into_affine();
            let g2 = BpfG2::generator();
            bpf_pairing_check(a_g1, g2, neg_a_g1, g2)
        };
        assert!(nat, "native pairing should pass at iteration {i}");
        assert!(bpf, "bpf pairing should pass at iteration {i}");
    }
}

// ---- 50 random unbalanced pairs: e(a*G1, G2) · e(b*G1, G2) != 1 -----------

#[test]
fn parity_50_random_unbalanced() {
    let mut rng = 0xDEAD_1337_FACE_FEEDu64;
    let mut failures = 0;
    for _ in 0..50 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);
        if a == 0 || b == 0 {
            continue;
        }

        let nat = {
            let pa = (G1Affine::generator() * Fr::from(a)).into_affine();
            let pb = (G1Affine::generator() * Fr::from(b)).into_affine();
            let g2 = G2Affine::generator();
            native_pairing_check(pa, g2, pb, g2)
        };
        let bpf = {
            let pa = (BpfG1::generator() * BpfFr::from(a)).into_affine();
            let pb = (BpfG1::generator() * BpfFr::from(b)).into_affine();
            let g2 = BpfG2::generator();
            bpf_pairing_check(pa, g2, pb, g2)
        };
        assert_eq!(nat, bpf, "backends disagree for a={a}, b={b}");
        if !nat {
            failures += 1;
        }
    }
    assert!(failures >= 45, "expected most pairs to fail, got {failures}/50 failures");
}

// ---- Distributed G1 arithmetic into pairing ---------------------------------
// e((a+b)*G, G2) · e(-(a*G + b*G), G2) = 1
// Tests that G1 add distributes correctly through the pairing.

#[test]
fn parity_50_distributed_add() {
    let mut rng = 0xABCD_1234_5678_EF01u64;
    for i in 0..50 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);

        let nat = {
            let sum_scalar = Fr::from(a) + Fr::from(b);
            let lhs = (G1Affine::generator() * sum_scalar).into_affine();
            let rhs_a = G1Affine::generator() * Fr::from(a);
            let rhs_b = G1Affine::generator() * Fr::from(b);
            let rhs = (-(rhs_a + rhs_b)).into_affine();
            let g2 = G2Affine::generator();
            native_pairing_check(lhs, g2, rhs, g2)
        };
        let bpf = {
            let sum_scalar = BpfFr::from(a) + BpfFr::from(b);
            let lhs = (BpfG1::generator() * sum_scalar).into_affine();
            let rhs_a = BpfG1::generator() * BpfFr::from(a);
            let rhs_b = BpfG1::generator() * BpfFr::from(b);
            let rhs = (-(rhs_a + rhs_b)).into_affine();
            let g2 = BpfG2::generator();
            bpf_pairing_check(lhs, g2, rhs, g2)
        };
        assert!(nat, "native distributed add check failed at iteration {i}");
        assert!(bpf, "bpf distributed add check failed at iteration {i}");
    }
}

// ---- Product scalar: e(a*b*G, G2) · e(-(a*G)*b, G2) = 1 -------------------
// Tests scalar mul composition into pairing.

#[test]
fn parity_50_product_scalar() {
    let mut rng = 0x9876_FEDC_BA01_2345u64;
    for i in 0..50 {
        let a = xorshift(&mut rng);
        let b = xorshift(&mut rng);

        let nat = {
            let ab = Fr::from(a) * Fr::from(b);
            let lhs = (G1Affine::generator() * ab).into_affine();
            let a_g = G1Affine::generator() * Fr::from(a);
            let rhs = (-(a_g * Fr::from(b))).into_affine();
            let g2 = G2Affine::generator();
            native_pairing_check(lhs, g2, rhs, g2)
        };
        let bpf = {
            let ab = BpfFr::from(a) * BpfFr::from(b);
            let lhs = (BpfG1::generator() * ab).into_affine();
            let a_g = BpfG1::generator() * BpfFr::from(a);
            let rhs = (-(a_g * BpfFr::from(b))).into_affine();
            let g2 = BpfG2::generator();
            bpf_pairing_check(lhs, g2, rhs, g2)
        };
        assert!(nat, "native product scalar check failed at iteration {i}");
        assert!(bpf, "bpf product scalar check failed at iteration {i}");
    }
}

// ---- Mixed: one identity slot -----------------------------------------------

#[test]
fn parity_one_identity_slot() {
    let nat = native_pairing_check(
        G1Affine::zero(),
        G2Affine::generator(),
        G1Affine::generator(),
        G2Affine::generator(),
    );
    let bpf = bpf_pairing_check(
        BpfG1::zero(),
        BpfG2::generator(),
        BpfG1::generator(),
        BpfG2::generator(),
    );
    assert_eq!(nat, bpf);
}
