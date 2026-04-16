//! Byte-level determinism pin for the verifier-facing surface.
//!
//! This test locks in exact SHA-256 hashes of the canonical serialized output
//! produced by the genshi-core native backend. Its purpose is to catch any
//! silent change in the wire format during the genshi-math BPF backend swap
//! (Phase 2 of the solana-codegen plan) — the BPF backend must produce byte-
//! identical output to the native backend, because the on-chain verifier will
//! parse these bytes directly.
//!
//! If this test ever fails, either:
//!   (a) the serialization format changed — update ALL consumers (solana
//!       instruction encoder, EVM emitter, WASM blob layout) and bump the
//!       wire-format version; or
//!   (b) the prover's math changed — investigate, because proofs produced by
//!       old clients will no longer verify.

#![cfg(feature = "prover")]

use ark_bn254::Fr as ArkFr;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use genshi_core::proving::prover;
use genshi_core::proving::serialization::{
    proof_to_bytes, public_inputs_to_bytes_le, vk_to_bytes,
};
use genshi_core::proving::srs::SRS;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hash(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

/// Deterministic reference circuit: three additions, three public outputs.
///
/// Large enough to exercise the full prover flow (selector polynomials,
/// permutation arg, quotient split) but small enough that the pinned hashes
/// stay stable against reasonable domain-size choices.
fn build_reference() -> (SRS, Vec<genshi_math::Fr>, prover::Proof, prover::VerificationKey) {
    let srs = SRS::insecure_for_testing(256);

    let mut builder = UltraCircuitBuilder::new();
    let a = builder.add_variable(ArkFr::from(3u64));
    let b = builder.add_variable(ArkFr::from(5u64));
    let c = builder.add(a, b);
    builder.set_public(c);

    let d = builder.add_variable(ArkFr::from(7u64));
    let e = builder.add(c, d);
    builder.set_public(e);

    let f = builder.add_variable(ArkFr::from(11u64));
    let g = builder.add(e, f);
    builder.set_public(g);

    let (proof, vk) = prover::prove(&builder, &srs);

    let pis: Vec<genshi_math::Fr> = vec![
        genshi_math::Fr::from_ark(ArkFr::from(8u64)),   // 3 + 5
        genshi_math::Fr::from_ark(ArkFr::from(15u64)),  // 8 + 7
        genshi_math::Fr::from_ark(ArkFr::from(26u64)),  // 15 + 11
    ];

    (srs, pis, proof, vk)
}

#[test]
fn reference_proof_is_byte_deterministic() {
    let (srs, pis, proof, vk) = build_reference();

    let srs_bytes = srs.save_to_bytes();
    let vk_bytes = vk_to_bytes(&vk);
    let proof_bytes = proof_to_bytes(&proof);
    let pi_bytes = public_inputs_to_bytes_le(&pis);

    let srs_hash = hash(&srs_bytes);
    let vk_hash = hash(&vk_bytes);
    let proof_hash = hash(&proof_bytes);
    let pi_hash = hash(&pi_bytes);

    // When the snapshot legitimately changes (format bump / math change) the
    // values below must be updated in the SAME commit that changes the format.
    // Running the test with `--nocapture` prints the fresh values.
    eprintln!("srs_hash   = {srs_hash}");
    eprintln!("vk_hash    = {vk_hash}");
    eprintln!("proof_hash = {proof_hash}");
    eprintln!("pi_hash    = {pi_hash}");

    // Golden values captured 2026-04-17 after the P1.6 genshi-math refactor.
    const SRS_HASH: &str =
        "d6cf83a8aa30d04469c64627d7d41a6b4d65733604bbcefb27b366eea9ea972c";
    const VK_HASH: &str =
        "11ef07537ce264d2786788f20b986db966f6507681cedf37ca243fe6d47c3f0a";
    const PROOF_HASH: &str =
        "22cc9620802906c9752ac5f6ee418181fe6407c0c01b67d21a060b58b8ebc6fe";
    const PI_HASH: &str =
        "9a5fe7857b03bab52e348e3f0f9e0295d8354da068e1a9ad89b9293e83d3e77a";

    assert_eq!(srs_hash, SRS_HASH, "SRS wire format drifted");
    assert_eq!(vk_hash, VK_HASH, "VK wire format drifted");
    assert_eq!(proof_hash, PROOF_HASH, "Proof wire format drifted");
    assert_eq!(pi_hash, PI_HASH, "PI wire format drifted");
}

#[test]
fn reference_proof_verifies() {
    let (srs, pis, proof, vk) = build_reference();
    assert!(
        genshi_core::proving::verifier::verify(&proof, &vk, &pis, &srs),
        "reference proof must verify under native backend"
    );
}
