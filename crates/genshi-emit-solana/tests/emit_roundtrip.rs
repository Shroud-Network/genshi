use std::fs;

use ark_bn254::Fr as ArkFr;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use genshi_core::proving::prover;
use genshi_core::proving::serialization::vk_to_bytes;
use genshi_core::proving::srs::SRS;
use genshi_emit_solana::{EmitConfig, emit_program};

fn make_test_vk() -> (SRS, Vec<u8>) {
    let srs = SRS::insecure_for_testing(256);
    let mut builder = UltraCircuitBuilder::new();
    let a = builder.add_variable(ArkFr::from(3u64));
    let b = builder.add_variable(ArkFr::from(5u64));
    let c = builder.add(a, b);
    builder.set_public(c);
    let (_, vk) = prover::prove(&builder, &srs);
    let vk_bytes = vk_to_bytes(&vk);
    (srs, vk_bytes)
}

#[test]
fn emit_creates_expected_files() {
    let (srs, vk_bytes) = make_test_vk();
    let out_dir = std::env::temp_dir().join("genshi_emit_test");
    let _ = fs::remove_dir_all(&out_dir);

    let mut config = EmitConfig::new("test-verifier", &out_dir);
    config.add_circuit("addition", vk_bytes);

    emit_program(&config, &srs).expect("emit_program failed");

    let src = out_dir.join("src");
    assert!(out_dir.join("Cargo.toml").exists());
    assert!(out_dir.join("Xargo.toml").exists());
    assert!(src.join("lib.rs").exists());
    assert!(src.join("verifier.rs").exists());
    assert!(src.join("transcript.rs").exists());
    assert!(src.join("types.rs").exists());
    assert!(src.join("srs.rs").exists());
    assert!(src.join("vk_constants.rs").exists());
    assert!(src.join("pairing_constants.rs").exists());

    let cargo = fs::read_to_string(out_dir.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("test-verifier"));
    assert!(cargo.contains("genshi-math"));
    assert!(cargo.contains("anchor-lang"));

    let lib = fs::read_to_string(src.join("lib.rs")).unwrap();
    assert!(lib.contains("verify_addition"));
    assert!(lib.contains("#[program]"));

    let vk = fs::read_to_string(src.join("vk_constants.rs")).unwrap();
    assert!(vk.contains("load_addition_vk"));
    assert!(vk.contains("G1Affine::from_raw"));

    let pairing = fs::read_to_string(src.join("pairing_constants.rs")).unwrap();
    assert!(pairing.contains("load_g2"));
    assert!(pairing.contains("load_g2_tau"));
    assert!(pairing.contains("G2Affine::from_raw"));

    let verifier = fs::read_to_string(src.join("verifier.rs")).unwrap();
    assert!(!verifier.contains("super::types"), "imports should be rewritten");
    assert!(!verifier.contains("#[cfg(test)]"), "tests should be stripped");
    assert!(verifier.contains("crate::types") || verifier.contains("use crate::transcript"));

    let srs_stub = fs::read_to_string(src.join("srs.rs")).unwrap();
    assert!(srs_stub.contains("pub struct SRS"));
    assert!(srs_stub.contains("g2:"));
    assert!(srs_stub.contains("g2_tau:"));
    assert!(!srs_stub.contains("g1_powers"), "SRS stub should not have G1 powers");

    let _ = fs::remove_dir_all(&out_dir);
}

#[test]
fn emit_multi_circuit() {
    let (srs, vk_bytes) = make_test_vk();
    let out_dir = std::env::temp_dir().join("genshi_emit_multi");
    let _ = fs::remove_dir_all(&out_dir);

    let mut config = EmitConfig::new("multi-verifier", &out_dir);
    config.add_circuit("withdraw", vk_bytes.clone());
    config.add_circuit("transfer", vk_bytes);

    emit_program(&config, &srs).expect("emit_program failed");

    let lib = fs::read_to_string(out_dir.join("src/lib.rs")).unwrap();
    assert!(lib.contains("verify_withdraw"));
    assert!(lib.contains("verify_transfer"));

    let vk = fs::read_to_string(out_dir.join("src/vk_constants.rs")).unwrap();
    assert!(vk.contains("load_withdraw_vk"));
    assert!(vk.contains("load_transfer_vk"));

    let _ = fs::remove_dir_all(&out_dir);
}

#[test]
fn emit_no_circuits_fails() {
    let srs = SRS::insecure_for_testing(4);
    let out_dir = std::env::temp_dir().join("genshi_emit_empty");
    let config = EmitConfig::new("empty", &out_dir);
    assert!(emit_program(&config, &srs).is_err());
}
