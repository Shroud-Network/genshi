use std::fs;
use std::process::Command;

use ark_bn254::Fr as ArkFr;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use genshi_core::proving::prover;
use genshi_core::proving::serialization::vk_to_bytes;
use genshi_core::proving::srs::SRS;
use genshi_emit_solana::{EmitConfig, emit_program};

#[test]
fn emitted_program_cargo_checks() {
    let srs = SRS::insecure_for_testing(256);
    let mut builder = UltraCircuitBuilder::new();
    let a = builder.add_variable(ArkFr::from(3u64));
    let b = builder.add_variable(ArkFr::from(5u64));
    let c = builder.add(a, b);
    builder.set_public(c);
    let (_, vk) = prover::prove(&builder, &srs);
    let vk_bytes = vk_to_bytes(&vk);

    let out_dir = std::env::temp_dir().join("genshi_emit_cargo_check");
    let _ = fs::remove_dir_all(&out_dir);

    let mut config = EmitConfig::new("check-verifier", &out_dir);
    config.add_circuit("addition", vk_bytes);
    emit_program(&config, &srs).expect("emit_program failed");

    // Patch crates-io so cargo resolves genshi-math from the workspace
    // (the BPF backend isn't published yet).
    let cargo_dir = out_dir.join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let math_path = manifest_dir.join("../genshi-math").canonicalize().unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        format!(
            "[patch.crates-io]\ngenshi-math = {{ path = \"{}\" }}\n",
            math_path.display()
        ),
    )
    .unwrap();

    let output = Command::new("cargo")
        .args(["check", "--lib"])
        .current_dir(&out_dir)
        .output()
        .expect("failed to run cargo check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        eprintln!("=== cargo check stdout ===\n{stdout}");
        eprintln!("=== cargo check stderr ===\n{stderr}");
    }

    let _ = fs::remove_dir_all(&out_dir);

    assert!(
        output.status.success(),
        "cargo check on emitted program failed — see stderr above"
    );
}
