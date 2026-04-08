//! janus — framework tooling CLI.
//!
//! This binary ships with the Janus framework and provides application-agnostic
//! utilities: SRS generation, artifact inspection, and verifier emission from
//! a serialized verification key. It does NOT know about any specific circuit
//! type — applications that need a proving CLI should ship their own binary
//! that links `janus-core` and their circuit crate.
//!
//! Subcommands:
//!   gen-srs        Generate an insecure-for-testing SRS and write it to disk.
//!   inspect        Dump a summary of a serialized proof or VK.
//!   emit-evm       Generate a Solidity verifier contract from a VK file.
//!   emit-poseidon2 Emit the Poseidon2.sol Solidity library.
//!   emit-libs      Emit reusable Solidity library contracts.
//!   verify         Run the native verifier against (proof, vk, public-inputs) files.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use clap::{Parser, Subcommand};

use janus_core::proving::serialization::{
    proof_from_bytes, vk_from_bytes,
};
use janus_core::proving::srs::SRS;
use janus_core::proving::verifier;

#[derive(Parser)]
#[command(
    name = "janus",
    version,
    about = "Framework tooling for the Janus dual-VM ZK proving framework"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an insecure SRS for local development and write it to disk.
    ///
    /// WARNING: uses a known secret tau. Never use the output in production —
    /// production deployments must consume an SRS derived from a verifiable
    /// ceremony (Janus uses Aztec's Powers of Tau).
    GenSrs {
        /// Maximum polynomial degree the SRS should support.
        #[arg(long)]
        max_degree: usize,
        /// Output file path for the serialized SRS.
        #[arg(long)]
        output: PathBuf,
    },

    /// Dump a one-line summary of a serialized proof or VK file.
    Inspect {
        /// Artifact kind: "proof" or "vk".
        #[arg(long)]
        kind: String,
        /// Path to the serialized artifact.
        #[arg(long)]
        file: PathBuf,
    },

    /// Generate a Solidity verifier contract for a given VK.
    EmitEvm {
        /// Path to serialized VK.
        #[arg(long)]
        vk: PathBuf,
        /// Path to serialized SRS (used to embed G2 points into the contract).
        #[arg(long)]
        srs: PathBuf,
        /// Output directory for the generated contract(s).
        #[arg(long)]
        output: PathBuf,
        /// Solidity contract name. Defaults to "JanusVerifier".
        #[arg(long, default_value = "JanusVerifier")]
        contract_name: String,
        /// Solidity pragma version string. Defaults to "^0.8.24".
        #[arg(long, default_value = "^0.8.24")]
        pragma: String,
    },

    /// Emit the Poseidon2.sol Solidity library to disk.
    ///
    /// Round constants are derived identically to janus-core's Poseidon2
    /// implementation (Invariant J4), so on-chain Merkle updates produce
    /// the same roots as in-circuit hashing.
    EmitPoseidon2 {
        /// Output directory; the file is written as `<dir>/Poseidon2.sol`.
        #[arg(long)]
        output: PathBuf,
    },

    /// Emit Janus's reusable Solidity library contracts (MerkleTree, NullifierSet, RootHistory).
    ///
    /// These are framework primitives that consumer applications can import
    /// directly. They make no assumption about the application's domain.
    EmitLibs {
        /// Output directory; library files are written as `<dir>/<Name>.sol`.
        #[arg(long)]
        output: PathBuf,
    },

    /// Verify a proof natively given (proof, vk, public-inputs) files.
    ///
    /// Public inputs are expected as concatenated 32-byte little-endian
    /// Fr elements — the canonical Janus Solana-side encoding.
    Verify {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        vk: PathBuf,
        #[arg(long)]
        public_inputs: PathBuf,
        #[arg(long)]
        srs: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenSrs { max_degree, output } => cmd_gen_srs(max_degree, &output),
        Commands::Inspect { kind, file } => cmd_inspect(&kind, &file),
        Commands::EmitEvm {
            vk,
            srs,
            output,
            contract_name,
            pragma,
        } => cmd_emit_evm(&vk, &srs, &output, &contract_name, &pragma),
        Commands::EmitPoseidon2 { output } => cmd_emit_poseidon2(&output),
        Commands::EmitLibs { output } => cmd_emit_libs(&output),
        Commands::Verify {
            proof,
            vk,
            public_inputs,
            srs,
        } => cmd_verify(&proof, &vk, &public_inputs, &srs),
    }
}

fn cmd_gen_srs(max_degree: usize, output: &PathBuf) -> ExitCode {
    let srs = SRS::insecure_for_testing(max_degree);
    let bytes = srs.save_to_bytes();
    match fs::write(output, &bytes) {
        Ok(()) => {
            println!(
                "wrote insecure SRS (max_degree={}, {} bytes) to {}",
                max_degree,
                bytes.len(),
                output.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to write SRS: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_inspect(kind: &str, file: &PathBuf) -> ExitCode {
    let bytes = match fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read {}: {e}", file.display());
            return ExitCode::FAILURE;
        }
    };

    match kind {
        "proof" => match proof_from_bytes(&bytes) {
            Ok(_proof) => {
                println!("proof OK: {} bytes", bytes.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("proof decode failed: {e:?}");
                ExitCode::FAILURE
            }
        },
        "vk" => match vk_from_bytes(&bytes) {
            Ok(_vk) => {
                println!("vk OK: {} bytes", bytes.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("vk decode failed: {e:?}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("unknown artifact kind: {other} (expected \"proof\" or \"vk\")");
            ExitCode::FAILURE
        }
    }
}

fn cmd_emit_evm(
    vk_path: &PathBuf,
    srs_path: &PathBuf,
    output_dir: &PathBuf,
    contract_name: &str,
    pragma: &str,
) -> ExitCode {
    let vk_bytes = match fs::read(vk_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read vk: {e}");
            return ExitCode::FAILURE;
        }
    };
    let vk = match vk_from_bytes(&vk_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vk decode failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let srs_bytes = match fs::read(srs_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read srs: {e}");
            return ExitCode::FAILURE;
        }
    };
    let srs = SRS::load_from_bytes(&srs_bytes);

    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    let opts = janus_evm::solidity_emitter::EmitterOptions::default()
        .with_contract_name(contract_name)
        .with_pragma(pragma);
    let sol = janus_evm::solidity_emitter::generate_verifier_sol_with(&vk, &srs, &opts);
    let out = output_dir.join(format!("{contract_name}.sol"));
    if let Err(e) = fs::write(&out, sol.as_bytes()) {
        eprintln!("failed to write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }

    println!("wrote Solidity verifier to {}", out.display());
    ExitCode::SUCCESS
}

fn cmd_emit_poseidon2(output_dir: &PathBuf) -> ExitCode {
    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    let sol = janus_evm::poseidon2_sol::generate_poseidon2_sol();
    let out = output_dir.join("Poseidon2.sol");
    if let Err(e) = fs::write(&out, sol.as_bytes()) {
        eprintln!("failed to write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }

    println!("wrote Poseidon2 library to {}", out.display());
    ExitCode::SUCCESS
}

fn cmd_emit_libs(output_dir: &PathBuf) -> ExitCode {
    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    for name in janus_evm::library_names() {
        let src = match janus_evm::library_source(name) {
            Some(s) => s,
            None => {
                eprintln!("internal: library {name} listed but not embedded");
                return ExitCode::FAILURE;
            }
        };
        let out = output_dir.join(format!("{name}.sol"));
        if let Err(e) = fs::write(&out, src.as_bytes()) {
            eprintln!("failed to write {}: {e}", out.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", out.display());
    }

    ExitCode::SUCCESS
}

fn cmd_verify(
    proof_path: &PathBuf,
    vk_path: &PathBuf,
    pi_path: &PathBuf,
    srs_path: &PathBuf,
) -> ExitCode {
    let proof_bytes = match fs::read(proof_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read proof: {e}");
            return ExitCode::FAILURE;
        }
    };
    let vk_bytes = match fs::read(vk_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read vk: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pi_bytes = match fs::read(pi_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read public inputs: {e}");
            return ExitCode::FAILURE;
        }
    };
    let srs_bytes = match fs::read(srs_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read srs: {e}");
            return ExitCode::FAILURE;
        }
    };

    let proof = match proof_from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("proof decode failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let vk = match vk_from_bytes(&vk_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vk decode failed: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let srs = SRS::load_from_bytes(&srs_bytes);

    if pi_bytes.len() % 32 != 0 {
        eprintln!("public inputs file must be a multiple of 32 bytes");
        return ExitCode::FAILURE;
    }
    let mut public_inputs = Vec::with_capacity(pi_bytes.len() / 32);
    for chunk in pi_bytes.chunks_exact(32) {
        public_inputs.push(Fr::from_le_bytes_mod_order(chunk));
    }

    if verifier::verify(&proof, &vk, &public_inputs, &srs) {
        println!("OK: proof verifies");
        ExitCode::SUCCESS
    } else {
        eprintln!("FAIL: proof does not verify");
        ExitCode::FAILURE
    }
}
