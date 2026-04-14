//! genshi framework CLI — library surface.
//!
//! This crate is the "zero-boilerplate" path for application developers who
//! want a circom-style command-line workflow on top of the genshi dual-VM
//! proving framework. After wiring a consumer crate to this library, the only
//! things the application author writes are:
//!
//! 1. Their `Circuit` implementations (same as always).
//! 2. One `genshi_cli::register!(MyCircuit, "my-circuit");` line per circuit,
//!    typically placed right next to the `impl Circuit for MyCircuit` block.
//! 3. A one-line `src/bin/genshi.rs` shim:
//!
//!    ```no_run
//!    fn main() -> std::process::ExitCode { genshi_cli::run() }
//!    ```
//!
//! Cargo auto-discovers anything under `src/bin/`, so no extra `[[bin]]`
//! entry in `Cargo.toml` is required. Once that's in place, the consumer
//! gets a fully-featured CLI:
//!
//! ```text
//! cargo run --bin genshi -- srs new --max-degree 65536 --output srs.bin
//! cargo run --bin genshi -- circuits list
//! cargo run --bin genshi -- extract-vk \
//!     --circuit my-circuit --srs srs.bin --output my-circuit.vk
//! cargo run --bin genshi -- emit-verifier \
//!     --circuit my-circuit --srs srs.bin \
//!     --contract-name MyVerifier --output verifier/
//! ```
//!
//! # How the registry works
//!
//! The [`register!`] macro uses the `inventory` crate to place a static
//! [`CircuitEntry`] record into a linker-collected slice. At runtime,
//! [`run`] enumerates every `CircuitEntry` that was registered anywhere in
//! the final binary. Because the consumer's `Circuit` impls are compiled
//! into the same binary as `genshi_cli::run`, inventory picks them up
//! automatically — no explicit registration list is required in `main`.
//!
//! All circuit-specific operations are exposed as *function pointers* on
//! `CircuitEntry`, so the CLI never needs to know the concrete associated
//! types of any circuit. The macro closes over the generic type at the
//! registration site and type-erases it for the CLI.

pub mod ceremony;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use clap::{Parser, Subcommand};

use genshi_core::proving::serialization::{proof_from_bytes, vk_from_bytes};
use genshi_core::proving::srs::SRS;
use genshi_core::proving::verifier;

// Publicly re-export the Circuit trait and the inventory crate so that
// consumer crates can say `genshi_cli::Circuit` and the `register!` macro
// can resolve `$crate::inventory::submit!` regardless of where it's invoked.
pub use genshi_core::circuit::Circuit;
#[doc(hidden)]
pub use inventory;

#[doc(hidden)]
pub mod __private {
    //! Implementation details used by the [`register!`] macro. Not part of
    //! the public API — the names and signatures here may change without a
    //! major-version bump.
    pub use genshi_core::proving::api;
    pub use genshi_core::proving::serialization::{
        proof_to_bytes, public_inputs_to_bytes_le, vk_to_bytes,
    };
    pub use genshi_core::proving::srs::SRS;
    pub use genshi_evm::solidity_emitter::{EmitterOptions, generate_verifier_sol_with};
    pub use serde_json;
}

// ============================================================================
// Circuit registry
// ============================================================================

/// Runtime record for a circuit registered with the genshi CLI.
///
/// The `register!` macro builds one of these at the circuit definition site
/// and submits it through `inventory`. The CLI never instantiates
/// `CircuitEntry` directly.
///
/// Each function pointer captures a single generic operation specialised to
/// one concrete `Circuit` type. This is how the CLI reaches circuit-generic
/// framework functions like `api::extract_vk::<C>` without knowing `C`.
pub struct CircuitEntry {
    /// Short, human-facing name used on the command line
    /// (e.g. `"withdraw"`). Must be unique across the final binary.
    pub name: &'static str,
    /// Stable circuit identifier from `Circuit::ID`
    /// (e.g. `"shroud-pool.withdraw"`).
    pub id: &'static str,
    /// Number of public inputs the circuit commits to. Displayed by
    /// `circuits list` and used to shape emitted Solidity.
    pub num_public_inputs: fn() -> usize,
    /// Extract the verification key for this circuit against `srs` and
    /// return its canonical byte encoding.
    pub extract_vk_bytes: fn(&SRS) -> Vec<u8>,
    /// Extract the VK and feed it (plus the SRS G2 anchor) through the
    /// genshi-evm Solidity emitter with the supplied options, returning the
    /// rendered contract source.
    pub emit_solidity:
        fn(&SRS, &genshi_evm::solidity_emitter::EmitterOptions) -> String,
    /// Deserialize a witness from JSON, prove the circuit, and return
    /// `(proof_bytes, vk_bytes, public_inputs_le_bytes)`.
    pub prove_from_json:
        fn(&str, &SRS) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String>,
    /// Return a valid witness as pretty-printed JSON.
    ///
    /// Used by `gen-witness` so developers get a concrete, provable witness
    /// they can run immediately and then edit with their own data.
    pub witness_json: fn() -> Result<String, String>,
}

inventory::collect!(CircuitEntry);

/// Register a circuit type with the genshi CLI.
///
/// Place this macro call next to each `impl Circuit for MyCircuit` block:
///
/// ```
/// use genshi_cli::Circuit;
/// use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
/// use ark_bn254::Fr;
/// use serde::{Serialize, Deserialize};
///
/// pub struct MyCircuit;
///
/// #[derive(Serialize, Deserialize)]
/// pub struct MyWitness { pub x: u64 }
///
/// impl Circuit for MyCircuit {
///     type Witness = MyWitness;
///     type PublicInputs = [Fr; 1];
///     const ID: &'static str = "example.my-circuit";
///     fn num_public_inputs() -> usize { 1 }
///     fn synthesize(builder: &mut UltraCircuitBuilder, w: &Self::Witness) -> Self::PublicInputs {
///         let v = builder.add_variable(Fr::from(w.x));
///         builder.set_public(v);
///         [Fr::from(w.x)]
///     }
///     fn dummy_witness() -> Self::Witness {
///         MyWitness { x: 0 }
///     }
/// }
///
/// genshi_cli::register!(MyCircuit, "my-circuit");
/// ```
///
/// The second argument is the short CLI name consumers will pass via
/// `--circuit`. It should be unique across the final binary.
///
/// This expands to an `inventory::submit!` call that builds a
/// [`CircuitEntry`] with type-erased function pointers specialised to the
/// given `Circuit` implementation.
#[macro_export]
macro_rules! register {
    // Form 1: Witness type is directly JSON-serializable (Serialize + Deserialize).
    //   genshi_cli::register!(MyCircuit, "name");
    ($ty:ty, $name:literal) => {
        $crate::inventory::submit! {
            $crate::CircuitEntry {
                name: $name,
                id: <$ty as $crate::Circuit>::ID,
                num_public_inputs: || {
                    <$ty as $crate::Circuit>::num_public_inputs()
                },
                extract_vk_bytes: |srs: &$crate::__private::SRS| {
                    let vk = $crate::__private::api::extract_vk::<$ty>(srs);
                    $crate::__private::vk_to_bytes(&vk)
                },
                emit_solidity: |srs: &$crate::__private::SRS,
                                opts: &$crate::__private::EmitterOptions| {
                    let vk = $crate::__private::api::extract_vk::<$ty>(srs);
                    $crate::__private::generate_verifier_sol_with(&vk, srs, opts)
                },
                prove_from_json: |json: &str, srs: &$crate::__private::SRS| {
                    let witness: <$ty as $crate::Circuit>::Witness =
                        $crate::__private::serde_json::from_str(json)
                            .map_err(|e| format!("witness deserialization failed: {e}"))?;
                    let (proof, vk, pi) = $crate::__private::api::prove::<$ty>(&witness, srs);
                    let proof_bytes = $crate::__private::proof_to_bytes(&proof);
                    let vk_bytes = $crate::__private::vk_to_bytes(&vk);
                    let pi_bytes = $crate::__private::public_inputs_to_bytes_le(pi.as_ref());
                    Ok((proof_bytes, vk_bytes, pi_bytes))
                },
                witness_json: || {
                    let w = <$ty as $crate::Circuit>::dummy_witness();
                    $crate::__private::serde_json::to_string_pretty(&w)
                        .map_err(|e| format!("witness serialization failed: {e}"))
                },
            }
        }
    };

    // Form 2 (4-arg): Witness needs JSON proxy types + both conversion directions.
    //   genshi_cli::register!(MyCircuit, "name",
    //       |json: &str| { ... -> Result<Witness, String> },
    //       |w: &Witness| { ... -> String }
    //   );
    ($ty:ty, $name:literal, $witness_from_json:expr, $witness_to_json:expr) => {
        $crate::inventory::submit! {
            $crate::CircuitEntry {
                name: $name,
                id: <$ty as $crate::Circuit>::ID,
                num_public_inputs: || {
                    <$ty as $crate::Circuit>::num_public_inputs()
                },
                extract_vk_bytes: |srs: &$crate::__private::SRS| {
                    let vk = $crate::__private::api::extract_vk::<$ty>(srs);
                    $crate::__private::vk_to_bytes(&vk)
                },
                emit_solidity: |srs: &$crate::__private::SRS,
                                opts: &$crate::__private::EmitterOptions| {
                    let vk = $crate::__private::api::extract_vk::<$ty>(srs);
                    $crate::__private::generate_verifier_sol_with(&vk, srs, opts)
                },
                prove_from_json: |json: &str, srs: &$crate::__private::SRS| {
                    let convert: fn(&str) -> Result<
                        <$ty as $crate::Circuit>::Witness,
                        String,
                    > = $witness_from_json;
                    let witness = convert(json)?;
                    let (proof, vk, pi) = $crate::__private::api::prove::<$ty>(&witness, srs);
                    let proof_bytes = $crate::__private::proof_to_bytes(&proof);
                    let vk_bytes = $crate::__private::vk_to_bytes(&vk);
                    let pi_bytes = $crate::__private::public_inputs_to_bytes_le(pi.as_ref());
                    Ok((proof_bytes, vk_bytes, pi_bytes))
                },
                witness_json: || {
                    let w = <$ty as $crate::Circuit>::dummy_witness();
                    let convert: fn(
                        &<$ty as $crate::Circuit>::Witness,
                    ) -> String = $witness_to_json;
                    Ok(convert(&w))
                },
            }
        }
    };

    // Form 2 (3-arg, legacy): from_json only, no reverse direction.
    //   genshi_cli::register!(MyCircuit, "name", |json: &str| { ... });
    ($ty:ty, $name:literal, $witness_from_json:expr) => {
        $crate::inventory::submit! {
            $crate::CircuitEntry {
                name: $name,
                id: <$ty as $crate::Circuit>::ID,
                num_public_inputs: || {
                    <$ty as $crate::Circuit>::num_public_inputs()
                },
                extract_vk_bytes: |srs: &$crate::__private::SRS| {
                    let vk = $crate::__private::api::extract_vk::<$ty>(srs);
                    $crate::__private::vk_to_bytes(&vk)
                },
                emit_solidity: |srs: &$crate::__private::SRS,
                                opts: &$crate::__private::EmitterOptions| {
                    let vk = $crate::__private::api::extract_vk::<$ty>(srs);
                    $crate::__private::generate_verifier_sol_with(&vk, srs, opts)
                },
                prove_from_json: |json: &str, srs: &$crate::__private::SRS| {
                    let convert: fn(&str) -> Result<
                        <$ty as $crate::Circuit>::Witness,
                        String,
                    > = $witness_from_json;
                    let witness = convert(json)?;
                    let (proof, vk, pi) = $crate::__private::api::prove::<$ty>(&witness, srs);
                    let proof_bytes = $crate::__private::proof_to_bytes(&proof);
                    let vk_bytes = $crate::__private::vk_to_bytes(&vk);
                    let pi_bytes = $crate::__private::public_inputs_to_bytes_le(pi.as_ref());
                    Ok((proof_bytes, vk_bytes, pi_bytes))
                },
                witness_json: || {
                    Err(format!(
                        "circuit `{}` does not provide a witness-to-JSON converter. \
                         Update the register! call to the 4-argument form: \
                         register!(Ty, \"name\", from_json, to_json)",
                        $name
                    ))
                },
            }
        }
    };
}

/// Iterate every circuit registered anywhere in the current binary.
pub fn all_circuits() -> impl Iterator<Item = &'static CircuitEntry> {
    inventory::iter::<CircuitEntry>.into_iter()
}

/// Look up a registered circuit by its CLI name.
pub fn find_circuit(name: &str) -> Option<&'static CircuitEntry> {
    all_circuits().find(|c| c.name == name)
}

// ============================================================================
// CLI definition
// ============================================================================

#[derive(Parser)]
#[command(
    name = "genshi",
    version,
    about = "Framework tooling for the genshi dual-VM ZK proving framework"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scaffold a new genshi application crate with a sample circuit.
    ///
    /// Creates a Cargo crate at `<name>/` (relative to the current working
    /// directory unless `--path` is given) containing:
    ///
    /// - `Cargo.toml` with `genshi-core` and `genshi-cli` deps
    /// - `src/lib.rs` with a stub `AddCircuit` and a
    ///   `genshi_cli::register!(AddCircuit, "add")` line
    /// - `src/bin/genshi.rs` — the one-line shim that calls `genshi_cli::run()`
    /// - a minimal `README.md` and `.gitignore`
    ///
    /// After running `cd <name> && cargo run --bin genshi -- circuits list`,
    /// the consumer has a working, circuit-aware CLI. The only file they
    /// ever edit beyond that point is `src/lib.rs`.
    New {
        /// Name of the crate to create. Also used as the directory name
        /// and as the Cargo `[package] name` field.
        name: String,
        /// Parent directory in which to create the crate. Defaults to the
        /// current working directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Dependency source for the generated crate. Accepts either
        /// `git` (the default — pulls `genshi-core` / `genshi-cli` from the
        /// upstream GitHub repo) or `path:<abs-dir>`, where `<abs-dir>` is
        /// the workspace root of a local genshi checkout (the directory
        /// containing `crates/genshi-cli`). Path mode is primarily useful
        /// for developing genshi itself.
        #[arg(long, default_value = "git")]
        source: String,
    },

    /// SRS management (generate, inspect).
    #[command(subcommand)]
    Srs(SrsCmd),

    /// List circuits registered in this binary.
    ///
    /// Only circuits whose `register!(...)` macro was linked into the final
    /// binary are shown. Running this from the stock `genshi-cli` crate will
    /// report an empty list; running it from a downstream crate that
    /// registers circuits will show them all.
    Circuits,

    /// Extract a circuit's verification key and write it to disk.
    ///
    /// Requires the circuit to be registered via `genshi_cli::register!` in
    /// this binary's dependency graph.
    ExtractVk {
        /// Short CLI name of the registered circuit (e.g. "withdraw").
        #[arg(long)]
        circuit: String,
        /// Path to a serialized SRS.
        #[arg(long)]
        srs: PathBuf,
        /// Output file for the canonical VK bytes.
        #[arg(long)]
        output: PathBuf,
    },

    /// Emit a Solidity verifier contract directly from a registered circuit.
    ///
    /// Internally performs `extract_vk` + `generate_verifier_sol_with` in a
    /// single step, so no intermediate VK file is required. This is the
    /// usual one-command path from "I changed my Circuit" to "I have a
    /// Solidity verifier to redeploy".
    EmitVerifier {
        /// Short CLI name of the registered circuit.
        #[arg(long)]
        circuit: String,
        /// Path to a serialized SRS.
        #[arg(long)]
        srs: PathBuf,
        /// Output directory; the file is written as
        /// `<dir>/<contract_name>.sol`.
        #[arg(long)]
        output: PathBuf,
        /// Solidity contract name. Defaults to `"genshiVerifier"`.
        #[arg(long, default_value = "genshiVerifier")]
        contract_name: String,
        /// Solidity pragma version string.
        #[arg(long, default_value = "^0.8.24")]
        pragma: String,
        /// Optional NatSpec `@notice` line rendered at the top of the
        /// contract.
        #[arg(long)]
        notice: Option<String>,
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

    /// Generate a Solidity verifier contract from a pre-serialized VK file.
    ///
    /// Use this when you already have a `.vk` on disk (for example because
    /// it was distributed separately from the source code). For the common
    /// "I just want a verifier for my circuit" flow, prefer
    /// [`Commands::EmitVerifier`].
    EmitEvm {
        /// Path to serialized VK.
        #[arg(long)]
        vk: PathBuf,
        /// Path to serialized SRS.
        #[arg(long)]
        srs: PathBuf,
        /// Output directory.
        #[arg(long)]
        output: PathBuf,
        /// Solidity contract name.
        #[arg(long, default_value = "genshiVerifier")]
        contract_name: String,
        /// Solidity pragma version string.
        #[arg(long, default_value = "^0.8.24")]
        pragma: String,
    },

    /// Emit the Poseidon2.sol Solidity library.
    EmitPoseidon2 {
        /// Output directory; the file is written as
        /// `<dir>/Poseidon2.sol`.
        #[arg(long)]
        output: PathBuf,
    },

    /// Emit genshi's reusable Solidity libraries (MerkleTree, NullifierSet,
    /// RootHistory, …).
    EmitLibs {
        /// Output directory.
        #[arg(long)]
        output: PathBuf,
    },

    /// Generate a witness JSON file for a registered circuit.
    ///
    /// Outputs a valid, provable witness built from the circuit's default
    /// values. You can pass it directly to `prove` to confirm the pipeline
    /// works, then edit the JSON with your own data.
    ///
    /// ```text
    /// genshi gen-witness --circuit transfer --output witness.json
    /// genshi prove --circuit transfer --witness witness.json --srs srs.bin --output out/
    /// ```
    GenWitness {
        /// Short CLI name of the registered circuit (e.g. "transfer").
        #[arg(long)]
        circuit: String,
        /// Output file path. Defaults to stdout if omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Generate a proof from a witness JSON file.
    ///
    /// Reads the witness from `--witness`, deserializes it into the circuit's
    /// native `Witness` type (via serde), runs the prover, and writes:
    /// - `<output>/proof.bin` — canonical proof bytes
    /// - `<output>/public_inputs.bin` — public inputs as 32-byte LE Fr elements
    /// - `<output>/vk.bin` — verification key
    ///
    /// The witness JSON schema is defined by the circuit's `Witness` type.
    Prove {
        /// Short CLI name of the registered circuit (e.g. "transfer").
        #[arg(long)]
        circuit: String,
        /// Path to the witness JSON file.
        #[arg(long)]
        witness: PathBuf,
        /// Path to a serialized SRS.
        #[arg(long)]
        srs: PathBuf,
        /// Output directory for proof artifacts.
        #[arg(long)]
        output: PathBuf,
    },

    /// Verify a proof natively given (proof, vk, public-inputs, srs) files.
    ///
    /// Public inputs are expected as concatenated 32-byte little-endian Fr
    /// elements — the canonical genshi Solana-side encoding.
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

#[derive(Subcommand)]
enum SrsCmd {
    /// Generate an insecure, for-testing-only SRS and write it to disk.
    ///
    /// WARNING: uses a known secret tau. Production deployments must consume
    /// an SRS derived from a verifiable ceremony (e.g. Aztec's Powers of
    /// Tau).
    New {
        /// Maximum polynomial degree the SRS should support.
        #[arg(long)]
        max_degree: usize,
        /// Output file path for the serialized SRS.
        #[arg(long)]
        output: PathBuf,
    },

    /// Import an SRS from a Powers of Tau `.ptau` ceremony file.
    ///
    /// Reads the BN254 G1/G2 points from a `.ptau` file (snarkjs / Hermez
    /// format) and converts them to genshi's internal SRS format. The
    /// `--max-degree` flag trims the imported SRS to the specified degree.
    ///
    /// Use this for production deployments where you want a ceremony-backed
    /// SRS instead of the insecure `srs new` shortcut.
    Import {
        /// Path to the `.ptau` ceremony file.
        #[arg(long)]
        input: PathBuf,
        /// Maximum polynomial degree to retain from the ceremony.
        #[arg(long)]
        max_degree: usize,
        /// Output file path for the serialized SRS.
        #[arg(long)]
        output: PathBuf,
    },

    /// Run a Powers-of-Tau ceremony and write the resulting SRS to disk.
    ///
    /// Generates a production-grade SRS using a multi-party ceremony with
    /// OS entropy. Security model: 1-of-N trust — as long as ANY participant
    /// destroys their secret, the toxic waste is unrecoverable.
    ///
    /// ```text
    /// genshi srs ceremony --max-degree 65536 --participants 3 --output srs.bin
    /// ```
    Ceremony {
        /// Maximum polynomial degree the SRS should support.
        #[arg(long)]
        max_degree: usize,
        /// Number of ceremony participants (each contributes OS entropy).
        #[arg(long, default_value_t = 3)]
        participants: usize,
        /// Output file path for the serialized SRS.
        #[arg(long)]
        output: PathBuf,
    },

    /// Verify the pairing consistency of an existing SRS file.
    ///
    /// Checks that all G1 points encode consecutive powers of the same tau
    /// and that g2_tau is consistent with the G1 sequence.
    ///
    /// ```text
    /// genshi srs verify --file srs.bin
    /// ```
    Verify {
        /// Path to the SRS file to verify.
        #[arg(long)]
        file: PathBuf,
    },
}

// ============================================================================
// Entry point
// ============================================================================

/// Parse argv, dispatch to the selected subcommand, and return an exit code.
///
/// This is the function downstream crates call from their `src/bin/genshi.rs`.
/// It is also what the `genshi` binary shipped with this crate invokes.
pub fn run() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::New {
            name,
            path,
            source,
        } => cmd_new(&name, path.as_deref(), &source),
        Commands::Srs(SrsCmd::New { max_degree, output }) => {
            cmd_srs_new(max_degree, &output)
        }
        Commands::Srs(SrsCmd::Import {
            input,
            max_degree,
            output,
        }) => cmd_srs_import(&input, max_degree, &output),
        Commands::Srs(SrsCmd::Ceremony {
            max_degree,
            participants,
            output,
        }) => cmd_srs_ceremony(max_degree, participants, &output),
        Commands::Srs(SrsCmd::Verify { file }) => cmd_srs_verify(&file),
        Commands::Circuits => cmd_circuits_list(),
        Commands::ExtractVk {
            circuit,
            srs,
            output,
        } => cmd_extract_vk(&circuit, &srs, &output),
        Commands::EmitVerifier {
            circuit,
            srs,
            output,
            contract_name,
            pragma,
            notice,
        } => cmd_emit_verifier(
            &circuit,
            &srs,
            &output,
            &contract_name,
            &pragma,
            notice.as_deref(),
        ),
        Commands::Inspect { kind, file } => cmd_inspect(&kind, &file),
        Commands::EmitEvm {
            vk,
            srs,
            output,
            contract_name,
            pragma,
        } => cmd_emit_evm(&vk, &srs, &output, &contract_name, &pragma),
        Commands::GenWitness { circuit, output } => {
            cmd_gen_witness(&circuit, output.as_deref())
        }
        Commands::Prove {
            circuit,
            witness,
            srs,
            output,
        } => cmd_prove(&circuit, &witness, &srs, &output),
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

// ============================================================================
// Command implementations
// ============================================================================

fn cmd_srs_new(max_degree: usize, output: &Path) -> ExitCode {
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

fn cmd_srs_import(input: &Path, max_degree: usize, output: &Path) -> ExitCode {
    let raw = match fs::read(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read ptau file {}: {e}", input.display());
            return ExitCode::FAILURE;
        }
    };

    let srs = match parse_ptau(&raw, max_degree) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ptau import failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let bytes = srs.save_to_bytes();
    match fs::write(output, &bytes) {
        Ok(()) => {
            println!(
                "imported ceremony SRS (max_degree={}, {} G1 points, {} bytes) to {}",
                srs.max_degree(),
                srs.size(),
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

fn cmd_srs_ceremony(max_degree: usize, participants: usize, output: &Path) -> ExitCode {
    if participants == 0 {
        eprintln!("participants must be at least 1");
        return ExitCode::FAILURE;
    }

    let (srs, _receipts) = ceremony::run_ceremony(max_degree, participants);

    let bytes = srs.save_to_bytes();
    match fs::write(output, &bytes) {
        Ok(()) => {
            println!(
                "wrote ceremony SRS (max_degree={}, {} participants, {} G1 points, {} bytes) to {}",
                max_degree,
                participants,
                srs.g1_powers.len(),
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

fn cmd_srs_verify(file: &Path) -> ExitCode {
    let srs = match load_srs(file) {
        Ok(s) => s,
        Err(code) => return code,
    };

    match ceremony::verify_srs(&srs) {
        Ok(()) => {
            println!(
                "OK: SRS is valid (max_degree={}, {} G1 points)",
                srs.g1_powers.len() - 1,
                srs.g1_powers.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: SRS verification failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_gen_witness(circuit_name: &str, output: Option<&Path>) -> ExitCode {
    let entry = match find_circuit(circuit_name) {
        Some(e) => e,
        None => return report_unknown_circuit(circuit_name),
    };

    let json = match (entry.witness_json)() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("gen-witness failed for circuit `{circuit_name}`: {e}");
            return ExitCode::FAILURE;
        }
    };

    match output {
        Some(path) => {
            if let Err(e) = fs::write(path, json.as_bytes()) {
                eprintln!("failed to write witness: {e}");
                return ExitCode::FAILURE;
            }
            println!(
                "wrote witness for circuit `{circuit_name}` to {}",
                path.display()
            );
        }
        None => {
            print!("{json}");
        }
    }
    ExitCode::SUCCESS
}

fn cmd_prove(
    circuit_name: &str,
    witness_path: &Path,
    srs_path: &Path,
    output_dir: &Path,
) -> ExitCode {
    let entry = match find_circuit(circuit_name) {
        Some(e) => e,
        None => return report_unknown_circuit(circuit_name),
    };
    let srs = match load_srs(srs_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let witness_json = match fs::read_to_string(witness_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read witness {}: {e}", witness_path.display());
            return ExitCode::FAILURE;
        }
    };

    let (proof_bytes, vk_bytes, pi_bytes) = match (entry.prove_from_json)(&witness_json, &srs) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("prove failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    let proof_path = output_dir.join("proof.bin");
    let vk_path = output_dir.join("vk.bin");
    let pi_path = output_dir.join("public_inputs.bin");

    for (path, data, label) in [
        (&proof_path, &proof_bytes, "proof"),
        (&vk_path, &vk_bytes, "vk"),
        (&pi_path, &pi_bytes, "public inputs"),
    ] {
        if let Err(e) = fs::write(path, data) {
            eprintln!("failed to write {label}: {e}");
            return ExitCode::FAILURE;
        }
    }

    println!(
        "proved circuit `{circuit_name}` ({} public inputs)",
        pi_bytes.len() / 32,
    );
    println!("  proof:         {} ({} bytes)", proof_path.display(), proof_bytes.len());
    println!("  vk:            {} ({} bytes)", vk_path.display(), vk_bytes.len());
    println!("  public_inputs: {} ({} bytes)", pi_path.display(), pi_bytes.len());
    ExitCode::SUCCESS
}

fn cmd_circuits_list() -> ExitCode {
    let mut any = false;
    for c in all_circuits() {
        any = true;
        println!(
            "{:<24} id={:<32} num_public_inputs={}",
            c.name,
            c.id,
            (c.num_public_inputs)()
        );
    }
    if !any {
        eprintln!(
            "no circuits registered in this binary\n\
             note: use `genshi_cli::register!(MyCircuit, \"my-circuit\")` in \
             a dependency crate to populate the registry"
        );
    }
    ExitCode::SUCCESS
}

fn cmd_extract_vk(circuit_name: &str, srs_path: &Path, output: &Path) -> ExitCode {
    let entry = match find_circuit(circuit_name) {
        Some(e) => e,
        None => return report_unknown_circuit(circuit_name),
    };
    let srs = match load_srs(srs_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let vk_bytes = (entry.extract_vk_bytes)(&srs);
    if let Err(e) = fs::write(output, &vk_bytes) {
        eprintln!("failed to write vk: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "wrote VK for circuit `{}` ({} bytes) to {}",
        circuit_name,
        vk_bytes.len(),
        output.display()
    );
    ExitCode::SUCCESS
}

fn cmd_emit_verifier(
    circuit_name: &str,
    srs_path: &Path,
    output_dir: &Path,
    contract_name: &str,
    pragma: &str,
    notice: Option<&str>,
) -> ExitCode {
    let entry = match find_circuit(circuit_name) {
        Some(e) => e,
        None => return report_unknown_circuit(circuit_name),
    };
    let srs = match load_srs(srs_path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    let mut opts = genshi_evm::solidity_emitter::EmitterOptions::default()
        .with_contract_name(contract_name)
        .with_pragma(pragma);
    if let Some(n) = notice {
        opts = opts.with_notice(n);
    }

    let sol = (entry.emit_solidity)(&srs, &opts);
    let out = output_dir.join(format!("{contract_name}.sol"));
    if let Err(e) = fs::write(&out, sol.as_bytes()) {
        eprintln!("failed to write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }

    println!(
        "wrote Solidity verifier for circuit `{}` ({} public inputs) to {}",
        circuit_name,
        (entry.num_public_inputs)(),
        out.display()
    );
    ExitCode::SUCCESS
}

fn cmd_inspect(kind: &str, file: &Path) -> ExitCode {
    let bytes = match fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read {}: {e}", file.display());
            return ExitCode::FAILURE;
        }
    };

    match kind {
        "proof" => match proof_from_bytes(&bytes) {
            Ok(_) => {
                println!("proof OK: {} bytes", bytes.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("proof decode failed: {e:?}");
                ExitCode::FAILURE
            }
        },
        "vk" => match vk_from_bytes(&bytes) {
            Ok(_) => {
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
    vk_path: &Path,
    srs_path: &Path,
    output_dir: &Path,
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
    let srs = match load_srs(srs_path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    let opts = genshi_evm::solidity_emitter::EmitterOptions::default()
        .with_contract_name(contract_name)
        .with_pragma(pragma);
    let sol = genshi_evm::solidity_emitter::generate_verifier_sol_with(&vk, &srs, &opts);
    let out = output_dir.join(format!("{contract_name}.sol"));
    if let Err(e) = fs::write(&out, sol.as_bytes()) {
        eprintln!("failed to write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }

    println!("wrote Solidity verifier to {}", out.display());
    ExitCode::SUCCESS
}

fn cmd_emit_poseidon2(output_dir: &Path) -> ExitCode {
    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    let sol = genshi_evm::poseidon2_sol::generate_poseidon2_sol();
    let out = output_dir.join("Poseidon2.sol");
    if let Err(e) = fs::write(&out, sol.as_bytes()) {
        eprintln!("failed to write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }

    println!("wrote Poseidon2 library to {}", out.display());
    ExitCode::SUCCESS
}

fn cmd_emit_libs(output_dir: &Path) -> ExitCode {
    if let Err(e) = fs::create_dir_all(output_dir) {
        eprintln!("failed to create output dir: {e}");
        return ExitCode::FAILURE;
    }

    for name in genshi_evm::library_names() {
        let src = match genshi_evm::library_source(name) {
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
    proof_path: &Path,
    vk_path: &Path,
    pi_path: &Path,
    srs_path: &Path,
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
    let srs = match load_srs(srs_path) {
        Ok(s) => s,
        Err(code) => return code,
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

// ============================================================================
// `genshi new` — project scaffolder
// ============================================================================

/// Source to use for `genshi-core` / `genshi-cli` in a scaffolded project.
enum DepSource {
    /// Pull both crates from the upstream GitHub repo.
    Git,
    /// Pull both crates as path dependencies rooted at the given directory
    /// (which must contain `crates/genshi-core` and `crates/genshi-cli`).
    /// Primarily for developing genshi itself.
    Path(PathBuf),
}

fn parse_source(s: &str) -> Result<DepSource, String> {
    if s == "git" {
        return Ok(DepSource::Git);
    }
    if let Some(p) = s.strip_prefix("path:") {
        if p.is_empty() {
            return Err("`path:` requires a directory after the colon".into());
        }
        return Ok(DepSource::Path(PathBuf::from(p)));
    }
    Err(format!(
        "unknown source `{s}`; expected `git` or `path:<abs-dir>`"
    ))
}

/// Validate a crate name against Cargo's rules (plus our own "no leading
/// digit" constraint because the name is also used as a Rust identifier in
/// the generated `src/bin/genshi.rs`).
fn validate_crate_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("name must not be empty");
    }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err("name must start with an ASCII letter or underscore");
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err("name may only contain ASCII letters, digits, `-`, and `_`");
        }
    }
    Ok(())
}

fn cmd_new(name: &str, parent: Option<&Path>, source_str: &str) -> ExitCode {
    if let Err(e) = validate_crate_name(name) {
        eprintln!("invalid crate name `{name}`: {e}");
        return ExitCode::FAILURE;
    }
    let source = match parse_source(source_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invalid --source: {e}");
            return ExitCode::FAILURE;
        }
    };

    let parent_dir = match parent {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("failed to get current dir: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let target = parent_dir.join(name);
    if target.exists() {
        eprintln!(
            "refusing to overwrite existing directory: {}",
            target.display()
        );
        return ExitCode::FAILURE;
    }

    // Rust `extern crate` form: hyphens become underscores.
    let crate_ident = name.replace('-', "_");

    // Render the deps block from the chosen source.
    let deps_block = match &source {
        DepSource::Git => String::from(
            "genshi-core = { git = \"https://github.com/shroud-network/genshi\", features = [\"serde\"] }\n\
             genshi-cli  = { git = \"https://github.com/shroud-network/genshi\" }",
        ),
        DepSource::Path(p) => {
            let base = p.display();
            format!(
                "genshi-core = {{ path = \"{base}/crates/genshi-core\", features = [\"serde\"] }}\n\
                 genshi-cli  = {{ path = \"{base}/crates/genshi-cli\" }}"
            )
        }
    };

    let cargo_toml = SCAFFOLD_CARGO_TOML
        .replace("{{name}}", name)
        .replace("{{deps}}", &deps_block);
    let lib_rs = SCAFFOLD_LIB_RS.to_string();
    let bin_rs = SCAFFOLD_BIN_RS.replace("{{crate_ident}}", &crate_ident);
    let readme = SCAFFOLD_README.replace("{{name}}", name);
    let gitignore = SCAFFOLD_GITIGNORE.to_string();

    // Layout:
    //   <target>/Cargo.toml
    //   <target>/README.md
    //   <target>/.gitignore
    //   <target>/src/lib.rs
    //   <target>/src/bin/genshi.rs
    //   <target>/src/circuits/mod.rs
    //   <target>/src/circuits/add.rs
    let src_dir = target.join("src");
    let bin_dir = src_dir.join("bin");
    let circuits_dir = src_dir.join("circuits");
    if let Err(e) = fs::create_dir_all(&bin_dir) {
        eprintln!("failed to create {}: {e}", bin_dir.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::create_dir_all(&circuits_dir) {
        eprintln!("failed to create {}: {e}", circuits_dir.display());
        return ExitCode::FAILURE;
    }

    let circuits_mod_rs = SCAFFOLD_CIRCUITS_MOD_RS.to_string();
    let circuits_add_rs = SCAFFOLD_CIRCUITS_ADD_RS.to_string();

    let files: [(PathBuf, String); 7] = [
        (target.join("Cargo.toml"), cargo_toml),
        (target.join("README.md"), readme),
        (target.join(".gitignore"), gitignore),
        (src_dir.join("lib.rs"), lib_rs),
        (bin_dir.join("genshi.rs"), bin_rs),
        (circuits_dir.join("mod.rs"), circuits_mod_rs),
        (circuits_dir.join("add.rs"), circuits_add_rs),
    ];
    for (path, content) in &files {
        if let Err(e) = fs::write(path, content) {
            eprintln!("failed to write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    }

    println!(
        "Created genshi application `{name}` at {}",
        target.display()
    );
    println!();
    println!("Next steps:");
    println!("  cd {name}");
    println!("  cargo run --bin genshi -- circuits");
    println!("  cargo run --bin genshi -- srs ceremony --max-degree 1024 --participants 1 --output srs.bin");
    println!("  cargo run --bin genshi -- gen-witness --circuit add --output witness.json");
    println!("  cargo run --bin genshi -- prove --circuit add --witness witness.json --srs srs.bin --output out/");
    println!("  cargo run --bin genshi -- verify --proof out/proof.bin --vk out/vk.bin --public-inputs out/public_inputs.bin --srs srs.bin");
    println!();
    println!("Add new circuits in src/circuits/ and register them with");
    println!("`genshi_cli::register!(YourCircuit, \"name\")` next to the impl.");

    ExitCode::SUCCESS
}

// ----------------------------------------------------------------------------
// Scaffold templates (embedded as static strings so the binary is self-
// contained; no external `templates/` directory to ship).
// ----------------------------------------------------------------------------

const SCAFFOLD_CARGO_TOML: &str = r#"[package]
name = "{{name}}"
version = "0.1.0"
edition = "2024"
rust-version = "1.85.0"
license = "MIT OR Apache-2.0"
description = "genshi ZK application scaffolded by `genshi new`"

[dependencies]
# genshi framework. The `genshi_cli::register!` calls in src/lib.rs live in a
# linker section that `src/bin/genshi.rs` pulls in via `use {{name}} as _;`.
{{deps}}

ark-bn254 = { version = "0.5", default-features = false }
serde = { version = "1", features = ["derive"] }
"#;

const SCAFFOLD_LIB_RS: &str = r#"//! A genshi application scaffolded by `genshi new`.
//!
//! ## Project layout
//!
//! ```text
//! src/
//! ├── lib.rs              ← you are here (crate root)
//! ├── bin/genshi.rs       ← CLI shim (do not edit)
//! └── circuits/
//!     ├── mod.rs           ← register circuit modules here
//!     └── add.rs           ← example circuit (replace with your own)
//! ```
//!
//! Add new circuits in `src/circuits/`. Each circuit file should:
//! 1. `impl Circuit for MyCircuit`
//! 2. Call `genshi_cli::register!(MyCircuit, "name")` next to the impl
//! 3. Be declared as `pub mod my_circuit;` in `src/circuits/mod.rs`

pub mod circuits;
"#;

const SCAFFOLD_BIN_RS: &str = r#"//! Entry point for this crate's `genshi` binary.
//!
//! The `use {{crate_ident}} as _;` line is load-bearing. It forces the Rust
//! linker to keep the `genshi_cli::register!(...)` statics defined in the
//! library crate alive inside the final binary — without it, the registry
//! would be empty at runtime and `genshi circuits list` would print nothing.
//!
//! You do not edit this file. Add new circuits in `src/lib.rs` alongside a
//! `genshi_cli::register!(...)` line and they automatically show up in the
//! CLI on the next rebuild.

use {{crate_ident}} as _;

fn main() -> std::process::ExitCode {
    genshi_cli::run()
}
"#;

const SCAFFOLD_README: &str = r#"# {{name}}

A genshi ZK application scaffolded by `genshi new`.

## Quick start

```bash
cargo run --bin genshi -- circuits
cargo run --bin genshi -- srs ceremony --max-degree 1024 --participants 1 --output srs.bin
cargo run --bin genshi -- gen-witness --circuit add --output witness.json
cargo run --bin genshi -- prove --circuit add --witness witness.json --srs srs.bin --output out/
cargo run --bin genshi -- verify --proof out/proof.bin --vk out/vk.bin --public-inputs out/public_inputs.bin --srs srs.bin
```

## Project layout

```
src/
├── lib.rs              # crate root
├── bin/genshi.rs       # CLI shim (do not edit)
└── circuits/
    ├── mod.rs          # register circuit modules here
    └── add.rs          # example circuit (replace with your own)
```

## Adding a circuit

1. Create a new file in `src/circuits/` (e.g. `my_circuit.rs`).
2. `impl genshi_core::circuit::Circuit for MyCircuit`.
3. Add `genshi_cli::register!(MyCircuit, "my-circuit");` next to the impl.
4. Declare the module in `src/circuits/mod.rs`: `pub mod my_circuit;`
5. Rebuild — the new circuit shows up in `cargo run --bin genshi -- circuits`.

## Framework gadgets

genshi ships reusable gadgets you can compose in your circuits:

- `genshi_core::gadgets::nullifier` — anti-double-spend nullifier derivation
- `genshi_core::gadgets::commitment` — note commitment (variable-field + Pedersen)
- `genshi_core::gadgets::merkle` — Merkle inclusion proofs
- `genshi_core::gadgets::range_proof` — range checks (8/16/32/64-bit)
- `genshi_core::gadgets::poseidon2_gadget` — Poseidon2 hashes
"#;

const SCAFFOLD_GITIGNORE: &str = "target/\n*.bin\n*.vk\n";

const SCAFFOLD_CIRCUITS_MOD_RS: &str = r#"//! Circuit modules.
//!
//! Add your circuits here. Each circuit file should define a struct that
//! implements `genshi_core::circuit::Circuit` and register it with
//! `genshi_cli::register!(MyCircuit, "name")`.

pub mod add;
"#;

const SCAFFOLD_CIRCUITS_ADD_RS: &str = r#"//! Example "a + b = c" circuit.
//!
//! Replace this with your own circuit. Keep the `genshi_cli::register!` line
//! at the bottom so the CLI can dispatch `--circuit add` to it.

use ark_bn254::Fr;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use genshi_core::circuit::Circuit;

pub struct AddCircuit;

/// Native witness for [`AddCircuit`].
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AddWitness {
    pub a: u64,
    pub b: u64,
}

impl Circuit for AddCircuit {
    type Witness = AddWitness;
    type PublicInputs = [Fr; 1];
    const ID: &'static str = "example.add";

    fn num_public_inputs() -> usize {
        1
    }

    fn synthesize(
        builder: &mut UltraCircuitBuilder,
        w: &Self::Witness,
    ) -> Self::PublicInputs {
        let a = builder.add_variable(Fr::from(w.a));
        let b = builder.add_variable(Fr::from(w.b));
        let c = builder.add(a, b);
        builder.set_public(c);
        [Fr::from(w.a) + Fr::from(w.b)]
    }

    fn dummy_witness() -> Self::Witness {
        AddWitness { a: 0, b: 0 }
    }
}

genshi_cli::register!(AddCircuit, "add");
"#;

// ============================================================================
// ptau parser (snarkjs / Hermez format)
// ============================================================================

/// Parse a Powers of Tau `.ptau` file (snarkjs/Hermez binary format) and
/// extract the BN254 G1/G2 points into a genshi SRS.
///
/// The `.ptau` format is a sequence of "sections" prefixed by a 12-byte
/// magic header (`zk_s_n_a_r_k_s`). We only read:
/// - Section 2: G1 powers (`τ^i · G1`)
/// - Section 3: G2 powers (`τ^i · G2` — we only need index 0 and 1)
///
/// Points in .ptau files are little-endian uncompressed BN254 coordinates.
fn parse_ptau(data: &[u8], max_degree: usize) -> Result<SRS, String> {
    use ark_bn254::{G1Affine, G2Affine, Fq, Fq2};
    use ark_ec::AffineRepr;

    // --- Header ---
    // First 4 bytes: magic "zks\n" or similar; varies by snarkjs version.
    // We look for the sections by scanning section headers.
    // snarkjs ptau binary layout:
    //   [4 bytes magic] [4 bytes version] [4 bytes num_sections]
    //   then for each section: [4 bytes section_type] [8 bytes section_size] [data...]

    if data.len() < 12 {
        return Err("ptau file too short".into());
    }

    let num_sections = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let mut offset = 12;

    // Section catalog: find section 2 (G1 powers) and section 3 (G2 powers)
    let mut g1_section: Option<(usize, usize)> = None; // (offset, size)
    let mut g2_section: Option<(usize, usize)> = None;

    for _ in 0..num_sections {
        if offset + 12 > data.len() {
            return Err("ptau section header truncated".into());
        }
        let section_type = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let section_size = u64::from_le_bytes(data[offset + 4..offset + 12].try_into().unwrap()) as usize;
        offset += 12;

        if offset + section_size > data.len() {
            return Err(format!(
                "ptau section {section_type} claims {section_size} bytes but file too short"
            ));
        }

        match section_type {
            2 => g1_section = Some((offset, section_size)),
            3 => g2_section = Some((offset, section_size)),
            _ => {}
        }
        offset += section_size;
    }

    let (g1_off, g1_size) = g1_section.ok_or("ptau file missing section 2 (G1 powers)")?;
    let (g2_off, g2_size) = g2_section.ok_or("ptau file missing section 3 (G2 powers)")?;

    // --- Parse G1 points ---
    // Each G1 point: 64 bytes (x: 32 bytes LE Fq, y: 32 bytes LE Fq)
    let g1_point_size = 64;
    let num_g1 = g1_size / g1_point_size;
    let need = max_degree + 1;
    if num_g1 < need {
        return Err(format!(
            "ptau has {num_g1} G1 points but max_degree={max_degree} requires {}",
            need
        ));
    }

    let mut g1_powers = Vec::with_capacity(need);
    for i in 0..need {
        let base = g1_off + i * g1_point_size;
        let x = Fq::from_le_bytes_mod_order(&data[base..base + 32]);
        let y = Fq::from_le_bytes_mod_order(&data[base + 32..base + 64]);
        let point = G1Affine::new_unchecked(x, y);
        if !point.is_on_curve() {
            return Err(format!("G1 point {i} not on curve"));
        }
        g1_powers.push(point);
    }

    // --- Parse G2 points ---
    // Each G2 point: 128 bytes (x: Fq2 = 64 bytes LE, y: Fq2 = 64 bytes LE)
    // Fq2 layout: c0 (32 bytes LE) || c1 (32 bytes LE)
    let g2_point_size = 128;
    let num_g2 = g2_size / g2_point_size;
    if num_g2 < 2 {
        return Err(format!("ptau has {num_g2} G2 points, need at least 2"));
    }

    let read_g2 = |idx: usize| -> Result<G2Affine, String> {
        let base = g2_off + idx * g2_point_size;
        let x_c0 = Fq::from_le_bytes_mod_order(&data[base..base + 32]);
        let x_c1 = Fq::from_le_bytes_mod_order(&data[base + 32..base + 64]);
        let y_c0 = Fq::from_le_bytes_mod_order(&data[base + 64..base + 96]);
        let y_c1 = Fq::from_le_bytes_mod_order(&data[base + 96..base + 128]);
        let x = Fq2::new(x_c0, x_c1);
        let y = Fq2::new(y_c0, y_c1);
        let point = G2Affine::new_unchecked(x, y);
        if !point.is_on_curve() {
            return Err(format!("G2 point {idx} not on curve"));
        }
        Ok(point)
    };

    let g2 = read_g2(0)?;     // τ^0 · G2 = G2 generator
    let g2_tau = read_g2(1)?;  // τ^1 · G2

    // Sanity: g1_powers[0] should be the BN254 G1 generator
    if g1_powers[0] != G1Affine::generator() {
        return Err("G1 powers[0] is not the BN254 generator — file may be corrupt or for a different curve".into());
    }

    Ok(SRS {
        g1_powers,
        g2,
        g2_tau,
    })
}

// ============================================================================
// Shared helpers
// ============================================================================

fn load_srs(path: &Path) -> Result<SRS, ExitCode> {
    match fs::read(path) {
        Ok(bytes) => Ok(SRS::load_from_bytes(&bytes)),
        Err(e) => {
            eprintln!("failed to read srs {}: {e}", path.display());
            Err(ExitCode::FAILURE)
        }
    }
}

fn report_unknown_circuit(name: &str) -> ExitCode {
    eprintln!("unknown circuit: `{name}`");
    let available: Vec<&'static str> = all_circuits().map(|c| c.name).collect();
    if available.is_empty() {
        eprintln!(
            "no circuits are registered in this binary — did you forget a \
             `genshi_cli::register!(MyCircuit, \"my-circuit\")` call?"
        );
    } else {
        eprintln!("available circuits: {}", available.join(", "));
    }
    ExitCode::FAILURE
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ================================================================
    // validate_crate_name
    // ================================================================

    #[test]
    fn test_validate_crate_name_valid_simple() {
        assert!(validate_crate_name("my-circuits").is_ok());
    }

    #[test]
    fn test_validate_crate_name_valid_underscore() {
        assert!(validate_crate_name("my_circuits").is_ok());
    }

    #[test]
    fn test_validate_crate_name_valid_leading_underscore() {
        assert!(validate_crate_name("_private").is_ok());
    }

    #[test]
    fn test_validate_crate_name_valid_single_letter() {
        assert!(validate_crate_name("x").is_ok());
    }

    #[test]
    fn test_validate_crate_name_valid_with_digits() {
        assert!(validate_crate_name("circuit2").is_ok());
    }

    #[test]
    fn test_validate_crate_name_empty() {
        assert!(validate_crate_name("").is_err());
    }

    #[test]
    fn test_validate_crate_name_starts_with_digit() {
        assert!(validate_crate_name("3circuits").is_err());
    }

    #[test]
    fn test_validate_crate_name_starts_with_hyphen() {
        assert!(validate_crate_name("-bad").is_err());
    }

    #[test]
    fn test_validate_crate_name_contains_space() {
        assert!(validate_crate_name("my circuits").is_err());
    }

    #[test]
    fn test_validate_crate_name_contains_dot() {
        assert!(validate_crate_name("my.circuits").is_err());
    }

    #[test]
    fn test_validate_crate_name_contains_slash() {
        assert!(validate_crate_name("my/circuits").is_err());
    }

    #[test]
    fn test_validate_crate_name_contains_at() {
        assert!(validate_crate_name("@scoped").is_err());
    }

    // ================================================================
    // parse_source
    // ================================================================

    #[test]
    fn test_parse_source_git() {
        let result = parse_source("git");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), DepSource::Git));
    }

    #[test]
    fn test_parse_source_path() {
        let result = parse_source("path:/some/dir");
        assert!(result.is_ok());
        match result.unwrap() {
            DepSource::Path(p) => assert_eq!(p, PathBuf::from("/some/dir")),
            _ => panic!("Expected DepSource::Path"),
        }
    }

    #[test]
    fn test_parse_source_path_empty_dir() {
        let result = parse_source("path:");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_source_unknown() {
        assert!(parse_source("crates.io").is_err());
    }

    #[test]
    fn test_parse_source_empty() {
        assert!(parse_source("").is_err());
    }

    #[test]
    fn test_parse_source_path_with_spaces() {
        let result = parse_source("path:/some/dir with spaces");
        assert!(result.is_ok());
        match result.unwrap() {
            DepSource::Path(p) => assert_eq!(p, PathBuf::from("/some/dir with spaces")),
            _ => panic!("Expected DepSource::Path"),
        }
    }

    // ================================================================
    // find_circuit / all_circuits (empty registry in test binary)
    // ================================================================

    #[test]
    fn test_find_circuit_nonexistent() {
        // In the test binary, no circuits are registered via inventory
        assert!(find_circuit("nonexistent").is_none());
    }

    // ================================================================
    // Scaffold template rendering
    // ================================================================

    #[test]
    fn test_scaffold_cargo_toml_renders_name() {
        let rendered = SCAFFOLD_CARGO_TOML.replace("{{name}}", "my-app");
        assert!(rendered.contains("name = \"my-app\""));
    }

    #[test]
    fn test_scaffold_cargo_toml_renders_git_deps() {
        let deps = "genshi-core = { git = \"https://github.com/shroud-network/genshi\", features = [\"serde\"] }\n\
                     genshi-cli  = { git = \"https://github.com/shroud-network/genshi\" }";
        let rendered = SCAFFOLD_CARGO_TOML
            .replace("{{name}}", "test-crate")
            .replace("{{deps}}", deps);
        assert!(rendered.contains("genshi-core"));
        assert!(rendered.contains("genshi-cli"));
        assert!(rendered.contains("shroud-network/genshi"));
    }

    #[test]
    fn test_scaffold_cargo_toml_renders_path_deps() {
        let deps = "genshi-core = { path = \"/my/local/crates/genshi-core\", features = [\"serde\"] }\n\
                     genshi-cli  = { path = \"/my/local/crates/genshi-cli\" }";
        let rendered = SCAFFOLD_CARGO_TOML
            .replace("{{name}}", "test-crate")
            .replace("{{deps}}", deps);
        assert!(rendered.contains("path = \"/my/local/crates/genshi-core\""));
    }

    #[test]
    fn test_scaffold_bin_rs_renders_crate_ident() {
        let rendered = SCAFFOLD_BIN_RS.replace("{{crate_ident}}", "my_app");
        assert!(rendered.contains("use my_app as _;"));
        assert!(rendered.contains("genshi_cli::run()"));
    }

    #[test]
    fn test_scaffold_bin_rs_hyphen_to_underscore() {
        let name = "my-cool-app";
        let crate_ident = name.replace('-', "_");
        let rendered = SCAFFOLD_BIN_RS.replace("{{crate_ident}}", &crate_ident);
        assert!(rendered.contains("use my_cool_app as _;"));
    }

    #[test]
    fn test_scaffold_lib_rs_declares_circuits_module() {
        assert!(SCAFFOLD_LIB_RS.contains("pub mod circuits;"));
    }

    #[test]
    fn test_scaffold_circuits_add_has_impl_and_register() {
        assert!(SCAFFOLD_CIRCUITS_ADD_RS.contains("impl Circuit for AddCircuit"));
        assert!(SCAFFOLD_CIRCUITS_ADD_RS.contains("genshi_cli::register!(AddCircuit, \"add\")"));
        assert!(SCAFFOLD_CIRCUITS_ADD_RS.contains("serde::Serialize"));
        assert!(SCAFFOLD_CIRCUITS_ADD_RS.contains("serde::Deserialize"));
    }

    #[test]
    fn test_scaffold_circuits_mod_declares_add() {
        assert!(SCAFFOLD_CIRCUITS_MOD_RS.contains("pub mod add;"));
    }

    #[test]
    fn test_scaffold_readme_renders_name() {
        let rendered = SCAFFOLD_README.replace("{{name}}", "my-app");
        assert!(rendered.contains("# my-app"));
    }

    #[test]
    fn test_scaffold_gitignore_has_target() {
        assert!(SCAFFOLD_GITIGNORE.contains("target/"));
    }

    // ================================================================
    // cmd_new on filesystem (uses temp dir)
    // ================================================================

    #[test]
    fn test_cmd_new_creates_all_files() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let result = cmd_new("test-crate", Some(tmp.as_path()), "git");
        assert_eq!(result, ExitCode::SUCCESS);

        let crate_dir = tmp.join("test-crate");
        assert!(crate_dir.join("Cargo.toml").exists());
        assert!(crate_dir.join("README.md").exists());
        assert!(crate_dir.join(".gitignore").exists());
        assert!(crate_dir.join("src/lib.rs").exists());
        assert!(crate_dir.join("src/bin/genshi.rs").exists());
        assert!(crate_dir.join("src/circuits/mod.rs").exists());
        assert!(crate_dir.join("src/circuits/add.rs").exists());

        // Verify content
        let cargo_toml = std::fs::read_to_string(crate_dir.join("Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("name = \"test-crate\""));
        assert!(cargo_toml.contains("shroud-network/genshi"));

        let bin_rs = std::fs::read_to_string(crate_dir.join("src/bin/genshi.rs")).unwrap();
        assert!(bin_rs.contains("use test_crate as _;"));

        let add_rs = std::fs::read_to_string(crate_dir.join("src/circuits/add.rs")).unwrap();
        assert!(add_rs.contains("impl Circuit for AddCircuit"));

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_cmd_new_refuses_existing_dir() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_exist_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let crate_dir = tmp.join("existing");
        std::fs::create_dir_all(&crate_dir).unwrap();

        let result = cmd_new("existing", Some(tmp.as_path()), "git");
        assert_eq!(result, ExitCode::FAILURE);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_cmd_new_invalid_name_fails() {
        let tmp = std::env::temp_dir();
        let result = cmd_new("3bad", Some(tmp.as_path()), "git");
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn test_cmd_new_invalid_source_fails() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_src_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let result = cmd_new("good-name", Some(tmp.as_path()), "invalid-source");
        assert_eq!(result, ExitCode::FAILURE);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_cmd_new_with_path_source() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_path_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let result = cmd_new("path-crate", Some(tmp.as_path()), "path:/my/local/genshi");
        assert_eq!(result, ExitCode::SUCCESS);

        let cargo_toml = std::fs::read_to_string(tmp.join("path-crate/Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("path = \"/my/local/genshi/crates/genshi-core\""));
        assert!(cargo_toml.contains("path = \"/my/local/genshi/crates/genshi-cli\""));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ================================================================
    // cmd_emit_poseidon2 / cmd_emit_libs on filesystem
    // ================================================================

    #[test]
    fn test_cmd_emit_poseidon2_writes_file() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_p2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        let result = cmd_emit_poseidon2(&tmp);
        assert_eq!(result, ExitCode::SUCCESS);
        assert!(tmp.join("Poseidon2.sol").exists());

        let sol = std::fs::read_to_string(tmp.join("Poseidon2.sol")).unwrap();
        assert!(sol.contains("library Poseidon2"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_cmd_emit_libs_writes_files() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_libs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        let result = cmd_emit_libs(&tmp);
        assert_eq!(result, ExitCode::SUCCESS);

        for name in genshi_evm::library_names() {
            assert!(
                tmp.join(format!("{name}.sol")).exists(),
                "Library {name}.sol should be emitted"
            );
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ================================================================
    // cmd_inspect
    // ================================================================

    #[test]
    fn test_cmd_inspect_unknown_kind() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_insp_{}", std::process::id()));
        std::fs::write(&tmp, b"some data").unwrap();

        let result = cmd_inspect("unknown", &tmp);
        assert_eq!(result, ExitCode::FAILURE);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_cmd_inspect_nonexistent_file() {
        let result = cmd_inspect("proof", Path::new("/nonexistent/file.bin"));
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn test_cmd_inspect_invalid_proof_bytes() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_bad_proof_{}", std::process::id()));
        std::fs::write(&tmp, b"not a proof").unwrap();

        let result = cmd_inspect("proof", &tmp);
        assert_eq!(result, ExitCode::FAILURE);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_cmd_inspect_invalid_vk_bytes() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_bad_vk_{}", std::process::id()));
        std::fs::write(&tmp, b"not a vk").unwrap();

        let result = cmd_inspect("vk", &tmp);
        assert_eq!(result, ExitCode::FAILURE);

        let _ = std::fs::remove_file(&tmp);
    }

    // ================================================================
    // cmd_srs_new roundtrip
    // ================================================================

    #[test]
    fn test_cmd_srs_new_writes_loadable_srs() {
        let tmp = std::env::temp_dir().join(format!("genshi_test_srs_{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let result = cmd_srs_new(64, &tmp);
        assert_eq!(result, ExitCode::SUCCESS);
        assert!(tmp.exists());

        // Load it back
        let bytes = std::fs::read(&tmp).unwrap();
        let srs = SRS::load_from_bytes(&bytes);
        assert_eq!(srs.max_degree(), 64);

        let _ = std::fs::remove_file(&tmp);
    }

    // ================================================================
    // cmd_verify with bad files
    // ================================================================

    #[test]
    fn test_cmd_verify_nonexistent_proof() {
        let result = cmd_verify(
            Path::new("/nonexistent/proof.bin"),
            Path::new("/nonexistent/vk.bin"),
            Path::new("/nonexistent/pi.bin"),
            Path::new("/nonexistent/srs.bin"),
        );
        assert_eq!(result, ExitCode::FAILURE);
    }
}
