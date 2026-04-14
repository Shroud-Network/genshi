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
    pub use genshi_core::proving::serialization::vk_to_bytes;
    pub use genshi_core::proving::srs::SRS;
    pub use genshi_evm::solidity_emitter::{EmitterOptions, generate_verifier_sol_with};
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
///
/// pub struct MyCircuit;
/// pub struct MyWitness { pub x: Fr }
///
/// impl Circuit for MyCircuit {
///     type Witness = MyWitness;
///     type PublicInputs = [Fr; 1];
///     const ID: &'static str = "example.my-circuit";
///     fn num_public_inputs() -> usize { 1 }
///     fn synthesize(builder: &mut UltraCircuitBuilder, w: &Self::Witness) -> Self::PublicInputs {
///         let v = builder.add_variable(w.x);
///         builder.set_public(v);
///         [w.x]
///     }
///     fn dummy_witness() -> Self::Witness {
///         MyWitness { x: Fr::from(0u64) }
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

    // Layout: <target>/Cargo.toml
    //         <target>/README.md
    //         <target>/.gitignore
    //         <target>/src/lib.rs
    //         <target>/src/bin/genshi.rs
    let src_dir = target.join("src");
    let bin_dir = src_dir.join("bin");
    if let Err(e) = fs::create_dir_all(&bin_dir) {
        eprintln!("failed to create {}: {e}", bin_dir.display());
        return ExitCode::FAILURE;
    }

    let files: [(PathBuf, String); 5] = [
        (target.join("Cargo.toml"), cargo_toml),
        (target.join("README.md"), readme),
        (target.join(".gitignore"), gitignore),
        (src_dir.join("lib.rs"), lib_rs),
        (bin_dir.join("genshi.rs"), bin_rs),
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
    println!("  cargo run --bin genshi -- circuits list");
    println!("  cargo run --bin genshi -- srs new --max-degree 1024 --output srs.bin");
    println!(
        "  cargo run --bin genshi -- emit-verifier --circuit add --srs srs.bin --output out/"
    );
    println!();
    println!(
        "Edit src/lib.rs to replace `AddCircuit` with your own circuit. Keep the"
    );
    println!(
        "`genshi_cli::register!(YourCircuit, \"your-name\")` line next to the impl."
    );

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
"#;

const SCAFFOLD_LIB_RS: &str = r#"//! A sample genshi application scaffolded by `genshi new`.
//!
//! The one thing to keep in mind: every `Circuit` impl you add here should
//! be paired with a `genshi_cli::register!(MyCircuit, "my-name")` line so
//! the CLI can dispatch `--circuit my-name` to it. Nothing else in this
//! crate needs to change — `src/bin/genshi.rs` is a one-line shim you do
//! not edit.

use ark_bn254::Fr;
use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use genshi_core::circuit::Circuit;

/// Stub "a + b = c" circuit. Delete me and write your own.
pub struct AddCircuit;

/// Native witness for [`AddCircuit`].
pub struct AddWitness {
    pub a: Fr,
    pub b: Fr,
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
        let a = builder.add_variable(w.a);
        let b = builder.add_variable(w.b);
        let c = builder.add(a, b);
        builder.set_public(c);
        [w.a + w.b]
    }

    fn dummy_witness() -> Self::Witness {
        AddWitness {
            a: Fr::from(0u64),
            b: Fr::from(0u64),
        }
    }
}

// Register this circuit with the genshi-cli registry. The CLI will expose
// `--circuit add` on all circuit-aware subcommands (`extract-vk`,
// `emit-verifier`, `circuits list`).
genshi_cli::register!(AddCircuit, "add");
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

```
cargo run --bin genshi -- circuits list
cargo run --bin genshi -- srs new --max-degree 1024 --output srs.bin
cargo run --bin genshi -- emit-verifier --circuit add --srs srs.bin --output out/
```

## Adding a circuit

1. Define your circuit type and `impl genshi_core::Circuit for MyCircuit` in
   `src/lib.rs` (or any module reachable from it).
2. Drop a `genshi_cli::register!(MyCircuit, "my-circuit");` line next to the
   impl so the CLI can dispatch `--circuit my-circuit`.
3. Rebuild — the new circuit shows up in `genshi circuits list`.

You do not edit `src/bin/genshi.rs` — it is a one-line shim that calls
`genshi_cli::run()`.
"#;

const SCAFFOLD_GITIGNORE: &str = "target/\n*.bin\n*.vk\n";

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
    fn test_scaffold_lib_rs_has_circuit_impl() {
        assert!(SCAFFOLD_LIB_RS.contains("impl Circuit for AddCircuit"));
        assert!(SCAFFOLD_LIB_RS.contains("genshi_cli::register!(AddCircuit, \"add\")"));
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

        // Verify content
        let cargo_toml = std::fs::read_to_string(crate_dir.join("Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("name = \"test-crate\""));
        assert!(cargo_toml.contains("shroud-network/genshi"));

        let bin_rs = std::fs::read_to_string(crate_dir.join("src/bin/genshi.rs")).unwrap();
        assert!(bin_rs.contains("use test_crate as _;"));

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
