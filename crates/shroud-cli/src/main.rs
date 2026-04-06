//! shroud-cli: Development tooling for shroud-honk proving scheme.
//!
//! This binary is for development and testing only — never deployed.
//! Used for: proof generation, verification, VK extraction, and
//! Solidity verifier generation.

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use shroud_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use shroud_core::circuits::transfer::TransferCircuit;
use shroud_core::circuits::withdraw::WithdrawCircuit;
use shroud_core::proving::prover;
use shroud_core::proving::verifier;
use shroud_core::proving::srs::SRS;
use shroud_core::proving::serialization::{
    proof_to_bytes, proof_from_bytes, vk_to_bytes, vk_from_bytes,
    public_inputs_to_bytes_le,
};
use shroud_core::witness::{
    TransferWitnessJson, WithdrawWitnessJson,
};

#[derive(Parser)]
#[command(name = "shroud-cli", version, about = "Development tooling for shroud-honk proving scheme")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a verification key for a circuit type
    GenVk {
        /// Circuit type: "transfer" or "withdraw"
        #[arg(long)]
        circuit: String,
        /// Output file for the serialized VK
        #[arg(long)]
        output: PathBuf,
        /// SRS size (default: 65536 for testing)
        #[arg(long, default_value = "65536")]
        srs_size: usize,
    },

    /// Generate a transfer proof from a JSON witness
    ProveTransfer {
        /// Path to JSON witness file
        #[arg(long)]
        witness: PathBuf,
        /// Output file for the proof bytes
        #[arg(long)]
        output: PathBuf,
        /// Output file for public inputs (LE bytes)
        #[arg(long)]
        public_inputs: Option<PathBuf>,
        /// SRS size (default: 65536)
        #[arg(long, default_value = "65536")]
        srs_size: usize,
    },

    /// Generate a withdraw proof from a JSON witness
    ProveWithdraw {
        /// Path to JSON witness file
        #[arg(long)]
        witness: PathBuf,
        /// Output file for the proof bytes
        #[arg(long)]
        output: PathBuf,
        /// Output file for public inputs (LE bytes)
        #[arg(long)]
        public_inputs: Option<PathBuf>,
        /// SRS size (default: 65536)
        #[arg(long, default_value = "65536")]
        srs_size: usize,
    },

    /// Verify a proof against a verification key
    Verify {
        /// Path to proof bytes file
        #[arg(long)]
        proof: PathBuf,
        /// Path to VK bytes file
        #[arg(long)]
        vk: PathBuf,
        /// Path to public inputs bytes file (LE)
        #[arg(long)]
        public_inputs: PathBuf,
        /// SRS size (default: 65536)
        #[arg(long, default_value = "65536")]
        srs_size: usize,
    },

    /// Generate an insecure testing SRS and save to file
    GenSrs {
        /// Maximum polynomial degree
        #[arg(long)]
        max_degree: usize,
        /// Output file
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenVk { circuit, output, srs_size } => {
            cmd_gen_vk(&circuit, &output, srs_size);
        }
        Commands::ProveTransfer { witness, output, public_inputs, srs_size } => {
            cmd_prove_transfer(&witness, &output, public_inputs.as_deref(), srs_size);
        }
        Commands::ProveWithdraw { witness, output, public_inputs, srs_size } => {
            cmd_prove_withdraw(&witness, &output, public_inputs.as_deref(), srs_size);
        }
        Commands::Verify { proof, vk, public_inputs, srs_size } => {
            cmd_verify(&proof, &vk, &public_inputs, srs_size);
        }
        Commands::GenSrs { max_degree, output } => {
            cmd_gen_srs(max_degree, &output);
        }
    }
}

fn load_srs(size: usize) -> SRS {
    eprintln!("Generating insecure test SRS (degree {})...", size);
    SRS::insecure_for_testing(size)
}

fn cmd_gen_vk(circuit: &str, output: &PathBuf, srs_size: usize) {
    let srs = load_srs(srs_size);

    let mut builder = UltraCircuitBuilder::new();

    match circuit {
        "transfer" => {
            // Build circuit with dummy witness to extract VK structure
            let dummy = make_dummy_transfer();
            dummy.build(&mut builder);
        }
        "withdraw" => {
            let dummy = make_dummy_withdraw();
            dummy.build(&mut builder);
        }
        _ => {
            eprintln!("Unknown circuit type: '{}'. Use 'transfer' or 'withdraw'.", circuit);
            std::process::exit(1);
        }
    }

    let (_, vk) = prover::prove(&builder, &srs);
    let bytes = vk_to_bytes(&vk);
    fs::write(output, &bytes).expect("Failed to write VK file");
    eprintln!("VK written to {} ({} bytes)", output.display(), bytes.len());
}

fn cmd_prove_transfer(witness_path: &PathBuf, output: &PathBuf, pi_output: Option<&std::path::Path>, srs_size: usize) {
    let json_str = fs::read_to_string(witness_path).expect("Failed to read witness file");
    let witness: TransferWitnessJson = serde_json::from_str(&json_str).expect("Failed to parse witness JSON");

    let input_note = witness.input_note.to_note().expect("Invalid input note");
    let merkle_path = witness.merkle_path.to_path().expect("Invalid merkle path");
    let output_note_1 = witness.output_note_1.to_note().expect("Invalid output note 1");
    let output_note_2 = witness.output_note_2.to_note().expect("Invalid output note 2");

    let circuit = TransferCircuit {
        input_note,
        merkle_path,
        output_note_1,
        output_note_2,
    };

    let mut builder = UltraCircuitBuilder::new();
    let public_inputs = circuit.build(&mut builder);

    let srs = load_srs(srs_size);
    let (proof, _) = prover::prove(&builder, &srs);

    let proof_bytes = proof_to_bytes(&proof);
    fs::write(output, &proof_bytes).expect("Failed to write proof file");
    eprintln!("Proof written to {} ({} bytes)", output.display(), proof_bytes.len());

    if let Some(pi_path) = pi_output {
        let pi_bytes = public_inputs_to_bytes_le(&public_inputs.to_vec());
        fs::write(pi_path, &pi_bytes).expect("Failed to write public inputs file");
        eprintln!("Public inputs written to {} ({} bytes)", pi_path.display(), pi_bytes.len());
    }
}

fn cmd_prove_withdraw(witness_path: &PathBuf, output: &PathBuf, pi_output: Option<&std::path::Path>, srs_size: usize) {
    let json_str = fs::read_to_string(witness_path).expect("Failed to read witness file");
    let witness: WithdrawWitnessJson = serde_json::from_str(&json_str).expect("Failed to parse witness JSON");

    let input_note = witness.input_note.to_note().expect("Invalid input note");
    let merkle_path = witness.merkle_path.to_path().expect("Invalid merkle path");
    let recipient = {
        use ark_bn254::Fr;
        use ark_ff::PrimeField;
        let bytes = hex_decode(&witness.recipient);
        Fr::from_le_bytes_mod_order(&bytes)
    };

    let circuit = WithdrawCircuit {
        input_note,
        merkle_path,
        recipient,
    };

    let mut builder = UltraCircuitBuilder::new();
    let public_inputs = circuit.build(&mut builder);

    let srs = load_srs(srs_size);
    let (proof, _) = prover::prove(&builder, &srs);

    let proof_bytes = proof_to_bytes(&proof);
    fs::write(output, &proof_bytes).expect("Failed to write proof file");
    eprintln!("Proof written to {} ({} bytes)", output.display(), proof_bytes.len());

    if let Some(pi_path) = pi_output {
        let pi_bytes = public_inputs_to_bytes_le(&public_inputs.to_vec());
        fs::write(pi_path, &pi_bytes).expect("Failed to write public inputs file");
        eprintln!("Public inputs written to {} ({} bytes)", pi_path.display(), pi_bytes.len());
    }
}

fn cmd_verify(proof_path: &PathBuf, vk_path: &PathBuf, pi_path: &PathBuf, srs_size: usize) {
    let proof_bytes = fs::read(proof_path).expect("Failed to read proof file");
    let vk_bytes = fs::read(vk_path).expect("Failed to read VK file");
    let pi_bytes = fs::read(pi_path).expect("Failed to read public inputs file");

    let proof = proof_from_bytes(&proof_bytes).expect("Failed to deserialize proof");
    let vk = vk_from_bytes(&vk_bytes).expect("Failed to deserialize VK");

    // Decode public inputs from LE bytes (32 bytes each)
    let num_pi = pi_bytes.len() / 32;
    let mut public_inputs = Vec::with_capacity(num_pi);
    for i in 0..num_pi {
        use ark_bn254::Fr;
        use ark_ff::PrimeField;
        let chunk = &pi_bytes[i * 32..(i + 1) * 32];
        public_inputs.push(Fr::from_le_bytes_mod_order(chunk));
    }

    let srs = load_srs(srs_size);
    let valid = verifier::verify(&proof, &vk, &public_inputs, &srs);

    if valid {
        println!("VALID");
    } else {
        println!("INVALID");
        std::process::exit(1);
    }
}

fn cmd_gen_srs(max_degree: usize, output: &PathBuf) {
    let srs = SRS::insecure_for_testing(max_degree);
    let bytes = srs.save_to_bytes();
    fs::write(output, &bytes).expect("Failed to write SRS file");
    eprintln!("SRS written to {} ({} bytes, {} G1 points)", output.display(), bytes.len(), srs.size());
}

// ============================================================================
// Dummy witness constructors (for gen-vk — needs valid circuit structure)
// ============================================================================

fn make_dummy_transfer() -> TransferCircuit {
    use ark_bn254::Fr;
    use shroud_core::note::Note;
    use shroud_core::circuits::gadgets::merkle::MERKLE_DEPTH;
    use shroud_core::crypto::pedersen;

    let g = pedersen::generator_g();
    let note = Note::new(100, ark_bn254::Fq::from(42u64), ark_bn254::Fq::from(1u64),
        ark_bn254::Fq::from(2u64), g, 0);
    let out1 = Note::new(60, ark_bn254::Fq::from(43u64), ark_bn254::Fq::from(3u64),
        ark_bn254::Fq::from(4u64), g, 0);
    let out2 = Note::new(40, ark_bn254::Fq::from(44u64), ark_bn254::Fq::from(5u64),
        ark_bn254::Fq::from(6u64), g, 0);

    // Generate a valid Merkle path
    let commitment = note.commitment();
    let mut leaves = vec![Fr::from(0u64); 4usize.pow(MERKLE_DEPTH as u32).min(1024)];
    leaves[0] = commitment;
    let path = shroud_core::circuits::gadgets::merkle::generate_merkle_path(&leaves, 0, MERKLE_DEPTH);

    TransferCircuit {
        input_note: note,
        merkle_path: path,
        output_note_1: out1,
        output_note_2: out2,
    }
}

fn make_dummy_withdraw() -> WithdrawCircuit {
    use ark_bn254::Fr;
    use shroud_core::note::Note;
    use shroud_core::circuits::gadgets::merkle::MERKLE_DEPTH;
    use shroud_core::crypto::pedersen;

    let g = pedersen::generator_g();
    let note = Note::new(100, ark_bn254::Fq::from(42u64), ark_bn254::Fq::from(1u64),
        ark_bn254::Fq::from(2u64), g, 0);

    let commitment = note.commitment();
    let mut leaves = vec![Fr::from(0u64); 4usize.pow(MERKLE_DEPTH as u32).min(1024)];
    leaves[0] = commitment;
    let path = shroud_core::circuits::gadgets::merkle::generate_merkle_path(&leaves, 0, MERKLE_DEPTH);

    WithdrawCircuit {
        input_note: note,
        merkle_path: path,
        recipient: Fr::from(0xDEADBEEFu64),
    }
}

/// Hex decode helper.
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .expect("Invalid hex");
        bytes.push(byte);
    }
    bytes
}
