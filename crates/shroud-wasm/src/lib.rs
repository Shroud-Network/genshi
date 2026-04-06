//! Browser WASM SDK for shroud-honk.
//!
//! This crate is the SINGLE WASM entry point shared across both EVM and Solana.
//! The proving side is 100% shared — same proof bytes, same WASM module.
//! Only the on-chain verifier contracts differ (Solidity vs Rust BPF).
//!
//! # Exports
//!
//! - `prove_transfer(witness_json, srs_bytes) -> proof_bytes`
//! - `prove_withdraw(witness_json, srs_bytes) -> proof_bytes`
//! - `compute_commitment(note_json) -> commitment_bytes`
//! - `derive_nullifier(np, secret, leaf_index) -> nullifier_bytes`
//!
//! # SRS Strategy
//!
//! The SRS is passed in as raw bytes from JavaScript. The JS wrapper
//! handles fetching from CDN and IndexedDB caching. This keeps the
//! WASM module pure (no async I/O).

// Re-export wasm-bindgen on WASM targets
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use shroud_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use shroud_core::circuits::transfer::TransferCircuit;
use shroud_core::circuits::withdraw::WithdrawCircuit;
use shroud_core::proving::prover;
use shroud_core::proving::serialization::{proof_to_bytes, public_inputs_to_bytes_le};
use shroud_core::proving::srs::SRS;
use shroud_core::witness::{TransferWitnessJson, WithdrawWitnessJson, NoteJson};

/// Result type wrapping proof bytes + public input bytes.
#[derive(serde::Serialize)]
pub struct ProofResult {
    /// Canonical proof bytes (uncompressed encoding).
    pub proof: Vec<u8>,
    /// Public input values as LE bytes (32 bytes each).
    pub public_inputs: Vec<u8>,
}

/// Generate a transfer proof from a JSON witness and SRS bytes.
///
/// # Arguments
/// * `witness_json` - JSON string matching `TransferWitnessJson` schema
/// * `srs_bytes` - Serialized SRS from `SRS::save_to_bytes()`
///
/// # Returns
/// JSON string containing `{ "proof": [bytes], "public_inputs": [bytes] }`
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn prove_transfer(witness_json: &str, srs_bytes: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();

    let witness: TransferWitnessJson = serde_json::from_str(witness_json)
        .map_err(|e| format!("Failed to parse witness: {e}"))?;

    let input_note = witness.input_note.to_note()
        .map_err(|e| format!("Invalid input note: {e:?}"))?;
    let merkle_path = witness.merkle_path.to_path()
        .map_err(|e| format!("Invalid merkle path: {e:?}"))?;
    let output_note_1 = witness.output_note_1.to_note()
        .map_err(|e| format!("Invalid output note 1: {e:?}"))?;
    let output_note_2 = witness.output_note_2.to_note()
        .map_err(|e| format!("Invalid output note 2: {e:?}"))?;

    let circuit = TransferCircuit {
        input_note,
        merkle_path,
        output_note_1,
        output_note_2,
    };

    let srs = SRS::load_from_bytes(srs_bytes);
    let mut builder = UltraCircuitBuilder::new();
    let public_inputs = circuit.build(&mut builder);

    let (proof, _) = prover::prove(&builder, &srs);
    let proof_bytes = proof_to_bytes(&proof);
    let pi_bytes = public_inputs_to_bytes_le(&public_inputs.to_vec());

    // Return proof + PI concatenated: [4-byte proof_len LE] [proof] [pi]
    let mut result = Vec::with_capacity(4 + proof_bytes.len() + pi_bytes.len());
    result.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&proof_bytes);
    result.extend_from_slice(&pi_bytes);

    Ok(result)
}

/// Generate a withdraw proof from a JSON witness and SRS bytes.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn prove_withdraw(witness_json: &str, srs_bytes: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();

    let witness: WithdrawWitnessJson = serde_json::from_str(witness_json)
        .map_err(|e| format!("Failed to parse witness: {e}"))?;

    let input_note = witness.input_note.to_note()
        .map_err(|e| format!("Invalid input note: {e:?}"))?;
    let merkle_path = witness.merkle_path.to_path()
        .map_err(|e| format!("Invalid merkle path: {e:?}"))?;

    let recipient_bytes = hex_decode(&witness.recipient);
    let recipient = Fr::from_le_bytes_mod_order(&recipient_bytes);

    let circuit = WithdrawCircuit {
        input_note,
        merkle_path,
        recipient,
    };

    let srs = SRS::load_from_bytes(srs_bytes);
    let mut builder = UltraCircuitBuilder::new();
    let public_inputs = circuit.build(&mut builder);

    let (proof, _) = prover::prove(&builder, &srs);
    let proof_bytes = proof_to_bytes(&proof);
    let pi_bytes = public_inputs_to_bytes_le(&public_inputs.to_vec());

    let mut result = Vec::with_capacity(4 + proof_bytes.len() + pi_bytes.len());
    result.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&proof_bytes);
    result.extend_from_slice(&pi_bytes);

    Ok(result)
}

/// Compute a note commitment from JSON note data.
///
/// Returns 32 bytes (BN254 Fr, LE encoding).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn compute_commitment(note_json: &str) -> Result<Vec<u8>, String> {
    let note_j: NoteJson = serde_json::from_str(note_json)
        .map_err(|e| format!("Failed to parse note: {e}"))?;
    let note = note_j.to_note()
        .map_err(|e| format!("Invalid note: {e:?}"))?;

    let commitment = note.commitment();
    let mut bytes = Vec::new();
    commitment.serialize_compressed(&mut bytes)
        .map_err(|e| format!("Serialization failed: {e}"))?;

    Ok(bytes)
}

/// Derive a nullifier from note secrets.
///
/// Returns 32 bytes (BN254 Fr, LE encoding).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn derive_nullifier(np_hex: &str, secret_hex: &str, leaf_index: u64) -> Result<Vec<u8>, String> {
    let np_bytes = hex_decode(np_hex);
    let secret_bytes = hex_decode(secret_hex);

    let np = ark_bn254::Fq::from_le_bytes_mod_order(&np_bytes);
    let secret = ark_bn254::Fq::from_le_bytes_mod_order(&secret_bytes);

    let np_fr = shroud_core::note::grumpkin_scalar_to_fr(np);
    let secret_fr = shroud_core::note::grumpkin_scalar_to_fr(secret);
    let leaf_fr = Fr::from(leaf_index);

    let nullifier = shroud_core::crypto::poseidon2::poseidon2_hash_3(np_fr, secret_fr, leaf_fr);
    let mut bytes = Vec::new();
    nullifier.serialize_compressed(&mut bytes)
        .map_err(|e| format!("Serialization failed: {e}"))?;

    Ok(bytes)
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        if i + 2 <= s.len() {
            let byte = u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0);
            bytes.push(byte);
        }
    }
    bytes
}

// ============================================================================
// Tests (native only, WASM tests use wasm-pack test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::note::Note;
    use shroud_core::crypto::pedersen;
    use shroud_core::circuits::gadgets::merkle::{MERKLE_DEPTH, generate_merkle_path};
    use shroud_core::witness::{NoteJson, MerklePathJson};

    fn make_test_transfer_json() -> (String, SRS) {
        let g = pedersen::generator_g();
        let note = Note::new(100, ark_bn254::Fq::from(42u64), ark_bn254::Fq::from(1u64),
            ark_bn254::Fq::from(2u64), g, 0);
        let out1 = Note::new(60, ark_bn254::Fq::from(43u64), ark_bn254::Fq::from(3u64),
            ark_bn254::Fq::from(4u64), g, 0);
        let out2 = Note::new(40, ark_bn254::Fq::from(44u64), ark_bn254::Fq::from(5u64),
            ark_bn254::Fq::from(6u64), g, 0);

        let commitment = note.commitment();
        let mut leaves = vec![Fr::from(0u64); 1024];
        leaves[0] = commitment;
        let path = generate_merkle_path(&leaves, 0, MERKLE_DEPTH);

        let witness = TransferWitnessJson {
            input_note: NoteJson::from_note(&note),
            merkle_path: MerklePathJson::from_path(&path),
            output_note_1: NoteJson::from_note(&out1),
            output_note_2: NoteJson::from_note(&out2),
        };

        let json = serde_json::to_string(&witness).unwrap();
        let srs = SRS::insecure_for_testing(65536);
        (json, srs)
    }

    #[test]
    fn test_compute_commitment_matches_native() {
        let g = pedersen::generator_g();
        let note = Note::new(100, ark_bn254::Fq::from(42u64), ark_bn254::Fq::from(1u64),
            ark_bn254::Fq::from(2u64), g, 7);

        let native_commitment = note.commitment();
        let mut expected_bytes = Vec::new();
        native_commitment.serialize_compressed(&mut expected_bytes).unwrap();

        let note_json = NoteJson::from_note(&note);
        let json_str = serde_json::to_string(&note_json).unwrap();
        let result = compute_commitment(&json_str).unwrap();

        assert_eq!(result, expected_bytes, "WASM commitment must match native");
    }

    #[test]
    fn test_derive_nullifier_matches_native() {
        let g = pedersen::generator_g();
        let note = Note::new(100, ark_bn254::Fq::from(42u64), ark_bn254::Fq::from(1u64),
            ark_bn254::Fq::from(2u64), g, 7);

        let native_nullifier = note.nullifier();
        let mut expected_bytes = Vec::new();
        native_nullifier.serialize_compressed(&mut expected_bytes).unwrap();

        let np_hex = format!("0x{}", ark_ff_hex(&ark_bn254::Fq::from(2u64)));
        let secret_hex = format!("0x{}", ark_ff_hex(&ark_bn254::Fq::from(1u64)));
        let result = derive_nullifier(&np_hex, &secret_hex, 7).unwrap();

        assert_eq!(result, expected_bytes, "WASM nullifier must match native");
    }

    fn ark_ff_hex(val: &ark_bn254::Fq) -> String {
        use ark_ff::BigInteger;
        let bytes = val.into_bigint().to_bytes_le();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_prove_transfer_produces_valid_proof() {
        let (json, srs) = make_test_transfer_json();
        let srs_bytes = srs.save_to_bytes();

        let result = prove_transfer(&json, &srs_bytes).unwrap();

        // Extract proof length and proof bytes
        let proof_len = u32::from_le_bytes(result[0..4].try_into().unwrap()) as usize;
        assert!(proof_len > 0, "Proof should not be empty");
        assert!(result.len() > 4 + proof_len, "Should have PI bytes after proof");

        // Verify the proof with the native verifier
        let proof_bytes = &result[4..4 + proof_len];
        let pi_bytes = &result[4 + proof_len..];

        let proof = shroud_core::proving::serialization::proof_from_bytes(proof_bytes)
            .expect("Proof deserialization should succeed");

        // Decode public inputs
        let num_pi = pi_bytes.len() / 32;
        assert_eq!(num_pi, 4, "Transfer has 4 public inputs");

        let mut public_inputs = Vec::new();
        for i in 0..num_pi {
            let chunk = &pi_bytes[i * 32..(i + 1) * 32];
            public_inputs.push(Fr::from_le_bytes_mod_order(chunk));
        }

        // Need VK — rebuild the circuit and extract VK
        let g = pedersen::generator_g();
        let note = Note::new(100, ark_bn254::Fq::from(42u64), ark_bn254::Fq::from(1u64),
            ark_bn254::Fq::from(2u64), g, 0);
        let out1 = Note::new(60, ark_bn254::Fq::from(43u64), ark_bn254::Fq::from(3u64),
            ark_bn254::Fq::from(4u64), g, 0);
        let out2 = Note::new(40, ark_bn254::Fq::from(44u64), ark_bn254::Fq::from(5u64),
            ark_bn254::Fq::from(6u64), g, 0);
        let commitment = note.commitment();
        let mut leaves = vec![Fr::from(0u64); 1024];
        leaves[0] = commitment;
        let path = generate_merkle_path(&leaves, 0, MERKLE_DEPTH);
        let circuit = TransferCircuit {
            input_note: note, merkle_path: path, output_note_1: out1, output_note_2: out2,
        };
        let mut builder = UltraCircuitBuilder::new();
        circuit.build(&mut builder);
        let (_, vk) = prover::prove(&builder, &srs);

        assert!(
            shroud_core::proving::verifier::verify(&proof, &vk, &public_inputs, &srs),
            "WASM-generated proof must verify natively"
        );
    }
}
