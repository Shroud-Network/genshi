//! Solana-specific proof verification using `verify_prepare()` + pairing syscalls.
//!
//! This module combines:
//! 1. `genshi_core::proving::verifier::verify_prepare()` — transcript + constraint check
//! 2. `crypto::pairing_check_2()` — BN254 pairing via `sol_alt_bn128_pairing` on Solana
//!
//! On native: uses arkworks pairing (tests, CLI, host-side verification).
//! On Solana BPF (`target_os = "solana"`): routes through the
//! `sol_alt_bn128_pairing` syscall via the `solana-program` crate.

use genshi_math::Fr;

use genshi_core::proving::types::{Proof, VerificationKey};
use genshi_core::proving::srs::SRS;
use genshi_core::proving::verifier::verify_prepare;
use genshi_core::proving::serialization::{proof_from_bytes, vk_from_bytes};

use crate::crypto::pairing_check_2;

/// Verify a proof using the prepare + pairing strategy.
///
/// This is the entry point for Solana on-chain verification.
/// On BPF, the pairing checks use `sol_alt_bn128_pairing` syscalls.
pub fn verify_with_syscalls(
    proof: &Proof,
    vk: &VerificationKey,
    public_inputs: &[Fr],
    srs: &SRS,
) -> bool {
    // Step 1-2: Transcript + constraint equation (pure field arithmetic)
    let intermediates = match verify_prepare(proof, vk, public_inputs) {
        Some(i) => i,
        None => return false, // Constraint equation failed
    };

    // `verify_prepare` performs the G₂-side simplification on both openings —
    // the ζ / ζ·ω scalars are folded into the G₁ LHS, so the pairing right-hand
    // side is the constant `τ·G₂` for both checks. See verifier.rs:706-715.
    let batch_ok = pairing_check_2(
        &intermediates.batch_lhs, &srs.g2,
        &intermediates.batch_neg_w, &srs.g2_tau,
    );
    if !batch_ok {
        return false;
    }

    pairing_check_2(
        &intermediates.z_lhs, &srs.g2,
        &intermediates.z_neg_w, &srs.g2_tau,
    )
}

/// Verify a proof from raw bytes (deserialization + verification).
///
/// This is the function that a Solana instruction handler would call.
pub fn verify_from_bytes(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    public_input_bytes: &[u8],
    srs: &SRS,
) -> Result<bool, &'static str> {
    let proof = proof_from_bytes(proof_bytes)
        .map_err(|_| "Failed to deserialize proof")?;
    let vk = vk_from_bytes(vk_bytes)
        .map_err(|_| "Failed to deserialize VK")?;

    let num_pi = public_input_bytes.len() / 32;
    let mut public_inputs = Vec::with_capacity(num_pi);
    for i in 0..num_pi {
        let chunk = &public_input_bytes[i * 32..(i + 1) * 32];
        public_inputs.push(Fr::from_le_bytes_mod_order(chunk));
    }

    Ok(verify_with_syscalls(&proof, &vk, &public_inputs, srs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as ArkFr;
    use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
    use genshi_core::proving::prover;
    use genshi_core::proving::srs::SRS;
    use genshi_core::proving::serialization::{proof_to_bytes, vk_to_bytes, public_inputs_to_bytes_le};

    fn gf(v: u64) -> Fr { Fr::from(v) }

    #[test]
    fn test_verify_with_syscalls_simple() {
        let srs = SRS::insecure_for_testing(128);
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(5u64));
        let c = builder.add(a, b);
        builder.set_public(c);

        let (proof, vk) = prover::prove(&builder, &srs);
        let pi = vec![gf(8)];

        assert!(verify_with_syscalls(&proof, &vk, &pi, &srs),
            "Syscall-based verification should pass");
    }

    #[test]
    fn test_verify_with_syscalls_wrong_pi() {
        let srs = SRS::insecure_for_testing(128);
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(3u64));
        let b = builder.add_variable(ArkFr::from(5u64));
        let c = builder.add(a, b);
        builder.set_public(c);

        let (proof, vk) = prover::prove(&builder, &srs);
        let wrong_pi = vec![gf(9)];

        assert!(!verify_with_syscalls(&proof, &vk, &wrong_pi, &srs),
            "Wrong PI should fail");
    }

    #[test]
    fn test_verify_from_bytes_roundtrip() {
        let srs = SRS::insecure_for_testing(128);
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(10u64));
        let b = builder.add_variable(ArkFr::from(20u64));
        let c = builder.add(a, b);
        builder.set_public(c);

        let (proof, vk) = prover::prove(&builder, &srs);
        let pi = vec![gf(30)];

        let proof_bytes = proof_to_bytes(&proof);
        let vk_bytes = vk_to_bytes(&vk);
        let pi_bytes = public_inputs_to_bytes_le(&pi);

        let result = verify_from_bytes(&proof_bytes, &vk_bytes, &pi_bytes, &srs);
        assert!(result.unwrap(), "Byte-level roundtrip verification should pass");
    }

    #[test]
    fn test_verify_circuit_trait_proof() {
        // End-to-end: produce a proof via genshi_core::api::prove::<C>(),
        // round-trip through bytes, and verify with the Solana-side helper.
        use genshi_core::circuit::{Circuit, ProvableCircuit};
        use genshi_core::proving::api;

        struct AddCircuit;
        struct AddWitness { a: ArkFr, b: ArkFr }

        impl Circuit for AddCircuit {
            type PublicInputs = [ArkFr; 1];
            const ID: &'static str = "genshi-solana.test.add";

            fn num_public_inputs() -> usize { 1 }
        }

        impl ProvableCircuit for AddCircuit {
            type Witness = AddWitness;

            fn synthesize(
                builder: &mut genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder,
                w: &Self::Witness,
            ) -> Self::PublicInputs {
                let a = builder.add_variable(w.a);
                let b = builder.add_variable(w.b);
                let c = builder.add(a, b);
                builder.set_public(c);
                [w.a + w.b]
            }

            fn dummy_witness() -> Self::Witness {
                AddWitness { a: ArkFr::from(0u64), b: ArkFr::from(0u64) }
            }
        }

        let srs = SRS::insecure_for_testing(128);
        let witness = AddWitness { a: ArkFr::from(11u64), b: ArkFr::from(22u64) };
        let (proof, vk, pi) = api::prove::<AddCircuit>(&witness, &srs);

        let proof_bytes = proof_to_bytes(&proof);
        let vk_bytes = vk_to_bytes(&vk);
        let pi_g: Vec<Fr> = pi.iter().copied().map(Fr::from_ark).collect();
        let pi_bytes = public_inputs_to_bytes_le(&pi_g);

        let result = verify_from_bytes(&proof_bytes, &vk_bytes, &pi_bytes, &srs);
        assert!(result.unwrap(), "Circuit-trait proof must verify on Solana entry point");
    }

    #[test]
    fn test_verify_matches_native() {
        let srs = SRS::insecure_for_testing(128);
        let mut builder = UltraCircuitBuilder::new();
        let a = builder.add_variable(ArkFr::from(7u64));
        let b = builder.add_variable(ArkFr::from(3u64));
        let c = builder.mul(a, b);
        builder.set_public(c);

        let (proof, vk) = prover::prove(&builder, &srs);
        let pi = vec![gf(21)];

        // Both verification paths should agree
        let native = genshi_core::proving::verifier::verify(&proof, &vk, &pi, &srs);
        let syscall = verify_with_syscalls(&proof, &vk, &pi, &srs);

        assert_eq!(native, syscall, "Syscall and native verification must agree");
    }
}
