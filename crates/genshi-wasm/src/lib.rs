//! Browser WASM helpers for the genshi framework.
//!
//! # What this crate ships
//!
//! **Generic Rust helpers** (for applications that wrap their own circuits
//! in a cdylib):
//!
//! - [`prove_circuit`] — build a circuit from any `genshi_core::Circuit`
//!   impl, run the prover, return canonical proof bytes + VK bytes.
//! - [`extract_vk_bytes`] — derive the VK for a circuit without proving.
//! - [`verify_proof_bytes`] — run the native verifier against canonical bytes.
//! - [`compose_proof_blob`] / [`split_proof_blob`] — canonical `(proof, PI)`
//!   envelope used over the JS ↔ WASM boundary.
//! - [`install_panic_hook`] — install `console_error_panic_hook` on wasm32.
//!
//! **Direct `#[wasm_bindgen]` exports** (available to JavaScript without
//! shipping an application-specific cdylib; see the [`wasm`] module):
//!
//! - `init()` — install the panic hook.
//! - `verifyProof(proof, vk, pi, srs)` — verify any genshi proof given its
//!   canonical byte encoding, without knowing the circuit type.
//! - `composeProofBlob(proof, pi)` / `proofFromBlob(blob)` /
//!   `piFromBlob(blob)` — envelope helpers, useful when a JS wrapper needs
//!   to ferry proof bundles between prover and verifier sides.
//!
//! Proving itself is inherently circuit-specific, so applications that
//! want a `prove_my_circuit()` export still need to ship their own cdylib
//! that wraps [`prove_circuit`] with their concrete witness type.
//!
//! # Example (generic driver)
//!
//! Application cdylibs wrap [`prove_circuit`] in a `#[wasm_bindgen]` export
//! that knows their concrete witness type. The driver itself is plain Rust:
//!
//! ```
//! use ark_bn254::Fr;
//! use genshi_core::Circuit;
//! use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
//! use genshi_core::proving::srs::SRS;
//! use genshi_wasm::{prove_circuit, split_proof_blob};
//!
//! struct AddCircuit;
//! struct AddWitness { a: Fr, b: Fr }
//!
//! impl Circuit for AddCircuit {
//!     type Witness = AddWitness;
//!     type PublicInputs = [Fr; 1];
//!     const ID: &'static str = "doctest.wasm.add";
//!     fn num_public_inputs() -> usize { 1 }
//!     fn synthesize(b: &mut UltraCircuitBuilder, w: &Self::Witness) -> Self::PublicInputs {
//!         let a = b.add_variable(w.a);
//!         let bb = b.add_variable(w.b);
//!         let c = b.add(a, bb);
//!         b.set_public(c);
//!         [w.a + w.b]
//!     }
//!     fn dummy_witness() -> Self::Witness {
//!         AddWitness { a: Fr::from(0u64), b: Fr::from(0u64) }
//!     }
//! }
//!
//! let srs_bytes = SRS::insecure_for_testing(128).save_to_bytes();
//! let witness = AddWitness { a: Fr::from(3u64), b: Fr::from(5u64) };
//! let (blob, _vk_bytes) = prove_circuit::<AddCircuit>(&witness, &srs_bytes).unwrap();
//!
//! // The blob is `[u32 proof_len LE] [proof bytes] [PI bytes]`.
//! let (_proof, _pi) = split_proof_blob(&blob).unwrap();
//! ```

extern crate alloc;

use alloc::vec::Vec;

use genshi_core::circuit::Circuit;
use genshi_core::proving::api;
use genshi_core::proving::prover::{Proof, VerificationKey};
use genshi_core::proving::serialization::{
    proof_from_bytes, proof_to_bytes, public_inputs_to_bytes_le, vk_from_bytes, vk_to_bytes,
};
use genshi_core::proving::srs::SRS;
use genshi_core::proving::verifier;

/// Install `console_error_panic_hook` exactly once on WASM targets.
///
/// This is a no-op on non-WASM builds. Applications' WASM entry points should
/// call this before their first circuit build so panics surface as readable
/// console errors.
pub fn install_panic_hook() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}

/// Layout of the byte blob returned by [`prove_circuit`].
///
/// `[4 bytes proof_len LE] [proof_len bytes proof] [remaining bytes public_inputs_le]`
///
/// Applications should parse this blob with [`split_proof_blob`].
pub fn compose_proof_blob(proof_bytes: &[u8], pi_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + proof_bytes.len() + pi_bytes.len());
    out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(proof_bytes);
    out.extend_from_slice(pi_bytes);
    out
}

/// Split a blob produced by [`compose_proof_blob`] back into
/// `(proof_bytes, pi_bytes)`.
pub fn split_proof_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    if blob.len() < 4 {
        return Err("blob too short");
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&blob[..4]);
    let proof_len = u32::from_le_bytes(len_bytes) as usize;
    if blob.len() < 4 + proof_len {
        return Err("blob truncated");
    }
    Ok((&blob[4..4 + proof_len], &blob[4 + proof_len..]))
}

/// Generic proving driver.
///
/// Given a concrete circuit type `C` and a native witness value, this function
/// builds the circuit, runs the genshi prover against the supplied SRS bytes,
/// and returns a proof blob plus the canonical verification key bytes.
///
/// Returns `(proof_blob, vk_bytes)`. Callers that don't need the VK can ignore
/// the second element.
///
/// Internally this is a thin wrapper around [`genshi_core::proving::api::prove`]
/// that handles SRS deserialization and proof/PI byte composition for the
/// browser side.
pub fn prove_circuit<C: Circuit>(
    witness: &C::Witness,
    srs_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    install_panic_hook();

    let srs = SRS::load_from_bytes(srs_bytes);

    let (proof, vk, public_inputs) = api::prove::<C>(witness, &srs);

    let proof_bytes = proof_to_bytes(&proof);
    let pi_bytes = public_inputs_to_bytes_le(public_inputs.as_ref());
    let blob = compose_proof_blob(&proof_bytes, &pi_bytes);

    let vk_bytes = vk_to_bytes(&vk);
    Ok((blob, vk_bytes))
}

/// Extract the verification key bytes for `C` against the supplied SRS bytes.
///
/// Equivalent to calling [`genshi_core::proving::api::extract_vk`] and then
/// serializing the result. Useful at setup time to ship a VK to the chain
/// (or to a Solidity verifier emitter) without first generating a proof.
pub fn extract_vk_bytes<C: Circuit>(srs_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let srs = SRS::load_from_bytes(srs_bytes);
    let vk = api::extract_vk::<C>(&srs);
    Ok(vk_to_bytes(&vk))
}

/// Generic verification driver.
///
/// Deserializes `proof_bytes` and `vk_bytes` into their native types and runs
/// the genshi native verifier against the supplied public inputs and SRS.
pub fn verify_proof_bytes(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    public_inputs: &[ark_bn254::Fr],
    srs: &SRS,
) -> Result<bool, &'static str> {
    let proof: Proof = proof_from_bytes(proof_bytes).map_err(|_| "proof decode failed")?;
    let vk: VerificationKey = vk_from_bytes(vk_bytes).map_err(|_| "vk decode failed")?;
    Ok(verifier::verify(&proof, &vk, public_inputs, srs))
}

// ============================================================================
// JavaScript-facing wasm-bindgen surface
// ============================================================================
//
// These exports only compile when targeting `wasm32` because `wasm-bindgen`
// and friends are wasm-only dependencies. On host builds (including the
// in-tree cargo test suite), the `wasm` module simply doesn't exist.

#[cfg(target_arch = "wasm32")]
pub mod wasm {
    //! Direct JavaScript entry points for the circuit-agnostic pieces of
    //! genshi: panic hook installation, byte-level proof verification, and
    //! envelope helpers for the `(proof, public_inputs)` blob format.

    use alloc::vec::Vec;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use wasm_bindgen::prelude::*;

    use genshi_core::proving::srs::SRS;

    use super::{compose_proof_blob, split_proof_blob, verify_proof_bytes};

    /// Install the `console_error_panic_hook`, so Rust panics surface as
    /// readable browser console errors instead of opaque `unreachable`
    /// traps. Safe to call multiple times.
    #[wasm_bindgen]
    pub fn init() {
        super::install_panic_hook();
    }

    /// Verify a genshi proof given canonical byte encodings.
    ///
    /// - `proof_bytes`: output of `genshi_core::proving::serialization::proof_to_bytes`.
    /// - `vk_bytes`: output of `vk_to_bytes` for the same circuit.
    /// - `pi_bytes`: concatenated 32-byte little-endian Fr public inputs
    ///   (`public_inputs_to_bytes_le`). This is the canonical Solana
    ///   encoding and is byte-equivalent to what the host CLI emits.
    /// - `srs_bytes`: SRS in `SRS::save_to_bytes` format.
    ///
    /// Returns `true` on a valid proof, `false` on a cryptographically
    /// failing proof, or a `JsError` on decode / length failures.
    #[wasm_bindgen(js_name = verifyProof)]
    pub fn verify_proof(
        proof_bytes: &[u8],
        vk_bytes: &[u8],
        pi_bytes: &[u8],
        srs_bytes: &[u8],
    ) -> Result<bool, JsError> {
        if pi_bytes.len() % 32 != 0 {
            return Err(JsError::new(
                "public input bytes must be a multiple of 32 (32-byte LE Fr elements)",
            ));
        }
        let mut pis = Vec::with_capacity(pi_bytes.len() / 32);
        for chunk in pi_bytes.chunks_exact(32) {
            pis.push(Fr::from_le_bytes_mod_order(chunk));
        }
        let srs = SRS::load_from_bytes(srs_bytes);
        verify_proof_bytes(proof_bytes, vk_bytes, &pis, &srs).map_err(JsError::new)
    }

    /// Pack a `(proof, public_inputs)` pair into the length-prefixed blob
    /// format documented on [`super::compose_proof_blob`].
    #[wasm_bindgen(js_name = composeProofBlob)]
    pub fn compose_proof_blob_js(proof_bytes: &[u8], pi_bytes: &[u8]) -> Vec<u8> {
        compose_proof_blob(proof_bytes, pi_bytes)
    }

    /// Extract the proof slice from a blob produced by `composeProofBlob`.
    #[wasm_bindgen(js_name = proofFromBlob)]
    pub fn proof_from_blob(blob: &[u8]) -> Result<Vec<u8>, JsError> {
        let (p, _) = split_proof_blob(blob).map_err(JsError::new)?;
        Ok(p.to_vec())
    }

    /// Extract the public-input slice from a blob produced by `composeProofBlob`.
    #[wasm_bindgen(js_name = piFromBlob)]
    pub fn pi_from_blob(blob: &[u8]) -> Result<Vec<u8>, JsError> {
        let (_, pi) = split_proof_blob(blob).map_err(JsError::new)?;
        Ok(pi.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;

    /// Minimal Circuit impl used to exercise the generic driver in tests.
    struct AddCircuit;
    struct AddWitness {
        a: Fr,
        b: Fr,
    }

    impl Circuit for AddCircuit {
        type Witness = AddWitness;
        type PublicInputs = [Fr; 1];
        const ID: &'static str = "genshi-wasm.test.add";

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

    #[test]
    fn test_prove_and_verify_circuit_roundtrip() {
        let srs = SRS::insecure_for_testing(128);
        let srs_bytes = srs.save_to_bytes();

        let witness = AddWitness {
            a: Fr::from(3u64),
            b: Fr::from(5u64),
        };
        let (blob, vk_bytes) = prove_circuit::<AddCircuit>(&witness, &srs_bytes).unwrap();

        let (proof_bytes, pi_bytes) = split_proof_blob(&blob).unwrap();
        let mut public_inputs = Vec::new();
        for i in 0..pi_bytes.len() / 32 {
            use ark_ff::PrimeField;
            public_inputs.push(Fr::from_le_bytes_mod_order(&pi_bytes[i * 32..(i + 1) * 32]));
        }

        assert_eq!(public_inputs, vec![Fr::from(8u64)]);
        assert!(verify_proof_bytes(proof_bytes, &vk_bytes, &public_inputs, &srs).unwrap());
    }

    #[test]
    fn test_blob_roundtrip() {
        let proof = vec![1u8, 2, 3, 4, 5];
        let pi = vec![9u8, 8, 7];
        let blob = compose_proof_blob(&proof, &pi);
        let (p, i) = split_proof_blob(&blob).unwrap();
        assert_eq!(p, proof.as_slice());
        assert_eq!(i, pi.as_slice());
    }

    #[test]
    fn test_extract_vk_bytes_matches_proved_vk() {
        let srs = SRS::insecure_for_testing(128);
        let srs_bytes = srs.save_to_bytes();

        let extracted = extract_vk_bytes::<AddCircuit>(&srs_bytes).unwrap();

        let witness = AddWitness { a: Fr::from(2u64), b: Fr::from(3u64) };
        let (_, proved_vk_bytes) = prove_circuit::<AddCircuit>(&witness, &srs_bytes).unwrap();

        assert_eq!(extracted, proved_vk_bytes);
    }
}
