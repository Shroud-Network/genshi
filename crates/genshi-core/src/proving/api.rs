//! Generic prover/verifier entry points keyed on the [`Circuit`] trait.
//!
//! This is the **public API surface** genshi exposes to applications. Most
//! consumers should never construct an [`UltraCircuitBuilder`] by hand or call
//! [`prover::prove`] directly. Instead, they implement [`Circuit`] for their
//! statement and call [`prove`] / [`verify`] / [`extract_vk`] from this module.
//!
//! Verification only needs [`Circuit`]; proving and VK extraction additionally
//! need [`ProvableCircuit`] — on Solana BPF (where the prover is gated off) the
//! latter trait doesn't exist, so only [`verify`] is reachable.
//!
//! ```
//! use ark_bn254::Fr;
//! use genshi_core::{Circuit, ProvableCircuit, proving::api};
//! use genshi_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
//! use genshi_core::proving::srs::SRS;
//!
//! struct AddCircuit;
//! struct AddWitness { a: Fr, b: Fr }
//!
//! impl Circuit for AddCircuit {
//!     type PublicInputs = [Fr; 1];
//!     const ID: &'static str = "doctest.add";
//!     fn num_public_inputs() -> usize { 1 }
//! }
//!
//! impl ProvableCircuit for AddCircuit {
//!     type Witness = AddWitness;
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
//! let srs = SRS::insecure_for_testing(128);
//! let vk = api::extract_vk::<AddCircuit>(&srs);
//!
//! let witness = AddWitness { a: Fr::from(3u64), b: Fr::from(5u64) };
//! let (proof, _vk, public_inputs) = api::prove::<AddCircuit>(&witness, &srs);
//! assert!(api::verify::<AddCircuit>(&proof, &vk, &public_inputs, &srs));
//! ```

use crate::circuit::Circuit;
use crate::proving::srs::SRS;
use crate::proving::types::{Proof, VerificationKey};
use crate::proving::verifier;
use alloc::vec::Vec;
use genshi_math::Fr as GFr;

#[cfg(feature = "prover")]
use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
#[cfg(feature = "prover")]
use crate::circuit::ProvableCircuit;
#[cfg(feature = "prover")]
use crate::proving::prover;

/// Build the constraint system for `C`, run the prover, and return both the
/// proof and the public inputs the circuit committed to.
///
/// The returned `VerificationKey` is the same one [`extract_vk`] would produce
/// for `C` and the same `srs`.
///
/// # Panics
///
/// Panics if `C::synthesize` produces an unsatisfied circuit. Catching this in
/// development is the whole point of [`UltraCircuitBuilder::check_circuit_correctness`],
/// which the prover invokes via `debug_assert!`.
#[cfg(feature = "prover")]
pub fn prove<C: ProvableCircuit>(
    witness: &C::Witness,
    srs: &SRS,
) -> (Proof, VerificationKey, C::PublicInputs) {
    let mut builder = UltraCircuitBuilder::new();
    let public_inputs = C::synthesize(&mut builder, witness);
    let (proof, vk) = prover::prove(&builder, srs);
    (proof, vk, public_inputs)
}

/// Verify a proof for `C` against its verification key and public inputs.
///
/// `public_inputs` may be `&C::PublicInputs` directly or any borrow that
/// dereferences to `&[Fr]` (which is what [`Circuit::PublicInputs`] guarantees
/// via its `AsRef<[Fr]>` bound).
pub fn verify<C: Circuit>(
    proof: &Proof,
    vk: &VerificationKey,
    public_inputs: &C::PublicInputs,
    srs: &SRS,
) -> bool {
    // `Circuit::PublicInputs` is still defined in terms of `ark_bn254::Fr` so
    // downstream circuit impls don't need to know about the `genshi_math`
    // abstraction; wrap each scalar into `genshi_math::Fr` at this boundary.
    let pi: Vec<GFr> = public_inputs.as_ref().iter().copied().map(GFr::from_ark).collect();
    verifier::verify(proof, vk, &pi, srs)
}

/// Compute the verification key for a circuit shape without producing a proof.
///
/// Internally synthesizes `C` against [`ProvableCircuit::dummy_witness`] — the
/// resulting circuit must therefore have the same gate count and public input
/// shape as a "real" run, which is the contract on `dummy_witness`.
#[cfg(feature = "prover")]
pub fn extract_vk<C: ProvableCircuit>(srs: &SRS) -> VerificationKey {
    let mut builder = UltraCircuitBuilder::new();
    let dummy = C::dummy_witness();
    let _ = C::synthesize(&mut builder, &dummy);
    prover::extract_vk_from_builder(&builder, srs)
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    struct AddCircuit;
    struct AddWitness {
        a: Fr,
        b: Fr,
    }

    impl Circuit for AddCircuit {
        type PublicInputs = [Fr; 1];
        const ID: &'static str = "genshi-core.test.add";

        fn num_public_inputs() -> usize {
            1
        }
    }

    impl ProvableCircuit for AddCircuit {
        type Witness = AddWitness;

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
            AddWitness { a: Fr::from(0u64), b: Fr::from(0u64) }
        }
    }

    #[test]
    fn test_prove_verify_via_circuit_trait() {
        let srs = SRS::insecure_for_testing(128);
        let witness = AddWitness { a: Fr::from(3u64), b: Fr::from(5u64) };

        let (proof, vk, public_inputs) = prove::<AddCircuit>(&witness, &srs);
        assert_eq!(public_inputs, [Fr::from(8u64)]);
        assert!(verify::<AddCircuit>(&proof, &vk, &public_inputs, &srs));
    }

    #[test]
    fn test_extract_vk_matches_prove_vk() {
        let srs = SRS::insecure_for_testing(128);
        let witness = AddWitness { a: Fr::from(7u64), b: Fr::from(11u64) };

        let standalone_vk = extract_vk::<AddCircuit>(&srs);
        let (_, prove_vk, _) = prove::<AddCircuit>(&witness, &srs);

        // The shape (selectors, sigmas, domain) must agree — the dummy witness
        // and the real witness produce the same circuit topology.
        assert_eq!(standalone_vk.domain_size, prove_vk.domain_size);
        assert_eq!(standalone_vk.num_public_inputs, prove_vk.num_public_inputs);
        assert_eq!(standalone_vk.q_m_comm, prove_vk.q_m_comm);
        assert_eq!(standalone_vk.q_1_comm, prove_vk.q_1_comm);
        assert_eq!(standalone_vk.sigma_comms, prove_vk.sigma_comms);
    }

    #[test]
    fn test_verify_rejects_wrong_public_inputs() {
        let srs = SRS::insecure_for_testing(128);
        let witness = AddWitness { a: Fr::from(3u64), b: Fr::from(5u64) };
        let (proof, vk, _) = prove::<AddCircuit>(&witness, &srs);

        let wrong: <AddCircuit as Circuit>::PublicInputs = [Fr::from(99u64)];
        assert!(!verify::<AddCircuit>(&proof, &vk, &wrong, &srs));
    }
}
