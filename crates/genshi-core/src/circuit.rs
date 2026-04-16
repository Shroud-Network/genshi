//! Circuit trait split — verifier-side (`Circuit`) and prover-side (`ProvableCircuit`).
//!
//! `Circuit` carries only the metadata the verifier needs (public-input count and a
//! stable ID). `ProvableCircuit` extends it with the witness type and the synthesis
//! function required for proof generation. The split lets Solana BPF builds strip the
//! prover path (arithmetization + gadgets + synthesis) while still knowing how to
//! verify proofs for a given circuit.
//!
//! # Example
//!
//! ```
//! use genshi_core::Circuit;
//! # #[cfg(feature = "prover")]
//! # use genshi_core::{ProvableCircuit, arithmetization::ultra_circuit_builder::UltraCircuitBuilder};
//! use ark_bn254::Fr;
//!
//! pub struct AddCircuit;
//! pub struct AddWitness { pub a: Fr, pub b: Fr }
//!
//! impl Circuit for AddCircuit {
//!     type PublicInputs = [Fr; 1];
//!     const ID: &'static str = "example.add";
//!
//!     fn num_public_inputs() -> usize { 1 }
//! }
//!
//! # #[cfg(feature = "prover")]
//! impl ProvableCircuit for AddCircuit {
//!     type Witness = AddWitness;
//!
//!     fn synthesize(builder: &mut UltraCircuitBuilder, w: &Self::Witness) -> Self::PublicInputs {
//!         let a = builder.add_variable(w.a);
//!         let b = builder.add_variable(w.b);
//!         let c = builder.add(a, b);
//!         builder.set_public(c);
//!         [w.a + w.b]
//!     }
//!
//!     fn dummy_witness() -> Self::Witness {
//!         AddWitness { a: Fr::from(0u64), b: Fr::from(0u64) }
//!     }
//! }
//! ```

use ark_bn254::Fr;

#[cfg(feature = "prover")]
use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;

/// Verifier-side circuit metadata.
///
/// Every application circuit implements this. The bounds are intentionally
/// minimal so this trait compiles on `no_std` verifier-only builds (Solana BPF)
/// with zero dependency on the prover path.
pub trait Circuit {
    /// Public inputs produced by the circuit, in the order enforced inside it.
    type PublicInputs: AsRef<[Fr]>;

    /// Stable identifier for this circuit — must be unique within an application.
    const ID: &'static str;

    /// Number of public inputs this circuit exposes. Must match `PublicInputs::as_ref().len()`.
    fn num_public_inputs() -> usize;
}

/// Prover-side circuit contract. Only compiled when the `prover` feature is on.
///
/// Extends `Circuit` with the witness type and the synthesis function. Setup and
/// proving take a `C: ProvableCircuit` bound; verification takes only `C: Circuit`.
#[cfg(feature = "prover")]
pub trait ProvableCircuit: Circuit {
    /// Native witness data handed to `synthesize`.
    type Witness;

    /// Wire the circuit's constraints into `builder` given `witness`, returning
    /// the public inputs in the same order the circuit publishes them.
    fn synthesize(
        builder: &mut UltraCircuitBuilder,
        witness: &Self::Witness,
    ) -> Self::PublicInputs;

    /// Construct a zeroed / placeholder witness.
    ///
    /// Used at setup time to compile the circuit shape for SRS/VK extraction
    /// without needing real private data.
    fn dummy_witness() -> Self::Witness;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
    use crate::proving::{api, srs::SRS};

    // ----------------------------------------------------------------
    // Minimal test circuit — exercises every trait requirement
    // ----------------------------------------------------------------

    struct TestAddCircuit;
    struct TestAddWitness { a: Fr, b: Fr }

    impl Circuit for TestAddCircuit {
        type PublicInputs = [Fr; 1];
        const ID: &'static str = "test.add";

        fn num_public_inputs() -> usize { 1 }
    }

    impl ProvableCircuit for TestAddCircuit {
        type Witness = TestAddWitness;

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
            TestAddWitness { a: Fr::from(0u64), b: Fr::from(0u64) }
        }
    }

    // Zero-public-input circuit
    struct TestMulCircuit;
    struct TestMulWitness { a: Fr, b: Fr, c: Fr }

    impl Circuit for TestMulCircuit {
        type PublicInputs = [Fr; 0];
        const ID: &'static str = "test.mul";

        fn num_public_inputs() -> usize { 0 }
    }

    impl ProvableCircuit for TestMulCircuit {
        type Witness = TestMulWitness;

        fn synthesize(
            builder: &mut UltraCircuitBuilder,
            w: &Self::Witness,
        ) -> Self::PublicInputs {
            let a = builder.add_variable(w.a);
            let b = builder.add_variable(w.b);
            let c = builder.add_variable(w.c);
            builder.create_mul_gate(a, b, c);
            []
        }

        fn dummy_witness() -> Self::Witness {
            TestMulWitness { a: Fr::from(0u64), b: Fr::from(0u64), c: Fr::from(0u64) }
        }
    }

    // ----------------------------------------------------------------
    // Trait conformance tests
    // ----------------------------------------------------------------

    #[test]
    fn test_circuit_id_is_stable() {
        assert_eq!(TestAddCircuit::ID, "test.add");
        assert_eq!(TestMulCircuit::ID, "test.mul");
    }

    #[test]
    fn test_num_public_inputs_matches_synthesize() {
        let w = TestAddCircuit::dummy_witness();
        let mut builder = UltraCircuitBuilder::new();
        let pi = TestAddCircuit::synthesize(&mut builder, &w);
        assert_eq!(pi.as_ref().len(), TestAddCircuit::num_public_inputs());
    }

    #[test]
    fn test_num_public_inputs_zero() {
        let w = TestMulCircuit::dummy_witness();
        let mut builder = UltraCircuitBuilder::new();
        let pi = TestMulCircuit::synthesize(&mut builder, &w);
        assert_eq!(pi.as_ref().len(), 0);
        assert_eq!(TestMulCircuit::num_public_inputs(), 0);
    }

    #[test]
    fn test_dummy_witness_produces_valid_circuit() {
        let w = TestAddCircuit::dummy_witness();
        let mut builder = UltraCircuitBuilder::new();
        let _pi = TestAddCircuit::synthesize(&mut builder, &w);
        assert!(
            builder.check_circuit_correctness(),
            "Dummy witness should produce a valid circuit"
        );
    }

    #[test]
    fn test_dummy_witness_mul_produces_valid_circuit() {
        let w = TestMulCircuit::dummy_witness();
        let mut builder = UltraCircuitBuilder::new();
        let _pi = TestMulCircuit::synthesize(&mut builder, &w);
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_synthesize_with_real_witness() {
        let w = TestAddWitness { a: Fr::from(3u64), b: Fr::from(7u64) };
        let mut builder = UltraCircuitBuilder::new();
        let pi = TestAddCircuit::synthesize(&mut builder, &w);
        assert_eq!(pi[0], Fr::from(10u64));
        assert!(builder.check_circuit_correctness());
    }

    #[test]
    fn test_extract_vk_from_trait() {
        let srs = SRS::insecure_for_testing(128);
        let vk = api::extract_vk::<TestAddCircuit>(&srs);
        assert_eq!(vk.num_public_inputs, 1);
        assert!(vk.domain_size > 0);
    }

    #[test]
    fn test_prove_verify_via_trait() {
        let srs = SRS::insecure_for_testing(128);
        let w = TestAddWitness { a: Fr::from(5u64), b: Fr::from(15u64) };
        let (proof, vk, pi) = api::prove::<TestAddCircuit>(&w, &srs);
        assert_eq!(pi, [Fr::from(20u64)]);
        assert!(api::verify::<TestAddCircuit>(&proof, &vk, &pi, &srs));
    }

    #[test]
    fn test_prove_verify_zero_pi_circuit() {
        let srs = SRS::insecure_for_testing(128);
        let w = TestMulWitness { a: Fr::from(3u64), b: Fr::from(4u64), c: Fr::from(12u64) };
        let (proof, vk, pi) = api::prove::<TestMulCircuit>(&w, &srs);
        assert!(pi.as_ref().is_empty());
        assert!(api::verify::<TestMulCircuit>(&proof, &vk, &pi, &srs));
    }

    #[test]
    fn test_wrong_witness_fails_verification() {
        let srs = SRS::insecure_for_testing(128);
        let w = TestAddWitness { a: Fr::from(5u64), b: Fr::from(15u64) };
        let (proof, vk, _) = api::prove::<TestAddCircuit>(&w, &srs);
        let wrong: [Fr; 1] = [Fr::from(999u64)];
        assert!(
            !api::verify::<TestAddCircuit>(&proof, &vk, &wrong, &srs),
            "Wrong PI should fail verification"
        );
    }

    #[test]
    fn test_different_circuits_different_vks() {
        let srs = SRS::insecure_for_testing(128);
        let vk_add = api::extract_vk::<TestAddCircuit>(&srs);
        let vk_mul = api::extract_vk::<TestMulCircuit>(&srs);
        // Different circuits must produce different VKs
        assert_ne!(vk_add.num_public_inputs, vk_mul.num_public_inputs);
    }
}
