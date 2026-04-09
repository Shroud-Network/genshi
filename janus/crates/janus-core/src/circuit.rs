//! The `Circuit` trait — the contract between an application and the Janus framework.
//!
//! An application defines a type that implements `Circuit` for each distinct
//! proof statement it wants to support. The framework then drives synthesis,
//! proving, and verification generically over any such type.
//!
//! # Example
//!
//! ```
//! use janus_core::{Circuit, arithmetization::ultra_circuit_builder::UltraCircuitBuilder};
//! use ark_bn254::Fr;
//!
//! pub struct AddCircuit;
//! pub struct AddWitness { pub a: Fr, pub b: Fr }
//!
//! impl Circuit for AddCircuit {
//!     type Witness = AddWitness;
//!     type PublicInputs = [Fr; 1];
//!     const ID: &'static str = "example.add";
//!
//!     fn num_public_inputs() -> usize { 1 }
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

use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;

/// Framework contract implemented by every application circuit.
///
/// An implementer provides:
/// - a `Witness` type carrying all private + public inputs in native form,
/// - a `PublicInputs` type (typically a fixed-size array of `Fr`),
/// - a stable string `ID` used by SRS/VK bookkeeping,
/// - a `synthesize` function that wires the constraint system, and
/// - a `dummy_witness` used at setup time to extract the verification key.
pub trait Circuit {
    /// Native witness data handed to `synthesize`.
    type Witness;

    /// Public inputs produced by the circuit, in the order enforced inside it.
    type PublicInputs: AsRef<[Fr]>;

    /// Stable identifier for this circuit — must be unique within an application.
    const ID: &'static str;

    /// Number of public inputs this circuit exposes. Must match `PublicInputs::as_ref().len()`.
    fn num_public_inputs() -> usize;

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
