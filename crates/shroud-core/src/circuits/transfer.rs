//! Transfer circuit: 1 input note → 2 output notes.
//!
//! Proves (without revealing amounts):
//! 1. Ownership: prover knows the secret to an existing note
//! 2. Merkle inclusion: input note commitment is in the tree
//! 3. Nullifier: correctly derived from note secrets + leaf index
//! 4. Output commitments: two new notes are validly committed
//! 5. Conservation: `input_amount == output_1_amount + output_2_amount`
//! 6. Range: all amounts are in `[0, 2^64)`
//!
//! **Public inputs** (order matters): merkle_root, nullifier, output_commitment_1, output_commitment_2
//! **Private witness**: all note fields, Merkle path, amounts, blinding factors, secrets
//!
//! **GUARDRAIL G1**: Amount is NEVER a public input in private transfer.

use ark_bn254::Fr;
use ark_ec::AffineRepr;

use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use crate::circuits::gadgets::merkle::{MerklePath, merkle_inclusion_gadget};
use crate::circuits::gadgets::nullifier::nullifier_gadget;
use crate::circuits::gadgets::note_commitment::full_note_commitment_gadget;
use crate::circuits::gadgets::range_proof::{range_check_64bit, register_range_table};
use crate::note::{Note, grumpkin_scalar_to_fr};

/// Public inputs produced by the transfer circuit.
///
/// The verifier checks these against on-chain state:
/// - `merkle_root` must be in the root history buffer (Guardrail G4)
/// - `nullifier` must not already be spent
/// - `output_commitment_1/2` are inserted into the Merkle tree
#[derive(Clone, Debug)]
pub struct TransferPublicInputs {
    pub merkle_root: Fr,
    pub nullifier: Fr,
    pub output_commitment_1: Fr,
    pub output_commitment_2: Fr,
}

impl TransferPublicInputs {
    /// Return public inputs as a slice in the order the circuit sets them.
    pub fn to_vec(&self) -> alloc::vec::Vec<Fr> {
        alloc::vec![self.merkle_root, self.nullifier, self.output_commitment_1, self.output_commitment_2]
    }
}

/// Transfer circuit witness: all private data needed to generate a proof.
#[derive(Clone, Debug)]
pub struct TransferCircuit {
    /// The input note being spent.
    pub input_note: Note,
    /// Merkle authentication path for the input note.
    pub merkle_path: MerklePath,
    /// First output note.
    pub output_note_1: Note,
    /// Second output note.
    pub output_note_2: Note,
}

impl TransferCircuit {
    /// Build the transfer circuit, adding all constraints to the builder.
    ///
    /// Returns the public input values (needed by the verifier).
    ///
    /// # Panics
    /// Panics if note public keys or Pedersen commitments are the identity point.
    pub fn build(&self, builder: &mut UltraCircuitBuilder) -> TransferPublicInputs {
        // Register the 8-bit range table (once, shared by all range checks)
        let range_table = register_range_table(builder);

        // ================================================================
        // Input note: compute native values
        // ================================================================
        let in_pedersen = self.input_note.pedersen_commitment();
        let in_cx: Fr = in_pedersen.x().expect("input Pedersen commitment must not be identity");
        let in_cy: Fr = in_pedersen.y().expect("input Pedersen commitment must not be identity");
        let in_secret_fr = grumpkin_scalar_to_fr(self.input_note.secret);
        let in_np_fr = grumpkin_scalar_to_fr(self.input_note.nullifier_preimage);
        let in_pk_x: Fr = self.input_note.owner_public_key.x()
            .expect("input owner public key must not be identity");
        let in_amount_fr = Fr::from(self.input_note.amount);
        let in_leaf_index_fr = Fr::from(self.input_note.leaf_index);

        // Allocate private witness wires
        let in_amount_w = builder.add_variable(in_amount_fr);
        let in_secret_w = builder.add_variable(in_secret_fr);
        let in_np_w = builder.add_variable(in_np_fr);
        let in_pk_x_w = builder.add_variable(in_pk_x);
        let in_leaf_idx_w = builder.add_variable(in_leaf_index_fr);

        // 1. Input note commitment (Pedersen computed natively, Poseidon2 in-circuit)
        let in_commitment = full_note_commitment_gadget(
            builder, in_secret_w, in_np_w, in_pk_x_w, in_cx, in_cy,
        );

        // 2. Merkle inclusion proof → root is public
        let merkle_root_w = merkle_inclusion_gadget(builder, in_commitment, &self.merkle_path);
        builder.set_public(merkle_root_w);

        // 3. Nullifier derivation → public
        let nullifier_w = nullifier_gadget(builder, in_np_w, in_secret_w, in_leaf_idx_w);
        builder.set_public(nullifier_w);

        // ================================================================
        // Output note 1
        // ================================================================
        let out1_pedersen = self.output_note_1.pedersen_commitment();
        let out1_cx: Fr = out1_pedersen.x().expect("output 1 Pedersen must not be identity");
        let out1_cy: Fr = out1_pedersen.y().expect("output 1 Pedersen must not be identity");
        let out1_secret_fr = grumpkin_scalar_to_fr(self.output_note_1.secret);
        let out1_np_fr = grumpkin_scalar_to_fr(self.output_note_1.nullifier_preimage);
        let out1_pk_x: Fr = self.output_note_1.owner_public_key.x()
            .expect("output 1 owner public key must not be identity");
        let out1_amount_fr = Fr::from(self.output_note_1.amount);

        let out1_amount_w = builder.add_variable(out1_amount_fr);
        let out1_secret_w = builder.add_variable(out1_secret_fr);
        let out1_np_w = builder.add_variable(out1_np_fr);
        let out1_pk_x_w = builder.add_variable(out1_pk_x);

        let out1_commitment_w = full_note_commitment_gadget(
            builder, out1_secret_w, out1_np_w, out1_pk_x_w, out1_cx, out1_cy,
        );
        builder.set_public(out1_commitment_w);

        // ================================================================
        // Output note 2
        // ================================================================
        let out2_pedersen = self.output_note_2.pedersen_commitment();
        let out2_cx: Fr = out2_pedersen.x().expect("output 2 Pedersen must not be identity");
        let out2_cy: Fr = out2_pedersen.y().expect("output 2 Pedersen must not be identity");
        let out2_secret_fr = grumpkin_scalar_to_fr(self.output_note_2.secret);
        let out2_np_fr = grumpkin_scalar_to_fr(self.output_note_2.nullifier_preimage);
        let out2_pk_x: Fr = self.output_note_2.owner_public_key.x()
            .expect("output 2 owner public key must not be identity");
        let out2_amount_fr = Fr::from(self.output_note_2.amount);

        let out2_amount_w = builder.add_variable(out2_amount_fr);
        let out2_secret_w = builder.add_variable(out2_secret_fr);
        let out2_np_w = builder.add_variable(out2_np_fr);
        let out2_pk_x_w = builder.add_variable(out2_pk_x);

        let out2_commitment_w = full_note_commitment_gadget(
            builder, out2_secret_w, out2_np_w, out2_pk_x_w, out2_cx, out2_cy,
        );
        builder.set_public(out2_commitment_w);

        // ================================================================
        // 5. Conservation: input_amount == out1_amount + out2_amount
        // GUARDRAIL G1: amounts stay private — only the equality is constrained
        // ================================================================
        let output_sum = builder.add(out1_amount_w, out2_amount_w);
        builder.assert_equal(in_amount_w, output_sum);

        // ================================================================
        // 6. Range proofs: all amounts in [0, 2^64)
        // ================================================================
        range_check_64bit(builder, in_amount_w, range_table);
        range_check_64bit(builder, out1_amount_w, range_table);
        range_check_64bit(builder, out2_amount_w, range_table);

        // ================================================================
        // Collect public input values for the verifier
        // ================================================================
        TransferPublicInputs {
            merkle_root: builder.get_variable(merkle_root_w),
            nullifier: builder.get_variable(nullifier_w),
            output_commitment_1: builder.get_variable(out1_commitment_w),
            output_commitment_2: builder.get_variable(out2_commitment_w),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen;
    use crate::circuits::gadgets::merkle::generate_merkle_path;
    use crate::proving::prover;
    use crate::proving::verifier;
    use crate::proving::srs::SRS;
    use ark_ff::Zero;

    type GrumpkinScalar = ark_bn254::Fq;

    /// Create a test note with the given amount at the given leaf index.
    fn make_note(amount: u64, leaf_index: u64) -> Note {
        let pk = pedersen::generator_g(); // test-only public key
        Note::new(
            amount,
            GrumpkinScalar::from(100u64 + amount),    // blinding
            GrumpkinScalar::from(200u64 + amount),    // secret
            GrumpkinScalar::from(300u64 + amount),    // nullifier_preimage
            pk,
            leaf_index,
        )
    }

    /// Build a minimal Merkle tree containing the input note and return the path.
    fn build_tree_and_path(note: &Note) -> MerklePath {
        let commitment = note.commitment();
        let leaf_idx = note.leaf_index as usize;

        // Create leaves: put commitment at the correct index, zeros elsewhere
        let num_leaves = 4; // depth=1 subtree, remaining 9 levels hash zeros
        let mut leaves = alloc::vec![Fr::zero(); num_leaves];
        leaves[leaf_idx] = commitment;

        generate_merkle_path(&leaves, leaf_idx, 1)
    }

    #[test]
    fn test_transfer_circuit_correctness() {
        let input_note = make_note(100, 0);
        let output_note_1 = make_note(60, 0); // leaf_index irrelevant for outputs
        let output_note_2 = make_note(40, 0);

        let path = build_tree_and_path(&input_note);

        let circuit = TransferCircuit {
            input_note,
            merkle_path: path,
            output_note_1,
            output_note_2,
        };

        let mut builder = UltraCircuitBuilder::new();
        let pi = circuit.build(&mut builder);

        assert!(builder.check_circuit_correctness(),
            "Transfer circuit with valid witness must be satisfied");

        // Verify public inputs match native computation
        assert_eq!(pi.nullifier, circuit.input_note.nullifier());
        assert_eq!(pi.output_commitment_1, circuit.output_note_1.commitment());
        assert_eq!(pi.output_commitment_2, circuit.output_note_2.commitment());
    }

    #[test]
    fn test_transfer_end_to_end_prove_verify() {
        let input_note = make_note(100, 0);
        let output_note_1 = make_note(70, 0);
        let output_note_2 = make_note(30, 0);

        let path = build_tree_and_path(&input_note);

        let circuit = TransferCircuit {
            input_note,
            merkle_path: path,
            output_note_1,
            output_note_2,
        };

        let mut builder = UltraCircuitBuilder::new();
        let pi = circuit.build(&mut builder);

        assert!(builder.check_circuit_correctness());

        // Prove and verify
        let srs = SRS::insecure_for_testing(65536);
        let (proof, vk) = prover::prove(&builder, &srs);
        assert!(
            verifier::verify(&proof, &vk, &pi.to_vec(), &srs),
            "Valid transfer proof must verify"
        );
    }

    #[test]
    fn test_transfer_wrong_public_inputs_fail() {
        let input_note = make_note(100, 0);
        let output_note_1 = make_note(60, 0);
        let output_note_2 = make_note(40, 0);

        let path = build_tree_and_path(&input_note);

        let circuit = TransferCircuit {
            input_note,
            merkle_path: path,
            output_note_1,
            output_note_2,
        };

        let mut builder = UltraCircuitBuilder::new();
        let pi = circuit.build(&mut builder);

        let srs = SRS::insecure_for_testing(65536);
        let (proof, vk) = prover::prove(&builder, &srs);

        // Tamper with the nullifier public input
        let mut bad_pi = pi.to_vec();
        bad_pi[1] = Fr::from(9999u64);
        assert!(
            !verifier::verify(&proof, &vk, &bad_pi, &srs),
            "Wrong public inputs must fail verification"
        );
    }

    #[test]
    fn test_transfer_conservation_violation_fails() {
        // Amounts don't balance: 100 != 60 + 50
        let input_note = make_note(100, 0);
        let output_note_1 = make_note(60, 0);
        let output_note_2 = make_note(50, 0); // should be 40

        let path = build_tree_and_path(&input_note);

        let circuit = TransferCircuit {
            input_note,
            merkle_path: path,
            output_note_1,
            output_note_2,
        };

        let mut builder = UltraCircuitBuilder::new();
        let _pi = circuit.build(&mut builder);

        assert!(
            !builder.check_circuit_correctness(),
            "Conservation violation must fail circuit check"
        );
    }

    #[test]
    fn test_transfer_amount_not_public() {
        // GUARDRAIL G1: verify that amount is NOT a public input
        let input_note = make_note(100, 0);
        let output_note_1 = make_note(60, 0);
        let output_note_2 = make_note(40, 0);

        let path = build_tree_and_path(&input_note);

        let circuit = TransferCircuit {
            input_note,
            merkle_path: path,
            output_note_1,
            output_note_2,
        };

        let mut builder = UltraCircuitBuilder::new();
        let pi = circuit.build(&mut builder);

        // There should be exactly 4 public inputs: root, nullifier, comm1, comm2
        assert_eq!(builder.get_public_inputs().len(), 4,
            "Transfer circuit must have exactly 4 public inputs");

        // None of the public inputs should be the amount
        let amount_fr = Fr::from(100u64);
        for &val in &pi.to_vec() {
            assert_ne!(val, amount_fr,
                "GUARDRAIL G1: amount must NEVER be a public input");
        }
    }

    #[test]
    fn test_transfer_constraint_count() {
        let input_note = make_note(100, 0);
        let output_note_1 = make_note(60, 0);
        let output_note_2 = make_note(40, 0);

        let path = build_tree_and_path(&input_note);

        let circuit = TransferCircuit {
            input_note,
            merkle_path: path,
            output_note_1,
            output_note_2,
        };

        let mut builder = UltraCircuitBuilder::new();
        let _pi = circuit.build(&mut builder);

        let count = builder.num_gates();
        // With basic arithmetic gates, Poseidon2 costs ~712 gates/hash.
        // Custom Poseidon2 gates (future optimization) would bring this to ~2,500.
        assert!(count < 20000,
            "Transfer circuit constraint count {} exceeds budget of 20000", count);
        // Log the actual count for benchmarking reference
        assert!(count > 1000,
            "Transfer circuit suspiciously small at {} gates", count);
    }
}
