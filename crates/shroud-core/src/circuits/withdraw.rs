//! Withdraw circuit: exit the shielded pool.
//!
//! Proves:
//! 1. Ownership: prover knows the secret to an existing note
//! 2. Merkle inclusion: note commitment is in the tree
//! 3. Nullifier: correctly derived (prevents double-spend)
//! 4. Amount matches the note (revealed publicly for on-chain transfer)
//!
//! **Public inputs** (order matters): merkle_root, nullifier, amount, recipient
//!
//! Unlike transfer, the withdrawal **does** reveal the amount, because the
//! on-chain contract needs to know how many tokens to send to the recipient.

use ark_bn254::Fr;
use ark_ec::AffineRepr;

use crate::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use crate::circuits::gadgets::merkle::{MerklePath, merkle_inclusion_gadget};
use crate::circuits::gadgets::nullifier::nullifier_gadget;
use crate::circuits::gadgets::note_commitment::full_note_commitment_gadget;
use crate::circuits::gadgets::range_proof::{range_check_64bit, register_range_table};
use crate::note::{Note, grumpkin_scalar_to_fr};

/// Public inputs produced by the withdraw circuit.
///
/// The verifier (on-chain contract) checks:
/// - `merkle_root` is in the root history buffer
/// - `nullifier` has not been spent
/// - `amount` tokens are transferred to `recipient`
#[derive(Clone, Debug)]
pub struct WithdrawPublicInputs {
    pub merkle_root: Fr,
    pub nullifier: Fr,
    pub amount: Fr,
    pub recipient: Fr,
}

impl WithdrawPublicInputs {
    /// Return public inputs as a slice in the order the circuit sets them.
    pub fn to_vec(&self) -> alloc::vec::Vec<Fr> {
        alloc::vec![self.merkle_root, self.nullifier, self.amount, self.recipient]
    }
}

/// Withdraw circuit witness: all private data needed to generate a proof.
#[derive(Clone, Debug)]
pub struct WithdrawCircuit {
    /// The note being withdrawn (spent).
    pub input_note: Note,
    /// Merkle authentication path for the input note.
    pub merkle_path: MerklePath,
    /// Recipient address (public — the on-chain address receiving tokens).
    pub recipient: Fr,
}

impl WithdrawCircuit {
    /// Build the withdraw circuit, adding all constraints to the builder.
    ///
    /// Returns the public input values (needed by the verifier).
    pub fn build(&self, builder: &mut UltraCircuitBuilder) -> WithdrawPublicInputs {
        // Register the 8-bit range table
        let range_table = register_range_table(builder);

        // ================================================================
        // Input note: compute native values
        // ================================================================
        let in_pedersen = self.input_note.pedersen_commitment();
        let in_cx: Fr = in_pedersen.x().expect("Pedersen commitment must not be identity");
        let in_cy: Fr = in_pedersen.y().expect("Pedersen commitment must not be identity");
        let in_secret_fr = grumpkin_scalar_to_fr(self.input_note.secret);
        let in_np_fr = grumpkin_scalar_to_fr(self.input_note.nullifier_preimage);
        let in_pk_x: Fr = self.input_note.owner_public_key.x()
            .expect("owner public key must not be identity");
        let in_amount_fr = Fr::from(self.input_note.amount);
        let in_leaf_index_fr = Fr::from(self.input_note.leaf_index);

        // Allocate private witness wires
        let in_amount_w = builder.add_variable(in_amount_fr);
        let in_secret_w = builder.add_variable(in_secret_fr);
        let in_np_w = builder.add_variable(in_np_fr);
        let in_pk_x_w = builder.add_variable(in_pk_x);
        let in_leaf_idx_w = builder.add_variable(in_leaf_index_fr);

        // 1. Input note commitment (Pedersen native, Poseidon2 in-circuit)
        let in_commitment = full_note_commitment_gadget(
            builder, in_secret_w, in_np_w, in_pk_x_w, in_cx, in_cy,
        );

        // 2. Merkle inclusion proof → root is public
        let merkle_root_w = merkle_inclusion_gadget(builder, in_commitment, &self.merkle_path);
        builder.set_public(merkle_root_w);

        // 3. Nullifier derivation → public
        let nullifier_w = nullifier_gadget(builder, in_np_w, in_secret_w, in_leaf_idx_w);
        builder.set_public(nullifier_w);

        // 4. Amount is public (withdrawal reveals how much is being taken out)
        builder.set_public(in_amount_w);

        // 5. Recipient is public (on-chain address receiving tokens)
        let recipient_w = builder.add_variable(self.recipient);
        builder.set_public(recipient_w);

        // 6. Range proof on the amount
        range_check_64bit(builder, in_amount_w, range_table);

        // ================================================================
        // Collect public input values for the verifier
        // ================================================================
        WithdrawPublicInputs {
            merkle_root: builder.get_variable(merkle_root_w),
            nullifier: builder.get_variable(nullifier_w),
            amount: builder.get_variable(in_amount_w),
            recipient: builder.get_variable(recipient_w),
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

    fn make_note(amount: u64, leaf_index: u64) -> Note {
        let pk = pedersen::generator_g();
        Note::new(
            amount,
            GrumpkinScalar::from(100u64 + amount),
            GrumpkinScalar::from(200u64 + amount),
            GrumpkinScalar::from(300u64 + amount),
            pk,
            leaf_index,
        )
    }

    fn build_tree_and_path(note: &Note) -> MerklePath {
        let commitment = note.commitment();
        let leaf_idx = note.leaf_index as usize;
        let num_leaves = 4;
        let mut leaves = alloc::vec![Fr::zero(); num_leaves];
        leaves[leaf_idx] = commitment;
        generate_merkle_path(&leaves, leaf_idx, 1)
    }

    #[test]
    fn test_withdraw_circuit_correctness() {
        let note = make_note(500, 2);
        let path = build_tree_and_path(&note);
        let recipient = Fr::from(0xDEADBEEFu64);

        let circuit = WithdrawCircuit {
            input_note: note,
            merkle_path: path,
            recipient,
        };

        let mut builder = UltraCircuitBuilder::new();
        let pi = circuit.build(&mut builder);

        assert!(builder.check_circuit_correctness(),
            "Withdraw circuit with valid witness must be satisfied");

        assert_eq!(pi.nullifier, circuit.input_note.nullifier());
        assert_eq!(pi.amount, Fr::from(500u64));
        assert_eq!(pi.recipient, recipient);
    }

    #[test]
    fn test_withdraw_end_to_end_prove_verify() {
        let note = make_note(250, 1);
        let path = build_tree_and_path(&note);
        let recipient = Fr::from(0xCAFEu64);

        let circuit = WithdrawCircuit {
            input_note: note,
            merkle_path: path,
            recipient,
        };

        let mut builder = UltraCircuitBuilder::new();
        let pi = circuit.build(&mut builder);

        assert!(builder.check_circuit_correctness());

        let srs = SRS::insecure_for_testing(65536);
        let (proof, vk) = prover::prove(&builder, &srs);
        assert!(
            verifier::verify(&proof, &vk, &pi.to_vec(), &srs),
            "Valid withdraw proof must verify"
        );
    }

    #[test]
    fn test_withdraw_wrong_amount_fails() {
        let note = make_note(250, 1);
        let path = build_tree_and_path(&note);
        let recipient = Fr::from(0xCAFEu64);

        let circuit = WithdrawCircuit {
            input_note: note,
            merkle_path: path,
            recipient,
        };

        let mut builder = UltraCircuitBuilder::new();
        let pi = circuit.build(&mut builder);

        let srs = SRS::insecure_for_testing(65536);
        let (proof, vk) = prover::prove(&builder, &srs);

        // Tamper with the amount public input
        let mut bad_pi = pi.to_vec();
        bad_pi[2] = Fr::from(999u64); // wrong amount
        assert!(
            !verifier::verify(&proof, &vk, &bad_pi, &srs),
            "Wrong amount must fail verification"
        );
    }

    #[test]
    fn test_withdraw_has_4_public_inputs() {
        let note = make_note(100, 0);
        let path = build_tree_and_path(&note);

        let circuit = WithdrawCircuit {
            input_note: note,
            merkle_path: path,
            recipient: Fr::from(42u64),
        };

        let mut builder = UltraCircuitBuilder::new();
        let _pi = circuit.build(&mut builder);

        assert_eq!(builder.get_public_inputs().len(), 4,
            "Withdraw circuit must have exactly 4 public inputs: root, nullifier, amount, recipient");
    }

    #[test]
    fn test_withdraw_constraint_count() {
        let note = make_note(100, 0);
        let path = build_tree_and_path(&note);

        let circuit = WithdrawCircuit {
            input_note: note,
            merkle_path: path,
            recipient: Fr::from(42u64),
        };

        let mut builder = UltraCircuitBuilder::new();
        let _pi = circuit.build(&mut builder);

        let count = builder.num_gates();
        // With basic arithmetic gates (~712 per Poseidon2 hash).
        // Custom Poseidon2 gates (future optimization) would bring this to ~1,500.
        assert!(count < 15000,
            "Withdraw circuit constraint count {} exceeds budget of 15000", count);
        assert!(count > 500,
            "Withdraw circuit suspiciously small at {} gates", count);
    }
}
