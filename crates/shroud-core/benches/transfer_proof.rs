//! Criterion benchmarks for shroud-honk proving performance.
//!
//! Measures: circuit construction, proof generation, verification,
//! and constraint counts for transfer and withdraw circuits.

use criterion::{criterion_group, criterion_main, Criterion};

use ark_bn254::Fr;
use ark_ff::Zero;
use shroud_core::arithmetization::ultra_circuit_builder::UltraCircuitBuilder;
use shroud_core::circuits::gadgets::merkle::{MerklePath, generate_merkle_path};
use shroud_core::circuits::transfer::TransferCircuit;
use shroud_core::circuits::withdraw::WithdrawCircuit;
use shroud_core::crypto::pedersen;
use shroud_core::note::Note;
use shroud_core::proving::prover;
use shroud_core::proving::verifier;
use shroud_core::proving::srs::SRS;

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
    let mut leaves = vec![Fr::zero(); num_leaves];
    leaves[leaf_idx] = commitment;
    generate_merkle_path(&leaves, leaf_idx, 1)
}

fn make_transfer_circuit() -> TransferCircuit {
    let input_note = make_note(100, 0);
    let path = build_tree_and_path(&input_note);
    TransferCircuit {
        input_note,
        merkle_path: path,
        output_note_1: make_note(60, 0),
        output_note_2: make_note(40, 0),
    }
}

fn make_withdraw_circuit() -> WithdrawCircuit {
    let note = make_note(250, 1);
    let path = build_tree_and_path(&note);
    WithdrawCircuit {
        input_note: note,
        merkle_path: path,
        recipient: Fr::from(0xCAFEu64),
    }
}

fn bench_transfer_build(c: &mut Criterion) {
    let circuit = make_transfer_circuit();
    c.bench_function("transfer_circuit_build", |b| {
        b.iter(|| {
            let mut builder = UltraCircuitBuilder::new();
            circuit.build(&mut builder);
        })
    });
}

fn bench_transfer_prove(c: &mut Criterion) {
    let circuit = make_transfer_circuit();
    let mut builder = UltraCircuitBuilder::new();
    let _pi = circuit.build(&mut builder);
    let srs = SRS::insecure_for_testing(65536);

    c.bench_function("transfer_prove", |b| {
        b.iter(|| {
            prover::prove(&builder, &srs);
        })
    });
}

fn bench_transfer_verify(c: &mut Criterion) {
    let circuit = make_transfer_circuit();
    let mut builder = UltraCircuitBuilder::new();
    let pi = circuit.build(&mut builder);
    let srs = SRS::insecure_for_testing(65536);
    let (proof, vk) = prover::prove(&builder, &srs);
    let pi_vec = pi.to_vec();

    c.bench_function("transfer_verify", |b| {
        b.iter(|| {
            verifier::verify(&proof, &vk, &pi_vec, &srs);
        })
    });
}

fn bench_withdraw_prove(c: &mut Criterion) {
    let circuit = make_withdraw_circuit();
    let mut builder = UltraCircuitBuilder::new();
    let _pi = circuit.build(&mut builder);
    let srs = SRS::insecure_for_testing(65536);

    c.bench_function("withdraw_prove", |b| {
        b.iter(|| {
            prover::prove(&builder, &srs);
        })
    });
}

fn constraint_counts(c: &mut Criterion) {
    let transfer = make_transfer_circuit();
    let mut tb = UltraCircuitBuilder::new();
    transfer.build(&mut tb);

    let withdraw = make_withdraw_circuit();
    let mut wb = UltraCircuitBuilder::new();
    withdraw.build(&mut wb);

    println!("\n=== Constraint Counts ===");
    println!("Transfer circuit: {} gates", tb.num_gates());
    println!("Withdraw circuit: {} gates", wb.num_gates());
    println!("=========================\n");

    // Dummy bench to include this in the output
    c.bench_function("constraint_count_transfer", |b| {
        b.iter(|| tb.num_gates())
    });
}

criterion_group! {
    name = circuit_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_transfer_build, constraint_counts
}

criterion_group! {
    name = proving_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_transfer_prove, bench_transfer_verify, bench_withdraw_prove
}

criterion_main!(circuit_benches, proving_benches);
