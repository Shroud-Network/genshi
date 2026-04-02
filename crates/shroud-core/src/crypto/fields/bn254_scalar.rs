//! BN254 scalar field (Fr).
//!
//! This is the native field for UltraHonk circuits. All circuit wire values,
//! Poseidon2 hash outputs, note commitments, and nullifiers live in this field.
//!
//! Fr order: 21888242871839275222246405745257275088548364400416034343698204186575808495617

pub use ark_bn254::Fr;
