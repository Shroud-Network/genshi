//! BN254 base field (Fq).
//!
//! This equals Grumpkin's scalar field — the cycle partner relationship.
//! Grumpkin arithmetic is native inside BN254 UltraHonk proofs because
//! Grumpkin's scalar field = BN254's base field.
//!
//! Fq order: 21888242871839275222246405745257275088696311157297823662689037894645226208583

pub use ark_bn254::Fq;
