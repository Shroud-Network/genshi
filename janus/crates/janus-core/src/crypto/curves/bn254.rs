//! BN254 curve types.
//!
//! G1 and G2 points used for KZG polynomial commitments and pairings.
//! The pairing equation is the basis for UltraHonk verification on both
//! EVM (ecAdd/ecMul/ecPairing precompiles) and Solana (sol_alt_bn128_* syscalls).

pub use ark_bn254::{Bn254, G1Affine, G1Projective, G2Affine, G2Projective};
