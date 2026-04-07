//! Grumpkin curve types.
//!
//! Grumpkin is BN254's cycle partner:
//!   - Grumpkin scalar field = BN254 base field (Fq)
//!   - Grumpkin base field   = BN254 scalar field (Fr)
//!
//! This means Grumpkin point arithmetic is NATIVE inside BN254 UltraHonk proofs.
//! Scalar multiplications cost ~50 constraints vs ~700 for Baby Jubjub.
//!
//! Used for: Pedersen commitments, public key operations, ownership proofs.

pub use ark_grumpkin::{Affine as GrumpkinAffine, Projective as GrumpkinProjective};

/// Grumpkin scalar field element (= BN254 base field Fq).
/// Used for secret keys, blinding factors, and Pedersen commitment scalars.
pub type GrumpkinScalar = ark_bn254::Fq;

/// Grumpkin base field element (= BN254 scalar field Fr).
/// The x/y coordinates of Grumpkin points are elements of this field.
pub type GrumpkinBase = ark_bn254::Fr;
