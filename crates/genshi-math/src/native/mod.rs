//! Native (host / WASM) backend. Zero-overhead wrappers over `ark_bn254`.
//!
//! The submodules below are intentionally thin — they re-export arkworks types
//! under stable genshi-math names so the verifier can be written against a
//! single surface that is identical in shape to the BPF backend.

pub mod fr;
pub mod curve;
pub mod pairing;

pub use fr::Fr;
pub use curve::{G1Affine, G1Projective, G2Affine, G2Projective};
pub use pairing::pairing_check;
